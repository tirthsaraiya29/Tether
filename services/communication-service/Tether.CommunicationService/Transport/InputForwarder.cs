using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Transport;

/// <summary>
/// Service-side (Session 0) named pipe host that relays raw input frames and bidirectional
/// control commands to and from the interactive-session Tether.SessionHelper process.
/// </summary>
public sealed class InputForwarder : IHostedService, IDisposable
{
    public const string BasePipeName = "Tether.InputPipe";
    private const int PipeBufferSize = 10 * 1024 * 1024;
    private const int WriteQueueCapacity = 4096;

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);

    private const int TokenUserClass = 1;

    private readonly ITetherLogger _logger;
    private readonly Channel<byte[]> _queue;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _pipeLock = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pendingRequests = new();

    private Task? _acceptTask;
    private Task? _writeTask;
    private NamedPipeServerStream? _activePipe;
    private TaskCompletionSource<bool>? _clientDisconnectTcs;

    public event Action<string>? OnHelperEventReceived;
    public event Action<string>? OnDesktopFrameReceived;

    public InputForwarder(ITetherLogger logger)
    {
        _logger = logger;
        _queue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(WriteQueueCapacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest,
            AllowSynchronousContinuations = false
        });
    }

    public bool IsHelperConnected
    {
        get
        {
            lock (_pipeLock)
            {
                return _activePipe is { IsConnected: true };
            }
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _acceptTask = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _writeTask = Task.Run(() => WriteLoopAsync(_cts.Token));
        _logger.Info("InputForwarder started.");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _cts.Cancel(); } catch { }
        try { await Task.WhenAny(_acceptTask ?? Task.CompletedTask, Task.Delay(2000, cancellationToken)); } catch { }
        try { await Task.WhenAny(_writeTask ?? Task.CompletedTask, Task.Delay(2000, cancellationToken)); } catch { }
        _logger.Info("InputForwarder stopped.");
    }

    public void Forward(ReadOnlySpan<byte> frame)
    {
        if (frame.Length <= 0) return;
        _queue.Writer.TryWrite(frame.ToArray());
    }

    public void PostToHelper(object payload)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        _queue.Writer.TryWrite(bytes);
    }

    public async Task<string?> RequestAsync(object payload, string requestId, TimeSpan timeout, CancellationToken ct)
    {
        if (!IsHelperConnected) return null;

        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[requestId] = tcs;

        try
        {
            PostToHelper(payload);

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linkedCts.CancelAfter(timeout);

            using (linkedCts.Token.Register(() => tcs.TrySetCanceled()))
            {
                return await tcs.Task;
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger.Warning($"InputForwarder: RequestAsync failed for requestId={requestId}: {ex.Message}");
            return null;
        }
        finally
        {
            _pendingRequests.TryRemove(requestId, out _);
        }
    }

    private bool IsAuthorizedHelperClient(NamedPipeServerStream pipe, uint activeSessionId, out uint clientPid)
    {
        clientPid = 0;
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out clientPid) || clientPid == 0)
            {
                return false;
            }

            if (clientPid == (uint)Environment.ProcessId)
            {
                return false;
            }

            using var proc = Process.GetProcessById((int)clientPid);
            if (proc.HasExited)
            {
                return false;
            }

            // Must match active console session
            if ((uint)proc.SessionId != activeSessionId)
            {
                _logger.Warning($"InputForwarder: Rejected pipe client PID {clientPid} in session {proc.SessionId} (expected active session {activeSessionId}).");
                return false;
            }

            // Must be Tether.SessionHelper
            string? procName = proc.ProcessName;
            if (!string.Equals(procName, "Tether.SessionHelper", StringComparison.OrdinalIgnoreCase))
            {
                _logger.Warning($"InputForwarder: Rejected unauthorized pipe client PID {clientPid} with process name '{procName}'.");
                return false;
            }

            // Verify executable name
            string? exePath = null;
            try { exePath = proc.MainModule?.FileName; } catch { }

            if (!string.IsNullOrEmpty(exePath))
            {
                string fileName = Path.GetFileName(exePath);
                if (!string.Equals(fileName, "Tether.SessionHelper.exe", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.Warning($"InputForwarder: Pipe client PID {clientPid} has unexpected executable name '{fileName}'.");
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.Warning($"InputForwarder: Failed to validate pipe client identity: {ex.Message}");
            return false;
        }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            var disconnectTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            try
            {
                var userSid = GetActiveConsoleUserSid(out uint activeSessionId);
                if (userSid is null)
                {
                    await Task.Delay(1000, ct);
                    continue;
                }

                string pipeName = $"{BasePipeName}.{activeSessionId}";
                var security = new PipeSecurity();

                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Deny));

                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                security.AddAccessRule(new PipeAccessRule(
                    userSid,
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    PipeBufferSize,
                    PipeBufferSize,
                    security);

                while (!ct.IsCancellationRequested)
                {
                    using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    waitCts.CancelAfter(TimeSpan.FromSeconds(3));
                    try
                    {
                        await pipe.WaitForConnectionAsync(waitCts.Token).ConfigureAwait(false);
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        if (ct.IsCancellationRequested) throw;
                        uint currentActiveSession = WTSGetActiveConsoleSessionId();
                        if (currentActiveSession != activeSessionId)
                        {
                            break;
                        }
                    }
                }

                if (!pipe.IsConnected)
                {
                    try { pipe.Dispose(); } catch { }
                    continue;
                }

                if (!IsAuthorizedHelperClient(pipe, activeSessionId, out uint clientPid))
                {
                    _logger.Warning($"InputForwarder: Terminating unauthorized connection from PID {clientPid} on pipe '{pipeName}'.");
                    try { pipe.Disconnect(); } catch { }
                    try { pipe.Dispose(); } catch { }
                    continue;
                }

                lock (_pipeLock)
                {
                    _activePipe = pipe;
                    _clientDisconnectTcs = disconnectTcs;
                }
                _logger.Info($"SessionHelper connected to bridge pipe '{pipeName}'.");

                var readTask = Task.Run(() => ReadLoopAsync(pipe, disconnectTcs, ct), ct);

                using var reg = ct.Register(() => disconnectTcs.TrySetResult(true));

                // Wait for client disconnect. A silent client death (no writes
                // in flight) never surfaces as a write error, so poll IsConnected.
                while (!disconnectTcs.Task.IsCompleted)
                {
                    bool connected;
                    lock (_pipeLock) { connected = pipe.IsConnected && ReferenceEquals(_activePipe, pipe); }
                    if (!connected)
                    {
                        disconnectTcs.TrySetResult(true);
                        break;
                    }
                    try { await Task.Delay(1000, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { disconnectTcs.TrySetResult(true); break; }
                }
                await disconnectTcs.Task.ConfigureAwait(false);
                try { await readTask; } catch { }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Warning($"Input pipe accept error: {ex.Message}");
                try { await Task.Delay(1000, ct); } catch { break; }
            }
            finally
            {
                lock (_pipeLock)
                {
                    if (ReferenceEquals(_activePipe, pipe))
                    {
                        _activePipe = null;
                        _clientDisconnectTcs = null;
                    }
                }
                try { pipe?.Dispose(); } catch { }
                _logger.Info("SessionHelper disconnected from bridge pipe.");
            }
        }
    }

    private async Task ReadLoopAsync(NamedPipeServerStream pipe, TaskCompletionSource<bool> disconnectTcs, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && pipe.IsConnected)
        {
            byte[]? frame;
            try
            {
                frame = await FrameCodec.ReadFrameAsync(pipe, ct);
            }
            catch
            {
                break;
            }

            if (frame is null || frame.Length == 0) break;

            if (frame[0] == (byte)'{')
            {
                try
                {
                    using var doc = JsonDocument.Parse(frame);
                    var root = doc.RootElement;
                    string type = root.TryGetProperty("type", out var tProp) ? (tProp.GetString() ?? "") : "";

                    if (type == "DESKTOP_FRAME")
                    {
                        string b64 = root.TryGetProperty("frameB64", out var fbProp) ? (fbProp.GetString() ?? "") : "";
                        OnDesktopFrameReceived?.Invoke(b64);
                        continue;
                    }

                    string reqId = root.TryGetProperty("requestId", out var rProp) ? (rProp.GetString() ?? "") : "";
                    if (!string.IsNullOrEmpty(reqId) && _pendingRequests.TryGetValue(reqId, out var tcs))
                    {
                        tcs.TrySetResult(System.Text.Encoding.UTF8.GetString(frame));
                    }

                    if (type is "CLIPBOARD_SYNC" or "NOTIFICATION_EVENT" or "MEDIA_METADATA_UPDATE" or "TERMINAL_OUTPUT")
                    {
                        OnHelperEventReceived?.Invoke(System.Text.Encoding.UTF8.GetString(frame));
                    }
                }
                catch { }
            }
        }
        disconnectTcs.TrySetResult(true);
    }

    private async Task WriteLoopAsync(CancellationToken ct)
    {
        var reader = _queue.Reader;
        while (!ct.IsCancellationRequested)
        {
            byte[]? frame;
            try
            {
                frame = await reader.ReadAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (ChannelClosedException) { break; }

            NamedPipeServerStream? pipe;
            TaskCompletionSource<bool>? staleTcs = null;
            lock (_pipeLock)
            {
                pipe = _activePipe;
                if (pipe is null || !pipe.IsConnected)
                {
                    // A dead-but-instanced pipe blocks AcceptLoopAsync on its
                    // disconnect TCS; signal it so a fresh pipe can be created.
                    staleTcs = _clientDisconnectTcs;
                    _activePipe = null;
                    _clientDisconnectTcs = null;
                }
            }
            if (pipe is null || !pipe.IsConnected)
            {
                staleTcs?.TrySetResult(true);
                continue; // realtime input frames are useless after reconnect; drop them
            }

            try
            {
                byte[] packet = new byte[4 + frame.Length];
                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(packet, frame.Length);
                Buffer.BlockCopy(frame, 0, packet, 4, frame.Length);
                await pipe.WriteAsync(packet, 0, packet.Length, ct).ConfigureAwait(false);
                await pipe.FlushAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Warning($"Bridge pipe forward / keepalive error: {ex.Message}");

                TaskCompletionSource<bool>? tcs = null;
                lock (_pipeLock)
                {
                    if (ReferenceEquals(_activePipe, pipe))
                    {
                        _activePipe = null;
                        tcs = _clientDisconnectTcs;
                        _clientDisconnectTcs = null;
                    }
                }
                tcs?.TrySetResult(true);
            }
        }
    }

    private static SecurityIdentifier? GetActiveConsoleUserSid(out uint activeSessionId)
    {
        activeSessionId = WTSGetActiveConsoleSessionId();
        if (activeSessionId == 0xFFFFFFFF) return null;

        if (!WTSQueryUserToken(activeSessionId, out IntPtr hToken)) return null;

        try
        {
            GetTokenInformation(hToken, TokenUserClass, IntPtr.Zero, 0, out uint dwLength);
            if (dwLength == 0) return null;

            IntPtr tokenInfo = Marshal.AllocHGlobal((int)dwLength);
            try
            {
                if (GetTokenInformation(hToken, TokenUserClass, tokenInfo, dwLength, out _))
                {
                    IntPtr pSid = Marshal.ReadIntPtr(tokenInfo);
                    return new SecurityIdentifier(pSid);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInfo);
            }
        }
        catch
        {
        }
        finally
        {
            CloseHandle(hToken);
        }

        return null;
    }

    public void Dispose()
    {
        try { _queue.Writer.TryComplete(); } catch { }
        try { _cts.Cancel(); } catch { }
        try { _cts.Dispose(); } catch { }
        lock (_pipeLock)
        {
            try { _activePipe?.Dispose(); } catch { }
            _activePipe = null;
            _clientDisconnectTcs = null;
        }
    }
}
