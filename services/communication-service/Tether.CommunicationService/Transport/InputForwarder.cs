using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Transport;

/// <summary>
/// Service-side (Session 0) named pipe host that relays raw input frames
/// to the interactive-session <c>Tether.SessionHelper</c> process, which
/// is the only component allowed to call <c>SendInput</c>.
/// </summary>
public sealed class InputForwarder : IHostedService, IDisposable
{
    public const string BasePipeName = "Tether.InputPipe";
    private const int PipeBufferSize = 64 * 1024;
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

    private const int TokenUserClass = 1;

    private readonly ITetherLogger _logger;
    private readonly Channel<byte[]> _queue;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _pipeLock = new();

    private Task? _acceptTask;
    private Task? _writeTask;
    private NamedPipeServerStream? _activePipe;
    private TaskCompletionSource<bool>? _clientDisconnectTcs;

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
        _logger.Info($"InputForwarder started.");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _cts.Cancel(); } catch { }
        try { await Task.WhenAny(_acceptTask ?? Task.CompletedTask, Task.Delay(2000, cancellationToken)); } catch { }
        try { await Task.WhenAny(_writeTask ?? Task.CompletedTask, Task.Delay(2000, cancellationToken)); } catch { }
        _logger.Info("InputForwarder stopped.");
    }

    /// <summary>
    /// Called from the TLS read loop. Never blocks.
    /// </summary>
    public void Forward(ReadOnlySpan<byte> frame)
    {
        if (frame.Length <= 0) return;
        _queue.Writer.TryWrite(frame.ToArray());
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            TaskCompletionSource<bool> disconnectTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

            try
            {
                SecurityIdentifier? userSid = GetActiveConsoleUserSid(out uint activeSessionId);
                if (userSid == null || activeSessionId == 0xFFFFFFFF)
                {
                    try { await Task.Delay(1000, ct); } catch { break; }
                    continue;
                }

                string pipeName = $"{BasePipeName}.{activeSessionId}";

                var security = new PipeSecurity();

                // Explicitly DENY Network SID to reject any remote/network-based named pipe connection (SMB/RPC)
                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Deny));

                // Allow SYSTEM
                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                // Allow Administrators
                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                // Allow only the active console user session SID
                security.AddAccessRule(new PipeAccessRule(
                    userSid,
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                pipe = NamedPipeServerStreamAcl.Create(
                    pipeName,
                    PipeDirection.Out,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    PipeBufferSize,
                    PipeBufferSize,
                    security);

                await pipe.WaitForConnectionAsync(ct);

                lock (_pipeLock)
                {
                    _activePipe = pipe;
                    _clientDisconnectTcs = disconnectTcs;
                }
                _logger.Info($"SessionHelper connected to input pipe '{pipeName}'.");

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
                _logger.Info("SessionHelper disconnected from input pipe.");
            }
        }
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
                }
            }
            if (pipe is null || !pipe.IsConnected)
            {
                staleTcs?.TrySetResult(true);
                continue; // realtime input frames are useless after reconnect; drop them
            }

            try
            {
                await FrameCodec.WriteFrameAsync(pipe, frame, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Warning($"Input pipe forward error: {ex.Message}");

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