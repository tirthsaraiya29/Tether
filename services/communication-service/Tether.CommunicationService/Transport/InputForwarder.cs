using System;
using System.IO.Pipes;
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
    public const string PipeName = "Tether.InputPipe";
    private const int PipeBufferSize = 64 * 1024;
    private const int WriteQueueCapacity = 4096;

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

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _acceptTask = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _writeTask = Task.Run(() => WriteLoopAsync(_cts.Token));
        _logger.Info($"InputForwarder started (pipe='{PipeName}').");
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
                var security = new PipeSecurity();
                security.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                pipe = NamedPipeServerStreamAcl.Create(
                    PipeName,
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
                _logger.Info("SessionHelper connected to input pipe.");

                // Hold the connection open until either:
                //   (a) the service is stopping, or
                //   (b) the write loop sees a broken pipe and signals disconnect.
                using var reg = ct.Register(() => disconnectTcs.TrySetResult(true));
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
            byte[] frame;
            try
            {
                frame = await reader.ReadAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (ChannelClosedException) { break; }

            NamedPipeServerStream? pipe;
            lock (_pipeLock) { pipe = _activePipe; }
            if (pipe is null) continue;

            try
            {
                await FrameCodec.WriteFrameAsync(pipe, frame, ct);
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