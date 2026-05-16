using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.IPC;
using Tether.Shared.Logging;

namespace Tether.CommunicationService;

public class PipeServer : IDisposable
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    public PipeServer(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(ListenForClients, _cts.Token);
        _logger.Info("Pipe server started");
    }

    private async Task ListenForClients()
    {
        while (_cts?.IsCancellationRequested == false)
        {
            try
            {
                using var pipeServer = new NamedPipeServerStream(
                    IpcConstants.PipeName,
                    PipeDirection.InOut,
                    1, // Allow ONE instance at a time
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous);

                _logger.Info($"Named pipe server waiting for connection on {IpcConstants.PipeName}...");
                await pipeServer.WaitForConnectionAsync(_cts.Token);
                _logger.Info("Desktop UI connected to pipe.");

                // Handle client messages
                await HandleClientMessages(pipeServer);

                _logger.Info("Desktop UI disconnected.");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error($"Pipe server error: {ex.Message}", ex);
                await Task.Delay(1000);
            }
        }
    }

    private async Task HandleClientMessages(NamedPipeServerStream pipeStream)
    {
        var buffer = new byte[IpcConstants.PipeBufferSize];

        while (pipeStream.IsConnected)
        {
            try
            {
                var read = await pipeStream.ReadAsync(buffer, 0, buffer.Length);
                if (read == 0) break;

                var json = Encoding.UTF8.GetString(buffer, 0, read);
                var evt = JsonSerializer.Deserialize<TetherEvent>(json);

                if (evt != null)
                {
                    _logger.Debug($"IPC received event: {evt.EventType} from Desktop UI");
                    _eventBus.Publish(evt);
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to handle pipe message: {ex.Message}", ex);
                break;
            }
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _listenTask?.Wait(5000);
        _cts?.Dispose();
    }
}