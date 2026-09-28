using System;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.IPC;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Ipc;

public sealed class IpcEventRelay
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;

    public IpcEventRelay(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
        _eventBus.Subscribe(OnEvent);
    }

    private void OnEvent(TetherEvent evt)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var json = JsonSerializer.Serialize(evt);
                var bytes = Encoding.UTF8.GetBytes(json);

                using var client = new NamedPipeClientStream(
                    ".",
                    IpcConstants.UiPipeName,
                    PipeDirection.Out,
                    PipeOptions.Asynchronous);

                await client.ConnectAsync(1000);
                await client.WriteAsync(bytes, 0, bytes.Length);
                await client.FlushAsync();
                _logger.Info($"IPC Relay forwarded event {evt.EventType} to UI pipe.");
            }
            catch (TimeoutException)
            {
                _logger.Debug($"IPC Relay timeout sending {evt.EventType} (no UI pipe listener).");
            }
            catch (Exception ex)
            {
                _logger.Debug($"IPC Relay error sending {evt.EventType}: {ex.Message}");
            }
        });
    }
}
