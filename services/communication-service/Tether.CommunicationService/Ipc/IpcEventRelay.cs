using System;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
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
    private readonly Channel<(string json, string eventType, int retriesLeft)> _outbox =
        Channel.CreateBounded<(string, string, int)>(new BoundedChannelOptions(1024) { FullMode = BoundedChannelFullMode.DropOldest });

    public IpcEventRelay(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
        _eventBus.Subscribe(evt =>
        {
            var json = JsonSerializer.Serialize(evt);
            _outbox.Writer.TryWrite((json, evt.EventType.ToString(), 5));
        });
        _ = Task.Run(DispatcherLoop);
    }

    private async Task DispatcherLoop()
    {
        await foreach (var (json, eventType, retries) in _outbox.Reader.ReadAllAsync())
        {
            try
            {
                using var client = new NamedPipeClientStream(".", IpcConstants.UiPipeName, PipeDirection.Out, PipeOptions.Asynchronous);
                await client.ConnectAsync(1000);
                var bytes = Encoding.UTF8.GetBytes(json);
                await client.WriteAsync(bytes, 0, bytes.Length);
                await client.FlushAsync();
                _logger.Info($"IPC Relay forwarded event {eventType} to UI pipe.");
            }
            catch (Exception ex)
            {
                if (retries > 1)
                {
                    _outbox.Writer.TryWrite((json, eventType, retries - 1));
                    await Task.Delay(300);
                }
                else
                {
                    _logger.Debug($"IpcEventRelay: unable to send {eventType} after retries: {ex.Message}");
                }
            }
        }
    }
}
