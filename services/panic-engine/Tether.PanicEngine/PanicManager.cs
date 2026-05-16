using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.PanicEngine;

public class PanicManager
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;

    public PanicManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
        _eventBus.Subscribe(OnEvent);
    }

    private void OnEvent(TetherEvent evt)
    {
        if (evt.EventType == TetherEventType.PANIC_TRIGGERED)
        {
            _logger.Warning("Panic mode activated!");
            // Additional actions: disable input, etc.
        }
    }

    public void TriggerPanic()
    {
        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PANIC_TRIGGERED,
            Source = "PanicManager"
        });
    }
}