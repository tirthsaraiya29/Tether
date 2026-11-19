using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.PanicEngine;

public class PanicManager
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly SafeCredentialFilterManager _filterManager;

    public SafeCredentialFilterManager FilterManager => _filterManager;

    public PanicManager(IEventBus eventBus, ITetherLogger logger, SafeCredentialFilterManager? filterManager = null)
    {
        _eventBus = eventBus;
        _logger = logger;
        _filterManager = filterManager ?? new SafeCredentialFilterManager(logger);
        _eventBus.Subscribe(OnEvent);
    }

    private void OnEvent(TetherEvent evt)
    {
        if (evt.EventType == TetherEventType.PANIC_TRIGGERED)
        {
            _logger.Warning("Panic mode activated!");
            _filterManager.ActivatePanicLock();
        }
        else if (evt.EventType == TetherEventType.PANIC_CLEARED)
        {
            _logger.Info("Panic mode cleared! Deactivating filter and initiating safe restoration...");
            _filterManager.DeactivatePanicLock();
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

    public void ClearPanic()
    {
        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PANIC_CLEARED,
            Source = "PanicManager"
        });
    }
}