using System.Runtime.InteropServices;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.EnforcementEngine;

public class EnforcementManager
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public EnforcementManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
        _eventBus.Subscribe(OnEvent);
        _logger.Info("EnforcementManager ready");
    }

    private void OnEvent(TetherEvent evt)
    {
        _logger.Debug($"EnforcementManager received: {evt.EventType}");
        if (evt.EventType == TetherEventType.TRUST_LOST ||
            evt.EventType == TetherEventType.PANIC_TRIGGERED)
        {
            _logger.Warning($"Enforcing lockdown due to {evt.EventType}");
            LockWorkStation();
        }
    }
}