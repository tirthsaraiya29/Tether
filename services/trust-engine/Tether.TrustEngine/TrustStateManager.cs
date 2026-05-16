using Tether.EventBus;
using Tether.Shared.Constants;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.TrustEngine;

public class TrustStateManager
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private TrustState _currentState = TrustState.LIMITED;

    public TrustStateManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
        _eventBus.Subscribe(OnEvent);
        _logger.Info("TrustStateManager initialized");
    }

    private void OnEvent(TetherEvent evt)
    {
        _logger.Info($"TrustStateManager received event: {evt.EventType}");

        switch (evt.EventType)
        {
            case TetherEventType.PHONE_CONNECTED:
            case TetherEventType.PHONE_UNLOCKED:
                _currentState = TrustState.TRUSTED;
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.TRUST_RESTORED,
                    Source = "TrustStateManager"
                });
                _logger.Info($"Trust state changed to {_currentState}");
                break;

            case TetherEventType.PHONE_DISCONNECTED:
                _currentState = TrustState.LIMITED;
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.TRUST_LOST,
                    Source = "TrustStateManager"
                });
                _logger.Info($"Trust state changed to {_currentState}");
                break;

            case TetherEventType.TRUST_DEGRADED:
                if (_currentState == TrustState.TRUSTED)
                {
                    _currentState = TrustState.DEGRADED;
                    _logger.Warning("Trust degraded due to proximity");
                }
                break;

            case TetherEventType.TRUST_LOST:
                _currentState = TrustState.LIMITED;
                _logger.Warning("Trust lost – enforcement will lock");
                break;

            case TetherEventType.PANIC_TRIGGERED:
                _currentState = TrustState.PANIC;
                _logger.Warning("PANIC mode activated");
                break;
        }
    }

    public TrustState GetCurrentState() => _currentState;
}