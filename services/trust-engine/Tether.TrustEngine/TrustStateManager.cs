using Tether.EventBus;
using Tether.Shared.Constants;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.TrustEngine
{
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

            if (evt.EventType == TetherEventType.PHONE_CONNECTED)
            {
                _currentState = TrustState.TRUSTED;
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.TRUST_RESTORED,
                    Source = "TrustStateManager"
                });
                _logger.Info($"Trust state changed to {_currentState}");
            }
            else if (evt.EventType == TetherEventType.PHONE_DISCONNECTED)
            {
                _currentState = TrustState.LIMITED;
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.TRUST_LOST,
                    Source = "TrustStateManager"
                });
                _logger.Info($"Trust state changed to {_currentState}");
            }
            else if (evt.EventType == TetherEventType.PHONE_UNLOCKED)
            {
                _currentState = TrustState.TRUSTED;
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.TRUST_RESTORED,
                    Source = "TrustStateManager"
                });
                _logger.Info($"Trust restored (phone unlocked)");
            }
        }

        public TrustState GetCurrentState() => _currentState;
    }
}