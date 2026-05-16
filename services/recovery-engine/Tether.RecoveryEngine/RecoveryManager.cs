using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.RecoveryEngine
{
    public class RecoveryManager
    {
        private readonly IEventBus _eventBus;
        private readonly ITetherLogger _logger;

        public RecoveryManager(IEventBus eventBus, ITetherLogger logger)
        {
            _eventBus = eventBus;
            _logger = logger;
            _eventBus.Subscribe(OnEvent);
            _logger.Info("RecoveryManager initialized (skeleton)");
        }

        private void OnEvent(TetherEvent evt)
        {
            _logger.Debug($"RecoveryManager saw event: {evt.EventType}");
        }
    }
}