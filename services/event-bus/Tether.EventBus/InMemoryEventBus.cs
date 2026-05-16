using System.Collections.Concurrent;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.EventBus
{
    public class InMemoryEventBus : IEventBus
    {
        private readonly ConcurrentBag<Action<TetherEvent>> _handlers = new();
        private readonly ITetherLogger _logger;

        public InMemoryEventBus(ITetherLogger logger)
        {
            _logger = logger;
        }

        public void Publish(TetherEvent evt)
        {
            _logger.Debug($"Publishing event: {evt.EventType}");
            foreach (var handler in _handlers)
            {
                try { handler(evt); }
                catch (Exception ex) { _logger.Error($"Handler failed: {ex.Message}", ex); }
            }
        }

        public void Subscribe(Action<TetherEvent> handler)
        {
            _handlers.Add(handler);
            _logger.Debug("New subscription added");
        }

        public void Unsubscribe(Action<TetherEvent> handler)
        {
            // simple removal – not perfect but fine for skeleton
            var list = _handlers.ToList();
            list.Remove(handler);
            _handlers.Clear();
            foreach (var h in list) _handlers.Add(h);
        }
    }
}