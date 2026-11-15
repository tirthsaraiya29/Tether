using System;
using System.Collections.Concurrent;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.EventBus;

public class InMemoryEventBus : IEventBus
{
    private readonly ConcurrentDictionary<Guid, Action<TetherEvent>> _handlers = new();
    private readonly ITetherLogger _logger;

    public InMemoryEventBus(ITetherLogger logger)
    {
        _logger = logger;
    }

    public void Publish(TetherEvent evt)
    {
        _logger.Debug($"Publishing event: {evt.EventType}");
        foreach (var handler in _handlers.Values)
        {
            try { handler(evt); }
            catch (Exception ex) { _logger.Error($"Handler failed: {ex.Message}", ex); }
        }
    }

    public void Subscribe(Action<TetherEvent> handler)
    {
        var id = Guid.NewGuid();
        _handlers.TryAdd(id, handler);
        _logger.Debug("New subscription added");
    }

    public void Unsubscribe(Action<TetherEvent> handler)
    {
        foreach (var pair in _handlers)
        {
            if (pair.Value == handler)
            {
                _handlers.TryRemove(pair.Key, out _);
            }
        }
    }
}