using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Tether.LinuxDaemon.Discovery;

public sealed class DiscoveryRateLimiter
{
    private const int MaxPerIpPerSec = 5;
    private const int MaxGlobalPerSec = 30;
    private const int MaxTrackedSources = 256;

    private readonly ConcurrentDictionary<string, Queue<DateTime>> _perIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<DateTime> _global = new();
    private readonly object _lock = new();

    public bool CheckAllowed(string sourceIp)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;

            while (_global.Count > 0 && (now - _global.Peek()).TotalSeconds >= 1.0)
                _global.Dequeue();

            if (_global.Count >= MaxGlobalPerSec)
                return false;

            if (_perIp.Count >= MaxTrackedSources)
            {
                var stale = new List<string>();
                foreach (var kvp in _perIp)
                {
                    while (kvp.Value.Count > 0 && (now - kvp.Value.Peek()).TotalSeconds >= 1.0)
                        kvp.Value.Dequeue();
                    if (kvp.Value.Count == 0)
                        stale.Add(kvp.Key);
                }
                foreach (var k in stale) _perIp.TryRemove(k, out _);

                if (_perIp.Count >= MaxTrackedSources)
                {
                    int toRemove = _perIp.Count - (MaxTrackedSources / 2);
                    foreach (var k in _perIp.Keys)
                    {
                        if (toRemove-- <= 0) break;
                        _perIp.TryRemove(k, out _);
                    }
                }
            }

            var q = _perIp.GetOrAdd(sourceIp, _ => new Queue<DateTime>());
            while (q.Count > 0 && (now - q.Peek()).TotalSeconds >= 1.0)
                q.Dequeue();

            if (q.Count >= MaxPerIpPerSec)
                return false;

            q.Enqueue(now);
            _global.Enqueue(now);
            return true;
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _perIp.Clear();
            _global.Clear();
        }
    }
}
