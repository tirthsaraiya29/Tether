using System;
using System.Collections.Generic;

namespace Tether.CommunicationService.Discovery;

/// <summary>
/// Bounded, thread-safe rate limiter for discovery probes.
/// Enforces global and per-source rate limits with automatic expiration
/// and an explicit hard cap on tracked sources to prevent memory exhaustion DoS.
/// </summary>
public sealed class DiscoveryRateLimiter
{
    public const int DefaultMaxPerIpPerSecond = 5;
    public const int DefaultMaxGlobalPerSecond = 30;
    public const int DefaultMaxTrackedSources = 256;
    public const long DefaultWindowTicks = 10_000_000; // 1 second
    public const long DefaultExpiryTicks = 30_000_000; // 3 seconds

    private readonly int _maxPerIp;
    private readonly int _maxGlobal;
    private readonly int _maxTrackedSources;
    private readonly long _windowTicks;
    private readonly long _expiryTicks;

    private readonly object _lock = new();
    private readonly Dictionary<string, (int count, long windowStartTicks)> _sources = new(StringComparer.OrdinalIgnoreCase);
    private int _globalCount;
    private long _globalWindowStartTicks;

    public DiscoveryRateLimiter(
        int maxPerIp = DefaultMaxPerIpPerSecond,
        int maxGlobal = DefaultMaxGlobalPerSecond,
        int maxTrackedSources = DefaultMaxTrackedSources,
        long windowTicks = DefaultWindowTicks,
        long expiryTicks = DefaultExpiryTicks)
    {
        _maxPerIp = maxPerIp;
        _maxGlobal = maxGlobal;
        _maxTrackedSources = maxTrackedSources;
        _windowTicks = windowTicks;
        _expiryTicks = expiryTicks;
    }

    public int TrackedSourceCount
    {
        get
        {
            lock (_lock) return _sources.Count;
        }
    }

    public bool CheckAllowed(string sourceKey, long nowTicks = 0)
    {
        if (string.IsNullOrWhiteSpace(sourceKey)) return false;
        if (nowTicks <= 0) nowTicks = DateTime.UtcNow.Ticks;

        lock (_lock)
        {
            // 1. Global rate limit checked first (prevents multi-source flooding bypass)
            if (nowTicks - _globalWindowStartTicks > _windowTicks)
            {
                _globalWindowStartTicks = nowTicks;
                _globalCount = 1;
            }
            else
            {
                if (_globalCount >= _maxGlobal)
                {
                    return false;
                }
                _globalCount++;
            }

            // 2. Per-source rate limit
            if (_sources.TryGetValue(sourceKey, out var entry))
            {
                if (nowTicks - entry.windowStartTicks > _windowTicks)
                {
                    _sources[sourceKey] = (1, nowTicks);
                    return true;
                }

                if (entry.count >= _maxPerIp)
                {
                    return false;
                }

                _sources[sourceKey] = (entry.count + 1, entry.windowStartTicks);
                return true;
            }

            // 3. New source tracking with bounded capacity and safe cleanup
            if (_sources.Count >= _maxTrackedSources)
            {
                List<string>? expiredKeys = null;
                foreach (var kvp in _sources)
                {
                    if (nowTicks - kvp.Value.windowStartTicks > _expiryTicks)
                    {
                        expiredKeys ??= new List<string>();
                        expiredKeys.Add(kvp.Key);
                    }
                }

                if (expiredKeys != null)
                {
                    foreach (var k in expiredKeys)
                    {
                        _sources.Remove(k);
                    }
                }

                // If still at capacity, evict the oldest entry
                if (_sources.Count >= _maxTrackedSources)
                {
                    string? oldestKey = null;
                    long oldestTicks = long.MaxValue;
                    foreach (var kvp in _sources)
                    {
                        if (kvp.Value.windowStartTicks < oldestTicks)
                        {
                            oldestTicks = kvp.Value.windowStartTicks;
                            oldestKey = kvp.Key;
                        }
                    }

                    if (oldestKey != null)
                    {
                        _sources.Remove(oldestKey);
                    }
                }
            }

            _sources[sourceKey] = (1, nowTicks);
            return true;
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _sources.Clear();
            _globalCount = 0;
            _globalWindowStartTicks = 0;
        }
    }
}
