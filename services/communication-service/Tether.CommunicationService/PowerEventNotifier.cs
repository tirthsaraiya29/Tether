using System;
using System.Linq;
using System.Text.Json;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Power;

public sealed class PowerEventNotifier
{
    private readonly PowerEventWatcher _watcher;
    private readonly ITetherLogger _logger;

    public PowerEventNotifier(PowerEventWatcher watcher, ITetherLogger logger)
    {
        _watcher = watcher;
        _logger = logger;
    }

    /// <summary>
    /// Call this when a phone session transitions to READY/AUTHENTICATED.
    /// The delegate should push a UTF-8 JSON frame over the TLS socket.
    /// </summary>
    public void FlushToSession(Action<string> sendFrame)
    {
        if (!_watcher.HasPending) return;

        var events = _watcher.SnapshotAndClear();
        if (events.Count == 0) return;

        var payload = new
        {
            type = "POWER_EVENT",
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            events = events.Select(e => new
            {
                eventType = e.Type.ToString().ToUpperInvariant(),
                timestamp = e.TimestampUtc.ToUnixTimeMilliseconds(),
                source = e.Source,
            }).ToArray(),
        };

        var json = JsonSerializer.Serialize(payload);
        _logger.Info($"PowerEventNotifier: delivering {events.Count} power event(s) to phone session.");

        try
        {
            sendFrame(json);
        }
        catch (Exception ex)
        {
            _logger.Error($"PowerEventNotifier: send failed: {ex.Message}", ex);
            // Requeue so next reconnect tries again
            foreach (var e in events) _watcher.RecordInitiated(e.Type, e.Source);
        }
    }
}