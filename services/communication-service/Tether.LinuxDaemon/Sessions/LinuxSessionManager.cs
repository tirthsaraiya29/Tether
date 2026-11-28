using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Transport;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Sessions;

public sealed class LinuxSessionManager
{
    private readonly ITetherLogger _logger;
    private readonly ConcurrentDictionary<string, LinuxSession> _activeSessions = new(StringComparer.OrdinalIgnoreCase);

    public LinuxSessionManager(ITetherLogger logger)
    {
        _logger = logger;
    }

    public void RegisterSession(LinuxSession session)
    {
        // A device that reconnects supersedes its previous transport. Leaving the old session
        // registered would let it keep receiving broadcasts/responses meant for the new one.
        if (session.Device != null)
        {
            var stale = _activeSessions.Values
                .Where(s => !ReferenceEquals(s, session) &&
                            s.Device != null &&
                            string.Equals(s.Device.Fingerprint, session.Device.Fingerprint, StringComparison.OrdinalIgnoreCase))
                .ToList();
            foreach (var old in stale)
            {
                if (_activeSessions.TryRemove(old.SessionId, out _))
                {
                    old.Abort("Replaced by a newer authenticated session");
                }
            }
        }

        _activeSessions[session.SessionId] = session;
        _logger.Info($"Registered active session {session.SessionId} (device={session.Device?.DisplayName ?? "unpaired"}). Total active={_activeSessions.Count}");
    }

    public void UnregisterSession(string sessionId)
    {
        if (_activeSessions.TryRemove(sessionId, out var session))
        {
            _logger.Info($"Unregistered session {sessionId}. Total active={_activeSessions.Count}");
        }
    }

    public LinuxSession? GetSession(string sessionId)
    {
        _activeSessions.TryGetValue(sessionId, out var session);
        return session;
    }

    public IReadOnlyCollection<LinuxSession> GetAllSessions() => _activeSessions.Values.ToList();

    public async Task BroadcastJsonAsync<T>(T payload, CancellationToken ct = default)
    {
        var tasks = _activeSessions.Values.Select(s => s.WriteJsonFrameSafeAsync(payload, ct));
        await Task.WhenAll(tasks);
    }

    public async Task BroadcastRawFrameAsync(byte[] payload, CancellationToken ct = default)
    {
        var tasks = _activeSessions.Values.Select(s => s.WriteRawFrameSafeAsync(payload, ct));
        await Task.WhenAll(tasks);
    }

    public async Task SendRawFrameToDeviceAsync(string deviceId, byte[] payload, CancellationToken ct = default)
    {
        var targetSessions = _activeSessions.Values
            .Where(s => string.Equals(s.Device?.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(s.Device?.Fingerprint, deviceId, StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var session in targetSessions)
        {
            await session.WriteRawFrameSafeAsync(payload, ct);
        }
    }
}
