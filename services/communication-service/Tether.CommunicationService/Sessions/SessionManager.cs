using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Transport;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Sessions;

/// <summary>
/// Registry for active TetherSession instances.
/// Enforces at most 1 active session per device by gracefully closing stale connections.
/// </summary>
public sealed class SessionManager
{
    private readonly ITetherLogger _logger;
    private readonly DeviceManager _deviceManager;
    private readonly ConcurrentDictionary<string, TetherSession> _activeSessions = new(StringComparer.Ordinal);

    public SessionManager(ITetherLogger logger, DeviceManager deviceManager)
    {
        _logger = logger;
        _deviceManager = deviceManager;
    }

    public int ActiveSessionCount => _activeSessions.Count;

    public void RegisterSession(TetherSession session)
    {
        var device = session.Device;
        if (device == null) return;

        if (device.CurrentSession != null && device.CurrentSession != session)
        {
            _logger.Info($"SessionManager: Terminating older stale session '{device.CurrentSession.SessionId}' for device '{device.DisplayName}'.");
            try { device.CurrentSession.Close("Replaced by new session"); } catch { }
        }

        _activeSessions[session.SessionId] = session;
        _deviceManager.MarkConnected(device.Fingerprint, session);
        _logger.Info($"SessionManager: Registered session '{session.SessionId}' for device '{device.DisplayName}' ({device.Fingerprint}). Total active={_activeSessions.Count}.");
    }

    public void UnregisterSession(TetherSession session)
    {
        if (_activeSessions.TryRemove(session.SessionId, out _))
        {
            if (session.Device != null)
            {
                _deviceManager.MarkDisconnected(session.Device.Fingerprint, session);
            }
            _logger.Info($"SessionManager: Unregistered session '{session.SessionId}'. Total active={_activeSessions.Count}.");
        }
    }

    public IReadOnlyCollection<TetherSession> GetActiveSessions() =>
        _activeSessions.Values.ToArray();

    public void BroadcastLaptopState(LaptopSnapshot snap)
    {
        var sessions = GetActiveSessions();
        foreach (var session in sessions)
        {
            _ = session.SendLaptopStateAsync(snap, System.Threading.CancellationToken.None);
        }
    }

    /// <summary>
    /// Broadcasts an already-serialized UTF-8 JSON frame to every active session.
    /// Used by the power-event pipeline (PowerEventNotifier) so the phone receives
    /// POWER_EVENT frames over the same TLS channel that carries laptop state.
    /// </summary>
    public void BroadcastRawFrame(string json)
    {
        if (string.IsNullOrEmpty(json)) return;

        var sessions = GetActiveSessions();
        if (sessions.Count == 0) return;

        var bytes = System.Text.Encoding.UTF8.GetBytes(json);

        foreach (var session in sessions)
        {
            _ = session.SendRawFrameAsync(bytes, System.Threading.CancellationToken.None);
        }
    }

    /// <summary>
    /// Synchronous, bounded broadcast used on the pre-shutdown / shutdown path.
    /// Waits up to <paramref name="timeout"/> for the TLS writes to drain.
    /// Returns true if every write completed within the budget.
    /// </summary>
    public bool TryBroadcastRawFrameBlocking(string json, TimeSpan timeout)
    {
        if (string.IsNullOrEmpty(json)) return false;

        var sessions = GetActiveSessions();
        if (sessions.Count == 0) return false;

        var bytes = System.Text.Encoding.UTF8.GetBytes(json);
        var tasks = new Task[sessions.Count];
        int i = 0;
        foreach (var s in sessions)
            tasks[i++] = s.SendRawFrameAsync(bytes, System.Threading.CancellationToken.None);

        try
        {
            return Task.WaitAll(tasks, timeout);
        }
        catch (AggregateException)
        {
            return false;
        }
    }
}