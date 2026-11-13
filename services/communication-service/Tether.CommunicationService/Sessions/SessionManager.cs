using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Transport;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Sessions;

/// <summary>
/// Tracks active TLS client connections (<see cref="TetherSession"/>).
/// Enforces single-active-session policy per physical phone (identified by public-key fingerprint).
/// If a phone reconnects with a fresh TLS connection before the old one is torn down,
/// the older session is evicted cleanly rather than wedging the transport.
/// </summary>
public sealed class SessionManager
{
    private readonly ConcurrentDictionary<string, TetherSession> _activeSessions = new();
    private readonly DeviceManager _deviceManager;
    private readonly ITetherLogger _logger;

    public SessionManager(DeviceManager deviceManager, ITetherLogger logger)
    {
        _deviceManager = deviceManager;
        _logger = logger;
    }

    public int ActiveSessionCount => _activeSessions.Count;
    public event Action<int>? ActiveSessionCountChanged;

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
        ActiveSessionCountChanged?.Invoke(_activeSessions.Count);
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
            ActiveSessionCountChanged?.Invoke(_activeSessions.Count);
        }
    }

    public IReadOnlyCollection<TetherSession> GetActiveSessions() =>
        _activeSessions.Values.ToArray();

    public void DisconnectDevice(string fingerprint, string reason)
    {
        var sessions = GetActiveSessions();
        foreach (var session in sessions)
        {
            if (string.Equals(session.Device?.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                try { session.Close(reason); } catch { }
            }
        }
    }

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
    /// <summary>
    /// Routes a serialized UTF-8 JSON frame exclusively to the active session owned by <paramref name="deviceId"/>.
    /// Used for sensitive frames such as TERMINAL_OUTPUT to prevent cross-device session data leaks.
    /// </summary>
    public bool SendRawFrameToDevice(string deviceId, string json)
    {
        if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(json)) return false;

        var sessions = GetActiveSessions();
        if (sessions.Count == 0) return false;

        var targetSession = sessions.FirstOrDefault(s =>
            string.Equals(s.Device?.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(s.Device?.Fingerprint, deviceId, StringComparison.OrdinalIgnoreCase));

        if (targetSession != null)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(json);
            _ = targetSession.SendRawFrameAsync(bytes, System.Threading.CancellationToken.None);
            return true;
        }

        return false;
    }

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
        if (sessions.Count == 0) return true;

        var bytes = System.Text.Encoding.UTF8.GetBytes(json);
        var tasks = new List<System.Threading.Tasks.Task>(sessions.Count);

        using var cts = new System.Threading.CancellationTokenSource(timeout);

        foreach (var session in sessions)
        {
            tasks.Add(session.SendRawFrameAsync(bytes, cts.Token));
        }

        try
        {
            return System.Threading.Tasks.Task.WaitAll(tasks.ToArray(), timeout);
        }
        catch (Exception ex)
        {
            _logger.Warning($"SessionManager: Blocking broadcast timed out or failed: {ex.Message}");
            return false;
        }
    }
}
