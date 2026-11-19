using System;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.PanicEngine;

public class PanicManager
{
    private readonly object _stateLock = new();
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly SafeCredentialFilterManager _filterManager;

    private string? _activePanicSessionId;
    private long _lastSequenceNumber;

    public SafeCredentialFilterManager FilterManager => _filterManager;
    public string? ActivePanicSessionId
    {
        get { lock (_stateLock) return _activePanicSessionId; }
    }

    public PanicManager(IEventBus eventBus, ITetherLogger logger, SafeCredentialFilterManager? filterManager = null)
    {
        _eventBus = eventBus;
        _logger = logger;
        _filterManager = filterManager ?? new SafeCredentialFilterManager(logger);

        if (_filterManager.IsPanicActive && !string.IsNullOrEmpty(_filterManager.ActiveSessionId))
        {
            _activePanicSessionId = _filterManager.ActiveSessionId;
        }

        _eventBus.Subscribe(OnEvent);
    }

    private void OnEvent(TetherEvent evt)
    {
        if (string.Equals(evt.Source, "PanicManager", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (evt.EventType == TetherEventType.PANIC_TRIGGERED)
        {
            _logger.Warning($"PanicManager: Received external PANIC_TRIGGERED event. Session: {evt.SessionId}");
            try
            {
                TriggerPanic(evt.SessionId, evt.SequenceNumber);
            }
            catch (Exception ex)
            {
                _logger.Error($"PanicManager: Failed to process PANIC_TRIGGERED: {ex.Message}");
            }
        }
        else if (evt.EventType == TetherEventType.PANIC_CLEARED)
        {
            _logger.Info($"PanicManager: Received external PANIC_CLEARED event. Session: {evt.SessionId}");
            ClearPanic(evt.SessionId, evt.SequenceNumber);
        }
    }

    public string TriggerPanic(string? customSessionId = null, long sequenceNumber = 0)
    {
        lock (_stateLock)
        {
            string sessionId = !string.IsNullOrWhiteSpace(customSessionId)
                ? customSessionId
                : Guid.NewGuid().ToString("D");

            _logger.Warning($"PanicManager: Initiating Panic Lock for session {sessionId}...");

            // Activate in filter manager (throws on persistence failure)
            _filterManager.ActivatePanicLock(sessionId);

            _activePanicSessionId = sessionId;
            _lastSequenceNumber = sequenceNumber;

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PANIC_TRIGGERED,
                Source = "PanicManager",
                SessionId = sessionId,
                SequenceNumber = sequenceNumber,
                Timestamp = DateTime.UtcNow
            });

            return sessionId;
        }
    }

    public bool ClearPanic(string? sessionId = null, long sequenceNumber = 0)
    {
        lock (_stateLock)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                _logger.Warning("PanicManager: ClearPanic rejected. No session ID provided in unlock request.");
                return false;
            }

            if (_activePanicSessionId == null)
            {
                _logger.Warning($"PanicManager: ClearPanic rejected. No active panic session to clear (received: {sessionId}).");
                return false;
            }

            if (!string.Equals(_activePanicSessionId, sessionId, StringComparison.OrdinalIgnoreCase))
            {
                _logger.Warning($"PanicManager: ClearPanic rejected. Session mismatch (active: {_activePanicSessionId}, received: {sessionId}).");
                return false;
            }

            if (sequenceNumber > 0 && sequenceNumber < _lastSequenceNumber)
            {
                _logger.Warning($"PanicManager: ClearPanic rejected. Stale event sequence ({sequenceNumber} < {_lastSequenceNumber}).");
                return false;
            }

            _logger.Info($"PanicManager: Clearing Panic Lock for session {sessionId}...");

            _filterManager.DeactivatePanicLock(sessionId);

            _activePanicSessionId = null;
            _lastSequenceNumber = sequenceNumber;

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PANIC_CLEARED,
                Source = "PanicManager",
                SessionId = sessionId,
                SequenceNumber = sequenceNumber,
                Timestamp = DateTime.UtcNow
            });

            return true;
        }
    }
}