using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Tether.Shared.Logging;

namespace Tether.PanicEngine;

public class SafeCredentialFilterManager
{
    public static readonly Guid TetherProviderGuid = new("c8c8d282-f4f1-451d-96fc-a8b1f783117b");

    private readonly object _syncLock = new();
    private readonly IPanicRestorationStore _store;
    private readonly ITetherLogger _logger;
    private PanicLockSessionState _currentSession;

    public SafeCredentialFilterManager(ITetherLogger logger, IPanicRestorationStore? store = null)
    {
        _logger = logger;
        _store = store ?? new WindowsRegistryPanicStore(logger);

        // Attempt recovery from persistent store (e.g., service restart during Panic Lock)
        PanicLockSessionState? loaded = null;
        try
        {
            loaded = _store.Load();
        }
        catch (Exception ex)
        {
            _logger.Warning($"SafeCredentialFilterManager: Error reading persistent state during initialization: {ex.Message}");
        }

        if (loaded != null && loaded.IsPanicActive)
        {
            _logger.Warning($"SafeCredentialFilterManager: Resumed active Panic Lock session '{loaded.SessionId}' after restart.");
            _currentSession = loaded;
        }
        else
        {
            _currentSession = new PanicLockSessionState
            {
                SessionId = string.Empty,
                IsPanicActive = false
            };
        }
    }

    public bool IsPanicActive
    {
        get
        {
            lock (_syncLock)
            {
                return _currentSession.IsPanicActive;
            }
        }
    }

    public string ActiveSessionId
    {
        get
        {
            lock (_syncLock)
            {
                return _currentSession.SessionId;
            }
        }
    }

    public void ActivatePanicLock(string? sessionId = null)
    {
        lock (_syncLock)
        {
            string newSessionId = !string.IsNullOrWhiteSpace(sessionId) ? sessionId : Guid.NewGuid().ToString("D");

            if (_currentSession.IsPanicActive && string.Equals(_currentSession.SessionId, newSessionId, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var nextSession = new PanicLockSessionState
            {
                SessionId = newSessionId,
                IsPanicActive = true,
                ActivatedAt = DateTimeOffset.UtcNow
            };

            try
            {
                _store.Save(nextSession);
                _currentSession = nextSession;
                _logger.Warning($"SafeCredentialFilterManager: Panic Lock activated [Session: {newSessionId}]");
            }
            catch (Exception ex)
            {
                _logger.Error($"SafeCredentialFilterManager: Failed to persist panic activation: {ex.Message}");
                throw;
            }
        }
    }

    public void DeactivatePanicLock(string? sessionId = null)
    {
        lock (_syncLock)
        {
            if (!_currentSession.IsPanicActive)
            {
                return;
            }

            if (!string.IsNullOrWhiteSpace(sessionId) &&
                !string.Equals(_currentSession.SessionId, sessionId, StringComparison.OrdinalIgnoreCase))
            {
                _logger.Warning($"SafeCredentialFilterManager: Rejecting deactivation with mismatched session ID (active: {_currentSession.SessionId}, given: {sessionId})");
                return;
            }

            _currentSession.IsPanicActive = false;
            _currentSession.DeactivatedAt = DateTimeOffset.UtcNow;

            try
            {
                _store.Save(_currentSession);
                _logger.Info($"SafeCredentialFilterManager: Panic Lock deactivated [Session: {_currentSession.SessionId}]");
            }
            catch (Exception ex)
            {
                _logger.Error($"SafeCredentialFilterManager: Failed to persist panic deactivation: {ex.Message}");
                throw;
            }
        }
    }

    public void ApplyFilter(Guid[] providers, bool[] allowStates)
    {
        if (providers == null || allowStates == null || providers.Length != allowStates.Length)
        {
            _logger.Warning("SafeCredentialFilterManager: Invalid providers/allowStates arguments in ApplyFilter.");
            return;
        }

        lock (_syncLock)
        {
            if (!_currentSession.IsPanicActive)
            {
                return;
            }

            bool changed = false;

            for (int i = 0; i < providers.Length; i++)
            {
                Guid pid = providers[i];

                if (pid == TetherProviderGuid)
                {
                    // Preserve incoming decision. If another filter or system policy denied Tether,
                    // never override another component's denial.
                    continue;
                }

                var existing = _currentSession.GetProvider(pid);

                if (existing != null)
                {
                    // Already captured in this session (e.g. LogonUI re-enumeration)
                    allowStates[i] = false;
                }
                else
                {
                    bool initiallyVisible = allowStates[i];

                    var tracked = new TrackedProviderState
                    {
                        ProviderId = pid,
                        OriginalVisibility = initiallyVisible,
                        HiddenByTether = initiallyVisible, // Only claim ownership if Tether turned it off!
                        CapturedAt = DateTimeOffset.UtcNow,
                        SessionId = _currentSession.SessionId
                    };

                    _currentSession.SetProvider(tracked);
                    allowStates[i] = false;
                    changed = true;
                }
            }

            if (changed)
            {
                try
                {
                    _store.Save(_currentSession);
                }
                catch (Exception ex)
                {
                    _logger.Error($"SafeCredentialFilterManager: Failed to save tracking state after filter: {ex.Message}");
                    throw;
                }
            }
        }
    }

    public bool Restore(Guid[] providers, bool[] allowStates)
    {
        if (providers == null || allowStates == null || providers.Length != allowStates.Length)
        {
            _logger.Warning("SafeCredentialFilterManager: Invalid providers/allowStates arguments in Restore.");
            return false;
        }

        lock (_syncLock)
        {
            if (_currentSession.IsPanicActive)
            {
                _logger.Warning("SafeCredentialFilterManager: Restoration rejected while Panic Lock is still active.");
                return false;
            }

            if (string.IsNullOrEmpty(_currentSession.SessionId))
            {
                _logger.Warning("SafeCredentialFilterManager: No active or prior session to restore from.");
                return false;
            }

            bool stateModified = false;

            for (int i = 0; i < providers.Length; i++)
            {
                Guid pid = providers[i];

                if (pid == TetherProviderGuid)
                {
                    // Preserve incoming decision. Never override another filter's denial.
                    continue;
                }

                var tracked = _currentSession.GetProvider(pid);

                if (tracked != null)
                {
                    if (tracked.HiddenByTether && tracked.OriginalVisibility)
                    {
                        allowStates[i] = true;
                        _currentSession.SetProvider(tracked with { HiddenByTether = false });
                        stateModified = true;
                    }
                    else if (!tracked.OriginalVisibility)
                    {
                        // Never unhide providers that were already hidden before Panic Lock
                        allowStates[i] = false;
                    }
                }
            }

            if (stateModified)
            {
                try
                {
                    _store.Save(_currentSession);
                }
                catch (Exception ex)
                {
                    _logger.Error($"SafeCredentialFilterManager: Failed to save updated session after restore: {ex.Message}");
                    throw;
                }
            }

            return true;
        }
    }

    public IReadOnlyList<TrackedProviderState> GetTrackedProviders()
    {
        lock (_syncLock)
        {
            return _currentSession.Providers.Values.ToList();
        }
    }
}
