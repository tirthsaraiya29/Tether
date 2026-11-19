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
            string newSessionId = !string.IsNullOrWhiteSpace(sessionId) ? sessionId : Guid.NewGuid().ToString("N");

            // If already active with the same session, keep existing tracking
            if (_currentSession.IsPanicActive && _currentSession.SessionId == newSessionId)
            {
                return;
            }

            _currentSession = new PanicLockSessionState
            {
                SessionId = newSessionId,
                IsPanicActive = true,
                ActivatedAt = DateTimeOffset.UtcNow
            };

            try
            {
                _store.Save(_currentSession);
                _logger.Warning($"SafeCredentialFilterManager: Panic Lock activated [Session: {newSessionId}]");
            }
            catch (Exception ex)
            {
                _logger.Error($"SafeCredentialFilterManager: Failed to save panic activation: {ex.Message}");
            }
        }
    }

    public void DeactivatePanicLock()
    {
        lock (_syncLock)
        {
            if (!_currentSession.IsPanicActive)
            {
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
            // Requirement 4: Preserve existing Credential Provider filtering behaviour outside Panic Lock.
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
                    // Tether's provider must remain available for unlock
                    allowStates[i] = true;
                    continue;
                }

                // Check existing tracking in the current panic session
                var existing = _currentSession.GetProvider(pid);

                if (existing != null)
                {
                    // Already captured in this session (e.g. LogonUI re-enumeration)
                    // Maintain filtering decision
                    allowStates[i] = false;
                }
                else
                {
                    // First time encountering this provider in the current session
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
            // Requirement 9: Do not weaken Panic Lock authentication or introduce a bypass through restoration
            if (_currentSession.IsPanicActive)
            {
                _logger.Warning("SafeCredentialFilterManager: Restoration rejected while Panic Lock is still active.");
                return false;
            }

            // Requirement 8: Fail safely if ownership or original state cannot be established reliably
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
                    allowStates[i] = true;
                    continue;
                }

                var tracked = _currentSession.GetProvider(pid);

                if (tracked != null)
                {
                    // Requirement 1 & 2: Restore only providers that Tether explicitly hid
                    if (tracked.HiddenByTether && tracked.OriginalVisibility)
                    {
                        allowStates[i] = true;

                        // Mark as restored so subsequent calls are idempotent
                        _currentSession.SetProvider(tracked with { HiddenByTether = false });
                        stateModified = true;
                    }
                    else if (!tracked.OriginalVisibility)
                    {
                        // Requirement 3: Never unhide providers that were already hidden before Panic Lock
                        allowStates[i] = false;
                    }
                    // If already restored (OriginalVisibility == true && !HiddenByTether), leave allowStates[i] untouched
                }
                // If not tracked by Tether, leave incoming allowStates[i] strictly untouched!
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
