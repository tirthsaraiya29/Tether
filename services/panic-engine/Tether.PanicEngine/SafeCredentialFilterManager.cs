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

        // Ensure Windows Credential Provider Filter is registered
        EnsureFilterRegistered(null, _logger);

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

        if (loaded != null)
        {
            _currentSession = loaded;
            if (loaded.IsPanicActive)
            {
                _logger.Warning($"SafeCredentialFilterManager: Resumed active Panic Lock session '{loaded.SessionId}' after restart.");
            }
            else
            {
                _logger.Info($"SafeCredentialFilterManager: Loaded prior session '{loaded.SessionId}' with {loaded.Providers.Count} tracked providers.");
            }
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
            // Repeated activation must be idempotent!
            // Never replace an active session and discard its ownership records!
            if (_currentSession.IsPanicActive)
            {
                _logger.Info($"SafeCredentialFilterManager: Repeated activation ignored. Session '{_currentSession.SessionId}' is already active.");
                return;
            }

            string newSessionId = !string.IsNullOrWhiteSpace(sessionId) ? sessionId : Guid.NewGuid().ToString("D");

            EnsureFilterRegistered(null, _logger);

            var nextSession = new PanicLockSessionState
            {
                SessionId = newSessionId,
                IsPanicActive = true,
                ActivatedAt = DateTimeOffset.UtcNow,
                Providers = new Dictionary<string, TrackedProviderState>(StringComparer.OrdinalIgnoreCase)
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

            var nextSession = new PanicLockSessionState
            {
                SessionId = _currentSession.SessionId,
                IsPanicActive = false,
                ActivatedAt = _currentSession.ActivatedAt,
                DeactivatedAt = DateTimeOffset.UtcNow,
                Providers = new Dictionary<string, TrackedProviderState>(_currentSession.Providers, StringComparer.OrdinalIgnoreCase),
                RestoredProviders = new HashSet<string>(_currentSession.RestoredProviders, StringComparer.OrdinalIgnoreCase),
                IndependentlyDeniedProviders = new HashSet<string>(_currentSession.IndependentlyDeniedProviders, StringComparer.OrdinalIgnoreCase)
            };

            try
            {
                _store.Save(nextSession);
                _currentSession = nextSession;
                _logger.Info($"SafeCredentialFilterManager: Panic Lock deactivated [Session: {_currentSession.SessionId}]");
            }
            catch (Exception ex)
            {
                // Preserve active panic state if persistence fails!
                _logger.Error($"SafeCredentialFilterManager: Failed to persist panic deactivation: {ex.Message}. Preserving active panic state.");
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
            var workingProviders = new Dictionary<string, TrackedProviderState>(_currentSession.Providers, StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < providers.Length; i++)
            {
                Guid pid = providers[i];

                if (pid == TetherProviderGuid)
                {
                    // Preserve incoming decision. If another filter or system policy denied Tether,
                    // never override another component's denial.
                    continue;
                }

                string key = pid.ToString("D");
                if (workingProviders.TryGetValue(key, out var existing))
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

                    workingProviders[key] = tracked;
                    allowStates[i] = false;
                    changed = true;
                }
            }

            if (changed)
            {
                var nextSession = new PanicLockSessionState
                {
                    SessionId = _currentSession.SessionId,
                    IsPanicActive = _currentSession.IsPanicActive,
                    ActivatedAt = _currentSession.ActivatedAt,
                    DeactivatedAt = _currentSession.DeactivatedAt,
                    Providers = workingProviders,
                    RestoredProviders = new HashSet<string>(_currentSession.RestoredProviders, StringComparer.OrdinalIgnoreCase),
                    IndependentlyDeniedProviders = new HashSet<string>(_currentSession.IndependentlyDeniedProviders, StringComparer.OrdinalIgnoreCase)
                };

                try
                {
                    _store.Save(nextSession);
                    _currentSession = nextSession;
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
            var workingProviders = new Dictionary<string, TrackedProviderState>(_currentSession.Providers, StringComparer.OrdinalIgnoreCase);
            var restoredSet = new HashSet<string>(_currentSession.RestoredProviders, StringComparer.OrdinalIgnoreCase);
            var deniedSet = new HashSet<string>(_currentSession.IndependentlyDeniedProviders, StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < providers.Length; i++)
            {
                Guid pid = providers[i];

                if (pid == TetherProviderGuid)
                {
                    // Preserve incoming decision. Never override another filter's denial.
                    continue;
                }

                string key = pid.ToString("D");

                bool isDenied = deniedSet.Contains(key) ||
                                (workingProviders.TryGetValue(key, out var tp) && tp.IndependentlyDenied);

                if (isDenied)
                {
                    // If an independent denial exists, preserve the denial rather than guessing! Never force allowStates[i] = true!
                    allowStates[i] = false;
                    deniedSet.Add(key);
                    if (workingProviders.TryGetValue(key, out var currentTp))
                    {
                        workingProviders[key] = currentTp with { IndependentlyDenied = true, HiddenByTether = false };
                        stateModified = true;
                    }
                }
                else if (workingProviders.TryGetValue(key, out var tracked))
                {
                    if (tracked.HiddenByTether && tracked.OriginalVisibility && !tracked.IndependentlyDenied)
                    {
                        // Clean restoration: Tether hid it, was originally visible, and no independent denial
                        allowStates[i] = true;
                        restoredSet.Add(key);
                        workingProviders.Remove(key);
                        stateModified = true;
                    }
                    else
                    {
                        // Pre-hidden or third-party denial: preserve denial
                        allowStates[i] = false;
                    }
                }
                // Providers absent from current enumeration are retained in workingProviders!
            }

            if (stateModified)
            {
                var nextSession = new PanicLockSessionState
                {
                    SessionId = _currentSession.SessionId,
                    IsPanicActive = _currentSession.IsPanicActive,
                    ActivatedAt = _currentSession.ActivatedAt,
                    DeactivatedAt = _currentSession.DeactivatedAt,
                    Providers = workingProviders,
                    RestoredProviders = restoredSet,
                    IndependentlyDeniedProviders = deniedSet
                };

                try
                {
                    _store.Save(nextSession);
                    _currentSession = nextSession;
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

    public bool RecordIndependentDenial(Guid providerId)
    {
        lock (_syncLock)
        {
            string key = providerId.ToString("D");
            var nextProviders = new Dictionary<string, TrackedProviderState>(_currentSession.Providers, StringComparer.OrdinalIgnoreCase);
            var nextDenied = new HashSet<string>(_currentSession.IndependentlyDeniedProviders, StringComparer.OrdinalIgnoreCase);
            nextDenied.Add(key);

            if (nextProviders.TryGetValue(key, out var existing))
            {
                nextProviders[key] = existing with { HiddenByTether = false, OriginalVisibility = false, IndependentlyDenied = true };
            }
            else
            {
                nextProviders[key] = new TrackedProviderState
                {
                    ProviderId = providerId,
                    OriginalVisibility = false,
                    HiddenByTether = false,
                    IndependentlyDenied = true,
                    CapturedAt = DateTimeOffset.UtcNow,
                    SessionId = _currentSession.SessionId
                };
            }

            var nextSession = new PanicLockSessionState
            {
                SessionId = _currentSession.SessionId,
                IsPanicActive = _currentSession.IsPanicActive,
                ActivatedAt = _currentSession.ActivatedAt,
                DeactivatedAt = _currentSession.DeactivatedAt,
                Providers = nextProviders,
                RestoredProviders = new HashSet<string>(_currentSession.RestoredProviders, StringComparer.OrdinalIgnoreCase),
                IndependentlyDeniedProviders = nextDenied
            };

            _store.Save(nextSession);
            _currentSession = nextSession;
            _logger.Info($"SafeCredentialFilterManager: Recorded independent denial for provider {providerId}. Tether ownership revoked.");
            return true;
        }
    }

    public static bool EnsureFilterRegistered(Microsoft.Win32.RegistryKey? rootKey = null, ITetherLogger? logger = null)
    {
        try
        {
            var baseKey = rootKey ?? Microsoft.Win32.Registry.LocalMachine;
            string filterSubKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\" + TetherProviderGuid.ToString("B");
            using var filterKey = baseKey.CreateSubKey(filterSubKeyPath, Microsoft.Win32.RegistryKeyPermissionCheck.ReadWriteSubTree);
            if (filterKey != null)
            {
                filterKey.SetValue("", "TetherCredentialProvider", Microsoft.Win32.RegistryValueKind.String);
                logger?.Info("SafeCredentialFilterManager: Ensured Credential Provider Filter registration in registry.");
                return true;
            }
        }
        catch (Exception ex)
        {
            logger?.Warning($"SafeCredentialFilterManager: Could not verify/write Credential Provider Filter registration: {ex.Message}");
        }
        return false;
    }
}
