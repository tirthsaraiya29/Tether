using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Tether.Shared.Logging;

namespace Tether.PanicEngine;

public sealed record TrackedProviderState
{
    public Guid ProviderId { get; init; }
    public bool OriginalVisibility { get; init; }
    public bool HiddenByTether { get; init; }
    public bool IndependentlyDenied { get; init; }
    public DateTimeOffset CapturedAt { get; init; }
    public string SessionId { get; init; } = string.Empty;
}

public sealed class PanicLockSessionState
{
    public string SessionId { get; set; } = string.Empty;
    public bool IsPanicActive { get; set; }
    public DateTimeOffset ActivatedAt { get; set; }
    public DateTimeOffset? DeactivatedAt { get; set; }
    public Dictionary<string, TrackedProviderState> Providers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> RestoredProviders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> IndependentlyDeniedProviders { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public TrackedProviderState? GetProvider(Guid id)
    {
        return Providers.TryGetValue(id.ToString("D"), out var state) ? state : null;
    }

    public void SetProvider(TrackedProviderState state)
    {
        Providers[state.ProviderId.ToString("D")] = state;
    }

    public bool RemoveProvider(Guid id)
    {
        return Providers.Remove(id.ToString("D"));
    }
}

public interface IPanicRestorationStore
{
    PanicLockSessionState? Load();
    void Save(PanicLockSessionState state);
    void Clear();
    bool VerifyAccessAcl();
}

public sealed class WindowsRegistryPanicStore : IPanicRestorationStore
{
    private readonly string _baseRegistryPath;
    private readonly RegistryKey _rootKey;
    private readonly ITetherLogger _logger;

    public WindowsRegistryPanicStore(
        ITetherLogger logger,
        RegistryKey? rootKey = null,
        string baseRegistryPath = @"SOFTWARE\Tether\PanicLock")
    {
        _logger = logger;
        _rootKey = rootKey ?? Registry.LocalMachine;
        _baseRegistryPath = baseRegistryPath;
    }

    private byte[]? GetOrCreateHmacKey(RegistryKey key, bool allowCreate)
    {
        var blob = key.GetValue("IntegrityKeyBlob") as byte[];
        if (blob != null && blob.Length > 0)
        {
            try
            {
                return ProtectedData.Unprotect(blob, null, DataProtectionScope.LocalMachine);
            }
            catch (Exception ex)
            {
                _logger.Error($"WindowsRegistryPanicStore: Failed to unprotect existing HMAC key: {ex.Message}");
                if (!allowCreate)
                {
                    return null;
                }
                throw;
            }
        }

        if (!allowCreate)
        {
            _logger.Error("WindowsRegistryPanicStore: IntegrityKeyBlob is missing during Load. Refusing unverified state.");
            return null;
        }

        byte[] rawKey = new byte[32];
        RandomNumberGenerator.Fill(rawKey);
        byte[] protectedBlob = ProtectedData.Protect(rawKey, null, DataProtectionScope.LocalMachine);
        key.SetValue("IntegrityKeyBlob", protectedBlob, RegistryValueKind.Binary);
        return rawKey;
    }

    public PanicLockSessionState? Load()
    {
        try
        {
            if (!VerifyAccessAcl())
            {
                _logger.Error("WindowsRegistryPanicStore: Refusing to load state. Registry ACL verification failed.");
                return null;
            }

            using var baseKey = _rootKey.OpenSubKey(_baseRegistryPath, false);
            if (baseKey == null)
            {
                return null;
            }

            var daclVerObj = baseKey.GetValue("VaultDaclVersion");
            if (daclVerObj is not int daclVer || daclVer < 2)
            {
                _logger.Error("WindowsRegistryPanicStore: Refusing to load state. VaultDaclVersion is missing or outdated.");
                return null;
            }

            var panicActiveObj = baseKey.GetValue("IsPanicActive");
            if (panicActiveObj is not int)
            {
                _logger.Error("WindowsRegistryPanicStore: Refusing to load state. IsPanicActive is missing or wrong type.");
                return null;
            }

            var json = baseKey.GetValue("SessionData") as string;
            var storedDigest = baseKey.GetValue("IntegrityDigest") as byte[];

            if (string.IsNullOrWhiteSpace(json) || storedDigest == null || storedDigest.Length == 0)
            {
                return null;
            }

            byte[]? hmacKey = GetOrCreateHmacKey(baseKey, allowCreate: false);
            if (hmacKey == null)
            {
                _logger.Error("WindowsRegistryPanicStore: Cannot obtain valid HMAC key for verification.");
                return null;
            }

            using var hmac = new HMACSHA256(hmacKey);
            var computedDigest = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
            CryptographicOperations.ZeroMemory(hmacKey);

            if (!CryptographicOperations.FixedTimeEquals(storedDigest, computedDigest))
            {
                _logger.Error("WindowsRegistryPanicStore: Tampering detected! Stored integrity digest does not match.");
                return null;
            }

            var state = JsonSerializer.Deserialize<PanicLockSessionState>(json);
            if (state == null)
            {
                return null;
            }

            // Synchronize with HiddenProviders (REG_MULTI_SZ) recorded by the native filter
            var hiddenStrings = baseKey.GetValue("HiddenProviders") as string[];
            if (hiddenStrings != null && hiddenStrings.Length > 0)
            {
                foreach (var s in hiddenStrings)
                {
                    if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
                    {
                        string key = guid.ToString("D");
                        if (state.RestoredProviders.Contains(key) || state.IndependentlyDeniedProviders.Contains(key))
                        {
                            continue;
                        }
                        if (!state.Providers.ContainsKey(key))
                        {
                            state.Providers[key] = new TrackedProviderState
                            {
                                ProviderId = guid,
                                OriginalVisibility = true,
                                HiddenByTether = true,
                                CapturedAt = DateTimeOffset.UtcNow,
                                SessionId = state.SessionId
                            };
                        }
                    }
                }
            }

            // Synchronize with IndependentlyDeniedProviders (REG_MULTI_SZ)
            var deniedStrings = baseKey.GetValue("IndependentlyDeniedProviders") as string[];
            if (deniedStrings != null && deniedStrings.Length > 0)
            {
                foreach (var s in deniedStrings)
                {
                    if (Guid.TryParse(s, out var guid) && guid != Guid.Empty)
                    {
                        state.IndependentlyDeniedProviders.Add(guid.ToString("D"));
                    }
                }
            }

            return state;
        }
        catch (Exception ex)
        {
            _logger.Error($"WindowsRegistryPanicStore: Failed to load restoration state: {ex.Message}");
            return null;
        }
    }

    public void Save(PanicLockSessionState state)
    {
        try
        {
            RegistrySecurity? rs = null;
            if (ReferenceEquals(_rootKey, Registry.LocalMachine))
            {
                rs = new RegistrySecurity();
                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

                rs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                rs.AddAccessRule(new RegistryAccessRule(systemSid, RegistryRights.FullControl, AccessControlType.Allow));
                rs.AddAccessRule(new RegistryAccessRule(adminsSid, RegistryRights.FullControl, AccessControlType.Allow));
            }

            using var baseKey = rs != null
                ? _rootKey.CreateSubKey(_baseRegistryPath, RegistryKeyPermissionCheck.ReadWriteSubTree, rs)
                : _rootKey.CreateSubKey(_baseRegistryPath, RegistryKeyPermissionCheck.ReadWriteSubTree);

            if (baseKey == null)
            {
                _logger.Error($"WindowsRegistryPanicStore: Unable to create or open {_baseRegistryPath} registry key.");
                throw new InvalidOperationException($"Failed to open or create {_baseRegistryPath} key.");
            }

            if (rs != null)
            {
                baseKey.SetAccessControl(rs);
            }

            baseKey.SetValue("VaultDaclVersion", 2, RegistryValueKind.DWord);
            baseKey.SetValue("PanicSessionId", state.SessionId ?? string.Empty, RegistryValueKind.String);

            // Read existing HiddenProviders from registry so we NEVER overwrite or drop
            // ownership records captured by the native filter!
            var existingHiddenStrings = baseKey.GetValue("HiddenProviders") as string[] ?? Array.Empty<string>();
            var combinedHidden = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var s in existingHiddenStrings)
            {
                if (Guid.TryParse(s, out var g))
                {
                    string gKey = g.ToString("D");
                    if (state.RestoredProviders.Contains(gKey) || state.IndependentlyDeniedProviders.Contains(gKey))
                    {
                        // Successfully restored or independently denied: do NOT resurrect!
                        continue;
                    }
                    var provState = state.GetProvider(g);
                    if (provState != null && (!provState.HiddenByTether || provState.IndependentlyDenied))
                    {
                        // Explicitly restored or denied in managed state: do not include
                        continue;
                    }
                    combinedHidden.Add(g.ToString("B"));
                }
            }

            // Include providers from managed state that are hidden by Tether
            foreach (var prov in state.Providers.Values)
            {
                string pKey = prov.ProviderId.ToString("D");
                if (state.RestoredProviders.Contains(pKey) || state.IndependentlyDeniedProviders.Contains(pKey))
                {
                    continue;
                }
                if (prov.HiddenByTether && prov.OriginalVisibility && !prov.IndependentlyDenied)
                {
                    combinedHidden.Add(prov.ProviderId.ToString("B"));
                }
            }

            if (combinedHidden.Count > 0)
            {
                baseKey.SetValue("HiddenProviders", combinedHidden.ToArray(), RegistryValueKind.MultiString);
            }
            else
            {
                baseKey.DeleteValue("HiddenProviders", false);
            }

            // Write IndependentlyDeniedProviders
            var combinedDenied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in state.IndependentlyDeniedProviders)
            {
                if (Guid.TryParse(d, out var dg))
                {
                    combinedDenied.Add(dg.ToString("B"));
                }
            }
            foreach (var prov in state.Providers.Values)
            {
                if (prov.IndependentlyDenied)
                {
                    combinedDenied.Add(prov.ProviderId.ToString("B"));
                }
            }

            if (combinedDenied.Count > 0)
            {
                baseKey.SetValue("IndependentlyDeniedProviders", combinedDenied.ToArray(), RegistryValueKind.MultiString);
            }
            else
            {
                baseKey.DeleteValue("IndependentlyDeniedProviders", false);
            }

            byte[]? hmacKey = GetOrCreateHmacKey(baseKey, allowCreate: true);
            if (hmacKey == null)
            {
                throw new CryptographicException("Failed to obtain HMAC key for signing.");
            }

            var json = JsonSerializer.Serialize(state);

            using var hmac = new HMACSHA256(hmacKey);
            var digest = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
            CryptographicOperations.ZeroMemory(hmacKey);

            baseKey.SetValue("SessionData", json, RegistryValueKind.String);
            baseKey.SetValue("IntegrityDigest", digest, RegistryValueKind.Binary);

            baseKey.Flush();

            // Write IsPanicActive LAST to guarantee failure-safe atomic deactivation
            baseKey.SetValue("IsPanicActive", state.IsPanicActive ? 1 : 0, RegistryValueKind.DWord);
            baseKey.Flush();
        }
        catch (Exception ex)
        {
            _logger.Error($"WindowsRegistryPanicStore: Failed to save restoration state: {ex.Message}");
            throw;
        }
    }

    public void Clear()
    {
        try
        {
            using var baseKey = _rootKey.OpenSubKey(_baseRegistryPath, true);
            if (baseKey != null)
            {
                baseKey.DeleteValue("SessionData", false);
                baseKey.DeleteValue("IntegrityDigest", false);
                baseKey.DeleteValue("HiddenProviders", false);
                baseKey.DeleteValue("IndependentlyDeniedProviders", false);
                baseKey.DeleteValue("PanicSessionId", false);
                baseKey.SetValue("IsPanicActive", 0, RegistryValueKind.DWord);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"WindowsRegistryPanicStore: Clear failed: {ex.Message}");
        }
    }

    public bool VerifyAccessAcl()
    {
        try
        {
            if (!ReferenceEquals(_rootKey, Registry.LocalMachine))
            {
                // Under test root (e.g. CurrentUser in unit test), skip LocalMachine system DACL check
                return true;
            }

            using var baseKey = _rootKey.OpenSubKey(_baseRegistryPath, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadPermissions);
            if (baseKey == null) return false;

            var acl = baseKey.GetAccessControl();
            if (!acl.AreAccessRulesProtected) return false;

            var rules = acl.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));
            if (rules.Count == 0) return false;

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            bool hasSystem = false;
            bool hasAdmins = false;

            foreach (AuthorizationRule rule in rules)
            {
                if (rule is not RegistryAccessRule regRule)
                {
                    return false;
                }

                if (regRule.AccessControlType == AccessControlType.Deny)
                {
                    if (regRule.IdentityReference == systemSid || regRule.IdentityReference == adminsSid)
                    {
                        return false;
                    }
                }
                else if (regRule.AccessControlType == AccessControlType.Allow)
                {
                    var rights = regRule.RegistryRights;
                    var req = RegistryRights.ReadKey | RegistryRights.WriteKey;
                    if ((rights & req) != req && (rights & RegistryRights.FullControl) != RegistryRights.FullControl)
                    {
                        return false;
                    }

                    if (regRule.IdentityReference == systemSid)
                    {
                        hasSystem = true;
                    }
                    else if (regRule.IdentityReference == adminsSid)
                    {
                        hasAdmins = true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }

            return hasSystem && hasAdmins;
        }
        catch
        {
            return false;
        }
    }
}

public sealed class InMemoryPanicRestorationStore : IPanicRestorationStore
{
    private readonly object _storeLock = new();
    private PanicLockSessionState? _savedState;
    private byte[]? _integrityDigest;
    private bool _simulateTampering;
    private bool _simulateUnauthorizedAccess;
    private bool _simulateUnexpectedAce;
    private bool _simulateUnauthorizedAllow;
    private bool _simulateSaveFailure;
    private bool _simulatePartialWriteSessionData;
    private bool _simulateKeyCorruption;
    private bool _simulateDeleteFailure;
    private readonly List<Guid> _simulatedHiddenProviders = new();
    private readonly byte[] _hmacKey = RandomNumberGenerator.GetBytes(32);

    public bool SimulateTampering
    {
        get { lock (_storeLock) return _simulateTampering; }
        set { lock (_storeLock) _simulateTampering = value; }
    }

    public bool SimulateUnauthorizedAccess
    {
        get { lock (_storeLock) return _simulateUnauthorizedAccess; }
        set { lock (_storeLock) _simulateUnauthorizedAccess = value; }
    }

    public bool SimulateUnexpectedAce
    {
        get { lock (_storeLock) return _simulateUnexpectedAce; }
        set { lock (_storeLock) _simulateUnexpectedAce = value; }
    }

    public bool SimulateUnauthorizedAllow
    {
        get { lock (_storeLock) return _simulateUnauthorizedAllow; }
        set { lock (_storeLock) _simulateUnauthorizedAllow = value; }
    }

    public bool SimulateSaveFailure
    {
        get { lock (_storeLock) return _simulateSaveFailure; }
        set { lock (_storeLock) _simulateSaveFailure = value; }
    }

    public bool SimulatePartialWriteSessionData
    {
        get { lock (_storeLock) return _simulatePartialWriteSessionData; }
        set { lock (_storeLock) _simulatePartialWriteSessionData = value; }
    }

    public bool SimulateKeyCorruption
    {
        get { lock (_storeLock) return _simulateKeyCorruption; }
        set { lock (_storeLock) _simulateKeyCorruption = value; }
    }

    public bool SimulateDeleteFailure
    {
        get { lock (_storeLock) return _simulateDeleteFailure; }
        set { lock (_storeLock) _simulateDeleteFailure = value; }
    }

    public List<Guid> SimulatedHiddenProviders
    {
        get { lock (_storeLock) return _simulatedHiddenProviders; }
    }

    public PanicLockSessionState? Load()
    {
        lock (_storeLock)
        {
            if (_simulateUnauthorizedAccess)
            {
                throw new UnauthorizedAccessException("Simulated access denied by unprivileged ACL.");
            }

            if (_simulateKeyCorruption)
            {
                return null;
            }

            if (_savedState == null) return null;

            var json = JsonSerializer.Serialize(_savedState);
            using var hmac = new HMACSHA256(_hmacKey);
            var computed = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));

            if (_simulateTampering || _integrityDigest == null || !CryptographicOperations.FixedTimeEquals(_integrityDigest, computed))
            {
                return null;
            }

            var loaded = JsonSerializer.Deserialize<PanicLockSessionState>(json);
            if (loaded != null && _simulatedHiddenProviders.Count > 0)
            {
                foreach (var g in _simulatedHiddenProviders)
                {
                    string key = g.ToString("D");
                    if (!loaded.Providers.ContainsKey(key))
                    {
                        loaded.Providers[key] = new TrackedProviderState
                        {
                            ProviderId = g,
                            OriginalVisibility = true,
                            HiddenByTether = true,
                            CapturedAt = DateTimeOffset.UtcNow,
                            SessionId = loaded.SessionId
                        };
                    }
                }
            }

            return loaded;
        }
    }

    public void Save(PanicLockSessionState state)
    {
        lock (_storeLock)
        {
            if (_simulateSaveFailure)
            {
                throw new IOException("Simulated disk or registry write failure during panic save.");
            }

            if (_simulatePartialWriteSessionData)
            {
                _savedState = null;
                _integrityDigest = null;
                throw new IOException("Simulated partial write failure to SessionData/IntegrityDigest.");
            }

            if (_simulateUnauthorizedAccess)
            {
                throw new UnauthorizedAccessException("Simulated access denied by unprivileged ACL.");
            }

            if (_simulateKeyCorruption)
            {
                throw new CryptographicException("Simulated DPAPI HMAC unprotect failure.");
            }

            // Sync with simulated hidden providers
            foreach (var prov in state.Providers.Values)
            {
                string pKey = prov.ProviderId.ToString("D");
                if (state.RestoredProviders.Contains(pKey) || state.IndependentlyDeniedProviders.Contains(pKey))
                {
                    _simulatedHiddenProviders.Remove(prov.ProviderId);
                }
                else if (prov.HiddenByTether && !_simulatedHiddenProviders.Contains(prov.ProviderId))
                {
                    _simulatedHiddenProviders.Add(prov.ProviderId);
                }
                else if (!prov.HiddenByTether)
                {
                    _simulatedHiddenProviders.Remove(prov.ProviderId);
                }
            }

            foreach (var r in state.RestoredProviders)
            {
                if (Guid.TryParse(r, out var rg))
                {
                    _simulatedHiddenProviders.Remove(rg);
                }
            }

            foreach (var d in state.IndependentlyDeniedProviders)
            {
                if (Guid.TryParse(d, out var dg))
                {
                    _simulatedHiddenProviders.Remove(dg);
                }
            }

            var json = JsonSerializer.Serialize(state);
            using var hmac = new HMACSHA256(_hmacKey);
            _integrityDigest = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
            _savedState = JsonSerializer.Deserialize<PanicLockSessionState>(json);
        }
    }

    public void Clear()
    {
        lock (_storeLock)
        {
            if (_simulateUnauthorizedAccess)
            {
                throw new UnauthorizedAccessException("Simulated access denied by unprivileged ACL.");
            }

            if (_simulateDeleteFailure)
            {
                throw new IOException("Simulated registry delete failure.");
            }

            _savedState = null;
            _integrityDigest = null;
            _simulatedHiddenProviders.Clear();
        }
    }

    public bool VerifyAccessAcl()
    {
        lock (_storeLock)
        {
            return !_simulateUnauthorizedAccess && !_simulateUnexpectedAce && !_simulateUnauthorizedAllow;
        }
    }
}
