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
    private const string BaseRegistryPath = @"SOFTWARE\Tether\PanicLock";
    private readonly ITetherLogger _logger;

    public WindowsRegistryPanicStore(ITetherLogger logger)
    {
        _logger = logger;
    }

    private static byte[] GetOrCreateHmacKey(RegistryKey key)
    {
        var blob = key.GetValue("IntegrityKeyBlob") as byte[];
        if (blob != null && blob.Length > 0)
        {
            try
            {
                return ProtectedData.Unprotect(blob, null, DataProtectionScope.LocalMachine);
            }
            catch
            {
                // Key corrupted or unprotect failed, fall through to regenerate
            }
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
            using var baseKey = Registry.LocalMachine.OpenSubKey(BaseRegistryPath, false);
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

            var json = baseKey.GetValue("SessionData") as string;
            var storedDigest = baseKey.GetValue("IntegrityDigest") as byte[];

            if (string.IsNullOrWhiteSpace(json) || storedDigest == null || storedDigest.Length == 0)
            {
                return null;
            }

            byte[] hmacKey;
            try
            {
                hmacKey = GetOrCreateHmacKey(baseKey);
            }
            catch (Exception ex)
            {
                _logger.Error($"WindowsRegistryPanicStore: Failed to obtain DPAPI protected HMAC key: {ex.Message}");
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

            return JsonSerializer.Deserialize<PanicLockSessionState>(json);
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
            var rs = new RegistrySecurity();
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            rs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            rs.AddAccessRule(new RegistryAccessRule(systemSid, RegistryRights.FullControl, AccessControlType.Allow));
            rs.AddAccessRule(new RegistryAccessRule(adminsSid, RegistryRights.FullControl, AccessControlType.Allow));

            using var baseKey = Registry.LocalMachine.CreateSubKey(BaseRegistryPath, RegistryKeyPermissionCheck.ReadWriteSubTree, rs);
            if (baseKey == null)
            {
                _logger.Error("WindowsRegistryPanicStore: Unable to create or open PanicLock registry key.");
                throw new InvalidOperationException("Failed to open or create HKLM\\SOFTWARE\\Tether\\PanicLock key.");
            }

            baseKey.SetAccessControl(rs);
            baseKey.SetValue("VaultDaclVersion", 2, RegistryValueKind.DWord);
            baseKey.SetValue("IsPanicActive", state.IsPanicActive ? 1 : 0, RegistryValueKind.DWord);
            baseKey.SetValue("PanicSessionId", state.SessionId ?? string.Empty, RegistryValueKind.String);

            var hiddenGuids = state.Providers.Values
                .Where(p => p.HiddenByTether && p.OriginalVisibility)
                .Select(p => p.ProviderId.ToString("B"))
                .ToArray();
            baseKey.SetValue("HiddenProviders", hiddenGuids, RegistryValueKind.MultiString);

            byte[] hmacKey = GetOrCreateHmacKey(baseKey);
            var json = JsonSerializer.Serialize(state);

            using var hmac = new HMACSHA256(hmacKey);
            var digest = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
            CryptographicOperations.ZeroMemory(hmacKey);

            baseKey.SetValue("SessionData", json, RegistryValueKind.String);
            baseKey.SetValue("IntegrityDigest", digest, RegistryValueKind.Binary);
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
            using var baseKey = Registry.LocalMachine.OpenSubKey(BaseRegistryPath, true);
            if (baseKey != null)
            {
                baseKey.DeleteValue("SessionData", false);
                baseKey.DeleteValue("IntegrityDigest", false);
                baseKey.DeleteValue("HiddenProviders", false);
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
            using var baseKey = Registry.LocalMachine.OpenSubKey(BaseRegistryPath, RegistryKeyPermissionCheck.ReadSubTree, RegistryRights.ReadPermissions);
            if (baseKey == null) return false;

            var acl = baseKey.GetAccessControl();
            if (!acl.AreAccessRulesProtected) return false;

            var rules = acl.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));
            if (rules.Count == 0) return false;

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            bool hasSystem = false;
            bool hasAdmins = false;

            foreach (RegistryAccessRule rule in rules)
            {
                if (rule.AccessControlType == AccessControlType.Deny)
                {
                    if (rule.IdentityReference == systemSid || rule.IdentityReference == adminsSid)
                    {
                        return false;
                    }
                }
                else if (rule.AccessControlType == AccessControlType.Allow)
                {
                    if (rule.IdentityReference == systemSid)
                    {
                        hasSystem = true;
                    }
                    else if (rule.IdentityReference == adminsSid)
                    {
                        hasAdmins = true;
                    }
                    else
                    {
                        return false;
                    }
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
    private bool _simulateSaveFailure;
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

    public bool SimulateSaveFailure
    {
        get { lock (_storeLock) return _simulateSaveFailure; }
        set { lock (_storeLock) _simulateSaveFailure = value; }
    }

    public PanicLockSessionState? Load()
    {
        lock (_storeLock)
        {
            if (_simulateUnauthorizedAccess)
            {
                throw new UnauthorizedAccessException("Simulated access denied by unprivileged ACL.");
            }

            if (_savedState == null) return null;

            var json = JsonSerializer.Serialize(_savedState);
            using var hmac = new HMACSHA256(_hmacKey);
            var computed = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));

            if (_simulateTampering || _integrityDigest == null || !CryptographicOperations.FixedTimeEquals(_integrityDigest, computed))
            {
                return null;
            }

            return JsonSerializer.Deserialize<PanicLockSessionState>(json);
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

            if (_simulateUnauthorizedAccess)
            {
                throw new UnauthorizedAccessException("Simulated access denied by unprivileged ACL.");
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

            _savedState = null;
            _integrityDigest = null;
        }
    }

    public bool VerifyAccessAcl()
    {
        lock (_storeLock)
        {
            return !_simulateUnauthorizedAccess;
        }
    }
}
