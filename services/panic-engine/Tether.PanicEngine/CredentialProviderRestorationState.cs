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
    private static readonly byte[] SystemBoundEntropy = Encoding.UTF8.GetBytes("Tether_System_Bound_Vault_v1");
    private readonly ITetherLogger _logger;

    public WindowsRegistryPanicStore(ITetherLogger logger)
    {
        _logger = logger;
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

            var json = baseKey.GetValue("SessionData") as string;
            var storedDigest = baseKey.GetValue("IntegrityDigest") as byte[];

            if (string.IsNullOrWhiteSpace(json) || storedDigest == null || storedDigest.Length == 0)
            {
                return null;
            }

            // Verify payload integrity using system-bound HMAC
            using var hmac = new HMACSHA256(SystemBoundEntropy);
            var computedDigest = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));
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
                return;
            }

            baseKey.SetAccessControl(rs);
            baseKey.SetValue("VaultDaclVersion", 2, RegistryValueKind.DWord);
            baseKey.SetValue("IsPanicActive", state.IsPanicActive ? 1 : 0, RegistryValueKind.DWord);

            var json = JsonSerializer.Serialize(state);
            using var hmac = new HMACSHA256(SystemBoundEntropy);
            var digest = hmac.ComputeHash(Encoding.UTF8.GetBytes(json));

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
            if (baseKey == null) return true;

            var acl = baseKey.GetAccessControl();
            if (acl.AreAccessRulesProtected)
            {
                return true;
            }
            return false;
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
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Tether_System_Bound_Vault_v1");

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
            using var hmac = new HMACSHA256(Entropy);
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
            if (_simulateUnauthorizedAccess)
            {
                throw new UnauthorizedAccessException("Simulated access denied by unprivileged ACL.");
            }

            var json = JsonSerializer.Serialize(state);
            using var hmac = new HMACSHA256(Entropy);
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
