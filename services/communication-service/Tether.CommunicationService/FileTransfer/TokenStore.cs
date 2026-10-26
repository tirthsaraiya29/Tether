using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Tether.CommunicationService.Security;

namespace Tether.CommunicationService.FileTransfer;

public class TokenStore
{
    private sealed record TokenMetaData(DateTimeOffset Expiry, string? DeviceFingerprint);

    private readonly ConcurrentDictionary<string, TokenMetaData> _tokens = new(StringComparer.Ordinal);
    private string? _localUiToken;
    private readonly object _lock = new();

    private static readonly string DataDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether");
    private static readonly string LocalTokenFile = Path.Combine(DataDir, "local_ui_token.txt");

    public string GenerateToken(TimeSpan validFor, string? deviceFingerprint = null)
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var token = Convert.ToHexString(bytes).ToLowerInvariant();

        _tokens[token] = new TokenMetaData(DateTimeOffset.UtcNow.Add(validFor), deviceFingerprint);
        Cleanup();
        return token;
    }

    public string GetOrCreateLocalUiToken()
    {
        lock (_lock)
        {
            if (!string.IsNullOrEmpty(_localUiToken) && ValidateToken(_localUiToken))
            {
                return _localUiToken;
            }

            try
            {
                Directory.CreateDirectory(DataDir);
                if (File.Exists(LocalTokenFile))
                {
                    var existing = File.ReadAllText(LocalTokenFile).Trim();
                    if (!string.IsNullOrEmpty(existing) && existing.Length >= 32)
                    {
                        _localUiToken = existing;
                        _tokens[_localUiToken] = new TokenMetaData(DateTimeOffset.UtcNow.AddDays(365), "LOCAL_UI");
                        return _localUiToken;
                    }
                }
            }
            catch { }

            byte[] bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            _localUiToken = Convert.ToHexString(bytes).ToLowerInvariant();

            try
            {
                Directory.CreateDirectory(DataDir);
                File.WriteAllText(LocalTokenFile, _localUiToken);
                EnsureFileAcl(LocalTokenFile);
            }
            catch { }

            _tokens[_localUiToken] = new TokenMetaData(DateTimeOffset.UtcNow.AddDays(365), "LOCAL_UI");
            return _localUiToken;
        }
    }

    public bool ValidateToken(string token, string? expectedDeviceFingerprint = null)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;

        if (_tokens.TryGetValue(token, out var metadata))
        {
            if (DateTimeOffset.UtcNow <= metadata.Expiry)
            {
                if (expectedDeviceFingerprint != null)
                {
                    if (string.Equals(expectedDeviceFingerprint, "LOCAL_UI", StringComparison.Ordinal))
                    {
                        if (metadata.DeviceFingerprint != null &&
                            !string.Equals(metadata.DeviceFingerprint, "LOCAL_UI", StringComparison.Ordinal))
                        {
                            return false;
                        }
                    }
                    else
                    {
                        if (metadata.DeviceFingerprint != null &&
                            string.Equals(metadata.DeviceFingerprint, "LOCAL_UI", StringComparison.Ordinal))
                        {
                            return false;
                        }
                        if (metadata.DeviceFingerprint != null &&
                            !string.Equals(metadata.DeviceFingerprint, expectedDeviceFingerprint, StringComparison.OrdinalIgnoreCase))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }
            _tokens.TryRemove(token, out _);
        }
        return false;
    }

    public bool TryGetTokenMetadata(string token, out (DateTimeOffset Expiry, string? DeviceFingerprint) metadata)
    {
        metadata = default;
        if (string.IsNullOrWhiteSpace(token)) return false;
        if (_tokens.TryGetValue(token, out var data))
        {
            metadata = (data.Expiry, data.DeviceFingerprint);
            return true;
        }
        return false;
    }

    public bool RevokeToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;
        return _tokens.TryRemove(token, out _);
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _tokens)
        {
            if (now > kvp.Value.Expiry)
            {
                _tokens.TryRemove(kvp.Key, out _);
            }
        }
    }

    private static void EnsureFileAcl(string filePath)
    {
        try
        {
            var fi = new FileInfo(filePath);
            var sec = fi.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var interactiveSid = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);

            sec.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(interactiveSid, FileSystemRights.Read, AccessControlType.Allow));

            try
            {
                var userSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                if (userSid != null)
                {
                    sec.AddAccessRule(new FileSystemAccessRule(userSid, FileSystemRights.FullControl, AccessControlType.Allow));
                }
            }
            catch { }

            fi.SetAccessControl(sec);
        }
        catch { }
    }
}
