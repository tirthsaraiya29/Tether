using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
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

    // FIX: WTSGetActiveConsoleSessionId is exported by kernel32.dll, NOT wtsapi32.dll
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

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
            if (!string.IsNullOrEmpty(_localUiToken) && ValidateToken(_localUiToken, "LOCAL_UI"))
            {
                return _localUiToken;
            }

            Directory.CreateDirectory(DataDir);

            if (File.Exists(LocalTokenFile))
            {
                try
                {
                    EnsureFileAcl(LocalTokenFile);
                    var existing = File.ReadAllText(LocalTokenFile).Trim();
                    if (!string.IsNullOrEmpty(existing) && existing.Length >= 32)
                    {
                        _localUiToken = existing;
                        _tokens[_localUiToken] = new TokenMetaData(DateTimeOffset.UtcNow.AddDays(7), "LOCAL_UI");
                        return _localUiToken;
                    }
                }
                catch { }
            }

            byte[] bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            _localUiToken = Convert.ToHexString(bytes).ToLowerInvariant();

            try
            {
                File.WriteAllText(LocalTokenFile, _localUiToken);
                EnsureFileAcl(LocalTokenFile);
            }
            catch { }

            _tokens[_localUiToken] = new TokenMetaData(DateTimeOffset.UtcNow.AddDays(7), "LOCAL_UI");
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

    public static SecurityIdentifier? GetActiveConsoleUserSid()
    {
        // 1. Try active console session first
        try
        {
            uint consoleSessionId = WTSGetActiveConsoleSessionId();
            if (consoleSessionId != 0xFFFFFFFF && TryGetSidFromSession(consoleSessionId, out var sid))
            {
                return sid;
            }
        }
        catch { }

        // 2. Fallback: Search common interactive user session IDs (e.g., Session 1 to 10)
        for (uint s = 1; s <= 10; s++)
        {
            try
            {
                if (TryGetSidFromSession(s, out var sid))
                {
                    return sid;
                }
            }
            catch { }
        }

        return null;
    }

    private static bool TryGetSidFromSession(uint sessionId, out SecurityIdentifier? userSid)
    {
        userSid = null;
        if (WTSQueryUserToken(sessionId, out IntPtr hToken))
        {
            try
            {
                using var wi = new System.Security.Principal.WindowsIdentity(hToken);
                if (wi.User != null &&
                    !wi.User.IsWellKnown(WellKnownSidType.LocalSystemSid) &&
                    !wi.User.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                {
                    userSid = wi.User;
                    return true;
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }
        return false;
    }

    public static void EnsureFileAcl(string filePath)
    {
        try
        {
            var fi = new FileInfo(filePath);
            if (fi.Exists)
            {
                fi.Attributes = FileAttributes.Normal;
            }

            var sec = new FileSecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            sec.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));

            // Grant Read strictly to the active logged-in desktop user
            var consoleUserSid = GetActiveConsoleUserSid();
            if (consoleUserSid != null)
            {
                sec.AddAccessRule(new FileSystemAccessRule(consoleUserSid, FileSystemRights.Read, AccessControlType.Allow));
            }

            try
            {
                var currentSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                if (currentSid != null &&
                    !currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid) &&
                    !currentSid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                {
                    sec.AddAccessRule(new FileSystemAccessRule(currentSid, FileSystemRights.FullControl, AccessControlType.Allow));
                }
            }
            catch { }

            fi.SetAccessControl(sec);
        }
        catch { }
    }
}