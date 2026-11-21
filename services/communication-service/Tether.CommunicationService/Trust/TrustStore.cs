using System.Text;
﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Trust;

public sealed record TrustedPhone
{
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = "";
    [JsonPropertyName("displayName")] public string DisplayName { get; init; } = "";
    [JsonPropertyName("publicKeySpki")] public string PublicKeySpkiBase64 { get; init; } = "";
    [JsonPropertyName("fingerprint")] public string Fingerprint { get; init; } = "";
    [JsonPropertyName("pairedAtUtc")] public DateTime PairedAtUtc { get; init; }
    [JsonPropertyName("lastSeenUtc")] public DateTime LastSeenUtc { get; set; }
    [JsonPropertyName("capabilities")] public List<string> Capabilities { get; init; } = new();
    [JsonPropertyName("protocolVersion")] public string ProtocolVersion { get; init; } = "2.0";
}

public sealed class TrustStore
{
    private static readonly string DefaultDataDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether");
    private readonly string _dataDir;
    private readonly string _dataFile;

    private static readonly byte[] DpapiEntropy = "Tether_TrustStore_DPAPI_Entropy_v1"u8.ToArray();
    private static readonly object _fileLock = new();
    private readonly ITetherLogger _logger;
    private readonly object _gate = new();
    private readonly Dictionary<string, TrustedPhone> _byFingerprint = new(StringComparer.OrdinalIgnoreCase);

    public TrustStore(ITetherLogger logger, string? customDataDir = null)
    {
        _logger = logger;
        _dataDir = customDataDir ?? DefaultDataDir;
        _dataFile = Path.Combine(_dataDir, "trust.json");
        Load();
    }

    public bool IsEmpty
    {
        get
        {
            lock (_gate) return _byFingerprint.Count == 0;
        }
    }

    public IReadOnlyCollection<TrustedPhone> All()
    {
        lock (_gate) return _byFingerprint.Values.ToArray();
    }

    public TrustedPhone? FindBySpkiBase64(string spkiBase64)
    {
        var fp = ComputeFingerprintOrNull(spkiBase64);
        if (fp is null) return null;
        lock (_gate) return _byFingerprint.TryGetValue(fp, out var d) ? d : null;
    }

    public TrustedPhone AddOrUpdate(string deviceId, string displayName, string spkiBase64,
                                    IEnumerable<string> capabilities, string protocolVersion)
    {
        var fingerprint = ComputeFingerprintOrNull(spkiBase64)
            ?? throw new ArgumentException("Invalid SPKI in trust store update.", nameof(spkiBase64));

        var entry = new TrustedPhone
        {
            DeviceId = string.IsNullOrEmpty(deviceId) ? fingerprint : deviceId,
            DisplayName = displayName,
            PublicKeySpkiBase64 = spkiBase64,
            Fingerprint = fingerprint,
            PairedAtUtc = DateTime.UtcNow,
            LastSeenUtc = DateTime.UtcNow,
            Capabilities = capabilities.ToList(),
            ProtocolVersion = protocolVersion
        };

        lock (_gate)
        {
            if (_byFingerprint.TryGetValue(fingerprint, out var existing))
                entry = entry with { PairedAtUtc = existing.PairedAtUtc };
            _byFingerprint[fingerprint] = entry;
        }

        Save();
        _logger.Info($"Trust store: pinned phone {fingerprint} ({displayName}).");
        return entry;
    }

    public void Touch(string fingerprint)
    {
        lock (_gate)
        {
            if (!_byFingerprint.TryGetValue(fingerprint, out var entry)) return;
            entry.LastSeenUtc = DateTime.UtcNow;
        }
        Save();
    }

    public bool Remove(string fingerprint)
    {
        bool removed;
        lock (_gate) removed = _byFingerprint.Remove(fingerprint);
        if (removed) { Save(); _logger.Info($"Trust store: revoked phone {fingerprint}."); }
        return removed;
    }

    public void Clear()
    {
        lock (_gate) _byFingerprint.Clear();
        Save();
        _logger.Info("Trust store: cleared.");
    }

    public static string? ComputeFingerprintOrNull(string spkiBase64)
    {
        try
        {
            var spki = Convert.FromBase64String(spkiBase64);
            var hash = SHA256.HashData(spki);
            return string.Join(":", hash.Select(b => b.ToString("X2")));
        }
        catch { return null; }
    }

    private void Load()
    {
        try
        {
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var currentSid = WindowsIdentity.GetCurrent().User;

            if (Directory.Exists(_dataDir))
            {
                var di = new DirectoryInfo(_dataDir);
                if ((di.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    _logger.Warning($"TrustStore: Reparse point detected on DataDir '{_dataDir}'. Removing junction.");
                    Directory.Delete(_dataDir, false);
                }
                else
                {
                    try
                    {
                        var dirSec = di.GetAccessControl(AccessControlSections.Owner);
                        var dirOwner = dirSec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                        bool isDirOwnerTrusted = dirOwner != null &&
                            (dirOwner.Equals(systemSid) || dirOwner.Equals(adminSid) || (currentSid != null && dirOwner.Equals(currentSid)));
                        if (!isDirOwnerTrusted)
                        {
                            _logger.Warning($"TrustStore: Untrusted owner '{dirOwner}' on DataDir '{_dataDir}'. Recreating directory.");
                            Directory.Delete(_dataDir, true);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"TrustStore: Could not verify DataDir owner: {ex.Message}");
                    }
                }
            }

            Directory.CreateDirectory(_dataDir);
            EnsureStorageAcls(_dataDir);

            if (!File.Exists(_dataFile)) return;

            var fi = new FileInfo(_dataFile);
            if ((fi.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                _logger.Warning($"TrustStore: Reparse point detected on DataFile '{_dataFile}'. Removing file.");
                File.Delete(_dataFile);
                return;
            }

            try
            {
                var fileSec = fi.GetAccessControl(AccessControlSections.Owner);
                var fileOwner = fileSec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                bool isFileOwnerTrusted = fileOwner != null &&
                    (fileOwner.Equals(systemSid) || fileOwner.Equals(adminSid) || (currentSid != null && fileOwner.Equals(currentSid)));
                if (!isFileOwnerTrusted)
                {
                    _logger.Warning($"TrustStore: Untrusted owner '{fileOwner}' on DataFile '{_dataFile}'. Discarding untrusted store.");
                    File.Delete(_dataFile);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.Warning($"TrustStore: Could not verify DataFile owner: {ex.Message}");
            }

            byte[] rawBytes = File.ReadAllBytes(_dataFile);
            if (rawBytes.Length == 0) return;

            string json;
            bool wasPlaintext = false;

            int firstNonWs = 0;
            while (firstNonWs < rawBytes.Length && char.IsWhiteSpace((char)rawBytes[firstNonWs])) firstNonWs++;

            if (firstNonWs < rawBytes.Length && (rawBytes[firstNonWs] == (byte)'[' || rawBytes[firstNonWs] == (byte)'{'))
            {
                json = Encoding.UTF8.GetString(rawBytes);
                wasPlaintext = true;
            }
            else
            {
                byte[] plainBytes = ProtectedData.Unprotect(rawBytes, DpapiEntropy, DataProtectionScope.LocalMachine);
                json = Encoding.UTF8.GetString(plainBytes);
            }

            var list = JsonSerializer.Deserialize<List<TrustedPhone>>(json) ?? new();
            lock (_gate)
            {
                _byFingerprint.Clear();
                foreach (var entry in list)
                {
                    if (string.IsNullOrWhiteSpace(entry.PublicKeySpkiBase64))
                    {
                        _logger.Warning($"TrustStore: Entry '{entry.DisplayName}' has empty SPKI key. Discarding.");
                        continue;
                    }

                    string? computedFp = ComputeFingerprintOrNull(entry.PublicKeySpkiBase64);
                    if (computedFp == null || !string.Equals(computedFp, entry.Fingerprint, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.Warning($"TrustStore: Fingerprint mismatch for entry '{entry.DisplayName}' (stored: '{entry.Fingerprint}', computed: '{computedFp}'). Discarding.");
                        continue;
                    }

                    _byFingerprint[entry.Fingerprint] = entry;
                }
            }
            _logger.Info($"Trust store loaded: {_byFingerprint.Count} paired phone(s).");

            if (wasPlaintext)
            {
                _logger.Info("Trust store: migrating legacy plaintext storage to DPAPI LocalMachine encryption.");
                Save();
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Trust store load failed: {ex.Message}");
        }
    }

    private void Save()
    {
        lock (_fileLock)
        {
            try
            {
                Directory.CreateDirectory(_dataDir);
                EnsureStorageAcls(_dataDir);

                var snapshot = All();
                var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });
                byte[] plainBytes = Encoding.UTF8.GetBytes(json);
                byte[] cipherBytes = ProtectedData.Protect(plainBytes, DpapiEntropy, DataProtectionScope.LocalMachine);

                string tempFile = Path.Combine(_dataDir, $"trust_{Guid.NewGuid():N}.tmp");
                File.WriteAllBytes(tempFile, cipherBytes);

                if (File.Exists(_dataFile))
                {
                    File.SetAttributes(_dataFile, FileAttributes.Normal);
                }

                File.Move(tempFile, _dataFile, overwrite: true);
                EnsureFileAcl(_dataFile);
            }
            catch (Exception ex)
            {
                _logger.Error($"Trust store save failed: {ex.Message}");
            }
        }
    }

    private static void EnsureStorageAcls(string dir)
    {
        try
        {
            var di = new DirectoryInfo(dir);
            var sec = new DirectorySecurity();
            // Explicitly strip inherited and stale entries
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var currentIdentity = WindowsIdentity.GetCurrent().User;

            sec.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            sec.AddAccessRule(new FileSystemAccessRule(
                adminSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            if (currentIdentity != null && !currentIdentity.Equals(systemSid) && !currentIdentity.Equals(adminSid))
            {
                sec.AddAccessRule(new FileSystemAccessRule(
                    currentIdentity,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }

            di.SetAccessControl(sec);
        }
        catch { /* best effort */ }
    }

    private static void EnsureFileAcl(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return;

            var fi = new FileInfo(filePath);
            fi.Attributes = FileAttributes.Normal;

            var sec = new FileSecurity();
            // Explicitly strip inherited and stale entries
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var currentIdentity = WindowsIdentity.GetCurrent().User;

            sec.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));

            if (currentIdentity != null && !currentIdentity.Equals(systemSid) && !currentIdentity.Equals(adminSid))
            {
                sec.AddAccessRule(new FileSystemAccessRule(currentIdentity, FileSystemRights.FullControl, AccessControlType.Allow));
            }

            fi.SetAccessControl(sec);
        }
        catch { /* best effort */ }
    }
}