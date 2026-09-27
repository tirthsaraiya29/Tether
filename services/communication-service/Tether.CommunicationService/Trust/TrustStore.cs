// services/communication-service/Tether.CommunicationService/Trust/TrustStore.cs
using System;
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
    [JsonPropertyName("protocolVersion")] public string ProtocolVersion { get; init; } = "1.0";
}

public sealed class TrustStore
{
    private static readonly string DataDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether");
    private static readonly string DataFile = Path.Combine(DataDir, "trust.json");

    private readonly ITetherLogger _logger;
    private readonly object _gate = new();
    private readonly Dictionary<string, TrustedPhone> _byFingerprint = new(StringComparer.OrdinalIgnoreCase);

    public TrustStore(ITetherLogger logger)
    {
        _logger = logger;
        Load();
    }

    public bool IsEmpty => _byFingerprint.Count == 0;

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
            if (!File.Exists(DataFile)) return;
            var json = File.ReadAllText(DataFile);
            var list = JsonSerializer.Deserialize<List<TrustedPhone>>(json) ?? new();
            foreach (var entry in list)
                _byFingerprint[entry.Fingerprint] = entry;
            _logger.Info($"Trust store loaded: {_byFingerprint.Count} paired phone(s).");
        }
        catch (Exception ex)
        {
            _logger.Error($"Trust store load failed: {ex.Message}");
        }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            EnsureDirAcl();
            var snapshot = All();
            var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(DataFile, json);
        }
        catch (Exception ex)
        {
            _logger.Error($"Trust store save failed: {ex.Message}");
        }
    }

    private static void EnsureDirAcl()
    {
        try
        {
            var di = new DirectoryInfo(DataDir);
            var sec = di.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            sec.AddAccessRule(new FileSystemAccessRule(systemSid,
                FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(adminSid,
                FileSystemRights.FullControl, AccessControlType.Allow));

            di.SetAccessControl(sec);
        }
        catch { /* best effort */ }
    }
}