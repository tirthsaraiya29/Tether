using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Tether.LinuxDaemon.Config;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Trust;

public sealed record TrustedPhoneRecord
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

public sealed class LinuxTrustStore
{
    private static readonly byte[] KeyDerivationSalt = "Tether_Linux_TrustStore_Salt_v1"u8.ToArray();
    private static readonly byte[] Magic = "TLTS"u8.ToArray(); // Tether Linux Trust Store

    private readonly ITetherLogger _logger;
    private readonly LinuxDaemonConfig _config;
    private readonly string _dataFile;
    private readonly object _gate = new();
    private readonly Dictionary<string, TrustedPhoneRecord> _byFingerprint = new(StringComparer.OrdinalIgnoreCase);

    public LinuxTrustStore(ITetherLogger logger, LinuxDaemonConfig config)
    {
        _logger = logger;
        _config = config;
        _config.EnsureDirectories();
        _dataFile = Path.Combine(_config.DataDir, "trust.json");
        Load();
    }

    public bool IsEmpty
    {
        get
        {
            lock (_gate) return _byFingerprint.Count == 0;
        }
    }

    public IReadOnlyCollection<TrustedPhoneRecord> All()
    {
        lock (_gate) return _byFingerprint.Values.ToArray();
    }

    public TrustedPhoneRecord? FindByFingerprint(string fingerprint)
    {
        lock (_gate) return _byFingerprint.TryGetValue(fingerprint, out var d) ? d : null;
    }

    public TrustedPhoneRecord? FindBySpkiBase64(string spkiBase64)
    {
        var fp = ComputeFingerprintOrNull(spkiBase64);
        if (fp is null) return null;
        return FindByFingerprint(fp);
    }

    public TrustedPhoneRecord AddOrUpdate(string deviceId, string displayName, string spkiBase64,
                                          IEnumerable<string> capabilities, string protocolVersion)
    {
        var fingerprint = ComputeFingerprintOrNull(spkiBase64)
            ?? throw new ArgumentException("Invalid SPKI in trust store update.", nameof(spkiBase64));

        var entry = new TrustedPhoneRecord
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
            {
                entry = entry with { PairedAtUtc = existing.PairedAtUtc };
            }
            _byFingerprint[fingerprint] = entry;
        }

        Save();
        _logger.Info($"Linux trust store: pinned phone {fingerprint} ('{displayName}').");
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
        if (removed)
        {
            Save();
            _logger.Info($"Linux trust store: revoked phone {fingerprint}.");
        }
        return removed;
    }

    public void Clear()
    {
        lock (_gate) _byFingerprint.Clear();
        Save();
        _logger.Info("Linux trust store: cleared all paired devices.");
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

    private byte[] GetEncryptionKey()
    {
        string machineId = "fallback-machine-id";
        if (File.Exists("/etc/machine-id"))
        {
            machineId = File.ReadAllText("/etc/machine-id").Trim();
        }
        else if (File.Exists("/var/lib/dbus/machine-id"))
        {
            machineId = File.ReadAllText("/var/lib/dbus/machine-id").Trim();
        }

        byte[] pwdBytes = Encoding.UTF8.GetBytes(machineId);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(pwdBytes, KeyDerivationSalt, 100_000, HashAlgorithmName.SHA256, 32);
        CryptographicOperations.ZeroMemory(pwdBytes);
        return key;
    }

    private void Load()
    {
        lock (_gate)
        {
            _byFingerprint.Clear();
            if (!File.Exists(_dataFile)) return;

            try
            {
                byte[] raw = File.ReadAllBytes(_dataFile);
                if (raw.Length == 0) return;

                string json;
                if (raw.Length > 4 + 12 + 16 && raw.AsSpan(0, 4).SequenceEqual(Magic))
                {
                    // AES-GCM encrypted
                    byte[] key = GetEncryptionKey();
                    try
                    {
                        var nonce = raw.AsSpan(4, 12);
                        var tag = raw.AsSpan(16, 16);
                        var cipher = raw.AsSpan(32);
                        var plain = new byte[cipher.Length];

                        using var aes = new AesGcm(key, 16);
                        aes.Decrypt(nonce, cipher, tag, plain);
                        json = Encoding.UTF8.GetString(plain);
                        CryptographicOperations.ZeroMemory(plain);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(key);
                    }
                }
                else
                {
                    // Plaintext fallback (e.g. initial import)
                    json = Encoding.UTF8.GetString(raw);
                }

                var list = JsonSerializer.Deserialize<List<TrustedPhoneRecord>>(json);
                if (list != null)
                {
                    foreach (var record in list)
                    {
                        if (!string.IsNullOrEmpty(record.Fingerprint))
                        {
                            _byFingerprint[record.Fingerprint] = record;
                        }
                    }
                }
                _logger.Info($"Linux trust store loaded {_byFingerprint.Count} trusted device(s).");
            }
            catch (Exception ex)
            {
                _logger.Error($"Linux trust store load failed: {ex.Message}");
            }
        }
    }

    private void Save()
    {
        lock (_gate)
        {
            try
            {
                var list = _byFingerprint.Values.ToList();
                byte[] plainBytes = JsonSerializer.SerializeToUtf8Bytes(list, new JsonSerializerOptions { WriteIndented = false });

                byte[] key = GetEncryptionKey();
                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                byte[] tag = new byte[16];
                byte[] cipher = new byte[plainBytes.Length];

                try
                {
                    using var aes = new AesGcm(key, 16);
                    aes.Encrypt(nonce, plainBytes, cipher, tag);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                    CryptographicOperations.ZeroMemory(plainBytes);
                }

                byte[] result = new byte[4 + 12 + 16 + cipher.Length];
                Buffer.BlockCopy(Magic, 0, result, 0, 4);
                Buffer.BlockCopy(nonce, 0, result, 4, 12);
                Buffer.BlockCopy(tag, 0, result, 16, 16);
                Buffer.BlockCopy(cipher, 0, result, 32, cipher.Length);

                string tmpFile = _dataFile + ".tmp";
                File.WriteAllBytes(tmpFile, result);

                if (OperatingSystem.IsLinux())
                {
                    try
                    {
                        File.SetUnixFileMode(tmpFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    }
                    catch { }
                }

                File.Move(tmpFile, _dataFile, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger.Error($"Linux trust store save failed: {ex.Message}");
            }
        }
    }
}
