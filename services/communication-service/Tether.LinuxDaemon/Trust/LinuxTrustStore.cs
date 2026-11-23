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
    private static readonly byte[] LegacyKeyDerivationSalt = "Tether_Linux_TrustStore_Salt_v1"u8.ToArray();
    private static readonly byte[] Magic = "TLTS"u8.ToArray(); // Tether Linux Trust Store
    private const string KeyPurposeInfo = "Tether_Linux_TrustStore_v2";

    private readonly ITetherLogger _logger;
    private readonly LinuxDaemonConfig _config;
    private readonly string _dataFile;
    private readonly string _keyFile;
    private readonly object _gate = new();
    private readonly Dictionary<string, TrustedPhoneRecord> _byFingerprint = new(StringComparer.OrdinalIgnoreCase);

    public LinuxTrustStore(ITetherLogger logger, LinuxDaemonConfig config)
    {
        _logger = logger;
        _config = config;
        _config.EnsureDirectories();
        _dataFile = Path.Combine(_config.DataDir, "trust.json");
        _keyFile = Path.Combine(_config.DataDir, "trust.key");
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

    private byte[] GetOrCreateMasterKey()
    {
        if (File.Exists(_keyFile))
        {
            try
            {
                byte[] existingKey = File.ReadAllBytes(_keyFile);
                if (existingKey.Length == 32)
                {
                    return existingKey;
                }
            }
            catch { }
        }

        // Generate fresh 256-bit cryptographically secure master key
        byte[] freshKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            string tmpKeyFile = _keyFile + ".tmp";
            File.WriteAllBytes(tmpKeyFile, freshKey);

            if (OperatingSystem.IsLinux())
            {
                try
                {
                    File.SetUnixFileMode(tmpKeyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
                catch { }
            }

            File.Move(tmpKeyFile, _keyFile, overwrite: true);

            if (OperatingSystem.IsLinux())
            {
                try
                {
                    File.SetUnixFileMode(_keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"Could not persist trust.key with restricted permissions: {ex.Message}");
        }

        return freshKey;
    }

    private static string GetMachineId()
    {
        if (File.Exists("/etc/machine-id"))
        {
            return File.ReadAllText("/etc/machine-id").Trim();
        }
        if (File.Exists("/var/lib/dbus/machine-id"))
        {
            return File.ReadAllText("/var/lib/dbus/machine-id").Trim();
        }
        return Environment.MachineName;
    }

    private byte[] GetV2EncryptionKey()
    {
        byte[] masterKey = GetOrCreateMasterKey();
        byte[] machineIdBytes = Encoding.UTF8.GetBytes(GetMachineId());
        byte[] purposeBytes = Encoding.UTF8.GetBytes(KeyPurposeInfo);

        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, 32, machineIdBytes, purposeBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(machineIdBytes);
        }
    }

    private static byte[] GetLegacyV1EncryptionKey()
    {
        string machineId = GetMachineId();
        byte[] pwdBytes = Encoding.UTF8.GetBytes(machineId);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(pwdBytes, LegacyKeyDerivationSalt, 100_000, HashAlgorithmName.SHA256, 32);
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

                string? json = null;
                bool needsMigration = false;

                if (raw.Length > 4 + 12 + 16 && raw.AsSpan(0, 4).SequenceEqual(Magic))
                {
                    var nonce = raw.AsSpan(4, 12);
                    var tag = raw.AsSpan(16, 16);
                    var cipher = raw.AsSpan(32);
                    var plain = new byte[cipher.Length];

                    // 1. Try V2 Master-Key decryption
                    byte[] v2Key = GetV2EncryptionKey();
                    bool decrypted = false;
                    try
                    {
                        using var aes = new AesGcm(v2Key, 16);
                        aes.Decrypt(nonce, cipher, tag, plain);
                        json = Encoding.UTF8.GetString(plain);
                        decrypted = true;
                    }
                    catch
                    {
                        // V2 failed: attempt legacy V1 decryption for migration
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(v2Key);
                    }

                    if (!decrypted)
                    {
                        byte[] v1Key = GetLegacyV1EncryptionKey();
                        try
                        {
                            using var aes = new AesGcm(v1Key, 16);
                            aes.Decrypt(nonce, cipher, tag, plain);
                            json = Encoding.UTF8.GetString(plain);
                            needsMigration = true;
                            _logger.Info("Linux trust store: successfully migrated legacy v1 machine-id keystore to v2 protected master key.");
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(v1Key);
                        }
                    }

                    CryptographicOperations.ZeroMemory(plain);
                }
                else
                {
                    // Plaintext fallback (e.g. initial import)
                    json = Encoding.UTF8.GetString(raw);
                    needsMigration = true;
                }

                if (!string.IsNullOrEmpty(json))
                {
                    var list = JsonSerializer.Deserialize<List<TrustedPhoneRecord>>(json);
                    if (list != null)
                    {
                        foreach (var record in list)
                        {
                            if (string.IsNullOrEmpty(record.PublicKeySpkiBase64)) continue;

                            string? verifiedFp = ComputeFingerprintOrNull(record.PublicKeySpkiBase64);
                            if (verifiedFp == null || !string.Equals(verifiedFp, record.Fingerprint, StringComparison.OrdinalIgnoreCase))
                            {
                                _logger.Warning($"Linux trust store: rejected corrupted/tampered device record '{record.DisplayName}' (fingerprint mismatch).");
                                continue;
                            }

                            if (record.Capabilities.Contains("LOCK", StringComparer.OrdinalIgnoreCase) &&
                                !record.Capabilities.Contains("POWER_ELEVATED", StringComparer.OrdinalIgnoreCase))
                            {
                                record.Capabilities.Add("POWER_ELEVATED");
                                needsMigration = true;
                            }

                            _byFingerprint[record.Fingerprint] = record;
                        }
                    }
                }

                _logger.Info($"Linux trust store loaded {_byFingerprint.Count} trusted device(s).");

                if (needsMigration)
                {
                    Save();
                }
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
            string? tmpFile = null;
            try
            {
                var list = _byFingerprint.Values.ToList();
                byte[] plainBytes = JsonSerializer.SerializeToUtf8Bytes(list, new JsonSerializerOptions { WriteIndented = false });

                byte[] key = GetV2EncryptionKey();
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

                tmpFile = _dataFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
                File.WriteAllBytes(tmpFile, result);

                if (OperatingSystem.IsLinux())
                {
                    try
                    {
                        File.SetUnixFileMode(tmpFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    }
                    catch { }
                }

                // If existing trust.json exists, backup to trust.json.bak
                if (File.Exists(_dataFile))
                {
                    try { File.Copy(_dataFile, _dataFile + ".bak", overwrite: true); } catch { }
                }

                File.Move(tmpFile, _dataFile, overwrite: true);
                tmpFile = null;
            }
            catch (Exception ex)
            {
                _logger.Error($"Linux trust store save failed: {ex.Message}");
            }
            finally
            {
                if (tmpFile != null && File.Exists(tmpFile))
                {
                    try { File.Delete(tmpFile); } catch { }
                }
            }
        }
    }
}
