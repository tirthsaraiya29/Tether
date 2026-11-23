using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxTrustStoreTests : IDisposable
{
    private readonly string _testDir;
    private readonly LinuxDaemonConfig _config;
    private readonly ITetherLogger _logger;

    public LinuxTrustStoreTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_trust_test_" + Guid.NewGuid().ToString("N"));
        _config = new LinuxDaemonConfig
        {
            DataDir = _testDir,
            RunDir = Path.Combine(_testDir, "run"),
            LogDir = Path.Combine(_testDir, "log")
        };
        _logger = new SerilogTetherLogger();
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true);
        }
        catch { }
    }

    private static string GenerateFakeSpkiBase64()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void TrustStore_StartsEmpty()
    {
        var store = new LinuxTrustStore(_logger, _config);
        Assert.True(store.IsEmpty);
        Assert.Empty(store.All());
    }

    [Fact]
    public void TrustStore_AddOrUpdate_PersistsEncryptedOnDiskAndReloads()
    {
        string fakeSpki = GenerateFakeSpkiBase64();
        string expectedFingerprint = LinuxTrustStore.ComputeFingerprintOrNull(fakeSpki)!;

        var store1 = new LinuxTrustStore(_logger, _config);
        var entry = store1.AddOrUpdate("dev-1", "Test Pixel", fakeSpki, new[] { "MEDIA", "LOCK" }, "2.0");

        Assert.NotNull(entry);
        Assert.Equal("Test Pixel", entry.DisplayName);
        Assert.Equal(expectedFingerprint, entry.Fingerprint);
        Assert.False(store1.IsEmpty);
        Assert.Single(store1.All());

        // Verify the file on disk is encrypted (starts with TLTS magic)
        string trustFile = Path.Combine(_config.DataDir, "trust.json");
        Assert.True(File.Exists(trustFile));
        byte[] rawBytes = File.ReadAllBytes(trustFile);
        Assert.True(rawBytes.Length > 32);
        Assert.Equal((byte)'T', rawBytes[0]);
        Assert.Equal((byte)'L', rawBytes[1]);
        Assert.Equal((byte)'T', rawBytes[2]);
        Assert.Equal((byte)'S', rawBytes[3]);

        // Load in a fresh store instance from disk
        var store2 = new LinuxTrustStore(_logger, _config);
        Assert.False(store2.IsEmpty);
        var reloaded = store2.FindByFingerprint(expectedFingerprint);
        Assert.NotNull(reloaded);
        Assert.Equal("Test Pixel", reloaded.DisplayName);
        Assert.Contains("MEDIA", reloaded.Capabilities);
    }

    [Fact]
    public void TrustStore_Remove_DeletesRecordAndSaves()
    {
        string fakeSpki = GenerateFakeSpkiBase64();
        string fp = LinuxTrustStore.ComputeFingerprintOrNull(fakeSpki)!;

        var store = new LinuxTrustStore(_logger, _config);
        store.AddOrUpdate("dev-1", "Phone", fakeSpki, new[] { "MEDIA" }, "2.0");
        Assert.False(store.IsEmpty);

        bool removed = store.Remove(fp);
        Assert.True(removed);
        Assert.True(store.IsEmpty);

        // Reload
        var storeReload = new LinuxTrustStore(_logger, _config);
        Assert.True(storeReload.IsEmpty);
    }

    [Fact]
    public void TrustStore_RejectsTamperedOrCorruptedFingerprint()
    {
        string fakeSpki = GenerateFakeSpkiBase64();
        string realFp = LinuxTrustStore.ComputeFingerprintOrNull(fakeSpki)!;

        var store = new LinuxTrustStore(_logger, _config);
        store.AddOrUpdate("dev-1", "Phone", fakeSpki, new[] { "MEDIA" }, "2.0");

        // Manually overwrite trust.json with a record having a forged/tampered fingerprint
        string trustFile = Path.Combine(_config.DataDir, "trust.json");
        var forgedList = new[]
        {
            new TrustedPhoneRecord
            {
                DeviceId = "forged-id",
                DisplayName = "Forged Phone",
                PublicKeySpkiBase64 = fakeSpki,
                Fingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                PairedAtUtc = DateTime.UtcNow,
                LastSeenUtc = DateTime.UtcNow,
                Capabilities = new System.Collections.Generic.List<string> { "FILES" }
            }
        };

        // Write plaintext json to force re-verification
        File.WriteAllText(trustFile, System.Text.Json.JsonSerializer.Serialize(forgedList));

        // Reload store
        var storeTampered = new LinuxTrustStore(_logger, _config);
        // The tampered record must be rejected because calculated fingerprint doesn't match forged fingerprint!
        Assert.True(storeTampered.IsEmpty);
    }

    [Fact]
    public void TrustStore_CreatesProtectedMasterKey_AndBackupCopy()
    {
        string fakeSpki = GenerateFakeSpkiBase64();
        var store = new LinuxTrustStore(_logger, _config);
        store.AddOrUpdate("dev-1", "Phone", fakeSpki, new[] { "MEDIA" }, "2.0");

        string keyFile = Path.Combine(_config.DataDir, "trust.key");
        Assert.True(File.Exists(keyFile));
        byte[] keyBytes = File.ReadAllBytes(keyFile);
        Assert.Equal(32, keyBytes.Length);

        // Update to trigger backup
        store.AddOrUpdate("dev-1", "Phone Renamed", fakeSpki, new[] { "MEDIA", "FILES" }, "2.0");
        string backupFile = Path.Combine(_config.DataDir, "trust.json.bak");
        Assert.True(File.Exists(backupFile));
    }
}
