using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Tether.CommunicationService.Trust;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class TETH_POT_001_TrustStoreSecurityTests
{
    private readonly string _testDir;

    public TETH_POT_001_TrustStoreSecurityTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "Tether_TrustStore_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    [Fact]
    public void ComputeFingerprintOrNull_ValidSpki_ComputesConsistentSha256Hex()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        string? fp = TrustStore.ComputeFingerprintOrNull(spki);

        Assert.NotNull(fp);
        Assert.Contains(":", fp);
        Assert.Equal(32, fp.Split(':').Length);
    }

    [Fact]
    public void ComputeFingerprintOrNull_InvalidBase64_ReturnsNull()
    {
        string? fp = TrustStore.ComputeFingerprintOrNull("not-valid-base64!@#$");
        Assert.Null(fp);
    }

    [Fact]
    public void Load_InjectedMismatchedFingerprintEntry_RejectedOnLoad()
    {
        var logger = new TestLogger();
        string dataFile = Path.Combine(_testDir, "trust.json");

        // Create a fake plaintext trust file with a spoofed entry where Fingerprint != SHA256(SPKI)
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
        string forgedFp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";

        var fakeEntries = new List<TrustedPhone>
        {
            new TrustedPhone
            {
                DeviceId = "spoofed-dev",
                DisplayName = "Spoofed Device",
                PublicKeySpkiBase64 = spki,
                Fingerprint = forgedFp,
                Capabilities = new List<string> { "POWER_ELEVATED", "FILES" }
            }
        };

        File.WriteAllText(dataFile, JsonSerializer.Serialize(fakeEntries));

        // Load trust store
        var trustStore = new TrustStore(logger, _testDir);

        Assert.True(trustStore.IsEmpty, "Spoofed entry with fingerprint mismatch must be discarded on load.");
        Assert.Null(trustStore.FindBySpkiBase64(spki));
    }

    [Fact]
    public void Load_ValidPlaintextEntry_AcceptedAndMigrated()
    {
        var logger = new TestLogger();
        string dataFile = Path.Combine(_testDir, "trust.json");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
        string validFp = TrustStore.ComputeFingerprintOrNull(spki)!;

        var entries = new List<TrustedPhone>
        {
            new TrustedPhone
            {
                DeviceId = "valid-dev",
                DisplayName = "Valid Device",
                PublicKeySpkiBase64 = spki,
                Fingerprint = validFp,
                Capabilities = new List<string> { "MEDIA" }
            }
        };

        File.WriteAllText(dataFile, JsonSerializer.Serialize(entries));

        var trustStore = new TrustStore(logger, _testDir);

        Assert.False(trustStore.IsEmpty);
        var loaded = trustStore.FindBySpkiBase64(spki);
        Assert.NotNull(loaded);
        Assert.Equal("valid-dev", loaded.DeviceId);
    }
}
