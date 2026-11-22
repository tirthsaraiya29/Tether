using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Security;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxIdentityTests : IDisposable
{
    private readonly string _testDir;
    private readonly LinuxDaemonConfig _config;
    private readonly ITetherLogger _logger;

    public LinuxIdentityTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_identity_test_" + Guid.NewGuid().ToString("N"));
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

    [Fact]
    public void Identity_GeneratesCertificateAndCalculatesFingerprint()
    {
        using var identity = new LinuxIdentity(_logger, _config);

        Assert.NotNull(identity.Certificate);
        Assert.True(identity.Certificate.HasPrivateKey);
        Assert.False(string.IsNullOrWhiteSpace(identity.Fingerprint));
        Assert.Contains(":", identity.Fingerprint);

        byte[] spki = identity.GetPublicKeySpkiDer();
        Assert.NotNull(spki);
        Assert.True(spki.Length > 0);

        string spkiBase64 = identity.GetPublicKeySpkiBase64();
        Assert.False(string.IsNullOrWhiteSpace(spkiBase64));

        Assert.Equal(identity.Fingerprint, identity.DeviceId);
        Assert.Equal(Environment.MachineName, identity.DeviceName);
    }

    [Fact]
    public void Identity_ReloadsExistingCertificateFromDisk()
    {
        string originalFingerprint;
        using (var firstIdentity = new LinuxIdentity(_logger, _config))
        {
            originalFingerprint = firstIdentity.Fingerprint;
        }

        using (var secondIdentity = new LinuxIdentity(_logger, _config))
        {
            Assert.Equal(originalFingerprint, secondIdentity.Fingerprint);
        }
    }
}
