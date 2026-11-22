using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Devices;
using Tether.LinuxDaemon.Pairing;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Security;
using Tether.LinuxDaemon.Sessions;
using Tether.LinuxDaemon.Transport;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxPairingAndSessionTests : IDisposable
{
    private readonly string _testDir;
    private readonly LinuxDaemonConfig _config;
    private readonly ITetherLogger _logger;
    private readonly LinuxTrustStore _trustStore;
    private readonly LinuxDeviceManager _deviceManager;
    private readonly LinuxIdentity _identity;
    private readonly IEventBus _eventBus;
    private readonly LinuxPairingManager _pairingManager;
    private readonly LinuxSessionManager _sessionManager;

    public LinuxPairingAndSessionTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_pairing_test_" + Guid.NewGuid().ToString("N"));
        _config = new LinuxDaemonConfig
        {
            DataDir = _testDir,
            RunDir = Path.Combine(_testDir, "run"),
            LogDir = Path.Combine(_testDir, "log")
        };
        _logger = new SerilogTetherLogger();
        _trustStore = new LinuxTrustStore(_logger, _config);
        _deviceManager = new LinuxDeviceManager(_logger, _trustStore);
        _identity = new LinuxIdentity(_logger, _config);
        _eventBus = new InMemoryEventBus(_logger);
        _pairingManager = new LinuxPairingManager(_eventBus, _logger, _identity, _deviceManager, _trustStore);
        _sessionManager = new LinuxSessionManager(_logger);
    }

    public void Dispose()
    {
        _identity.Dispose();
        try
        {
            if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true);
        }
        catch { }
    }

    private static (string spkiBase64, ECDsa key) GeneratePhoneKey()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()), ecdsa);
    }

    [Fact]
    public void PairingManager_CreatesPairingResponse_With6DigitPin()
    {
        var (phoneSpki, _) = GeneratePhoneKey();
        byte[] initBytes = "test-init-bytes"u8.ToArray();

        var (pending, resp, respBytes) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            "MEDIA,LOCK",
            phoneSpki,
            "Pixel 9 Pro",
            initBytes);

        Assert.NotNull(pending);
        Assert.Equal(HandshakeStatus.PairingPending, resp.Status);
        Assert.False(string.IsNullOrEmpty(resp.RequestId));
        Assert.Equal(6, pending.Pin.Length);
        Assert.True(int.TryParse(pending.Pin, out _));
        Assert.True(respBytes.Length > 0);
    }

    [Fact]
    public void PairingManager_VerifiesCorrectProof_AndRejectsInvalidProof()
    {
        var (phoneSpki, _) = GeneratePhoneKey();
        byte[] initBytes = "test-init"u8.ToArray();

        var (pending, resp, _) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            "MEDIA,LOCK",
            phoneSpki,
            "Pixel 9 Pro",
            initBytes);

        // Try wrong proof / wrong PIN
        bool wrongSuccess = _pairingManager.TryVerifyPhoneProof(resp.RequestId!, Convert.ToBase64String("000000"u8.ToArray()), out _, out _);
        Assert.False(wrongSuccess);

        // Try correct PIN proof
        bool correctSuccess = _pairingManager.TryVerifyPhoneProof(resp.RequestId!, Convert.ToBase64String(Encoding.UTF8.GetBytes(pending.Pin)), out string hostProof, out var matchedPending);
        Assert.True(correctSuccess);
        Assert.NotNull(matchedPending);
        Assert.False(string.IsNullOrEmpty(hostProof));

        // Pinned in trust store
        string phoneFp = LinuxTrustStore.ComputeFingerprintOrNull(phoneSpki)!;
        Assert.NotNull(_trustStore.FindByFingerprint(phoneFp));
    }

    [Fact]
    public void PairingManager_EvictsAfterThreeFailedAttempts()
    {
        var (phoneSpki, _) = GeneratePhoneKey();
        byte[] initBytes = "test-init"u8.ToArray();

        var (pending, resp, _) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            "MEDIA,LOCK",
            phoneSpki,
            "Pixel 9 Pro",
            initBytes);

        for (int i = 0; i < 3; i++)
        {
            _pairingManager.TryVerifyPhoneProof(resp.RequestId!, Convert.ToBase64String("999999"u8.ToArray()), out _, out _);
        }

        // Even with correct PIN now, request was evicted
        bool fourthAttempt = _pairingManager.TryVerifyPhoneProof(resp.RequestId!, Convert.ToBase64String(Encoding.UTF8.GetBytes(pending.Pin)), out _, out _);
        Assert.False(fourthAttempt);
    }
}
