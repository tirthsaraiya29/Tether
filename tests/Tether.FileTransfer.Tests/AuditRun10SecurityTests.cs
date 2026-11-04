using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Pairing;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Trust;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.FileTransfer.Tests;

public class AuditRun10SecurityTests
{
    private sealed class TestEventBus : IEventBus
    {
        public List<TetherEvent> PublishedEvents { get; } = new();
        private readonly List<Action<TetherEvent>> _subscribers = new();

        public void Publish(TetherEvent evt)
        {
            PublishedEvents.Add(evt);
            foreach (var sub in _subscribers) sub(evt);
        }

        public void Subscribe(Action<TetherEvent> handler) => _subscribers.Add(handler);
        public void Subscribe(TetherEventType eventType, Action<TetherEvent> handler) => _subscribers.Add(handler);
        public void Unsubscribe(Action<TetherEvent> handler) => _subscribers.Remove(handler);
    }

    [Fact]
    public async Task TestLocationFlags()
    {
        await RunTestFlags(X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
    }

    [Fact]
    public void TETHER_2026_WindowsIdentity_PreservesPairedIdentityFingerprint()
    {
        var identity = new WindowsIdentity(new MockLogger());
        Assert.NotNull(identity.Certificate);
        Assert.NotNull(identity.Fingerprint);
        Assert.True(identity.Certificate.HasPrivateKey);
        Assert.Equal(95, identity.Fingerprint.Length);

        using var store = new X509Store("My", StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var existing = store.Certificates
            .Find(X509FindType.FindBySubjectDistinguishedName, "CN=Tether Windows Identity", validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault();
        if (existing != null)
        {
            Assert.Equal(existing.Thumbprint, identity.Certificate.Thumbprint);
        }
    }

    private static async Task RunTestFlags(X509KeyStorageFlags flags)
    {
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(new X500DistinguishedName("CN=Test TLS"), ecdsa, System.Security.Cryptography.HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new System.Security.Cryptography.OidCollection { new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1") }, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        using var selfSigned = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] pfx = selfSigned.Export(X509ContentType.Pfx, "temp");

#pragma warning disable SYSLIB0057
        using var cert = new X509Certificate2(pfx, "temp", flags);
#pragma warning restore SYSLIB0057

        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var ssl = new System.Net.Security.SslStream(client.GetStream(), false);
            var opt = new System.Net.Security.SslServerAuthenticationOptions
            {
                ServerCertificate = cert,
                ClientCertificateRequired = false,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };
            if (cert.HasPrivateKey)
            {
                opt.ServerCertificateSelectionCallback = (s, h) => cert;
                opt.ServerCertificate = null;
            }
            await ssl.AuthenticateAsServerAsync(opt);
        });

        var clientTask = Task.Run(async () =>
        {
            using var client = new System.Net.Sockets.TcpClient();
            await client.ConnectAsync(System.Net.IPAddress.Loopback, port);
            using var ssl = new System.Net.Security.SslStream(client.GetStream(), false, (s, c, ch, err) => true);
            await ssl.AuthenticateAsClientAsync("localhost");
        });

        await Task.WhenAll(serverTask, clientTask);
    }

    [Fact]
    public void TETHER_2026_001_UnlockCommand_RequiresElevatedCapability_NotMedia()
    {
        // 1. Verify capability mapping
        string? unlockCap = CapabilityManager.MapCommandToCapability("unlock");
        string? authOkCap = CapabilityManager.MapCommandToCapability("auth_ok");

        Assert.Equal("POWER_ELEVATED", unlockCap);
        Assert.Equal("POWER_ELEVATED", authOkCap);
        Assert.NotEqual("MEDIA", unlockCap);

        // 2. Verify device permission evaluation
        var logger = new MockLogger();
        var capManager = new CapabilityManager(logger);

        var mediaOnlyDevice = new TetherDevice
        {
            DeviceId = "test-phone",
            DisplayName = "Test Phone",
            Capabilities = new List<string> { "MEDIA" }
        };

        var elevatedDevice = new TetherDevice
        {
            DeviceId = "trusted-phone",
            DisplayName = "Trusted Phone",
            Capabilities = new List<string> { "POWER_ELEVATED", "MEDIA" }
        };

        var systemUnlockDevice = new TetherDevice
        {
            DeviceId = "system-unlock-phone",
            DisplayName = "System Unlock Phone",
            Capabilities = new List<string> { "SYSTEM_UNLOCK", "MEDIA" }
        };

        Assert.False(capManager.CanDeviceExecuteCommand(mediaOnlyDevice, "unlock"));
        Assert.False(capManager.CanDeviceExecuteCommand(mediaOnlyDevice, "auth_ok"));

        Assert.True(capManager.CanDeviceExecuteCommand(elevatedDevice, "unlock"));
        Assert.True(capManager.CanDeviceExecuteCommand(elevatedDevice, "auth_ok"));

        Assert.True(capManager.CanDeviceExecuteCommand(systemUnlockDevice, "unlock"));
        Assert.True(capManager.CanDeviceExecuteCommand(systemUnlockDevice, "auth_ok"));
    }

    [Fact]
    public void TETHER_2026_002_WindowsIdentity_IncludesSanExtension()
    {
        var logger = new MockLogger();
        using var identity = new WindowsIdentity(logger);
        var cert = identity.Certificate;

        Assert.NotNull(cert);
        Assert.True(cert.HasPrivateKey);

        // Verify Subject Alternative Name (SAN) extension exists
        var sanExt = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        Assert.NotNull(sanExt);

        // Verify fingerprint can be generated and key signs data
        Assert.False(string.IsNullOrEmpty(identity.Fingerprint));
        Assert.True(identity.GetPublicKeySpkiDer().Length > 0);
    }

    [Fact]
    public void TETHER_2026_003_DeviceManager_DoesNotSilentlyEscalateCapabilities()
    {
        var logger = new MockLogger();
        var trustStore = new TrustStore(logger);

        // Seed or test with a restricted device
        string testSpki = Convert.ToBase64String(new byte[64]);
        var existing = trustStore.AddOrUpdate("dev-restricted", "Restricted Phone", testSpki, new[] { "MEDIA" }, "2.0");
        Assert.Single(existing.Capabilities);
        Assert.Contains("MEDIA", existing.Capabilities);

        // Re-hydrate device manager
        var devManager = new DeviceManager(logger, trustStore);
        var device = devManager.GetAllDevices().FirstOrDefault(d => d.DeviceId == existing.DeviceId);

        Assert.NotNull(device);
        // Verify TERMINAL and POWER_ELEVATED were NOT silently added
        Assert.DoesNotContain("TERMINAL", device.Capabilities);
        Assert.DoesNotContain("POWER_ELEVATED", device.Capabilities);
        Assert.DoesNotContain("FILES", device.Capabilities);
        Assert.Contains("MEDIA", device.Capabilities);
    }

    [Fact]
    public void TETHER_2026_005_PairingRequested_DoesNotBroadcastPinOverEventBus()
    {
        var logger = new MockLogger();
        var eventBus = new TestEventBus();
        using var identity = new WindowsIdentity(logger);
        var trustStore = new TrustStore(logger);
        var devManager = new DeviceManager(logger, trustStore);
        var pairingManager = new PairingManager(eventBus, logger, identity, devManager);

        string phoneSpki = Convert.ToBase64String(new byte[64]);
        byte[] initBytes = new byte[32];

        var (pending, response, responseBytes) = pairingManager.CreatePairingResponse(
            "win-dev-1",
            "WinHost",
            identity.GetPublicKeySpkiBase64(),
            "ALL",
            phoneSpki,
            "Pixel 9",
            initBytes);

        Assert.Equal(HandshakeStatus.PairingPending, response.Status);
        Assert.False(string.IsNullOrEmpty(pending.RequestId));
        Assert.False(string.IsNullOrEmpty(pending.Pin));

        // Verify the event published on event bus
        var pairingEvent = eventBus.PublishedEvents.FirstOrDefault(e => e.EventType == TetherEventType.PAIRING_REQUESTED);
        Assert.NotNull(pairingEvent);
        Assert.NotNull(pairingEvent.PayloadJson);

        // Check that PayloadJson does NOT contain "pin" property
        using var doc = JsonDocument.Parse(pairingEvent.PayloadJson);
        var root = doc.RootElement;
        Assert.False(root.TryGetProperty("pin", out _), "VULNERABILITY DETECTED: 'pin' is present in PAIRING_REQUESTED IPC payload!");

        // But TryGetPin should securely return the PIN directly
        Assert.True(pairingManager.TryGetPin(pending.RequestId, out string retrievedPin));
        Assert.Equal(pending.Pin, retrievedPin);
    }

    [Fact]
    public void TETHER_2026_008_PairingManager_LimitsPendingRequestsPerClient()
    {
        var logger = new MockLogger();
        var eventBus = new TestEventBus();
        using var identity = new WindowsIdentity(logger);
        var trustStore = new TrustStore(logger);
        var devManager = new DeviceManager(logger, trustStore);
        var pairingManager = new PairingManager(eventBus, logger, identity, devManager);

        string phoneSpki = Convert.ToBase64String(new byte[64]);
        byte[] initBytes = new byte[32];

        // 1st request -> success
        var res1 = pairingManager.CreatePairingResponse("win1", "WinHost", identity.GetPublicKeySpkiBase64(), "ALL", phoneSpki, "AttackerPhone", initBytes);
        Assert.Equal(HandshakeStatus.PairingPending, res1.response.Status);

        // 2nd request -> success
        var res2 = pairingManager.CreatePairingResponse("win1", "WinHost", identity.GetPublicKeySpkiBase64(), "ALL", phoneSpki, "AttackerPhone", initBytes);
        Assert.Equal(HandshakeStatus.PairingPending, res2.response.Status);

        // 3rd request -> must be rejected (throttled)
        var res3 = pairingManager.CreatePairingResponse("win1", "WinHost", identity.GetPublicKeySpkiBase64(), "ALL", phoneSpki, "AttackerPhone", initBytes);
        Assert.Equal(HandshakeStatus.PairingDenied, res3.response.Status);
    }
}
