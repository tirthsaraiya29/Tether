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
    public void TETHER_2026_001_UnlockCommand_RequiresSystemUnlockCapability_NotMedia()
    {
        // 1. Verify capability mapping
        string? unlockCap = CapabilityManager.MapCommandToCapability("unlock");
        string? authOkCap = CapabilityManager.MapCommandToCapability("auth_ok");

        Assert.Equal("SYSTEM_UNLOCK", unlockCap);
        Assert.Equal("SYSTEM_UNLOCK", authOkCap);
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

        var unlockedDevice = new TetherDevice
        {
            DeviceId = "trusted-phone",
            DisplayName = "Trusted Phone",
            Capabilities = new List<string> { "SYSTEM_UNLOCK", "MEDIA" }
        };

        Assert.False(capManager.CanDeviceExecuteCommand(mediaOnlyDevice, "unlock"));
        Assert.True(capManager.CanDeviceExecuteCommand(unlockedDevice, "unlock"));
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
