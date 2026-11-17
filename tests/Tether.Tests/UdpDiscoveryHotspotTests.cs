using System.Net;
using System.Text;
using System.Text.Json;
using Tether.CommunicationService;
using Tether.CommunicationService.Discovery;
using Tether.CommunicationService.Security;
using Tether.Shared.Logging;
using Tether.Shared.Network;
using Xunit;

namespace Tether.Tests;

public class UdpDiscoveryHotspotTests
{
    private sealed class NoOpLogger : ITetherLogger
    {
        public void Debug(string message) { }
        public void Info(string message) { }
        public void Warning(string message) { }
        public void Error(string message, Exception? ex = null) { }
        public void Critical(string message, Exception? ex = null) { }
    }

    private static UdpDiscovery CreateDiscoveryInstance()
    {
        var identity = new WindowsIdentity(new NoOpLogger());
        return new UdpDiscovery(new NoOpLogger(), identity);
    }

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.254.0.1", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("192.168.43.1", true)]
    [InlineData("169.254.10.5", true)]
    // Security Boundaries: loopback, CGNAT, WAN, multicast, broadcast
    [InlineData("127.0.0.1", false)]
    [InlineData("127.0.0.2", false)]
    [InlineData("100.64.0.1", false)]       // CGNAT
    [InlineData("100.100.50.25", false)]    // CGNAT
    [InlineData("100.127.255.254", false)]  // CGNAT
    [InlineData("8.8.8.8", false)]          // WAN
    [InlineData("1.1.1.1", false)]          // WAN
    [InlineData("203.0.113.1", false)]      // Test WAN
    [InlineData("224.0.0.251", false)]      // Multicast
    [InlineData("0.0.0.0", false)]
    [InlineData("255.255.255.255", false)]
    public void IsPrivateIpv4_EnforcesSecurityBoundaries(string ipStr, bool expected)
    {
        var ip = IPAddress.Parse(ipStr);
        Assert.Equal(expected, UdpDiscovery.IsPrivateIpv4(ip));
    }

    [Fact]
    public void IsPrivateIpv4_RejectsIpv6()
    {
        Assert.False(UdpDiscovery.IsPrivateIpv4(IPAddress.IPv6Loopback));
        Assert.False(UdpDiscovery.IsPrivateIpv4(IPAddress.Parse("fe80::1")));
        Assert.False(UdpDiscovery.IsPrivateIpv4(IPAddress.Parse("2001:db8::1")));
    }

    [Theory]
    [InlineData("device-12345", true)]
    [InlineData("android_phone_v2", true)]
    [InlineData("host.local:37123", true)]
    [InlineData("AA:BB:CC:DD:EE:FF", true)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData(null, false)]
    [InlineData("id<script>alert(1)</script>", false)]
    [InlineData("device\nid", false)]
    [InlineData("device\0id", false)]
    [InlineData("device;rm -rf /", false)]
    public void IsValidDeviceId_StrictValidation(string? deviceId, bool expected)
    {
        Assert.Equal(expected, UdpDiscovery.IsValidDeviceId(deviceId));
    }

    [Fact]
    public void IsValidDeviceId_RejectsOversized()
    {
        string oversized = new string('a', 129);
        Assert.False(UdpDiscovery.IsValidDeviceId(oversized));

        string validMax = new string('a', 128);
        Assert.True(UdpDiscovery.IsValidDeviceId(validMax));
    }

    [Fact]
    public void ValidateInboundProbe_ValidProbe_Accepted()
    {
        using var discovery = CreateDiscoveryInstance();
        var remoteEp = new IPEndPoint(IPAddress.Parse("192.168.43.50"), NetworkConstants.DiscoveryPort);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "android-device-123",
            tcpPort = NetworkConstants.ControlPort
        });

        bool result = discovery.ValidateInboundProbe(payload, remoteEp, out string? probeDeviceId);

        Assert.True(result);
        Assert.Equal("android-device-123", probeDeviceId);
    }

    [Fact]
    public void ValidateInboundProbe_RejectsLoopbackAndCgnat()
    {
        using var discovery = CreateDiscoveryInstance();
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "test-device"
        });

        // Loopback must be rejected
        var loopbackEp = new IPEndPoint(IPAddress.Parse("127.0.0.1"), NetworkConstants.DiscoveryPort);
        Assert.False(discovery.ValidateInboundProbe(payload, loopbackEp, out _));

        // CGNAT must be rejected
        var cgnatEp = new IPEndPoint(IPAddress.Parse("100.64.0.15"), NetworkConstants.DiscoveryPort);
        Assert.False(discovery.ValidateInboundProbe(payload, cgnatEp, out _));

        // Public IP must be rejected
        var wanEp = new IPEndPoint(IPAddress.Parse("8.8.8.8"), NetworkConstants.DiscoveryPort);
        Assert.False(discovery.ValidateInboundProbe(payload, wanEp, out _));
    }

    [Fact]
    public void ValidateInboundProbe_RejectsMalformedPayloads()
    {
        using var discovery = CreateDiscoveryInstance();
        var remoteEp = new IPEndPoint(IPAddress.Parse("192.168.43.50"), NetworkConstants.DiscoveryPort);

        // Undersized (< 10 bytes)
        Assert.False(discovery.ValidateInboundProbe(Encoding.UTF8.GetBytes("{}"), remoteEp, out _));

        // Oversized (> 1024 bytes)
        var oversized = new byte[1025];
        Assert.False(discovery.ValidateInboundProbe(oversized, remoteEp, out _));

        // Not JSON
        Assert.False(discovery.ValidateInboundProbe(Encoding.UTF8.GetBytes("NON_JSON_CORRUPTED_BYTES"), remoteEp, out _));

        // Wrong type
        var wrongType = JsonSerializer.SerializeToUtf8Bytes(new { type = "UNKNOWN_MESSAGE" });
        Assert.False(discovery.ValidateInboundProbe(wrongType, remoteEp, out _));
    }

    [Fact]
    public void ValidateInboundProbe_RejectsInvalidPortAndDeviceId()
    {
        using var discovery = CreateDiscoveryInstance();
        var remoteEp = new IPEndPoint(IPAddress.Parse("192.168.43.50"), NetworkConstants.DiscoveryPort);

        // Port != 37123 must be rejected (e.g. port 80, 8080, 37124)
        var lowPortPayload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "valid-id",
            tcpPort = 80
        });
        Assert.False(discovery.ValidateInboundProbe(lowPortPayload, remoteEp, out _));

        var fileTransferPortPayload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "valid-id",
            tcpPort = 37124
        });
        Assert.False(discovery.ValidateInboundProbe(fileTransferPortPayload, remoteEp, out _));

        // Port > 65535
        var highPortPayload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "valid-id",
            tcpPort = 70000
        });
        Assert.False(discovery.ValidateInboundProbe(highPortPayload, remoteEp, out _));

        // Malicious Device ID
        var badIdPayload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "evil<script>alert(1)</script>"
        });
        Assert.False(discovery.ValidateInboundProbe(badIdPayload, remoteEp, out _));
    }

    [Fact]
    public void RateLimiting_DropsFloodingProbes()
    {
        using var discovery = CreateDiscoveryInstance();
        var remoteEp = new IPEndPoint(IPAddress.Parse("192.168.1.100"), NetworkConstants.DiscoveryPort);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "valid-device"
        });

        // First 5 probes within 1 second must pass
        for (int i = 0; i < UdpDiscovery.MaxProbesPerSecondPerIp; i++)
        {
            Assert.True(discovery.ValidateInboundProbe(payload, remoteEp, out _), $"Probe #{i + 1} should be accepted");
        }

        // 6th probe within the same second must be dropped
        Assert.False(discovery.ValidateInboundProbe(payload, remoteEp, out _), "6th probe should be rate-limited and dropped");
    }

    [Fact]
    public void DiscoveryRateLimiter_GlobalAndCapacityLimits()
    {
        var limiter = new DiscoveryRateLimiter(maxPerIp: 5, maxGlobal: 30, maxTrackedSources: 50);
        long startTicks = DateTime.UtcNow.Ticks;

        // 1. Global limit across different IPs in the same second window
        for (int i = 0; i < 30; i++)
        {
            string ip = $"192.168.1.{i + 1}";
            Assert.True(limiter.CheckAllowed(ip, startTicks), $"Global probe #{i + 1} should be allowed");
        }

        // 31st probe from a brand-new IP must be dropped by the global limit
        Assert.False(limiter.CheckAllowed("192.168.1.99", startTicks), "31st probe must exceed global limit");

        // 2. Window expiration allows new probes
        long nextWindowTicks = startTicks + TimeSpan.FromSeconds(1.1).Ticks;
        Assert.True(limiter.CheckAllowed("192.168.1.99", nextWindowTicks), "Probe in new window must be allowed");

        // 3. Capacity bounded tracking and eviction
        limiter.Reset();
        long now = startTicks;
        // Insert 50 entries
        for (int i = 0; i < 50; i++)
        {
            limiter.CheckAllowed($"10.0.0.{i + 1}", now);
        }
        Assert.True(limiter.TrackedSourceCount <= 50, "Tracked sources should not exceed max capacity");

        // Advance beyond expiry (3.5s) and insert more
        long later = now + TimeSpan.FromSeconds(3.5).Ticks;
        for (int i = 50; i < 70; i++)
        {
            limiter.CheckAllowed($"10.0.0.{i + 1}", later);
        }
        Assert.True(limiter.TrackedSourceCount <= 50, "Expired sources must be cleaned up without exceeding capacity");
    }

    [Fact]
    public void IsAllowedInterface_ValidatesAllInterfaceTypes()
    {
        // Allowed: Wi-Fi, Ethernet
        Assert.True(UdpDiscovery.IsAllowedInterface("Wi-Fi", "Intel(R) Wi-Fi 6 AX200", System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211, System.Net.NetworkInformation.OperationalStatus.Up));
        Assert.True(UdpDiscovery.IsAllowedInterface("Ethernet", "Realtek Gaming GbE Family Controller", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, System.Net.NetworkInformation.OperationalStatus.Up));

        // Ineligible: Down interface
        Assert.False(UdpDiscovery.IsAllowedInterface("Wi-Fi", "Intel Wi-Fi", System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211, System.Net.NetworkInformation.OperationalStatus.Down));

        // Ineligible: Loopback, Tunnel, PPP, Slip
        Assert.False(UdpDiscovery.IsAllowedInterface("Loopback", "Software Loopback Interface 1", System.Net.NetworkInformation.NetworkInterfaceType.Loopback, System.Net.NetworkInformation.OperationalStatus.Up));
        Assert.False(UdpDiscovery.IsAllowedInterface("Tunnel", "Teredo Tunneling Pseudo-Interface", System.Net.NetworkInformation.NetworkInterfaceType.Tunnel, System.Net.NetworkInformation.OperationalStatus.Up));
        Assert.False(UdpDiscovery.IsAllowedInterface("PPP", "WAN Miniport (PPPOE)", System.Net.NetworkInformation.NetworkInterfaceType.Ppp, System.Net.NetworkInformation.OperationalStatus.Up));

        // Ineligible: Cellular / WWAN
        Assert.False(UdpDiscovery.IsAllowedInterface("Cellular", "Qualcomm Snapdragon X55 LTE", (System.Net.NetworkInformation.NetworkInterfaceType)243, System.Net.NetworkInformation.OperationalStatus.Up));
        Assert.False(UdpDiscovery.IsAllowedInterface("Mobile Broadband", "Broadband Adapter", System.Net.NetworkInformation.NetworkInterfaceType.Wwanpp, System.Net.NetworkInformation.OperationalStatus.Up));

        // Ineligible: Virtual / VPN / Hyper-V / WSL
        Assert.False(UdpDiscovery.IsAllowedInterface("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, System.Net.NetworkInformation.OperationalStatus.Up));
        Assert.False(UdpDiscovery.IsAllowedInterface("wg0", "WireGuard Tunnel", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, System.Net.NetworkInformation.OperationalStatus.Up));
        Assert.False(UdpDiscovery.IsAllowedInterface("Tailscale", "Tailscale Tunnel", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, System.Net.NetworkInformation.OperationalStatus.Up));
        Assert.False(UdpDiscovery.IsAllowedInterface("OpenVPN", "TAP-Windows Adapter V9", System.Net.NetworkInformation.NetworkInterfaceType.Ethernet, System.Net.NetworkInformation.OperationalStatus.Up));
    }

    [Fact]
    public void GetDiscoveryTargetEndPoints_ExcludesGlobalBroadcastAndLoopback()
    {
        var targets = UdpDiscovery.GetDiscoveryTargetEndPoints(NetworkConstants.DiscoveryPort);

        Assert.NotNull(targets);
        // Security Remediation: Global broadcast 255.255.255.255 must NEVER be unconditionally added
        Assert.DoesNotContain(targets, t => t.Address.Equals(IPAddress.Broadcast));

        foreach (var target in targets)
        {
            Assert.Equal(NetworkConstants.DiscoveryPort, target.Port);
            Assert.False(IPAddress.IsLoopback(target.Address));
            Assert.True(UdpDiscovery.IsPrivateIpv4(target.Address) || target.Address.GetAddressBytes()[3] == 255);
        }
    }

    [Fact]
    public void FirewallRules_IncludeLocalSubnetRestriction()
    {
        string ruleArgs = Worker.BuildFirewallRuleArguments(
            "Tether-Control-TCP",
            "TCP",
            NetworkConstants.ControlPort,
            @"C:\Program Files\Tether\Tether.CommunicationService.exe"
        );

        Assert.Contains("remoteip=localsubnet", ruleArgs);
        Assert.Contains("profile=any", ruleArgs);
        Assert.Contains("localport=37123", ruleArgs);
        Assert.Contains("action=allow", ruleArgs);
    }
}
