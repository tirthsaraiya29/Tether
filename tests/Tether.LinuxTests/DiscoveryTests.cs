using System;
using System.Net;
using System.Text;
using System.Text.Json;
using Tether.LinuxDaemon.Discovery;
using Tether.Shared.Logging;
using Tether.Shared.Security;
using Xunit;

namespace Tether.LinuxTests;

public class DiscoveryTests
{
    private sealed class MockIdentity : IHostIdentity
    {
        public System.Security.Cryptography.X509Certificates.X509Certificate2 Certificate => throw new NotImplementedException();
        public string Fingerprint => "AA:BB:CC:DD";
        public string DeviceId => "test-device-id";
        public string DeviceName => "FedoraHost";
        public byte[] GetPublicKeySpkiDer() => Array.Empty<byte>();
        public string GetPublicKeySpkiBase64() => "";
    }

    [Theory]
    [InlineData("192.168.1.50", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.20.10.2", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("127.0.0.1", false)] // Loopback rejected
    [InlineData("8.8.8.8", false)] // Public WAN rejected
    [InlineData("100.64.0.1", false)] // CGNAT rejected
    public void IsPrivateIpv4_ValidatesCorrectly(string ip, bool expected)
    {
        var addr = IPAddress.Parse(ip);
        Assert.Equal(expected, LinuxUdpDiscovery.IsPrivateIpv4(addr));
    }

    [Theory]
    [InlineData("valid-device-123", true)]
    [InlineData("dev_with.dots:and-colons", true)]
    [InlineData("", false)]
    [InlineData("invalid spaces!", false)]
    [InlineData("invalid$chars#", false)]
    public void IsValidDeviceId_ValidatesCorrectly(string id, bool expected)
    {
        Assert.Equal(expected, LinuxUdpDiscovery.IsValidDeviceId(id));
    }

    [Fact]
    public void DiscoveryRateLimiter_AllowsUpToFivePerSecPerIp()
    {
        var limiter = new DiscoveryRateLimiter();
        string ip = "192.168.1.100";

        for (int i = 0; i < 5; i++)
        {
            Assert.True(limiter.CheckAllowed(ip));
        }

        // 6th attempt within the same second is rejected
        Assert.False(limiter.CheckAllowed(ip));

        // Different IP is allowed
        Assert.True(limiter.CheckAllowed("192.168.1.101"));
    }

    [Fact]
    public void ValidateInboundProbe_AcceptsValidProbe()
    {
        var discovery = new LinuxUdpDiscovery(new SerilogTetherLogger(), new MockIdentity());
        var remote = new IPEndPoint(IPAddress.Parse("192.168.1.100"), 37124);

        var probe = new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "phone-device-id",
            tcpPort = 37123
        };
        byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(probe));

        bool valid = discovery.ValidateInboundProbe(bytes, remote, out string? devId);
        Assert.True(valid);
        Assert.Equal("phone-device-id", devId);
    }

    [Fact]
    public void ValidateInboundProbe_RejectsInvalidPortOrType()
    {
        var discovery = new LinuxUdpDiscovery(new SerilogTetherLogger(), new MockIdentity());
        var remote = new IPEndPoint(IPAddress.Parse("192.168.1.100"), 37124);

        var probeWrongPort = new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "phone-device-id",
            tcpPort = 9999
        };
        byte[] bytesWrongPort = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(probeWrongPort));
        Assert.False(discovery.ValidateInboundProbe(bytesWrongPort, remote, out _));

        var probeWrongType = new
        {
            type = "SOME_OTHER_PACKET",
            deviceId = "phone-device-id",
            tcpPort = 37123
        };
        byte[] bytesWrongType = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(probeWrongType));
        Assert.False(discovery.ValidateInboundProbe(bytesWrongType, remote, out _));
    }
}
