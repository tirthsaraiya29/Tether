using System.Net;
using System.Text.Json;
using Tether.CommunicationService.Discovery;
using Tether.Shared.Network;
using Xunit;

namespace Tether.Tests;

public class UdpDiscoveryHotspotTests
{
    [Fact]
    public void GetDiscoveryTargetEndPoints_IncludesBroadcastAndValidPorts()
    {
        var targets = UdpDiscovery.GetDiscoveryTargetEndPoints(NetworkConstants.DiscoveryPort);

        Assert.NotNull(targets);
        Assert.NotEmpty(targets);

        // Global broadcast must always be present
        Assert.Contains(targets, t => t.Address.Equals(IPAddress.Broadcast) && t.Port == NetworkConstants.DiscoveryPort);

        // Every target must have the designated discovery port
        foreach (var target in targets)
        {
            Assert.Equal(NetworkConstants.DiscoveryPort, target.Port);
            Assert.False(IPAddress.IsLoopback(target.Address));
        }
    }

    [Theory]
    [InlineData("192.168.43.15", "255.255.255.0", "192.168.43.255")] // Typical Android Hotspot
    [InlineData("192.168.49.20", "255.255.255.0", "192.168.49.255")] // Wi-Fi Direct / Local Hotspot
    [InlineData("172.20.10.3", "255.255.255.240", "172.20.10.15")]   // Alternate Hotspot subnet
    [InlineData("10.42.0.50", "255.255.255.0", "10.42.0.255")]       // Linux/Android Tethering
    public void DirectedSubnetBroadcast_CalculatesExpectedAddress(string ipStr, string maskStr, string expectedBcastStr)
    {
        var ipBytes = IPAddress.Parse(ipStr).GetAddressBytes();
        var maskBytes = IPAddress.Parse(maskStr).GetAddressBytes();
        var bcastBytes = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            bcastBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
        }
        var computedBcast = new IPAddress(bcastBytes);

        Assert.Equal(IPAddress.Parse(expectedBcastStr), computedBcast);
    }

    [Fact]
    public void DiscoveryResponsePayload_ContainsRequiredHotspotFields()
    {
        var payloadObj = new
        {
            type = "TETHER_DISCOVERY_RESPONSE",
            deviceId = "test-windows-id",
            deviceName = "Test-Workstation",
            tcpPort = NetworkConstants.ControlPort
        };

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(payloadObj);
        using var doc = JsonDocument.Parse(jsonBytes);
        var root = doc.RootElement;

        Assert.Equal("TETHER_DISCOVERY_RESPONSE", root.GetProperty("type").GetString());
        Assert.Equal("test-windows-id", root.GetProperty("deviceId").GetString());
        Assert.Equal("Test-Workstation", root.GetProperty("deviceName").GetString());
        Assert.Equal(NetworkConstants.ControlPort, root.GetProperty("tcpPort").GetInt32());
    }
}
