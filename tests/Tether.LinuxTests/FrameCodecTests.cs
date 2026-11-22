using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Transport;
using Xunit;

namespace Tether.LinuxTests;

public class FrameCodecTests
{
    [Fact]
    public async Task FrameCodec_Roundtrip_JsonPayload()
    {
        using var ms = new MemoryStream();
        var original = new HandshakeResponse
        {
            DeviceId = "test-device-id",
            DeviceName = "Fedora Workstation",
            PublicKey = "spki-base64",
            Status = HandshakeStatus.Paired,
            Capabilities = "MEDIA,LOCK,FILES,TERMINAL",
            Pqc = false,
            Os = "linux"
        };

        await FrameCodec.WriteJsonFrameAsync(ms, original, CancellationToken.None);

        ms.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(ms, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("HANDSHAKE_RESPONSE", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal("linux", doc.RootElement.GetProperty("os").GetString());
        Assert.Equal("test-device-id", doc.RootElement.GetProperty("deviceId").GetString());
    }

    [Fact]
    public async Task FrameCodec_RejectsOversizedFrame()
    {
        using var ms = new MemoryStream();
        // Write 4 bytes length indicating 2 MB (over 1 MB limit)
        byte[] lenBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(2 * 1024 * 1024));
        ms.Write(lenBytes, 0, 4);
        ms.Position = 0;

        var result = await FrameCodec.ReadFrameAsync(ms, CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task FrameCodec_RejectsNegativeOrZeroLength()
    {
        using var ms = new MemoryStream();
        byte[] lenBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(0));
        ms.Write(lenBytes, 0, 4);
        ms.Position = 0;

        var result = await FrameCodec.ReadFrameAsync(ms, CancellationToken.None);
        Assert.Null(result);
    }
}
