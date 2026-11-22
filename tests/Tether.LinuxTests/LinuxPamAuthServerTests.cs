using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Security;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxPamAuthServerTests : IDisposable
{
    private readonly string _testDir;
    private readonly LinuxDaemonConfig _config;
    private readonly ITetherLogger _logger;
    private readonly LinuxPamAuthServer _server;

    public LinuxPamAuthServerTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_pam_test_" + Guid.NewGuid().ToString("N"));
        _config = new LinuxDaemonConfig
        {
            DataDir = _testDir,
            RunDir = Path.Combine(_testDir, "run"),
            LogDir = Path.Combine(_testDir, "log"),
            PamSocketPath = Path.Combine(_testDir, "run", "auth.sock")
        };
        _logger = new SerilogTetherLogger();
        _server = new LinuxPamAuthServer(_logger, _config);
    }

    public void Dispose()
    {
        _server.Dispose();
        try
        {
            if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true);
        }
        catch { }
    }

    [Fact]
    public void ArmUnlockGrant_AllowsSingleConsumption_AndExpires()
    {
        _server.ArmUnlockGrant("testuser", "phone-fp-1", validitySeconds: 2);
        Assert.True(_server.HasActiveGrant("testuser"));
        Assert.False(_server.HasActiveGrant("otheruser"));

        // First consume succeeds
        bool first = _server.ConsumeGrant("testuser");
        Assert.True(first);

        // Second consume fails (one-time use)
        bool second = _server.ConsumeGrant("testuser");
        Assert.False(second);
        Assert.False(_server.HasActiveGrant("testuser"));
    }

    [Fact]
    public void ArmUnlockGrant_ExpiredGrantFails()
    {
        _server.ArmUnlockGrant("testuser", "phone-fp-1", validitySeconds: -1);
        Assert.False(_server.HasActiveGrant("testuser"));
        Assert.False(_server.ConsumeGrant("testuser"));
    }

    [Fact]
    public async Task PamSocket_Ipc_AuthenticatesGrantedUser()
    {
        _server.Start();
        Assert.True(File.Exists(_config.PamSocketPath));

        _server.ArmUnlockGrant("alice", "phone-123", validitySeconds: 5);

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        // Send AUTH_REQUEST for alice
        var req = new { action = "AUTH_REQUEST", user = "alice", service = "gdm-password" };
        byte[] reqBytes = JsonSerializer.SerializeToUtf8Bytes(req);
        byte[] lenBytes = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lenBytes, reqBytes.Length);

        await client.SendAsync(lenBytes, SocketFlags.None);
        await client.SendAsync(reqBytes, SocketFlags.None);

        // Read response
        byte[] respLenBytes = new byte[4];
        int r1 = await client.ReceiveAsync(respLenBytes, SocketFlags.None);
        Assert.Equal(4, r1);
        int respLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(respLenBytes);
        Assert.True(respLen > 0);

        byte[] respBody = new byte[respLen];
        int r2 = await client.ReceiveAsync(respBody, SocketFlags.None);
        Assert.Equal(respLen, r2);

        using var doc = JsonDocument.Parse(respBody);
        Assert.Equal("SUCCESS", doc.RootElement.GetProperty("status").GetString());
        Assert.Equal("alice", doc.RootElement.GetProperty("user").GetString());
    }

    [Fact]
    public async Task PamSocket_Ipc_RejectsUngrantedUser()
    {
        _server.Start();

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        // Send AUTH_REQUEST for ungranted user 'bob'
        var req = new { action = "AUTH_REQUEST", user = "bob", service = "sudo" };
        byte[] reqBytes = JsonSerializer.SerializeToUtf8Bytes(req);
        byte[] lenBytes = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lenBytes, reqBytes.Length);

        await client.SendAsync(lenBytes, SocketFlags.None);
        await client.SendAsync(reqBytes, SocketFlags.None);

        byte[] respLenBytes = new byte[4];
        await client.ReceiveAsync(respLenBytes, SocketFlags.None);
        int respLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(respLenBytes);

        byte[] respBody = new byte[respLen];
        await client.ReceiveAsync(respBody, SocketFlags.None);

        using var doc = JsonDocument.Parse(respBody);
        Assert.Equal("DENIED", doc.RootElement.GetProperty("status").GetString());
    }
}
