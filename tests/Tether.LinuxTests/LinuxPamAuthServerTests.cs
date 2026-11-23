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
        _server = new LinuxPamAuthServer(_logger, _config)
        {
            BypassUidCheckForTesting = true
        };
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

        // Send AUTH_REQUEST for alice via permitted service gdm-password
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
    public async Task PamSocket_Ipc_RejectsUnpermittedService_EvenIfGrantArmed()
    {
        // TETH-SEC-LNX-001 Regression Test: Unpermitted services (sshd, sudo) MUST NOT consume workstation grants
        _server.Start();
        _server.ArmUnlockGrant("alice", "phone-123", validitySeconds: 15);

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        // Attempt to consume unlock grant via sshd
        var req = new { action = "AUTH_REQUEST", user = "alice", service = "sshd" };
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
        Assert.Equal("SERVICE_DENIED", doc.RootElement.GetProperty("status").GetString());
        Assert.Contains("not authorized", doc.RootElement.GetProperty("reason").GetString());

        // Verify the grant was NOT consumed by the unauthorized service
        Assert.True(_server.HasActiveGrant("alice"));
    }

    [Fact]
    public async Task PamSocket_Ipc_ReturnsNoGrantForUngrantedUser()
    {
        _server.Start();

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        // Send AUTH_REQUEST for ungranted user 'bob' on gdm-password
        var req = new { action = "AUTH_REQUEST", user = "bob", service = "gdm-password" };
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
        // Returns NO_GRANT so PAM can gracefully fall back to native password
        Assert.Equal("NO_GRANT", doc.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task PamSocket_Ipc_StatusQuery_ReturnsHealthAndConnectivity()
    {
        _server.PhoneConnectedProvider = () => true;
        _server.ConnectedDeviceNameProvider = () => "Pixel 9 Pro";
        _server.ConnectedDeviceFingerprintProvider = () => "A1:B2:C3:D4";
        _server.Start();

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        var req = new { action = "STATUS_REQUEST", user = "alice" };
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
        Assert.Equal("ONLINE", doc.RootElement.GetProperty("status").GetString());
        Assert.True(doc.RootElement.GetProperty("phoneConnected").GetBoolean());
        Assert.Equal("Pixel 9 Pro", doc.RootElement.GetProperty("connectedDeviceName").GetString());
        Assert.Equal("A1:B2:C3:D4", doc.RootElement.GetProperty("connectedDeviceFingerprint").GetString());
    }

    [Fact]
    public async Task PamSocket_Ipc_RejectsArmGrantOverIpc_ByDefault()
    {
        // TETH-SEC-LNX-002: Local IPC callers must NEVER manufacture unlock grants.
        _server.AllowIpcArmGrantForTesting = false;
        _server.Start();

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        var req = new { action = "ARM_GRANT", user = "root", deviceId = "malicious-local" };
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
        Assert.Contains("ARM_GRANT cannot be invoked via local IPC", doc.RootElement.GetProperty("reason").GetString());
        Assert.False(_server.HasActiveGrant("root"));
    }

    [Fact]
    public async Task PamSocket_Ipc_RequestPhoneAuth_DispatchesPrompt_WhenPhoneConnected()
    {
        bool promptDispatched = false;
        string? promptedUser = null;

        _server.PhoneConnectedProvider = () => true;
        _server.RequestPhoneAuthHandler = (user) =>
        {
            promptDispatched = true;
            promptedUser = user;
        };
        _server.Start();

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        var req = new { action = "REQUEST_PHONE_AUTH", user = "testuser" };
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
        Assert.Equal("PROMPTED", doc.RootElement.GetProperty("status").GetString());
        Assert.Equal("testuser", doc.RootElement.GetProperty("user").GetString());
        Assert.True(promptDispatched);
        Assert.Equal("testuser", promptedUser);
        Assert.True(_server.HasPendingPrompt("testuser"));
    }

    [Fact]
    public async Task PamSocket_Ipc_RequestPhoneAuth_FailsWhenPhoneDisconnected()
    {
        _server.PhoneConnectedProvider = () => false;
        _server.Start();

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        var req = new { action = "REQUEST_PHONE_AUTH", user = "testuser" };
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
        Assert.Equal("PHONE_DISCONNECTED", doc.RootElement.GetProperty("status").GetString());
        Assert.False(_server.HasPendingPrompt("testuser"));
    }

    [Fact]
    public async Task PamSocket_Ipc_ConcurrentGrantConsumption_OnlyOneSucceeds()
    {
        _server.Start();
        _server.ArmUnlockGrant("charlie", "phone-999", validitySeconds: 15);

        int successCount = 0;
        int consumedCount = 0;

        var tasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

            var req = new { action = "AUTH_REQUEST", user = "charlie", service = "gdm-password" };
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
            string status = doc.RootElement.GetProperty("status").GetString() ?? "";
            if (status == "SUCCESS") Interlocked.Increment(ref successCount);
            else if (status == "CONSUMED" || status == "NO_GRANT") Interlocked.Increment(ref consumedCount);
        });

        await Task.WhenAll(tasks);

        // Exactly one consumer must receive SUCCESS; all other concurrent callers must be rejected
        Assert.Equal(1, successCount);
        Assert.Equal(9, consumedCount);
        Assert.False(_server.HasActiveGrant("charlie"));
    }

    [Fact]
    public async Task PamSocket_Ipc_RejectsOversizedRequest()
    {
        _server.Start();

        using var client = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await client.ConnectAsync(new UnixDomainSocketEndPoint(_config.PamSocketPath));

        // Send length header claiming 8192 bytes (> 4096 byte maximum)
        byte[] lenBytes = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lenBytes, 8192);
        await client.SendAsync(lenBytes, SocketFlags.None);

        // Server must close connection or reject without reading 8KB body
        byte[] buffer = new byte[16];
        int read = await client.ReceiveAsync(buffer, SocketFlags.None);
        Assert.Equal(0, read); // Socket closed
    }
}
