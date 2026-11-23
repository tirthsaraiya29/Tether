using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

public class InProcessDaemonIntegrationTests : IAsyncLifetime
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
    private readonly LinuxTcpServer _server;

    public InProcessDaemonIntegrationTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_inproc_test_" + Guid.NewGuid().ToString("N"));
        _config = new LinuxDaemonConfig
        {
            DataDir = _testDir,
            RunDir = Path.Combine(_testDir, "run"),
            LogDir = Path.Combine(_testDir, "log"),
            ControlPort = 0 // Ephemeral port
        };
        _logger = new SerilogTetherLogger();
        _trustStore = new LinuxTrustStore(_logger, _config);
        _deviceManager = new LinuxDeviceManager(_logger, _trustStore);
        _identity = new LinuxIdentity(_logger, _config);
        _eventBus = new InMemoryEventBus(_logger);
        _pairingManager = new LinuxPairingManager(_eventBus, _logger, _identity, _deviceManager, _trustStore);
        _sessionManager = new LinuxSessionManager(_logger);

        _server = new LinuxTcpServer(
            _eventBus,
            _logger,
            _identity,
            _config,
            _deviceManager,
            _sessionManager,
            _pairingManager,
            _trustStore,
            (memory, sess, ct) => Task.CompletedTask);
    }

    public async Task InitializeAsync()
    {
        _server.Start();
        await _server.WaitForStartAsync(new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token);
    }

    public Task DisposeAsync()
    {
        _server.Dispose();
        _identity.Dispose();
        try
        {
            if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true);
        }
        catch { }
        return Task.CompletedTask;
    }

    private static (string spkiBase64, ECDsa key) GenerateClientKey()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()), ecdsa);
    }

    [Fact]
    public async Task InProcess_TlsHandshake_EstablishesTls13WithValidSpkiCertificate()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", _server.BoundPort);

        X509Certificate? serverCert = null;
        using var ssl = new SslStream(tcp.GetStream(), false, (sender, cert, chain, errors) =>
        {
            serverCert = cert;
            return true;
        });

        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13
        });

        Assert.NotNull(serverCert);
        byte[] spki = serverCert.GetPublicKey();
        Assert.True(spki.Length > 0);
    }

    [Fact]
    public async Task InProcess_HandshakeInit_ReturnsValidPendingPairing()
    {
        var (phoneSpki, _) = GenerateClientKey();

        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", _server.BoundPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        var init = new HandshakeInit
        {
            Version = "2.0",
            DeviceId = "TEST_PHONE_INPROC_01",
            DeviceName = "Test Pixel Device",
            PublicKey = phoneSpki,
            IsPairingRequested = true,
            Capabilities = "FILES,MEDIA,TERMINAL,ADMIN"
        };

        await FrameCodec.WriteJsonFrameAsync(ssl, init, CancellationToken.None);

        using var respDoc = await FrameCodec.ReadJsonFrameAsync(ssl, CancellationToken.None);
        Assert.NotNull(respDoc);

        var root = respDoc.RootElement;
        Assert.Equal("HANDSHAKE_RESPONSE", root.GetProperty("type").GetString());
        Assert.Equal("PAIRING_PENDING", root.GetProperty("status").GetString());
        Assert.Equal("linux", root.GetProperty("os").GetString());
        Assert.False(string.IsNullOrEmpty(root.GetProperty("requestId").GetString()));
        Assert.False(string.IsNullOrEmpty(root.GetProperty("publicKey").GetString()));
    }

    [Fact]
    public async Task InProcess_MalformedJson_GracefullyClosed()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", _server.BoundPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        byte[] garbage = "{ this is not valid json !@#$%^&* }"u8.ToArray();
        await FrameCodec.WriteFrameAsync(ssl, garbage, CancellationToken.None);

        byte[] buf = new byte[16];
        int read = await ssl.ReadAsync(buf, 0, buf.Length);
        Assert.Equal(0, read);
    }

    [Fact]
    public async Task InProcess_OversizedFrame_GracefullyClosed()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", _server.BoundPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        byte[] fakeHeader = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(fakeHeader, 50 * 1024 * 1024);

        await ssl.WriteAsync(fakeHeader, 0, fakeHeader.Length);
        await ssl.FlushAsync();

        byte[] buf = new byte[16];
        int read = await ssl.ReadAsync(buf, 0, buf.Length);
        Assert.Equal(0, read);
    }

    [Fact]
    public async Task InProcess_RapidConnectDisconnect_StressTest()
    {
        for (int i = 0; i < 15; i++)
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", _server.BoundPort);

            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync("localhost");

            ssl.Close();
        }

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", _server.BoundPort);
        Assert.True(client.Connected);
    }
}
