using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Transport;
using Xunit;

namespace Tether.LinuxTests;

[Collection("LiveDaemon")]
public class LiveDaemonIntegrationTests
{
    private const int TcpPort = 37123;
    private const int HttpsPort = 37124;

    private static bool IsLiveDaemonRunning()
    {
        try
        {
            using var tcp = new TcpClient();
            var ar = tcp.BeginConnect("127.0.0.1", TcpPort, null, null);
            bool success = ar.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(500));
            if (!success) return false;
            tcp.EndConnect(ar);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private const string SkipLiveDaemonReason = "Live daemon integration tests require an external live Linux daemon on localhost:37123. For automated in-process integration testing, see InProcessDaemonIntegrationTests.";

    private static (string spkiBase64, ECDsa key) GenerateClientKey()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()), ecdsa);
    }

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_HealthEndpoint_Returns200Ok()
    {
        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler);

        var resp = await client.GetAsync($"https://127.0.0.1:{HttpsPort}/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string text = await resp.Content.ReadAsStringAsync();
        Assert.Equal("OK", text);
    }

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_ProtectedEndpoints_RejectUnauthorized()
    {
        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler);

        var endpoints = new[] { "/windows", "/apps", "/file/token" };
        foreach (var ep in endpoints)
        {
            var resp = await client.GetAsync($"https://127.0.0.1:{HttpsPort}{ep}");
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }
    }

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_TlsHandshake_EstablishesTls13WithValidSpkiCertificate()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", TcpPort);

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

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_HandshakeInit_ReturnsValidPendingPairing()
    {
        var (phoneSpki, phoneKey) = GenerateClientKey();

        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", TcpPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        var init = new HandshakeInit
        {
            Version = "2.0",
            DeviceId = "TEST_PHONE_LIVE_01",
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

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_RapidConnectDisconnect_StressTest()
    {
        // Perform 25 rapid TLS connection cycles
        for (int i = 0; i < 25; i++)
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync("127.0.0.1", TcpPort);

            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync("localhost");

            // Write a small ping or close immediately
            ssl.Close();
        }

        // Verify daemon is still alive and responsive after stress loop
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", TcpPort);
        Assert.True(client.Connected);
    }

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_MalformedJson_GracefullyClosed()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", TcpPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        // Send a frame with garbage JSON
        byte[] garbage = "{ this is not valid json !@#$%^&* }"u8.ToArray();
        await FrameCodec.WriteFrameAsync(ssl, garbage, CancellationToken.None);

        // Daemon should reject and close the stream
        byte[] buf = new byte[16];
        int read = await ssl.ReadAsync(buf, 0, buf.Length);
        Assert.Equal(0, read);
    }

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_OversizedFrame_GracefullyClosed()
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", TcpPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        // Send a header specifying an illegal size (e.g. 50 MB > 1 MB max)
        byte[] fakeHeader = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(fakeHeader, 50 * 1024 * 1024);

        await ssl.WriteAsync(fakeHeader, 0, fakeHeader.Length);
        await ssl.FlushAsync();

        // Daemon should close connection immediately upon validating length
        byte[] buf = new byte[16];
        int read = await ssl.ReadAsync(buf, 0, buf.Length);
        Assert.Equal(0, read);
    }

    [Fact(Skip = SkipLiveDaemonReason)]
    public async Task LiveDaemon_UdpDiscovery_RespondsWithMatchingInfo()
    {
        IPAddress? lanIp = null;
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
            var ipProps = ni.GetIPProperties();
            foreach (var ua in ipProps.UnicastAddresses)
            {
                if (ua.Address.AddressFamily == AddressFamily.InterNetwork &&
                    Tether.LinuxDaemon.Discovery.LinuxUdpDiscovery.IsPrivateIpv4(ua.Address))
                {
                    lanIp = ua.Address;
                    break;
                }
            }
            if (lanIp != null) break;
        }

        if (lanIp == null) return;

        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = 2000;

        var probe = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_PROBE",
            deviceId = "test-probe-client"
        });

        await udp.SendAsync(probe, probe.Length, new IPEndPoint(lanIp, HttpsPort));

        var receiveTask = udp.ReceiveAsync();
        var completed = await Task.WhenAny(receiveTask, Task.Delay(2000));
        if (completed == receiveTask)
        {
            var result = await receiveTask;
            string json = Encoding.UTF8.GetString(result.Buffer);
            using var doc = JsonDocument.Parse(json);
            Assert.Equal("TETHER_DISCOVERY_RESPONSE", doc.RootElement.GetProperty("type").GetString());
            Assert.Equal("linux", doc.RootElement.GetProperty("os").GetString());
            Assert.Equal(TcpPort, doc.RootElement.GetProperty("tcpPort").GetInt32());
        }
    }
}
