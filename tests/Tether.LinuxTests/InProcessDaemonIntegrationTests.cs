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
    public async Task InProcess_FullPairingFlow_SucceedsWithMatchingTranscriptHashAndPinProof()
    {
        var (phoneSpkiBase64, phoneKey) = GenerateClientKey();
        byte[] phoneSpki = Convert.FromBase64String(phoneSpkiBase64);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", _server.BoundPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        var init = new HandshakeInit
        {
            Version = "2.0",
            DeviceId = "TEST_PHONE_E2E_01",
            DeviceName = "Test Pixel E2E",
            PublicKey = phoneSpkiBase64,
            IsPairingRequested = true,
            Capabilities = "FILES,MEDIA,TERMINAL,ADMIN"
        };

        byte[] initBytes = JsonSerializer.SerializeToUtf8Bytes(init);
        await FrameCodec.WriteFrameAsync(ssl, initBytes, CancellationToken.None);

        byte[]? respBytes = await FrameCodec.ReadFrameAsync(ssl, CancellationToken.None);
        Assert.NotNull(respBytes);

        using var respDoc = JsonDocument.Parse(respBytes);
        var respRoot = respDoc.RootElement;
        Assert.Equal("HANDSHAKE_RESPONSE", respRoot.GetProperty("type").GetString());
        Assert.Equal("PAIRING_PENDING", respRoot.GetProperty("status").GetString());
        Assert.Equal("linux", respRoot.GetProperty("os").GetString());

        string requestId = respRoot.GetProperty("requestId").GetString()!;
        string hostSpkiBase64 = respRoot.GetProperty("publicKey").GetString()!;
        byte[] hostSpki = Convert.FromBase64String(hostSpkiBase64);

        // Find the pending pairing request generated on the daemon
        var pendingRequests = _pairingManager.GetPendingRequests();
        var pending = Assert.Single(pendingRequests, p => p.RequestId == requestId);
        string pin = pending.Pin;
        Assert.Equal(6, pin.Length);

        // Verify transcript hash
        byte[] transcriptHash;
        using (var sha = SHA512.Create())
        {
            var combined = new byte[initBytes.Length + respBytes.Length];
            Buffer.BlockCopy(initBytes, 0, combined, 0, initBytes.Length);
            Buffer.BlockCopy(respBytes, 0, combined, initBytes.Length, respBytes.Length);
            transcriptHash = sha.ComputeHash(combined);
        }
        Assert.Equal(pending.TranscriptHash, transcriptHash);

        // Compute HMAC-SHA256 AuthKey with SAS PIN
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin.Trim());
        byte[] authKey;
        using (var hmac = new HMACSHA256(pinBytes))
        {
            byte[] label = "TETHER-PAIRING-v2"u8.ToArray();
            byte[] reqIdBytes = Encoding.UTF8.GetBytes(requestId);
            using var ms = new MemoryStream();
            ms.Write(label);
            ms.Write(transcriptHash);
            ms.Write(reqIdBytes);
            ms.Write(hostSpki);
            ms.Write(phoneSpki);
            authKey = hmac.ComputeHash(ms.ToArray());
        }

        // Sign AuthKey with client private key
        byte[] signature = phoneKey.SignData(authKey, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        // Pack proof: len(authKey) || authKey || len(sig) || sig
        using var msProof = new MemoryStream();
        byte[] authKeyLen = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(authKeyLen, authKey.Length);
        msProof.Write(authKeyLen);
        msProof.Write(authKey);
        byte[] sigLen = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(sigLen, signature.Length);
        msProof.Write(sigLen);
        msProof.Write(signature);
        string phoneProofBase64 = Convert.ToBase64String(msProof.ToArray());

        // Send PAIRING_CONFIRMED frame
        var confirmed = new
        {
            type = "PAIRING_CONFIRMED",
            requestId = requestId,
            proof = phoneProofBase64
        };
        await FrameCodec.WriteJsonFrameAsync(ssl, confirmed, CancellationToken.None);

        // Receive PAIRING_COMPLETE frame
        using var completeDoc = await FrameCodec.ReadJsonFrameAsync(ssl, CancellationToken.None);
        Assert.NotNull(completeDoc);
        var completeRoot = completeDoc.RootElement;
        Assert.Equal("PAIRING_COMPLETE", completeRoot.GetProperty("type").GetString());
        Assert.Equal("OK", completeRoot.GetProperty("status").GetString());
        Assert.Equal("linux", completeRoot.GetProperty("os").GetString());

        string hostProofBase64 = completeRoot.GetProperty("proof").GetString()!;
        Assert.False(string.IsNullOrEmpty(hostProofBase64));

        // Verify mutual server proof
        byte[] expectedServerProof;
        using (var serverHmac = new HMACSHA256(pinBytes))
        {
            byte[] label = "SERVER-OK"u8.ToArray();
            using var ms = new MemoryStream();
            ms.Write(label);
            ms.Write(authKey);
            ms.Write(hostSpki);
            ms.Write(phoneSpki);
            expectedServerProof = serverHmac.ComputeHash(ms.ToArray());
        }
        Assert.Equal(Convert.ToBase64String(expectedServerProof), hostProofBase64);

        // Verify device is recorded in trust store
        string phoneFp = LinuxTrustStore.ComputeFingerprintOrNull(phoneSpkiBase64)!;
        var trustedDevice = _trustStore.FindByFingerprint(phoneFp);
        Assert.NotNull(trustedDevice);
        Assert.Equal("Test Pixel E2E", trustedDevice.DisplayName);
    }

    [Fact]
    public async Task InProcess_Pairing_InvalidPin_ReturnsRemainingAttempts()
    {
        var (phoneSpkiBase64, phoneKey) = GenerateClientKey();
        byte[] phoneSpki = Convert.FromBase64String(phoneSpkiBase64);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", _server.BoundPort);

        using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");

        var init = new HandshakeInit
        {
            Version = "2.0",
            DeviceId = "TEST_PHONE_INVALID_PIN_01",
            DeviceName = "Test Pixel Invalid PIN",
            PublicKey = phoneSpkiBase64,
            IsPairingRequested = true,
            Capabilities = "FILES,MEDIA,TERMINAL,ADMIN"
        };

        byte[] initBytes = JsonSerializer.SerializeToUtf8Bytes(init);
        await FrameCodec.WriteFrameAsync(ssl, initBytes, CancellationToken.None);

        byte[]? respBytes = await FrameCodec.ReadFrameAsync(ssl, CancellationToken.None);
        Assert.NotNull(respBytes);

        using var respDoc = JsonDocument.Parse(respBytes);
        var respRoot = respDoc.RootElement;
        string requestId = respRoot.GetProperty("requestId").GetString()!;
        string hostSpkiBase64 = respRoot.GetProperty("publicKey").GetString()!;
        byte[] hostSpki = Convert.FromBase64String(hostSpkiBase64);

        // Intentionally wrong PIN
        string wrongPin = "000000";
        byte[] pinBytes = Encoding.UTF8.GetBytes(wrongPin);

        byte[] transcriptHash;
        using (var sha = SHA512.Create())
        {
            var combined = new byte[initBytes.Length + respBytes.Length];
            Buffer.BlockCopy(initBytes, 0, combined, 0, initBytes.Length);
            Buffer.BlockCopy(respBytes, 0, combined, initBytes.Length, respBytes.Length);
            transcriptHash = sha.ComputeHash(combined);
        }

        byte[] authKey;
        using (var hmac = new HMACSHA256(pinBytes))
        {
            byte[] label = "TETHER-PAIRING-v2"u8.ToArray();
            byte[] reqIdBytes = Encoding.UTF8.GetBytes(requestId);
            using var ms = new MemoryStream();
            ms.Write(label);
            ms.Write(transcriptHash);
            ms.Write(reqIdBytes);
            ms.Write(hostSpki);
            ms.Write(phoneSpki);
            authKey = hmac.ComputeHash(ms.ToArray());
        }

        byte[] signature = phoneKey.SignData(authKey, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        using var msProof = new MemoryStream();
        byte[] authKeyLen = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(authKeyLen, authKey.Length);
        msProof.Write(authKeyLen);
        msProof.Write(authKey);
        byte[] sigLen = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(sigLen, signature.Length);
        msProof.Write(sigLen);
        msProof.Write(signature);
        string phoneProofBase64 = Convert.ToBase64String(msProof.ToArray());

        var confirmed = new
        {
            type = "PAIRING_CONFIRMED",
            requestId = requestId,
            proof = phoneProofBase64
        };
        await FrameCodec.WriteJsonFrameAsync(ssl, confirmed, CancellationToken.None);

        using var errDoc = await FrameCodec.ReadJsonFrameAsync(ssl, CancellationToken.None);
        Assert.NotNull(errDoc);
        var errRoot = errDoc.RootElement;
        Assert.Equal("PAIRING_INVALID_PIN", errRoot.GetProperty("type").GetString());
        Assert.Equal(2, errRoot.GetProperty("remainingAttempts").GetInt32());

        // Verify device is NOT added to trust store
        string phoneFp = LinuxTrustStore.ComputeFingerprintOrNull(phoneSpkiBase64)!;
        Assert.Null(_trustStore.FindByFingerprint(phoneFp));
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
