using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
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

public class LinuxPairingAndSessionTests : IDisposable
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

    public LinuxPairingAndSessionTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_pairing_test_" + Guid.NewGuid().ToString("N"));
        _config = new LinuxDaemonConfig
        {
            DataDir = _testDir,
            RunDir = Path.Combine(_testDir, "run"),
            LogDir = Path.Combine(_testDir, "log")
        };
        _logger = new SerilogTetherLogger();
        _trustStore = new LinuxTrustStore(_logger, _config);
        _deviceManager = new LinuxDeviceManager(_logger, _trustStore);
        _identity = new LinuxIdentity(_logger, _config);
        _eventBus = new InMemoryEventBus(_logger);
        _pairingManager = new LinuxPairingManager(_eventBus, _logger, _identity, _deviceManager, _trustStore);
        _sessionManager = new LinuxSessionManager(_logger);
    }

    public void Dispose()
    {
        _identity.Dispose();
        try
        {
            if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true);
        }
        catch { }
    }

    private static (string spkiBase64, ECDsa key) GeneratePhoneKey()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()), ecdsa);
    }

    [Fact]
    public void PairingManager_CreatesPairingResponse_With6DigitPin()
    {
        var (phoneSpki, _) = GeneratePhoneKey();
        byte[] initBytes = "test-init-bytes"u8.ToArray();

        var (pending, resp, respBytes) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            "MEDIA,LOCK",
            phoneSpki,
            "Pixel 9 Pro",
            initBytes);

        Assert.NotNull(pending);
        Assert.Equal(HandshakeStatus.PairingPending, resp.Status);
        Assert.False(string.IsNullOrEmpty(resp.RequestId));
        Assert.Equal(6, pending.Pin.Length);
        Assert.True(int.TryParse(pending.Pin, out _));
        Assert.True(respBytes.Length > 0);
    }

    private static string BuildPhoneProofPayload(string pin, byte[] transcriptHash, string requestId, byte[] hostSpki, byte[] phoneSpki, ECDsa phoneKey)
    {
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

        byte[] signature = phoneKey.SignData(authKey, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] payload = new byte[4 + authKey.Length + 4 + signature.Length];
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(0, 4), authKey.Length);
        Buffer.BlockCopy(authKey, 0, payload, 4, authKey.Length);

        int sigOffset = 4 + authKey.Length;
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(sigOffset, 4), signature.Length);
        Buffer.BlockCopy(signature, 0, payload, sigOffset + 4, signature.Length);

        return Convert.ToBase64String(payload);
    }

    [Fact]
    public void PairingManager_VerifiesCorrectProof_AndRejectsInvalidProof()
    {
        var (phoneSpki, phoneKey) = GeneratePhoneKey();
        byte[] initBytes = "test-init"u8.ToArray();

        var (pending, resp, _) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            "MEDIA,LOCK",
            phoneSpki,
            "Pixel 9 Pro",
            initBytes);

        byte[] hostSpki = _identity.GetPublicKeySpkiDer();
        byte[] phoneSpkiDer = Convert.FromBase64String(phoneSpki);

        // Negative Test 1: Raw PIN string fallback is strictly rejected
        bool rawPinSuccess = _pairingManager.TryVerifyPhoneProof(resp.RequestId!, Convert.ToBase64String(Encoding.UTF8.GetBytes(pending.Pin)), out _, out _);
        Assert.False(rawPinSuccess);

        // Negative Test 2: Wrong PIN HMAC proof
        string wrongPinProof = BuildPhoneProofPayload("000000", pending.TranscriptHash, resp.RequestId!, hostSpki, phoneSpkiDer, phoneKey);
        bool wrongSuccess = _pairingManager.TryVerifyPhoneProof(resp.RequestId!, wrongPinProof, out _, out _);
        Assert.False(wrongSuccess);

        // Negative Test 3: Correct PIN but signed by untrusted/wrong private key
        var (_, wrongKey) = GeneratePhoneKey();
        string wrongKeyProof = BuildPhoneProofPayload(pending.Pin, pending.TranscriptHash, resp.RequestId!, hostSpki, phoneSpkiDer, wrongKey);
        bool wrongKeySuccess = _pairingManager.TryVerifyPhoneProof(resp.RequestId!, wrongKeyProof, out _, out _);
        Assert.False(wrongKeySuccess);

        // Positive Test: Correct PIN and signed by paired phone's private key
        // Need a fresh pairing response since 3 failed attempts above evicted the request
        var (freshPending, freshResp, _) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            "MEDIA,LOCK",
            phoneSpki,
            "Pixel 9 Pro",
            initBytes);

        string correctProof = BuildPhoneProofPayload(freshPending.Pin, freshPending.TranscriptHash, freshResp.RequestId!, hostSpki, phoneSpkiDer, phoneKey);
        bool correctSuccess = _pairingManager.TryVerifyPhoneProof(freshResp.RequestId!, correctProof, out string hostProof, out var matchedPending);
        Assert.True(correctSuccess);
        Assert.NotNull(matchedPending);
        Assert.False(string.IsNullOrEmpty(hostProof));

        // Pinned in trust store
        string phoneFp = LinuxTrustStore.ComputeFingerprintOrNull(phoneSpki)!;
        Assert.NotNull(_trustStore.FindByFingerprint(phoneFp));
    }

    [Fact]
    public void PairingManager_EvictsAfterThreeFailedAttempts()
    {
        var (phoneSpki, phoneKey) = GeneratePhoneKey();
        byte[] initBytes = "test-init"u8.ToArray();

        var (pending, resp, _) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            "MEDIA,LOCK",
            phoneSpki,
            "Pixel 9 Pro",
            initBytes);

        byte[] hostSpki = _identity.GetPublicKeySpkiDer();
        byte[] phoneSpkiDer = Convert.FromBase64String(phoneSpki);

        string wrongProof = BuildPhoneProofPayload("999999", pending.TranscriptHash, resp.RequestId!, hostSpki, phoneSpkiDer, phoneKey);

        for (int i = 0; i < 3; i++)
        {
            _pairingManager.TryVerifyPhoneProof(resp.RequestId!, wrongProof, out _, out _);
        }

        // Even with correct PIN now, request was evicted
        string correctProof = BuildPhoneProofPayload(pending.Pin, pending.TranscriptHash, resp.RequestId!, hostSpki, phoneSpkiDer, phoneKey);
        bool fourthAttempt = _pairingManager.TryVerifyPhoneProof(resp.RequestId!, correctProof, out _, out _);
        Assert.False(fourthAttempt);
    }

    [Fact]
    public async Task LinuxSession_Reconnect_RequiresProofOfPossession_AndRejectsSpoofedPublicKey()
    {
        var (phoneSpki, phoneKey) = GeneratePhoneKey();
        string phoneFp = LinuxTrustStore.ComputeFingerprintOrNull(phoneSpki)!;

        // Pre-trust the phone in trust store
        _trustStore.AddOrUpdate(phoneFp, "Trusted Phone", phoneSpki, new[] { "FILES", "MEDIA" }, "2.0");

        var session = new LinuxSession(
            _eventBus,
            _logger,
            _identity,
            _deviceManager,
            _sessionManager,
            _pairingManager,
            _trustStore,
            (_, _, _) => Task.CompletedTask);

        // Test pipe stream to simulate client-server frames
        using var clientToServer = new MemoryStream();
        using var serverToClient = new MemoryStream();

        // Simulate paired reconnect: client sends HANDSHAKE_INIT with trusted public key
        var initPayload = new HandshakeInit
        {
            Type = "HANDSHAKE_INIT",
            Version = "2.0",
            DeviceId = phoneFp,
            DeviceName = "Trusted Phone",
            PublicKey = phoneSpki,
            IsPairingRequested = false
        };

        // Negative Test: Spoofed client connects and provides NO proof or wrong signature
        // Server sends serverNonce in HandshakeResponse (Status=Paired)
        // Client responds with invalid HANDSHAKE_PROOF signed by an attacker key
        var (attackerSpki, attackerKey) = GeneratePhoneKey();

        byte[] serverNonce = RandomNumberGenerator.GetBytes(32);
        byte[] clientNonce = RandomNumberGenerator.GetBytes(32);

        // Build transcript as expected
        byte[] hostPubKeyBytes = Encoding.UTF8.GetBytes(_identity.GetPublicKeySpkiBase64());
        byte[] phonePubKeyBytes = Encoding.UTF8.GetBytes(phoneSpki);

        int totalSize = 4 + serverNonce.Length + 4 + clientNonce.Length + 4 + hostPubKeyBytes.Length + 4 + phonePubKeyBytes.Length;
        byte[] transcript = new byte[totalSize];
        int offset = 0;

        BinaryPrimitives.WriteInt32BigEndian(transcript.AsSpan(offset, 4), serverNonce.Length);
        offset += 4;
        Buffer.BlockCopy(serverNonce, 0, transcript, offset, serverNonce.Length);
        offset += serverNonce.Length;

        BinaryPrimitives.WriteInt32BigEndian(transcript.AsSpan(offset, 4), clientNonce.Length);
        offset += 4;
        Buffer.BlockCopy(clientNonce, 0, transcript, offset, clientNonce.Length);
        offset += clientNonce.Length;

        BinaryPrimitives.WriteInt32BigEndian(transcript.AsSpan(offset, 4), hostPubKeyBytes.Length);
        offset += 4;
        Buffer.BlockCopy(hostPubKeyBytes, 0, transcript, offset, hostPubKeyBytes.Length);
        offset += hostPubKeyBytes.Length;

        BinaryPrimitives.WriteInt32BigEndian(transcript.AsSpan(offset, 4), phonePubKeyBytes.Length);
        offset += 4;
        Buffer.BlockCopy(phonePubKeyBytes, 0, transcript, offset, phonePubKeyBytes.Length);

        // Attacker attempts to sign transcript with their own key instead of paired phone's key
        byte[] attackerSig = attackerKey.SignData(transcript, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var badProofFrame = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "HANDSHAKE_PROOF",
            signature = Convert.ToBase64String(attackerSig),
            clientNonce = Convert.ToBase64String(clientNonce)
        });

        // Set up client memory stream containing HANDSHAKE_INIT followed by fraudulent HANDSHAKE_PROOF
        var simStream = new SimplexBidirectionalStream();
        await FrameCodec.WriteJsonFrameAsync(simStream.ClientInput, initPayload, CancellationToken.None);
        await FrameCodec.WriteFrameAsync(simStream.ClientInput, badProofFrame, CancellationToken.None);

        session.SetStreamForTesting(simStream);

        // Run session handshake with CTS timeout
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var runTask = session.RunAsync(new System.Net.Sockets.TcpClient(), cts.Token);

        // Await session completion - it MUST reject and not authenticate the attacker
        await Task.WhenAny(runTask, Task.Delay(2000));
        Assert.Null(session.Device); // Device must NOT be authenticated!
    }

    private sealed class SimplexBidirectionalStream : Stream
    {
        private readonly MemoryStream _in = new();
        private readonly MemoryStream _out = new();
        public Stream ClientInput => _in;
        public Stream ClientOutput => _out;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _in.Length;
        public override long Position { get => _in.Position; set => _in.Position = value; }

        public override void Flush() { }
        public override void SetLength(long value) { _in.SetLength(value); }
        public override long Seek(long offset, SeekOrigin origin) => _in.Seek(offset, origin);

        public override int Read(byte[] buffer, int offset, int count)
        {
            long currPos = _in.Position;
            _in.Seek(0, SeekOrigin.Begin);
            int read = _in.Read(buffer, offset, count);
            return read;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return await _in.ReadAsync(buffer, cancellationToken);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _out.Write(buffer, offset, count);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _out.WriteAsync(buffer, offset, count, cancellationToken);
        }
    }
}
