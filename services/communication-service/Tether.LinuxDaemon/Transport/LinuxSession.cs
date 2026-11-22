using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.LinuxDaemon.Devices;
using Tether.LinuxDaemon.Pairing;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Sessions;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Tether.Shared.Security;

namespace Tether.LinuxDaemon.Transport;

public sealed class LinuxSession : IDisposable
{
    private const string ServerCapabilities = "FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED,INPUT,WINDOWS_ADMIN,APP_MANAGEMENT";

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly IHostIdentity _identity;
    private readonly LinuxDeviceManager _deviceManager;
    private readonly LinuxSessionManager _sessionManager;
    private readonly LinuxPairingManager _pairingManager;
    private readonly LinuxTrustStore _trustStore;
    private readonly Func<ReadOnlyMemory<byte>, LinuxSession, CancellationToken, Task> _rawFrameRouter;

    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private SslStream? _tls;
    private Stream? _testStream;
    private long _lastFrameReceivedTicks;

    public string SessionId { get; } = Guid.NewGuid().ToString("N")[..8];
    public LinuxDevice? Device { get; private set; }
    public string IpAddress { get; set; } = "";

    public LinuxSession(
        IEventBus eventBus,
        ITetherLogger logger,
        IHostIdentity identity,
        LinuxDeviceManager deviceManager,
        LinuxSessionManager sessionManager,
        LinuxPairingManager pairingManager,
        LinuxTrustStore trustStore,
        Func<ReadOnlyMemory<byte>, LinuxSession, CancellationToken, Task> rawFrameRouter)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _deviceManager = deviceManager;
        _sessionManager = sessionManager;
        _pairingManager = pairingManager;
        _trustStore = trustStore;
        _rawFrameRouter = rawFrameRouter;
        _lastFrameReceivedTicks = DateTime.UtcNow.Ticks;
    }

    public LinuxSession(
        IEventBus eventBus,
        ITetherLogger logger,
        IHostIdentity identity,
        LinuxDeviceManager deviceManager,
        LinuxSessionManager sessionManager,
        LinuxPairingManager pairingManager,
        LinuxTrustStore trustStore,
        Func<JsonDocument, LinuxSession, LinuxDevice, Stream, CancellationToken, Task> legacyRouter)
        : this(eventBus, logger, identity, deviceManager, sessionManager, pairingManager, trustStore,
            async (memory, sess, ct) =>
            {
                if (memory.Length > 0 && memory.Span[0] == (byte)'{' && sess.Device != null)
                {
                    using var doc = JsonDocument.Parse(memory);
                    var st = (Stream?)sess._tls ?? sess._testStream;
                    if (st != null)
                    {
                        await legacyRouter(doc, sess, sess.Device, st, ct);
                    }
                }
            })
    {
    }

    public void SetStreamForTesting(Stream stream) => _testStream = stream;

    public void RecordPongReceived()
        => Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);

    public async Task WriteJsonFrameSafeAsync<T>(T payload, CancellationToken ct)
    {
        var stream = (Stream?)_tls ?? _testStream;
        if (stream == null) return;
        await _writeLock.WaitAsync(ct);
        try
        {
            await FrameCodec.WriteJsonFrameAsync(stream, payload, ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task WriteRawFrameSafeAsync(byte[] payload, CancellationToken ct)
    {
        var stream = (Stream?)_tls ?? _testStream;
        if (stream == null || payload == null || payload.Length == 0) return;
        await _writeLock.WaitAsync(ct);
        try
        {
            await FrameCodec.WriteFrameAsync(stream, payload, ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task RunAsync(TcpClient client, CancellationToken serviceCt)
    {
        var remote = (client.Client.RemoteEndPoint as System.Net.IPEndPoint)?.Address?.ToString() ?? "unknown";
        IpAddress = remote;
        _logger.Info($"LinuxSession [{SessionId}]: TCP connection accepted from {remote}.");

        try
        {
            var networkStream = client.GetStream();
            _tls = new SslStream(networkStream, leaveInnerStreamOpen: false);

            var sslOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _identity.Certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            };

            if (_identity.Certificate.HasPrivateKey)
            {
                sslOptions.ServerCertificateSelectionCallback = (_, _) => _identity.Certificate;
                sslOptions.ServerCertificate = null;
            }

            using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt);
            tlsCts.CancelAfter(TimeSpan.FromSeconds(10));

            await _tls.AuthenticateAsServerAsync(sslOptions, tlsCts.Token);
            _logger.Info($"LinuxSession [{SessionId}]: TLS established with {remote} ({_tls.NegotiatedCipherSuite}).");

            bool authenticated = await HandleHandshakeAsync(serviceCt);
            if (!authenticated || Device == null)
            {
                _logger.Warning($"LinuxSession [{SessionId}]: Closed without authentication.");
                return;
            }

            _sessionManager.RegisterSession(this);
            _deviceManager.MarkConnected(Device.Fingerprint);

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PHONE_CONNECTED,
                Source = nameof(LinuxSession),
                PayloadJson = JsonSerializer.Serialize(new
                {
                    deviceId = Device.DeviceId,
                    displayName = Device.DisplayName,
                    fingerprint = Device.Fingerprint
                })
            });

            await RunFrameLoopAsync(serviceCt);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxSession [{SessionId}] ended with error: {ex.Message}");
        }
        finally
        {
            _sessionManager.UnregisterSession(SessionId);
            if (Device != null)
            {
                _deviceManager.MarkDisconnected(Device.Fingerprint);
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.PHONE_DISCONNECTED,
                    Source = nameof(LinuxSession),
                    PayloadJson = JsonSerializer.Serialize(new
                    {
                        deviceId = Device.DeviceId,
                        displayName = Device.DisplayName,
                        fingerprint = Device.Fingerprint
                    })
                });
            }
        }
    }

    private async Task<bool> HandleHandshakeAsync(CancellationToken ct)
    {
        var stream = (Stream?)_tls ?? _testStream;
        if (stream == null) return false;

        using var hsDoc = await FrameCodec.ReadJsonFrameAsync(stream, ct);
        if (hsDoc == null) return false;

        string type = hsDoc.RootElement.TryGetProperty("type", out var tProp) ? (tProp.GetString() ?? "") : "";
        if (type != "HANDSHAKE_INIT") return false;

        var init = JsonSerializer.Deserialize<HandshakeInit>(hsDoc.RootElement.GetRawText());
        if (init == null || string.IsNullOrEmpty(init.PublicKey)) return false;

        string? phoneFp = LinuxTrustStore.ComputeFingerprintOrNull(init.PublicKey);
        if (phoneFp == null) return false;

        var trusted = _trustStore.FindByFingerprint(phoneFp);
        if (trusted != null)
        {
            // Already paired! Instant reconnect
            Device = _deviceManager.GetDevice(phoneFp) ?? LinuxDevice.FromRecord(trusted);

            var resp = new HandshakeResponse
            {
                DeviceId = _identity.DeviceId,
                DeviceName = _identity.DeviceName,
                PublicKey = _identity.GetPublicKeySpkiBase64(),
                Status = HandshakeStatus.Paired,
                Capabilities = ServerCapabilities,
                Pqc = false,
                Os = "linux"
            };

            await WriteJsonFrameSafeAsync(resp, ct);
            _logger.Info($"LinuxSession [{SessionId}]: Reconnected known phone '{Device.DisplayName}' ({phoneFp}).");
            return true;
        }

        if (!init.IsPairingRequested)
        {
            var unpResp = new HandshakeResponse
            {
                DeviceId = _identity.DeviceId,
                DeviceName = _identity.DeviceName,
                PublicKey = _identity.GetPublicKeySpkiBase64(),
                Status = HandshakeStatus.Unpaired,
                Capabilities = ServerCapabilities,
                Pqc = false,
                Os = "linux"
            };
            await WriteJsonFrameSafeAsync(unpResp, ct);
            return false;
        }

        // New pairing flow
        byte[] initBytes = JsonSerializer.SerializeToUtf8Bytes(init);
        var (pending, pairResp, _) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            ServerCapabilities,
            init.PublicKey,
            init.DeviceName,
            initBytes);

        await WriteJsonFrameSafeAsync(pairResp, ct);
        if (pairResp.Status == HandshakeStatus.PairingDenied) return false;

        // Read proof from phone
        using var proofCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        proofCts.CancelAfter(TimeSpan.FromSeconds(60));

        using var proofDoc = await FrameCodec.ReadJsonFrameAsync(stream, proofCts.Token);
        if (proofDoc == null) return false;

        string proofType = proofDoc.RootElement.TryGetProperty("type", out var ptProp) ? (ptProp.GetString() ?? "") : "";
        if (proofType != "HANDSHAKE_PROOF") return false;

        string proofReqId = proofDoc.RootElement.TryGetProperty("requestId", out var rProp) ? (rProp.GetString() ?? "") : "";
        string presentedProof = proofDoc.RootElement.TryGetProperty("proof", out var pProp) ? (pProp.GetString() ?? "") : "";

        if (string.IsNullOrEmpty(presentedProof) && proofDoc.RootElement.TryGetProperty("pin", out var pinProp))
        {
            presentedProof = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(pinProp.GetString() ?? ""));
        }

        if (_pairingManager.TryVerifyPhoneProof(proofReqId, presentedProof, out string hostProof, out var pairedPending))
        {
            Device = _deviceManager.GetDevice(phoneFp);
            await WriteJsonFrameSafeAsync(new
            {
                type = "HANDSHAKE_VERIFIED",
                status = "OK",
                hostProof = hostProof
            }, ct);
            return true;
        }

        await WriteJsonFrameSafeAsync(new
        {
            type = "HANDSHAKE_VERIFIED",
            status = "FAILED",
            reason = "Invalid PIN or proof"
        }, ct);
        return false;
    }

    private async Task RunFrameLoopAsync(CancellationToken ct)
    {
        var stream = (Stream?)_tls ?? _testStream;
        if (stream == null || Device == null) return;

        while (!ct.IsCancellationRequested)
        {
            using var frameCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            frameCts.CancelAfter(TimeSpan.FromSeconds(60));

            byte[]? frame;
            try
            {
                frame = await FrameCodec.ReadFrameAsync(stream, frameCts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Idle timeout, send ping
                await WriteJsonFrameSafeAsync(new { type = "PING", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, ct);
                continue;
            }

            if (frame == null || frame.Length == 0) break;

            Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);
            await _rawFrameRouter(frame, this, ct);
        }
    }

    public void Dispose()
    {
        _writeLock.Dispose();
        _tls?.Dispose();
    }
}
