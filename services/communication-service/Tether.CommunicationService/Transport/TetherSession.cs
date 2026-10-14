using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Pairing;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Trust;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Transport;

public sealed class TetherSession : IDisposable
{
    private const string ProtocolVersion = "2.0";
    private const string ServerCaps = "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED,INPUT";

    private const byte PacketTypeInputEvent = 0x05;

    private static readonly TimeSpan PairingConfirmTimeout = TimeSpan.FromSeconds(120);

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly DeviceManager _deviceManager;
    private readonly SessionManager _sessionManager;
    private readonly PairingManager _pairingManager;
    private readonly PacketRouter _packetRouter;
    private readonly InputForwarder _inputForwarder;

    private SslStream? _tls;
    private long _lastFrameReceivedTicks;

    public string SessionId { get; } = Guid.NewGuid().ToString("N")[..8];
    public TetherDevice? Device { get; private set; }

    public TetherSession(
        IEventBus eventBus,
        ITetherLogger logger,
        WindowsIdentity identity,
        DeviceManager deviceManager,
        SessionManager sessionManager,
        PairingManager pairingManager,
        PacketRouter packetRouter,
        InputForwarder inputForwarder)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _deviceManager = deviceManager;
        _sessionManager = sessionManager;
        _pairingManager = pairingManager;
        _packetRouter = packetRouter;
        _inputForwarder = inputForwarder;
        _lastFrameReceivedTicks = DateTime.UtcNow.Ticks;
    }

    public void RecordPongReceived()
    {
        Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);
    }

    public async Task SendLaptopStateAsync(LaptopSnapshot snap, CancellationToken ct)
    {
        var tls = _tls;
        if (tls == null) return;
        try
        {
            await FrameCodec.WriteJsonFrameAsync(tls, new LaptopStateFrame
            {
                BatteryLevel = snap.BatteryLevel,
                BatteryPercent = snap.BatteryLevel,
                IsCharging = snap.IsCharging,
                LockState = snap.LockState,
                WallpaperB64 = snap.WallpaperB64,
                WallpaperHash = snap.WallpaperHash,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            }, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"TetherSession [{SessionId}]: Error pushing LAPTOP_STATE: {ex.Message}");
        }
    }

    public async Task SendRawFrameAsync(byte[] payload, CancellationToken ct)
    {
        var tls = _tls;
        if (tls == null || payload == null || payload.Length == 0) return;
        try
        {
            await FrameCodec.WriteFrameAsync(tls, payload, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"TetherSession [{SessionId}]: Error pushing raw frame: {ex.Message}");
        }
    }

    public async Task RunAsync(TcpClient client, CancellationToken serviceCt)
    {
        var remote = (client.Client.RemoteEndPoint as System.Net.IPEndPoint)?.Address?.ToString() ?? "unknown";
        _logger.Info($"TetherSession [{SessionId}]: TCP connection accepted from {remote}.");

        try
        {
            var networkStream = client.GetStream();
            _tls = new SslStream(networkStream, leaveInnerStreamOpen: false);

            var sslOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _identity.Certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            };

            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(180));

            await _tls.AuthenticateAsServerAsync(sslOptions, handshakeCts.Token);
            _logger.Info($"TetherSession [{SessionId}]: TLS 1.3 established with {remote} ({_tls.NegotiatedCipherSuite}).");

            bool authenticated = await HandleHandshakeAsync(handshakeCts.Token);
            if (!authenticated || Device == null)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Closed without authentication.");
                return;
            }

            _sessionManager.RegisterSession(this);

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PHONE_CONNECTED,
                Source = nameof(TetherSession),
                PayloadJson = JsonSerializer.Serialize(new
                {
                    deviceId = Device.DeviceId,
                    displayName = Device.DisplayName,
                    fingerprint = Device.Fingerprint
                })
            });

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.TRUST_RESTORED,
                Source = nameof(TetherSession)
            });

            try
            {
                LaptopStateCollector.ResetWallpaperHashCache();
                var initSnap = LaptopStateCollector.GetLaptopSnapshotForPhone(_logger);
                await FrameCodec.WriteJsonFrameAsync(_tls!, new LaptopStateFrame
                {
                    BatteryLevel = initSnap.BatteryLevel,
                    BatteryPercent = initSnap.BatteryLevel,
                    IsCharging = initSnap.IsCharging,
                    LockState = initSnap.LockState,
                    WallpaperB64 = initSnap.WallpaperB64,
                    WallpaperHash = initSnap.WallpaperHash,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                }, serviceCt);
            }
            catch (Exception ex)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Failed sending initial LAPTOP_STATE frame: {ex.Message}");
            }

            await CommandAndHeartbeatLoopAsync(serviceCt);
        }
        catch (OperationCanceledException) { _logger.Info($"TetherSession [{SessionId}]: Handshake timed out."); }
        catch (AuthenticationException ex) { _logger.Warning($"TetherSession [{SessionId}]: TLS failure: {ex.Message}"); }
        catch (Exception ex) { _logger.Warning($"TetherSession [{SessionId}]: Session error: {ex.Message}"); }
        finally
        {
            _sessionManager.UnregisterSession(this);
            if (Device != null)
            {
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.PHONE_DISCONNECTED,
                    Source = nameof(TetherSession),
                    PayloadJson = JsonSerializer.Serialize(new { deviceId = Device.DeviceId })
                });
            }
        }
    }

    private async Task<bool> HandleHandshakeAsync(CancellationToken ct)
    {
        var stream = _tls!;

        var initFrameBytes = await FrameCodec.ReadFrameAsync(stream, ct);
        if (initFrameBytes is null)
        {
            _logger.Warning($"TetherSession [{SessionId}]: No HANDSHAKE_INIT received.");
            return false;
        }

        HandshakeInit? init;
        try { init = JsonSerializer.Deserialize<HandshakeInit>(initFrameBytes); }
        catch (JsonException ex)
        {
            _logger.Warning($"TetherSession [{SessionId}]: Malformed HANDSHAKE_INIT: {ex.Message}");
            return false;
        }

        if (init == null || !string.Equals(init.Type, "HANDSHAKE_INIT", StringComparison.Ordinal) || string.IsNullOrEmpty(init.PublicKey))
        {
            _logger.Warning($"TetherSession [{SessionId}]: Rejected HANDSHAKE_INIT (bad type or missing public key).");
            return false;
        }

        string? phoneFingerprint = TrustStore.ComputeFingerprintOrNull(init.PublicKey);
        if (phoneFingerprint == null)
        {
            _logger.Warning($"TetherSession [{SessionId}]: Rejected HANDSHAKE_INIT (invalid public key base64).");
            return false;
        }

        var knownDevice = _deviceManager.GetByFingerprint(phoneFingerprint);

        // If the phone explicitly says it has no pinned key for us, do a fresh
        // interactive pairing even if we still have it marked Paired. This
        // covers the case where the phone's pinned key was lost or the app was
        // reinstalled while our trust store still had the fingerprint.
        if (init.IsPairingRequested)
        {
            var (pending, respPayload, respBytes) = _pairingManager.CreatePairingResponse(
                _identity.DeviceId,
                _identity.DeviceName,
                _identity.GetPublicKeySpkiBase64(),
                ServerCaps,
                init.PublicKey,
                init.DeviceName,
                initFrameBytes);

            await FrameCodec.WriteFrameAsync(stream, respBytes, ct);
            _logger.Info($"TetherSession [{SessionId}]: Sent HANDSHAKE_RESPONSE (PAIRING_PENDING) with requestId '{pending.RequestId}'. Waiting for PAIRING_CONFIRMED...");

            // Loop reading frames while we wait for the phone's PAIRING_CONFIRMED.
            // The phone may send PINGs (keepalive, telemetry polls) during the
            // window before the user enters the PIN; those must not abort the
            // pairing session. We respond to PING with PONG and keep waiting.
            // Only PAIRING_CONFIRMED, PAIRING_REJECTED, or a real timeout end
            // this loop.
            JsonDocument? confirmedDoc = null;
            var deadline = DateTime.UtcNow + PairingConfirmTimeout;

            while (DateTime.UtcNow < deadline)
            {
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readCts.CancelAfter(TimeSpan.FromSeconds(30));

                JsonDocument? frame;
                try
                {
                    frame = await FrameCodec.ReadJsonFrameAsync(stream, readCts.Token);
                }
                catch (OperationCanceledException)
                {
                    frame = null;
                }

                if (frame is null)
                {
                    // read timeout or socket closed; keep waiting up to the
                    // outer deadline so the user still has time to enter the PIN
                    if (!stream.CanRead) break;
                    continue;
                }

                string frameType = frame.RootElement.TryGetProperty("type", out var tp)
                    ? tp.GetString() ?? ""
                    : "";

                if (string.Equals(frameType, "PING", StringComparison.Ordinal))
                {
                    try
                    {
                        await FrameCodec.WriteJsonFrameAsync(stream, new
                        {
                            type = "PONG",
                            timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                        }, ct);
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"TetherSession [{SessionId}]: Failed sending PONG during pairing wait: {ex.Message}");
                        frame.Dispose();
                        break;
                    }
                    frame.Dispose();
                    continue;
                }

                if (string.Equals(frameType, "PAIRING_REJECTED", StringComparison.Ordinal))
                {
                    _logger.Info($"TetherSession [{SessionId}]: Pairing rejected by phone before PIN confirmation.");
                    frame.Dispose();
                    return false;
                }

                // Anything else: this is what we were waiting for. Let the
                // outer code validate that it is actually PAIRING_CONFIRMED.
                confirmedDoc = frame;
                break;
            }

            if (confirmedDoc == null)
            {
                _logger.Warning($"TetherSession [{SessionId}]: No PAIRING_CONFIRMED frame received.");
                return false;
            }

            using (confirmedDoc)
            {
                string confirmedType = confirmedDoc.RootElement.TryGetProperty("type", out var t)
                    ? t.GetString() ?? ""
                    : "";

                if (!string.Equals(confirmedType, "PAIRING_CONFIRMED", StringComparison.Ordinal))
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Expected PAIRING_CONFIRMED but got '{confirmedType}'.");
                    return false;
                }

                string reqId = confirmedDoc.RootElement.TryGetProperty("requestId", out var rp)
                    ? rp.GetString() ?? ""
                    : "";
                string proofBase64 = confirmedDoc.RootElement.TryGetProperty("proof", out var pp)
                    ? pp.GetString() ?? ""
                    : "";

                bool verified = _pairingManager.TryVerifyPhoneProof(reqId, proofBase64, out string winProofBase64, out _);
                if (!verified)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: PIN proof verification failed for requestId '{reqId}'.");
                    await FrameCodec.WriteJsonFrameAsync(stream, new { type = "PAIRING_COMPLETE", status = "DENIED" }, ct);
                    return false;
                }

                await FrameCodec.WriteJsonFrameAsync(stream, new
                {
                    type = "PAIRING_COMPLETE",
                    status = "OK",
                    proof = winProofBase64,
                    capabilities = ServerCaps
                }, ct);

                Device = _deviceManager.GetByFingerprint(phoneFingerprint);
                _logger.Info($"TetherSession [{SessionId}]: Pairing complete and device '{phoneFingerprint}' authenticated!");
                return true;
            }
        }

        if (knownDevice != null && knownDevice.TrustState == DeviceTrustState.Paired)
        {
            byte[] serverNonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            string challengeBase64 = Convert.ToBase64String(serverNonce);

            await FrameCodec.WriteJsonFrameAsync(stream, new
            {
                type = "AUTH_CHALLENGE",
                challenge = challengeBase64
            }, ct);

            using var authDoc = await FrameCodec.ReadJsonFrameAsync(stream, ct);
            if (authDoc == null)
            {
                _logger.Warning($"TetherSession [{SessionId}]: No AUTH_RESPONSE received for challenge.");
                return false;
            }

            var root = authDoc.RootElement;
            if (!root.TryGetProperty("type", out var typeProp) ||
                !string.Equals(typeProp.GetString(), "AUTH_RESPONSE", StringComparison.Ordinal))
            {
                _logger.Warning($"TetherSession [{SessionId}]: Expected AUTH_RESPONSE frame, received '{typeProp.GetString()}'.");
                return false;
            }

            if (!root.TryGetProperty("signature", out var sigProp) || string.IsNullOrWhiteSpace(sigProp.GetString()))
            {
                _logger.Warning($"TetherSession [{SessionId}]: AUTH_RESPONSE missing signature property.");
                return false;
            }

            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromBase64String(sigProp.GetString()!);
            }
            catch (FormatException ex)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Malformed base64 signature in AUTH_RESPONSE: {ex.Message}");
                return false;
            }

            bool signatureVerified = false;
            try
            {
                byte[] spkiBytes = Convert.FromBase64String(init.PublicKey);
                using var ecdsa = System.Security.Cryptography.ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(spkiBytes, out _);

                signatureVerified =
                    ecdsa.VerifyData(serverNonce, signatureBytes, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence) ||
                    ecdsa.VerifyData(serverNonce, signatureBytes, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (Exception ex)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Cryptographic verification failed with exception: {ex.Message}");
                return false;
            }

            if (!signatureVerified)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Private key possession verification failed for paired device '{phoneFingerprint}'. Rejecting connection.");
                await FrameCodec.WriteJsonFrameAsync(stream, new HandshakeResponse
                {
                    DeviceId = _identity.DeviceId,
                    DeviceName = _identity.DeviceName,
                    PublicKey = _identity.GetPublicKeySpkiBase64(),
                    Status = HandshakeStatus.PairingDenied
                }, ct);
                return false;
            }

            Device = knownDevice;
            _logger.Info($"TetherSession [{SessionId}]: Cryptographically authenticated paired phone {phoneFingerprint} ({knownDevice.DisplayName}).");

            var resp = new HandshakeResponse
            {
                DeviceId = _identity.DeviceId,
                DeviceName = _identity.DeviceName,
                PublicKey = _identity.GetPublicKeySpkiBase64(),
                Status = HandshakeStatus.Paired,
                Capabilities = ServerCaps,
                Pqc = false
            };
            await FrameCodec.WriteJsonFrameAsync(stream, resp, ct);
            return true;
        }

        _logger.Warning($"TetherSession [{SessionId}]: Unknown phone {phoneFingerprint} did not request pairing. Denying.");
        await FrameCodec.WriteJsonFrameAsync(stream, new HandshakeResponse
        {
            DeviceId = _identity.DeviceId,
            DeviceName = _identity.DeviceName,
            PublicKey = _identity.GetPublicKeySpkiBase64(),
            Status = HandshakeStatus.PairingDenied
        }, ct);

        return false;
    }

    private async Task CommandAndHeartbeatLoopAsync(CancellationToken ct)
    {
        var stream = _tls!;
        Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);

        while (!ct.IsCancellationRequested)
        {
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(TimeSpan.FromSeconds(10));

            try
            {
                var frameBytes = await FrameCodec.ReadFrameAsync(stream, readCts.Token);
                if (frameBytes is null)
                {
                    _logger.Info($"TetherSession [{SessionId}]: Socket EOF received. Closing session.");
                    break;
                }

                Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);

                // Binary input path (hot, 60-120 Hz).
                if (frameBytes.Length >= 1 && frameBytes[0] == PacketTypeInputEvent)
                {
                    _inputForwarder.Forward(frameBytes);
                    continue;
                }

                JsonDocument doc;
                try { doc = JsonDocument.Parse(frameBytes); }
                catch (JsonException ex)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Malformed JSON frame: {ex.Message}");
                    continue;
                }

                using (doc)
                {
                    await _packetRouter.RouteFrameAsync(doc, this, Device!, stream, ct);
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                try
                {
                    await FrameCodec.WriteJsonFrameAsync(stream, new { type = "PING", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, ct);
                }
                catch (Exception ex)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Failed sending PING probe: {ex.Message}. Terminating connection.");
                    break;
                }

                long elapsedSeconds =
                    (DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastFrameReceivedTicks)) / TimeSpan.TicksPerSecond;

                if (elapsedSeconds > 180)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Heartbeat timeout (no frames received in {elapsedSeconds}s). Declaring connection dead.");
                    break;
                }
            }
        }
    }

    public void Close(string reason)
    {
        _logger.Info($"TetherSession [{SessionId}]: Closing session. Reason: {reason}");
        try { _tls?.Dispose(); } catch { }
        _tls = null;
    }

    public void Dispose() => Close("Dispose called");
}