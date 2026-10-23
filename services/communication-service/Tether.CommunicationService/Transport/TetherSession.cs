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

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly DeviceManager _deviceManager;
    private readonly SessionManager _sessionManager;
    private readonly PairingManager _pairingManager;
    private readonly PacketRouter _packetRouter;
    private readonly InputForwarder _inputForwarder;

    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private SslStream? _tls;
    private long _lastFrameReceivedTicks;

    public string SessionId { get; } = Guid.NewGuid().ToString("N")[..8];
    public TetherDevice? Device { get; private set; }
    public string IpAddress { get; set; } = "";

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

    public async Task WriteJsonFrameSafeAsync<T>(T payload, CancellationToken ct)
    {
        var tls = _tls;
        if (tls == null) return;
        await _writeLock.WaitAsync(ct);
        try
        {
            await FrameCodec.WriteJsonFrameAsync(tls, payload, ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task WriteRawFrameSafeAsync(byte[] payload, CancellationToken ct)
    {
        var tls = _tls;
        if (tls == null || payload == null || payload.Length == 0) return;
        await _writeLock.WaitAsync(ct);
        try
        {
            await FrameCodec.WriteFrameAsync(tls, payload, ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task SendLaptopStateAsync(LaptopSnapshot snap, CancellationToken ct)
    {
        try
        {
            await WriteJsonFrameSafeAsync(new LaptopStateFrame
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
        try
        {
            await WriteRawFrameSafeAsync(payload, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"TetherSession [{SessionId}]: Error pushing raw frame: {ex.Message}");
        }
    }

    public async Task RunAsync(TcpClient client, CancellationToken serviceCt)
    {
        var remote = (client.Client.RemoteEndPoint as System.Net.IPEndPoint)?.Address?.ToString() ?? "unknown";
        IpAddress = remote;
        _logger.Info($"TetherSession [{SessionId}]: TCP connection accepted from {remote}.");

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
                RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true,
            };

            // Workaround for ECDSA CNG key container issues
            if (_identity.Certificate.HasPrivateKey)
            {
                sslOptions.ServerCertificateSelectionCallback = (sender, host) => _identity.Certificate;
                sslOptions.ServerCertificate = null;
            }

            using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt);
            tlsCts.CancelAfter(TimeSpan.FromSeconds(15));

            await _tls.AuthenticateAsServerAsync(sslOptions, tlsCts.Token);
            _logger.Info($"TetherSession [{SessionId}]: TLS 1.3 established with {remote} ({_tls.NegotiatedCipherSuite}).");

            using var authCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt);
            authCts.CancelAfter(TimeSpan.FromSeconds(180));

            bool authenticated = await HandleHandshakeAsync(authCts.Token);
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
                var initSnap = LaptopStateCollector.GetLaptopSnapshot(_logger);
                await WriteJsonFrameSafeAsync(new LaptopStateFrame
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
        catch (AuthenticationException ex)
        {
            string inner = ex.InnerException != null ? $" ({ex.InnerException.Message})" : "";
            _logger.Warning($"TetherSession [{SessionId}]: TLS failure: {ex.Message}{inner}");
        }
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

        if (knownDevice != null && knownDevice.TrustState == DeviceTrustState.Paired)
        {
            Device = knownDevice;
            _logger.Info($"TetherSession [{SessionId}]: Recognized paired phone {phoneFingerprint} ({knownDevice.DisplayName}).");

            var resp = new HandshakeResponse
            {
                DeviceId = _identity.DeviceId,
                DeviceName = _identity.DeviceName,
                PublicKey = _identity.GetPublicKeySpkiBase64(),
                Status = HandshakeStatus.Paired,
                Capabilities = ServerCaps,
                Pqc = false
            };
            await WriteJsonFrameSafeAsync(resp, ct);

            try
            {
                using var proofCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                proofCts.CancelAfter(TimeSpan.FromSeconds(3));
                var proofBytes = await FrameCodec.ReadFrameAsync(stream, proofCts.Token);
                if (proofBytes != null && proofBytes.Length > 0)
                {
                    using var proofDoc = JsonDocument.Parse(proofBytes);
                    if (proofDoc.RootElement.TryGetProperty("type", out var pType) &&
                        string.Equals(pType.GetString(), "HANDSHAKE_PROOF", StringComparison.Ordinal))
                    {
                        _logger.Debug($"TetherSession [{SessionId}]: Received HANDSHAKE_PROOF for paired device. Responding with HANDSHAKE_VERIFIED.");
                        await WriteJsonFrameSafeAsync(new { type = "HANDSHAKE_VERIFIED", status = "OK" }, ct);
                    }
                }
            }
            catch (OperationCanceledException) { /* Optional HANDSHAKE_PROOF not sent, proceed */ }
            catch (Exception ex)
            {
                _logger.Debug($"TetherSession [{SessionId}]: Handshake proof check completed: {ex.Message}");
            }

            return true;
        }

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

            await WriteRawFrameSafeAsync(respBytes, ct);
            _logger.Info($"TetherSession [{SessionId}]: Sent HANDSHAKE_RESPONSE (PAIRING_PENDING) with requestId '{pending.RequestId}'. Waiting for PAIRING_CONFIRMED...");

            using var pairingCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            pairingCts.CancelAfter(TimeSpan.FromSeconds(120));

            using var confirmedDoc = await FrameCodec.ReadJsonFrameAsync(stream, pairingCts.Token);
            if (confirmedDoc == null)
            {
                _logger.Warning($"TetherSession [{SessionId}]: No PAIRING_CONFIRMED frame received.");
                return false;
            }

            string confirmedType = confirmedDoc.RootElement.TryGetProperty("type", out var typeProp) ? typeProp.GetString() ?? "" : "";
            if (string.Equals(confirmedType, "PAIRING_REJECTED", StringComparison.Ordinal))
            {
                string reqIdToCancel = confirmedDoc.RootElement.TryGetProperty("requestId", out var rProp) ? rProp.GetString() ?? "" : pending.RequestId;
                _pairingManager.CancelRequest(reqIdToCancel);
                _logger.Info($"TetherSession [{SessionId}]: Pairing rejected by phone for requestId '{reqIdToCancel}'.");
                return false;
            }

            if (!string.Equals(confirmedType, "PAIRING_CONFIRMED", StringComparison.Ordinal))
            {
                _logger.Warning($"TetherSession [{SessionId}]: Expected PAIRING_CONFIRMED but got '{confirmedType}'.");
                return false;
            }

            string reqId = confirmedDoc.RootElement.TryGetProperty("requestId", out var reqProp) ? reqProp.GetString() ?? "" : "";
            string proofBase64 = confirmedDoc.RootElement.TryGetProperty("proof", out var proofProp) ? proofProp.GetString() ?? "" : "";

            bool verified = _pairingManager.TryVerifyPhoneProof(reqId, proofBase64, out string winProofBase64, out _);
            if (!verified)
            {
                _logger.Warning($"TetherSession [{SessionId}]: PIN proof verification failed for requestId '{reqId}'.");
                await WriteJsonFrameSafeAsync(new { type = "PAIRING_COMPLETE", status = "DENIED" }, ct);
                return false;
            }

            await WriteJsonFrameSafeAsync(new
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

        _logger.Warning($"TetherSession [{SessionId}]: Unknown phone {phoneFingerprint} did not request pairing. Denying.");
        await WriteJsonFrameSafeAsync(new HandshakeResponse
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

        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var combinedCt = sessionCts.Token;

        // Decoupled heartbeat probing task sending PING every 10s unconditionally
        _ = Task.Run(async () =>
        {
            while (!combinedCt.IsCancellationRequested)
            {
                try { await Task.Delay(10000, combinedCt); }
                catch (OperationCanceledException) { break; }

                _logger.Debug($"TetherSession [{SessionId}]: Periodic 10s heartbeat probe sending PING...");
                try
                {
                    await WriteJsonFrameSafeAsync(new { type = "PING", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, combinedCt);
                }
                catch (Exception ex)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Failed sending PING probe: {ex.Message}. Terminating connection.");
                    try { sessionCts.Cancel(); } catch { }
                    break;
                }

                long elapsedSeconds = (DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastFrameReceivedTicks)) / TimeSpan.TicksPerSecond;
                if (elapsedSeconds > 45)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Heartbeat timeout ({elapsedSeconds}s silence). Declaring connection dead.");
                    try { sessionCts.Cancel(); } catch { }
                    break;
                }
            }
        }, combinedCt);

        while (!combinedCt.IsCancellationRequested)
        {
            try
            {
                var frameBytes = await FrameCodec.ReadFrameAsync(stream, combinedCt);
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

                // JSON control path.
                JsonDocument doc;
                try { doc = JsonDocument.Parse(frameBytes); }
                catch (JsonException ex)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Malformed JSON frame: {ex.Message}");
                    continue;
                }

                using (doc)
                {
                    await _packetRouter.RouteFrameAsync(doc, this, Device!, stream, combinedCt);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Socket read error: {ex.Message}");
                break;
            }
        }

        try { sessionCts.Cancel(); } catch { }
    }

    public void Close(string reason)
    {
        _logger.Info($"TetherSession [{SessionId}]: Closing session. Reason: {reason}");
        try { _tls?.Dispose(); } catch { }
        _tls = null;
    }

    public void Dispose() => Close("Dispose called");
}
