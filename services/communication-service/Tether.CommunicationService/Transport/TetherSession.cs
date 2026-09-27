using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
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
    private const string ServerCaps = "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED";

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly DeviceManager _deviceManager;
    private readonly SessionManager _sessionManager;
    private readonly PairingManager _pairingManager;
    private readonly PacketRouter _packetRouter;

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
        PacketRouter packetRouter)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _deviceManager = deviceManager;
        _sessionManager = sessionManager;
        _pairingManager = pairingManager;
        _packetRouter = packetRouter;
        _lastFrameReceivedTicks = DateTime.UtcNow.Ticks;
    }

    public void RecordPongReceived()
    {
        Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);
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
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(15));

            await _tls.AuthenticateAsServerAsync(sslOptions, handshakeCts.Token);
            _logger.Info($"TetherSession [{SessionId}]: TLS 1.3 established with {remote} ({_tls.NegotiatedCipherSuite}).");

            // Perform Tether Handshake & Authentication
            bool authenticated = await HandleHandshakeAsync(handshakeCts.Token);
            if (!authenticated || Device == null)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Closed without authentication.");
                return;
            }

            // Register active session in SessionManager
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

            // Post-handshake packet loop with PING/PONG keepalive
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

        using var initDoc = await FrameCodec.ReadJsonFrameAsync(stream, ct);
        if (initDoc is null)
        {
            _logger.Warning($"TetherSession [{SessionId}]: No HANDSHAKE_INIT received.");
            return false;
        }

        string rawInitJson = initDoc.RootElement.GetRawText();
        HandshakeInit? init;
        try { init = JsonSerializer.Deserialize<HandshakeInit>(rawInitJson); }
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
            // RECONNECT FLOW: Known paired phone
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
            await FrameCodec.WriteJsonFrameAsync(stream, resp, ct);
            return true;
        }

        if (init.IsPairingRequested)
        {
            // FIRST-TIME PAIRING FLOW with 6-digit PIN SAS commitment proof
            byte[] initBytes = System.Text.Encoding.UTF8.GetBytes(rawInitJson);

            var respPayload = new HandshakeResponse
            {
                DeviceId = _identity.DeviceId,
                DeviceName = _identity.DeviceName,
                PublicKey = _identity.GetPublicKeySpkiBase64(),
                Status = HandshakeStatus.PairingPending,
                Capabilities = ServerCaps,
                Pqc = false
            };
            byte[] respBytes = JsonSerializer.SerializeToUtf8Bytes(respPayload);

            byte[] transcriptHash;
            using (var sha = System.Security.Cryptography.SHA512.Create())
            {
                var combined = new byte[initBytes.Length + respBytes.Length];
                Buffer.BlockCopy(initBytes, 0, combined, 0, initBytes.Length);
                Buffer.BlockCopy(respBytes, 0, combined, initBytes.Length, respBytes.Length);
                transcriptHash = sha.ComputeHash(combined);
            }

            var pending = _pairingManager.RegisterPairingRequest(init.PublicKey, init.DeviceName, transcriptHash);

            var respJsonWithReq = JsonSerializer.Deserialize<System.Text.Json.Nodes.JsonObject>(respBytes)!;
            respJsonWithReq["requestId"] = pending.RequestId;
            respJsonWithReq["commitment"] = pending.CommitmentBase64;

            await FrameCodec.WriteFrameAsync(stream, JsonSerializer.SerializeToUtf8Bytes(respJsonWithReq), ct);
            _logger.Info($"TetherSession [{SessionId}]: Sent HANDSHAKE_RESPONSE (PAIRING_PENDING) with requestId '{pending.RequestId}'. Waiting for PAIRING_CONFIRMED...");

            // Read PAIRING_CONFIRMED frame from phone
            using var confirmedDoc = await FrameCodec.ReadJsonFrameAsync(stream, ct);
            if (confirmedDoc == null)
            {
                _logger.Warning($"TetherSession [{SessionId}]: No PAIRING_CONFIRMED frame received.");
                return false;
            }

            string confirmedType = confirmedDoc.RootElement.GetProperty("type").GetString() ?? "";
            if (!string.Equals(confirmedType, "PAIRING_CONFIRMED", StringComparison.Ordinal))
            {
                _logger.Warning($"TetherSession [{SessionId}]: Expected PAIRING_CONFIRMED but got '{confirmedType}'.");
                return false;
            }

            string reqId = confirmedDoc.RootElement.GetProperty("requestId").GetString() ?? "";
            string proofBase64 = confirmedDoc.RootElement.GetProperty("proof").GetString() ?? "";

            bool verified = _pairingManager.TryVerifyPhoneProof(reqId, proofBase64, out string winProofBase64, out _);
            if (!verified)
            {
                _logger.Warning($"TetherSession [{SessionId}]: PIN proof verification failed for requestId '{reqId}'.");
                await FrameCodec.WriteJsonFrameAsync(stream, new { type = "PAIRING_COMPLETE", status = "DENIED" }, ct);
                return false;
            }

            // Send PAIRING_COMPLETE
            await FrameCodec.WriteJsonFrameAsync(stream, new
            {
                type = "PAIRING_COMPLETE",
                status = "OK",
                proof = winProofBase64
            }, ct);

            Device = _deviceManager.GetByFingerprint(phoneFingerprint);
            _logger.Info($"TetherSession [{SessionId}]: Pairing complete and device '{phoneFingerprint}' authenticated!");
            return true;
        }

        // Unknown device that did not ask to pair -> fail closed
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
            // Read next frame with 30-second timeout to check keepalive
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(TimeSpan.FromSeconds(30));

            try
            {
                var doc = await FrameCodec.ReadJsonFrameAsync(stream, readCts.Token);
                if (doc != null)
                {
                    Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);
                    await _packetRouter.RouteFrameAsync(doc, this, Device!, stream, ct);
                }
                else
                {
                    _logger.Info($"TetherSession [{SessionId}]: Socket EOF received. Closing session.");
                    break;
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // 30 seconds of inactivity -> Send PING heartbeat
                _logger.Debug($"TetherSession [{SessionId}]: 30s idle threshold reached. Sending PING probe...");
                try
                {
                    await FrameCodec.WriteJsonFrameAsync(stream, new { type = "PING", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, ct);
                }
                catch (Exception ex)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Failed sending PING probe: {ex.Message}. Terminating connection.");
                    break;
                }

                // Wait 15 seconds for response/PONG
                long elapsedSeconds = (DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastFrameReceivedTicks)) / TimeSpan.TicksPerSecond;
                if (elapsedSeconds > 45)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Heartbeat timeout (no PONG received in 45s). Declaring connection dead.");
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
