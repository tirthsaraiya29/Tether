using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan ProofTimeout = TimeSpan.FromSeconds(8);

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
        => Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);

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

            if (_identity.Certificate.HasPrivateKey)
            {
                sslOptions.ServerCertificateSelectionCallback = (sender, host) => _identity.Certificate;
                sslOptions.ServerCertificate = null;
            }

            using var tlsCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt);
            tlsCts.CancelAfter(TimeSpan.FromSeconds(15));

            await _tls.AuthenticateAsServerAsync(sslOptions, tlsCts.Token);
            _logger.Info($"TetherSession [{SessionId}]: TLS established with {remote} ({_tls.NegotiatedCipherSuite}).");

            using var authCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt);
            authCts.CancelAfter(HandshakeTimeout);

            bool authenticated = await HandleHandshakeAsync(authCts.Token);
            if (!authenticated || Device == null)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Closed without authentication.");
                return;
            }

            _sessionManager.RegisterSession(this);
            _deviceManager.MarkConnected(Device.Fingerprint, this);

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
        catch (OperationCanceledException)
        {
            _logger.Info($"TetherSession [{SessionId}]: Handshake timed out.");
        }
        catch (AuthenticationException ex)
        {
            string inner = ex.InnerException != null ? $" ({ex.InnerException.Message})" : "";
            _logger.Warning($"TetherSession [{SessionId}]: TLS failure: {ex.Message}{inner}");
        }
        catch (Exception ex)
        {
            _logger.Warning($"TetherSession [{SessionId}]: Session error: {ex.Message}");
        }
        finally
        {
            _sessionManager.UnregisterSession(this);
            if (Device != null)
            {
                _deviceManager.MarkDisconnected(Device.Fingerprint, this);
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
        try
        {
            init = JsonSerializer.Deserialize<HandshakeInit>(initFrameBytes);
        }
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
        bool isAlreadyPaired = knownDevice != null && knownDevice.TrustState == DeviceTrustState.Paired;

        _logger.Info($"TetherSession [{SessionId}]: Handshake eval -> FP={phoneFingerprint}, " +
                     $"isAlreadyPaired={isAlreadyPaired}, " +
                     $"clientPairingReq={init.IsPairingRequested}");

        // =========================================================================
        // PATH 1: KNOWN PAIRED DEVICE -> Cryptographic Proof-of-Possession Challenge
        // =========================================================================
        if (isAlreadyPaired && knownDevice != null)
        {
            string storedSpki = string.IsNullOrEmpty(knownDevice.PublicKeySpkiBase64)
                ? init.PublicKey
                : knownDevice.PublicKeySpkiBase64;

            _logger.Info($"TetherSession [{SessionId}]: Recognized paired phone {phoneFingerprint} ({knownDevice.DisplayName}). Issuing serverNonce challenge.");

            byte[] serverNonce = RandomNumberGenerator.GetBytes(32);
            string serverNonceB64 = Convert.ToBase64String(serverNonce);

            var resp = new HandshakeResponse
            {
                DeviceId = _identity.DeviceId,
                DeviceName = _identity.DeviceName,
                PublicKey = _identity.GetPublicKeySpkiBase64(),
                Status = HandshakeStatus.Paired,
                Capabilities = ServerCaps,
                Pqc = false,
                ServerNonce = serverNonceB64
            };
            await WriteJsonFrameSafeAsync(resp, ct);

            byte[]? proofBytes;
            try
            {
                using var proofCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                proofCts.CancelAfter(ProofTimeout);
                proofBytes = await FrameCodec.ReadFrameAsync(stream, proofCts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.Warning($"TetherSession [{SessionId}]: HANDSHAKE_PROOF timed out after {ProofTimeout.TotalSeconds:0}s. Failing closed.");
                return false;
            }

            if (proofBytes is null || proofBytes.Length == 0)
            {
                _logger.Warning($"TetherSession [{SessionId}]: Empty HANDSHAKE_PROOF received. Failing closed.");
                return false;
            }

            if (!TryVerifyHandshakeProof(proofBytes, storedSpki, serverNonce, init.PublicKey, out string failureReason))
            {
                _logger.Warning($"TetherSession [{SessionId}]: HANDSHAKE_PROOF verification failed: {failureReason}. Failing closed.");
                return false;
            }

            await WriteJsonFrameSafeAsync(new { type = "HANDSHAKE_VERIFIED", status = "OK" }, ct);
            _logger.Info($"TetherSession [{SessionId}]: Proof verified for {knownDevice.DisplayName}. Auto-connect successful!");
            Device = knownDevice;
            return true;
        }

        // =========================================================================
        // PATH 2: NEW / UNPAIRED DEVICE -> Interactive PIN Pairing
        // =========================================================================
        if (init.IsPairingRequested || !isAlreadyPaired)
        {
            _logger.Info($"TetherSession [{SessionId}]: Initial pairing required for {phoneFingerprint}. Invoking PairingManager.");

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
                _logger.Warning($"TetherSession [{SessionId}]: Proof verification failed for requestId '{reqId}'. Tearing down session.");
                _pairingManager.CancelRequest(reqId);
                try { await WriteJsonFrameSafeAsync(new { type = "PAIRING_COMPLETE", status = "DENIED" }, ct); } catch { }
                Close("Pairing proof verification failed");
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
            _logger.Info($"TetherSession [{SessionId}]: Pairing successfully finalized for '{phoneFingerprint}'.");
            return true;
        }

        // =========================================================================
        // PATH 3: UNKNOWN & NOT REQUESTING PAIRING -> Deny Connection
        // =========================================================================
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

    private bool TryVerifyHandshakeProof(
        byte[] proofBytes,
        string storedPhoneSpkiBase64,
        byte[] serverNonce,
        string presentedPhoneSpkiBase64,
        out string failureReason)
    {
        failureReason = "";

        JsonDocument proofDoc;
        try
        {
            proofDoc = JsonDocument.Parse(proofBytes);
        }
        catch (JsonException ex)
        {
            string rawSnippet = Encoding.UTF8.GetString(proofBytes);
            failureReason = $"Malformed JSON ({ex.Message}). Raw: '{rawSnippet}'";
            return false;
        }

        using (proofDoc)
        {
            var root = proofDoc.RootElement;

            if (!root.TryGetProperty("type", out var typeProp) ||
                !string.Equals(typeProp.GetString(), "HANDSHAKE_PROOF", StringComparison.Ordinal))
            {
                string rawSnippet = Encoding.UTF8.GetString(proofBytes);
                failureReason = $"Missing/invalid 'type'. Raw: '{rawSnippet}'";
                return false;
            }

            if (!root.TryGetProperty("signature", out var sigProp) ||
                !root.TryGetProperty("clientNonce", out var cNonceProp))
            {
                failureReason = "Missing 'signature' or 'clientNonce'";
                return false;
            }

            string? sigStr = sigProp.GetString();
            string? nonceStr = cNonceProp.GetString();
            if (string.IsNullOrEmpty(sigStr) || string.IsNullOrEmpty(nonceStr))
            {
                failureReason = "'signature' or 'clientNonce' is empty";
                return false;
            }

            byte[] signature;
            byte[] clientNonce;
            try
            {
                signature = Convert.FromBase64String(sigStr);
                clientNonce = Convert.FromBase64String(nonceStr);
            }
            catch (FormatException)
            {
                failureReason = "Invalid base64 in signature/clientNonce";
                return false;
            }

            if (signature.Length == 0 || clientNonce.Length == 0)
            {
                failureReason = "Empty signature or clientNonce bytes";
                return false;
            }

            // 1:1 match with TetherPairingManager.kt: buildHandshakeTranscript()
            byte[] transcript = BuildHandshakeTranscript(
                serverNonce,
                clientNonce,
                _identity.GetPublicKeySpkiBase64(),
                presentedPhoneSpkiBase64);

            if (!VerifyEcdsaSignature(storedPhoneSpkiBase64, transcript, signature))
            {
                failureReason = "ECDSA signature verification failed";
                return false;
            }

            return true;
        }
    }

    private static byte[] BuildHandshakeTranscript(
        byte[] serverNonce,
        byte[] clientNonce,
        string windowsSpkiBase64,
        string phoneSpkiBase64)
    {
        byte[] winPubKeyBytes = Encoding.UTF8.GetBytes(windowsSpkiBase64);
        byte[] phonePubKeyBytes = Encoding.UTF8.GetBytes(phoneSpkiBase64);

        int totalSize = 4 + serverNonce.Length +
                        4 + clientNonce.Length +
                        4 + winPubKeyBytes.Length +
                        4 + phonePubKeyBytes.Length;

        byte[] result = new byte[totalSize];
        int offset = 0;

        WritePrefixed(result, ref offset, serverNonce);
        WritePrefixed(result, ref offset, clientNonce);
        WritePrefixed(result, ref offset, winPubKeyBytes);
        WritePrefixed(result, ref offset, phonePubKeyBytes);

        return result;
    }

    private static void WritePrefixed(byte[] dest, ref int offset, byte[] data)
    {
        BinaryPrimitives.WriteInt32BigEndian(dest.AsSpan(offset, 4), data.Length);
        offset += 4;
        Buffer.BlockCopy(data, 0, dest, offset, data.Length);
        offset += data.Length;
    }

    private static bool VerifyEcdsaSignature(string phoneSpkiBase64, byte[] data, byte[] signature)
    {
        try
        {
            byte[] spki = Convert.FromBase64String(phoneSpkiBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
            return ecdsa.VerifyData(
                data,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        catch
        {
            return false;
        }
    }

    private async Task CommandAndHeartbeatLoopAsync(CancellationToken ct)
    {
        var stream = _tls!;
        Interlocked.Exchange(ref _lastFrameReceivedTicks, DateTime.UtcNow.Ticks);

        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var combinedCt = sessionCts.Token;

        _ = Task.Run(async () =>
        {
            while (!combinedCt.IsCancellationRequested)
            {
                try { await Task.Delay(10000, combinedCt); }
                catch (OperationCanceledException) { break; }

                try
                {
                    await WriteJsonFrameSafeAsync(new { type = "PING", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, combinedCt);
                }
                catch (Exception ex)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Failed sending PING probe: {ex.Message}. Terminating.");
                    try { sessionCts.Cancel(); } catch { }
                    break;
                }

                long elapsedSeconds = (DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastFrameReceivedTicks)) / TimeSpan.TicksPerSecond;
                if (elapsedSeconds > 45)
                {
                    _logger.Warning($"TetherSession [{SessionId}]: Heartbeat timeout ({elapsedSeconds}s). Terminating.");
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

                if (frameBytes.Length >= 1 && frameBytes[0] == PacketTypeInputEvent)
                {
                    _inputForwarder.Forward(frameBytes);
                    continue;
                }

                JsonDocument doc;
                try
                {
                    doc = JsonDocument.Parse(frameBytes);
                }
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