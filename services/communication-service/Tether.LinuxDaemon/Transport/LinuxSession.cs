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
    private const string ServerCapabilities = "FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED,INPUT,APP_MANAGEMENT,LINUX_ADMIN";

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
    public void SetDeviceForTesting(LinuxDevice device) => Device = device;

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

        var initFrameBytes = await FrameCodec.ReadFrameAsync(stream, ct);
        if (initFrameBytes == null) return false;

        HandshakeInit? init;
        try
        {
            init = JsonSerializer.Deserialize<HandshakeInit>(initFrameBytes);
        }
        catch (JsonException)
        {
            return false;
        }

        if (init == null || init.Type != "HANDSHAKE_INIT" || string.IsNullOrEmpty(init.PublicKey)) return false;

        string? phoneFp = LinuxTrustStore.ComputeFingerprintOrNull(init.PublicKey);
        if (phoneFp == null) return false;

        var trusted = _trustStore.FindByFingerprint(phoneFp);
        bool isAlreadyPaired = trusted != null;

        if (isAlreadyPaired && !init.IsPairingRequested)
        {
            if (string.IsNullOrEmpty(trusted!.PublicKeySpkiBase64))
            {
                _logger.Warning($"LinuxSession [{SessionId}]: Paired device record for {phoneFp} missing stored SPKI. Denying.");
                await WriteJsonFrameSafeAsync(new HandshakeResponse
                {
                    DeviceId = _identity.DeviceId,
                    DeviceName = _identity.DeviceName,
                    PublicKey = _identity.GetPublicKeySpkiBase64(),
                    Status = HandshakeStatus.PairingDenied,
                    Capabilities = ServerCapabilities,
                    Pqc = false,
                    Os = "linux"
                }, ct);
                return false;
            }

            _logger.Info($"LinuxSession [{SessionId}]: Recognized paired phone {phoneFp} ('{trusted.DisplayName}'). Issuing serverNonce challenge.");

            byte[] serverNonce = RandomNumberGenerator.GetBytes(32);
            string serverNonceB64 = Convert.ToBase64String(serverNonce);

            using var proofCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            proofCts.CancelAfter(TimeSpan.FromSeconds(15));

            var resp = new HandshakeResponse
            {
                DeviceId = _identity.DeviceId,
                DeviceName = _identity.DeviceName,
                PublicKey = _identity.GetPublicKeySpkiBase64(),
                Status = HandshakeStatus.Paired,
                Capabilities = ServerCapabilities,
                Pqc = false,
                Os = "linux",
                ServerNonce = serverNonceB64
            };

            await WriteJsonFrameSafeAsync(resp, proofCts.Token);

            byte[]? proofBytes;
            try
            {
                proofBytes = await FrameCodec.ReadFrameAsync(stream, proofCts.Token);
            }
            catch (OperationCanceledException)
            {
                _logger.Warning($"LinuxSession [{SessionId}]: Reconnect HANDSHAKE_PROOF timed out after 15s. Failing closed.");
                return false;
            }

            if (proofBytes == null || proofBytes.Length == 0)
            {
                _logger.Warning($"LinuxSession [{SessionId}]: Empty HANDSHAKE_PROOF frame received. Failing closed.");
                return false;
            }

            if (!TryVerifyReconnectProof(proofBytes, trusted.PublicKeySpkiBase64, serverNonce, init.PublicKey, out string failureReason))
            {
                _logger.Warning($"LinuxSession [{SessionId}]: HANDSHAKE_PROOF verification failed: {failureReason}. Failing closed.");
                return false;
            }

            await WriteJsonFrameSafeAsync(new { type = "HANDSHAKE_VERIFIED", status = "OK" }, proofCts.Token);
            Device = _deviceManager.GetDevice(phoneFp) ?? LinuxDevice.FromRecord(trusted);
            _logger.Info($"LinuxSession [{SessionId}]: Proof verified for '{Device.DisplayName}'. Reconnect successful!");
            return true;
        }

        // New pairing flow (unpaired device or explicit pairing request)
        _logger.Info($"LinuxSession [{SessionId}]: Initial pairing required for {phoneFp} ('{init.DeviceName}'). Invoking PairingManager.");
        var (pending, pairResp, respBytes) = _pairingManager.CreatePairingResponse(
            _identity.DeviceId,
            _identity.DeviceName,
            _identity.GetPublicKeySpkiBase64(),
            ServerCapabilities,
            init.PublicKey,
            init.DeviceName,
            initFrameBytes);

        if (pairResp.Status == HandshakeStatus.PairingDenied)
        {
            await WriteJsonFrameSafeAsync(pairResp, ct);
            return false;
        }

        using var pairingCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        pairingCts.CancelAfter(TimeSpan.FromSeconds(LinuxPairingManager.ExpirationSeconds));

        await WriteRawFrameSafeAsync(respBytes, pairingCts.Token);
        _logger.Info($"LinuxSession [{SessionId}]: Sent HANDSHAKE_RESPONSE (PAIRING_PENDING) for reqId '{pending.RequestId}'. Waiting for PAIRING_CONFIRMED...");

        string currentRequestId = pending.RequestId;
        try
        {
            while (!pairingCts.Token.IsCancellationRequested)
            {
                using var confirmedDoc = await FrameCodec.ReadJsonFrameAsync(stream, pairingCts.Token);
                if (confirmedDoc == null)
                {
                    _logger.Warning($"LinuxSession [{SessionId}]: No PAIRING_CONFIRMED frame received.");
                    return false;
                }

                string confirmedType = confirmedDoc.RootElement.TryGetProperty("type", out var typeProp) ? (typeProp.GetString() ?? "") : "";
                if (string.Equals(confirmedType, "PAIRING_REJECTED", StringComparison.Ordinal))
                {
                    string reqIdToCancel = confirmedDoc.RootElement.TryGetProperty("requestId", out var rProp) ? (rProp.GetString() ?? "") : pending.RequestId;
                    _pairingManager.CancelRequest(reqIdToCancel);
                    _logger.Info($"LinuxSession [{SessionId}]: Pairing rejected by phone for requestId '{reqIdToCancel}'.");
                    return false;
                }

                if (!string.Equals(confirmedType, "PAIRING_CONFIRMED", StringComparison.Ordinal) &&
                    !string.Equals(confirmedType, "HANDSHAKE_PROOF", StringComparison.Ordinal))
                {
                    _logger.Warning($"LinuxSession [{SessionId}]: Expected PAIRING_CONFIRMED but got '{confirmedType}'.");
                    return false;
                }

                string reqId = confirmedDoc.RootElement.TryGetProperty("requestId", out var reqProp) ? (reqProp.GetString() ?? "") : "";
                string proofBase64 = confirmedDoc.RootElement.TryGetProperty("proof", out var proofProp) ? (proofProp.GetString() ?? "") : "";

                bool verified = _pairingManager.TryVerifyPhoneProof(reqId, proofBase64, out string hostProofBase64, out var pendingPairing);

                if (!verified)
                {
                    int failedAttempts = pendingPairing?.FailedAttempts ?? LinuxPairingManager.MaxFailedAttempts;
                    int remainingAttempts = Math.Max(0, LinuxPairingManager.MaxFailedAttempts - failedAttempts);

                    if (remainingAttempts > 0)
                    {
                        _logger.Warning($"LinuxSession [{SessionId}]: Proof verification failed for requestId '{reqId}'. {remainingAttempts} attempt(s) remaining.");
                        await WriteJsonFrameSafeAsync(new
                        {
                            type = "PAIRING_INVALID_PIN",
                            requestId = reqId,
                            remainingAttempts = remainingAttempts,
                            message = $"Incorrect PIN. {remainingAttempts} attempt(s) remaining."
                        }, pairingCts.Token);
                        continue;
                    }

                    _logger.Warning($"LinuxSession [{SessionId}]: Proof verification failed for requestId '{reqId}'. Max attempts exhausted.");
                    _pairingManager.CancelRequest(reqId);
                    try { await WriteJsonFrameSafeAsync(new { type = "PAIRING_COMPLETE", status = "DENIED", reason = "Max attempts exhausted" }, pairingCts.Token); } catch { }
                    return false;
                }

                await WriteJsonFrameSafeAsync(new
                {
                    type = "PAIRING_COMPLETE",
                    status = "OK",
                    proof = hostProofBase64,
                    capabilities = ServerCapabilities,
                    os = "linux"
                }, pairingCts.Token);

                Device = _deviceManager.GetDevice(phoneFp) ?? LinuxDevice.FromRecord(_trustStore.FindByFingerprint(phoneFp)!);
                _logger.Info($"LinuxSession [{SessionId}]: Pairing successfully finalized for '{phoneFp}'.");
                return true;
            }
        }
        finally
        {
            if (Device == null)
            {
                _pairingManager.CancelRequest(currentRequestId);
            }
        }

        return false;
    }

    private bool TryVerifyReconnectProof(
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
            failureReason = $"Malformed JSON ({ex.Message})";
            return false;
        }

        using (proofDoc)
        {
            var root = proofDoc.RootElement;
            if (!root.TryGetProperty("type", out var typeProp) ||
                !string.Equals(typeProp.GetString(), "HANDSHAKE_PROOF", StringComparison.Ordinal))
            {
                failureReason = "Missing or invalid 'type'";
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

            if (!string.Equals(presentedPhoneSpkiBase64, storedPhoneSpkiBase64, StringComparison.Ordinal))
            {
                failureReason = "Presented SPKI does not match stored SPKI";
                return false;
            }

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
        string hostSpkiBase64,
        string phoneSpkiBase64)
    {
        byte[] hostPubKeyBytes = Encoding.UTF8.GetBytes(hostSpkiBase64);
        byte[] phonePubKeyBytes = Encoding.UTF8.GetBytes(phoneSpkiBase64);

        int totalSize = 4 + serverNonce.Length +
                        4 + clientNonce.Length +
                        4 + hostPubKeyBytes.Length +
                        4 + phonePubKeyBytes.Length;

        byte[] result = new byte[totalSize];
        int offset = 0;

        WritePrefixed(result, ref offset, serverNonce);
        WritePrefixed(result, ref offset, clientNonce);
        WritePrefixed(result, ref offset, hostPubKeyBytes);
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

    /// <summary>Terminates this transport; used when a newer authenticated session replaces it.</summary>
    public void Abort(string reason)
    {
        _logger.Info($"LinuxSession [{SessionId}]: aborting transport ({reason}).");
        try { _tls?.Close(); } catch { }
        try { _tls?.Dispose(); } catch { }
    }

    public void Dispose()
    {
        _writeLock.Dispose();
        _tls?.Dispose();
    }
}
