using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Pairing;

public sealed class PendingPairing
{
    public string RequestId { get; init; } = "";
    public string PhoneFingerprint { get; init; } = "";
    public string PhoneSpkiBase64 { get; init; } = "";
    public byte[] PhoneSpkiDer { get; init; } = Array.Empty<byte>();
    public string DisplayName { get; init; } = "";
    public string Pin { get; init; } = "";
    public byte[] TranscriptHash { get; init; } = Array.Empty<byte>();
    public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;
    public int FailedAttempts { get; set; } = 0;
}

public sealed class PairingManager
{
    private const int MaxFailedAttempts = 3;
    private const int ExpirationSeconds = 120;

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly DeviceManager _deviceManager;
    private readonly ConcurrentDictionary<string, PendingPairing> _pending = new(StringComparer.OrdinalIgnoreCase);

    public PairingManager(IEventBus eventBus, ITetherLogger logger, WindowsIdentity identity, DeviceManager deviceManager)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _deviceManager = deviceManager;
    }

    public (PendingPairing pending, HandshakeResponse response, byte[] responseBytes) CreatePairingResponse(
        string winDeviceId,
        string winDeviceName,
        string winSpkiBase64,
        string winCapabilities,
        string phoneSpkiBase64,
        string phoneDisplayName,
        byte[] initBytes)
    {
        // Evict expired requests
        var expiredKeys = _pending
            .Where(kvp => (DateTime.UtcNow - kvp.Value.CreatedUtc).TotalSeconds > ExpirationSeconds)
            .Select(kvp => kvp.Key)
            .ToList();
        foreach (var key in expiredKeys)
        {
            _pending.TryRemove(key, out _);
        }

        if (_pending.Count >= 32)
        {
            _logger.Warning($"PairingManager: Max pending pairing requests reached ({_pending.Count}/32). Rejecting new request from '{phoneDisplayName}'.");
            var errResp = new HandshakeResponse
            {
                DeviceId = winDeviceId,
                DeviceName = winDeviceName,
                PublicKey = winSpkiBase64,
                Status = HandshakeStatus.PairingDenied,
                Capabilities = winCapabilities,
                Pqc = false,
                RequestId = "",
                Commitment = ""
            };
            byte[] errBytes = JsonSerializer.SerializeToUtf8Bytes(errResp);
            return (new PendingPairing(), errResp, errBytes);
        }

        byte[] phoneSpkiDer = Convert.FromBase64String(phoneSpkiBase64);
        string phoneFingerprint = Trust.TrustStore.ComputeFingerprintOrNull(phoneSpkiBase64)
            ?? throw new ArgumentException("Invalid phone public key base64.", nameof(phoneSpkiBase64));

        string requestId = Guid.NewGuid().ToString("N");

        int pinNum = RandomNumberGenerator.GetInt32(100000, 1000000);
        string pin = pinNum.ToString("D6");

        // FIX TETH-001: Do NOT transmit a PIN hash/commitment over the wire.
        // Leaving Commitment empty completely removes the offline oracle.
        var respPayload = new HandshakeResponse
        {
            DeviceId = winDeviceId,
            DeviceName = winDeviceName,
            PublicKey = winSpkiBase64,
            Status = HandshakeStatus.PairingPending,
            Capabilities = winCapabilities,
            Pqc = false,
            RequestId = requestId,
            Commitment = ""
        };

        byte[] respBytes = JsonSerializer.SerializeToUtf8Bytes(respPayload);

        byte[] transcriptHash;
        using (var sha = SHA512.Create())
        {
            var combined = new byte[initBytes.Length + respBytes.Length];
            Buffer.BlockCopy(initBytes, 0, combined, 0, initBytes.Length);
            Buffer.BlockCopy(respBytes, 0, combined, initBytes.Length, respBytes.Length);
            transcriptHash = sha.ComputeHash(combined);
        }

        var pending = new PendingPairing
        {
            RequestId = requestId,
            PhoneFingerprint = phoneFingerprint,
            PhoneSpkiBase64 = phoneSpkiBase64,
            PhoneSpkiDer = phoneSpkiDer,
            DisplayName = phoneDisplayName,
            Pin = pin,
            TranscriptHash = transcriptHash,
            CreatedUtc = DateTime.UtcNow,
            FailedAttempts = 0
        };

        _pending[requestId] = pending;

        // FIX TETH-011: Do NOT write the PIN to disk or plaintext logs.
        _logger.Info($"PairingManager: Generated pairing request {requestId} for phone '{phoneDisplayName}' ({phoneFingerprint}).");

        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PAIRING_REQUESTED,
            Source = nameof(PairingManager),
            PayloadJson = JsonSerializer.Serialize(new
            {
                requestId = requestId,
                pin = pin,
                phoneFingerprint = phoneFingerprint,
                displayName = phoneDisplayName,
                timestampUtcTicks = DateTime.UtcNow.Ticks
            })
        });

        return (pending, respPayload, respBytes);
    }

    public bool TryVerifyPhoneProof(string requestId, string presentedProofBase64, out string winProofBase64, out PendingPairing? pending)
    {
        winProofBase64 = "";
        pending = null;

        if (string.IsNullOrEmpty(requestId) || string.IsNullOrEmpty(presentedProofBase64))
            return false;

        if (!_pending.TryGetValue(requestId, out pending))
        {
            _logger.Warning($"PairingManager: Unknown or expired requestId '{requestId}'.");
            return false;
        }

        if (DateTime.UtcNow - pending.CreatedUtc > TimeSpan.FromSeconds(ExpirationSeconds))
        {
            _logger.Warning($"PairingManager: Pairing request '{requestId}' expired.");
            _pending.TryRemove(requestId, out _);
            return false;
        }

        byte[] proofPayload;
        try { proofPayload = Convert.FromBase64String(presentedProofBase64); }
        catch
        {
            _logger.Warning($"PairingManager: Malformed proof base64 for '{requestId}'.");
            return false;
        }

        // Unpack payload: len(authKey) || authKey || len(signature) || signature
        if (!TryUnpackProof(proofPayload, out byte[] presentedAuthKey, out byte[] signature))
        {
            pending.FailedAttempts++;
            _logger.Warning($"PairingManager: Proof payload framing invalid for '{requestId}'.");
            return false;
        }

        byte[] winSpkiDer = _identity.GetPublicKeySpkiDer();
        byte[] expectedAuthKey = ComputeAuthKey(pending.Pin, pending.TranscriptHash, requestId, winSpkiDer, pending.PhoneSpkiDer);

        // 1. Verify PIN proof
        bool isPinMatch = CryptographicOperations.FixedTimeEquals(expectedAuthKey, presentedAuthKey);
        if (!isPinMatch)
        {
            pending.FailedAttempts++;
            _logger.Warning($"PairingManager: Invalid PIN proof for '{requestId}' (Attempt {pending.FailedAttempts}/{MaxFailedAttempts}).");

            if (pending.FailedAttempts >= MaxFailedAttempts)
            {
                _logger.Error($"PairingManager: Max failed attempts reached for '{requestId}'. Invalidating pairing request.");
                _pending.TryRemove(requestId, out _);
            }
            return false;
        }

        // 2. Verify asymmetric signature from phone private key
        if (!VerifyPhoneSignature(pending.PhoneSpkiBase64, expectedAuthKey, signature))
        {
            pending.FailedAttempts++;
            _logger.Warning($"PairingManager: Phone private key signature verification failed for '{requestId}'.");
            if (pending.FailedAttempts >= MaxFailedAttempts)
            {
                _pending.TryRemove(requestId, out _);
            }
            return false;
        }

        // 3. Promote trusted device
        _deviceManager.PromoteToPaired(
            pending.PhoneFingerprint,
            pending.DisplayName,
            pending.PhoneSpkiBase64,
            new[] { "CLIPBOARD", "FILES", "NOTIFICATIONS", "MEDIA", "TERMINAL", "POWER_ELEVATED", "INPUT" });

        // 4. Construct mutual server proof
        byte[] winProof = ComputeServerProof(pending.Pin, expectedAuthKey, winSpkiDer, pending.PhoneSpkiDer);
        winProofBase64 = Convert.ToBase64String(winProof);

        _pending.TryRemove(requestId, out _);
        _logger.Info($"PairingManager: Pairing request '{requestId}' successfully verified! Phone '{pending.DisplayName}' pinned.");
        return true;
    }

    public void CancelRequest(string requestId)
    {
        if (_pending.TryRemove(requestId, out var pending))
        {
            _logger.Info($"PairingManager: Cancelled pairing request '{requestId}' for '{pending.DisplayName}'.");
        }
    }

    private static byte[] ComputeAuthKey(string pin, byte[] transcriptHash, string requestId, byte[] winSpki, byte[] phoneSpki)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pin.Trim()));
        byte[] label = Encoding.UTF8.GetBytes("TETHER-PAIRING-v2");
        byte[] reqIdBytes = Encoding.UTF8.GetBytes(requestId);

        using var ms = new MemoryStream();
        ms.Write(label);
        ms.Write(transcriptHash);
        ms.Write(reqIdBytes);
        ms.Write(winSpki);
        ms.Write(phoneSpki);

        return hmac.ComputeHash(ms.ToArray());
    }

    private static byte[] ComputeServerProof(string pin, byte[] authKey, byte[] winSpki, byte[] phoneSpki)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pin.Trim()));
        byte[] label = Encoding.UTF8.GetBytes("SERVER-OK");

        using var ms = new MemoryStream();
        ms.Write(label);
        ms.Write(authKey);
        ms.Write(winSpki);
        ms.Write(phoneSpki);

        return hmac.ComputeHash(ms.ToArray());
    }

    private static bool TryUnpackProof(byte[] payload, out byte[] authKey, out byte[] signature)
    {
        authKey = Array.Empty<byte>();
        signature = Array.Empty<byte>();

        if (payload.Length < 8) return false;

        int authKeyLen = BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(0, 4));
        if (authKeyLen <= 0 || payload.Length < 4 + authKeyLen + 4) return false;

        authKey = new byte[authKeyLen];
        Buffer.BlockCopy(payload, 4, authKey, 0, authKeyLen);

        int sigOffset = 4 + authKeyLen;
        int sigLen = BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(sigOffset, 4));
        if (sigLen <= 0 || payload.Length < sigOffset + 4 + sigLen) return false;

        signature = new byte[sigLen];
        Buffer.BlockCopy(payload, sigOffset + 4, signature, 0, sigLen);

        return true;
    }

    private static bool VerifyPhoneSignature(string phoneSpkiBase64, byte[] data, byte[] signature)
    {
        try
        {
            byte[] spki = Convert.FromBase64String(phoneSpkiBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch
        {
            return false;
        }
    }
}