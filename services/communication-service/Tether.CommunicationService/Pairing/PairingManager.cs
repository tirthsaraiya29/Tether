using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Tether.CommunicationService.Devices;
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
    public string CommitmentBase64 { get; init; } = "";
    public byte[] ExpectedPhoneProof { get; init; } = Array.Empty<byte>();
    public byte[] ExpectedWinProof { get; init; } = Array.Empty<byte>();
    public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;
    public int FailedAttempts { get; set; } = 0;
}

/// <summary>
/// Manages 6-digit PIN SAS pairing authorization over TLS 1.3.
/// Generates random PINs, displays them on DesktopUI over IPC,
/// verifies SHA-512 proofs in constant-time, and rate-limits failed attempts.
/// </summary>
public sealed class PairingManager
{
    private const int MaxFailedAttempts = 3;
    private const int ExpirationSeconds = 60;

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

    public PendingPairing RegisterPairingRequest(string phoneSpkiBase64, string displayName, byte[] transcriptHash)
    {
        byte[] phoneSpkiDer = Convert.FromBase64String(phoneSpkiBase64);
        string phoneFingerprint = Trust.TrustStore.ComputeFingerprintOrNull(phoneSpkiBase64)
            ?? throw new ArgumentException("Invalid phone public key base64.", nameof(phoneSpkiBase64));

        byte[] winSpkiDer = _identity.GetPublicKeySpkiDer();
        string requestId = Guid.NewGuid().ToString("N");

        // Generate cryptographically random 6-digit PIN (100000 - 999999)
        int pinNum = RandomNumberGenerator.GetInt32(100000, 1000000);
        string pin = pinNum.ToString("D6");

        // Commitment = SHA-512(PIN || WinPubKey || PhonePubKey || RequestId)
        byte[] commitment = ComputeSha512(
            Encoding.UTF8.GetBytes(pin),
            winSpkiDer,
            phoneSpkiDer,
            Encoding.UTF8.GetBytes(requestId));
        string commitmentBase64 = Convert.ToBase64String(commitment);

        // Expected PhoneProof = SHA-512(PIN || PhonePubKey || WinPubKey || RequestId || TranscriptHash)
        byte[] expectedPhoneProof = ComputeSha512(
            Encoding.UTF8.GetBytes(pin),
            phoneSpkiDer,
            winSpkiDer,
            Encoding.UTF8.GetBytes(requestId),
            transcriptHash);

        // Expected WinProof = SHA-512("SERVER-OK" || PIN || WinPubKey || PhonePubKey || RequestId)
        byte[] expectedWinProof = ComputeSha512(
            Encoding.UTF8.GetBytes("SERVER-OK"),
            Encoding.UTF8.GetBytes(pin),
            winSpkiDer,
            phoneSpkiDer,
            Encoding.UTF8.GetBytes(requestId));

        var pending = new PendingPairing
        {
            RequestId = requestId,
            PhoneFingerprint = phoneFingerprint,
            PhoneSpkiBase64 = phoneSpkiBase64,
            PhoneSpkiDer = phoneSpkiDer,
            DisplayName = displayName,
            Pin = pin,
            CommitmentBase64 = commitmentBase64,
            ExpectedPhoneProof = expectedPhoneProof,
            ExpectedWinProof = expectedWinProof,
            CreatedUtc = DateTime.UtcNow,
            FailedAttempts = 0
        };

        _pending[requestId] = pending;

        _logger.Info($"PairingManager: Generated pairing request {requestId} for phone '{displayName}' ({phoneFingerprint}). PIN displayed on DesktopUI.");

        // Publish event to DesktopUI over Named Pipe IPC
        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PAIRING_REQUESTED,
            Source = nameof(PairingManager),
            PayloadJson = JsonSerializer.Serialize(new
            {
                requestId = requestId,
                pin = pin,
                phoneFingerprint = phoneFingerprint,
                displayName = displayName,
                timestampUtcTicks = DateTime.UtcNow.Ticks
            })
        });

        return pending;
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

        // Check 60s expiration
        if (DateTime.UtcNow - pending.CreatedUtc > TimeSpan.FromSeconds(ExpirationSeconds))
        {
            _logger.Warning($"PairingManager: Pairing request '{requestId}' expired.");
            _pending.TryRemove(requestId, out _);
            return false;
        }

        byte[] presentedProof;
        try { presentedProof = Convert.FromBase64String(presentedProofBase64); }
        catch
        {
            _logger.Warning($"PairingManager: Malformed proof base64 for '{requestId}'.");
            return false;
        }

        // Constant-time comparison
        bool isMatch = CryptographicOperations.FixedTimeEquals(pending.ExpectedPhoneProof, presentedProof);

        if (!isMatch)
        {
            pending.FailedAttempts++;
            _logger.Warning($"PairingManager: Invalid PIN proof for requestId '{requestId}' (Attempt {pending.FailedAttempts}/{MaxFailedAttempts}).");

            if (pending.FailedAttempts >= MaxFailedAttempts)
            {
                _logger.Error($"PairingManager: Max failed attempts reached for '{requestId}'. Invalidating pairing request.");
                _pending.TryRemove(requestId, out _);
            }
            return false;
        }

        // Success! Promote device in DeviceManager
        _deviceManager.PromoteToPaired(
            pending.PhoneFingerprint,
            pending.DisplayName,
            pending.PhoneSpkiBase64,
            new[] { "CLIPBOARD", "FILES", "NOTIFICATIONS", "MEDIA", "TERMINAL", "POWER_ELEVATED" });

        winProofBase64 = Convert.ToBase64String(pending.ExpectedWinProof);
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

    private static byte[] ComputeSha512(params byte[][] inputs)
    {
        using var sha = SHA512.Create();
        int totalLen = inputs.Sum(i => i.Length);
        var combined = new byte[totalLen];
        int offset = 0;
        foreach (var input in inputs)
        {
            Buffer.BlockCopy(input, 0, combined, offset, input.Length);
            offset += input.Length;
        }
        return sha.ComputeHash(combined);
    }
}
