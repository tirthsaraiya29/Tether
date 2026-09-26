using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Tether.CommunicationService;

/// <summary>
/// Owns the state for the TOFU (Trust On First Use) pairing window.
/// Tracks in-flight pairing requests, correlates PAIRING_DECISION events
/// back to the correct handshake, and enforces timing-safe key matching.
/// </summary>
public sealed class PairingCoordinator
{
    public sealed class PendingPairing
    {
        public string RequestId { get; init; } = "";
        public byte[] PhonePublicKey { get; init; } = Array.Empty<byte>();
        public string Fingerprint { get; init; } = "";
        public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;
        public TaskCompletionSource<bool> Decision { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private readonly ConcurrentDictionary<string, PendingPairing> _pending = new();

    public int PendingCount => _pending.Count;

    public PendingPairing Register(byte[] phonePublicKey)
    {
        if (phonePublicKey == null || phonePublicKey.Length < 64)
            throw new ArgumentException("Phone public key too short.", nameof(phonePublicKey));

        var fingerprint = ComputeFingerprint(phonePublicKey);
        var requestId = Guid.NewGuid().ToString("N");
        var pending = new PendingPairing
        {
            RequestId = requestId,
            PhonePublicKey = phonePublicKey,
            Fingerprint = fingerprint
        };
        _pending[requestId] = pending;
        return pending;
    }

    public void Remove(string requestId) => _pending.TryRemove(requestId, out _);

    /// <summary>
    /// Resolves a pending pairing request. Returns true if a matching RequestId existed
    /// (whether or not the decision was honored). A key mismatch fails closed to DENY.
    /// </summary>
    public bool TryResolve(string requestId, byte[] presentedKey, bool allowed)
    {
        if (string.IsNullOrEmpty(requestId)) return false;
        if (!_pending.TryGetValue(requestId, out var pending)) return false;

        if (presentedKey == null ||
            !CryptographicOperations.FixedTimeEquals(presentedKey, pending.PhonePublicKey))
        {
            // Fail closed: the decision does not match the key presented at handshake time.
            pending.Decision.TrySetResult(false);
            return true;
        }

        return pending.Decision.TrySetResult(allowed);
    }

    public static string ComputeFingerprint(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        return string.Join(":", hash.Select(b => b.ToString("X2")));
    }
}