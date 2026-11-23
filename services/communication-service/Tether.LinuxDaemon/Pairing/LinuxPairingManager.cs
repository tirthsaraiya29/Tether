using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Devices;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Tether.Shared.Security;

namespace Tether.LinuxDaemon.Pairing;

public sealed class PendingLinuxPairing
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

public sealed class LinuxPairingManager
{
    public const int MaxFailedAttempts = 3;
    public const int ExpirationSeconds = 120;

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly IHostIdentity _identity;
    private readonly LinuxDeviceManager _deviceManager;
    private readonly LinuxTrustStore _trustStore;
    private readonly ConcurrentDictionary<string, PendingLinuxPairing> _pending = new(StringComparer.OrdinalIgnoreCase);

    public LinuxPairingManager(
        IEventBus eventBus,
        ITetherLogger logger,
        IHostIdentity identity,
        LinuxDeviceManager deviceManager,
        LinuxTrustStore trustStore)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _deviceManager = deviceManager;
        _trustStore = trustStore;
    }

    public (PendingLinuxPairing pending, HandshakeResponse response, byte[] responseBytes) CreatePairingResponse(
        string hostDeviceId,
        string hostDeviceName,
        string hostSpkiBase64,
        string hostCapabilities,
        string phoneSpkiBase64,
        string phoneDisplayName,
        byte[] initBytes)
    {
        // Evict expired requests
        var expiredKeys = _pending
            .Where(kvp => (DateTime.UtcNow - kvp.Value.CreatedUtc).TotalSeconds > ExpirationSeconds)
            .Select(kvp => kvp.Key)
            .ToList();
        foreach (var key in expiredKeys) _pending.TryRemove(key, out _);

        byte[] phoneSpkiDer = Convert.FromBase64String(phoneSpkiBase64);
        string phoneFingerprint = LinuxTrustStore.ComputeFingerprintOrNull(phoneSpkiBase64)
            ?? throw new ArgumentException("Invalid phone public key base64.", nameof(phoneSpkiBase64));

        int existingFromSamePhone = _pending.Values.Count(p => string.Equals(p.PhoneFingerprint, phoneFingerprint, StringComparison.OrdinalIgnoreCase));
        if (existingFromSamePhone >= 2 || _pending.Count >= 32)
        {
            _logger.Warning($"PairingManager: Pending limits exceeded. Rejecting pairing request from '{phoneDisplayName}'.");
            var errResp = new HandshakeResponse
            {
                DeviceId = hostDeviceId,
                DeviceName = hostDeviceName,
                PublicKey = hostSpkiBase64,
                Status = HandshakeStatus.PairingDenied,
                Capabilities = hostCapabilities,
                Pqc = false,
                Os = "linux",
                RequestId = ""
            };
            return (new PendingLinuxPairing(), errResp, JsonSerializer.SerializeToUtf8Bytes(errResp));
        }

        string requestId = Guid.NewGuid().ToString("N");
        int pinNum = RandomNumberGenerator.GetInt32(100000, 1000000);
        string pin = pinNum.ToString("D6");

        var respPayload = new HandshakeResponse
        {
            DeviceId = hostDeviceId,
            DeviceName = hostDeviceName,
            PublicKey = hostSpkiBase64,
            Status = HandshakeStatus.PairingPending,
            Capabilities = hostCapabilities,
            Pqc = false,
            Os = "linux",
            RequestId = requestId
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

        var pending = new PendingLinuxPairing
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

        _logger.Info($"PairingManager: Generated pairing request {requestId} for phone '{phoneDisplayName}' ({phoneFingerprint}).");

        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PAIRING_REQUESTED,
            Source = nameof(LinuxPairingManager),
            PayloadJson = JsonSerializer.Serialize(new
            {
                requestId = requestId,
                phoneFingerprint = phoneFingerprint,
                displayName = phoneDisplayName,
                timestampUtcTicks = DateTime.UtcNow.Ticks
            })
        });

        ShowSecurePairingPrompt(phoneDisplayName, pin);

        return (pending, respPayload, respBytes);
    }

    public void CancelRequest(string requestId)
    {
        if (string.IsNullOrEmpty(requestId)) return;
        if (_pending.TryRemove(requestId, out var pending))
        {
            _logger.Info($"PairingManager: Cancelled pairing request '{requestId}' for '{pending.DisplayName}'.");
        }
    }

    public bool TryVerifyPhoneProof(string requestId, string presentedProofBase64, out string hostProofBase64, out PendingLinuxPairing? pending)
    {
        hostProofBase64 = "";
        pending = null;

        if (string.IsNullOrEmpty(requestId) || string.IsNullOrEmpty(presentedProofBase64))
            return false;

        if (!_pending.TryGetValue(requestId, out pending))
        {
            _logger.Warning($"PairingManager: Unknown or expired requestId '{requestId}'.");
            return false;
        }

        if ((DateTime.UtcNow - pending.CreatedUtc).TotalSeconds > ExpirationSeconds)
        {
            _pending.TryRemove(requestId, out _);
            _logger.Warning($"PairingManager: Pairing request '{requestId}' expired.");
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
            if (pending.FailedAttempts >= MaxFailedAttempts)
            {
                _pending.TryRemove(requestId, out _);
            }
            return false;
        }

        byte[] hostSpkiDer = _identity.GetPublicKeySpkiDer();
        byte[] expectedAuthKey = ComputeAuthKey(pending.Pin, pending.TranscriptHash, requestId, hostSpkiDer, pending.PhoneSpkiDer);

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

        // Successfully verified!
        _pending.TryRemove(requestId, out _);

        byte[] hostProof = ComputeServerProof(pending.Pin, expectedAuthKey, hostSpkiDer, pending.PhoneSpkiDer);
        hostProofBase64 = Convert.ToBase64String(hostProof);

        _trustStore.AddOrUpdate(
            deviceId: pending.PhoneFingerprint,
            displayName: pending.DisplayName,
            spkiBase64: pending.PhoneSpkiBase64,
            capabilities: new[] { "MEDIA", "LOCK", "INPUT", "NOTIFICATIONS", "TERMINAL", "FILES", "APP_MANAGEMENT" },
            protocolVersion: "2.0");

        _deviceManager.ReloadFromTrustStore();
        _deviceManager.MarkConnected(pending.PhoneFingerprint);

        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PAIRING_DECISION,
            Source = nameof(LinuxPairingManager),
            PayloadJson = JsonSerializer.Serialize(new
            {
                requestId = requestId,
                fingerprint = pending.PhoneFingerprint,
                displayName = pending.DisplayName,
                allowed = true
            })
        });

        _logger.Info($"PairingManager: Successfully paired with phone '{pending.DisplayName}' ({pending.PhoneFingerprint})!");
        return true;
    }

    private static byte[] ComputeAuthKey(string pin, byte[] transcriptHash, string requestId, byte[] hostSpki, byte[] phoneSpki)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin.Trim());
        try
        {
            using var hmac = new HMACSHA256(pinBytes);
            byte[] label = "TETHER-PAIRING-v2"u8.ToArray();
            byte[] reqIdBytes = Encoding.UTF8.GetBytes(requestId);

            using var ms = new MemoryStream();
            ms.Write(label);
            ms.Write(transcriptHash);
            ms.Write(reqIdBytes);
            ms.Write(hostSpki);
            ms.Write(phoneSpki);

            return hmac.ComputeHash(ms.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinBytes);
        }
    }

    private static byte[] ComputeServerProof(string pin, byte[] authKey, byte[] hostSpki, byte[] phoneSpki)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin.Trim());
        try
        {
            using var hmac = new HMACSHA256(pinBytes);
            byte[] label = "SERVER-OK"u8.ToArray();

            using var ms = new MemoryStream();
            ms.Write(label);
            ms.Write(authKey);
            ms.Write(hostSpki);
            ms.Write(phoneSpki);

            return hmac.ComputeHash(ms.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pinBytes);
        }
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

    private void ShowSecurePairingPrompt(string phoneName, string pin)
    {
        Task.Run(() =>
        {
            try
            {
                var session = PlatformDetection.GetActiveSessionInfo();
                string title = "Tether Pairing Code";
                string body = $"Device '{phoneName}' is requesting to pair.\n\nPIN: {pin}";

                // 1. Try notify-send
                try
                {
                    var psiNotify = new ProcessStartInfo
                    {
                        FileName = "notify-send",
                        Arguments = $"--app-name=Tether --urgency=critical \"{title}: {pin}\" \"Device '{phoneName}' is requesting to pair.\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    if (!string.IsNullOrEmpty(session.XdgRuntimeDir))
                    {
                        psiNotify.EnvironmentVariables["XDG_RUNTIME_DIR"] = session.XdgRuntimeDir;
                    }
                    if (!string.IsNullOrEmpty(session.DisplayName))
                    {
                        psiNotify.EnvironmentVariables["DISPLAY"] = session.DisplayName;
                    }
                    if (!string.IsNullOrEmpty(session.WaylandDisplay))
                    {
                        psiNotify.EnvironmentVariables["WAYLAND_DISPLAY"] = session.WaylandDisplay;
                    }

                    using var p = Process.Start(psiNotify);
                    p?.WaitForExit(3000);
                }
                catch { }

                // 2. Try zenity popup if available and in user desktop
                try
                {
                    var psiZenity = new ProcessStartInfo
                    {
                        FileName = "zenity",
                        Arguments = $"--info --title=\"Tether Pairing Request\" --text=\"{body}\" --timeout=60",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    if (!string.IsNullOrEmpty(session.XdgRuntimeDir))
                    {
                        psiZenity.EnvironmentVariables["XDG_RUNTIME_DIR"] = session.XdgRuntimeDir;
                    }
                    if (!string.IsNullOrEmpty(session.DisplayName))
                    {
                        psiZenity.EnvironmentVariables["DISPLAY"] = session.DisplayName;
                    }
                    if (!string.IsNullOrEmpty(session.WaylandDisplay))
                    {
                        psiZenity.EnvironmentVariables["WAYLAND_DISPLAY"] = session.WaylandDisplay;
                    }

                    using var pZen = Process.Start(psiZenity);
                }
                catch { }
            }
            catch (Exception ex)
            {
                _logger.Warning($"Could not display GUI pairing prompt: {ex.Message}");
            }
        });
    }
}
