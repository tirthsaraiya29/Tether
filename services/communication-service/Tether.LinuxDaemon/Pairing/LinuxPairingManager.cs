using System;
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

        _logger.Info($"PairingManager: Generated pairing request {requestId} for phone '{phoneDisplayName}' ({phoneFingerprint}). PIN={pin}");

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

        byte[] expectedPhoneProof = ComputeTranscriptHmac(pending.TranscriptHash, pending.Pin, "PhoneProof"u8.ToArray());
        byte[] presentedBytes;
        try { presentedBytes = Convert.FromBase64String(presentedProofBase64); }
        catch { presentedBytes = Array.Empty<byte>(); }

        bool matchesHmac = presentedBytes.Length > 0 &&
                           CryptographicOperations.FixedTimeEquals(expectedPhoneProof, presentedBytes);

        bool matchesPlainPin = false;
        if (!matchesHmac)
        {
            try
            {
                string decodedPin = Encoding.UTF8.GetString(presentedBytes).Trim();
                if (CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(decodedPin), Encoding.UTF8.GetBytes(pending.Pin)))
                {
                    matchesPlainPin = true;
                }
            }
            catch { }
        }

        if (!matchesHmac && !matchesPlainPin)
        {
            pending.FailedAttempts++;
            _logger.Warning($"PairingManager: Proof mismatch for requestId '{requestId}' (attempt {pending.FailedAttempts}/{MaxFailedAttempts}).");
            if (pending.FailedAttempts >= MaxFailedAttempts)
            {
                _pending.TryRemove(requestId, out _);
                _logger.Warning($"PairingManager: Max failed attempts reached. Dropped requestId '{requestId}'.");
            }
            return false;
        }

        // Successfully verified!
        _pending.TryRemove(requestId, out _);

        byte[] hostProof = ComputeTranscriptHmac(pending.TranscriptHash, pending.Pin, "HostProof"u8.ToArray());
        hostProofBase64 = Convert.ToBase64String(hostProof);

        _trustStore.AddOrUpdate(
            deviceId: pending.PhoneFingerprint,
            displayName: pending.DisplayName,
            spkiBase64: pending.PhoneSpkiBase64,
            capabilities: new[] { "MEDIA", "LOCK", "INPUT", "NOTIFICATIONS", "TERMINAL", "FILES", "WINDOWS_ADMIN", "APP_MANAGEMENT" },
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

    private static byte[] ComputeTranscriptHmac(byte[] transcriptHash, string pin, byte[] label)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
        using var hmac = new HMACSHA256(pinBytes);
        byte[] data = new byte[transcriptHash.Length + label.Length];
        Buffer.BlockCopy(transcriptHash, 0, data, 0, transcriptHash.Length);
        Buffer.BlockCopy(label, 0, data, transcriptHash.Length, label.Length);
        return hmac.ComputeHash(data);
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
