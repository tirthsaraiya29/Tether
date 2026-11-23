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

    public IReadOnlyCollection<PendingLinuxPairing> GetPendingRequests()
    {
        var now = DateTime.UtcNow;
        return _pending.Values
            .Where(p => (now - p.CreatedUtc).TotalSeconds <= ExpirationSeconds)
            .ToList();
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
        // 1. Display strictly on the active console screen (per SECURITY.md pairing protocol mandate)
        try
        {
            Console.WriteLine();
            Console.WriteLine("=================================================");
            Console.WriteLine("          TETHER DEVICE PAIRING REQUEST          ");
            Console.WriteLine("=================================================");
            Console.WriteLine($" Device:       {phoneName}");
            Console.WriteLine($" Pairing PIN:  {pin}");
            Console.WriteLine(" Enter this 6-digit PIN on your phone to pair.");
            Console.WriteLine("=================================================");
            Console.WriteLine();
            Console.Out.Flush();
        }
        catch { }

        Task.Run(() =>
        {
            try
            {
                var session = PlatformDetection.GetActiveSessionInfo();
                string title = "Tether Pairing Code";
                string body = $"Device '{phoneName}' is requesting to pair.\n\nPairing PIN: {pin}\nEnter this 6-digit PIN on your phone.";

                string runtimeDir = session.XdgRuntimeDir ?? $"/run/user/{session.Uid}";
                string busAddr = $"unix:path={runtimeDir}/bus";
                string display = !string.IsNullOrEmpty(session.DisplayName) ? session.DisplayName : ":0";
                string waylandDisplay = !string.IsNullOrEmpty(session.WaylandDisplay) ? session.WaylandDisplay : "wayland-0";
                string userHome = $"/home/{session.UserName}";

                bool isRoot = PlatformDetection.IsRoot;
                bool shouldDropPrivileges = isRoot && !string.IsNullOrEmpty(session.UserName) && !string.Equals(session.UserName, "root", StringComparison.OrdinalIgnoreCase);

                // 2. Try desktop notification via notify-send (dropping privileges to active desktop user)
                try
                {
                    ProcessStartInfo psiNotify;
                    if (shouldDropPrivileges)
                    {
                        psiNotify = new ProcessStartInfo
                        {
                            FileName = "runuser",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        psiNotify.ArgumentList.Add("-u");
                        psiNotify.ArgumentList.Add(session.UserName);
                        psiNotify.ArgumentList.Add("--");
                        psiNotify.ArgumentList.Add("env");
                        psiNotify.ArgumentList.Add($"XDG_RUNTIME_DIR={runtimeDir}");
                        psiNotify.ArgumentList.Add($"DBUS_SESSION_BUS_ADDRESS={busAddr}");
                        psiNotify.ArgumentList.Add($"DISPLAY={display}");
                        psiNotify.ArgumentList.Add($"WAYLAND_DISPLAY={waylandDisplay}");
                        psiNotify.ArgumentList.Add($"HOME={userHome}");
                        psiNotify.ArgumentList.Add("notify-send");
                        psiNotify.ArgumentList.Add("--app-name=Tether");
                        psiNotify.ArgumentList.Add("--urgency=critical");
                        psiNotify.ArgumentList.Add($"{title}: {pin}");
                        psiNotify.ArgumentList.Add($"Device '{phoneName}' is requesting to pair.\nPairing PIN: {pin}");
                    }
                    else
                    {
                        psiNotify = new ProcessStartInfo
                        {
                            FileName = "notify-send",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        psiNotify.ArgumentList.Add("--app-name=Tether");
                        psiNotify.ArgumentList.Add("--urgency=critical");
                        psiNotify.ArgumentList.Add($"{title}: {pin}");
                        psiNotify.ArgumentList.Add($"Device '{phoneName}' is requesting to pair.\nPairing PIN: {pin}");
                        psiNotify.EnvironmentVariables["XDG_RUNTIME_DIR"] = runtimeDir;
                        psiNotify.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = busAddr;
                        psiNotify.EnvironmentVariables["DISPLAY"] = display;
                        psiNotify.EnvironmentVariables["WAYLAND_DISPLAY"] = waylandDisplay;
                        psiNotify.EnvironmentVariables["HOME"] = userHome;
                    }

                    using var p = Process.Start(psiNotify);
                    p?.WaitForExit(3000);
                }
                catch { }

                // 3. Try interactive GUI dialog (zenity or kdialog) with software rendering constraints to avoid GPU/Vulkan crashes
                try
                {
                    ProcessStartInfo? psiGui = null;
                    if (File.Exists("/usr/bin/zenity") || File.Exists("/bin/zenity"))
                    {
                        if (shouldDropPrivileges)
                        {
                            psiGui = new ProcessStartInfo
                            {
                                FileName = "runuser",
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };
                            psiGui.ArgumentList.Add("-u");
                            psiGui.ArgumentList.Add(session.UserName);
                            psiGui.ArgumentList.Add("--");
                            psiGui.ArgumentList.Add("env");
                            psiGui.ArgumentList.Add("LIBGL_ALWAYS_SOFTWARE=1");
                            psiGui.ArgumentList.Add("GSK_RENDERER=cairo");
                            psiGui.ArgumentList.Add("GDK_DEBUG=gl-disable");
                            psiGui.ArgumentList.Add("NO_AT_BRIDGE=1");
                            psiGui.ArgumentList.Add($"XDG_RUNTIME_DIR={runtimeDir}");
                            psiGui.ArgumentList.Add($"DBUS_SESSION_BUS_ADDRESS={busAddr}");
                            psiGui.ArgumentList.Add($"DISPLAY={display}");
                            psiGui.ArgumentList.Add($"WAYLAND_DISPLAY={waylandDisplay}");
                            psiGui.ArgumentList.Add($"HOME={userHome}");
                            psiGui.ArgumentList.Add("zenity");
                            psiGui.ArgumentList.Add("--info");
                            psiGui.ArgumentList.Add("--title=Tether Pairing Request");
                            psiGui.ArgumentList.Add($"--text={body}");
                            psiGui.ArgumentList.Add("--timeout=60");
                        }
                        else
                        {
                            psiGui = new ProcessStartInfo
                            {
                                FileName = "zenity",
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };
                            psiGui.ArgumentList.Add("--info");
                            psiGui.ArgumentList.Add("--title=Tether Pairing Request");
                            psiGui.ArgumentList.Add($"--text={body}");
                            psiGui.ArgumentList.Add("--timeout=60");
                            psiGui.EnvironmentVariables["LIBGL_ALWAYS_SOFTWARE"] = "1";
                            psiGui.EnvironmentVariables["GSK_RENDERER"] = "cairo";
                            psiGui.EnvironmentVariables["GDK_DEBUG"] = "gl-disable";
                            psiGui.EnvironmentVariables["NO_AT_BRIDGE"] = "1";
                            psiGui.EnvironmentVariables["XDG_RUNTIME_DIR"] = runtimeDir;
                            psiGui.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = busAddr;
                            psiGui.EnvironmentVariables["DISPLAY"] = display;
                            psiGui.EnvironmentVariables["WAYLAND_DISPLAY"] = waylandDisplay;
                            psiGui.EnvironmentVariables["HOME"] = userHome;
                        }
                    }
                    else if (File.Exists("/usr/bin/kdialog") || File.Exists("/bin/kdialog"))
                    {
                        if (shouldDropPrivileges)
                        {
                            psiGui = new ProcessStartInfo
                            {
                                FileName = "runuser",
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };
                            psiGui.ArgumentList.Add("-u");
                            psiGui.ArgumentList.Add(session.UserName);
                            psiGui.ArgumentList.Add("--");
                            psiGui.ArgumentList.Add("env");
                            psiGui.ArgumentList.Add($"XDG_RUNTIME_DIR={runtimeDir}");
                            psiGui.ArgumentList.Add($"DBUS_SESSION_BUS_ADDRESS={busAddr}");
                            psiGui.ArgumentList.Add($"DISPLAY={display}");
                            psiGui.ArgumentList.Add($"WAYLAND_DISPLAY={waylandDisplay}");
                            psiGui.ArgumentList.Add($"HOME={userHome}");
                            psiGui.ArgumentList.Add("kdialog");
                            psiGui.ArgumentList.Add("--title");
                            psiGui.ArgumentList.Add("Tether Pairing Request");
                            psiGui.ArgumentList.Add("--msgbox");
                            psiGui.ArgumentList.Add(body);
                        }
                        else
                        {
                            psiGui = new ProcessStartInfo
                            {
                                FileName = "kdialog",
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };
                            psiGui.ArgumentList.Add("--title");
                            psiGui.ArgumentList.Add("Tether Pairing Request");
                            psiGui.ArgumentList.Add("--msgbox");
                            psiGui.ArgumentList.Add(body);
                            psiGui.EnvironmentVariables["XDG_RUNTIME_DIR"] = runtimeDir;
                            psiGui.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = busAddr;
                            psiGui.EnvironmentVariables["DISPLAY"] = display;
                            psiGui.EnvironmentVariables["WAYLAND_DISPLAY"] = waylandDisplay;
                            psiGui.EnvironmentVariables["HOME"] = userHome;
                        }
                    }

                    if (psiGui != null)
                    {
                        using var pZen = Process.Start(psiGui);
                    }
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
