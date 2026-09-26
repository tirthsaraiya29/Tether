using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Windows.Devices.Enumeration;
using Windows.Devices.WiFiDirect;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Credentials;
using Tether.EventBus;
using Tether.Shared.DTO;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService;

[SupportedOSPlatform("windows10.0.22621.0")]
public sealed class WiFiDirectTransportServer : IDisposable
{
    public const int LISTEN_PORT = 37123;
    private const string SERVICE_NAME = "TetherWindows";
    private const int FRAME_MAX_SIZE = 1024 * 1024;
    private const int UNLOCK_COOLDOWN_MS = 3000;
    private const int HEARTBEAT_INTERVAL_MS = 30_000;
    private const int HEARTBEAT_TIMEOUT_MS = 120_000;
    private const int PAIRING_DECISION_TIMEOUT_SEC = 30;
    private const string REG_BASE = @"SOFTWARE\Tether\CredentialProvider";

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly PairingCoordinator _pairingCoordinator;

    private WiFiDirectAdvertisementPublisher? _publisher;
    private WiFiDirectConnectionListener? _connectionListener;
    private StreamSocketListener? _socketListener;
    private CancellationTokenSource? _cts;
    private Task? _heartbeatTask;

    private Stream? _stream;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    private readonly object _sessionLock = new();
    private byte[]? _sessionKey;
    private bool _isAuthenticated;
    private DateTime _lastInboundFrameUtc = DateTime.UtcNow;
    private DateTime _lastUnlockTime = DateTime.MinValue;
    private bool _isPlannedResetActive;

    private RSA? _serverRsa;
    private byte[]? _serverPublicKeyBytes;
    private byte[]? _trustedPhonePublicKey;
    private bool _isProvisioned;
    private bool _isStopping;

    private EventWaitHandle? _appEvent;
    private EventWaitHandle? _screenEvent;
    private readonly object _ipcLock = new();

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken, string? lpApplicationName, string? lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public WiFiDirectTransportServer(IEventBus eventBus, ITetherLogger logger, PairingCoordinator pairingCoordinator)
    {
        _eventBus = eventBus;
        _logger = logger;
        _pairingCoordinator = pairingCoordinator;

        LoadTrustedPhoneKey();

        _eventBus.Subscribe(evt =>
        {
            try
            {
                switch (evt.EventType)
                {
                    case TetherEventType.PROVISION_PHONE:
                        if (!string.IsNullOrEmpty(evt.PayloadJson))
                        {
                            var payload = JsonSerializer.Deserialize<ProvisionPayload>(evt.PayloadJson);
                            if (payload != null && !string.IsNullOrEmpty(payload.PublicKeyBase64))
                                ProvisionPhone(payload.PublicKeyBase64);
                        }
                        break;

                    case TetherEventType.PAIRING_DECISION:
                        if (!string.IsNullOrEmpty(evt.PayloadJson))
                        {
                            var payload = JsonSerializer.Deserialize<PairingDecisionPayload>(evt.PayloadJson);
                            if (payload != null) HandlePairingDecision(payload);
                        }
                        break;

                    case TetherEventType.FORGET_PHONE:
                        ForgetPhone();
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"WiFiDirectTransportServer event handling failed ({evt.EventType}): {ex.Message}");
            }
        });
    }

    // =====================================================================
    //  LIFECYCLE
    // =====================================================================

    public void Start()
    {
        lock (_ipcLock) { _isStopping = false; }

        EnsureServerKeyPair();
        MigrateOldKeys();

        if (!IsProvisioned())
            _logger.Warning("Wi-Fi Direct transport: no trusted phone provisioned. Awaiting first-time pairing (TOFU).");

        InitializeIpcHandles();

        _cts = new CancellationTokenSource();

        StartAdvertisement();
        StartSocketListener();

        _heartbeatTask = Task.Run(() => HeartbeatLoopAsync(_cts.Token));

        _logger.Info($"📡 Wi-Fi Direct transport advertising as '{SERVICE_NAME}' (autonomous GO) and listening on TCP {LISTEN_PORT}.");
    }

    public void Stop()
    {
        _isStopping = true;

        try { _cts?.Cancel(); } catch { }

        StopAdvertisement();
        StopSocketListener();
        DisposeSession();

        try { _heartbeatTask?.Wait(2000); } catch { }
        try { _cts?.Dispose(); } catch { }
        _cts = null;

        _logger.Info("Wi-Fi Direct transport stopped.");
    }

    public void Dispose() => Stop();

    // =====================================================================
    //  WI-FI DIRECT ADVERTISEMENT (GROUP OWNER) + CONNECTION LISTENER
    // =====================================================================

    private void StartAdvertisement()
    {
        try
        {
            _publisher = new WiFiDirectAdvertisementPublisher();
            _publisher.StatusChanged += OnPublisherStatusChanged;

            // Configure as autonomous Group Owner (SoftAP-like)
            _publisher.Advertisement.IsAutonomousGroupOwnerEnabled = true;
            _publisher.Advertisement.ListenStateDiscoverability =
                WiFiDirectAdvertisementListenStateDiscoverability.Intensive;

            // Enable legacy mode so Android devices that don't natively support
            // Wi-Fi Direct can still connect as standard Wi-Fi clients.
            var legacy = _publisher.Advertisement.LegacySettings;
            legacy.IsEnabled = true;
            legacy.Ssid = SERVICE_NAME;

            var credential = new PasswordCredential { Password = GenerateRandomPassphrase() };
            legacy.Passphrase = credential;

            _publisher.Start();

            // ---- Native Wi-Fi Direct connection listener ----
            // Fires when an Android peer negotiates a native P2P connection
            // (as opposed to a legacy SoftAP association). Because we are an
            // autonomous GO, no negotiation is required, but accepting the
            // request via WiFiDirectDevice.FromIdAsync() is required for some
            // Windows builds to complete the P2P group formation. The data
            // socket itself still arrives on our StreamSocketListener.
            _connectionListener = new WiFiDirectConnectionListener();
            _connectionListener.ConnectionRequested += OnConnectionRequested;

            _logger.Info($"✅ Wi-Fi Direct advertisement started. SSID='{legacy.Ssid}', " +
                         $"AutonomousGO=true, LegacyEnabled=true, ConnectionListener=armed.");
        }
        catch (Exception ex)
        {
            _logger.Error($"❌ Wi-Fi Direct advertisement failed: {ex.Message}");
        }
    }

    private void StopAdvertisement()
    {
        try
        {
            if (_connectionListener != null)
            {
                _connectionListener.ConnectionRequested -= OnConnectionRequested;
                _connectionListener = null;
            }
        }
        catch { }

        try
        {
            if (_publisher != null)
            {
                _publisher.StatusChanged -= OnPublisherStatusChanged;
                _publisher.Stop();
            }
        }
        catch { }
        finally
        {
            _publisher = null;
            _connectionListener = null;
        }
    }

    private void OnConnectionRequested(
        WiFiDirectConnectionListener sender,
        WiFiDirectConnectionRequestedEventArgs args)
    {
        _ = HandleConnectionRequestAsync(args);
    }

    private async Task HandleConnectionRequestAsync(WiFiDirectConnectionRequestedEventArgs args)
    {
        WiFiDirectConnectionRequest? request = null;
        WiFiDirectDevice? device = null;

        try
        {
            request = args.GetConnectionRequest();
            _logger.Info($"📥 Wi-Fi Direct connection request from '{request.DeviceInformation.Name}' " +
                         $"(id={request.DeviceInformation.Id})");

            // Complete P2P group formation. Required even though we are autonomous GO.
            device = await WiFiDirectDevice.FromIdAsync(request.DeviceInformation.Id);
            if (device == null)
            {
                _logger.Warning("WiFiDirectDevice.FromIdAsync returned null — dropping request.");
                return;
            }

            var endpointPairs = device.GetConnectionEndpointPairs();
            foreach (var ep in endpointPairs)
            {
                _logger.Info($"   ↳ P2P endpoint negotiated: local={ep.LocalHostName}, remote={ep.RemoteHostName}");
            }

            // We do NOT open an outbound socket here. As GO, the peer initiates
            // the TCP connection to our StreamSocketListener, which is already
            // bound and waiting. That socket is the sole data path into the
            // cryptographic pipeline.
        }
        catch (Exception ex)
        {
            _logger.Error($"Wi-Fi Direct connection request handling failed: {ex.Message}");
        }
        finally
        {
            try { device?.Dispose(); } catch { }
            try { request?.Dispose(); } catch { }
        }
    }

    private void OnPublisherStatusChanged(
        WiFiDirectAdvertisementPublisher sender,
        WiFiDirectAdvertisementPublisherStatusChangedEventArgs args)
    {
        _logger.Info($"Wi-Fi Direct advertisement status: {args.Status}" +
                     (args.Error != WiFiDirectError.Success ? $" (Error: {args.Error})" : ""));

        if (args.Status == WiFiDirectAdvertisementPublisherStatus.Aborted && !_isStopping)
        {
            _logger.Warning("Wi-Fi Direct advertisement aborted. Attempting restart...");
            _ = Task.Delay(3000).ContinueWith(_ =>
            {
                if (!_isStopping) StartAdvertisement();
            });
        }
    }

    private static string GenerateRandomPassphrase()
    {
        const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        var result = new char[16];
        for (int i = 0; i < result.Length; i++)
            result[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
        return new string(result);
    }

    // =====================================================================
    //  SOCKET LISTENER (TCP over Wi-Fi Direct virtual adapter)
    // =====================================================================

    private void StartSocketListener()
    {
        try
        {
            _socketListener = new StreamSocketListener();
            _socketListener.ConnectionReceived += OnSocketConnectionReceived;

            // Bind to all interfaces; Wi-Fi Direct virtual adapter (typically
            // 192.168.137.1 for SoftAP mode, or an APIPA 169.254.x.x range for
            // native P2P) is reachable because we are the group owner. Isolation
            // is provided by the Wi-Fi Direct WPA2 layer, so no subnet check is
            // performed here (unlike the previous LAN transport).
            _ = _socketListener.BindServiceNameAsync(LISTEN_PORT.ToString())
                .AsTask()
                .ContinueWith(t =>
                {
                    if (t.IsFaulted)
                    {
                        _logger.Error($"❌ Failed to bind StreamSocketListener on port {LISTEN_PORT}: {t.Exception?.Message}");
                    }
                    else
                    {
                        _logger.Info($"✅ StreamSocketListener bound to port {LISTEN_PORT} (Wi-Fi Direct virtual adapter).");
                    }
                });
        }
        catch (Exception ex)
        {
            _logger.Error($"❌ StreamSocketListener creation failed: {ex.Message}");
        }
    }

    private void StopSocketListener()
    {
        try
        {
            if (_socketListener != null)
            {
                _socketListener.ConnectionReceived -= OnSocketConnectionReceived;
                _socketListener.Dispose();
                _socketListener = null;
            }
        }
        catch { }
        finally
        {
            _socketListener = null;
        }
    }

    private async void OnSocketConnectionReceived(StreamSocketListener sender,
        StreamSocketListenerConnectionReceivedEventArgs args)
    {
        // Gate: only one active session at a time
        if (!await _connectionLock.WaitAsync(0))
        {
            _logger.Warning("Rejecting additional peer: a session is already active.");
            try { args.Socket.Dispose(); } catch { }
            return;
        }

        var socket = args.Socket;
        try
        {
            // Convert WinRT StreamSocket to a standard .NET duplex Stream.
            // AsStreamForRead / AsStreamForWrite are extension methods declared
            // in System.IO.WindowsRuntimeStreamExtensions.
            var inputStream = socket.InputStream.AsStreamForRead();
            var outputStream = socket.OutputStream.AsStreamForWrite();
            _stream = new DuplexStream(inputStream, outputStream);

            var remote = socket.Information.RemoteAddress?.ToString() ?? "unknown";
            _logger.Info($"🔌 Wi-Fi Direct peer connected from {remote}.");

            await HandlePeerAsync(_stream, _cts?.Token ?? CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.Warning($"Wi-Fi Direct session ended: {ex.Message}");
        }
        finally
        {
            lock (_sessionLock)
            {
                _isAuthenticated = false;
                _sessionKey = null;
            }

            try { socket.Dispose(); } catch { }
            _stream = null;

            if (!_isStopping)
            {
                _logger.Warning("🔒 Wi-Fi Direct peer disconnected. Locking workstation.");
                LockWorkstation();
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = nameof(WiFiDirectTransportServer) });
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = nameof(WiFiDirectTransportServer) });
            }

            _connectionLock.Release();
        }
    }

    // =====================================================================
    //  PEER SESSION (cryptographic handshake + command loop)
    // =====================================================================

    private async Task HandlePeerAsync(Stream stream, CancellationToken ct)
    {
        bool wasAuthenticated = false;
        bool plannedReset = false;

        try
        {
            // ------- Handshake phase: plain JSON frames -------
            var helloStr = await ReadJsonFrameAsync(stream, ct);
            if (helloStr == null) return;

            using var helloDoc = JsonDocument.Parse(helloStr);
            var helloRoot = helloDoc.RootElement;
            string type = helloRoot.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";

            if (type != "INIT_HANDSHAKE")
            {
                _logger.Warning($"Expected INIT_HANDSHAKE, got '{type}'. Dropping.");
                return;
            }

            string phonePubB64 = helloRoot.GetProperty("phonePublicKey").GetString()!;
            string phoneNonceB64 = helloRoot.GetProperty("phoneNonce").GetString()!;
            bool pairingRequest =
                helloRoot.TryGetProperty("pairingRequest", out var prEl) &&
                prEl.ValueKind == JsonValueKind.True;

            byte[] phonePub = Convert.FromBase64String(phonePubB64);
            byte[] phoneNonce = Convert.FromBase64String(phoneNonceB64);

            bool pairingAccepted;

            // CASE A: already provisioned
            if (IsProvisioned())
            {
                if (_trustedPhonePublicKey == null ||
                    !CryptographicOperations.FixedTimeEquals(phonePub, _trustedPhonePublicKey))
                {
                    _logger.Error("🚫 Phone public key does NOT match pinned identity. Dropping handshake.");
                    return;
                }
                _logger.Info("Existing trusted phone reconnected — pinned key matched.");
                pairingAccepted = true;
            }
            // CASE B: first-time pairing (TOFU)
            else
            {
                if (!pairingRequest)
                {
                    _logger.Warning("No trusted key provisioned and pairingRequest is false. Dropping connection.");
                    return;
                }

                _logger.Info("🔐 First-time pairing request received. Querying DesktopUI for user authorization...");
                pairingAccepted = await RequestPairingDecisionAsync(phonePub, phonePubB64, ct);

                if (!pairingAccepted)
                {
                    _logger.Warning("Pairing denied or timed out. Sending rejection and dropping connection.");
                    try
                    {
                        var reject = new { type = "HANDSHAKE_RESPONSE", pairingAccepted = false };
                        await SendJsonFrameAsync(stream, JsonSerializer.Serialize(reject), ct);
                    }
                    catch { }
                    return;
                }

                ProvisionPhone(phonePubB64);
                _logger.Info("✅ Pairing approved by user; phone key pinned.");
            }

            // ------- Key agreement -------
            byte[] sessionKey = new byte[32];
            RandomNumberGenerator.Fill(sessionKey);
            byte[] windowsNonce = new byte[32];
            RandomNumberGenerator.Fill(windowsNonce);

            byte[] encryptedSessionKey;
            using (var phoneRsa = RSA.Create())
            {
                phoneRsa.ImportSubjectPublicKeyInfo(phonePub, out _);
                encryptedSessionKey = phoneRsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA1);
            }

            byte[] toSign = Concat(phoneNonce, windowsNonce);
            byte[] signature;
            lock (_sessionLock)
            {
                if (_serverRsa == null) return;
                signature = _serverRsa.SignData(toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            var respObj = new
            {
                type = "HANDSHAKE_RESPONSE",
                encryptedSessionKey = Convert.ToBase64String(encryptedSessionKey),
                windowsPublicKey = Convert.ToBase64String(_serverPublicKeyBytes!),
                windowsNonce = Convert.ToBase64String(windowsNonce),
                signature = Convert.ToBase64String(signature),
                pairingAccepted = true
            };
            await SendJsonFrameAsync(stream, JsonSerializer.Serialize(respObj), ct);

            // ------- AUTH_CONFIRM -------
            var authStr = await ReadJsonFrameAsync(stream, ct);
            if (authStr == null) return;

            using var authDoc = JsonDocument.Parse(authStr);
            if (authDoc.RootElement.GetProperty("type").GetString() != "AUTH_CONFIRM") return;
            byte[] phoneConfirm = Convert.FromBase64String(authDoc.RootElement.GetProperty("signature").GetString()!);

            byte[] expectedHmac;
            using (var hmac = new HMACSHA256(sessionKey))
                expectedHmac = hmac.ComputeHash(Concat(windowsNonce, sessionKey));

            if (!CryptographicOperations.FixedTimeEquals(phoneConfirm, expectedHmac))
            {
                _logger.Error("🚫 AUTH_CONFIRM HMAC mismatch. Peer authentication failed.");
                return;
            }

            lock (_sessionLock)
            {
                _sessionKey = sessionKey;
                _isAuthenticated = true;
                _lastInboundFrameUtc = DateTime.UtcNow;
            }

            wasAuthenticated = true;
            _logger.Info("✅ Peer authenticated. Secure Wi-Fi Direct session established.");
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = nameof(WiFiDirectTransportServer) });
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = nameof(WiFiDirectTransportServer) });

            // ------- Encrypted command loop -------
            while (!ct.IsCancellationRequested)
            {
                byte[]? rawFrame = await ReadBinaryFrameAsync(stream, ct);
                if (rawFrame == null) break;

                string? json = DecryptFrame(rawFrame);
                if (json == null)
                {
                    _logger.Warning("Failed to decrypt inbound frame; dropping session.");
                    break;
                }

                using var cmdDoc = JsonDocument.Parse(json);
                var cmdRoot = cmdDoc.RootElement;
                string cmdType = cmdRoot.TryGetProperty("type", out var ctEl) ? ctEl.GetString() ?? "" : "";

                if (cmdType == "COMMAND_EXECUTE")
                {
                    string command = cmdRoot.TryGetProperty("command", out var cmdEl) ? cmdEl.GetString() ?? "" : "";
                    await ExecuteCommandAsync(stream, command, ct);
                }
                else
                {
                    _logger.Debug($"Inbound frame type '{cmdType}' ignored.");
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.Warning($"Peer session ended: {ex.Message}");
        }
        finally
        {
            lock (_sessionLock)
            {
                plannedReset = _isPlannedResetActive;
                _isPlannedResetActive = false;
                _isAuthenticated = false;
                _sessionKey = null;
            }

            if (wasAuthenticated && !_isStopping)
            {
                if (plannedReset)
                {
                    _logger.Info("🔄 Planned reset signaled by phone. Skipping workstation lock.");
                }
                else
                {
                    _logger.Warning("🔒 Peer disconnected. Locking workstation.");
                    LockWorkstation();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = nameof(WiFiDirectTransportServer) });
                }
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = nameof(WiFiDirectTransportServer) });
            }
        }
    }

    // =====================================================================
    //  PAIRING (TOFU) FLOW
    // =====================================================================

    private async Task<bool> RequestPairingDecisionAsync(byte[] phonePub, string phonePubB64, CancellationToken ct)
    {
        var pending = _pairingCoordinator.Register(phonePub);

        try
        {
            var payload = new PairingRequestPayload
            {
                RequestId = pending.RequestId,
                PhonePublicKeyBase64 = phonePubB64,
                Fingerprint = pending.Fingerprint,
                TimestampUtcTicks = DateTime.UtcNow.Ticks
            };

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PAIRING_REQUESTED,
                Source = nameof(WiFiDirectTransportServer),
                PayloadJson = JsonSerializer.Serialize(payload)
            });

            _logger.Info($"📣 PAIRING_REQUESTED broadcast (RequestId={pending.RequestId}, Fingerprint={pending.Fingerprint}). " +
                         $"Awaiting DesktopUI decision (timeout {PAIRING_DECISION_TIMEOUT_SEC}s)...");

            var delayTask = Task.Delay(TimeSpan.FromSeconds(PAIRING_DECISION_TIMEOUT_SEC), ct);
            var completed = await Task.WhenAny(pending.Decision.Task, delayTask);

            if (completed != pending.Decision.Task)
            {
                _logger.Warning($"⏱️ Pairing request {pending.RequestId} timed out after {PAIRING_DECISION_TIMEOUT_SEC}s. Failing closed.");
                pending.Decision.TrySetResult(false);
            }

            return await pending.Decision.Task.ConfigureAwait(false);
        }
        finally
        {
            _pairingCoordinator.Remove(pending.RequestId);
        }
    }

    private void HandlePairingDecision(PairingDecisionPayload payload)
    {
        if (string.IsNullOrEmpty(payload.RequestId))
        {
            _logger.Warning("Ignoring PAIRING_DECISION with empty RequestId.");
            return;
        }

        byte[] presentedKey;
        try
        {
            presentedKey = Convert.FromBase64String(payload.PhonePublicKeyBase64 ?? "");
        }
        catch
        {
            _logger.Warning($"PAIRING_DECISION {payload.RequestId} contained invalid base64 key. Failing closed.");
            _pairingCoordinator.TryResolve(payload.RequestId, Array.Empty<byte>(), allowed: false);
            return;
        }

        bool known = _pairingCoordinator.TryResolve(payload.RequestId, presentedKey, payload.Allowed);

        if (!known)
        {
            _logger.Warning($"PAIRING_DECISION for unknown/expired RequestId {payload.RequestId} ignored.");
            return;
        }

        _logger.Info($"Pairing decision applied for {payload.RequestId}: {(payload.Allowed ? "ALLOW" : "DENY")}");
    }

    public void ForgetPhone()
    {
        try
        {
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(REG_BASE, true))
            {
                if (key != null)
                {
                    key.DeleteValue("TrustedPhonePublicKey", throwOnMissingValue: false);
                    key.SetValue("Provisioned", 0, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }

            LoadTrustedPhoneKey();
            _logger.Info("🗑️ Trusted phone key cleared from registry. Device is now UNPAIRED.");

            try { _stream?.Close(); } catch { }
        }
        catch (Exception ex)
        {
            _logger.Error($"ForgetPhone failed: {ex.Message}");
        }
    }

    // =====================================================================
    //  HEARTBEAT
    // =====================================================================

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(HEARTBEAT_INTERVAL_MS, ct);

                bool isAuth;
                DateTime lastSeen;
                lock (_sessionLock)
                {
                    isAuth = _isAuthenticated;
                    lastSeen = _lastInboundFrameUtc;
                }

                if (!isAuth) continue;

                if ((DateTime.UtcNow - lastSeen).TotalMilliseconds > HEARTBEAT_TIMEOUT_MS)
                {
                    _logger.Warning($"💀 Peer silent for {(DateTime.UtcNow - lastSeen).TotalSeconds:F1}s. Forcing disconnect & lock.");
                    try { _stream?.Close(); } catch { }
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.Debug($"Heartbeat loop error: {ex.Message}");
            }
        }
    }

    // =====================================================================
    //  FRAMING (stream-based)
    // =====================================================================

    private static async Task<string?> ReadJsonFrameAsync(Stream stream, CancellationToken ct)
    {
        var bytes = await ReadBinaryFrameAsync(stream, ct);
        return bytes == null ? null : Encoding.UTF8.GetString(bytes);
    }

    private static async Task<byte[]?> ReadBinaryFrameAsync(Stream stream, CancellationToken ct)
    {
        byte[] lenBuf = new byte[4];
        if (!await ReadExactAsync(stream, lenBuf, 0, 4, ct)) return null;

        int len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
        if (len <= 0 || len > FRAME_MAX_SIZE) return null;

        byte[] body = new byte[len];
        if (!await ReadExactAsync(stream, body, 0, len, ct)) return null;

        return body;
    }

    private static async Task SendJsonFrameAsync(Stream stream, string json, CancellationToken ct)
    {
        byte[] body = Encoding.UTF8.GetBytes(json);
        await WriteFramedAsync(stream, body, ct);
    }

    private async Task SendEncryptedAsync(Stream stream, object payload, CancellationToken ct)
    {
        byte[]? key;
        lock (_sessionLock) { key = _sessionKey; }
        if (key == null) return;

        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(payload);
        byte[] iv = new byte[12];
        RandomNumberGenerator.Fill(iv);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[16];

        using (var gcm = new AesGcm(key, 16))
            gcm.Encrypt(iv, plain, cipher, tag);

        byte[] combined = new byte[iv.Length + cipher.Length + tag.Length];
        System.Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
        System.Buffer.BlockCopy(cipher, 0, combined, iv.Length, cipher.Length);
        System.Buffer.BlockCopy(tag, 0, combined, iv.Length + cipher.Length, tag.Length);

        await WriteFramedAsync(stream, combined, ct);
    }

    private static async Task WriteFramedAsync(Stream stream, byte[] body, CancellationToken ct)
    {
        byte[] lenBuf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(lenBuf, body.Length);
        await stream.WriteAsync(lenBuf, 0, 4, ct);
        await stream.WriteAsync(body, 0, body.Length, ct);
        await stream.FlushAsync(ct);
    }

    private string? DecryptFrame(byte[] data)
    {
        byte[]? key;
        lock (_sessionLock) { key = _sessionKey; }
        if (key == null || data.Length < 28) return null;

        ReadOnlySpan<byte> iv = data.AsSpan(0, 12);
        ReadOnlySpan<byte> tag = data.AsSpan(data.Length - 16, 16);
        ReadOnlySpan<byte> cipher = data.AsSpan(12, data.Length - 28);
        byte[] plain = new byte[cipher.Length];

        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(iv, cipher, tag, plain);
            return Encoding.UTF8.GetString(plain);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    // =====================================================================
    //  COMMAND DISPATCH
    // =====================================================================

    private async Task ExecuteCommandAsync(Stream stream, string command, CancellationToken ct)
    {
        try
        {
            _logger.Info($"📬 Command received over Wi-Fi Direct: {command}");

            if (command != "reset_pending" && command != "auth_ok")
                await SendEncryptedAsync(stream, new { type = "CONFIRM_COMMAND", confirmedCommand = command }, ct);

            switch (command)
            {
                case "auth_ok":
                    break;

                case "reset_pending":
                    lock (_sessionLock) { _isPlannedResetActive = true; }
                    break;

                case "panic":
                case "lock_now":
                    SignalCredentialProvider(lost: true);
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = nameof(WiFiDirectTransportServer) });
                    LockWorkstation();
                    break;

                case "unlock":
                    if ((DateTime.Now - _lastUnlockTime).TotalMilliseconds < UNLOCK_COOLDOWN_MS) break;
                    _lastUnlockTime = DateTime.Now;
                    SignalCredentialProvider(lost: false);
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = nameof(WiFiDirectTransportServer) });
                    break;

                case "screen_unlock":
                    SignalCredentialProvider(lost: false);
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_UNLOCKED, Source = nameof(WiFiDirectTransportServer) });
                    break;

                case "volume_up":
                case "volume_down":
                case "brightness_up":
                case "brightness_down":
                    break;

                case "sleep":
                    RunDetached("rundll32.exe", "powrprof.dll,SetSuspendState 0,1,0");
                    break;

                case "reboot":
                    RunDetached("shutdown", "/r /t 0");
                    break;

                case "shutdown":
                    RunDetached("shutdown", "/s /t 0");
                    break;

                case "PING":
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"ExecuteCommandAsync({command}) failed: {ex.Message}");
        }
    }

    private static void RunDetached(string exe, string args)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }
        catch { }
    }

    private void LockWorkstation()
    {
        IntPtr userToken = IntPtr.Zero;
        try
        {
            uint session = WTSGetActiveConsoleSessionId();
            if (session == 0xFFFFFFFF) return;
            if (!WTSQueryUserToken(session, out userToken)) return;

            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = @"Winsta0\Default";
            var cmd = new StringBuilder("rundll32.exe user32.dll,LockWorkStation");

            if (CreateProcessAsUser(userToken, null, cmd.ToString(), IntPtr.Zero, IntPtr.Zero, false, 0,
                IntPtr.Zero, null, ref si, out var pi))
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"LockWorkstation failed: {ex.Message}");
        }
        finally
        {
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    // =====================================================================
    //  IPC CREDENTIAL PROVIDER SIGNALS
    // =====================================================================

    private void InitializeIpcHandles()
    {
        lock (_ipcLock)
        {
            try
            {
                var security = new System.Security.AccessControl.EventWaitHandleSecurity();
                security.AddAccessRule(new System.Security.AccessControl.EventWaitHandleAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.AuthenticatedUserSid, null),
                    System.Security.AccessControl.EventWaitHandleRights.Synchronize |
                    System.Security.AccessControl.EventWaitHandleRights.Modify,
                    System.Security.AccessControl.AccessControlType.Allow));

                var selfSid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                if (selfSid != null)
                {
                    security.AddAccessRule(new System.Security.AccessControl.EventWaitHandleAccessRule(
                        selfSid, System.Security.AccessControl.EventWaitHandleRights.FullControl,
                        System.Security.AccessControl.AccessControlType.Allow));
                }

                _appEvent = EventWaitHandleAcl.Create(false, EventResetMode.ManualReset,
                    @"Global\TetherPhoneAppUnlocked", out _, security);
                _screenEvent = EventWaitHandleAcl.Create(false, EventResetMode.ManualReset,
                    @"Global\TetherPhoneScreenUnlocked", out _, security);

                _logger.Info("Global credential provider sync handles created.");
            }
            catch (Exception ex)
            {
                _logger.Error($"IPC handle init failed: {ex.Message}");
            }
        }
    }

    private void SignalCredentialProvider(bool lost)
    {
        lock (_ipcLock)
        {
            try
            {
                if (lost)
                {
                    _appEvent?.Reset();
                    _screenEvent?.Reset();
                }
                else
                {
                    _appEvent?.Set();
                    _screenEvent?.Set();
                }
            }
            catch (Exception ex)
            {
                _logger.Debug($"SignalCredentialProvider failed: {ex.Message}");
            }
        }
    }

    // =====================================================================
    //  CRYPTO IDENTITY
    // =====================================================================

    private void EnsureServerKeyPair()
    {
        try
        {
            const string keyPath = @"SOFTWARE\Tether\CredentialProvider\ServerKey_v1";
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, true);
            if (key == null)
            {
                using var newKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(keyPath);
                using var rsa = RSA.Create(2048);
                newKey.SetValue("PrivateKey", rsa.ExportRSAPrivateKey(), Microsoft.Win32.RegistryValueKind.Binary);
                newKey.SetValue("PublicKey", rsa.ExportSubjectPublicKeyInfo(), Microsoft.Win32.RegistryValueKind.Binary);
                lock (_sessionLock)
                {
                    _serverRsa = rsa;
                    _serverPublicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
                }
                _logger.Info("Generated new server RSA identity.");
            }
            else
            {
                var priv = (byte[])key.GetValue("PrivateKey")!;
                var pub = (byte[])key.GetValue("PublicKey")!;
                var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(priv, out _);
                lock (_sessionLock)
                {
                    _serverRsa = rsa;
                    _serverPublicKeyBytes = pub;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Server RSA key setup failed: {ex.Message}");
        }
    }

    private void LoadTrustedPhoneKey()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(REG_BASE);
            if (key == null) { _isProvisioned = false; _trustedPhonePublicKey = null; return; }

            var provisioned = key.GetValue("Provisioned") as int?;
            var storedKey = key.GetValue("TrustedPhonePublicKey") as string;

            if (provisioned == 1 && !string.IsNullOrEmpty(storedKey))
            {
                _trustedPhonePublicKey = Convert.FromBase64String(storedKey);
                _isProvisioned = true;
                _logger.Info("Trusted phone public key loaded.");
            }
            else
            {
                _trustedPhonePublicKey = null;
                _isProvisioned = false;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"LoadTrustedPhoneKey failed: {ex.Message}");
            _isProvisioned = false;
            _trustedPhonePublicKey = null;
        }
    }

    private void MigrateOldKeys()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(REG_BASE, true);
            if (key == null) return;

            foreach (var name in key.GetValueNames().Where(n => n.StartsWith("Key_")).ToList())
                key.DeleteValue(name);

            key.SetValue("Provisioned", 0, Microsoft.Win32.RegistryValueKind.DWord);
            LoadTrustedPhoneKey();
        }
        catch (Exception ex)
        {
            _logger.Error($"Migration failed: {ex.Message}");
        }
    }

    public bool IsProvisioned() =>
        _isProvisioned && _trustedPhonePublicKey != null && _trustedPhonePublicKey.Length >= 64;

    public void ProvisionPhone(string base64PublicKey)
    {
        try
        {
            var bytes = Convert.FromBase64String(base64PublicKey);
            if (bytes.Length < 64) { _logger.Error("Provisioning failed: key too short."); return; }

            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(REG_BASE);
            key.SetValue("TrustedPhonePublicKey", base64PublicKey, Microsoft.Win32.RegistryValueKind.String);
            key.SetValue("Provisioned", 1, Microsoft.Win32.RegistryValueKind.DWord);

            LoadTrustedPhoneKey();
            _logger.Info("Phone key provisioned successfully.");
        }
        catch (Exception ex)
        {
            _logger.Error($"ProvisionPhone failed: {ex.Message}");
        }
    }

    // =====================================================================
    //  UTILITIES
    // =====================================================================

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        System.Buffer.BlockCopy(a, 0, r, 0, a.Length);
        System.Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buf, int off, int len, CancellationToken ct)
    {
        int read = 0;
        while (read < len)
        {
            int n;
            try { n = await stream.ReadAsync(buf.AsMemory(off + read, len - read), ct); }
            catch { return false; }
            if (n <= 0) return false;
            read += n;
        }
        return true;
    }

    private void DisposeSession()
    {
        lock (_sessionLock)
        {
            _isAuthenticated = false;
            _sessionKey = null;
        }
        try { _stream?.Close(); } catch { }
        _stream = null;
    }

    // =====================================================================
    //  DUPLEX STREAM (combines WinRT InputStream + OutputStream)
    // =====================================================================

    private sealed class DuplexStream : Stream
    {
        private readonly Stream _input;
        private readonly Stream _output;

        public DuplexStream(Stream input, Stream output)
        {
            _input = input;
            _output = output;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
            => _input.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _input.ReadAsync(buffer, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => _output.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _output.WriteAsync(buffer, cancellationToken);

        public override void Flush() => _output.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _output.FlushAsync(cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { _input.Dispose(); } catch { }
                try { _output.Dispose(); } catch { }
            }
            base.Dispose(disposing);
        }
    }
}