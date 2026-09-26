using Microsoft.Win32;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.Shared.DTO;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService;

/// <summary>
/// Wi-Fi / LAN transport server. Replaces BLE entirely.
/// Speaks the same wire protocol as Android's TetherLanService:
///   - UDP broadcast discovery on port 37123 (TETHER_DISCOVER_REQ/RESP)
///   - TCP listener on port 37123
///   - Mutual RSA handshake + AES-256-GCM framed commands
/// NO BLE. NO RSSI. NO PROXIMITY. Same-subnet enforcement only.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LanTransportServer : IDisposable
{
    public const int LISTEN_PORT = 37123;
    private const string SERVICE_TYPE = "_tether._tcp.";
    private const int FRAME_MAX_SIZE = 1024 * 1024;
    private const int UNLOCK_COOLDOWN_MS = 3000;
    private const int HEARTBEAT_INTERVAL_MS = 30_000;
    private const int HEARTBEAT_TIMEOUT_MS = 120_000;

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;

    // Network
    private TcpListener? _tcpListener;
    private UdpClient? _udpDiscovery;
    private CancellationTokenSource? _cts;
    private Task? _tcpLoopTask;
    private Task? _udpLoopTask;
    private Task? _heartbeatTask;

    private TcpClient? _client;
    private NetworkStream? _stream;
    private readonly SemaphoreSlim _connectionLock = new(1, 1);

    // Session / crypto state
    private readonly object _sessionLock = new();
    private byte[]? _sessionKey;
    private bool _isAuthenticated;
    private DateTime _lastInboundFrameUtc = DateTime.UtcNow;
    private DateTime _lastUnlockTime = DateTime.MinValue;
    private bool _isPlannedResetActive;

    private RSA? _serverRsa;
    private byte[]? _serverPublicKeyBytes;    // SubjectPublicKeyInfo
    private byte[]? _trustedPhonePublicKey;   // SubjectPublicKeyInfo (pinned)
    private bool _isProvisioned;

    private bool _isStopping;

    // IPC handles for the Windows credential provider
    private EventWaitHandle? _appEvent;
    private EventWaitHandle? _screenEvent;
    private readonly object _ipcLock = new();

    // ---------- Win32 ----------
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
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
        public int dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    public LanTransportServer(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;

        LoadTrustedPhoneKey();

        _eventBus.Subscribe(evt =>
        {
            if (evt.EventType == TetherEventType.PROVISION_PHONE && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    var payload = JsonSerializer.Deserialize<ProvisionPayload>(evt.PayloadJson);
                    if (payload != null && !string.IsNullOrEmpty(payload.PublicKeyBase64))
                        ProvisionPhone(payload.PublicKeyBase64);
                }
                catch (Exception ex)
                {
                    _logger.Error($"Provisioning event failed: {ex.Message}");
                }
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
            _logger.Warning("LAN transport: no trusted phone provisioned. Waiting for pairing via IPC.");

        InitializeIpcHandles();

        _cts = new CancellationTokenSource();
        _tcpLoopTask = Task.Run(() => TcpAcceptLoopAsync(_cts.Token));
        _udpLoopTask = Task.Run(() => UdpDiscoveryLoopAsync(_cts.Token));
        _heartbeatTask = Task.Run(() => HeartbeatLoopAsync(_cts.Token));

        _logger.Info($"📡 LAN transport listening on TCP {LISTEN_PORT} and UDP {LISTEN_PORT} (service '{SERVICE_TYPE}').");
    }

    public void Stop()
    {
        _isStopping = true;
        try { _cts?.Cancel(); } catch { }
        try { _tcpListener?.Stop(); } catch { }
        try { _udpDiscovery?.Close(); } catch { }
        DisposeSession();
        _logger.Info("LAN transport stopped.");
    }

    public void Dispose() => Stop();

    // =====================================================================
    //  TCP LISTENER
    // =====================================================================

    private async Task TcpAcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            _tcpListener = new TcpListener(IPAddress.Any, LISTEN_PORT);
            _tcpListener.Start(4);
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to bind TCP {LISTEN_PORT}: {ex.Message}");
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            TcpClient? incoming = null;
            try { incoming = await _tcpListener.AcceptTcpClientAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.Warning($"Accept failed: {ex.Message}");
                await Task.Delay(500, ct);
                continue;
            }

            // ----- Same-subnet enforcement -----
            var remoteEp = incoming.Client.RemoteEndPoint as IPEndPoint;
            if (remoteEp == null || !IsSameSubnet(remoteEp.Address))
            {
                _logger.Warning($"🚫 Rejected connection from non-LAN address: {remoteEp?.Address}");
                try { incoming.Close(); } catch { }
                continue;
            }

            if (!await _connectionLock.WaitAsync(0, ct))
            {
                _logger.Warning("Rejecting additional peer: a session is already active.");
                try { incoming.Close(); } catch { }
                continue;
            }

            try { await HandlePeerAsync(incoming, ct); }
            finally { _connectionLock.Release(); }
        }
    }

    private async Task HandlePeerAsync(TcpClient peer, CancellationToken ct)
    {
        _client = peer;
        _stream = peer.GetStream();
        peer.NoDelay = true;
        peer.ReceiveTimeout = HEARTBEAT_TIMEOUT_MS;

        // Enable OS-level TCP keepalive for half-open detection
        try
        {
            peer.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        }
        catch { /* best effort */ }

        var remote = (IPEndPoint)peer.Client.RemoteEndPoint!;
        _logger.Info($"🔌 Peer connected from {remote.Address}:{remote.Port}");

        bool wasAuthenticated = false;
        bool plannedReset = false;

        try
        {
            // ------- Handshake phase: plain JSON frames -------
            var helloStr = await ReadJsonFrameAsync(ct);
            if (helloStr == null) return;

            using var helloDoc = JsonDocument.Parse(helloStr);
            var helloRoot = helloDoc.RootElement;
            string type = helloRoot.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";

            if (type != "INIT_HANDSHAKE")
            {
                _logger.Warning($"Expected INIT_HANDSHAKE, got '{type}'. Dropping.");
                return;
            }

            if (!IsProvisioned())
            {
                _logger.Warning("Peer attempted handshake but no trusted phone key is provisioned. Dropping.");
                return;
            }

            string phonePubB64 = helloRoot.GetProperty("phonePublicKey").GetString()!;
            string phoneNonceB64 = helloRoot.GetProperty("phoneNonce").GetString()!;
            byte[] phonePub = Convert.FromBase64String(phonePubB64);
            byte[] phoneNonce = Convert.FromBase64String(phoneNonceB64);

            if (_trustedPhonePublicKey == null ||
                !CryptographicOperations.FixedTimeEquals(phonePub, _trustedPhonePublicKey))
            {
                _logger.Error("🚫 Phone public key does NOT match pinned identity. Dropping handshake.");
                return;
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
                signature = Convert.ToBase64String(signature)
            };
            await SendJsonFrameAsync(JsonSerializer.Serialize(respObj), ct);

            // ------- AUTH_CONFIRM -------
            var authStr = await ReadJsonFrameAsync(ct);
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
            _logger.Info($"✅ Peer authenticated ({remote.Address}). Secure LAN session established.");
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = nameof(LanTransportServer) });
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = nameof(LanTransportServer) });

            // ------- Encrypted command loop -------
            while (!ct.IsCancellationRequested)
            {
                byte[]? rawFrame = await ReadBinaryFrameAsync(ct);
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
                    await ExecuteCommandAsync(command, ct);
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

            DisposeSession();

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
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = nameof(LanTransportServer) });
                }
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = nameof(LanTransportServer) });
            }
        }
    }

    // =====================================================================
    //  UDP DISCOVERY
    // =====================================================================

    private async Task UdpDiscoveryLoopAsync(CancellationToken ct)
    {
        try
        {
            _udpDiscovery = new UdpClient();
            _udpDiscovery.EnableBroadcast = true;
            _udpDiscovery.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpDiscovery.Client.Bind(new IPEndPoint(IPAddress.Any, LISTEN_PORT));
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to bind UDP {LISTEN_PORT}: {ex.Message}");
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _udpDiscovery.ReceiveAsync(ct);
                string text = Encoding.UTF8.GetString(result.Buffer);

                using var doc = JsonDocument.Parse(text);
                if (doc.RootElement.TryGetProperty("type", out var t) &&
                    t.GetString() == "TETHER_DISCOVER_REQ")
                {
                    if (!IsSameSubnet(result.RemoteEndPoint.Address))
                        continue;

                    var respObj = new
                    {
                        type = "TETHER_DISCOVER_RESP",
                        port = LISTEN_PORT,
                        serviceType = SERVICE_TYPE
                    };
                    byte[] payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(respObj));

                    await _udpDiscovery.SendAsync(payload, payload.Length, result.RemoteEndPoint);
                    _logger.Debug($"↩️  Replied to discovery request from {result.RemoteEndPoint.Address}");
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _logger.Debug($"UDP discovery loop error: {ex.Message}");
                await Task.Delay(500, ct);
            }
        }
    }

    // =====================================================================
    //  HEARTBEAT (replaces RSSI proximity watchdog)
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
                    try { _client?.Close(); } catch { }
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
    //  FRAMING
    // =====================================================================
    //  Wire format (both directions):
    //      [4-byte big-endian length][ payload bytes ]
    //
    //  Handshake phase:  payload is UTF-8 JSON
    //  Command  phase:   payload is  [12-byte IV][ciphertext][16-byte tag]
    //                    (AES-256-GCM, IV random per frame)

    private async Task<string?> ReadJsonFrameAsync(CancellationToken ct)
    {
        var bytes = await ReadBinaryFrameAsync(ct);
        return bytes == null ? null : Encoding.UTF8.GetString(bytes);
    }

    private async Task<byte[]?> ReadBinaryFrameAsync(CancellationToken ct)
    {
        var stream = _stream;
        if (stream == null) return null;

        byte[] lenBuf = new byte[4];
        if (!await ReadExactAsync(stream, lenBuf, 0, 4, ct)) return null;

        int len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
        if (len <= 0 || len > FRAME_MAX_SIZE) return null;

        byte[] body = new byte[len];
        if (!await ReadExactAsync(stream, body, 0, len, ct)) return null;

        lock (_sessionLock) { _lastInboundFrameUtc = DateTime.UtcNow; }
        return body;
    }

    private async Task SendJsonFrameAsync(string json, CancellationToken ct)
    {
        var stream = _stream;
        if (stream == null) return;

        byte[] body = Encoding.UTF8.GetBytes(json);
        await WriteFramedAsync(stream, body, ct);
    }

    private async Task SendEncryptedAsync(object payload, CancellationToken ct)
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
        Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
        Buffer.BlockCopy(cipher, 0, combined, iv.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, combined, iv.Length + cipher.Length, tag.Length);

        var stream = _stream;
        if (stream == null) return;
        await WriteFramedAsync(stream, combined, ct);
    }

    private static async Task WriteFramedAsync(NetworkStream stream, byte[] body, CancellationToken ct)
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

    private async Task ExecuteCommandAsync(string command, CancellationToken ct)
    {
        try
        {
            _logger.Info($"📬 Command received over LAN: {command}");

            if (command != "reset_pending" && command != "auth_ok")
                await SendEncryptedAsync(new { type = "CONFIRM_COMMAND", confirmedCommand = command }, ct);

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
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = nameof(LanTransportServer) });
                    LockWorkstation();
                    break;

                case "unlock":
                    if ((DateTime.Now - _lastUnlockTime).TotalMilliseconds < UNLOCK_COOLDOWN_MS) break;
                    _lastUnlockTime = DateTime.Now;
                    SignalCredentialProvider(lost: false);
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = nameof(LanTransportServer) });
                    break;

                case "screen_unlock":
                    SignalCredentialProvider(lost: false);
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_UNLOCKED, Source = nameof(LanTransportServer) });
                    break;

                case "volume_up":
                case "volume_down":
                case "brightness_up":
                case "brightness_down":
                    // Hook into your existing hardware command plumbing if needed.
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
                    // Heartbeat from Android periodic health check
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
                var security = new EventWaitHandleSecurity();
                security.AddAccessRule(new EventWaitHandleAccessRule(
                    new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                    EventWaitHandleRights.Synchronize | EventWaitHandleRights.Modify,
                    AccessControlType.Allow));

                var selfSid = WindowsIdentity.GetCurrent().User;
                if (selfSid != null)
                {
                    security.AddAccessRule(new EventWaitHandleAccessRule(
                        selfSid, EventWaitHandleRights.FullControl, AccessControlType.Allow));
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
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, true);
            if (key == null)
            {
                using var newKey = Registry.LocalMachine.CreateSubKey(keyPath);
                using var rsa = RSA.Create(2048);
                newKey.SetValue("PrivateKey", rsa.ExportRSAPrivateKey(), RegistryValueKind.Binary);
                newKey.SetValue("PublicKey", rsa.ExportSubjectPublicKeyInfo(), RegistryValueKind.Binary);
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
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider");
            if (key == null) { _isProvisioned = false; return; }

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
                _isProvisioned = false;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"LoadTrustedPhoneKey failed: {ex.Message}");
            _isProvisioned = false;
        }
    }

    private void MigrateOldKeys()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
            if (key == null) return;

            foreach (var name in key.GetValueNames().Where(n => n.StartsWith("Key_")).ToList())
                key.DeleteValue(name);

            key.SetValue("Provisioned", 0, RegistryValueKind.DWord);
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

            using var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider");
            key.SetValue("TrustedPhonePublicKey", base64PublicKey, RegistryValueKind.String);
            key.SetValue("Provisioned", 1, RegistryValueKind.DWord);

            LoadTrustedPhoneKey();
            _logger.Info("Phone key provisioned successfully.");
        }
        catch (Exception ex)
        {
            _logger.Error($"ProvisionPhone failed: {ex.Message}");
        }
    }

    // =====================================================================
    //  SAME-SUBNET ENFORCEMENT
    // =====================================================================

    private static bool IsSameSubnet(IPAddress remote)
    {
        if (remote.AddressFamily != AddressFamily.InterNetwork) return false;
        if (IPAddress.IsLoopback(remote)) return true;

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                var mask = ua.IPv4Mask;
                if (mask == null) continue;
                if (SameNetwork(remote, ua.Address, mask)) return true;
            }
        }
        return false;
    }

    private static bool SameNetwork(IPAddress a, IPAddress b, IPAddress mask)
    {
        byte[] ab = a.GetAddressBytes();
        byte[] bb = b.GetAddressBytes();
        byte[] mb = mask.GetAddressBytes();
        if (ab.Length != 4 || bb.Length != 4 || mb.Length != 4) return false;
        for (int i = 0; i < 4; i++)
            if ((ab[i] & mb[i]) != (bb[i] & mb[i])) return false;
        return true;
    }

    // =====================================================================
    //  UTILITIES
    // =====================================================================

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }

    private static async Task<bool> ReadExactAsync(NetworkStream s, byte[] buf, int off, int len, CancellationToken ct)
    {
        int read = 0;
        while (read < len)
        {
            int n;
            try { n = await s.ReadAsync(buf.AsMemory(off + read, len - read), ct); }
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
        try { _client?.Close(); } catch { }
        _stream = null;
        _client = null;
    }
}