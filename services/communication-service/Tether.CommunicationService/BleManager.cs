using Microsoft.Win32;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.Shared.DTO;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Foundation;
using Windows.Storage.Streams;
using Windows.UI;

namespace Tether.CommunicationService;

internal enum BleConnectionState
{
    Disconnected,
    Scanning,
    Connecting,
    GattConnected,
    CharacteristicsReady,
    Authenticating,
    SessionReady,
    Ready,
    Disconnecting,
    Failed
}

public partial class BleManager : IDisposable
{
    // =====================================================================
    // Dependencies
    // =====================================================================
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;

    // =====================================================================
    // BLE primitives / synchronization
    // =====================================================================
    private BluetoothLEAdvertisementWatcher? _advWatcher;
    private readonly SemaphoreSlim _scanLock = new(1, 1);
    private readonly SemaphoreSlim _connectionSemaphore = new(1, 1);
    private readonly SemaphoreSlim _disconnectSemaphore = new(1, 1);
    private readonly object _lock = new();

    // =====================================================================
    // Authoritative session — single owner of all per-connection state
    // =====================================================================
    private sealed class BleSession
    {
        public long Generation;
        public CancellationTokenSource Cts = new();

        public BluetoothLEDevice? Device;
        public TypedEventHandler<BluetoothLEDevice, object>? ConnectionStatusHandler;

        public GattDeviceService? Service;
        public GattCharacteristic? ChallengeChar;
        public GattCharacteristic? SignatureChar;
        public GattCharacteristic? CommandChar;
        public GattCharacteristic? PublicKeyChar;
        public GattCharacteristic? WindowsPublicKeyChar;
        public GattCharacteristic? AuthChallengeChar;
        public GattCharacteristic? AuthSignatureChar;
        public GattSession? GattSession;

        public TaskCompletionSource<bool>? SecureAuthTcs;
        public byte[]? SessionKey;
        public bool SecureModeSupported;
        public bool LegacyModeSupported;

        public readonly Queue<int> RssiSamples = new();
        public DateTime LastRssiSampleUtc = DateTime.MinValue;

        public bool DisconnectLogged;
    }

    private BleSession? _session;
    private long _connectionGeneration;
    private BleConnectionState _state = BleConnectionState.Disconnected;

    // =====================================================================
    // Lifecycle / proximity state (orthogonal to connection state)
    // =====================================================================
    private bool _isWorkstationLocked = false;
    private bool _lockedByProximity = false;
    private bool _isReauthenticating = false;
    private bool _isStopping = false;
    private bool _isPlannedResetActive = false;
    private bool _firstAdvertReceived = false;

    // =====================================================================
    // Trust
    // =====================================================================
    private bool _isProvisioned = false;
    private byte[]? _trustedPublicKey = null;
    private RSA? _clientRsa;
    private byte[]? _clientPublicKeyBytes;

    // =====================================================================
    // Timers
    // =====================================================================
    private System.Threading.Timer? _rssiTimer;
    private System.Threading.Timer? _healthCheckTimer;
    private CancellationTokenSource? _cts = new();

    private DateTime _lastUnlockTime = DateTime.MinValue;
    private const int UNLOCK_COOLDOWN_MS = 3000;

    private const int RSSI_GOOD = -65;
    private const int RSSI_LOCK = -78;
    private const int SAMPLE_INTERVAL_MS = 250;
    private const int SAMPLES_PER_AVERAGE = 5;
    private static readonly TimeSpan RssiFreshness = TimeSpan.FromSeconds(3);

    // =====================================================================
    // UUIDs
    // =====================================================================
    private readonly Guid SERVICE_UUID = new("0000FFE0-0000-1000-8000-00805F9B34FB");
    private readonly Guid CHALLENGE_CHAR_UUID = new("0000FFE3-0000-1000-8000-00805F9B34FB");
    private readonly Guid SIGNATURE_CHAR_UUID = new("0000FFE4-0000-1000-8000-00805F9B34FB");
    private readonly Guid COMMAND_CHAR_UUID = new("0000FFE5-0000-1000-8000-00805F9B34FB");
    private readonly Guid PUBLIC_KEY_CHAR_UUID = new("0000FFE6-0000-1000-8000-00805F9B34FB");
    private readonly Guid WINDOWS_PUBLIC_KEY_CHAR_UUID = new("0000FFE7-0000-1000-8000-00805F9B34FB");
    private readonly Guid AUTH_CHALLENGE_CHAR_UUID = new("0000FFE8-0000-1000-8000-00805F9B34FB");
    private readonly Guid AUTH_SIGNATURE_CHAR_UUID = new("0000FFE9-0000-1000-8000-00805F9B34FB");

    // =====================================================================
    // P/Invoke
    // =====================================================================
    [DllImport("user32.dll")] private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    private const byte VK_VOLUME_UP = 0xAF;
    private const byte VK_VOLUME_DOWN = 0xAE;
    private const uint KEYEVENTF_KEYDOWN = 0x0000;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    [DllImport("kernel32.dll", SetLastError = false)] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSDisconnectSession(IntPtr hServer, uint sessionId, bool bWait);

    [DllImport("gdi32.dll")] private static extern bool SetMonitorBrightness(IntPtr hMonitor, uint dwBrightness);
    [DllImport("gdi32.dll")] private static extern bool GetMonitorBrightness(IntPtr hMonitor, out uint pdwMinimumBrightness, out uint pdwCurrentBrightness, out uint pdwMaximumBrightness);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);
    [DllImport("user32.dll")] private static extern bool GetPhysicalMonitorsFromHMONITOR(IntPtr hMonitor, uint dwPhysicalMonitorArraySize, [Out] PHYSICAL_MONITOR[] pPhysicalMonitorArray);
    [DllImport("user32.dll")] private static extern bool DestroyPhysicalMonitor(IntPtr hMonitor);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PHYSICAL_MONITOR
    {
        public IntPtr hPhysicalMonitor;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szPhysicalMonitorDescription;
        public uint dwPhysicalMonitorHandleCount;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
    [DllImport("kernel32.dll", SetLastError = false)] private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken, string? lpApplicationName, string? lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

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

    private const uint MONITOR_DEFAULTTOPRIMARY = 0x00000001;

    // =====================================================================
    // Construction
    // =====================================================================
    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;

        LoadTrustedKey();

        _healthCheckTimer = new System.Threading.Timer(_ =>
        {
            try { HealthCheckCallback(); }
            catch (Exception ex) { _logger.Error($"Health check threw: {ex.Message}"); }
        }, null, Timeout.Infinite, Timeout.Infinite);

        _eventBus.Subscribe(evt =>
        {
            if (evt.EventType == TetherEventType.PHONE_UNLOCKED || evt.EventType == TetherEventType.TRUST_RESTORED)
            {
                lock (_lock)
                {
                    if (_isWorkstationLocked)
                    {
                        _logger.Info("Trust context updated via global EventBus listener.");
                        _isWorkstationLocked = false;
                        _appEvent?.Set();
                        _screenEvent?.Set();
                    }
                }
            }
        });

        _eventBus.Subscribe(evt =>
        {
            if (evt.EventType == TetherEventType.PROVISION_PHONE && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    var payload = System.Text.Json.JsonSerializer.Deserialize<ProvisionPayload>(evt.PayloadJson);
                    if (payload != null && !string.IsNullOrEmpty(payload.PublicKeyBase64))
                        ProvisionPhone(payload.PublicKeyBase64);
                }
                catch (Exception ex) { _logger.Error($"Provisioning event failed: {ex.Message}"); }
            }
        });
    }

    // =====================================================================
    // State-machine primitives
    // =====================================================================
    private bool TryTransition(BleSession? s, BleConnectionState to)
    {
        lock (_lock)
        {
            if (s != null && s.Generation != _connectionGeneration) return false;
            if (!IsValidTransition(_state, to)) return false;
            _state = to;
        }
        _logger.Debug($"[BLE] -> {to}");
        return true;
    }

    private static bool IsValidTransition(BleConnectionState from, BleConnectionState to)
    {
        if (from == to) return true;
        return (from, to) switch
        {
            (BleConnectionState.Disconnected, BleConnectionState.Scanning) => true,
            (BleConnectionState.Disconnected, BleConnectionState.Connecting) => true,
            (BleConnectionState.Scanning, BleConnectionState.Connecting) => true,
            (BleConnectionState.Scanning, BleConnectionState.Disconnected) => true,
            (BleConnectionState.Connecting, BleConnectionState.GattConnected) => true,
            (BleConnectionState.Connecting, BleConnectionState.CharacteristicsReady) => true,
            (BleConnectionState.Connecting, BleConnectionState.Authenticating) => true,
            (BleConnectionState.Connecting, BleConnectionState.SessionReady) => true,
            (BleConnectionState.Connecting, BleConnectionState.Ready) => true,
            (BleConnectionState.Connecting, BleConnectionState.Disconnected) => true,
            (BleConnectionState.Connecting, BleConnectionState.Failed) => true,
            (BleConnectionState.GattConnected, BleConnectionState.CharacteristicsReady) => true,
            (BleConnectionState.GattConnected, BleConnectionState.Failed) => true,
            (BleConnectionState.GattConnected, BleConnectionState.Disconnecting) => true,
            (BleConnectionState.CharacteristicsReady, BleConnectionState.Authenticating) => true,
            (BleConnectionState.CharacteristicsReady, BleConnectionState.Failed) => true,
            (BleConnectionState.CharacteristicsReady, BleConnectionState.Disconnecting) => true,
            (BleConnectionState.Authenticating, BleConnectionState.SessionReady) => true,
            (BleConnectionState.Authenticating, BleConnectionState.Failed) => true,
            (BleConnectionState.Authenticating, BleConnectionState.Disconnecting) => true,
            (BleConnectionState.SessionReady, BleConnectionState.Ready) => true,
            (BleConnectionState.SessionReady, BleConnectionState.Disconnecting) => true,
            (BleConnectionState.SessionReady, BleConnectionState.Failed) => true,
            (BleConnectionState.Ready, BleConnectionState.Disconnecting) => true,
            (BleConnectionState.Ready, BleConnectionState.Failed) => true,
            (BleConnectionState.Failed, BleConnectionState.Disconnected) => true,
            (BleConnectionState.Failed, BleConnectionState.Scanning) => true,
            (BleConnectionState.Failed, BleConnectionState.Connecting) => true,
            (BleConnectionState.Disconnecting, BleConnectionState.Disconnected) => true,
            (BleConnectionState.Disconnecting, BleConnectionState.Scanning) => true,
            (_, BleConnectionState.Disconnected) => true,
            _ => false
        };
    }

    // =====================================================================
    // Trust / provisioning
    // =====================================================================
    private void EnsureClientKeyPair()
    {
        // NOTE: the private key is still stored as a plaintext blob in HKLM.
        // That is a known weakness to be replaced with DPAPI-NG in a follow-up.
        try
        {
            const string legacyKeyName = @"SOFTWARE\Tether\CredentialProvider\ClientKey";
            const string productionKeyName = @"SOFTWARE\Tether\CredentialProvider\ClientKey_v2";

            using (var legacyKey = Registry.LocalMachine.OpenSubKey(legacyKeyName, true))
            {
                if (legacyKey != null)
                {
                    Registry.LocalMachine.DeleteSubKeyTree(legacyKeyName, false);
                    _logger.Info("Purged legacy PKCS#1 registry artifacts.");
                }
            }

            using var key = Registry.LocalMachine.OpenSubKey(productionKeyName, true);
            if (key == null)
            {
                using var newKey = Registry.LocalMachine.CreateSubKey(productionKeyName);
                var rsa = RSA.Create(2048);
                newKey.SetValue("PrivateKey", rsa.ExportRSAPrivateKey(), RegistryValueKind.Binary);
                newKey.SetValue("PublicKey", rsa.ExportSubjectPublicKeyInfo(), RegistryValueKind.Binary);
                _clientRsa = rsa;
                _clientPublicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
            }
            else
            {
                var privateBlob = (byte[])key.GetValue("PrivateKey")!;
                var publicBlob = (byte[])key.GetValue("PublicKey")!;
                _clientRsa = RSA.Create();
                _clientRsa.ImportRSAPrivateKey(privateBlob, out _);
                _clientPublicKeyBytes = publicBlob;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Key manager failed: {ex.Message}");
        }
    }

    private void LoadTrustedKey()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider");
            if (key != null)
            {
                var provisioned = key.GetValue("Provisioned") as int?;
                var storedKey = key.GetValue("TrustedPhonePublicKey") as string;
                _isProvisioned = provisioned == 1 && !string.IsNullOrEmpty(storedKey);
                if (_isProvisioned && !string.IsNullOrEmpty(storedKey))
                {
                    _trustedPublicKey = Convert.FromBase64String(storedKey);
                    _logger.Info("Trusted phone public key loaded.");
                }
                else
                {
                    _trustedPublicKey = null;
                    _logger.Info("Device is unprovisioned.");
                }
            }
            else
            {
                _isProvisioned = false;
                _trustedPublicKey = null;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to load trusted key: {ex.Message}");
            _isProvisioned = false;
            _trustedPublicKey = null;
        }
    }

    private bool IsProvisioned() => _isProvisioned && _trustedPublicKey is { Length: >= 64 };

    private string? GetTrustedPublicKey() =>
        _trustedPublicKey == null ? null : Convert.ToBase64String(_trustedPublicKey);

    public void ProvisionPhone(string base64PublicKey)
    {
        try
        {
            var keyBytes = Convert.FromBase64String(base64PublicKey);
            if (keyBytes.Length < 64) { _logger.Error("Provisioning failed: key too short."); return; }

            using var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider");
            key.SetValue("TrustedPhonePublicKey", base64PublicKey, RegistryValueKind.String);
            key.SetValue("Provisioned", 1, RegistryValueKind.DWord);
            LoadTrustedKey();
            RestartScanning();
        }
        catch (Exception ex) { _logger.Error($"Provisioning failed: {ex.Message}"); }
    }

    // =====================================================================
    // Start / stop
    // =====================================================================
    public void Start()
    {
        lock (_lock) { _isStopping = false; }
        EnsureClientKeyPair();

        if (!IsProvisioned())
            _logger.Warning("No trusted phone provisioned. Waiting for provisioning via IPC.");
        else
            _logger.Info("Provisioned phone detected. Starting BLE scanning.");

        StartScanning();
    }

    private void StartScanning()
    {
        if (!_scanLock.Wait(0)) return;
        try
        {
            lock (_lock)
            {
                if (_isStopping) return;
                if (_state != BleConnectionState.Disconnected &&
                    _state != BleConnectionState.Failed &&
                    _state != BleConnectionState.Scanning)
                    return;
            }

            try
            {
                if (_advWatcher != null)
                {
                    try { _advWatcher.Stop(); } catch { }
                    _advWatcher.Received -= OnDeviceAdvertised;
                    _advWatcher = null;
                }

                _advWatcher = new BluetoothLEAdvertisementWatcher { ScanningMode = BluetoothLEScanningMode.Active };
                _advWatcher.Received += OnDeviceAdvertised;
                _advWatcher.Start();

                lock (_lock)
                {
                    if (_state != BleConnectionState.Connecting &&
                        _state != BleConnectionState.GattConnected &&
                        _state != BleConnectionState.CharacteristicsReady &&
                        _state != BleConnectionState.Authenticating &&
                        _state != BleConnectionState.SessionReady &&
                        _state != BleConnectionState.Ready)
                        _state = BleConnectionState.Scanning;
                }
                _logger.Info("📡 BLE watcher listening.");
            }
            catch (COMException ex) when ((uint)ex.HResult == 0x800710DF)
            {
                _logger.Warning("⚠️ Bluetooth radio unavailable. Retrying in 5s.");
                Task.Delay(5000).ContinueWith(_ => { if (!_isStopping) StartScanning(); });
            }
            catch (Exception ex)
            {
                _logger.Error($"BLE scanner failed: {ex.Message}. Retrying in 5s.");
                Task.Delay(5000).ContinueWith(_ => { if (!_isStopping) StartScanning(); });
            }
        }
        finally
        {
            if (_scanLock.CurrentCount == 0) _scanLock.Release();
        }
    }

    public void RestartScanning()
    {
        lock (_lock)
        {
            if (_isStopping) return;
            if (_advWatcher != null)
            {
                try { _advWatcher.Stop(); } catch { }
                _advWatcher.Received -= OnDeviceAdvertised;
                _advWatcher = null;
            }
            if (_state == BleConnectionState.Scanning || _state == BleConnectionState.Disconnected)
                _state = BleConnectionState.Disconnected;
        }
        StartScanning();
    }

    // =====================================================================
    // Advertisement handler
    // =====================================================================
    private async void OnDeviceAdvertised(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        try
        {
            if (_isStopping) return;
            if (!args.Advertisement.ServiceUuids.Contains(SERVICE_UUID)) return;
            if (!IsProvisioned()) return;

            var session = _session;
            if (session?.Device != null && session.Device.BluetoothAddress == args.BluetoothAddress)
            {
                lock (_lock)
                {
                    session.LastRssiSampleUtc = DateTime.UtcNow;
                    session.RssiSamples.Enqueue(args.RawSignalStrengthInDBm);
                    while (session.RssiSamples.Count > SAMPLES_PER_AVERAGE) session.RssiSamples.Dequeue();
                    _firstAdvertReceived = true;
                }
                return;
            }

            if (session != null) return;

            if (!await _connectionSemaphore.WaitAsync(0)) return;
            try
            {
                lock (_lock)
                {
                    if (_session != null || _isStopping) return;
                }
                _logger.Info($"🎯 Intercepted matching Service UUID from {args.BluetoothAddress:X}");
                await ConnectToDeviceViaAddressAsync(args.BluetoothAddress);
            }
            finally { _connectionSemaphore.Release(); }
        }
        catch (Exception ex)
        {
            _logger.Error($"OnDeviceAdvertised failed: {ex.Message}");
        }
    }

    // =====================================================================
    // Long-write helper
    // =====================================================================
    /// <summary>
    /// Performs a BLE Long Write against the given characteristic by issuing
    /// successive ATT Write Requests at increasing offsets. Each chunk is
    /// bounded by the negotiated ATT MTU minus the 3-byte Write Request header.
    ///
    /// This replaces GattReliableWriteTransaction, whose CommitAsync() is known
    /// to never complete on certain Windows BT stack configurations (notably
    /// Realtek and older Intel adapters). The manual offset loop gives us
    /// explicit per-chunk timeouts and observability, and is functionally
    /// equivalent to the standard Long Write procedure.
    /// </summary>
    private async Task<GattCommunicationStatus> WriteLongAsync(
        GattCharacteristic characteristic,
        byte[] payload,
        TimeSpan perChunkTimeout,
        CancellationToken token)
    {
        if (payload.Length == 0) return GattCommunicationStatus.Success;

        int mtu = 23;
        try
        {
            var sess = _session?.GattSession;
            if (sess != null)
            {
                int m = sess.MaxPduSize;
                if (m > 0) mtu = m;
            }
        }
        catch { }

        // ATT Write Request consumes 3 bytes of the PDU (opcode + handle).
        int chunkSize = Math.Max(20, mtu - 3);
        int offset = 0;

        while (offset < payload.Length)
        {
            if (token.IsCancellationRequested) return GattCommunicationStatus.Unreachable;

            int len = Math.Min(chunkSize, payload.Length - offset);
            byte[] chunk = new byte[len];
            System.Buffer.BlockCopy(payload, offset, chunk, 0, len);

            using var writer = new DataWriter();
            writer.WriteBytes(chunk);

            var writeOp = characteristic.WriteValueWithResultAsync(
                writer.DetachBuffer(),
                GattWriteOption.WriteWithResponse).AsTask();

            var completed = await Task.WhenAny(writeOp, Task.Delay(perChunkTimeout, token));
            if (completed != writeOp)
            {
                _logger.Warning($"[BLE] Long-write chunk at offset {offset} timed out after {perChunkTimeout.TotalMilliseconds:F0} ms.");
                return GattCommunicationStatus.ProtocolError;
            }

            GattWriteResult result;
            try
            {
                result = await writeOp;
            }
            catch (Exception ex)
            {
                _logger.Warning($"[BLE] Long-write chunk at offset {offset} threw: {ex.Message}");
                return GattCommunicationStatus.ProtocolError;
            }

            if (result.Status != GattCommunicationStatus.Success)
            {
                _logger.Warning($"[BLE] Long-write chunk at offset {offset} returned {result.Status}.");
                return result.Status;
            }

            offset += len;
        }

        return GattCommunicationStatus.Success;
    }

    // =====================================================================
    // Connection pipeline
    // =====================================================================
    private async Task ConnectToDeviceViaAddressAsync(ulong bluetoothAddress)
    {
        const int maxAttempts = 5;
        int delayMs = 250;

        long generation;
        BleSession session;
        lock (_lock)
        {
            generation = ++_connectionGeneration;
            session = new BleSession { Generation = generation };
            _session = session;
            _state = BleConnectionState.Connecting;
        }

        bool reachedReady = false;

        try
        {
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                if (_isStopping) break;
                if (session.Generation != _connectionGeneration) return;

                lock (_lock) { _state = BleConnectionState.Connecting; }

                _logger.Info($"[BLE] Attempt {attempt}/{maxAttempts} → {bluetoothAddress:X}");

                try
                {
                    if (!IsProvisioned())
                    {
                        _logger.Warning("[BLE] Not provisioned; aborting connection attempts.");
                        break;
                    }

                    var device = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);
                    if (device == null)
                    {
                        _logger.Warning("[BLE] FromBluetoothAddressAsync returned null.");
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }

                    lock (_lock)
                    {
                        if (_isStopping || session.Generation != _connectionGeneration)
                        {
                            device.Dispose();
                            return;
                        }
                        session.Device = device;
                    }

                    TypedEventHandler<BluetoothLEDevice, object> handler =
                        (s, _) => OnConnectionStatusChangedForSession(session, s);
                    session.ConnectionStatusHandler = handler;
                    device.ConnectionStatusChanged += handler;

                    try
                    {
                        session.GattSession = await GattSession.FromDeviceIdAsync(device.BluetoothDeviceId);
                        session.GattSession.MaintainConnection = true;
                        device.RequestPreferredConnectionParameters(
                            BluetoothLEPreferredConnectionParameters.ThroughputOptimized);
                    }
                    catch (Exception ex)
                    {
                        _logger.Debug($"[BLE] Connection parameters unavailable: {ex.Message}");
                    }

                    _logger.Info("[BLE] GATT connected.");
                    TryTransition(session, BleConnectionState.GattConnected);

                    // ---------------------------------------------------------
                    // Service discovery
                    // ---------------------------------------------------------
                    GattDeviceServicesResult? servicesResult = null;
                    bool serviceFound = false;
                    for (int i = 1; i <= 3; i++)
                    {
                        try { servicesResult = await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached); }
                        catch { servicesResult = await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Cached); }
                        if (servicesResult?.Status == GattCommunicationStatus.Success && servicesResult.Services.Count > 0)
                        { serviceFound = true; break; }
                        await Task.Delay(200 * i);
                    }
                    if (!serviceFound)
                    {
                        _logger.Warning($"[BLE] Attempt {attempt}: service discovery failed (status={servicesResult?.Status}).");
                        await CleanupSessionAsync(session);
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }
                    session.Service = servicesResult!.Services.First();

                    // ---------------------------------------------------------
                    // Characteristic discovery
                    // ---------------------------------------------------------
                    GattCharacteristicsResult? charsResult = null;
                    bool charsFound = false;
                    for (int i = 1; i <= 3; i++)
                    {
                        try { charsResult = await session.Service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached); }
                        catch { charsResult = await session.Service.GetCharacteristicsAsync(BluetoothCacheMode.Cached); }
                        if (charsResult?.Status == GattCommunicationStatus.Success && charsResult.Characteristics.Count > 0)
                        { charsFound = true; break; }
                        await Task.Delay(200 * i);
                    }
                    if (!charsFound)
                    {
                        _logger.Warning($"[BLE] Attempt {attempt}: characteristic discovery failed (status={charsResult?.Status}).");
                        await CleanupSessionAsync(session);
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }

                    var chars = charsResult!.Characteristics;
                    session.ChallengeChar = chars.FirstOrDefault(c => c.Uuid == CHALLENGE_CHAR_UUID);
                    session.SignatureChar = chars.FirstOrDefault(c => c.Uuid == SIGNATURE_CHAR_UUID);
                    session.CommandChar = chars.FirstOrDefault(c => c.Uuid == COMMAND_CHAR_UUID);
                    session.PublicKeyChar = chars.FirstOrDefault(c => c.Uuid == PUBLIC_KEY_CHAR_UUID);
                    session.WindowsPublicKeyChar = chars.FirstOrDefault(c => c.Uuid == WINDOWS_PUBLIC_KEY_CHAR_UUID);
                    session.AuthChallengeChar = chars.FirstOrDefault(c => c.Uuid == AUTH_CHALLENGE_CHAR_UUID);
                    session.AuthSignatureChar = chars.FirstOrDefault(c => c.Uuid == AUTH_SIGNATURE_CHAR_UUID);

                    session.SecureModeSupported =
                        session.WindowsPublicKeyChar != null &&
                        session.AuthChallengeChar != null &&
                        session.AuthSignatureChar != null;

                    session.LegacyModeSupported =
                        session.SignatureChar != null;

                    _logger.Info($"[BLE] Characteristics discovered. SecureMode={session.SecureModeSupported} " +
                                 $"Legacy={session.LegacyModeSupported} " +
                                 $"Cmd={session.CommandChar != null} Ch={session.ChallengeChar != null} " +
                                 $"Sig={session.SignatureChar != null} Pub={session.PublicKeyChar != null}");

                    bool mandatoryPresent =
                        session.ChallengeChar != null &&
                        session.CommandChar != null &&
                        session.PublicKeyChar != null;

                    bool anyAuthPath = session.SecureModeSupported || session.LegacyModeSupported;

                    if (!mandatoryPresent || !anyAuthPath)
                    {
                        _logger.Warning($"[BLE] Attempt {attempt}: characteristics insufficient. " +
                                        $"Secure={session.SecureModeSupported} Legacy={session.LegacyModeSupported} " +
                                        $"Cmd={session.CommandChar != null} Ch={session.ChallengeChar != null} " +
                                        $"Sig={session.SignatureChar != null} Pub={session.PublicKeyChar != null}");
                        await CleanupSessionAsync(session);
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }

                    var trustedKey = _trustedPublicKey;
                    if (trustedKey == null)
                    {
                        _logger.Warning($"[BLE] Attempt {attempt}: no trusted key loaded.");
                        await CleanupSessionAsync(session);
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }

                    TryTransition(session, BleConnectionState.CharacteristicsReady);

                    // ---------------------------------------------------------
                    // Wire command notifications
                    // ---------------------------------------------------------
                    var commandChar = session.CommandChar!;
                    commandChar.ValueChanged += (s, e) => OnCommandReceivedForSession(session, s, e);
                    var cccdResult = await commandChar.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                        GattClientCharacteristicConfigurationDescriptorValue.Notify);
                    if (cccdResult.Status != GattCommunicationStatus.Success)
                    {
                        _logger.Warning($"[BLE] Attempt {attempt}: Command CCCD enable failed (status={cccdResult.Status}).");
                        await CleanupSessionAsync(session);
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }
                    _logger.Info("[BLE] Command notifications enabled.");

                    // ---------------------------------------------------------
                    // Encrypt and write the session key (manual BLE Long Write)
                    // ---------------------------------------------------------
                    byte[] generatedKey = new byte[32];
                    RandomNumberGenerator.Fill(generatedKey);

                    byte[] encryptedSessionKey;
                    using (var rsa = RSA.Create())
                    {
                        rsa.ImportSubjectPublicKeyInfo(trustedKey, out _);
                        // NOTE: SHA-1 OAEP retained for Android keystore compatibility.
                        // Must be upgraded to SHA-256 on both sides simultaneously.
                        encryptedSessionKey = rsa.Encrypt(generatedKey, RSAEncryptionPadding.OaepSHA1);
                    }

                    GattCommunicationStatus keyWriteStatus;
                    try
                    {
                        keyWriteStatus = await WriteLongAsync(
                            session.ChallengeChar!,
                            encryptedSessionKey,
                            perChunkTimeout: TimeSpan.FromSeconds(3),
                            token: session.Cts.Token);
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"[BLE] Attempt {attempt}: session key long-write threw: {ex.Message}");
                        keyWriteStatus = GattCommunicationStatus.ProtocolError;
                    }

                    if (keyWriteStatus != GattCommunicationStatus.Success)
                    {
                        CryptographicOperations.ZeroMemory(generatedKey);
                        _logger.Warning($"[BLE] Attempt {attempt}: session key write failed (status={keyWriteStatus}).");
                        await CleanupSessionAsync(session);
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }
                    session.SessionKey = generatedKey;
                    _logger.Info("[BLE] Session key delivered to phone.");

                    TryTransition(session, BleConnectionState.Authenticating);

                    // ---------------------------------------------------------
                    // Authentication
                    // ---------------------------------------------------------
                    bool authenticated = await AuthenticateSessionAsync(session, trustedKey);
                    if (!authenticated)
                    {
                        _logger.Warning($"[BLE] Attempt {attempt}: authentication failed.");
                        await CleanupSessionAsync(session);
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }
                    _logger.Info("[BLE] Peer authenticated.");

                    TryTransition(session, BleConnectionState.SessionReady);

                    lock (_lock)
                    {
                        if (_isStopping || session.Generation != _connectionGeneration)
                        {
                            _ = CleanupSessionAsync(session, finalTeardown: true);
                            return;
                        }
                        _firstAdvertReceived = false;
                    }

                    TryTransition(session, BleConnectionState.Ready);
                    reachedReady = true;

                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                    StartRssiMonitoring();
                    StartHealthCheck();
                    return;
                }
                catch (Exception ex)
                {
                    _logger.Error($"[BLE] Attempt {attempt}/{maxAttempts} threw: {ex.GetType().Name}: {ex.Message}");
                    await CleanupSessionAsync(session);
                    if (attempt == maxAttempts) break;
                    try { await Task.Delay(delayMs); } catch { return; }
                    delayMs *= 2;
                }
            }
        }
        finally
        {
            if (!reachedReady)
            {
                _logger.Warning("[BLE] All connection attempts exhausted. Scheduling rescan.");
                await HandleDisconnectionAsync(session);
            }
        }
    }

    // =====================================================================
    // Authentication
    // =====================================================================
    private async Task<bool> AuthenticateSessionAsync(BleSession session, byte[] trustedKey)
    {
        if (session.SecureModeSupported)
        {
            var authChallengeChar = session.AuthChallengeChar;
            var authSignatureChar = session.AuthSignatureChar;
            var challengeChar = session.ChallengeChar;

            if (authChallengeChar == null || authSignatureChar == null || challengeChar == null)
            {
                _logger.Warning("Secure mode marked supported but FFE3/FFE8/FFE9 missing on session.");
                return false;
            }

            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            session.SecureAuthTcs = tcs;

            authChallengeChar.ValueChanged += (s, e) => OnAuthChallengeReceivedForSession(session, s, e);
            await authChallengeChar.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                GattClientCharacteristicConfigurationDescriptorValue.Notify);

            await SendClientPublicKeyBytesRawAsync(session);
            await Task.Delay(100, session.Cts.Token);

            byte[] triggerNonce = new byte[16];
            RandomNumberGenerator.Fill(triggerNonce);
            using (var w = new DataWriter())
            {
                w.WriteBytes(triggerNonce);
                await challengeChar.WriteValueWithResultAsync(w.DetachBuffer(), GattWriteOption.WriteWithResponse);
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(session.Cts.Token);
            var completed = await Task.WhenAny(tcs.Task, Task.Delay(2500, timeoutCts.Token));
            if (completed == tcs.Task && await tcs.Task)
            {
                session.SecureAuthTcs = null;
                return true;
            }

            // Direct read fallback if notification was dropped.
            var readResult = await authChallengeChar.ReadValueAsync(BluetoothCacheMode.Uncached);
            if (readResult.Status == GattCommunicationStatus.Success && readResult.Value.Length > 0)
            {
                var reader = DataReader.FromBuffer(readResult.Value);
                byte[] nonce = new byte[reader.UnconsumedBufferLength];
                reader.ReadBytes(nonce);

                byte[] signature;
                lock (_lock)
                {
                    if (_clientRsa == null) { session.SecureAuthTcs = null; return false; }
                    signature = _clientRsa.SignData(nonce, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }

                using var sigWriter = new DataWriter();
                sigWriter.WriteBytes(signature);
                var sigResult = await authSignatureChar.WriteValueWithResultAsync(
                    sigWriter.DetachBuffer(), GattWriteOption.WriteWithResponse);

                if (sigResult.Status == GattCommunicationStatus.Success)
                {
                    var finalWait = await Task.WhenAny(tcs.Task, Task.Delay(2500));
                    if (finalWait == tcs.Task && await tcs.Task)
                    {
                        session.SecureAuthTcs = null;
                        return true;
                    }
                }
            }

            _logger.Warning("Secure channel verification failed; engaging legacy HMAC fallback.");
            session.SecureAuthTcs = null;

            if (session.SignatureChar == null)
            {
                _logger.Warning("Legacy HMAC fallback unavailable (FFE4 not exposed by peer). Auth failed closed.");
                return false;
            }
            return await AuthenticateDeviceViaChallengeAsync(session, CancellationToken.None);
        }

        if (session.SignatureChar == null)
        {
            _logger.Warning("No auth path available (secure and legacy both unavailable).");
            return false;
        }
        return await AuthenticateDeviceViaChallengeAsync(session, CancellationToken.None);
    }

    private async Task SendClientPublicKeyBytesRawAsync(BleSession session)
    {
        var pubKeyChar = session.WindowsPublicKeyChar;
        var pubKeyBytes = _clientPublicKeyBytes;
        if (pubKeyChar == null || pubKeyBytes == null) return;

        try
        {
            var status = await WriteLongAsync(
                pubKeyChar,
                pubKeyBytes,
                perChunkTimeout: TimeSpan.FromSeconds(3),
                token: session.Cts.Token);

            if (status != GattCommunicationStatus.Success)
            {
                _logger.Warning($"Client public key long-write failed: {status}");
                return;
            }
            _logger.Info("Client public key written to secure channel.");
        }
        catch (Exception ex)
        {
            _logger.Error($"Client public key write threw: {ex.Message}");
        }
    }

    private async void OnAuthChallengeReceivedForSession(BleSession session, GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        try
        {
            if (session != _session) return;
            if (session.Generation != _connectionGeneration) return;

            var reader = DataReader.FromBuffer(args.CharacteristicValue);
            byte[] nonce = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(nonce);

            byte[] signature;
            lock (_lock)
            {
                if (_clientRsa == null) return;
                signature = _clientRsa.SignData(nonce, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            var sigChar = session.AuthSignatureChar;
            if (sigChar == null) return;

            using var writer = new DataWriter();
            writer.WriteBytes(signature);
            var result = await sigChar.WriteValueWithResultAsync(
                writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
            if (result.Status != GattCommunicationStatus.Success)
            {
                _logger.Error($"Auth response rejected: {result.Status}");
                session.SecureAuthTcs?.TrySetResult(false);
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Auth challenge handling failed: {ex.Message}");
            session.SecureAuthTcs?.TrySetResult(false);
        }
    }

    private async Task<bool> AuthenticateDeviceViaChallengeAsync(BleSession session, CancellationToken token)
    {
        var challengeChar = session.ChallengeChar;
        var signatureChar = session.SignatureChar;
        var key = session.SessionKey;

        if (challengeChar == null || signatureChar == null || key == null || key.Length == 0)
            return false;

        try
        {
            byte[] nonce = new byte[16];
            RandomNumberGenerator.Fill(nonce);

            using (var w = new DataWriter())
            {
                w.WriteBytes(nonce);
                var wr = await challengeChar.WriteValueWithResultAsync(
                    w.DetachBuffer(), GattWriteOption.WriteWithResponse);
                if (wr.Status != GattCommunicationStatus.Success) return false;
            }

            byte[]? sig = null;
            foreach (var mode in new[] { BluetoothCacheMode.Uncached, BluetoothCacheMode.Cached })
            {
                try
                {
                    var rr = await signatureChar.ReadValueAsync(mode);
                    if (rr.Status != GattCommunicationStatus.Success) continue;
                    using var reader = DataReader.FromBuffer(rr.Value);
                    sig = new byte[reader.UnconsumedBufferLength];
                    reader.ReadBytes(sig);
                    break;
                }
                catch (ObjectDisposedException) { return false; }
                catch { }
            }

            if (sig == null || sig.Length == 0) return false;

            using var hmac = new HMACSHA256(key);
            var computed = hmac.ComputeHash(nonce);
            return CryptographicOperations.FixedTimeEquals(sig, computed);
        }
        catch (ObjectDisposedException) { return false; }
        catch (Exception ex)
        {
            _logger.Error($"Legacy HMAC verification error: {ex.Message}");
            return false;
        }
    }

    // =====================================================================
    // Inbound command handling — AEAD only, fail-closed
    // =====================================================================
    private void OnCommandReceivedForSession(BleSession session, GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        try
        {
            if (session != _session) return;
            if (session.Generation != _connectionGeneration) return;
            if (_state != BleConnectionState.Ready &&
                _state != BleConnectionState.SessionReady &&
                _state != BleConnectionState.Authenticating)
                return;

            var reader = DataReader.FromBuffer(args.CharacteristicValue);
            byte[] input = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(input);

            var key = session.SessionKey;
            if (key == null || key.Length != 32)
            {
                _logger.Warning("Rejected command: no active session key.");
                return;
            }

            if (input.Length < 12 + 1 + 16)
            {
                _logger.Warning("Rejected command: payload too short for AES-GCM.");
                return;
            }

            byte[] nonce = new byte[12];
            byte[] ciphertext = new byte[input.Length - 12 - 16];
            byte[] tag = new byte[16];
            System.Buffer.BlockCopy(input, 0, nonce, 0, 12);
            System.Buffer.BlockCopy(input, 12, ciphertext, 0, ciphertext.Length);
            System.Buffer.BlockCopy(input, 12 + ciphertext.Length, tag, 0, 16);

            byte[] plaintext = new byte[ciphertext.Length];
            try
            {
                using var aesGcm = new AesGcm(key, 16);
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            catch (CryptographicException)
            {
                _logger.Warning("Rejected command: AES-GCM authentication failed.");
                return;
            }

            string command = Encoding.UTF8.GetString(plaintext).Trim().ToLowerInvariant();
            CryptographicOperations.ZeroMemory(plaintext);

            _logger.Info($"📬 Command received: {command}");
            _ = Task.Run(() => ExecuteCommandAsync(command));
        }
        catch (Exception ex)
        {
            _logger.Error($"Command handling error: {ex.Message}");
        }
    }

    private async Task ExecuteCommandAsync(string command)
    {
        try
        {
            if (command != "reset_pending" && command != "auth_ok")
                await SendCommandConfirmationAsync(command);

            switch (command)
            {
                case "auth_ok":
                    _session?.SecureAuthTcs?.TrySetResult(true);
                    break;

                case "reset_pending":
                    lock (_lock) { _isPlannedResetActive = true; }
                    break;

                case "panic":
                case "lock_now":
                    await LockWorkstationAsync();
                    break;

                case "unlock":
                    if ((DateTime.Now - _lastUnlockTime).TotalMilliseconds < UNLOCK_COOLDOWN_MS)
                    {
                        _logger.Debug("Unlock cooldown active.");
                        break;
                    }
                    lock (_lock)
                    {
                        _isWorkstationLocked = false;
                        _lockedByProximity = false;
                        _firstAdvertReceived = false;
                    }
                    _lastUnlockTime = DateTime.Now;
                    _appEvent?.Set();
                    _screenEvent?.Set();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent
                    {
                        EventType = TetherEventType.OVERLAY_DISABLED,
                        Source = "BleManager",
                        PayloadJson = "{\"Action\":\"wake_and_unlock\"}"
                    });
                    break;

                case "screen_unlock":
                    _screenEvent?.Set();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_UNLOCKED, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent
                    {
                        EventType = TetherEventType.TRUST_RESTORED,
                        Source = "BleManager",
                        PayloadJson = "{\"Action\":\"wake_display\"}"
                    });
                    break;

                case "volume_up": await SendUiEventAsync(UiEvent("volume_up")); break;
                case "volume_down": await SendUiEventAsync(UiEvent("volume_down")); break;
                case "brightness_up": await SendUiEventAsync(UiEvent("brightness_up")); break;
                case "brightness_down": await SendUiEventAsync(UiEvent("brightness_down")); break;

                case "sleep":
                    await Task.Run(() => Process.Start(new ProcessStartInfo
                    {
                        FileName = "rundll32.exe",
                        Arguments = "powrprof.dll,SetSuspendState 0,1,0",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }));
                    break;

                case "reboot":
                    await Task.Run(() => Process.Start(new ProcessStartInfo
                    {
                        FileName = "shutdown",
                        Arguments = "/r /t 0",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }));
                    break;

                case "shutdown":
                    await Task.Run(() => Process.Start(new ProcessStartInfo
                    {
                        FileName = "shutdown",
                        Arguments = "/s /t 0",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }));
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Command execution error: {ex.Message}");
        }
    }

    private static TetherEvent UiEvent(string action) =>
        new()
        {
            EventType = TetherEventType.TRUST_RESTORED,
            Source = "BleManager",
            PayloadJson = $"{{\"Action\":\"{action}\"}}"
        };

    private async Task LockWorkstationAsync()
    {
        lock (_lock)
        {
            _isWorkstationLocked = true;
            _lockedByProximity = false;
        }
        ResetIPCHandles();
        _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
        await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.LOCK_WORKSTATION, Source = "BleManager" });

        IntPtr userToken = IntPtr.Zero;
        try
        {
            uint activeSessionId = WTSGetActiveConsoleSessionId();
            if (activeSessionId != 0xFFFFFFFF && WTSQueryUserToken(activeSessionId, out userToken))
            {
                var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"Winsta0\Default" };
                var cmd = new StringBuilder("rundll32.exe user32.dll,LockWorkStation");
                if (CreateProcessAsUser(userToken, null, cmd.ToString(), IntPtr.Zero, IntPtr.Zero,
                        false, 0, IntPtr.Zero, null, ref si, out var pi))
                {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
            }
        }
        catch { }
        finally
        {
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    private async Task SendCommandConfirmationAsync(string command)
    {
        var session = _session;
        if (session?.SessionKey == null || session.CommandChar == null) return;

        try
        {
            var plaintext = Encoding.UTF8.GetBytes($"confirm_{command}");
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using (var aesGcm = new AesGcm(session.SessionKey, 16))
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            byte[] payload = new byte[12 + ciphertext.Length + 16];
            System.Buffer.BlockCopy(nonce, 0, payload, 0, 12);
            System.Buffer.BlockCopy(ciphertext, 0, payload, 12, ciphertext.Length);
            System.Buffer.BlockCopy(tag, 0, payload, 12 + ciphertext.Length, 16);

            using var writer = new DataWriter();
            writer.WriteBytes(payload);
            var result = await session.CommandChar.WriteValueWithResultAsync(
                writer.DetachBuffer(), GattWriteOption.WriteWithResponse);

            if (result.Status != GattCommunicationStatus.Success)
                _logger.Warning($"Confirmation write failed: {result.Status}");
        }
        catch (Exception ex)
        {
            _logger.Error($"Confirmation frame failed: {ex.Message}");
        }
    }

    // =====================================================================
    // RSSI / proximity
    // =====================================================================
    private void StartRssiMonitoring()
    {
        _rssiTimer?.Dispose();
        _rssiTimer = new System.Threading.Timer(_ =>
        {
            try { SampleRssi(); }
            catch (Exception ex) { _logger.Error($"RSSI sample threw: {ex.Message}"); }
        }, null, 0, SAMPLE_INTERVAL_MS);
    }

    private void StopRssiMonitoring() => _rssiTimer?.Dispose();

    private void SampleRssi()
    {
        var session = _session;
        if (session == null) return;

        bool stopping, alreadyLocked, firstAdvert;
        lock (_lock)
        {
            stopping = _isStopping;
            alreadyLocked = _isWorkstationLocked;
            firstAdvert = _firstAdvertReceived;
        }
        if (stopping || alreadyLocked || !firstAdvert) return;

        double? avg = null;
        lock (_lock)
        {
            var age = DateTime.UtcNow - session.LastRssiSampleUtc;
            if (age <= RssiFreshness && session.RssiSamples.Count >= 2)
                avg = session.RssiSamples.Average();
        }
        if (avg == null) return;

        EvaluateProximity(avg.Value);
    }

    private void EvaluateProximity(double avgRssi)
    {
        bool isLockedLocal, lockedByProximityLocal;
        lock (_lock)
        {
            if (_isStopping) return;
            isLockedLocal = _isWorkstationLocked;
            lockedByProximityLocal = _lockedByProximity;
        }

        if (!isLockedLocal)
        {
            _ = SendUiEventAsync(new TetherEvent
            {
                EventType = TetherEventType.TRUST_DEGRADED,
                Source = "BleManager",
                PayloadJson = $"{{\"Rssi\":{avgRssi:F0}}}"
            });
        }

        if (isLockedLocal && lockedByProximityLocal && avgRssi >= RSSI_GOOD)
        {
            lock (_lock)
            {
                if (_isReauthenticating) return;
                _isReauthenticating = true;
            }
            try
            {
                _logger.Info($"Device returned within threshold: {avgRssi:F0} dBm. Re-authenticating.");
                var session = _session;
                if (session?.SessionKey == null) return;

                bool ok;
                if (session.SecureModeSupported)
                {
                    ok = AuthenticateSessionAsync(session, _trustedPublicKey!)
                        .GetAwaiter().GetResult();
                }
                else if (session.SignatureChar != null)
                {
                    ok = AuthenticateDeviceViaChallengeAsync(session, CancellationToken.None)
                        .GetAwaiter().GetResult();
                }
                else
                {
                    ok = false;
                }

                if (!ok) { _logger.Error("❌ Proximity re-auth failed."); return; }
                if ((DateTime.Now - _lastUnlockTime).TotalMilliseconds < UNLOCK_COOLDOWN_MS) return;

                lock (_lock)
                {
                    _isWorkstationLocked = false;
                    _lockedByProximity = false;
                    _firstAdvertReceived = false;
                }
                _lastUnlockTime = DateTime.Now;
                try { _appEvent?.Set(); } catch { }
                try { _screenEvent?.Set(); } catch { }
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
            }
            finally { lock (_lock) { _isReauthenticating = false; } }
            return;
        }

        if (!isLockedLocal && avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 Signal below lock threshold: {avgRssi:F0} dBm.");
            lock (_lock)
            {
                _isWorkstationLocked = true;
                _lockedByProximity = true;
            }
            ResetIPCHandles();
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        }
    }

    // =====================================================================
    // Connection status / cleanup / disconnection
    // =====================================================================
    private void OnConnectionStatusChangedForSession(BleSession session, BluetoothLEDevice sender)
    {
        if (sender.ConnectionStatus != BluetoothConnectionStatus.Disconnected) return;
        if (session != _session) return;

        bool logFirst;
        lock (_lock)
        {
            logFirst = !session.DisconnectLogged;
            session.DisconnectLogged = true;
        }
        if (logFirst) _logger.Warning("BLE connection dropped.");

        _ = HandleDisconnectionAsync(session);
    }

    private async Task CleanupSessionAsync(BleSession session, bool finalTeardown = false)
    {
        if (session.SessionKey != null)
        {
            CryptographicOperations.ZeroMemory(session.SessionKey);
            session.SessionKey = null;
        }
        session.SecureAuthTcs?.TrySetCanceled();
        session.SecureAuthTcs = null;

        var device = session.Device;
        if (device != null && session.ConnectionStatusHandler != null)
        {
            try { device.ConnectionStatusChanged -= session.ConnectionStatusHandler; } catch { }
        }
        session.ConnectionStatusHandler = null;

        try { session.Service?.Dispose(); } catch { }
        session.Service = null;

        try { device?.Dispose(); } catch { }
        session.Device = null;

        try
        {
            if (session.GattSession != null)
            {
                session.GattSession.MaintainConnection = false;
                session.GattSession.Dispose();
                session.GattSession = null;
            }
        }
        catch { }

        lock (_lock)
        {
            session.RssiSamples.Clear();
            if (_session == session) _firstAdvertReceived = false;
        }

        if (finalTeardown)
        {
            try { session.Cts.Cancel(); } catch { }
        }

        await Task.CompletedTask;
    }

    private async Task HandleDisconnectionAsync(BleSession session)
    {
        if (!await _disconnectSemaphore.WaitAsync(0)) return;
        try
        {
            if (session != _session) return;

            bool isPlannedReset;
            lock (_lock)
            {
                isPlannedReset = _isPlannedResetActive;
                _isPlannedResetActive = false;
                _session = null;
                _connectionGeneration++;
                if (!isPlannedReset) _isWorkstationLocked = true;
                _lockedByProximity = false;
                _state = BleConnectionState.Disconnected;
            }

            StopRssiMonitoring();
            StopHealthCheck();
            await CleanupSessionAsync(session, finalTeardown: true);

            if (_isStopping) return;

            if (isPlannedReset)
            {
                _logger.Info("🔄 Phone radio reset — restarting scan.");
                StartScanning();
                return;
            }

            ResetIPCHandles();
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });
            _logger.Error("🔒 LOCKING: Device disconnected unexpectedly.");
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });

            await Task.Delay(1000);
            if (!_isStopping) StartScanning();
        }
        finally { _disconnectSemaphore.Release(); }
    }

    // =====================================================================
    // Health check
    // =====================================================================
    private void StartHealthCheck()
    {
        lock (_lock)
        {
            _healthCheckTimer?.Change(TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30));
        }
    }

    private void StopHealthCheck()
    {
        lock (_lock)
        {
            _healthCheckTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        }
    }

    private void HealthCheckCallback()
    {
        BleSession? session;
        bool connected, stopping;
        lock (_lock)
        {
            session = _session;
            connected = _state == BleConnectionState.Ready || _state == BleConnectionState.SessionReady;
            stopping = _isStopping;
        }
        if (stopping) return;

        if (connected && session?.Device != null &&
            session.Device.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
        {
            _logger.Warning("Health check: device lost. Forcing disconnection handling.");
            _ = HandleDisconnectionAsync(session);
        }
    }

    public void Stop()
    {
        StopHealthCheck();
        lock (_lock)
        {
            _isStopping = true;
            _connectionGeneration++;
        }
        try { _cts?.Cancel(); } catch { }
        try { _advWatcher?.Stop(); } catch { }
        _advWatcher = null;

        var session = _session;
        if (session != null) _ = HandleDisconnectionAsync(session);
        StopRssiMonitoring();
    }

    public void Dispose() => Stop();

    // =====================================================================
    // UI / overlay / hardware
    // =====================================================================
    private void EnsureOverlayProcessRunning(TetherEvent evt)
    {
        if (evt.EventType != TetherEventType.OVERLAY_ENABLED) return;
        if (Process.GetProcessesByName("Tether.OverlayUI").Length > 0) return;

        IntPtr userToken = IntPtr.Zero;
        try
        {
            uint activeSessionId = WTSGetActiveConsoleSessionId();
            if (activeSessionId == 0xFFFFFFFF) return;
            if (!WTSQueryUserToken(activeSessionId, out userToken)) return;

            var si = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = @"Winsta0\Default"
            };
            string serviceDir = AppContext.BaseDirectory;
            string exePath = Path.Combine(serviceDir, "Tether.OverlayUI.exe");

            if (!File.Exists(exePath))
            {
                var current = new DirectoryInfo(serviceDir);
                while (current != null)
                {
                    var possible = Path.Combine(
                        current.FullName,
                        @"Tether.OverlayUI\bin\Release\net8.0-windows\win-x64\Tether.OverlayUI.exe");
                    if (File.Exists(possible)) { exePath = possible; break; }
                    current = current.Parent;
                }
            }

            if (CreateProcessAsUser(userToken, null, $"\"{exePath}\"",
                    IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, ref si, out var pi))
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        catch (Exception ex) { _logger.Error($"Overlay launch failed: {ex.Message}"); }
        finally { if (userToken != IntPtr.Zero) CloseHandle(userToken); }
    }

    private async Task SendUiEventAsync(TetherEvent evt)
    {
        EnsureOverlayProcessRunning(evt);
        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(evt);
            var bytes = Encoding.UTF8.GetBytes(json);
            using var client = new System.IO.Pipes.NamedPipeClientStream(
                ".", "TetherUiPipe", System.IO.Pipes.PipeDirection.Out);
            await client.ConnectAsync(1000);
            await client.WriteAsync(bytes, 0, bytes.Length);
            await client.FlushAsync();
        }
        catch (Exception ex) { _logger.Debug($"UI IPC failed: {ex.Message}"); }
    }

    public async Task UpdateHardwareLevelsOnPhoneAsync(byte volume, byte brightness)
    {
        var session = _session;
        if (session?.CommandChar == null) return;
        try
        {
            using var writer = new DataWriter();
            writer.WriteByte(0x01);
            writer.WriteByte(volume);
            writer.WriteByte(brightness);
            await session.CommandChar.WriteValueWithResultAsync(
                writer.DetachBuffer(), GattWriteOption.WriteWithoutResponse);
        }
        catch { }
    }
}