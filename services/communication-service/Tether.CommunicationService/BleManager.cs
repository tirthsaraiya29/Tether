using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
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
using Windows.Devices.Enumeration;
using Windows.Foundation;
using Windows.Storage.Streams;
using Windows.UI;

namespace Tether.CommunicationService;

public partial class BleManager : IDisposable
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private BluetoothLEAdvertisementWatcher? _advWatcher;
    private BluetoothLEDevice? _device;
    private System.Threading.Timer? _rssiTimer;
    private readonly List<int> _rssiSamples = new();
    private readonly object _lock = new();
    private readonly SemaphoreSlim _scanLock = new(1, 1);
    private bool _isScanning = false;

    private bool _isReauthenticating = false;
    private bool _isWorkstationLocked = false;
    private bool _isConnected = false;
    private bool _lockedByProximity = false;
    private bool _isStopping = false;
    private bool _isPlannedResetActive = false;
    private byte[]? _sessionKey;
    private bool _isProvisioned = false;
    private byte[]? _trustedPublicKey = null;

    private DateTime _lastUnlockTime = DateTime.MinValue;
    private const int UNLOCK_COOLDOWN_MS = 3000;

    private DateTime _lastSeenTime = DateTime.Now;
    private bool _firstAdvertReceived = false;

    private const int RSSI_GOOD = -65;
    private const int RSSI_LOCK = -78;
    private const int SAMPLE_INTERVAL_MS = 100;
    private const int SAMPLES_PER_AVERAGE = 3;

    private System.Threading.Timer? _healthCheckTimer;
    private readonly object _reconnectLock = new object();

#pragma warning disable CS0414
    private bool _reconnectPending = false;
#pragma warning restore CS0414

    private readonly Guid SERVICE_UUID = new Guid("0000FFE0-0000-1000-8000-00805F9B34FB");
    private readonly Guid CHALLENGE_CHAR_UUID = new Guid("0000FFE3-0000-1000-8000-00805F9B34FB");
    private readonly Guid SIGNATURE_CHAR_UUID = new Guid("0000FFE4-0000-1000-8000-00805F9B34FB");
    private readonly Guid COMMAND_CHAR_UUID = new Guid("0000FFE5-0000-1000-8000-00805F9B34FB");
    private readonly Guid PUBLIC_KEY_CHAR_UUID = new Guid("0000FFE6-0000-1000-8000-00805F9B34FB");

    private readonly Guid WINDOWS_PUBLIC_KEY_CHAR_UUID = new Guid("0000FFE7-0000-1000-8000-00805F9B34FB");
    private readonly Guid AUTH_CHALLENGE_CHAR_UUID = new Guid("0000FFE8-0000-1000-8000-00805F9B34FB");
    private readonly Guid AUTH_SIGNATURE_CHAR_UUID = new Guid("0000FFE9-0000-1000-8000-00805F9B34FB");

    private readonly SemaphoreSlim _connectionSemaphore = new SemaphoreSlim(1, 1);
    private CancellationTokenSource? _cts;

    private GattDeviceService? _service;
    private GattCharacteristic? _challengeChar;
    private GattCharacteristic? _signatureChar;
    private GattCharacteristic? _commandChar;
    private GattCharacteristic? _publicKeyChar;

    private GattCharacteristic? _windowsPublicKeyChar;
    private GattCharacteristic? _authChallengeChar;
    private GattCharacteristic? _authSignatureChar;
    private bool _secureModeSupported = false;
    private TaskCompletionSource<bool>? _secureAuthTcs;
    private GattSession? _gattSession;

    private RSA? _clientRsa;
    private byte[]? _clientPublicKeyBytes;

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    private const byte VK_VOLUME_UP = 0xAF;
    private const byte VK_VOLUME_DOWN = 0xAE;
    private const uint KEYEVENTF_KEYDOWN = 0x0000;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSDisconnectSession(IntPtr hServer, uint sessionId, bool bWait);

    [DllImport("gdi32.dll")]
    private static extern bool SetMonitorBrightness(IntPtr hMonitor, uint dwBrightness);

    [DllImport("gdi32.dll")]
    private static extern bool GetMonitorBrightness(IntPtr hMonitor, out uint pdwMinimumBrightness, out uint pdwCurrentBrightness, out uint pdwMaximumBrightness);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll")]
    private static extern bool GetPhysicalMonitorsFromHMONITOR(IntPtr hMonitor, uint dwPhysicalMonitorArraySize, [Out] PHYSICAL_MONITOR[] pPhysicalMonitorArray);

    [DllImport("user32.dll")]
    private static extern bool DestroyPhysicalMonitor(IntPtr hMonitor);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PHYSICAL_MONITOR
    {
        public IntPtr hPhysicalMonitor;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szPhysicalMonitorDescription;
        public uint dwPhysicalMonitorHandleCount;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

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

    private const uint MONITOR_DEFAULTTOPRIMARY = 0x00000001;

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;

        LoadTrustedKey();
        _healthCheckTimer = new System.Threading.Timer(HealthCheckCallback, null, Timeout.Infinite, Timeout.Infinite);

        _eventBus.Subscribe(evt => {
            if (evt.EventType == TetherEventType.PHONE_UNLOCKED || evt.EventType == TetherEventType.TRUST_RESTORED)
            {
                lock (_lock)
                {
                    if (_isWorkstationLocked)
                    {
                        _logger.Info("Trust context updated via global EventBus listener setup loop.");
                        _isWorkstationLocked = false;

                        _appEvent?.Set();
                        _screenEvent?.Set();
                    }
                }
            }
        });

        _eventBus.Subscribe(evt => {
            if (evt.EventType == TetherEventType.PROVISION_PHONE && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    var payload = System.Text.Json.JsonSerializer.Deserialize<ProvisionPayload>(evt.PayloadJson);
                    if (payload != null && !string.IsNullOrEmpty(payload.PublicKeyBase64))
                    {
                        ProvisionPhone(payload.PublicKeyBase64);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to process provisioning event: {ex.Message}");
                }
            }
        });
    }

    private void EnsureClientKeyPair()
    {
        try
        {
            const string legacyKeyName = @"SOFTWARE\Tether\CredentialProvider\ClientKey";
            const string productionKeyName = @"SOFTWARE\Tether\CredentialProvider\ClientKey_v2";

            using (var legacyKey = Registry.LocalMachine.OpenSubKey(legacyKeyName, true))
            {
                if (legacyKey != null)
                {
                    Registry.LocalMachine.DeleteSubKeyTree(legacyKeyName, false);
                    _logger.Info("Purged outdated legacy PKCS#1 registry artifacts.");
                }
            }

            using var key = Registry.LocalMachine.OpenSubKey(productionKeyName, true);
            if (key == null)
            {
                using var newKey = Registry.LocalMachine.CreateSubKey(productionKeyName);
                var rsa = RSA.Create(2048); // Do not wrap in using; instance must remain alive

                var privateKeyBlob = rsa.ExportRSAPrivateKey();
                var publicKeyBlob = rsa.ExportSubjectPublicKeyInfo();

                newKey.SetValue("PrivateKey", privateKeyBlob, RegistryValueKind.Binary);
                newKey.SetValue("PublicKey", publicKeyBlob, RegistryValueKind.Binary);

                _clientRsa = rsa;
                _clientPublicKeyBytes = publicKeyBlob;
                _logger.Info("Seamlessly committed production X.509 identity keys.");
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
            _logger.Error($"Self-healing key manager failed: {ex.Message}");
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
                    _logger.Info("Trusted phone public key loaded from registry.");
                }
                else
                {
                    _trustedPublicKey = null;
                    _logger.Info("No trusted phone key found; device is unprovisioned.");
                }
            }
            else
            {
                _isProvisioned = false;
                _trustedPublicKey = null;
                _logger.Info("CredentialProvider registry key missing; device is unprovisioned.");
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to load trusted key: {ex.Message}");
            _isProvisioned = false;
            _trustedPublicKey = null;
        }
    }

    private void MigrateOldKeys()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
            if (key != null)
            {
                var valueNames = key.GetValueNames().Where(n => n.StartsWith("Key_")).ToList();
                foreach (var name in valueNames)
                {
                    key.DeleteValue(name);
                    _logger.Info($"Removed legacy key: {name}");
                }
                key.SetValue("Provisioned", 0, RegistryValueKind.DWord);
                _logger.Info("Migration completed: old keys cleared, provisioned flag reset.");
            }
            LoadTrustedKey();
        }
        catch (Exception ex)
        {
            _logger.Error($"Migration failed: {ex.Message}");
        }
    }

    private bool IsProvisioned()
    {
        return _isProvisioned && _trustedPublicKey != null && _trustedPublicKey.Length >= 64;
    }

    private string? GetTrustedPublicKey()
    {
        if (_trustedPublicKey == null) return null;
        return Convert.ToBase64String(_trustedPublicKey);
    }

    public void ProvisionPhone(string base64PublicKey)
    {
        try
        {
            var keyBytes = Convert.FromBase64String(base64PublicKey);
            if (keyBytes.Length < 64)
            {
                _logger.Error("Provisioning failed: public key is too short.");
                return;
            }

            using var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider");
            key.SetValue("TrustedPhonePublicKey", base64PublicKey, RegistryValueKind.String);
            key.SetValue("Provisioned", 1, RegistryValueKind.DWord);
            _logger.Info("Phone provisioned with new trusted public key.");

            LoadTrustedKey();
            RestartScanning();
        }
        catch (Exception ex)
        {
            _logger.Error($"CNG Key Setup Provisioning failed: {ex.Message}");
        }
    }

    public void Start()
    {
        lock (_lock)
        {
            _isStopping = false;
        }

        EnsureClientKeyPair();
        MigrateOldKeys();

        if (!IsProvisioned())
        {
            _logger.Warning("No trusted phone provisioned. Waiting for provisioning via IPC.");
        }
        else
        {
            _logger.Info("Provisioned phone detected. Starting BLE scanning.");
        }

        StartScanning();
    }

    private void StartScanning()
    {
        if (!_scanLock.Wait(0))
            return;
        try
        {
            lock (_lock)
            {
                if (_isStopping) return;
                if (_isScanning) return;
                _isScanning = true;
            }

            if (_advWatcher != null)
            {
                try { _advWatcher.Stop(); } catch { }
                _advWatcher.Received -= OnDeviceAdvertised;
                _advWatcher = null;
            }

            _advWatcher = new BluetoothLEAdvertisementWatcher
            {
                ScanningMode = BluetoothLEScanningMode.Active
            };
            _advWatcher.Received += OnDeviceAdvertised;

            try
            {
                _advWatcher.Start();
                _logger.Info("📡 Unfiltered Software-Level BLE Watcher safely instantiated and listening.");
                lock (_lock) { _isScanning = false; }
            }
            catch (COMException ex) when ((uint)ex.HResult == 0x800710DF)
            {
                _logger.Warning("⚠️ Bluetooth radio is disabled or unavailable. Retrying in 5 seconds...");
                lock (_lock) { _isScanning = false; }
                Task.Delay(5000).ContinueWith(_ => StartScanning());
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to initialize BLE scanner: {ex.Message}. Retrying...");
                lock (_lock) { _isScanning = false; }
                Task.Delay(5000).ContinueWith(_ => StartScanning());
            }
        }
        finally
        {
            if (_scanLock.CurrentCount == 0)
                _scanLock.Release();
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
        }
        StartScanning();
    }

    private async void OnDeviceAdvertised(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        _logger.Debug($"BLE advert received from {args.BluetoothAddress:X}, UUIDs: {string.Join(",", args.Advertisement.ServiceUuids)}");

        if (_isStopping) return;

        if (!args.Advertisement.ServiceUuids.Contains(SERVICE_UUID))
            return;

        if (!IsProvisioned())
        {
            _logger.Warning("Ignoring advertisement: device not provisioned.");
            return;
        }

        if (_isConnected)
        {
            lock (_lock)
            {
                if (_device != null && _device.BluetoothAddress == args.BluetoothAddress)
                {
                    if (_device.ConnectionStatus == Windows.Devices.Bluetooth.BluetoothConnectionStatus.Connected)
                    {
                        _lastSeenTime = DateTime.Now;
                        _firstAdvertReceived = true;

                        int liveRssi = args.RawSignalStrengthInDBm;
                        _rssiSamples.Add(liveRssi);
                        if (_rssiSamples.Count > SAMPLES_PER_AVERAGE)
                        {
                            _rssiSamples.RemoveAt(0);
                        }

                        double avg = _rssiSamples.Average();
                        _logger.Info($"📊 Average RSSI (Live Stream): {avg:F0} dBm (samples: {_rssiSamples.Count})");
                        EvaluateProximity(avg);
                        return;
                    }

                    _logger.Warning("🎯 Received advertisement from connected device, but OS connection status is disconnected. Resetting session...");
                }
                else
                {
                    return;
                }
            }
            HandleDisconnection();
            return;
        }

        bool acquired = await _connectionSemaphore.WaitAsync(0);
        if (!acquired) return;

        try
        {
            lock (_lock)
            {
                if (_isConnected || _isStopping) return;
            }

            _logger.Info($"🎯 Intercepted matching Service UUID from address: {args.BluetoothAddress:X}");
            await ConnectToDeviceViaAddressAsync(args.BluetoothAddress);
        }
        finally
        {
            _connectionSemaphore.Release();
        }
    }

    private async Task ConnectToDeviceViaAddressAsync(ulong bluetoothAddress)
    {
        const int maxRetryAttempts = 5;
        int delayMs = 200;

        for (int attempt = 1; attempt <= maxRetryAttempts; attempt++)
        {
            CleanupDevice();
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            try
            {
                if (!IsProvisioned()) return;

                var device = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);
                if (device == null) return;

                lock (_lock)
                {
                    if (_isStopping)
                    {
                        device.Dispose();
                        return;
                    }
                    _device = device;
                    _device.ConnectionStatusChanged += OnConnectionStatusChanged;
                }

                try
                {
                    _gattSession = await GattSession.FromDeviceIdAsync(device.BluetoothDeviceId);
                    _gattSession.MaintainConnection = true;

                    // Request high-throughput / low-latency parameters on the device
                    device.RequestPreferredConnectionParameters(
                        BluetoothLEPreferredConnectionParameters.ThroughputOptimized);
                }
                catch { }

                GattDeviceServicesResult? servicesResult = null;
                bool serviceFound = false;
                for (int serviceAttempt = 1; serviceAttempt <= 3; serviceAttempt++)
                {
                    try
                    {
                        servicesResult = await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached);
                    }
                    catch
                    {
                        servicesResult = await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Cached);
                    }

                    if (servicesResult != null && servicesResult.Status == GattCommunicationStatus.Success && servicesResult.Services.Count > 0)
                    {
                        serviceFound = true;
                        break;
                    }
                    await Task.Delay(200 * serviceAttempt, token);
                }

                if (!serviceFound)
                {
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                lock (_lock) { _service = servicesResult!.Services.First(); }

                GattCharacteristicsResult? charsResult = null;
                bool charsFound = false;
                for (int charAttempt = 1; charAttempt <= 3; charAttempt++)
                {
                    try
                    {
                        charsResult = await _service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
                    }
                    catch
                    {
                        charsResult = await _service.GetCharacteristicsAsync(BluetoothCacheMode.Cached);
                    }

                    if (charsResult != null && charsResult.Status == GattCommunicationStatus.Success && charsResult.Characteristics.Count > 0)
                    {
                        charsFound = true;
                        break;
                    }
                    await Task.Delay(200 * charAttempt, token);
                }

                if (!charsFound)
                {
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                var characteristicsList = charsResult!.Characteristics;
                _challengeChar = characteristicsList.FirstOrDefault(c => c.Uuid == CHALLENGE_CHAR_UUID);
                _signatureChar = characteristicsList.FirstOrDefault(c => c.Uuid == SIGNATURE_CHAR_UUID);
                _commandChar = characteristicsList.FirstOrDefault(c => c.Uuid == COMMAND_CHAR_UUID);
                _publicKeyChar = characteristicsList.FirstOrDefault(c => c.Uuid == PUBLIC_KEY_CHAR_UUID);

                _windowsPublicKeyChar = characteristicsList.FirstOrDefault(c => c.Uuid == WINDOWS_PUBLIC_KEY_CHAR_UUID);
                _authChallengeChar = characteristicsList.FirstOrDefault(c => c.Uuid == AUTH_CHALLENGE_CHAR_UUID);
                _authSignatureChar = characteristicsList.FirstOrDefault(c => c.Uuid == AUTH_SIGNATURE_CHAR_UUID);
                _secureModeSupported = (_windowsPublicKeyChar != null && _authChallengeChar != null && _authSignatureChar != null);

                if (_challengeChar == null || _signatureChar == null || _commandChar == null || _publicKeyChar == null)
                {
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                var trustedKey = _trustedPublicKey;
                if (trustedKey == null)
                {
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                _commandChar!.ValueChanged -= OnCommandReceivedFromPhone;
                _commandChar.ValueChanged += OnCommandReceivedFromPhone;

                await _commandChar.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                    GattClientCharacteristicConfigurationDescriptorValue.Notify);

                byte[] generatedKey = new byte[32];
                RandomNumberGenerator.Fill(generatedKey);
                byte[] encryptedSessionKey;
                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(trustedKey, out _);
                    encryptedSessionKey = rsa.Encrypt(generatedKey, RSAEncryptionPadding.OaepSHA1);
                }

                using (var writer = new DataWriter())
                {
                    writer.WriteBytes(encryptedSessionKey);
                    var keyResult = await _challengeChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
                    if (keyResult.Status != GattCommunicationStatus.Success)
                    {
                        CleanupDevice();
                        if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                        await Task.Delay(delayMs, token);
                        delayMs *= 2;
                        continue;
                    }
                }

                lock (_lock) { _sessionKey = generatedKey; }

                bool isAuthenticated = false;

                if (_secureModeSupported)
                {
                    _secureAuthTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                    _authChallengeChar!.ValueChanged -= OnAuthChallengeReceived;
                    _authChallengeChar.ValueChanged += OnAuthChallengeReceived;

                    await _authChallengeChar.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                        GattClientCharacteristicConfigurationDescriptorValue.Notify);

                    // 1. Send client public key to phone first
                    await SendClientPublicKeyAsync(token);

                    // 2. Allow Android to register the public key in its dictionary
                    await Task.Delay(100, token);

                    // 3. Send trigger token to initiate challenge generation
                    byte[] triggerNonce = new byte[16];
                    RandomNumberGenerator.Fill(triggerNonce);
                    using (var writer = new DataWriter())
                    {
                        writer.WriteBytes(triggerNonce);
                        await _challengeChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
                    }

                    // 4. Wait for auth challenge notification with direct read fallback
                    using (var delayCts = CancellationTokenSource.CreateLinkedTokenSource(token))
                    {
                        var completedTask = await Task.WhenAny(_secureAuthTcs!.Task, Task.Delay(2500, delayCts.Token));
                        if (completedTask == _secureAuthTcs.Task && await _secureAuthTcs.Task)
                        {
                            isAuthenticated = true;
                        }
                        else if (!_secureAuthTcs.Task.IsCompleted)
                        {
                            // Direct read fallback if notification was dropped
                            var readResult = await _authChallengeChar.ReadValueAsync(BluetoothCacheMode.Uncached);
                            if (readResult.Status == GattCommunicationStatus.Success && readResult.Value.Length > 0)
                            {
                                var reader = DataReader.FromBuffer(readResult.Value);
                                byte[] nonce = new byte[reader.UnconsumedBufferLength];
                                reader.ReadBytes(nonce);

                                byte[] signature;
                                lock (_lock)
                                {
                                    signature = _clientRsa!.SignData(nonce, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                                }

                                using var sigWriter = new DataWriter();
                                sigWriter.WriteBytes(signature);
                                var sigResult = await _authSignatureChar!.WriteValueWithResultAsync(sigWriter.DetachBuffer(), GattWriteOption.WriteWithResponse);
                                if (sigResult.Status == GattCommunicationStatus.Success)
                                {
                                    var finalWait = await Task.WhenAny(_secureAuthTcs.Task, Task.Delay(2500, delayCts.Token));
                                    if (finalWait == _secureAuthTcs.Task && await _secureAuthTcs.Task)
                                    {
                                        isAuthenticated = true;
                                    }
                                }
                            }
                        }
                        delayCts.Cancel();
                    }

                    if (!isAuthenticated)
                    {
                        _logger.Warning("Secure channel verification deferred or timed out. Engaging adaptive Legacy HMAC fallback...");
                        isAuthenticated = await AuthenticateDeviceViaChallengeAsync(trustedKey, token);
                    }
                }
                else
                {
                    isAuthenticated = await AuthenticateDeviceViaChallengeAsync(trustedKey, token);
                }

                if (!isAuthenticated)
                {
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                lock (_lock)
                {
                    if (_isStopping)
                    {
                        CleanupDevice();
                        return;
                    }
                    _isConnected = true;
                    _firstAdvertReceived = false;
                    _lastSeenTime = DateTime.Now;
                }

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                StartRssiMonitoring();
                StartHealthCheck();
                return;
            }
            catch (Exception ex)
            {
                _logger.Error($"Connection attempt {attempt} failed: {ex.Message}");
            }

            CleanupDevice();

            if (attempt == maxRetryAttempts)
            {
                HandleDisconnection();
                return;
            }

            await Task.Delay(delayMs);
            delayMs *= 2;
        }
    }

    private async Task SendClientPublicKeyBytesRawAsync(CancellationToken token)
    {
        if (_clientPublicKeyBytes == null || _windowsPublicKeyChar == null) return;

        using (var writer = new DataWriter())
        {
            writer.WriteBytes(_clientPublicKeyBytes);
            await _windowsPublicKeyChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
        }
        _logger.Info("Raw client identity public verification key written to dedicated secure mapping channel.");
    }

    private async Task SendClientPublicKeyAsync(CancellationToken token)
    {
        await SendClientPublicKeyBytesRawAsync(token);
    }

    private async void OnAuthChallengeReceived(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        try
        {
            var reader = DataReader.FromBuffer(args.CharacteristicValue);
            byte[] nonce = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(nonce);

            byte[] signature;
            lock (_lock)
            {
                if (_clientRsa == null) return;
                signature = _clientRsa.SignData(nonce, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }

            GattCharacteristic? localAuthSignatureChar;
            lock (_lock)
            {
                localAuthSignatureChar = _authSignatureChar;
            }

            if (localAuthSignatureChar != null)
            {
                using var writer = new DataWriter();
                writer.WriteBytes(signature);
                var result = await localAuthSignatureChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
                if (result.Status == GattCommunicationStatus.Success)
                {
                    _logger.Info("Asymmetric hardware challenge token response transmitted successfully. Waiting for phone confirmation...");
                }
                else
                {
                    _logger.Error($"Asymmetric payload response signature rejected by host target service. Status: {result.Status}");
                    _secureAuthTcs?.TrySetResult(false);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Error responding to Secure Mode Auth Challenge: {ex.Message}");
            _secureAuthTcs?.TrySetResult(false);
        }
    }

    private async Task<GattDeviceServicesResult> TryGetGattServicesAsync(BluetoothLEDevice device, CancellationToken token)
    {
        try
        {
            return await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached);
        }
        catch
        {
            await Task.Delay(100, token);
            return await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Cached);
        }
    }

    private async Task<GattCharacteristicsResult> TryGetCharacteristicsAsync(GattDeviceService service, CancellationToken token)
    {
        try
        {
            return await service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
        }
        catch (COMException ex) when ((uint)ex.HResult == 0x8000FFFF || (uint)ex.HResult == 0x8007001F)
        {
            await Task.Delay(100, token);
            return await service.GetCharacteristicsAsync(BluetoothCacheMode.Cached);
        }
    }

    private async Task<byte[]?> ReadPublicKeyFromPhone(CancellationToken token)
    {
        GattCharacteristic? localPublicKeyChar;
        lock (_lock)
        {
            localPublicKeyChar = _publicKeyChar;
        }

        if (localPublicKeyChar == null)
        {
            _logger.Error("Public key characteristic is null.");
            return null;
        }

        var outputStream = new MemoryStream();
        uint currentOffset = 0;

        while (!token.IsCancellationRequested)
        {
            try
            {
                var readResult = await localPublicKeyChar.ReadValueAsync(BluetoothCacheMode.Uncached);
                if (readResult.Status != GattCommunicationStatus.Success)
                {
                    _logger.Warning($"Chunk read failed at offset {currentOffset}, status: {readResult.Status}");
                    return null;
                }

                using var reader = DataReader.FromBuffer(readResult.Value);
                byte[] chunkBytes = new byte[reader.UnconsumedBufferLength];
                if (chunkBytes.Length == 0)
                {
                    break;
                }

                reader.ReadBytes(chunkBytes);
                outputStream.Write(chunkBytes, 0, chunkBytes.Length);
                currentOffset += (uint)chunkBytes.Length;

                if (chunkBytes.Length == 0)
                {
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"Exception during public key sliding stream read: {ex.Message}");
                return null;
            }
        }

        var assembled = outputStream.ToArray();
        return assembled.Length >= 64 ? assembled : null;
    }

    private async Task<bool> AuthenticateDeviceViaChallengeAsync(byte[] phonePublicKeyBytes, CancellationToken token)
    {
        GattCharacteristic? localChallengeChar;
        GattCharacteristic? localSignatureChar;
        byte[]? currentKey;

        lock (_lock)
        {
            localChallengeChar = _challengeChar;
            localSignatureChar = _signatureChar;
            currentKey = _sessionKey;
        }

        if (localChallengeChar == null || localSignatureChar == null || phonePublicKeyBytes == null)
            return false;

        if (currentKey == null || currentKey.Length == 0)
        {
            _logger.Error("Crypto Intercept: Missing established symmetric session key.");
            return false;
        }

        try
        {
            byte[] challengeNonce = new byte[16];
            RandomNumberGenerator.Fill(challengeNonce);

            using (var writer = new DataWriter())
            {
                writer.WriteBytes(challengeNonce);
                var writeResult = await localChallengeChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
                if (writeResult.Status != GattCommunicationStatus.Success)
                {
                    _logger.Error($"Failed writing challenge: {writeResult.Status}");
                    return false;
                }
            }

            byte[]? phoneSignature = null;
            foreach (var cacheMode in new[] { BluetoothCacheMode.Uncached, BluetoothCacheMode.Cached })
            {
                try
                {
                    var readResult = await localSignatureChar.ReadValueAsync(cacheMode);
                    if (readResult.Status != GattCommunicationStatus.Success)
                        continue;

                    using var reader = DataReader.FromBuffer(readResult.Value);
                    phoneSignature = new byte[reader.UnconsumedBufferLength];
                    reader.ReadBytes(phoneSignature);
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception) { }
            }

            if (phoneSignature == null || phoneSignature.Length == 0)
                return false;

            using (var hmac = new HMACSHA256(currentKey))
            {
                byte[] computedHash = hmac.ComputeHash(challengeNonce);
                return CryptographicOperations.FixedTimeEquals(phoneSignature, computedHash);
            }
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.Error($"Signature verification error: {ex.Message}");
            return false;
        }
    }

    private string? GetStoredPublicKey(string addressHex)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider");
            return key?.GetValue($"Key_{addressHex}") as string;
        }
        catch { return null; }
    }

    private void StorePublicKey(string addressHex, string base64Key)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider");
            if (key.GetValue($"Key_{addressHex}") == null)
            {
                key.SetValue($"Key_{addressHex}", base64Key);
                _logger.Info($"Master identity token pinned successfully for target node: {addressHex}");
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to store public key: {ex.Message}");
        }
    }

    private void OnCommandReceivedFromPhone(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        try
        {
            var reader = DataReader.FromBuffer(args.CharacteristicValue);
            byte[] inputBytes = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(inputBytes);

            string command;
            byte[]? localSessionKey;
            lock (_lock) { localSessionKey = _sessionKey; }

            if (localSessionKey != null && inputBytes.Length > 16)
            {
                try
                {
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = localSessionKey;
                        aes.Mode = CipherMode.CBC;
                        aes.Padding = PaddingMode.PKCS7;
                        byte[] iv = new byte[16];
                        Array.Copy(inputBytes, 0, iv, 0, 16);

                        using (var decryptor = aes.CreateDecryptor(aes.Key, iv))
                        using (var ms = new MemoryStream(inputBytes, 16, inputBytes.Length - 16))
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        using (var sr = new StreamReader(cs, Encoding.UTF8))
                        {
                            command = sr.ReadToEnd().Trim().ToLowerInvariant();
                        }
                    }
                }
                catch
                {
                    command = Encoding.UTF8.GetString(inputBytes).Trim().ToLowerInvariant();
                }
            }
            else
            {
                command = Encoding.UTF8.GetString(inputBytes).Trim().ToLowerInvariant();
            }

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
            {
                await SendCommandConfirmationAsync(command);
            }

            switch (command)
            {
                case "auth_ok":
                    _secureAuthTcs?.TrySetResult(true);
                    break;

                case "reset_pending":
                    lock (_lock) { _isPlannedResetActive = true; }
                    break;

                case "panic":
                case "lock_now":
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
                        if (activeSessionId != 0xFFFFFFFF)
                        {
                            if (WTSQueryUserToken(activeSessionId, out userToken))
                            {
                                var si = new STARTUPINFO();
                                si.cb = Marshal.SizeOf(si);
                                si.lpDesktop = @"Winsta0\Default";

                                StringBuilder cmd = new StringBuilder("rundll32.exe user32.dll,LockWorkStation");

                                bool success = CreateProcessAsUser(
                                    userToken,
                                    null,
                                    cmd.ToString(),
                                    IntPtr.Zero,
                                    IntPtr.Zero,
                                    false,
                                    0,
                                    IntPtr.Zero,
                                    null,
                                    ref si,
                                    out var pi);

                                if (success)
                                {
                                    CloseHandle(pi.hProcess);
                                    CloseHandle(pi.hThread);
                                }
                            }
                        }
                    }
                    catch
                    {
                    }
                    finally
                    {
                        if (userToken != IntPtr.Zero) CloseHandle(userToken);
                    }
                    break;

                case "unlock":
                    if ((DateTime.Now - _lastUnlockTime).TotalMilliseconds < UNLOCK_COOLDOWN_MS)
                    {
                        _logger.Debug("Unlock cooldown active, ignoring duplicate unlock.");
                        break;
                    }
                    lock (_lock)
                    {
                        _isWorkstationLocked = false;
                        _lockedByProximity = false;
                        _firstAdvertReceived = false;
                        _lastSeenTime = DateTime.Now;
                    }
                    _lastUnlockTime = DateTime.Now;
                    _appEvent?.Set();
                    _screenEvent?.Set();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager", PayloadJson = "{\"Action\":\"wake_and_unlock\"}" });
                    break;

                case "screen_unlock":
                    _screenEvent?.Set();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_UNLOCKED, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager", PayloadJson = "{\"Action\":\"wake_display\"}" });
                    break;

                case "volume_up":
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager", PayloadJson = "{\"Action\":\"volume_up\"}" });
                    break;
                case "volume_down":
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager", PayloadJson = "{\"Action\":\"volume_down\"}" });
                    break;
                case "brightness_up":
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager", PayloadJson = "{\"Action\":\"brightness_up\"}" });
                    break;
                case "brightness_down":
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager", PayloadJson = "{\"Action\":\"brightness_down\"}" });
                    break;

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
        catch
        {
        }
    }

    private async Task SendCommandConfirmationAsync(string command)
    {
        byte[]? sessionKey;
        GattCharacteristic? commandChar;

        lock (_lock)
        {
            sessionKey = _sessionKey;
            commandChar = _commandChar;
        }

        if (sessionKey == null || commandChar == null)
        {
            _logger.Warning($"Symmetric link uninitialized. Skipping confirmation framing transmission for execution context: {command}");
            return;
        }

        try
        {
            string plainText = $"confirm_{command}";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBuffer;

            using (var aes = Aes.Create())
            {
                aes.Key = sessionKey;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateIV();
                byte[] iv = aes.IV;

                using (var encryptor = aes.CreateEncryptor(aes.Key, iv))
                using (var ms = new MemoryStream())
                {
                    ms.Write(iv, 0, iv.Length);
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encryptedBuffer = ms.ToArray();
                }
            }

            using (var writer = new DataWriter())
            {
                writer.WriteBytes(encryptedBuffer);
                var result = await commandChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
                if (result.Status == GattCommunicationStatus.Success)
                {
                    _logger.Info($"Secure encrypted execution confirmation transmitted for payload: {command}");
                }
                else
                {
                    _logger.Error($"Failed transmitting command confirmation packet over BLE. Status: {result.Status}");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Error constructing secure confirmation frame: {ex.Message}");
        }
    }

    private void AdjustVolumeNative(int delta)
    {
        byte key = delta > 0 ? VK_VOLUME_UP : VK_VOLUME_DOWN;
        keybd_event(key, 0, KEYEVENTF_KEYDOWN, UIntPtr.Zero);
        keybd_event(key, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    private async Task AdjustBrightnessNativeAsync(int deltaPercent)
    {
        await Task.Run(() =>
        {
            try
            {
                IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
                if (hMonitor == IntPtr.Zero)
                    return;

                const uint physicalMonitorCount = 1;
                var monitors = new PHYSICAL_MONITOR[physicalMonitorCount];
                if (!GetPhysicalMonitorsFromHMONITOR(hMonitor, physicalMonitorCount, monitors))
                    return;

                IntPtr hPhysical = monitors[0].hPhysicalMonitor;
                if (hPhysical == IntPtr.Zero)
                    return;

                if (!GetMonitorBrightness(hPhysical, out uint min, out uint current, out uint max))
                {
                    DestroyPhysicalMonitor(hPhysical);
                    return;
                }

                float step = (max - min) / 100.0f;
                int newBrightness = (int)(current + (deltaPercent * step));
                newBrightness = Math.Clamp(newBrightness, (int)min, (int)max);

                SetMonitorBrightness(hPhysical, (uint)newBrightness);
                DestroyPhysicalMonitor(hPhysical);
            }
            catch (Exception ex)
            {
                _logger.Error($"Brightness adjustment error: {ex.Message}");
            }
        });
    }

    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        if (sender.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
        {
            lock (_lock)
            {
                if (_device != sender)
                {
                    _logger.Debug("Ignoring disconnection from stale device.");
                    return;
                }
            }
            _logger.Warning("BLE connection dropped.");
            HandleDisconnection();
        }
    }

    private async Task SampleRssi()
    {
        bool connected;
        bool stopping;
        bool alreadyLocked;
        bool firstAdvertReceived;
        DateTime lastSeen;

        lock (_lock)
        {
            connected = _isConnected;
            stopping = _isStopping;
            alreadyLocked = _isWorkstationLocked;
            lastSeen = _lastSeenTime;
            firstAdvertReceived = _firstAdvertReceived;
        }

        if (!connected || stopping || alreadyLocked)
            return;

        if (!firstAdvertReceived)
            return;

        double secondsSinceLastSeen = (DateTime.Now - lastSeen).TotalSeconds;

        if (secondsSinceLastSeen > 8.0)
        {
            _logger.Warning($"⚠️ Proximity Watchdog Timeout: No beacons captured for {secondsSinceLastSeen:F1} seconds. Triggering secure lock.");

            lock (_lock)
            {
                _rssiSamples.Clear();
                EvaluateProximity(RSSI_LOCK - 5);
            }
        }
        else
        {
            await Task.CompletedTask;
        }
    }

    private async void EvaluateProximity(double avgRssi)
    {
        bool isLockedLocal;
        bool lockedByProximityLocal;
        lock (_lock)
        {
            isLockedLocal = _isWorkstationLocked;
            lockedByProximityLocal = _lockedByProximity;
            if (_isStopping) return;
        }

        if (!isLockedLocal)
        {
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_DEGRADED, Source = "BleManager", PayloadJson = $"{{\"Rssi\":{avgRssi}}}" });
        }

        if (isLockedLocal && lockedByProximityLocal && avgRssi >= RSSI_GOOD)
        {
            lock (_lock)
            {
                if (_isReauthenticating)
                {
                    return;
                }
                _isReauthenticating = true;
            }

            _logger.Info($"Device returned within threshold: {avgRssi:F0} dBm. Re-authenticating...");

            try
            {
                string addressHex;
                lock (_lock)
                {
                    addressHex = _device?.BluetoothAddress.ToString("X") ?? "";
                }

                string? storedKey = GetStoredPublicKey(addressHex);
                byte[]? publicKeyBytes = null;

                if (!string.IsNullOrEmpty(storedKey))
                    publicKeyBytes = Convert.FromBase64String(storedKey);
                else if (_trustedPublicKey != null)
                    publicKeyBytes = _trustedPublicKey;
                else
                {
                    _logger.Error("No stored public key available for proximity recovery.");
                    return;
                }

                bool identityReverified = false;
                for (int retry = 0; retry < 3 && !identityReverified; retry++)
                {
                    if (_secureModeSupported)
                    {
                        TaskCompletionSource<bool> localTcs;
                        lock (_lock)
                        {
                            _secureAuthTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                            localTcs = _secureAuthTcs;
                        }

                        try
                        {
                            byte[] triggerNonce = new byte[16];
                            RandomNumberGenerator.Fill(triggerNonce);
                            using (var writer = new DataWriter())
                            {
                                writer.WriteBytes(triggerNonce);
                                var triggerResult = await _challengeChar!.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
                                if (triggerResult.Status == GattCommunicationStatus.Success)
                                {
                                    using (var timeoutCts = new CancellationTokenSource(3000))
                                    {
                                        var completedTask = await Task.WhenAny(localTcs.Task, Task.Delay(3000, timeoutCts.Token));
                                        if (completedTask == localTcs.Task)
                                        {
                                            identityReverified = await localTcs.Task;
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Error($"Secure proximity re-auth iteration failure: {ex.Message}");
                        }
                    }
                    else
                    {
                        identityReverified = await AuthenticateDeviceViaChallengeAsync(publicKeyBytes, CancellationToken.None);
                    }

                    if (!identityReverified && retry < 2)
                    {
                        _logger.Warning($"Re-auth attempt {retry + 1} failed, retrying...");
                        await Task.Delay(500);
                    }
                }

                if (identityReverified)
                {
                    if ((DateTime.Now - _lastUnlockTime).TotalMilliseconds < UNLOCK_COOLDOWN_MS)
                    {
                        _logger.Debug("Unlock cooldown active, skipping unlock.");
                        return;
                    }
                    _logger.Info("✅ Proximity re-authentication passed. Unlocking.");
                    lock (_lock)
                    {
                        _isWorkstationLocked = false;
                        _lockedByProximity = false;
                        _firstAdvertReceived = false;
                        _lastSeenTime = DateTime.Now;
                    }
                    _lastUnlockTime = DateTime.Now;

                    try { _appEvent?.Set(); } catch { }
                    try { _screenEvent?.Set(); } catch { }

                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                    _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
                }
                else
                {
                    _logger.Error("❌ Re-authentication failed after retries.");
                }
            }
            finally
            {
                lock (_lock)
                {
                    _isReauthenticating = false;
                }
            }
            return;
        }

        if (!isLockedLocal && avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 Signal below lock threshold: {avgRssi:F0} dBm. Locking.");
            lock (_lock) { _isWorkstationLocked = true; _lockedByProximity = true; }

            ResetIPCHandles();
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        }
    }

    private void HandleDisconnection()
    {
        bool wasConnected;
        bool isPlannedReset;

        lock (_lock)
        {
            wasConnected = _isConnected;
            _isConnected = false;
            isPlannedReset = _isPlannedResetActive;
            _sessionKey = null;

            if (!isPlannedReset)
                _isWorkstationLocked = true;
            _lockedByProximity = false;
            _isPlannedResetActive = false;
        }

        StopRssiMonitoring();
        StopHealthCheck();
        _cts?.Cancel();

        if (_isStopping)
        {
            CleanupDevice();
            return;
        }

        if (isPlannedReset)
        {
            _logger.Info("🔄 Connection dropped via expected phone radio reset loop. Restarting scanning.");
            CleanupDevice();
            StartScanning();
            return;
        }

        ResetIPCHandles();
        _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });
        _logger.Error("🔒 LOCKING: Device disconnected unexpectedly.");
        _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });

        CleanupDevice();

        Task.Delay(1000).ContinueWith(_ => StartScanning());
    }

    private void CleanupDevice()
    {
        lock (_lock)
        {
            _firstAdvertReceived = false;
            _rssiSamples.Clear();

            if (_authChallengeChar != null)
            {
                _authChallengeChar.ValueChanged -= OnAuthChallengeReceived;
                _authChallengeChar = null;
            }
            if (_commandChar != null)
            {
                _commandChar.ValueChanged -= OnCommandReceivedFromPhone;
                _commandChar = null;
            }

            _challengeChar = null;
            _signatureChar = null;
            _publicKeyChar = null;
            _windowsPublicKeyChar = null;
            _authSignatureChar = null;

            _service?.Dispose();
            _service = null;

            if (_device != null)
            {
                _device.ConnectionStatusChanged -= OnConnectionStatusChanged;
                _device.Dispose();
                _device = null;
            }

            if (_gattSession != null)
            {
                _gattSession.MaintainConnection = false;
                _gattSession.Dispose();
                _gattSession = null;
            }

            _secureAuthTcs?.TrySetCanceled();
            _secureAuthTcs = null;
        }
    }

    private void StartRssiMonitoring()
    {
        _logger.Info("📶 Starting RSSI monitoring timer.");
        _rssiTimer?.Dispose();
        _rssiTimer = new System.Threading.Timer(async _ => await SampleRssi(), null, 0, SAMPLE_INTERVAL_MS);
    }

    private void StopRssiMonitoring() => _rssiTimer?.Dispose();

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

    private async void HealthCheckCallback(object? state)
    {
        bool connected;
        bool stopping;
        BluetoothLEDevice? device;
        lock (_lock)
        {
            connected = _isConnected;
            stopping = _isStopping;
            device = _device;
        }

        if (stopping) return;

        if (connected && (device == null || device.ConnectionStatus == BluetoothConnectionStatus.Disconnected))
        {
            _logger.Warning("Health check: device lost while connection flag was true. Forcing disconnection handling.");
            HandleDisconnection();
            return;
        }

        if (!connected && device == null) return;

        if (!connected && device != null)
        {
            _logger.Warning("Health check: device reference exists but not connected; cleaning up.");
            CleanupDevice();
            StartScanning();
        }
    }

    public void Stop()
    {
        StopHealthCheck();
        lock (_lock) { _isStopping = true; }
        _cts?.Cancel();
        _advWatcher?.Stop();
        _advWatcher = null;
        CleanupDevice();
        StopRssiMonitoring();
    }

    public void Dispose() => Stop();

    private void EnsureOverlayProcessRunning(TetherEvent evt)
    {
        if (evt.EventType != TetherEventType.OVERLAY_ENABLED)
            return;

        var processes = Process.GetProcessesByName("Tether.OverlayUI");
        if (processes.Length > 0) return;

        IntPtr userToken = IntPtr.Zero;
        try
        {
            uint activeSessionId = WTSGetActiveConsoleSessionId();
            if (activeSessionId == 0xFFFFFFFF) return;

            if (WTSQueryUserToken(activeSessionId, out userToken))
            {
                var si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = @"Winsta0\Default";

                string serviceDir = Path.GetDirectoryName(Assembly.GetEntryAssembly()!.Location)!;
                string exePath = Path.Combine(serviceDir, "Tether.OverlayUI.exe");

                if (!File.Exists(exePath))
                {
                    DirectoryInfo? current = new DirectoryInfo(serviceDir);
                    while (current != null)
                    {
                        string possibleUiPath = Path.Combine(current.FullName, @"Tether.OverlayUI\bin\Release\net8.0-windows\win-x64\Tether.OverlayUI.exe");
                        if (File.Exists(possibleUiPath))
                        {
                            exePath = possibleUiPath;
                            break;
                        }
                        current = current.Parent;
                    }
                }

                string exactPath = $"\"{exePath}\"";
                _logger.Info($"Spawning OverlayUI in interactive user session: {activeSessionId}. Validated Path: {exePath}");

                bool success = CreateProcessAsUser(
                    userToken,
                    null,
                    exactPath,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    0,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out var pi);

                if (success)
                {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    _logger.Info("Overlay UI launched successfully within active interactive context loop.");
                }
                else
                {
                    _logger.Error($"Failed to launch UI process via user token. Win32 Error: {Marshal.GetLastWin32Error()}");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to spin up UI space execution layer in user space: {ex.Message}");
        }
        finally
        {
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    private async Task SendUiEventAsync(TetherEvent evt)
    {
        EnsureOverlayProcessRunning(evt);

        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(evt);
            var bytes = Encoding.UTF8.GetBytes(json);

            using var client = new System.IO.Pipes.NamedPipeClientStream(".", "TetherUiPipe", System.IO.Pipes.PipeDirection.Out);

            await client.ConnectAsync(1000);
            await client.WriteAsync(bytes, 0, bytes.Length);
            await client.FlushAsync();
        }
        catch (Exception ex)
        {
            _logger.Debug($"IPC UI Proximity pipeline transmission failed: {ex.Message}");
        }
    }

    public async Task UpdateHardwareLevelsOnPhoneAsync(byte volume, byte brightness)
    {
        GattCharacteristic? localCommandChar;
        lock (_lock) { localCommandChar = _commandChar; }
        if (localCommandChar == null) return;

        try
        {
            using (var writer = new DataWriter())
            {
                writer.WriteByte(0x01);
                writer.WriteByte(volume);
                writer.WriteByte(brightness);
                await localCommandChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithoutResponse);
            }
        }
        catch { }
    }
}