using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Enumeration;
using Windows.Foundation;
using Windows.Storage.Streams;
using Tether.Shared.DTO;

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
    private readonly SemaphoreSlim _scanLock = new(1, 1);   // For StartScanning concurrency
    private bool _isScanning = false;

    private bool _isWorkstationLocked = false;
    private bool _isConnected = false;
    private bool _lockedByProximity = false;
    private bool _isStopping = false;
    private bool _isPlannedResetActive = false;
    private byte[]? _sessionKey;
    private bool _isProvisioned = false;
    private byte[]? _trustedPublicKey = null;

    private const int RSSI_GOOD = -55;
    private const int RSSI_LOCK = -75;
    private const int SAMPLE_INTERVAL_MS = 500;
    private const int SAMPLES_PER_AVERAGE = 10;            // Increased from 5 for better smoothing

    private readonly Guid SERVICE_UUID = new Guid("0000FFE0-0000-1000-8000-00805F9B34FB");
    private readonly Guid CHALLENGE_CHAR_UUID = new Guid("0000FFE3-0000-1000-8000-00805F9B34FB");
    private readonly Guid SIGNATURE_CHAR_UUID = new Guid("0000FFE4-0000-1000-8000-00805F9B34FB");
    private readonly Guid COMMAND_CHAR_UUID = new Guid("0000FFE5-0000-1000-8000-00805F9B34FB");
    private readonly Guid PUBLIC_KEY_CHAR_UUID = new Guid("0000FFE6-0000-1000-8000-00805F9B34FB");

    private readonly SemaphoreSlim _connectionSemaphore = new SemaphoreSlim(1, 1);
    private CancellationTokenSource? _cts;                  // Cancellation for ongoing GATT operations

    private GattDeviceService? _service;
    private GattCharacteristic? _challengeChar;
    private GattCharacteristic? _signatureChar;
    private GattCharacteristic? _commandChar;
    private GattCharacteristic? _publicKeyChar;

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
        string lpCommandLine,
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

            // Force a fresh BLE scan to discover the newly provisioned phone
            RestartScanning();
        }
        catch (Exception ex)
        {
            _logger.Error($"Provisioning failed: {ex.Message}");
        }
    }

    public void Start()
    {
        lock (_lock)
        {
            _isStopping = false;
        }

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
        // Prevent concurrent scan start/stop races
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

            // Strict Teardown
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
            // Release the lock if we haven't already set _isScanning false inside the try
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

        if (_isConnected) return;
        if (_isStopping) return;

        if (!args.Advertisement.ServiceUuids.Contains(SERVICE_UUID))
            return;

        if (!IsProvisioned())
        {
            _logger.Warning("Ignoring advertisement: device not provisioned.");
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
                if (!IsProvisioned())
                {
                    _logger.Warning("Device unprovisioned; rejecting connection attempt.");
                    return;
                }

                var device = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);
                if (device == null)
                {
                    _logger.Error("Device instance returned null from address mapping.");
                    return;
                }

                var accessStatus = await device.RequestAccessAsync();
                if (accessStatus != DeviceAccessStatus.Allowed)
                {
                    _logger.Error($"Access denied by Windows: {accessStatus}");
                    device.Dispose();
                    return;
                }

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

                _logger.Info($"BLE device transport link connected (Attempt {attempt}/{maxRetryAttempts}). Settling radio context...");

                try
                {
                    var gattSession = await GattSession.FromDeviceIdAsync(device.BluetoothDeviceId);
                    gattSession.MaintainConnection = true;
                    _logger.Info($"GattSession max PDU size: {gattSession.MaxPduSize} bytes.");
                }
                catch (Exception ex)
                {
                    _logger.Warning($"GattSession optimization skipped: {ex.Message}");
                }

                GattCommunicationStatus serviceStatus = GattCommunicationStatus.Unreachable;
                GattDeviceServicesResult? servicesResult = null;

                try
                {
                    servicesResult = await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Cached);
                    serviceStatus = servicesResult.Status;
                }
                catch
                {
                    servicesResult = await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached);
                    serviceStatus = servicesResult?.Status ?? GattCommunicationStatus.Unreachable;
                }

                if (servicesResult == null || serviceStatus != GattCommunicationStatus.Success || servicesResult.Services.Count == 0)
                {
                    servicesResult = await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached);
                    serviceStatus = servicesResult?.Status ?? GattCommunicationStatus.Unreachable;
                }

                if (servicesResult == null || serviceStatus != GattCommunicationStatus.Success || servicesResult.Services.Count == 0)
                {
                    _logger.Error($"Failed to resolve GATT service: status={serviceStatus}");
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                lock (_lock) { _service = servicesResult.Services.First(); }

                GattCommunicationStatus charStatus = GattCommunicationStatus.Unreachable;
                GattCharacteristicsResult? charsResult = null;

                try
                {
                    charsResult = await _service.GetCharacteristicsAsync(BluetoothCacheMode.Cached);
                    charStatus = charsResult.Status;
                }
                catch
                {
                    charsResult = await _service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
                    charStatus = charsResult?.Status ?? GattCommunicationStatus.Unreachable;
                }

                if (charsResult == null || charStatus != GattCommunicationStatus.Success || charsResult.Characteristics.Count == 0)
                {
                    charsResult = await _service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
                    charStatus = charsResult?.Status ?? GattCommunicationStatus.Unreachable;
                }

                if (charsResult == null || charStatus != GattCommunicationStatus.Success || charsResult.Characteristics.Count == 0)
                {
                    _logger.Error($"Failed to map characteristics: {charStatus}");
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                var characteristicsList = charsResult.Characteristics;
                _challengeChar = characteristicsList.FirstOrDefault(c => c.Uuid == CHALLENGE_CHAR_UUID);
                _signatureChar = characteristicsList.FirstOrDefault(c => c.Uuid == SIGNATURE_CHAR_UUID);
                _commandChar = characteristicsList.FirstOrDefault(c => c.Uuid == COMMAND_CHAR_UUID);
                _publicKeyChar = characteristicsList.FirstOrDefault(c => c.Uuid == PUBLIC_KEY_CHAR_UUID);

                if (_challengeChar == null || _signatureChar == null || _commandChar == null || _publicKeyChar == null)
                {
                    _logger.Error("Failed to discover all required characteristics.");
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                var trustedKey = _trustedPublicKey;
                if (trustedKey == null)
                {
                    _logger.Error("Trusted key is null; cannot proceed.");
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

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
                        _logger.Error($"Session key write failed: {keyResult.Status}");
                        CleanupDevice();
                        if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                        await Task.Delay(delayMs, token);
                        delayMs *= 2;
                        continue;
                    }
                }

                lock (_lock) { _sessionKey = generatedKey; }

                bool isAuthenticated = await AuthenticateDeviceViaChallengeAsync(trustedKey, token);
                if (!isAuthenticated)
                {
                    _logger.Error("CRYPTOGRAPHIC CHALLENGE REJECTED.");
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                _commandChar.ValueChanged -= OnCommandReceivedFromPhone;
                _commandChar.ValueChanged += OnCommandReceivedFromPhone;

                bool subscriptionOk = false;
                for (int subAttempt = 1; subAttempt <= 3 && !subscriptionOk; subAttempt++)
                {
                    var cccdResult = await _commandChar.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                        GattClientCharacteristicConfigurationDescriptorValue.Notify);
                    if (cccdResult.Status == GattCommunicationStatus.Success)
                    {
                        subscriptionOk = true;
                        break;
                    }
                    _logger.Warning($"Failed to configure GATT notifications (attempt {subAttempt}/3). Status: {cccdResult.Status}");
                    await Task.Delay(100 * subAttempt, token);
                }

                if (!subscriptionOk)
                {
                    CleanupDevice();
                    if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                    await Task.Delay(delayMs, token);
                    delayMs *= 2;
                    continue;
                }

                _logger.Info("Control pipeline stream initialized. Status code: Success");
                _logger.Info("CRYPTOGRAPHIC TETHER PIPELINE FULLY ENFORCED.");

                lock (_lock)
                {
                    if (_isStopping)
                    {
                        CleanupDevice();
                        return;
                    }
                    _isConnected = true;
                }

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                StartRssiMonitoring();
                return;
            }
            catch (TaskCanceledException ex)
            {
                _logger.Warning($"GATT negotiation canceled (attempt {attempt}): {ex.Message}");
            }
            catch (OperationCanceledException)
            {
                _logger.Warning($"Connection attempt {attempt} cancelled.");
                CleanupDevice();
                if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                continue;
            }
            catch (COMException ex)
            {
                _logger.Error($"Windows WinRT COM Error [0x{ex.HResult:X8}]: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.Error($"General GATT setup exception: {ex.GetType().Name} - {ex.Message}");
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

                if (chunkBytes.Length < 22)
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
            string command = Encoding.UTF8.GetString(inputBytes).Trim().ToLowerInvariant();

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
            _logger.Info($"📬 Intercepted Mobile Telemetry Payload: {command}");

            switch (command)
            {
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
                    _logger.Error($"🚨 Manual lock triggered: {command}");
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

                                string cmd = "rundll32.exe user32.dll,LockWorkStation";

                                bool success = CreateProcessAsUser(
                                    userToken,
                                    null,
                                    cmd,
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
                                    _logger.Info("Workstation lock pipeline routed seamlessly via user session context.");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Error($"Failed to execute cross-session lock proxy: {ex.Message}");
                    }
                    finally
                    {
                        if (userToken != IntPtr.Zero) CloseHandle(userToken);
                    }
                    break;

                case "unlock":
                    lock (_lock) { _isWorkstationLocked = false; _lockedByProximity = false; }
                    _logger.Info("🔓 Manual unlock override");
                    _appEvent?.Set();
                    _screenEvent?.Set();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager", PayloadJson = "{\"Action\":\"wake_and_unlock\"}" });
                    break;

                case "screen_unlock":
                    _logger.Info("📱 Phone screen unlock detected.");
                    _screenEvent?.Set();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_UNLOCKED, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager", PayloadJson = "{\"Action\":\"wake_display\"}" });
                    break;

                case "volume_up":
                    AdjustVolumeNative(1);
                    break;
                case "volume_down":
                    AdjustVolumeNative(-1);
                    break;
                case "brightness_up":
                    await AdjustBrightnessNativeAsync(5);
                    break;
                case "brightness_down":
                    await AdjustBrightnessNativeAsync(-5);
                    break;

                case "sleep":
                    _logger.Info("💤 Executing sleep...");
                    await Task.Run(() => Process.Start(new ProcessStartInfo
                    {
                        FileName = "rundll32.exe",
                        Arguments = "powrprof.dll,SetSuspendState 0,1,0",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }));
                    break;

                case "reboot":
                    _logger.Info("🔄 Executing reboot... ");
                    await Task.Run(() => Process.Start(new ProcessStartInfo
                    {
                        FileName = "shutdown",
                        Arguments = "/r /t 0",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }));
                    break;

                case "shutdown":
                    _logger.Info("⏻ Executing shutdown...");
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
                // Ignore if this is not the current device (stale event from a previous connection)
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
        BluetoothLEDevice? device;
        bool connected;
        bool stopping;

        lock (_lock)
        {
            device = _device;
            connected = _isConnected;
            stopping = _isStopping;
        }

        if (device == null || !connected || stopping)
            return;

        try
        {
            var info = await DeviceInformation.CreateFromIdAsync(
                device.DeviceId,
                new[] { "System.Devices.Aep.SignalStrength" },
                DeviceInformationKind.AssociationEndpoint);

            if (info.Properties.TryGetValue("System.Devices.Aep.SignalStrength", out object? rssi))
            {
                lock (_lock)
                {
                    _rssiSamples.Add(Convert.ToInt32(rssi));
                    if (_rssiSamples.Count >= SAMPLES_PER_AVERAGE)
                    {
                        double avg = _rssiSamples.Average();
                        _rssiSamples.Clear();
                        EvaluateProximity(avg);
                    }
                }
            }
        }
        catch { }
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
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_DEGRADED, Source = "BleManager", PayloadJson = $"{{\"\":{avgRssi}}}" });
        }

        if (isLockedLocal && lockedByProximityLocal && avgRssi >= RSSI_GOOD)
        {
            _logger.Info($"Device returned within threshold parameters: {avgRssi:F0} dBm. Prompting Challenge Verification...");

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

            // Retry authentication up to 3 times with short delay
            bool identityReverified = false;
            for (int retry = 0; retry < 3 && !identityReverified; retry++)
            {
                identityReverified = await AuthenticateDeviceViaChallengeAsync(publicKeyBytes, CancellationToken.None);
                if (!identityReverified && retry < 2)
                {
                    _logger.Warning($"Re-authentication attempt {retry + 1} failed, retrying...");
                    await Task.Delay(500);
                }
            }

            if (identityReverified)
            {
                _logger.Info("✅ Proximity Re-authentication passed successfully.");
                lock (_lock) { _isWorkstationLocked = false; _lockedByProximity = false; }

                _appEvent?.Set();
                _screenEvent?.Set();

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
            }
            else
            {
                _logger.Error("❌ Re-authentication failed after retries.");
            }
            return;
        }

        if (!isLockedLocal && avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 Signal below fallback bounds: {avgRssi:F0} dBm. Locking.");
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
            // If we are already disconnected, avoid reentrancy
            if (!wasConnected)
            {
                _logger.Debug("HandleDisconnection called but already disconnected.");
                return;
            }
            _isConnected = false;
            isPlannedReset = _isPlannedResetActive;
            _sessionKey = null;

            if (!isPlannedReset)
                _isWorkstationLocked = true;
            _lockedByProximity = false;
            _isPlannedResetActive = false;
        }

        StopRssiMonitoring();
        // Cancel any ongoing GATT operations – only if we have a token
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

        // If we never fully connected (wasConnected was true but we are here means it's a full disconnect)
        // Actually, we already set wasConnected to true if we were connected, so this path is for unexpected drops.
        ResetIPCHandles();
        _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });
        _logger.Error("🔒 LOCKING: Device disconnected unexpectedly.");
        _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });

        CleanupDevice();
        StartScanning();
    }

    private void CleanupDevice()
    {
        lock (_lock)
        {
            try
            {
                if (_cts != null)
                {
                    _cts.Cancel();
                    _cts.Dispose();
                    _cts = null;
                }

                if (_commandChar != null)
                {
                    _commandChar.ValueChanged -= OnCommandReceivedFromPhone;
                    _commandChar = null;
                }

                _challengeChar = null;
                _signatureChar = null;
                _publicKeyChar = null;

                _service?.Dispose();
                _service = null;

                if (_device != null)
                {
                    _device.ConnectionStatusChanged -= OnConnectionStatusChanged;
                    _device.Dispose();
                    _device = null;
                }

                _rssiSamples.Clear();
                _sessionKey = null;
            }
            catch (Exception ex)
            {
                _logger.Error($"CleanupDevice error: {ex.Message}");
            }
        }
    }

    private void StartRssiMonitoring()
    {
        _rssiTimer?.Dispose();
        _rssiTimer = new System.Threading.Timer(async _ => await SampleRssi(), null, 0, SAMPLE_INTERVAL_MS);
    }

    private void StopRssiMonitoring() => _rssiTimer?.Dispose();

    public void Stop()
    {
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

        try
        {
            string exactPath = @"C:\Dev\Tether\Tether.OverlayUI\bin\Debug\net8.0-windows\Tether.OverlayUI.exe";
            if (File.Exists(exactPath))
            {
                Process.Start(new ProcessStartInfo { FileName = exactPath, UseShellExecute = true });
            }
        }
        catch (Exception ex) { _logger.Error($"Failed to spin up UI space execution layer: {ex.Message}"); }
    }

    private async Task SendUiEventAsync(TetherEvent evt)
    {
        EnsureOverlayProcessRunning(evt);

        try
        {
            var json = System.Text.Json.JsonSerializer.Serialize(evt);
            var bytes = Encoding.UTF8.GetBytes(json);
            using var client = new System.IO.Pipes.NamedPipeClientStream(".", Tether.Shared.IPC.IpcConstants.UiPipeName, System.IO.Pipes.PipeDirection.Out);
            await client.ConnectAsync(200);
            await client.WriteAsync(bytes, 0, bytes.Length);
            await client.FlushAsync();
        }
        catch { }
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

internal static class TaskExtensions
{
    public static void KeepServiceAlive(this Task task, Action<Task> continuation) => task.ContinueWith(continuation);
}