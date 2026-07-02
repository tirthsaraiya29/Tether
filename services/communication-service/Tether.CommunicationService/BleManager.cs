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

    private bool _isWorkstationLocked = false;
    private bool _isConnected = false;
    private bool _lockedByProximity = false;
    private bool _isStopping = false;
    private bool _isPlannedResetActive = false;
    private byte[]? _sessionKey;

    private const int RSSI_GOOD = -55;
    private const int RSSI_LOCK = -75;
    private const int SAMPLE_INTERVAL_MS = 500;
    private const int SAMPLES_PER_AVERAGE = 5;

    private readonly Guid SERVICE_UUID = new Guid("0000FFE0-0000-1000-8000-00805F9B34FB");
    private readonly Guid CHALLENGE_CHAR_UUID = new Guid("0000FFE3-0000-1000-8000-00805F9B34FB");
    private readonly Guid SIGNATURE_CHAR_UUID = new Guid("0000FFE4-0000-1000-8000-00805F9B34FB");
    private readonly Guid COMMAND_CHAR_UUID = new Guid("0000FFE5-0000-1000-8000-00805F9B34FB");
    private readonly Guid PUBLIC_KEY_CHAR_UUID = new Guid("0000FFE6-0000-1000-8000-00805F9B34FB");

    private readonly SemaphoreSlim _connectionSemaphore = new SemaphoreSlim(1, 1);

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

    private const uint MONITOR_DEFAULTTOPRIMARY = 0x00000001;

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;

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
    }

    public void Start()
    {
        lock (_lock)
        {
            _isStopping = false;
        }
        _logger.Info($"Core BLE Management Stack listening for validated targets...");
        StartScanning();
    }

    private void StartScanning()
    {
        lock (_lock)
        {
            if (_isStopping) return;

            if (_advWatcher != null)
            {
                try { _advWatcher.Stop(); } catch { }
                _advWatcher.Received -= OnDeviceAdvertised;
            }

            _advWatcher = new BluetoothLEAdvertisementWatcher
            {
                ScanningMode = BluetoothLEScanningMode.Active
            };

            _advWatcher.AdvertisementFilter.Advertisement.ServiceUuids.Add(SERVICE_UUID);
            _advWatcher.Received += OnDeviceAdvertised;

            try
            {
                _advWatcher.Start();
                _logger.Info("📡 Active over-the-air advertisement listener established.");
            }
            catch (COMException ex) when ((uint)ex.HResult == 0x800710DF)
            {
                _logger.Warning("⚠️ Bluetooth radio is disabled or unavailable on the host system. Retrying link initialization in 5 seconds...");
                Task.Delay(5000).KeepServiceAlive(_ => StartScanning());
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to initialize BLE scanner framework: {ex.Message}. Retrying...");
                Task.Delay(5000).KeepServiceAlive(_ => StartScanning());
            }
        }
    }

    private async void OnDeviceAdvertised(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        if (_isConnected) return;

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
        const int maxRetryAttempts = 3;
        int delayMs = 150;

        for (int attempt = 1; attempt <= maxRetryAttempts; attempt++)
        {
            try
            {
                CleanupDevice();

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
                    _logger.Info($"GattSession max PDU size synchronized to: {gattSession.MaxPduSize} bytes.");
                }
                catch (Exception ex)
                {
                    _logger.Warning($"GattSession optimization bypass triggered: {ex.Message}");
                }

                var servicesResult = await TryGetGattServicesAsync(device);
                if (servicesResult.Status != GattCommunicationStatus.Success || servicesResult.Services.Count == 0)
                {
                    _logger.Error($"Failed to resolve GATT target service context: status={servicesResult.Status}, serviceCount={servicesResult.Services.Count}");
                    CleanupDevice();

                    if (attempt == maxRetryAttempts)
                    {
                        HandleDisconnection();
                        return;
                    }

                    await Task.Delay(delayMs);
                    delayMs *= 2;
                    continue;
                }

                lock (_lock)
                {
                    _service = servicesResult.Services.First();
                }

                var allCharacteristicsResult = await TryGetCharacteristicsAsync(_service);
                if (allCharacteristicsResult.Status != GattCommunicationStatus.Success || allCharacteristicsResult.Characteristics.Count == 0)
                {
                    _logger.Error($"Failed to map characteristics buffer layout context: {allCharacteristicsResult.Status}");
                    CleanupDevice();

                    if (attempt == maxRetryAttempts)
                    {
                        HandleDisconnection();
                        return;
                    }

                    await Task.Delay(delayMs);
                    delayMs *= 2;
                    continue;
                }

                var characteristicsList = allCharacteristicsResult.Characteristics;
                _challengeChar = characteristicsList.FirstOrDefault(c => c.Uuid == CHALLENGE_CHAR_UUID);
                _signatureChar = characteristicsList.FirstOrDefault(c => c.Uuid == SIGNATURE_CHAR_UUID);
                _commandChar = characteristicsList.FirstOrDefault(c => c.Uuid == COMMAND_CHAR_UUID);
                _publicKeyChar = characteristicsList.FirstOrDefault(c => c.Uuid == PUBLIC_KEY_CHAR_UUID);

                if (_challengeChar == null || _signatureChar == null || _commandChar == null || _publicKeyChar == null)
                {
                    _logger.Error("Failed to discover all required characteristic hardware registers.");
                    CleanupDevice();

                    if (attempt == maxRetryAttempts)
                    {
                        HandleDisconnection();
                        return;
                    }

                    await Task.Delay(delayMs);
                    delayMs *= 2;
                    continue;
                }

                try
                {
                    using var zeroWriter = new DataWriter();
                    zeroWriter.WriteBytes(new byte[16]);
                    await _challengeChar.WriteValueWithResultAsync(zeroWriter.DetachBuffer(), GattWriteOption.WriteWithResponse);
                }
                catch { }

                await Task.Delay(150);

                var publicKeyBytes = await ReadPublicKeyFromPhone();
                if (publicKeyBytes == null || publicKeyBytes.Length < 64)
                {
                    _logger.Error("Security aborted: Public key byte array stream returned null or truncated data.");
                    CleanupDevice();

                    if (attempt == maxRetryAttempts)
                    {
                        HandleDisconnection();
                        return;
                    }

                    await Task.Delay(delayMs);
                    delayMs *= 2;
                    continue;
                }

                var base64Key = Convert.ToBase64String(publicKeyBytes);
                StorePublicKey(device.BluetoothAddress.ToString("X"), base64Key);
                _logger.Info($"Identity parameters successfully recorded for target node {device.BluetoothAddress:X}");

                byte[] generatedKey = new byte[32];
                RandomNumberGenerator.Fill(generatedKey);
                byte[] encryptedSessionKey;
                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                    encryptedSessionKey = rsa.Encrypt(generatedKey, RSAEncryptionPadding.Pkcs1);
                }

                using (var writer = new DataWriter())
                {
                    writer.WriteBytes(encryptedSessionKey);
                    var keyResult = await _challengeChar.WriteValueWithResultAsync(writer.DetachBuffer(), GattWriteOption.WriteWithResponse);
                    if (keyResult.Status != GattCommunicationStatus.Success)
                    {
                        CleanupDevice();
                        if (attempt == maxRetryAttempts) { HandleDisconnection(); return; }
                        await Task.Delay(delayMs); delayMs *= 2; continue;
                    }
                }

                lock (_lock)
                {
                    _sessionKey = generatedKey;
                }

                var isAuthenticated = await AuthenticateDeviceViaChallengeAsync(publicKeyBytes);
                if (!isAuthenticated)
                {
                    _logger.Error("CRYPTOGRAPHIC CHALLENGE REJECTED: Digital token signature mismatch.");
                    CleanupDevice();

                    if (attempt == maxRetryAttempts)
                    {
                        HandleDisconnection();
                        return;
                    }

                    await Task.Delay(delayMs);
                    delayMs *= 2;
                    continue;
                }

                _commandChar.ValueChanged -= OnCommandReceivedFromPhone;
                _commandChar.ValueChanged += OnCommandReceivedFromPhone;

                var subscriptionOk = false;
                for (var subAttempt = 1; subAttempt <= 3 && !subscriptionOk; subAttempt++)
                {
                    var cccdResult = await _commandChar.WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                        GattClientCharacteristicConfigurationDescriptorValue.Notify);

                    if (cccdResult.Status == GattCommunicationStatus.Success)
                    {
                        subscriptionOk = true;
                        break;
                    }

                    _logger.Warning($"Failed to configure GATT notifications (attempt {subAttempt}/3). Status: {cccdResult.Status}");
                    await Task.Delay(250 * subAttempt);
                }

                if (!subscriptionOk)
                {
                    CleanupDevice();

                    if (attempt == maxRetryAttempts)
                    {
                        HandleDisconnection();
                        return;
                    }

                    await Task.Delay(delayMs);
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
            catch (COMException ex)
            {
                _logger.Error($"Windows WinRT COM Error [0x{ex.HResult:X8}]: {ex.Message}");
            }
            catch (TaskCanceledException ex)
            {
                _logger.Warning($"GATT negotiation canceled (attempt {attempt}/{maxRetryAttempts}): {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.Error($"General GATT setup exception encountered: {ex.GetType().Name} - {ex.Message}");
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

    private async Task<GattDeviceServicesResult> TryGetGattServicesAsync(BluetoothLEDevice device)
    {
        try
        {
            return await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached);
        }
        catch (Exception)
        {
            await Task.Delay(100);
            return await device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Cached);
        }
    }

    private async Task<GattCharacteristicsResult> TryGetCharacteristicsAsync(GattDeviceService service)
    {
        try
        {
            return await service.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
        }
        catch (COMException ex) when ((uint)ex.HResult == 0x8000FFFF || (uint)ex.HResult == 0x8007001F)
        {
            await Task.Delay(100);
            return await service.GetCharacteristicsAsync(BluetoothCacheMode.Cached);
        }
    }

    private async Task<byte[]?> ReadPublicKeyFromPhone()
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

        foreach (var cacheMode in new[] { BluetoothCacheMode.Uncached, BluetoothCacheMode.Cached })
        {
            try
            {
                var readResult = await localPublicKeyChar.ReadValueAsync(cacheMode);
                if (readResult.Status != GattCommunicationStatus.Success)
                {
                    continue;
                }

                using var reader = DataReader.FromBuffer(readResult.Value);
                byte[] publicKeyBytes = new byte[reader.UnconsumedBufferLength];
                reader.ReadBytes(publicKeyBytes);
                return publicKeyBytes;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception)
            {
            }
        }

        return null;
    }

    private async Task<bool> AuthenticateDeviceViaChallengeAsync(byte[] phonePublicKeyBytes)
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
                    _logger.Error($"Failed writing cryptographic challenge payload: {writeResult.Status}");
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
                    {
                        continue;
                    }

                    using var reader = DataReader.FromBuffer(readResult.Value);
                    phoneSignature = new byte[reader.UnconsumedBufferLength];
                    reader.ReadBytes(phoneSignature);
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception)
                {
                }
            }

            if (phoneSignature == null || phoneSignature.Length == 0)
                return false;

            if (currentKey != null)
            {
                using (var hmac = new HMACSHA256(currentKey))
                {
                    byte[] computedHash = hmac.ComputeHash(challengeNonce);
                    return CryptographicOperations.FixedTimeEquals(phoneSignature, computedHash);
                }
            }
            else
            {
                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(phonePublicKeyBytes, out _);
                    return rsa.VerifyData(challengeNonce, phoneSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
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
                    lock (_lock)
                    {
                        _isPlannedResetActive = true;
                    }
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

                    try
                    {
                        uint activeSessionId = WTSGetActiveConsoleSessionId();
                        if (activeSessionId != 0xFFFFFFFF)
                        {
                            if (!WTSDisconnectSession(IntPtr.Zero, activeSessionId, false))
                            {
                                int errorCode = Marshal.GetLastWin32Error();
                                _logger.Warning($"WTSDisconnectSession failed for Session {activeSessionId}. Win32 Error: {errorCode}");
                            }
                            else
                            {
                                _logger.Info($"Successfully disconnected active console Session {activeSessionId}.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Error($"Failed to execute WTS session lock primitive: {ex.Message}");
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
                {
                    return;
                }

                const uint physicalMonitorCount = 1;
                var monitors = new PHYSICAL_MONITOR[physicalMonitorCount];
                if (!GetPhysicalMonitorsFromHMONITOR(hMonitor, physicalMonitorCount, monitors))
                {
                    return;
                }

                IntPtr hPhysical = monitors[0].hPhysicalMonitor;
                if (hPhysical == IntPtr.Zero)
                {
                    return;
                }

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
        catch
        {
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
            {
                publicKeyBytes = Convert.FromBase64String(storedKey);
            }
            else
            {
                _logger.Error("No stored public key available for proximity recovery authorization.");
                return;
            }

            bool identityReverified = await AuthenticateDeviceViaChallengeAsync(publicKeyBytes);
            if (identityReverified)
            {
                _logger.Info("✅ Proximity Re-authentication passed successfully.");
                lock (_lock) { _isWorkstationLocked = false; _lockedByProximity = false; }

                _appEvent?.Set();
                _screenEvent?.Set();

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
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
            _isConnected = false;
            isPlannedReset = _isPlannedResetActive;
            _sessionKey = null;

            if (!isPlannedReset)
            {
                _isWorkstationLocked = true;
            }
            _lockedByProximity = false;
            _isPlannedResetActive = false;
        }

        StopRssiMonitoring();

        if (_isStopping)
        {
            CleanupDevice();
            return;
        }

        if (isPlannedReset)
        {
            _logger.Info("🔄 Connection dropped via expected phone radio reset loop. Workstation status preserved; restarting background mesh scanning.");
            CleanupDevice();
            StartScanning();
            return;
        }

        if (!wasConnected)
        {
            _logger.Warning("⚠️ Connection dropped prior to completing full validation framework setup loops. Restarting scan loop.");
            CleanupDevice();
            StartScanning();
            return;
        }

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
        lock (_lock)
        {
            _isStopping = true;
        }
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
        lock (_lock)
        {
            localCommandChar = _commandChar;
        }
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