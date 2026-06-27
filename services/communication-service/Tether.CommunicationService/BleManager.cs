using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
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
    private string? _currentConnectingId;

    // Configuration Thresholds
    private const int RSSI_GOOD = -55;
    private const int RSSI_LOCK = -80;
    private const int SAMPLE_INTERVAL_MS = 500;
    private const int SAMPLES_PER_AVERAGE = 5;

    // Target Identification & Secure Dynamic UUIDs
    private readonly Guid SERVICE_UUID = new Guid("0000FFE0-0000-1000-8000-00805F9B34FB");
    private readonly Guid CHALLENGE_CHAR_UUID = new Guid("0000FFE3-0000-1000-8000-00805F9B34FB");
    private readonly Guid SIGNATURE_CHAR_UUID = new Guid("0000FFE4-0000-1000-8000-00805F9B34FB");
    private readonly Guid COMMAND_CHAR_UUID = new Guid("0000FFE5-0000-1000-8000-00805F9B34FB");
    private readonly Guid PUBLIC_KEY_CHAR_UUID = new Guid("0000FFE6-0000-1000-8000-00805F9B34FB");

    // GATT Characteristic Tracking
    private GattCharacteristic? _challengeChar;
    private GattCharacteristic? _signatureChar;
    private GattCharacteristic? _commandChar;
    private GattCharacteristic? _publicKeyChar;

    // Native Windows API for instant volume control
    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    private const byte VK_VOLUME_UP = 0xAF;
    private const byte VK_VOLUME_DOWN = 0xAE;
    private const uint KEYEVENTF_KEYDOWN = 0x0000;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    // Native Windows API for brightness control
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

                        // Fire cross-session Win32 Handles to clear the OS lock screen
                        _appEvent?.Set();
                        _screenEvent?.Set();
                    }
                }
            }
        });
    }

    public void Start()
    {
        _logger.Info($"BLE Manager starting - cryptographic verification active for target devices advertising service UUID");
        StartScanning();
    }

    private void StartScanning()
    {
        if (_advWatcher != null)
        {
            _advWatcher.Stop();
            _advWatcher.Received -= OnDeviceAdvertised;
        }

        _advWatcher = new BluetoothLEAdvertisementWatcher
        {
            ScanningMode = BluetoothLEScanningMode.Active
        };

        _advWatcher.AdvertisementFilter.Advertisement.ServiceUuids.Add(SERVICE_UUID);
        _advWatcher.Received += OnDeviceAdvertised;
        _advWatcher.Start();
        _logger.Info("📡 Raw Over-The-Air UUID Sniffer initialized successfully.");
    }

    private void OnDeviceAdvertised(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        if (_isConnected || _currentConnectingId != null) return;

        string structuralDeviceId = args.BluetoothAddress.ToString();
        lock (_lock)
        {
            _currentConnectingId = structuralDeviceId;
        }

        _logger.Info($"🎯 Intercepted matching Service UUID from address: {args.BluetoothAddress:X}");
        ConnectToDeviceViaAddress(args.BluetoothAddress);
    }

    private async void ConnectToDeviceViaAddress(ulong bluetoothAddress)
    {
        try
        {
            CleanupDevice();

            var device = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);
            if (device == null)
            {
                _logger.Error("Device is null.");
                return;
            }

            var accessStatus = await device.RequestAccessAsync();
            if (accessStatus != DeviceAccessStatus.Allowed)
            {
                _logger.Error($"Access denied by Windows: {accessStatus}");
                device.Dispose();
                return;
            }

            _device = device;
            _device.ConnectionStatusChanged += OnConnectionStatusChanged;

            var servicesResult = await _device.GetGattServicesAsync(BluetoothCacheMode.Uncached);

            if (servicesResult.Status != GattCommunicationStatus.Success)
            {
                _logger.Error($"Failed to get GATT services: {servicesResult.Status}");
                HandleDisconnection();
                return;
            }

            var mainService = servicesResult.Services.FirstOrDefault(s => s.Uuid == SERVICE_UUID);
            if (mainService == null)
            {
                _logger.Error($"Service {SERVICE_UUID} not found on device.");
                HandleDisconnection();
                return;
            }

            // Resolve all characteristics
            var challengeResult = await mainService.GetCharacteristicsForUuidAsync(CHALLENGE_CHAR_UUID, BluetoothCacheMode.Uncached);
            var signatureResult = await mainService.GetCharacteristicsForUuidAsync(SIGNATURE_CHAR_UUID, BluetoothCacheMode.Uncached);
            var commandResult = await mainService.GetCharacteristicsForUuidAsync(COMMAND_CHAR_UUID, BluetoothCacheMode.Uncached);
            var publicKeyResult = await mainService.GetCharacteristicsForUuidAsync(PUBLIC_KEY_CHAR_UUID, BluetoothCacheMode.Uncached);

            if (challengeResult.Status == GattCommunicationStatus.Success && challengeResult.Characteristics.Count > 0 &&
                signatureResult.Status == GattCommunicationStatus.Success && signatureResult.Characteristics.Count > 0 &&
                commandResult.Status == GattCommunicationStatus.Success && commandResult.Characteristics.Count > 0 &&
                publicKeyResult.Status == GattCommunicationStatus.Success && publicKeyResult.Characteristics.Count > 0)
            {
                _challengeChar = challengeResult.Characteristics[0];
                _signatureChar = signatureResult.Characteristics[0];
                _commandChar = commandResult.Characteristics[0];
                _publicKeyChar = publicKeyResult.Characteristics[0];

                // ✅ AUTOMATIC: Read public key from phone
                byte[]? publicKeyBytes = await ReadPublicKeyFromPhone();

                // ✅ AUTOMATIC: Store public key in registry
                if (publicKeyBytes != null)
                {
                    string base64Key = Convert.ToBase64String(publicKeyBytes);
                    StorePublicKey(device.BluetoothAddress.ToString("X"), base64Key);
                    _logger.Info($"✅ Public key automatically stored for device {device.BluetoothAddress:X}");
                }

                // Perform authentication using the auto-obtained key
                bool isAuthenticated = await AuthenticateDeviceViaChallengeAsync(publicKeyBytes);
                if (!isAuthenticated)
                {
                    _logger.Error("❌ CRYPTOGRAPHIC CHALLENGE REJECTED.");
                    HandleDisconnection();
                    return;
                }

                _commandChar.ValueChanged += OnCommandReceivedFromPhone;
                var status = await _commandChar.WriteClientCharacteristicConfigurationDescriptorAsync(
                    GattClientCharacteristicConfigurationDescriptorValue.Notify);
                _logger.Info($"🛡️ Button Pipeline Subscription Complete. State code: {status}");

                _logger.Info("🛡️ SECURITY HANDSHAKE VERIFIED.");
                _isConnected = true;
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                StartRssiMonitoring();
            }
            else
            {
                _logger.Error("Failed to discover all required characteristics.");
                HandleDisconnection();
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"GATT processing error: {ex.GetType().Name} - {ex.Message}");
            HandleDisconnection();
        }
        finally
        {
            lock (_lock) { _currentConnectingId = null; }
        }
    }

    private async Task<byte[]?> ReadPublicKeyFromPhone()
    {
        if (_publicKeyChar == null)
        {
            _logger.Error("Public key characteristic is null.");
            return null;
        }

        try
        {
            var readResult = await _publicKeyChar.ReadValueAsync(BluetoothCacheMode.Uncached);
            if (readResult.Status != GattCommunicationStatus.Success)
            {
                _logger.Error($"Failed to read public key: {readResult.Status}");
                return null;
            }

            using (var reader = DataReader.FromBuffer(readResult.Value))
            {
                byte[] publicKeyBytes = new byte[reader.UnconsumedBufferLength];
                reader.ReadBytes(publicKeyBytes);
                return publicKeyBytes;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Error reading public key: {ex.Message}");
            return null;
        }
    }

    private async Task<bool> PerformAuthenticationAsync(BluetoothLEDevice device)
    {
        try
        {
            string addressHex = device.BluetoothAddress.ToString("X");
            string? storedKey = GetStoredPublicKey(addressHex);
            byte[]? publicKeyBytes = null;

            if (!string.IsNullOrEmpty(storedKey))
            {
                publicKeyBytes = Convert.FromBase64String(storedKey);
                _logger.Info($"Using stored public key for device {addressHex}");
            }
            else
            {
                _logger.Info($"No stored public key for {addressHex}. Reading from phone...");

                // Check pairing status but do NOT auto-pair
                if (!device.DeviceInformation.Pairing.IsPaired)
                {
                    _logger.Warning("Device is not paired. Public key read may fail if characteristic requires encryption.");
                }

                if (_publicKeyChar == null)
                {
                    _logger.Error("Public key characteristic is null.");
                    return false;
                }

                // Read the public key characteristic
                var readResult = await _publicKeyChar.ReadValueAsync(BluetoothCacheMode.Uncached);
                if (readResult.Status != GattCommunicationStatus.Success)
                {
                    _logger.Error($"Failed to read public key: {readResult.Status}");
                    return false;
                }

                using (var reader = DataReader.FromBuffer(readResult.Value))
                {
                    publicKeyBytes = new byte[reader.UnconsumedBufferLength];
                    reader.ReadBytes(publicKeyBytes);
                }

                string base64Key = Convert.ToBase64String(publicKeyBytes);
                StorePublicKey(addressHex, base64Key);
                _logger.Info($"Public key stored for device {addressHex}");
            }

            // Perform challenge-response using the obtained public key
            return await AuthenticateDeviceViaChallengeAsync(publicKeyBytes);
        }
        catch (Exception ex)
        {
            _logger.Error($"Authentication error: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> AuthenticateDeviceViaChallengeAsync(byte[] phonePublicKeyBytes)
    {
        if (_challengeChar == null || _signatureChar == null || phonePublicKeyBytes == null)
            return false;

        try
        {
            byte[] challengeNonce = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challengeNonce);
            }

            using (var writer = new DataWriter())
            {
                writer.WriteBytes(challengeNonce);
                var writeResult = await _challengeChar.WriteValueWithResultAsync(writer.DetachBuffer());
                if (writeResult.Status != GattCommunicationStatus.Success)
                {
                    _logger.Error($"Failed writing cryptographic challenge payload: {writeResult.Status}");
                    return false;
                }
            }

            var readResult = await _signatureChar.ReadValueAsync(BluetoothCacheMode.Uncached);
            if (readResult.Status != GattCommunicationStatus.Success)
            {
                _logger.Error($"Failed reading verification signature loop: {readResult.Status}");
                return false;
            }

            using (var reader = DataReader.FromBuffer(readResult.Value))
            {
                byte[] phoneSignature = new byte[reader.UnconsumedBufferLength];
                reader.ReadBytes(phoneSignature);

                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(phonePublicKeyBytes, out _);
                    return rsa.VerifyData(challengeNonce, phoneSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
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
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider");
            return key?.GetValue($"PhonePublicKey_{addressHex}") as string;
        }
        catch { return null; }
    }

    private void StorePublicKey(string addressHex, string base64Key)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider");
            key.SetValue($"PhonePublicKey_{addressHex}", base64Key);
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

            // Fire-and-forget: execute command on a thread pool thread
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
            switch (command)
            {
                case "panic":
                case "lock_now":
                    lock (_lock) { _isWorkstationLocked = true; }
                    _logger.Error($"🚨 Manual lock triggered: {command}");
                    ResetIPCHandles();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
                    break;

                case "unlock":
                    lock (_lock) { _isWorkstationLocked = false; }
                    _logger.Info("🔓 Manual unlock override");
                    _appEvent?.Set();
                    _screenEvent?.Set();
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                    await SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
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
                    _logger.Info("🔄 Executing reboot...");
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

                case "volume_up":
                    _logger.Info("🔊 Increasing volume...");
                    AdjustVolumeNative(1);
                    break;

                case "volume_down":
                    _logger.Info("🔉 Decreasing volume...");
                    AdjustVolumeNative(-1);
                    break;

                case "brightness_up":
                    _logger.Info("☀️ Increasing brightness...");
                    await AdjustBrightnessNativeAsync(5);
                    break;

                case "brightness_down":
                    _logger.Info("🌙 Decreasing brightness...");
                    await AdjustBrightnessNativeAsync(-5);
                    break;

                default:
                    _logger.Warning($"Unknown command: {command}");
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
        // Simulate pressing the media volume key - instantaneous
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
                // Get primary monitor handle
                IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
                if (hMonitor == IntPtr.Zero)
                {
                    _logger.Warning("Failed to get primary monitor handle");
                    return;
                }

                uint physicalMonitorCount = 1;
                PHYSICAL_MONITOR[] monitors = new PHYSICAL_MONITOR[1];
                if (!GetPhysicalMonitorsFromHMONITOR(hMonitor, physicalMonitorCount, monitors))
                {
                    _logger.Warning("Failed to get physical monitor");
                    return;
                }

                IntPtr hPhysical = monitors[0].hPhysicalMonitor;
                uint min, current, max;
                if (!GetMonitorBrightness(hPhysical, out min, out current, out max))
                {
                    _logger.Warning("Failed to get current brightness");
                    DestroyPhysicalMonitor(hPhysical);
                    return;
                }

                // Calculate new brightness (deltaPercent is +/- percentage points)
                float step = (max - min) / 100.0f;
                int newBrightness = (int)(current + (deltaPercent * step));
                newBrightness = Math.Clamp(newBrightness, (int)min, (int)max);

                if (!SetMonitorBrightness(hPhysical, (uint)newBrightness))
                {
                    _logger.Warning("Failed to set brightness");
                }
                else
                {
                    _logger.Info($"Brightness set to {newBrightness} (range: {min}-{max})");
                }

                DestroyPhysicalMonitor(hPhysical);
            }
            catch (Exception ex)
            {
                _logger.Warning($"Brightness adjustment failed: {ex.Message}");
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
        else if (sender.ConnectionStatus == BluetoothConnectionStatus.Connected)
        {
            _logger.Info("BLE device connected.");
        }
    }

    private async void EvaluateProximity(double avgRssi)
    {
        bool isLockedLocal;
        lock (_lock)
        {
            isLockedLocal = _isWorkstationLocked;
        }

        if (!isLockedLocal)
        {
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_DEGRADED, Source = "BleManager", PayloadJson = $"{{\"Rssi\":{avgRssi}}}" });
        }

        if (isLockedLocal && avgRssi >= RSSI_GOOD)
        {
            _logger.Info($"Device returned within threshold parameters: {avgRssi:F0} dBm. Prompting Challenge Validation...");

            string addressHex = _device?.BluetoothAddress.ToString("X") ?? "";
            string? storedKey = GetStoredPublicKey(addressHex);
            byte[]? publicKeyBytes = null;

            if (!string.IsNullOrEmpty(storedKey))
            {
                publicKeyBytes = Convert.FromBase64String(storedKey);
            }
            else
            {
                _logger.Error("No stored public key for re-authentication");
                return;
            }

            bool identityReverified = await AuthenticateDeviceViaChallengeAsync(publicKeyBytes);
            if (identityReverified)
            {
                _logger.Info("✅ Proximity Re-authentication passed successfully.");
                lock (_lock) { _isWorkstationLocked = false; }

                _appEvent?.Set();
                _screenEvent?.Set();

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
            }
            else
            {
                _logger.Error("❌ Re-authentication challenge rejected during verification loop.");
            }
            return;
        }

        if (!isLockedLocal && avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 Signal below fallback bounds: {avgRssi:F0} dBm. Locking.");
            lock (_lock) { _isWorkstationLocked = true; }

            ResetIPCHandles();

            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        }
    }

    private void HandleDisconnection()
    {
        if (!_isConnected)
        {
            CleanupDevice();
            return;
        }
        _isConnected = false;
        StopRssiMonitoring();

        lock (_lock) { _isWorkstationLocked = true; }

        ResetIPCHandles();

        _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });
        _logger.Error("🔒 LOCKING: Device disconnected.");

        _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        CleanupDevice();
    }

    private void CleanupDevice()
    {
        if (_commandChar != null)
        {
            _commandChar.ValueChanged -= OnCommandReceivedFromPhone;
        }
        if (_device != null)
        {
            _device.ConnectionStatusChanged -= OnConnectionStatusChanged;
            _device.Dispose();
            _device = null;
        }
        _challengeChar = null;
        _signatureChar = null;
        _commandChar = null;
        _publicKeyChar = null;
    }

    private void StartRssiMonitoring()
    {
        _rssiTimer?.Dispose();
        _rssiTimer = new System.Threading.Timer(async _ => await SampleRssi(), null, 0, SAMPLE_INTERVAL_MS);
    }

    private async Task SampleRssi()
    {
        if (_device == null || !_isConnected) return;
        try
        {
            var info = await DeviceInformation.CreateFromIdAsync(_device.DeviceId, new[] { "System.Devices.Aep.SignalStrength" }, DeviceInformationKind.AssociationEndpoint);
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

    private void StopRssiMonitoring() => _rssiTimer?.Dispose();

    public void Stop()
    {
        _advWatcher?.Stop();
        _advWatcher = null;
        CleanupDevice();
        StopRssiMonitoring();
    }

    public void Dispose() => Stop();

    private void EnsureOverlayProcessRunning(TetherEvent evt)
    {
        bool shouldLaunch = evt.EventType == TetherEventType.OVERLAY_ENABLED;

        if (evt.EventType == TetherEventType.TRUST_DEGRADED && evt.PayloadJson != null)
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(evt.PayloadJson);
                if (doc.RootElement.TryGetProperty("Rssi", out var rssiProp) && rssiProp.GetDouble() < -68)
                {
                    shouldLaunch = true;
                }
            }
            catch { }
        }

        if (!shouldLaunch) return;

        var processes = Process.GetProcessesByName("Tether.OverlayUI");
        if (processes.Length > 0) return;

        try
        {
            string exactPath = @"C:\Dev\Tether\Tether.OverlayUI\bin\Debug\net8.0-windows\Tether.OverlayUI.exe";

            if (File.Exists(exactPath))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exactPath,
                    UseShellExecute = true
                });
                _logger.Info($"🚀 Launched overlay execution process vector: {exactPath}");
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to spin up UI space execution layer: {ex.Message}");
        }
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
}