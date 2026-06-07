using System.ComponentModel;
using System.Diagnostics;
using System.Numerics;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Timers;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Enumeration;
using Windows.Graphics;
using Windows.Storage.Streams;
using Windows.System;
using Windows.UI.Composition;

namespace Tether.CommunicationService;

public partial class BleManager : IDisposable
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private DeviceWatcher? _deviceWatcher;
    private BluetoothLEAdvertisementWatcher? _advWatcher;
    private BluetoothLEDevice? _device;
    private System.Threading.Timer? _rssiTimer;
    private readonly List<int> _rssiSamples = new();
    private readonly object _lock = new();
    private byte _lastTrustState = 0x00;

    private bool _isWorkstationLocked = false;
    private bool _isConnected = false;
    private string? _currentConnectingId;

    // Configuration Thresholds
    private const int RSSI_GOOD = -55;
    private const int RSSI_LOCK = -80;
    private const int SAMPLE_INTERVAL_MS = 500;
    private const int SAMPLES_PER_AVERAGE = 5;

    // Target Identification & Secure Dynamic UUIDs
    private const string TARGET_DEVICE_NAME = "Tirth's S25 FE";
    private readonly Guid SERVICE_UUID = new Guid("0000FFE0-0000-1000-8000-00805F9B34FB");
    private readonly Guid CHALLENGE_CHAR_UUID = new Guid("0000FFE3-0000-1000-8000-00805F9B34FB");
    private readonly Guid SIGNATURE_CHAR_UUID = new Guid("0000FFE4-0000-1000-8000-00805F9B34FB");
    private readonly Guid COMMAND_CHAR_UUID = new Guid("0000FFE5-0000-1000-8000-00805F9B34FB");

    // GATT Characteristic Tracking
    private GattCharacteristic? _challengeChar;
    private GattCharacteristic? _signatureChar;
    private GattCharacteristic? _commandChar;

    /// <summary>
    /// 🔑 PASTE YOUR EXPORTED ANDROID PUBLIC KEY HERE (Base64 Format)
    /// </summary>
    private const string PHONE_PUBLIC_KEY_BASE64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2dbYLlmSn9Z90MfKIFyOAhN9GK+/kdNRSr1Y0ceIFumC/FHdMRoQvXIJH7QHoQVPBP/91w3+dwMg6LkEn7N2DRV6XyH1vOhqTxWeae6n9qHSk+o0KttNwL1bnpBAz1tjFztdvaXEsuNbj1h8bZN2QE3UIrQJNU/9yeLx8JKrCkC8WajJv0RRAQx07pY+n0wbxF0PB/o2kGYhR5gZ1SEzIzbw+swzG5mF0CovolFCNQPoyAwlkbG/ATZRSVFDMA6Min4MkZWBfzQLLEHq0qLoHD+Pio0gmKOy/np+nU1ihzcoLe3CyYxFgludECvay0gGa0WjhmB79kvBsbPrVvuE2QIDAQAB";

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
        _logger.Info($"BLE Manager starting - cryptographic verification active for target: '{TARGET_DEVICE_NAME}'");
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
            if (device == null) return;

            var accessStatus = await device.RequestAccessAsync();
            if (accessStatus != DeviceAccessStatus.Allowed)
            {
                _logger.Error($"Access denied by Windows: {accessStatus}");
                device.Dispose();
                return;
            }

            _device = device;
            _device.ConnectionStatusChanged += OnConnectionStatusChanged;

            var servicesResult = await _device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached);

            if (servicesResult.Status == GattCommunicationStatus.Success && servicesResult.Services.Count > 0)
            {
                var mainService = servicesResult.Services[0];

                var challengeResult = await mainService.GetCharacteristicsForUuidAsync(CHALLENGE_CHAR_UUID, BluetoothCacheMode.Uncached);
                var signatureResult = await mainService.GetCharacteristicsForUuidAsync(SIGNATURE_CHAR_UUID, BluetoothCacheMode.Uncached);
                var commandResult = await mainService.GetCharacteristicsForUuidAsync(COMMAND_CHAR_UUID, BluetoothCacheMode.Uncached);

                if (challengeResult.Status == GattCommunicationStatus.Success && challengeResult.Characteristics.Count > 0 &&
                    signatureResult.Status == GattCommunicationStatus.Success && signatureResult.Characteristics.Count > 0 &&
                    commandResult.Status == GattCommunicationStatus.Success && commandResult.Characteristics.Count > 0)
                {
                    _challengeChar = challengeResult.Characteristics[0];
                    _signatureChar = signatureResult.Characteristics[0];
                    _commandChar = commandResult.Characteristics[0];

                    bool isAuthenticated = await AuthenticateDeviceViaChallengeAsync();
                    if (!isAuthenticated)
                    {
                        _logger.Error("❌ CRYPTOGRAPHIC CHALLENGE REJECTED.");
                        HandleDisconnection();
                        return;
                    }

                    _commandChar.ValueChanged += OnCommandReceivedFromPhone;
                    var status = await _commandChar.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
                    _logger.Info($"🛡️ Button Pipeline Subscription Complete. State code: {status}");

                    _logger.Info("🛡️ SECURITY HANDSHAKE VERIFIED.");
                    _isConnected = true;
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                    StartRssiMonitoring();
                }
            }
            else
            {
                HandleDisconnection();
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"GATT processing link fault: {ex.Message}");
            HandleDisconnection();
        }
        finally
        {
            lock (_lock) { _currentConnectingId = null; }
        }
    }

    private void OnDeviceDiscovered(DeviceWatcher sender, DeviceInformation args)
    {
        if (_isConnected || _currentConnectingId != null) return;
        _logger.Info($"🎯 SECURE TARGET FOUND VIA SERVICE UUID (ID suffix: {args.Id.Substring(Math.Max(0, args.Id.Length - 5))})");
        ConnectToDevice(args.Id);
    }

    private async void ConnectToDevice(string deviceId)
    {
        lock (_lock)
        {
            if (_isConnected || _currentConnectingId != null) return;
            _currentConnectingId = deviceId;
        }

        try
        {
            _logger.Info($"Attempting connection to: {deviceId}");
            CleanupDevice();

            var device = await BluetoothLEDevice.FromIdAsync(deviceId);
            if (device == null) return;

            var accessStatus = await device.RequestAccessAsync();
            if (accessStatus != DeviceAccessStatus.Allowed)
            {
                _logger.Error($"Access denied by Windows: {accessStatus}");
                device.Dispose();
                return;
            }

            if (_currentConnectingId != deviceId) { device.Dispose(); return; }

            _device = device;
            _device.ConnectionStatusChanged += OnConnectionStatusChanged;

            var servicesResult = await _device.GetGattServicesForUuidAsync(SERVICE_UUID, BluetoothCacheMode.Uncached);

            if (_device == null || _currentConnectingId != deviceId) return;

            if (servicesResult.Status == GattCommunicationStatus.Success && servicesResult.Services.Count > 0)
            {
                var mainService = servicesResult.Services[0];
                _logger.Info("✅ Core Service found. Discovering cryptographic characteristics...");

                var challengeResult = await mainService.GetCharacteristicsForUuidAsync(CHALLENGE_CHAR_UUID, BluetoothCacheMode.Uncached);
                var signatureResult = await mainService.GetCharacteristicsForUuidAsync(SIGNATURE_CHAR_UUID, BluetoothCacheMode.Uncached);
                var commandResult = await mainService.GetCharacteristicsForUuidAsync(COMMAND_CHAR_UUID, BluetoothCacheMode.Uncached);

                if (challengeResult.Status == GattCommunicationStatus.Success && challengeResult.Characteristics.Count > 0 &&
                    signatureResult.Status == GattCommunicationStatus.Success && signatureResult.Characteristics.Count > 0 &&
                    commandResult.Status == GattCommunicationStatus.Success && commandResult.Characteristics.Count > 0)
                {
                    _challengeChar = challengeResult.Characteristics[0];
                    _signatureChar = signatureResult.Characteristics[0];
                    _commandChar = commandResult.Characteristics[0];

                    _logger.Info("Characteristics resolved. Initializing identity challenge...");

                    bool isAuthenticated = await AuthenticateDeviceViaChallengeAsync();
                    if (!isAuthenticated)
                    {
                        _logger.Error("❌ CRYPTOGRAPHIC VERIFICATION FAILED. Rogue device detected.");
                        HandleDisconnection();
                        return;
                    }

                    _commandChar.ValueChanged += OnCommandReceivedFromPhone;
                    var status = await _commandChar.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
                    _logger.Info($"🛡️ Button Pipeline Subscription Complete. State code: {status}");

                    _logger.Info("🛡️ CRYPTOGRAPHIC VERIFICATION PASSED. Identity verified via Android Keystore.");
                    _isConnected = true;
                    _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                    StartRssiMonitoring();
                }
                else
                {
                    _logger.Error("Failed to discover secure cryptographic characteristics.");
                    HandleDisconnection();
                }
            }
            else
            {
                _logger.Error($"Secure Service discovery failed: {servicesResult.Status}");
                HandleDisconnection();
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Connection lifecycle processing failure: {ex.GetType().Name} - {ex.Message}");
            HandleDisconnection();
        }
        finally
        {
            lock (_lock) { _currentConnectingId = null; }
        }
    }

    private void OnCommandReceivedFromPhone(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        try
        {
            var reader = DataReader.FromBuffer(args.CharacteristicValue);
            byte[] inputBytes = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(inputBytes);
            string command = Encoding.UTF8.GetString(inputBytes);

            _logger.Info($"📬 Manual Command Payload Evaluated from Device UI: {command}");

            if (command == "PANIC" || command == "LOCK_NOW")
            {
                lock (_lock)
                {
                    _isWorkstationLocked = true;
                }
                _logger.Error($"🚨 MANUAL SECURE LOCK ACTION TRIGGERED BY PHONE: {command}");

                // Clear out active Session 0 login tokens instantly
                ResetIPCHandles();

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });

                // Force an immediate layout projection instead of evaluating proximity loops asynchronously
                _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
            }
            else if (command == "UNLOCK")
            {
                lock (_lock)
                {
                    _isWorkstationLocked = false;
                }
                _logger.Info("🔓 MANUAL UNLOCK OVERRIDE DISPATCHED VIA DEVICE APPLICATION CONSOLE");

                // Signal Windows Global Wait Handles to clear the OS layer login screen
                _appEvent?.Set();
                _screenEvent?.Set();

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
                _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed parsing incoming button descriptor notification payload: {ex.Message}");
        }
    }

    private async Task<bool> AuthenticateDeviceViaChallengeAsync()
    {
        if (_challengeChar == null || _signatureChar == null) return false;

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
                return VerifyPhoneSignature(challengeNonce, phoneSignature);
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Error executing security challenge execution: {ex.Message}");
            return false;
        }
    }

    // Refactored cryptographic verification engine in BleManager.cs
    private bool VerifyPhoneSignature(byte[] challengeData, byte[] signatureToVerify)
    {
        if (string.IsNullOrWhiteSpace(PHONE_PUBLIC_KEY_BASE64) ||
            PHONE_PUBLIC_KEY_BASE64.StartsWith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0...["))
        {
            _logger.Error("❌ CRITICAL: Production Bluetooth Public Key validation token is unconfigured.");
            return false;
        }

        try
        {
            byte[] publicKeyBytes = Convert.FromBase64String(PHONE_PUBLIC_KEY_BASE64);
            using (var rsa = RSA.Create())
            {
                // Inject public key components exported from Android isolated hardware engine
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                // Execute SHA-256 validation against the original challenge nonce payload
                return rsa.VerifyData(
                    challengeData,
                    signatureToVerify,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1
                );
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Signature engine fault encountered: {ex.Message}");
            return false;
        }
    }

    private async Task UnpairTargetDeviceAsync()
    {
        try
        {
            string aqs = Windows.Devices.Bluetooth.GenericAttributeProfile.GattDeviceService.GetDeviceSelectorFromUuid(SERVICE_UUID);
            var devices = await DeviceInformation.FindAllAsync(aqs);

            foreach (var device in devices)
            {
                if (device.Pairing.IsPaired)
                {
                    _logger.Warning($"Flushing system cache connection bounds for discovered node.");
                    await device.Pairing.UnpairAsync();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug($"Unpairing routing skipped: {ex.Message}");
        }
    }

    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        if (sender.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
        {
            _logger.Warning("Physical connection link drop reported by underlying Windows OS core.");
            HandleDisconnection();
        }
    }

    private void OnDeviceRemoved(DeviceWatcher sender, DeviceInformationUpdate args)
    {
        if (_device?.DeviceId == args.Id || _currentConnectingId == args.Id)
        {
            _logger.Warning("Target device boundary range connection dropped from scanner.");
            HandleDisconnection();
        }
    }

    private async void EvaluateProximity(double avgRssi)
    {
        bool isLockedLocal;
        lock (_lock)
        {
            isLockedLocal = _isWorkstationLocked;
        }

        // Only project trust degradation metadata layers if the workspace remains active 
        if (!isLockedLocal)
        {
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.TRUST_DEGRADED, Source = "BleManager", PayloadJson = $"{{\"Rssi\":{avgRssi}}}" });
        }

        if (isLockedLocal && avgRssi >= RSSI_GOOD)
        {
            _logger.Info($"Device returned within threshold parameters: {avgRssi:F0} dBm. Prompting Challenge Validation...");

            bool identityReverified = await AuthenticateDeviceViaChallengeAsync();
            if (identityReverified)
            {
                _logger.Info("✅ Proximity Re-authentication passed successfully.");
                lock (_lock) { _isWorkstationLocked = false; }

                // Signal Windows Global Wait Handles to drop OS-level locking frames automatically
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

            // Wipe out OS authentication states instantly
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

        // Sever Win32 session authentication lines immediately
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
        _deviceWatcher?.Stop();
        CleanupDevice();
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

        var processes = System.Diagnostics.Process.GetProcessesByName("Tether.OverlayUI");
        if (processes.Length > 0) return;

        try
        {
            string exactPath = @"C:\Dev\Tether\Tether.OverlayUI\bin\Debug\net8.0-windows\Tether.OverlayUI.exe";

            if (System.IO.File.Exists(exactPath))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
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
            var bytes = System.Text.Encoding.UTF8.GetBytes(json);
            using var client = new System.IO.Pipes.NamedPipeClientStream(".", Tether.Shared.IPC.IpcConstants.UiPipeName, System.IO.Pipes.PipeDirection.Out);
            await client.ConnectAsync(200);
            await client.WriteAsync(bytes, 0, bytes.Length);
            await client.FlushAsync();
        }
        catch { }
    }
}