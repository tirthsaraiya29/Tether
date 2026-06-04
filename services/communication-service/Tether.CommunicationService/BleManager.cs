using System.ComponentModel;
using System.Diagnostics;
using System.Numerics;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using System.Timers;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement; // Added for the Broadcast Watcher
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Enumeration;
using Windows.Graphics;
using Windows.Storage.Streams;
using Windows.System;
using Windows.UI.Composition;
using static System.Net.Mime.MediaTypeNames;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Tether.CommunicationService;

public class BleManager : IDisposable
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private DeviceWatcher? _deviceWatcher;
    private BluetoothLEAdvertisementWatcher? _advWatcher; // Added: New Broadcast Sniffer
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

    // Target Identification
    private const string TARGET_DEVICE_NAME = "Tirth's S25 FE";
    private readonly Guid PANIC_CHAR_UUID = new Guid("0000FFE2-0000-1000-8000-00805F9B34FB");

    // Added: Broadcast Protocol Constants
    private const ushort TARGET_MANUFACTURER_ID = 0xFFFF;
    private const byte DEVICE_ID = 0x01;
    private const byte STATE_IDLE = 0x00;
    private const byte STATE_MANUAL_LOCK = 0x01;
    private const byte STATE_PANIC = 0x02;

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;

        _eventBus.Subscribe(evt => {
            if (evt.EventType == TetherEventType.PHONE_UNLOCKED || evt.EventType == TetherEventType.TRUST_RESTORED)
            {
                lock (_lock)
                {
                    _isWorkstationLocked = false;
                }
            }
        });
    }

    public async void Start()
    {
        _logger.Info($"BLE Manager starting - target: '{TARGET_DEVICE_NAME}'");

        // Add 'await' here and ensure the method is 'async'
        await UnpairTargetDeviceAsync();

        StartScanning(); // Keeps existing GATT scanning
        StartAdvertisementWatcher(); // Starts the parallel broadcast sniffer
    }

    // --- ADDED: NEW BROADCAST SNIFFER LOGIC ---
    private void StartAdvertisementWatcher()
    {
        _advWatcher = new BluetoothLEAdvertisementWatcher
        {
            ScanningMode = BluetoothLEScanningMode.Active
        };

        _advWatcher.Received += OnAdvertisementReceived;
        _advWatcher.Start();
        _logger.Info("📡 BLE Advertisement sniffer active for instant commands...");
    }

    private void OnAdvertisementReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        foreach (var manufacturerData in args.Advertisement.ManufacturerData)
        {
            if (manufacturerData.CompanyId == TARGET_MANUFACTURER_ID)
            {
                ParseTetherPayload(manufacturerData.Data, args.RawSignalStrengthInDBm);
            }
        }
    }

    private void ParseTetherPayload(IBuffer dataBuffer, short rssi)
    {
        var reader = DataReader.FromBuffer(dataBuffer);
        byte[] payload = new byte[reader.UnconsumedBufferLength];
        reader.ReadBytes(payload);

        if (payload.Length >= 2 && payload[0] == DEVICE_ID)
        {
            byte trustState = payload[1];

            EvaluateProximity((double)rssi);

            if (trustState == _lastTrustState) return;
            _lastTrustState = trustState;

            if (trustState == STATE_MANUAL_LOCK)
            {
                TriggerInstantLock("🔒 Manual Lock via Broadcast");
            }
            else if (trustState == STATE_PANIC)
            {
                TriggerInstantLock("🚨 PANIC via Broadcast");
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PANIC_TRIGGERED, Source = "BleManager" });
            }
        }
    }

    private void TriggerInstantLock(string logMessage)
    {
        if (!_isWorkstationLocked)
        {
            _logger.Error(logMessage);
            _isWorkstationLocked = true;
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });

            // FIXED: Stream instant full lock command to the OverlayUI application
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        }
    }
    // --- END NEW BROADCAST LOGIC ---


    // --- EXISTING GATT & PAIRING LOGIC (UNTTOUCHED) ---
    private void StartScanning()
    {
        // Filter for Bluetooth LE Protocol
        string aqsFilter = "System.Devices.Aep.ProtocolId:=\"{bb7bb05e-5972-42b5-94fc-76eaa7084d49}\"";

        string[] requestedProperties = {
            "System.Devices.Aep.Bluetooth.Le.IsConnectable",
            "System.Devices.Aep.SignalStrength",
            "System.ItemNameDisplay"
        };

        _deviceWatcher = DeviceInformation.CreateWatcher(
            aqsFilter,
            requestedProperties,
            DeviceInformationKind.AssociationEndpoint);

        _deviceWatcher.Added += OnDeviceDiscovered;
        _deviceWatcher.Removed += OnDeviceRemoved;
        _deviceWatcher.EnumerationCompleted += (s, e) => _logger.Info("Initial BLE scan complete.");

        _deviceWatcher.Start();
        _logger.Info("BLE scanner active and watching for GATT connections...");
    }

    private void OnDeviceDiscovered(DeviceWatcher sender, DeviceInformation args)
    {
        if (_isConnected || _currentConnectingId != null) return;

        if (!string.IsNullOrEmpty(args.Name) && args.Name.Contains(TARGET_DEVICE_NAME, StringComparison.OrdinalIgnoreCase))
        {
            _logger.Info($"🎯 TARGET FOUND: {args.Name} (ID suffix: {args.Id.Substring(Math.Max(0, args.Id.Length - 5))})");
            ConnectToDevice(args.Id);
        }
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

            // Guard: Check if the phone rotated its ID while we were waiting
            if (_currentConnectingId != deviceId) { device.Dispose(); return; }

            _device = device;
            _device.ConnectionStatusChanged += OnConnectionStatusChanged;

            // Bypass stale Windows GATT cache
            var servicesResult = await _device.GetGattServicesAsync(BluetoothCacheMode.Uncached);

            if (_device == null || _currentConnectingId != deviceId) return;

            if (servicesResult.Status == GattCommunicationStatus.Success)
            {
                _logger.Info($"✅ Connected. Discovering characteristics...");

                foreach (var service in servicesResult.Services)
                {
                    try
                    {
                        var charResult = await service.GetCharacteristicsForUuidAsync(PANIC_CHAR_UUID);
                        if (charResult.Status == GattCommunicationStatus.Success && charResult.Characteristics.Count > 0)
                        {
                            var panicChar = charResult.Characteristics[0];
                            panicChar.ValueChanged += PanicChar_ValueChanged;

                            await panicChar.WriteClientCharacteristicConfigurationDescriptorAsync(
                                GattClientCharacteristicConfigurationDescriptorValue.Notify);

                            _logger.Info("Panic listener active.");
                        }
                    }
                    catch (Exception ex) { _logger.Debug($"GATT characteristic setup skipped: {ex.Message}"); }
                }

                _isConnected = true;
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                StartRssiMonitoring();
            }
            else
            {
                _logger.Error($"GATT discovery failed: {servicesResult.Status}");
                HandleDisconnection();
            }
        }
        catch (TaskCanceledException)
        {
            _logger.Warning("Connection aborted cleanly (device rotated MAC or went out of range).");
            // No need to call HandleDisconnection; it was already called by OnDeviceRemoved
        }
        catch (ObjectDisposedException)
        {
            _logger.Warning("Connection aborted cleanly (device object was disposed).");
        }
        catch (COMException ex)
        {
            _logger.Error($"Connection failed: COM Error 0x{ex.HResult:X} - {ex.Message}");
            HandleDisconnection();
        }
        catch (Exception ex)
        {
            _logger.Error($"Connection failed: {ex.GetType().Name} - {ex.Message}");
            HandleDisconnection();
        }
        finally
        {
            lock (_lock) { _currentConnectingId = null; }
        }
    }

    private async Task UnpairTargetDeviceAsync()
    {
        _logger.Info("Cleaning up existing Windows Bluetooth pairings for a fresh start...");
        try
        {
            // Get the selector for the specific device name
            string aqs = BluetoothLEDevice.GetDeviceSelectorFromDeviceName(TARGET_DEVICE_NAME);

            // Find all paired devices matching that name
            var devices = await DeviceInformation.FindAllAsync(aqs);

            foreach (var device in devices)
            {
                if (device.Pairing.IsPaired)
                {
                    _logger.Warning($"Found existing pairing for {device.Name}. Unpairing internally...");
                    // This forces Windows to drop the stale GATT cache
                    var result = await device.Pairing.UnpairAsync();
                    _logger.Info($"Unpairing status: {result.Status}");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Debug($"Unpairing step skipped: {ex.Message}");
        }
    }

    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        if (sender.ConnectionStatus == BluetoothConnectionStatus.Disconnected)
        {
            _logger.Warning("Physical connection lost reported by OS.");
            HandleDisconnection();
        }
    }

    private void OnDeviceRemoved(DeviceWatcher sender, DeviceInformationUpdate args)
    {
        if (_device?.DeviceId == args.Id || _currentConnectingId == args.Id)
        {
            _logger.Warning("Target device disappeared from BLE scanner.");
            HandleDisconnection();
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
        _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });
        _logger.Error("🔒 LOCKING: Device disconnected.");

        // FIXED: Replaced native LockWorkStation() with Overlay UI activation event
        _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        CleanupDevice();
    }

    private void CleanupDevice()
    {
        if (_device != null)
        {
            _device.ConnectionStatusChanged -= OnConnectionStatusChanged;
            _device.Dispose();
            _device = null;
        }
    }

    private void PanicChar_ValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        var reader = DataReader.FromBuffer(args.CharacteristicValue);
        if (reader.UnconsumedBufferLength > 0 && reader.ReadByte() == 0x01)
        {
            _logger.Error("🚨 PANIC RECEIVED FROM PHONE (VIA GATT)!");
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PANIC_TRIGGERED, Source = "BleManager" });

            // FIXED: Alert your overlay screen rather than dropping the desktop session
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        }
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
        catch { /* Device likely rotated MAC mid-sample */ }
    }

    private void EvaluateProximity(double avgRssi)
    {
        _ = SendUiEventAsync (new TetherEvent { EventType = TetherEventType.TRUST_DEGRADED, Source = "BleManager", PayloadJson = $"{{\"Rssi\":{avgRssi}}}"});
        if (_isWorkstationLocked && avgRssi >= RSSI_GOOD)
        {
            _logger.Info($"✅ Welcome back: {avgRssi:F0} dBm");
            _isWorkstationLocked = false;
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_DISABLED, Source = "BleManager" });
            return;
        }

        if (!_isWorkstationLocked && avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 Signal lost: {avgRssi:F0} dBm. Locking.");
            _isWorkstationLocked = true;
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
            _ = SendUiEventAsync(new TetherEvent { EventType = TetherEventType.OVERLAY_ENABLED, Source = "BleManager" });
        }
    }

    private void StopRssiMonitoring() => _rssiTimer?.Dispose();

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public void Stop()
    {
        _advWatcher?.Stop(); // Added cleanup for the sniffer
        _deviceWatcher?.Stop();
        CleanupDevice();
    }

    public void Dispose() => Stop();

    private void EnsureOverlayProcessRunning(TetherEvent evt)
    {
        // Only spin up the interface if a lock is commanded or if proximity crosses the fade boundary
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
            catch { /* Payload parse fallback */ }
        }

        if (!shouldLaunch) return;

        // Check if the Overlay UI process space is already active on the machine
        var processes = System.Diagnostics.Process.GetProcessesByName("Tether.OverlayUI");
        if (processes.Length > 0) return;

        try
        {
            // FIXED: Using your exact compiled executable path for guaranteed execution
            string exactPath = @"C:\Dev\Tether\Tether.OverlayUI\bin\Debug\net8.0-windows\Tether.OverlayUI.exe";

            if (System.IO.File.Exists(exactPath))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = exactPath,
                    UseShellExecute = true
                });
                _logger.Info($"🚀 Tether.OverlayUI wasn't running. Launched process at: {exactPath}");
            }
            else
            {
                _logger.Error($"❌ Could not find Overlay UI executable at the expected location: {exactPath}");
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to spin up Overlay UI process framework: {ex.Message}");
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
            await client.ConnectAsync(200); // 200ms connection verification window [cite: 738]
            await client.WriteAsync(bytes, 0, bytes.Length); 
            await client.FlushAsync();
            }
        catch
        {
            // Fails silently if the pipe server is booting up or cycling states
        }
    }
}