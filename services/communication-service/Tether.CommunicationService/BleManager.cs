using System.Runtime.InteropServices;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Enumeration;
using Windows.Storage.Streams;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService;

public class BleManager : IDisposable
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private DeviceWatcher? _deviceWatcher;
    private BluetoothLEDevice? _device;
    private Timer? _rssiTimer;
    private readonly List<int> _rssiSamples = new();
    private readonly object _lock = new();

    private bool _isWorkstationLocked = false;
    private bool _isConnected = false;
    private string? _currentConnectingId;

    // Configuration Thresholds
    private const int RSSI_GOOD = -50;
    private const int RSSI_LOCK = -75;
    private const int SAMPLE_INTERVAL_MS = 500;
    private const int SAMPLES_PER_AVERAGE = 5;

    // Target Identification
    private const string TARGET_DEVICE_NAME = "Tirth's S25 FE";
    private readonly Guid PANIC_CHAR_UUID = new Guid("0000FFE2-0000-1000-8000-00805F9B34FB");

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public async void Start()
    {
        _logger.Info($"BLE Manager starting - target: '{TARGET_DEVICE_NAME}'");

        // Add 'await' here and ensure the method is 'async'
        await UnpairTargetDeviceAsync();

        StartScanning();
    }

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
        _logger.Info("BLE scanner active and watching for advertisements...");
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
        LockWorkStation();

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
            _logger.Error("🚨 PANIC RECEIVED FROM PHONE!");
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PANIC_TRIGGERED, Source = "BleManager" });
            LockWorkStation();
        }
    }

    private void StartRssiMonitoring()
    {
        _rssiTimer?.Dispose();
        _rssiTimer = new Timer(async _ => await SampleRssi(), null, 0, SAMPLE_INTERVAL_MS);
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
        if (_isWorkstationLocked && avgRssi >= RSSI_GOOD)
        {
            _logger.Info($"✅ Welcome back: {avgRssi:F0} dBm");
            _isWorkstationLocked = false;
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
            return;
        }

        if (!_isWorkstationLocked && avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 Signal lost: {avgRssi:F0} dBm. Locking.");
            _isWorkstationLocked = true;
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
            LockWorkStation();
        }
    }

    private void StopRssiMonitoring() => _rssiTimer?.Dispose();

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public void Stop()
    {
        _deviceWatcher?.Stop();
        CleanupDevice();
    }

    public void Dispose() => Stop();
}