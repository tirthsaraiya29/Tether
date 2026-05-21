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
    private Timer? _connectionMonitorTimer;
    private readonly List<int> _rssiSamples = new();
    private readonly object _lock = new();
    private bool _isWorkstationLocked = false;
    private bool _isConnected = false;
    private bool _isConnecting = false;
    private string? _connectedDeviceId;

    private const int RSSI_GOOD = -50;
    private const int RSSI_WARNING = -65;
    private const int RSSI_LOCK = -75;

    private const int SAMPLE_INTERVAL_MS = 500;
    private const int SAMPLES_PER_AVERAGE = 5;
    private const int CONNECTION_CHECK_INTERVAL_MS = 10000;

    private const string TARGET_DEVICE_NAME = "Tirth's S25 FE";
    private readonly Guid PANIC_CHAR_UUID = new Guid("0000FFE2-0000-1000-8000-00805F9B34FB");

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public void Start()
    {
        _logger.Info($"BLE Manager starting - looking for device: '{TARGET_DEVICE_NAME}'");
        StartScanning();
    }

    private void StartScanning()
    {
        string aqsFilter = "System.Devices.Aep.ProtocolId:=\"{bb7bb05e-5972-42b5-94fc-76eaa7084d49}\"";

        string[] requestedProperties = {
            "System.Devices.Aep.DeviceAddress",
            "System.Devices.Aep.Bluetooth.Le.IsConnectable",
            "System.Devices.Aep.SignalStrength",
            "System.Devices.Aep.IsConnected",
            "System.ItemNameDisplay"
        };

        _deviceWatcher = DeviceInformation.CreateWatcher(
            aqsFilter,
            requestedProperties,
            DeviceInformationKind.AssociationEndpoint);

        _deviceWatcher.Added += OnDeviceAdded;
        _deviceWatcher.Updated += OnDeviceUpdated;
        _deviceWatcher.Removed += OnDeviceRemoved;
        _deviceWatcher.EnumerationCompleted += OnEnumerationCompleted;

        _deviceWatcher.Start();
        _logger.Info("BLE scanning started...");
    }

    private void OnDeviceAdded(DeviceWatcher sender, DeviceInformation args)
    {
        _logger.Info($"🔍 DEVICE FOUND: Name='{args.Name}', ID={args.Id}");

        // If we are already pinned to a specific device, ignore everything else
        if (_connectedDeviceId != null && args.Id != _connectedDeviceId)
        {
            return;
        }

        bool isConnectable = false;
        if (args.Properties.TryGetValue("System.Devices.Aep.Bluetooth.Le.IsConnectable", out object? connectableValue))
        {
            isConnectable = connectableValue as bool? ?? false;
        }

        if (!isConnectable) return;

        bool isTargetDevice = false;

        // Either match by pinned ID, or initial name scan
        if (_connectedDeviceId != null && args.Id == _connectedDeviceId)
        {
            isTargetDevice = true;
        }
        else if (string.IsNullOrEmpty(_connectedDeviceId) && !string.IsNullOrEmpty(args.Name))
        {
            if (args.Name.Contains(TARGET_DEVICE_NAME, StringComparison.OrdinalIgnoreCase))
            {
                isTargetDevice = true;
                _logger.Info($"  ✅ NAME MATCHED! Found target device: '{args.Name}'");
            }
        }

        if (isTargetDevice)
        {
            _logger.Info($"🎯 CONNECTING to {args.Name}...");
            ConnectToDevice(args.Id);
        }
    }

    private void OnDeviceUpdated(DeviceWatcher sender, DeviceInformationUpdate args)
    {
        if (_device != null && _device.DeviceId == args.Id) return;

        if (_connectedDeviceId != null && args.Id == _connectedDeviceId)
        {
            _logger.Info($"Pinned device {_connectedDeviceId} updated, attempting connection...");
            ConnectToDevice(args.Id);
        }
    }

    private void OnDeviceRemoved(DeviceWatcher sender, DeviceInformationUpdate args)
    {
        if (_device != null && _device.DeviceId == args.Id)
        {
            _logger.Warning($"Target device removed from enumeration");
            HandleDisconnection();
        }
    }

    private void OnEnumerationCompleted(DeviceWatcher sender, object args)
    {
        _logger.Info("Device enumeration completed - continuing to listen for new devices");
    }

    private async void ConnectToDevice(string deviceId)
    {
        if (_isConnected || _isConnecting) return;

        _isConnecting = true;

        try
        {
            _logger.Info($"Connecting to device: {deviceId}");

            _device?.Dispose();
            _device = null;

            _device = await BluetoothLEDevice.FromIdAsync(deviceId);

            if (_device == null)
            {
                _logger.Error("Failed to create BluetoothLEDevice object");
                return;
            }

            _device.ConnectionStatusChanged += OnConnectionStatusChanged;

            var accessStatus = await _device.RequestAccessAsync();
            if (accessStatus != DeviceAccessStatus.Allowed)
            {
                _logger.Error($"Access to device not allowed: {accessStatus}");
                return;
            }

            var servicesResult = await _device.GetGattServicesAsync(BluetoothCacheMode.Uncached);

            if (servicesResult.Status == GattCommunicationStatus.Success)
            {
                _logger.Info($"✅ Successfully connected!");

                _isConnected = true;
                _connectedDeviceId = deviceId; // Pin the device

                // Setup Panic Subscription
                foreach (var service in servicesResult.Services)
                {
                    var charResult = await service.GetCharacteristicsForUuidAsync(PANIC_CHAR_UUID);
                    if (charResult.Status == GattCommunicationStatus.Success && charResult.Characteristics.Count > 0)
                    {
                        var panicChar = charResult.Characteristics[0];
                        panicChar.ValueChanged += PanicChar_ValueChanged;
                        await panicChar.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
                        _logger.Info("Subscribed to Panic Characteristic Notifications");
                    }
                }

                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.PHONE_CONNECTED,
                    Source = "BleManager",
                    PayloadJson = $"{{\"DeviceName\":\"{_device.Name}\"}}"
                });

                StartRssiMonitoring();
                StartConnectionMonitoring();
            }
            else
            {
                _logger.Error($"Failed to discover GATT services: {servicesResult.Status}");
                HandleDisconnection();
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Connection error: {ex.Message}");
            HandleDisconnection();
        }
        finally
        {
            _isConnecting = false;
        }
    }

    private void PanicChar_ValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        var reader = DataReader.FromBuffer(args.CharacteristicValue);
        byte[] data = new byte[reader.UnconsumedBufferLength];
        reader.ReadBytes(data);

        if (data.Length > 0 && data[0] == 0x01)
        {
            _logger.Error("🚨 PANIC TRIGGERED BY PHONE!");
            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PANIC_TRIGGERED,
                Source = "BleManager"
            });
            LockWorkStation();
        }
    }

    private void StartRssiMonitoring()
    {
        lock (_lock) { _rssiSamples.Clear(); }
        _rssiTimer?.Dispose();
        _rssiTimer = new Timer(async _ => await SampleRssi(), null, 0, SAMPLE_INTERVAL_MS);
    }

    private async Task SampleRssi()
    {
        if (_device == null || _device.ConnectionStatus != BluetoothConnectionStatus.Connected)
        {
            if (_isConnected) HandleDisconnection();
            return;
        }

        try
        {
            var deviceInfo = await DeviceInformation.CreateFromIdAsync(
                _device.DeviceId,
                new[] { "System.Devices.Aep.SignalStrength" },
                DeviceInformationKind.AssociationEndpoint);

            if (deviceInfo.Properties.TryGetValue("System.Devices.Aep.SignalStrength", out object? rssiValue))
            {
                int currentRssi = Convert.ToInt32(rssiValue);

                lock (_lock)
                {
                    _rssiSamples.Add(currentRssi);
                    if (_rssiSamples.Count >= SAMPLES_PER_AVERAGE)
                    {
                        double avgRssi = _rssiSamples.Average();
                        _rssiSamples.Clear();
                        EvaluateProximity(avgRssi);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"RSSI sampling error: {ex.Message}");
        }
    }

    private void EvaluateProximity(double avgRssi)
    {
        if (_isWorkstationLocked)
        {
            if (avgRssi >= RSSI_GOOD)
            {
                _isWorkstationLocked = false;
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager", PayloadJson = $"{{\"RSSI\":{avgRssi:F0}}}" });
            }
            return;
        }

        if (avgRssi <= RSSI_WARNING && avgRssi > RSSI_LOCK)
        {
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_DEGRADED, Source = "BleManager", PayloadJson = $"{{\"RSSI\":{avgRssi:F0}}}" });
        }

        if (avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 SIGNAL LOST: {avgRssi:F0} dBm <= {RSSI_LOCK}. LOCKING WORKSTATION!");
            _isWorkstationLocked = true;

            // Notice PANIC is removed from here. Only TRUST_LOST happens.
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager", PayloadJson = $"{{\"RSSI\":{avgRssi:F0}}}" });
            LockWorkStation();
        }
    }

    private void StartConnectionMonitoring()
    {
        _connectionMonitorTimer?.Dispose();
        _connectionMonitorTimer = new Timer(async _ => await CheckConnection(), null, CONNECTION_CHECK_INTERVAL_MS, CONNECTION_CHECK_INTERVAL_MS);
    }

    private async Task CheckConnection()
    {
        if (_device == null || _device.ConnectionStatus != BluetoothConnectionStatus.Connected)
        {
            if (_isConnected) HandleDisconnection();
        }
    }

    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        if (sender.ConnectionStatus != BluetoothConnectionStatus.Connected && _isConnected)
        {
            HandleDisconnection();
        }
    }

    private void HandleDisconnection()
    {
        if (!_isConnected) return;

        _logger.Warning("Handling disconnection...");
        _isConnected = false;
        _isWorkstationLocked = false; // Reset for when it reconnects

        StopRssiMonitoring();

        _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });

        _logger.Error("🔒 Device disconnected - LOCKING WORKSTATION!");
        LockWorkStation();

        // INFINITE RECONNECT TO PINNED DEVICE
        if (_connectedDeviceId != null)
        {
            _logger.Info($"Pinned to {_connectedDeviceId}. Entering infinite reconnect loop...");
            Task.Run(ReconnectLoopAsync);
        }
    }

    private async Task ReconnectLoopAsync()
    {
        while (!_isConnected && _connectedDeviceId != null)
        {
            await Task.Delay(3000); // Poll every 3 seconds
            if (!_isConnected && _connectedDeviceId != null && !_isConnecting)
            {
                ConnectToDevice(_connectedDeviceId);
            }
        }
    }

    private void StopRssiMonitoring()
    {
        _rssiTimer?.Dispose();
        _rssiTimer = null;
        _connectionMonitorTimer?.Dispose();
        _connectionMonitorTimer = null;
    }

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public void Stop()
    {
        if (_deviceWatcher != null)
        {
            _deviceWatcher.Stop();
            _deviceWatcher = null;
        }
        StopRssiMonitoring();
        if (_device != null)
        {
            _device.ConnectionStatusChanged -= OnConnectionStatusChanged;
            _device.Dispose();
            _device = null;
        }
        _isConnected = false;
        _connectedDeviceId = null; // Clear pinning on intentional stop
    }

    public void Dispose() => Stop();
}