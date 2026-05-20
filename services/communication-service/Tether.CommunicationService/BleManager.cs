using System.Runtime.InteropServices;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Enumeration;
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
    private string? _connectedDeviceId;
    private int _reconnectAttempts = 0;
    private const int MAX_RECONNECT_ATTEMPTS = 5;

    private const int RSSI_GOOD = -50;
    private const int RSSI_WARNING = -65;
    private const int RSSI_LOCK = -75;

    private const int SAMPLE_INTERVAL_MS = 500;
    private const int SAMPLES_PER_AVERAGE = 5;
    private const int CONNECTION_CHECK_INTERVAL_MS = 10000;

    // CHANGE THIS to match what you see in the logs!
    private const string TARGET_DEVICE_NAME = "Tirth's S25 FE";

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
        // LOG EVERY DEVICE FOUND - CRITICAL FOR DEBUGGING
        _logger.Info($"🔍 DEVICE FOUND: Name='{args.Name}', ID={args.Id}");

        // Log all properties for debugging
        foreach (var prop in args.Properties)
        {
            _logger.Debug($"  Property: {prop.Key} = {prop.Value}");
        }

        // Check if connectable
        bool isConnectable = false;
        if (args.Properties.TryGetValue("System.Devices.Aep.Bluetooth.Le.IsConnectable", out object? connectableValue))
        {
            isConnectable = connectableValue as bool? ?? false;
            _logger.Info($"  Is Connectable: {isConnectable}");
        }

        if (!isConnectable)
        {
            _logger.Debug($"  Skipping {args.Name} - not connectable");
            return;
        }

        // Try to match by name
        bool isTargetDevice = false;

        if (!string.IsNullOrEmpty(args.Name))
        {
            _logger.Info($"  Checking name match: '{args.Name}' contains '{TARGET_DEVICE_NAME}'?");

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
        else
        {
            _logger.Info($"  ❌ Not target device, ignoring");
        }
    }

    private void OnDeviceUpdated(DeviceWatcher sender, DeviceInformationUpdate args)
    {
        _logger.Debug($"Device updated: {args.Id}");

        if (_device != null && _device.DeviceId == args.Id)
            return;

        if (_connectedDeviceId != null && args.Id == _connectedDeviceId)
        {
            _logger.Info($"Device {_connectedDeviceId} updated, attempting connection...");
            // We need to get the full DeviceInformation to check the name
            _ = Task.Run(async () =>
            {
                var deviceInfo = await DeviceInformation.CreateFromIdAsync(args.Id);
                if (deviceInfo != null && !string.IsNullOrEmpty(deviceInfo.Name))
                {
                    if (deviceInfo.Name.Contains(TARGET_DEVICE_NAME, StringComparison.OrdinalIgnoreCase))
                    {
                        ConnectToDevice(args.Id);
                    }
                }
            });
        }
    }

    private void OnDeviceRemoved(DeviceWatcher sender, DeviceInformationUpdate args)
    {
        _logger.Info($"Device removed: {args.Id}");
        if (_device != null && _device.DeviceId == args.Id)
        {
            _logger.Warning($"Target device removed from enumeration");
            HandleDisconnection();
        }
    }

    private void OnEnumerationCompleted(DeviceWatcher sender, object args)
    {
        _logger.Info("Device enumeration completed - continuing to listen for new devices");
        // Keep the watcher running - it will still fire Added events for new devices
    }

    private async void ConnectToDevice(string deviceId)
    {
        if (_device != null && _device.ConnectionStatus == BluetoothConnectionStatus.Connected)
        {
            _logger.Info("Already connected to a device");
            return;
        }

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

            _logger.Info($"Device name: {_device.Name}");
            _logger.Info($"Device connection status: {_device.ConnectionStatus}");

            _device.ConnectionStatusChanged += OnConnectionStatusChanged;

            var accessStatus = await _device.RequestAccessAsync();
            _logger.Info($"Device access status: {accessStatus}");

            if (accessStatus != DeviceAccessStatus.Allowed)
            {
                _logger.Error($"Access to device not allowed: {accessStatus}");
                return;
            }

            _logger.Info("Discovering GATT services...");
            var servicesResult = await _device.GetGattServicesAsync(BluetoothCacheMode.Uncached);

            if (servicesResult.Status == GattCommunicationStatus.Success)
            {
                _logger.Info($"✅ Successfully connected! Found {servicesResult.Services.Count} services");
                foreach (var service in servicesResult.Services)
                {
                    _logger.Debug($"  Service: {service.Uuid}");
                }

                _isConnected = true;
                _connectedDeviceId = deviceId;
                _reconnectAttempts = 0;

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
                _logger.Error($"  This usually means the device is not advertising as connectable");
                _logger.Error($"  Make sure nRF Connect has 'Connectable' checkbox ENABLED");
                HandleDisconnection();
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Connection error: {ex.Message}");
            _logger.Error($"Stack trace: {ex.StackTrace}");
            HandleDisconnection();
        }
    }

    private void StartRssiMonitoring()
    {
        lock (_lock)
        {
            _rssiSamples.Clear();
        }

        _rssiTimer?.Dispose();
        _rssiTimer = new Timer(async _ => await SampleRssi(), null, 0, SAMPLE_INTERVAL_MS);
        _logger.Info("RSSI monitoring started");
    }

    private async Task SampleRssi()
    {
        if (_device == null || _device.ConnectionStatus != BluetoothConnectionStatus.Connected)
        {
            if (_isConnected)
            {
                _logger.Warning("Device disconnected during RSSI sampling");
                HandleDisconnection();
            }
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
                    _logger.Debug($"RSSI sample: {currentRssi} dBm");

                    if (_rssiSamples.Count >= SAMPLES_PER_AVERAGE)
                    {
                        double avgRssi = _rssiSamples.Average();
                        _rssiSamples.Clear();

                        _logger.Info($"📊 Average RSSI: {avgRssi:F0} dBm");
                        EvaluateProximity(avgRssi);
                    }
                }
            }
            else
            {
                _logger.Debug("RSSI property not available in this sample");
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
                _logger.Info($"✅ Signal restored: {avgRssi:F0} dBm");
                _isWorkstationLocked = false;
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.TRUST_RESTORED,
                    Source = "BleManager",
                    PayloadJson = $"{{\"RSSI\":{avgRssi:F0}}}"
                });
            }
            return;
        }

        if (avgRssi <= RSSI_WARNING && avgRssi > RSSI_LOCK)
        {
            _logger.Warning($"⚠️ Signal weak: {avgRssi:F0} dBm");
            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.TRUST_DEGRADED,
                Source = "BleManager",
                PayloadJson = $"{{\"RSSI\":{avgRssi:F0}}}"
            });
        }

        if (avgRssi <= RSSI_LOCK)
        {
            _logger.Error($"🔒 SIGNAL LOST: {avgRssi:F0} dBm <= {RSSI_LOCK}. LOCKING WORKSTATION!");

            _isWorkstationLocked = true;

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.TRUST_LOST,
                Source = "BleManager",
                PayloadJson = $"{{\"RSSI\":{avgRssi:F0}}}"
            });

            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PANIC_TRIGGERED,
                Source = "BleManager",
                PayloadJson = $"{{\"Reason\":\"RSSI threshold exceeded\",\"RSSI\":{avgRssi:F0}}}"
            });

            LockWorkStation();
        }
    }

    private void StartConnectionMonitoring()
    {
        _connectionMonitorTimer?.Dispose();
        _connectionMonitorTimer = new Timer(async _ => await CheckConnection(), null, CONNECTION_CHECK_INTERVAL_MS, CONNECTION_CHECK_INTERVAL_MS);
        _logger.Info("Connection monitoring started");
    }

    private async Task CheckConnection()
    {
        if (_device == null)
        {
            if (_isConnected)
            {
                _logger.Warning("Device is null but marked as connected");
                HandleDisconnection();
            }
            return;
        }

        if (_device.ConnectionStatus != BluetoothConnectionStatus.Connected)
        {
            _logger.Warning($"Device connection lost (status: {_device.ConnectionStatus})");
            HandleDisconnection();
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
                _logger.Debug($"Connection check passed, RSSI: {Convert.ToInt32(rssiValue)} dBm");
            }
            else
            {
                _logger.Debug("Connection check: RSSI property not available");
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"Connection check error: {ex.Message}");
        }
    }

    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        _logger.Info($"Connection status changed: {sender.ConnectionStatus}");

        if (sender.ConnectionStatus != BluetoothConnectionStatus.Connected && _isConnected)
        {
            HandleDisconnection();
        }
        else if (sender.ConnectionStatus == BluetoothConnectionStatus.Connected && !_isConnected)
        {
            _logger.Info("Device reconnected!");
            _isConnected = true;
            _reconnectAttempts = 0;
            StartRssiMonitoring();
        }
    }

    private void HandleDisconnection()
    {
        if (!_isConnected)
            return;

        _logger.Warning("Handling disconnection...");
        _isConnected = false;
        _isWorkstationLocked = false;

        StopRssiMonitoring();

        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PHONE_DISCONNECTED,
            Source = "BleManager"
        });

        _logger.Error("🔒 Device disconnected - LOCKING WORKSTATION!");
        LockWorkStation();

        if (_reconnectAttempts < MAX_RECONNECT_ATTEMPTS && _connectedDeviceId != null)
        {
            _reconnectAttempts++;
            _logger.Info($"Attempting to reconnect ({_reconnectAttempts}/{MAX_RECONNECT_ATTEMPTS})...");

            Task.Delay(5000).ContinueWith(_ =>
            {
                if (_connectedDeviceId != null && (_device == null || _device.ConnectionStatus != BluetoothConnectionStatus.Connected))
                {
                    ConnectToDevice(_connectedDeviceId);
                }
            });
        }
        else if (_reconnectAttempts >= MAX_RECONNECT_ATTEMPTS)
        {
            _logger.Error("Max reconnection attempts reached. Will continue scanning for device.");
            _connectedDeviceId = null;
            _reconnectAttempts = 0;
            if (_deviceWatcher?.Status != DeviceWatcherStatus.Started)
            {
                StartScanning();
            }
        }
    }

    private void StopRssiMonitoring()
    {
        _rssiTimer?.Dispose();
        _rssiTimer = null;
        _connectionMonitorTimer?.Dispose();
        _connectionMonitorTimer = null;
        _logger.Info("RSSI and connection monitoring stopped");
    }

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public void Stop()
    {
        _logger.Info("Stopping BLE Manager...");
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
        _logger.Info("BLE Manager stopped");
    }

    public void Dispose()
    {
        Stop();
    }
}