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
    private readonly List<int> _rssiSamples = new();
    private readonly object _lock = new();

    private bool _isWorkstationLocked = false;

    private const int RSSI_GOOD = -60;
    private const int RSSI_DEGRADED = -70;
    private const int RSSI_LOCK = -80;
    private const int SAMPLE_INTERVAL_MS = 200;
    private const int SAMPLES_PER_SECOND = 5;

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public void Start() => StartScanning();

    private void StartScanning()
    {
        // Use the name from your Windows Settings screenshot
        string targetName = "Tirth's S25 FE";

        // Broaden filter to find the device regardless of state
        string aqsFilter = $"System.ItemNameDisplay:~~\"{targetName}\" OR System.Devices.Aep.ProtocolId:=\"{{bb7bb05e-5972-42b5-94fc-76eaa7084d49}}\"";

        string[] requestedProperties = {
            "System.Devices.Aep.DeviceAddress",
            "System.Devices.Aep.SignalStrength",
            "System.Devices.Aep.IsConnected"
        };

        _deviceWatcher = DeviceInformation.CreateWatcher(
            aqsFilter,
            requestedProperties,
            DeviceInformationKind.AssociationEndpoint);

        _deviceWatcher.Added += OnDeviceAdded;
        // CRITICAL: Handle updates for devices that are already "Known" or "Connected"
        _deviceWatcher.Updated += OnDeviceUpdated;

        _deviceWatcher.Start();
        _logger.Info($"BLE scanning started for {targetName}...");
    }

    private async void OnDeviceAdded(DeviceWatcher sender, DeviceInformation args)
    {
        // BLOCK CLASSIC IDS: They start with "Bluetooth#". We only want "BluetoothLE#"
        if (!args.Id.Contains("BluetoothLE")) return;

        // Check for either the phone's name or the nRF name
        if (args.Name.Contains("Tirth") || args.Name.Contains("TetherPhone"))
        {
            _logger.Info($"Found valid BLE Device: {args.Name}");
            await InitializeDevice(args.Id);
        }
    }

    private async void OnDeviceUpdated(DeviceWatcher sender, DeviceInformationUpdate args)
    {
        // BLOCK CLASSIC IDS
        if (!args.Id.Contains("BluetoothLE")) return;

        if (_device == null)
        {
            var deviceDoc = await DeviceInformation.CreateFromIdAsync(args.Id);
            if (deviceDoc.Name.Contains("Tirth") || deviceDoc.Name.Contains("TetherPhone"))
            {
                await InitializeDevice(args.Id);
            }
        }
    }

    private async Task InitializeDevice(string deviceId)
    {
        if (_device != null && _device.ConnectionStatus == BluetoothConnectionStatus.Connected) return;

        try
        {
            _logger.Info($"Initializing BLE session for {deviceId}...");
            _device = await BluetoothLEDevice.FromIdAsync(deviceId);

            if (_device == null) return;

            // --- NEW: FORCED PAIRING CHECK ---
            if (_device.DeviceInformation.Pairing.CanPair && !_device.DeviceInformation.Pairing.IsPaired)
            {
                _logger.Warning("Device is not paired. Requesting custom pairing...");
                // This tells Windows to perform a "Just Works" pairing
                var result = await _device.DeviceInformation.Pairing.Custom.PairAsync(DevicePairingKinds.ConfirmOnly);
                _logger.Info($"Pairing result: {result.Status}");
            }

            // --- NEW: ACCESS CONSENT ---
            // Sometimes Windows needs a nudge to know we have permission to use the radio
            var accessStatus = await _device.RequestAccessAsync();
            _logger.Info($"Access status: {accessStatus}");

            // Attempt to connect by pulling services
            _logger.Info("Negotiating LE Link...");
            var servicesResult = await _device.GetGattServicesAsync(BluetoothCacheMode.Uncached);

            if (servicesResult.Status == GattCommunicationStatus.Success)
            {
                _logger.Info("SUCCESS: GATT Services discovered. Link is LIVE.");
                _device.ConnectionStatusChanged += OnConnectionStatusChanged;
                _isWorkstationLocked = false;

                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });
                StartRssiMonitoring();
            }
            else
            {
                _logger.Warning($"Gatt Error: {servicesResult.Status}. (Check if nRF Connect Advertiser is still running)");
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Hard Init failed: {ex.Message}");
            _device = null;
        }
    }

    private void StartRssiMonitoring()
    {
        lock (_lock) { _rssiSamples.Clear(); }
        _rssiTimer?.Dispose();
        _rssiTimer = new Timer(async _ => await SampleAndAverage(), null, 0, SAMPLE_INTERVAL_MS);
    }

    private async Task SampleAndAverage()
    {
        if (_device == null)
        {
            _logger.Warning("RSSI Check: Device is null");
            StopRssiMonitoring();
            return;
        }

        if (_device.ConnectionStatus != BluetoothConnectionStatus.Connected)
        {
            _logger.Warning($"RSSI Check: Device status is {_device.ConnectionStatus}");
            StopRssiMonitoring();
            return;
        }

        try
        {
            string rssiProperty = "System.Devices.Aep.SignalStrength";

            // Explicitly requesting the property from the AEP (Association Endpoint)
            var deviceUpdate = await DeviceInformation.CreateFromIdAsync(
                _device.DeviceId,
                new[] { rssiProperty },
                DeviceInformationKind.AssociationEndpoint);

            if (deviceUpdate.Properties.TryGetValue(rssiProperty, out object? rssiValue))
            {
                if (rssiValue is int currentRssi)
                {
                    lock (_lock)
                    {
                        _rssiSamples.Add(currentRssi);
                        // Log EVERY sample so we know the timer is actually working
                        _logger.Info($"Raw RSSI Sample: {currentRssi} dBm");

                        if (_rssiSamples.Count >= SAMPLES_PER_SECOND)
                        {
                            double avg = _rssiSamples.Average();
                            _rssiSamples.Clear();
                            EvaluateProximity(avg);
                        }
                    }
                }
                else
                {
                    _logger.Warning($"RSSI Property found but was unexpected type: {rssiValue?.GetType().Name}");
                }
            }
            else
            {
                // This is the most common failure point
                _logger.Debug("RSSI property not available in this cycle.");
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"RSSI Loop Error: {ex.Message}");
        }
    }

    private void EvaluateProximity(double avg)
    {
        // Always show the average in the console
        _logger.Info($">>> Average RSSI (1s): {avg:F0} dBm <<<");

        if (avg <= RSSI_LOCK && !_isWorkstationLocked)
        {
            _isWorkstationLocked = true;
            _logger.Warning($"RSSI CRITICAL: {avg:F0} <= {RSSI_LOCK}. LOCKING.");
            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.TRUST_LOST,
                Source = "BleManager",
                PayloadJson = $"{{\"RSSI\":{avg:F0}}}"
            });
            LockWorkStation();
        }
        else if (avg >= RSSI_GOOD && _isWorkstationLocked)
        {
            _isWorkstationLocked = false;
            _logger.Info($"RSSI RECOVERED: {avg:F0} >= {RSSI_GOOD}. UNLOCKING STATE.");
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
        }
    }

    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        if (sender.ConnectionStatus != BluetoothConnectionStatus.Connected && !_isWorkstationLocked)
        {
            _isWorkstationLocked = true;
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });
            LockWorkStation();
            StopRssiMonitoring();
        }
    }

    private void StopRssiMonitoring()
    {
        _rssiTimer?.Dispose();
        _rssiTimer = null;
    }

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public void Stop()
    {
        _deviceWatcher?.Stop();
        _rssiTimer?.Dispose();
        _device?.Dispose();
    }

    public void Dispose() => Stop();
}