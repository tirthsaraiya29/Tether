using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
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
    private GattCharacteristic? _pingChar;
    private GattCharacteristic? _pongChar;
    private Timer? _heartbeatTimer;
    private int _missedPongs = 0;
    private const int PING_INTERVAL_MS = 2000;
    private const int MAX_MISSED_PONGS = 2;  // Lock after ~4 seconds without response

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public void Start()
    {
        _logger.Info("Starting BLE heartbeat proximity monitor...");
        StartScanning();
    }

    private void StartScanning()
    {
        string[] requestedProperties = { "System.Devices.Aep.DeviceAddress" };
        _deviceWatcher = DeviceInformation.CreateWatcher(
            "(System.Devices.Aep.ProtocolId:=\"{bb7bb05e-5972-42b5-94fc-76eaa7084d49}\")",
            requestedProperties,
            DeviceInformationKind.AssociationEndpoint);

        _deviceWatcher.Added += OnDeviceAdded;
        _deviceWatcher.Start();
        _logger.Info("BLE scanning started");
    }

    private async void OnDeviceAdded(DeviceWatcher sender, DeviceInformation args)
    {
        // Filter by name (case-insensitive is safer)
        if (args.Name == null || !args.Name.Contains("TetherPhone", StringComparison.OrdinalIgnoreCase)) return;

        _logger.Info($"Found Tether phone: {args.Name}");
        try
        {
            // Use the ID directly instead of parsing the address manually
            _device = await BluetoothLEDevice.FromIdAsync(args.Id);
            if (_device == null) return;

            _device.ConnectionStatusChanged += OnConnectionStatusChanged;

            // Discover GATT service
            var services = await _device.GetGattServicesForUuidAsync(Guid.Parse("0000ffe0-0000-1000-8000-00805f9b34fb"));
            if (services.Status != GattCommunicationStatus.Success || services.Services.Count == 0)
            {
                _logger.Error("Tether service not found on phone");
                return;
            }

            var service = services.Services[0];
            var characteristics = await service.GetCharacteristicsAsync();

            foreach (var c in characteristics.Characteristics)
            {
                if (c.Uuid.ToString().ToUpper() == "0000ffe1-0000-1000-8000-00805f9b34fb")
                    _pingChar = c;
                else if (c.Uuid.ToString().ToUpper() == "0000ffe2-0000-1000-8000-00805f9b34fb")
                    _pongChar = c;
            }

            if (_pingChar == null || _pongChar == null)
            {
                _logger.Error("Ping or pong characteristic missing");
                return;
            }

            // Subscribe to pong notifications
            _pongChar.ValueChanged += OnPongReceived;
            await _pongChar.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue.Notify);

            _logger.Info($"Connected to {_device.Name}. Starting heartbeat.");
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "BleManager" });

            StartHeartbeat();
        }
        catch (Exception ex)
        {
            _logger.Error($"BLE connection error: {ex.Message}");
        }
    }

    private void StartHeartbeat()
    {
        _missedPongs = 0;
        _heartbeatTimer?.Dispose();
        _heartbeatTimer = new Timer(async _ => await SendPing(), null, 0, PING_INTERVAL_MS);
    }

    private async Task SendPing()
    {
        if (_pingChar == null || _device?.ConnectionStatus != BluetoothConnectionStatus.Connected)
        {
            HandleDisconnection();
            return;
        }

        try
        {
            var pingData = Encoding.UTF8.GetBytes("ping");
            await _pingChar.WriteValueAsync(pingData.AsBuffer());
            _logger.Debug("Ping sent");

            // Increment missed pongs; will be reset when pong received
            lock (this) { _missedPongs++; }

            if (_missedPongs >= MAX_MISSED_PONGS)
            {
                _logger.Warning($"No pong after {_missedPongs} attempts – locking workstation");
                _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_LOST, Source = "BleManager" });
                LockWorkStation();
                StopHeartbeat();
            }
        }
        catch (Exception ex) { _logger.Error($"Ping failed: {ex.Message}"); }
    }

    private void OnPongReceived(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        var reader = DataReader.FromBuffer(args.CharacteristicValue);
        byte[] data = new byte[reader.UnconsumedBufferLength];
        reader.ReadBytes(data);
        string response = Encoding.UTF8.GetString(data);
        if (response == "pong")
        {
            lock (this) { _missedPongs = 0; }
            _logger.Debug("Pong received – phone in range");
            // Optionally publish TRUST_RESTORED if previously degraded
            _eventBus.Publish(new TetherEvent { EventType = TetherEventType.TRUST_RESTORED, Source = "BleManager" });
        }
    }

    private void OnConnectionStatusChanged(BluetoothLEDevice sender, object args)
    {
        if (sender.ConnectionStatus != BluetoothConnectionStatus.Connected)
        {
            HandleDisconnection();
        }
    }

    private void HandleDisconnection()
    {
        _logger.Warning("Phone disconnected – immediate lock");
        _eventBus.Publish(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "BleManager" });
        LockWorkStation();
        StopHeartbeat();
    }

    private void StopHeartbeat()
    {
        _heartbeatTimer?.Dispose();
        _heartbeatTimer = null;
    }

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public void Stop()
    {
        _deviceWatcher?.Stop();
        _heartbeatTimer?.Dispose();
        _device?.Dispose();
        _logger.Info("BLE manager stopped");
    }

    public void Dispose() => Stop();
}