using System.Collections.Concurrent;
using InTheHand.Net.Bluetooth;
using InTheHand.Net.Sockets;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService;

public class BleManager : IDisposable
{
    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private Thread? _discoveryThread;
    private bool _isRunning;

    private readonly ConcurrentDictionary<string, BluetoothDeviceInfo> _foundDevices = new();

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public void Start()
    {
        try
        {
            using var testClient = new BluetoothClient();
        }
        catch (Exception ex)
        {
            _logger.Error($"Bluetooth unavailable: {ex.Message}");
            return;
        }

        _logger.Info("BLE manager starting with 32feet.NET");

        _isRunning = true;

        _discoveryThread = new Thread(DiscoverDevices);
        _discoveryThread.Start();
    }

    private void DiscoverDevices()
    {
        while (_isRunning)
        {
            try
            {
                _logger.Debug("Scanning for Bluetooth devices...");

                using var client = new BluetoothClient();

                var devices = client.DiscoverDevices();

                foreach (var device in devices)
                {
                    if (device.DeviceName?.Contains("TetherPhone") == true)
                    {
                        var address = device.DeviceAddress.ToString();

                        if (_foundDevices.TryAdd(address, device))
                        {
                            _logger.Info(
                                $"Found Tether phone: {device.DeviceName} - {address}");

                            _eventBus.Publish(new TetherEvent
                            {
                                EventType = TetherEventType.PHONE_CONNECTED,
                                Source = "BleManager",
                                PayloadJson =
                                    $"{{\"DeviceName\":\"{device.DeviceName}\",\"Address\":\"{address}\"}}"
                            });
                        }
                    }
                }

                Thread.Sleep(10000);
            }
            catch (Exception ex)
            {
                _logger.Error($"BLE discovery error: {ex.Message}", ex);
                Thread.Sleep(30000);
            }
        }
    }

    public void Stop()
    {
        _isRunning = false;

        _discoveryThread?.Join(5000);

        _logger.Info("BLE manager stopped");
    }

    public void Dispose() => Stop();
}