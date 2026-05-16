using System.Runtime.InteropServices;
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
    private Thread? _monitoringThread;
    private bool _isRunning;
    private string? _connectedPhoneAddress;
    private DateTime _lastSeen;

    public BleManager(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public void Start()
    {
        _logger.Info("BLE proximity monitoring starting...");
        _isRunning = true;
        _monitoringThread = new Thread(MonitorPhone);
        _monitoringThread.Start();
    }

    private void MonitorPhone()
    {
        while (_isRunning)
        {
            try
            {
                using var client = new BluetoothClient();

                // Correct DiscoverDevices - no parameters or maxDevices only
                var devices = client.DiscoverDevices();

                var phone = devices.FirstOrDefault(d => d.DeviceName != null && d.DeviceName.Contains("TetherPhone"));

                if (phone != null)
                {
                    var phoneAddress = phone.DeviceAddress.ToString();

                    if (_connectedPhoneAddress == null)
                    {
                        // Phone just connected
                        _connectedPhoneAddress = phoneAddress;
                        _logger.Info($"Phone connected: {phone.DeviceName}");
                        _eventBus.Publish(new TetherEvent
                        {
                            EventType = TetherEventType.PHONE_CONNECTED,
                            Source = "BleManager"
                        });
                    }
                    _lastSeen = DateTime.Now;

                    // Since 32feet.NET doesn't provide RSSI, we use connection status
                    // For true proximity, we'll implement heartbeat method next
                    _logger.Debug($"Phone in range: {phone.DeviceName}");

                    // Restore trust when phone is nearby
                    _eventBus.Publish(new TetherEvent
                    {
                        EventType = TetherEventType.TRUST_RESTORED,
                        Source = "BleManager"
                    });
                }
                else if (_connectedPhoneAddress != null)
                {
                    // Phone was connected but not found in scan
                    if ((DateTime.Now - _lastSeen).TotalSeconds > 3)
                    {
                        _logger.Warning("Phone disappeared - immediate lock");
                        _eventBus.Publish(new TetherEvent
                        {
                            EventType = TetherEventType.PHONE_DISCONNECTED,
                            Source = "BleManager"
                        });
                        LockWorkStation();
                        _connectedPhoneAddress = null;
                    }
                }

                Thread.Sleep(2000); // Scan every 2 seconds
            }
            catch (Exception ex)
            {
                _logger.Error($"BLE monitoring error: {ex.Message}");
                Thread.Sleep(5000);
            }
        }
    }

    [DllImport("user32.dll")]
    private static extern bool LockWorkStation();

    public void Stop()
    {
        _isRunning = false;
        _monitoringThread?.Join(5000);
        _logger.Info("BLE monitoring stopped");
    }

    public void Dispose() => Stop();
}