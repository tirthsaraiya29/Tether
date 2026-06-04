using System;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using Tether.Shared.Events;
using Tether.Shared.IPC;

namespace Tether.DesktopUI
{
    public partial class MainWindow : Window
    {
        private readonly PipeClient _pipeClient = new PipeClient();

        // ADD THESE TWO PROPERTIES:
        private LockOverlayWindow _overlayWindow = null;
        private bool _isListening = true;

        public MainWindow()
        {
            InitializeComponent();
            AppendStatus("Desktop UI started. Waiting for events...");
            StartServiceListener();
        }
        private async void StartServiceListener()
        {
            await Task.Run(async () =>
            {
                while (_isListening)
                {
                    try
                    {
                        using var server = new NamedPipeServerStream(
                            IpcConstants.UiPipeName,
                            PipeDirection.In,
                            1,
                            PipeTransmissionMode.Message,
                            PipeOptions.Asynchronous);

                        await server.WaitForConnectionAsync();

                        var buffer = new byte[IpcConstants.PipeBufferSize];
                        var read = await server.ReadAsync(buffer, 0, buffer.Length);
                        if (read == 0) continue;

                        var json = Encoding.UTF8.GetString(buffer, 0, read);
                        var evt = JsonSerializer.Deserialize<TetherEvent>(json);

                        if (evt != null)
                        {
                            // Dispatch telemetry tracking details back to our main UI UI safety loop
                            Dispatcher.Invoke(() => HandleIncomingServiceEvent(evt));
                        }
                    }
                    catch
                    {
                        await Task.Delay(500);
                    }
                }
            });
        }

        private void HandleIncomingServiceEvent(TetherEvent evt)
        {
            switch (evt.EventType)
            {
                case TetherEventType.TRUST_DEGRADED:
                    if (evt.PayloadJson != null && _overlayWindow == null)
                    {
                        try
                        {
                            var data = JsonSerializer.Deserialize<JsonElement>(evt.PayloadJson);
                            if (data.TryGetProperty("Rssi", out var rssiProp))
                            {
                                double currentRssi = rssiProp.GetDouble();

                                // Automatically trigger overlay initialization if values drop pass -68
                                if (currentRssi < -68)
                                {
                                    EnsureOverlayActive();
                                    _overlayWindow.UpdateBlurFromRssi(currentRssi);
                                }
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.OVERLAY_ENABLED:
                    EnsureOverlayActive();
                    _overlayWindow.UpdateBlurFromRssi(-75); 
                    AppendStatus("Workstation overlay locked out via proximity rule.");
                    break;

                case TetherEventType.OVERLAY_DISABLED:
                    DismissOverlayActive();
                    AppendStatus("Workstation overlay cleared by trusted companion.");
                    break;
            }
        }

        private void EnsureOverlayActive()
        {
            if (_overlayWindow == null)
            {
                _overlayWindow = new LockOverlayWindow();
                _overlayWindow.Owner = this;
                _overlayWindow.Closed += (s, e) => _overlayWindow = null;
                _overlayWindow.Show();
            }
        }

        private void DismissOverlayActive()
        {
            if (_overlayWindow != null)
            {
                _overlayWindow.Close();
                _overlayWindow = null;
            }
        }

        private async void SimulatePhoneConnected_Click(object sender, RoutedEventArgs e)
        {
            await _pipeClient.SendEventAsync(new TetherEvent { EventType = TetherEventType.PHONE_CONNECTED, Source = "DesktopUI" });
            AppendStatus("Simulated PHONE_CONNECTED sent to service.");
        }

        private async void SimulatePhoneDisconnected_Click(object sender, RoutedEventArgs e)
        {
            await _pipeClient.SendEventAsync(new TetherEvent { EventType = TetherEventType.PHONE_DISCONNECTED, Source = "DesktopUI" });
            AppendStatus("Simulated PHONE_DISCONNECTED sent to service.");
        }

        private async void PanicButton_Click(object sender, RoutedEventArgs e)
        {
            await _pipeClient.SendEventAsync(new TetherEvent { EventType = TetherEventType.PANIC_TRIGGERED, Source = "DesktopUI" });
            AppendStatus("PANIC event sent to service.");
        }

        private void AppendStatus(string msg)
        {
            StatusTextBox.AppendText($"{DateTime.Now:T}: {msg}\n");
            StatusTextBox.ScrollToEnd();
        }
    }
}