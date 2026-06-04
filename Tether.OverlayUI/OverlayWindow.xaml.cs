using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Input;

namespace Tether.OverlayUI
{
    public partial class OverlayWindow : Window
    {
        public OverlayWindow()
        {
            InitializeComponent();
            this.Closing += OnWindowClosing;
            this.PreviewKeyDown += OnKeyIntercept;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Force window to span across the entire virtual desktop real-estate (All monitors)
            this.Left = SystemParameters.VirtualScreenLeft;
            this.Top = SystemParameters.VirtualScreenTop;
            this.Width = SystemParameters.VirtualScreenWidth;
            this.Height = SystemParameters.VirtualScreenHeight;
        }

        // Stops Alt+F4 closures completely
        private void OnWindowClosing(object sender, CancelEventArgs e)
        {
            e.Cancel = true;
        }

        // Drops system short keys from bubbling up
        private void OnKeyIntercept(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.System && e.SystemKey == Key.F4)
            {
                e.Handled = true;
            }
        }

        // Targets the background element blur cleanly
        public void UpdateBlurFromRssi(double rssi)
        {
            double startRssi = -68;
            double maxRssi = -75;

            if (rssi >= startRssi)
            {
                ScreenBlur.Radius = 0;
            }
            else if (rssi <= maxRssi)
            {
                ScreenBlur.Radius = 50; // Max crisp-to-heavy box blur radius ceiling
            }
            else
            {
                double ratio = (startRssi - rssi) / (startRssi - maxRssi);
                ScreenBlur.Radius = ratio * 50;
            }
        }

        private async void Unlock_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Formulate the structural recovery event payload
                var releaseEvent = new Tether.Shared.Events.TetherEvent
                {
                    EventType = Tether.Shared.Events.TetherEventType.PHONE_UNLOCKED,
                    Source = "OverlayUI"
                };

                var json = System.Text.Json.JsonSerializer.Serialize(releaseEvent);
                var bytes = System.Text.Encoding.UTF8.GetBytes(json);

                // Push message directly up the main background service communication channel
                using var client = new System.IO.Pipes.NamedPipeClientStream(".", Tether.Shared.IPC.IpcConstants.PipeName, System.IO.Pipes.PipeDirection.Out);
                await client.ConnectAsync(300); // 300ms connection window limit
                await client.WriteAsync(bytes, 0, bytes.Length);
                await client.FlushAsync();
            }
            catch (Exception ex)
            {
                // Allows graceful fallbacks if service instances are bouncing during active testing
                System.Diagnostics.Debug.WriteLine($"IPC Release Handshake Failed: {ex.Message}");
            }
            finally
            {
                // Safely unhook and exit the local process frame cleanly
                this.Closing -= OnWindowClosing;
                this.Close();
                System.Windows.Application.Current.Shutdown();
            }
        }
    }
}