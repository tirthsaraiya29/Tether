using System.Windows;
using Tether.Shared.Events;
using Tether.DesktopUI;

namespace Tether.DesktopUI
{
    public partial class MainWindow : Window
    {
        private readonly PipeClient _pipeClient = new PipeClient();

        public MainWindow()
        {
            InitializeComponent();
            AppendStatus("Desktop UI started. Waiting for events...");
        }

        private async void SimulatePhoneConnected_Click(object sender, RoutedEventArgs e)
        {
            await _pipeClient.SendEventAsync(new TetherEvent
            {
                EventType = TetherEventType.PHONE_CONNECTED,
                Source = "DesktopUI"
            });
            AppendStatus("Simulated PHONE_CONNECTED sent to service.");
        }

        private async void SimulatePhoneDisconnected_Click(object sender, RoutedEventArgs e)
        {
            await _pipeClient.SendEventAsync(new TetherEvent
            {
                EventType = TetherEventType.PHONE_DISCONNECTED,
                Source = "DesktopUI"
            });
            AppendStatus("Simulated PHONE_DISCONNECTED sent to service.");
        }

        private async void PanicButton_Click(object sender, RoutedEventArgs e)
        {
            await _pipeClient.SendEventAsync(new TetherEvent
            {
                EventType = TetherEventType.PANIC_TRIGGERED,
                Source = "DesktopUI"
            });
            AppendStatus("PANIC event sent to service - screen should lock");
        }

        private void AppendStatus(string msg)
        {
            StatusTextBox.AppendText($"{DateTime.Now:T}: {msg}\n");
            StatusTextBox.ScrollToEnd();
        }
    }
}