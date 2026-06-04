using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Input;

namespace Tether.DesktopUI
{
    public partial class LockOverlayWindow : Window
    {
        public LockOverlayWindow()
        {
            InitializeComponent();
            this.Closing += OnWindowClosing;
            this.PreviewKeyDown += OnKeyIntercept;
        }

        // Prevents users manually escaping via Alt+F4
        private void OnWindowClosing(object sender, CancelEventArgs e)
        {
            e.Cancel = true;
        }

        // Intercepts and drops Windows keyboard layout bypass sequences
        private void OnKeyIntercept(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.System && e.SystemKey == Key.F4)
            {
                e.Handled = true;
            }
        }

        // Adjusts visual depth properties using your exact formula specs
        public void UpdateBlurFromRssi(double rssi)
        {
            // Gradual blur parameters: starts at -68dBm, reaches heavy max at -75dBm
            double startRssi = -68;
            double maxRssi = -75;

            if (rssi >= startRssi)
            {
                GlassBlur.Radius = 0;
            }
            else if (rssi <= maxRssi)
            {
                GlassBlur.Radius = 40; // Represents the heavy 80% blur ceiling out of 50 max points
            }
            else
            {
                // Linear interpolation across the target interval
                double ratio = (startRssi - rssi) / (startRssi - maxRssi);
                GlassBlur.Radius = ratio * 40;
            }
        }

        private void Unlock_Click(object sender, RoutedEventArgs e)
        {
            // Simple overlay dismissal framework context
            this.Closing -= OnWindowClosing;
            this.Close();
        }
    }
}