using System;
using System.Windows;

namespace Tether.DesktopUI
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Intercept fatal XAML and UI Thread crashes
            this.DispatcherUnhandledException += (sender, args) =>
            {
                MessageBox.Show($"UI Crash: {args.Exception.Message}\n\n{args.Exception.InnerException?.Message}",
                                "Tether Fatal Error",
                                MessageBoxButton.OK,
                                MessageBoxImage.Error);

                args.Handled = true;
                Environment.Exit(1);
            };

            // Intercept background thread and early memory allocation crashes
            AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
            {
                if (args.ExceptionObject is Exception ex)
                {
                    MessageBox.Show($"Core Crash: {ex.Message}\n\n{ex.InnerException?.Message}",
                                    "Tether Fatal Error",
                                    MessageBoxButton.OK,
                                    MessageBoxImage.Error);
                }
            };

            base.OnStartup(e);
        }
    }
}