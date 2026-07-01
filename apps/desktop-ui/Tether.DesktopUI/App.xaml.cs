using MaterialDesignThemes.Wpf;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Windows;
using Tether.DesktopUI.Services;
using Tether.DesktopUI.ViewModels;
using Tether.DesktopUI.Views;
using Tether.Shared.Logging;

namespace Tether.DesktopUI;

public partial class App : Application
{
    private IHost? _host;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Apply Material Design theme programmatically
        var paletteHelper = new PaletteHelper();
        var theme = paletteHelper.GetTheme();
        theme.SetPrimaryColor(System.Windows.Media.Color.FromRgb(0x1E, 0x88, 0xE5)); // Blue
        theme.SetSecondaryColor(System.Windows.Media.Color.FromRgb(0x3F, 0x51, 0xB5)); // Indigo
        paletteHelper.SetTheme(theme);

        _host = Host.CreateDefaultBuilder(e.Args)
            .ConfigureServices((context, services) =>
            {
                services.AddSingleton<ITetherLogger, SerilogTetherLogger>(); // implement or use dummy
                services.AddSingleton<PipeClientService>();
                services.AddSingleton<MainViewModel>();
                services.AddSingleton<ConfigViewModel>();
                services.AddSingleton<StatusViewModel>();
                services.AddSingleton<LogsViewModel>();
                services.AddSingleton<MainWindow>();
            })
            .Build();

        var mainWindow = _host.Services.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _host?.Dispose();
        base.OnExit(e);
    }
}