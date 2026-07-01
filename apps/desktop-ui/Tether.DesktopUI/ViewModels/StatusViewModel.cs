using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Tether.DesktopUI.Services;
using Tether.Shared.Events;

namespace Tether.DesktopUI.ViewModels;

public class StatusViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly PipeClientService _pipeService;
    private string _connectionStatus = "Disconnected";
    private string _trustState = "Unknown";
    private string _rssi = "N/A";
    private CancellationTokenSource _cts = new();

    public string ConnectionStatus
    {
        get => _connectionStatus;
        set { _connectionStatus = value; OnPropertyChanged(); }
    }

    public string TrustState
    {
        get => _trustState;
        set { _trustState = value; OnPropertyChanged(); }
    }

    public string Rssi
    {
        get => _rssi;
        set { _rssi = value; OnPropertyChanged(); }
    }

    public StatusViewModel(PipeClientService pipeService)
    {
        _pipeService = pipeService;
        _pipeService.EventReceived += OnEventReceived;
        _ = Task.Run(UpdateStatusLoop, _cts.Token);
    }

    private void OnEventReceived(TetherEvent evt)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            switch (evt.EventType)
            {
                case TetherEventType.PHONE_CONNECTED:
                    ConnectionStatus = "Connected";
                    TrustState = "Trusted (Unlocked)";
                    break;
                case TetherEventType.PHONE_DISCONNECTED:
                    ConnectionStatus = "Disconnected";
                    TrustState = "Untrusted (Locked)";
                    break;
                case TetherEventType.TRUST_RESTORED:
                    TrustState = "Trusted (Unlocked)";
                    break;
                case TetherEventType.TRUST_LOST:
                    TrustState = "Untrusted (Locked)";
                    break;
                case TetherEventType.TRUST_DEGRADED:
                    TrustState = "Degraded";
                    // parse RSSI from payload if needed
                    break;
            }
        });
    }

    private async Task UpdateStatusLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            await Task.Delay(5000);
            // could poll service state via pipe or registry
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string name = null!) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}