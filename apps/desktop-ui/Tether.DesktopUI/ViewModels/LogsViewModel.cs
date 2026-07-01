using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace Tether.DesktopUI.ViewModels;

public class LogsViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly string _logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether", "Logs");
    private readonly string _logFile = "BleManager_Ipc.log";
    private ObservableCollection<string> _logEntries = new();
    private CancellationTokenSource _cts = new();

    public ObservableCollection<string> LogEntries
    {
        get => _logEntries;
        set { _logEntries = value; OnPropertyChanged(); }
    }

    public LogsViewModel()
    {
        _ = Task.Run(LoadLogs, _cts.Token);
    }

    private async Task LoadLogs()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                string fullPath = Path.Combine(_logDir, _logFile);
                if (File.Exists(fullPath))
                {
                    var lines = await File.ReadAllLinesAsync(fullPath);
                    await Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        LogEntries.Clear();
                        foreach (var line in lines)
                            LogEntries.Add(line);
                    });
                }
                await Task.Delay(5000, _cts.Token);
            }
            catch (OperationCanceledException) { break; }
            catch { }
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