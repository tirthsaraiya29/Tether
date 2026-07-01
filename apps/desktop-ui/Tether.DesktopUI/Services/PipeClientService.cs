using System;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.Shared.Events;
using Tether.Shared.IPC;

namespace Tether.DesktopUI.Services;

public class PipeClientService : IDisposable
{
    private CancellationTokenSource _cts = new();
    private Task? _listenTask;

    public event Action<TetherEvent>? EventReceived;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(Listen, _cts.Token);
    }

    private async Task Listen()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", IpcConstants.UiPipeName, PipeDirection.In);
                await pipe.ConnectAsync(1000, _cts.Token);
                if (!pipe.IsConnected) continue;

                var buffer = new byte[4096];
                while (pipe.IsConnected && !_cts.IsCancellationRequested)
                {
                    int read = await pipe.ReadAsync(buffer, 0, buffer.Length, _cts.Token);
                    if (read == 0) break;

                    string json = Encoding.UTF8.GetString(buffer, 0, read);
                    var evt = JsonSerializer.Deserialize<TetherEvent>(json);
                    if (evt != null)
                        EventReceived?.Invoke(evt);
                }
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(5000); }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}