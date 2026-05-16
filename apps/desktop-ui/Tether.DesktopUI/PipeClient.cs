using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Tether.Shared.Events;
using Tether.Shared.IPC;

namespace Tether.DesktopUI;

public class PipeClient
{
    public async Task<bool> SendEventAsync(TetherEvent evt)
    {
        try
        {
            var json = JsonSerializer.Serialize(evt);
            var bytes = Encoding.UTF8.GetBytes(json);

            using var client = new NamedPipeClientStream(".", IpcConstants.PipeName, PipeDirection.Out);
            await client.ConnectAsync(3000);

            await client.WriteAsync(bytes, 0, bytes.Length);
            await client.FlushAsync();

            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Pipe error: {ex.Message}");
            return false;
        }
    }
}