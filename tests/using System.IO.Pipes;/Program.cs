using System.IO.Pipes;
using System.Text;
using System.Text.Json;

var evt = new { EventType = 1, Source = "PipeTest" };
var json = JsonSerializer.Serialize(evt);
var bytes = Encoding.UTF8.GetBytes(json);

try
{
    Console.WriteLine("Attempting to connect to TetherPipe...");
    using var client = new NamedPipeClientStream(".", "TetherPipe", PipeDirection.Out);
    await client.ConnectAsync(2000);
    Console.WriteLine("Connected!");
    await client.WriteAsync(bytes, 0, bytes.Length);
    await client.FlushAsync();
    Console.WriteLine("Event sent. Check service logs.");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
}

Console.WriteLine("Press any key to exit...");
Console.ReadKey();