using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace Tether.SessionHelper;

internal static class Program
{
    private const string InputPipeName = "Tether.InputPipe";
    private const int MaxFrameBytes = 1024 * 1024;

    private static async Task<int> Main(string[] args)
    {
        var injector = new InputInjector();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

        Console.WriteLine("[INF] Tether.SessionHelper starting; connecting to input pipe...");

        while (!cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(
                    serverName: ".",
                    pipeName: InputPipeName,
                    direction: PipeDirection.In,
                    options: PipeOptions.Asynchronous);

                await pipe.ConnectAsync(5000, cts.Token);
                Console.WriteLine("[INF] Connected to input pipe.");

                await PumpAsync(pipe, injector, cts.Token);

                Console.WriteLine("[WRN] Input pipe closed.");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WRN] Input pipe error: {ex.Message}");
            }

            try { await Task.Delay(1000, cts.Token); } catch { break; }
        }

        Console.WriteLine("[INF] Tether.SessionHelper exiting.");
        return 0;
    }

    private static async Task PumpAsync(Stream pipe, InputInjector injector, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        while (!ct.IsCancellationRequested)
        {
            if (!await ReadExactAsync(pipe, lenBuf, ct)) return;

            int len = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
            if (len <= 0 || len > MaxFrameBytes)
            {
                Console.WriteLine($"[WRN] Invalid frame length {len}; closing pipe.");
                return;
            }

            var body = new byte[len];
            if (!await ReadExactAsync(pipe, body, ct)) return;

            try
            {
                injector.Handle(body);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WRN] Injector threw: {ex.Message}");
            }
        }
    }

    private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n;
            try { n = await s.ReadAsync(buf.AsMemory(read, buf.Length - read), ct); }
            catch (OperationCanceledException) { return false; }
            catch { return false; }
            if (n <= 0) return false;
            read += n;
        }
        return true;
    }
}