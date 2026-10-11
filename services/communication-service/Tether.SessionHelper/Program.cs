using System;
using System.IO;
using System.IO.Pipes;
using System.Management;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Tether.SessionHelper;

internal static class Program
{
    private const string InputPipeName = "Tether.InputPipe";
    private const int MaxFrameBytes = 1024 * 1024;

    private static async Task<int> Main(string[] args)
    {
        if (args is { Length: > 0 })
        {
            return await RunCommandAsync(args);
        }

        return await RunPipeClientAsync();
    }

    private static Task<int> RunCommandAsync(string[] args)
    {
        string command = args[0].Trim().ToLowerInvariant();

        try
        {
            switch (command)
            {
                case "get-volume":
                    return Task.FromResult(AudioController.GetMasterVolume());

                case "set-volume":
                    if (args.Length >= 2 && int.TryParse(args[1], out int setVol))
                    {
                        AudioController.SetMasterVolume(setVol);
                        return Task.FromResult(0);
                    }
                    return Task.FromResult(-1);

                case "adjust-volume":
                    if (args.Length >= 2 && int.TryParse(args[1], out int delta))
                    {
                        AudioController.AdjustMasterVolume(delta);
                        return Task.FromResult(0);
                    }
                    return Task.FromResult(-1);

                case "toggle-mute":
                    AudioController.ToggleMute();
                    return Task.FromResult(0);

                case "brightness-up":
                    return Task.FromResult(AdjustBrightness(args.Length >= 2 ? args[1] : "10"));

                case "brightness-down":
                    return Task.FromResult(AdjustBrightness(args.Length >= 2 ? "-" + args[1] : "-10"));

                case "dump-laptop-state":
                    if (args.Length >= 2)
                    {
                        return Task.FromResult(DumpLaptopState(args[1]));
                    }
                    return Task.FromResult(-1);

                default:
                    return Task.FromResult(-1);
            }
        }
        catch
        {
            return Task.FromResult(-1);
        }
    }

    private static int AdjustBrightness(string deltaStr)
    {
        int delta = 10;
        if (!int.TryParse(deltaStr, out delta) || delta == 0) delta = 10;

        try
        {
            int current = 50;

            using (var getSearcher = new ManagementObjectSearcher(
                       new ManagementScope(@"root\WMI"),
                       new ObjectQuery("SELECT * FROM WmiMonitorBrightness")))
            using (var results = getSearcher.Get())
            {
                foreach (ManagementObject obj in results)
                {
                    using (obj)
                    {
                        object? val = obj["CurrentBrightness"];
                        if (val != null) current = Convert.ToInt32(val);
                    }
                    break;
                }
            }

            int target = Math.Clamp(current + delta, 0, 100);

            using (var setSearcher = new ManagementObjectSearcher(
                       new ManagementScope(@"root\WMI"),
                       new ObjectQuery("SELECT * FROM WmiMonitorBrightnessMethods")))
            using (var results = setSearcher.Get())
            {
                foreach (ManagementObject m in results)
                {
                    using (m)
                    {
                        m.InvokeMethod("WmiSetBrightness", new object[] { 0u, (uint)target });
                    }
                    break;
                }
            }

            return 0;
        }
        catch
        {
            return -1;
        }
    }

    private static int DumpLaptopState(string outputPath)
    {
        try
        {
            string lockState = LockStateDetector.GetLockStateString();
            var (b64, hash) = WallpaperReader.GetDownscaledWallpaperBase64AndHash();

            var payload = new
            {
                lockState,
                wallpaperB64 = b64,
                wallpaperHash = hash
            };

            string json = JsonSerializer.Serialize(payload);
            File.WriteAllText(outputPath, json);
            return 0;
        }
        catch
        {
            return -1;
        }
    }

    private static async Task<int> RunPipeClientAsync()
    {
        var injector = new InputInjector();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

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
                await PumpAsync(pipe, injector, cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
            }

            try { await Task.Delay(1000, cts.Token); }
            catch { break; }
        }

        return 0;
    }

    private static async Task PumpAsync(Stream pipe, InputInjector injector, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        while (!ct.IsCancellationRequested)
        {
            if (!await ReadExactAsync(pipe, lenBuf, ct)) return;

            int len = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
            if (len <= 0 || len > MaxFrameBytes) return;

            var body = new byte[len];
            if (!await ReadExactAsync(pipe, body, ct)) return;

            try { injector.Handle(body); } catch { }
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