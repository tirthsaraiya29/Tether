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

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle hPipe, out uint ServerProcessId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);
    private static readonly IntPtr DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = new IntPtr(-4);

    private static async Task<int> Main(string[] args)
    {
        try { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); } catch { }

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

                case "get-brightness":
                    return Task.FromResult(GetBrightness());

                case "set-brightness":
                    if (args.Length >= 2 && int.TryParse(args[1], out int setBri))
                    {
                        return Task.FromResult(SetBrightness(setBri));
                    }
                    return Task.FromResult(-1);

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

    private static int GetBrightness()
    {
        try
        {
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
                        if (val != null) return Convert.ToInt32(val);
                    }
                    break;
                }
            }
            return -1;
        }
        catch
        {
            return -1;
        }
    }

    private static int SetBrightness(int targetLevel)
    {
        int target = Math.Clamp(targetLevel, 0, 100);
        try
        {
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
        using var injector = new InputInjector();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

        int currentSessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        string perSessionPipeName = $"{InputPipeName}.{currentSessionId}";

        while (!cts.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(
                    serverName: ".",
                    pipeName: perSessionPipeName,
                    direction: PipeDirection.In,
                    options: PipeOptions.Asynchronous);

                await pipe.ConnectAsync(5000, cts.Token);

                if (!IsTrustedServerProcess(pipe))
                {
                    pipe.Close();
                    await Task.Delay(1000, cts.Token);
                    continue;
                }

                await PumpAsync(pipe, injector, cts.Token);

                // Pipe session ended (service restart, reconnect, helper kill):
                // lift anything still held so the host is not stuck with a
                // phantom pressed key or mouse button.
                injector.ReleaseAllHeld();
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

        // Process exit path (shutdown, service kill): same release, so held
        // input state never outlives this process.
        injector.ReleaseAllHeld();
        return 0;
    }

    private static bool IsTrustedServerProcess(NamedPipeClientStream pipe)
    {
        try
        {
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverPid))
                return false;

            // 1. Validate that serverPid corresponds to Tether.CommunicationService running in Session 0.
            // Using Process.GetProcessesByName queries the system process table via NtQuerySystemInformation
            // without requiring open handles or PROCESS_QUERY_LIMITED_INFORMATION, which standard medium-integrity
            // user tokens are denied on Session 0 SYSTEM processes.
            bool isMatchingCommService = false;
            try
            {
                var candidates = System.Diagnostics.Process.GetProcessesByName("Tether.CommunicationService");
                foreach (var p in candidates)
                {
                    try
                    {
                        if (p.Id == (int)serverPid && p.SessionId == 0)
                        {
                            isMatchingCommService = true;
                            break;
                        }
                    }
                    catch { }
                    finally
                    {
                        try { p.Dispose(); } catch { }
                    }
                }
            }
            catch
            {
                return false;
            }

            if (!isMatchingCommService)
                return false;

            // 2. Defense-in-depth: If the caller is elevated and can acquire a PROCESS_QUERY_LIMITED_INFORMATION handle,
            // also verify that the image filename matches. If access is denied (standard user token), the verified
            // Session 0 process table identity is accepted.
            try
            {
                IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, serverPid);
                if (hProc != IntPtr.Zero)
                {
                    try
                    {
                        var sb = new System.Text.StringBuilder(1024);
                        uint size = (uint)sb.Capacity;
                        if (QueryFullProcessImageName(hProc, 0, sb, ref size))
                        {
                            string fullPath = sb.ToString();
                            string fileName = System.IO.Path.GetFileName(fullPath);
                            if (!string.Equals(fileName, "Tether.CommunicationService.exe", StringComparison.OrdinalIgnoreCase))
                                return false;
                        }
                    }
                    finally
                    {
                        CloseHandle(hProc);
                    }
                }
            }
            catch { }

            return true;
        }
        catch
        {
            return false;
        }
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

            try { injector.Enqueue(body); } catch { }
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