using System;
using System.IO;
using System.IO.Pipes;
using System.Management;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Tether.SessionHelper;

internal static class Program
{
    private const string InputPipeName = "Tether.InputPipe";
    private const int MaxFrameBytes = 10 * 1024 * 1024; // 10MB to accommodate high-res screenshots
    private const byte PacketTypeInputEvent = 0x05;

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
                    direction: PipeDirection.InOut,
                    options: PipeOptions.Asynchronous);

                await pipe.ConnectAsync(5000, cts.Token);

                if (!IsTrustedServerProcess(pipe))
                {
                    pipe.Close();
                    await Task.Delay(1000, cts.Token);
                    continue;
                }

                await RunSessionBridgeLoopAsync(pipe, injector, cts.Token);
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

    private static async Task RunSessionBridgeLoopAsync(NamedPipeClientStream pipe, InputInjector injector, CancellationToken ct)
    {
        var writeLock = new SemaphoreSlim(1, 1);

        async Task SendJsonFrameAsync(object payload)
        {
            try
            {
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
                await writeLock.WaitAsync(ct);
                try
                {
                    await WriteFrameRawAsync(pipe, bytes, ct);
                }
                finally
                {
                    writeLock.Release();
                }
            }
            catch { }
        }

        // Initialize Clipboard Controller on STA Thread
        ClipboardController? clipboardController = null;
        var clipThread = new Thread(() =>
        {
            clipboardController = new ClipboardController(text =>
            {
                _ = SendJsonFrameAsync(new { type = "CLIPBOARD_SYNC", text, source = "PC" });
            });
            System.Windows.Forms.Application.Run(clipboardController);
        });
        clipThread.SetApartmentState(ApartmentState.STA);
        clipThread.IsBackground = true;
        clipThread.Start();

        // Initialize Notification Controller
        _ = NotificationController.InitializeAsync(notif =>
        {
            _ = SendJsonFrameAsync(new
            {
                type = "NOTIFICATION_EVENT",
                id = notif.Id,
                app = notif.App,
                title = notif.Title,
                body = notif.Body,
                timestamp = notif.Timestamp,
                source = "WINDOWS"
            });
        });

        // Initialize Media Session Controller
        _ = MediaSessionController.InitializeAsync(meta =>
        {
            _ = SendJsonFrameAsync(new
            {
                type = "MEDIA_METADATA_UPDATE",
                title = meta.Title,
                artist = meta.Artist,
                album = meta.Album,
                isPlaying = meta.IsPlaying,
                position = meta.PositionSeconds,
                duration = meta.DurationSeconds,
                thumbnail = meta.ThumbnailBase64
            });
        });

        // Initialize Terminal Session Manager
        var terminalMgr = new TerminalSessionManager((sessionId, data) =>
        {
            _ = SendJsonFrameAsync(new
            {
                type = "TERMINAL_OUTPUT",
                terminalId = sessionId,
                data
            });
        });

        // Background screen stream state
        CancellationTokenSource? streamCts = null;

        var lenBuf = new byte[4];
        while (!ct.IsCancellationRequested)
        {
            if (!await ReadExactAsync(pipe, lenBuf, ct)) break;

            int len = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
            if (len <= 0 || len > MaxFrameBytes) break;

            var body = new byte[len];
            if (!await ReadExactAsync(pipe, body, ct)) break;

            if (body[0] == PacketTypeInputEvent)
            {
                try { injector.Handle(body); } catch { }
                continue;
            }

            if (body[0] == (byte)'{')
            {
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    string type = doc.RootElement.TryGetProperty("type", out var tProp) ? (tProp.GetString() ?? "") : "";
                    string reqId = doc.RootElement.TryGetProperty("requestId", out var rProp) ? (rProp.GetString() ?? "") : "";

                    switch (type)
                    {
                        case "SCREENSHOT_REQUEST":
                            long winHwnd = doc.RootElement.TryGetProperty("hwnd", out var hProp) ? hProp.GetInt64() : 0;
                            int qual = doc.RootElement.TryGetProperty("quality", out var qProp) ? qProp.GetInt32() : 75;
                            byte[]? imgBytes = winHwnd != 0
                                ? ScreenCaptureEngine.CaptureWindow(new IntPtr(winHwnd), qual)
                                : ScreenCaptureEngine.CaptureFullScreen(qual);
                            string b64 = imgBytes != null ? Convert.ToBase64String(imgBytes) : "";
                            await SendJsonFrameAsync(new { type = "SCREENSHOT_RESPONSE", requestId = reqId, imageB64 = b64, success = imgBytes != null });
                            break;

                        case "WINDOWS_LIST_REQUEST":
                            var winList = ScreenCaptureEngine.GetOpenWindows();
                            await SendJsonFrameAsync(new { type = "WINDOWS_LIST_RESPONSE", requestId = reqId, windows = winList });
                            break;

                        case "START_SCREEN_STREAM":
                            streamCts?.Cancel();
                            streamCts = new CancellationTokenSource();
                            int fps = Math.Clamp(doc.RootElement.TryGetProperty("fps", out var fProp) ? fProp.GetInt32() : 15, 1, 30);
                            int streamQual = Math.Clamp(doc.RootElement.TryGetProperty("quality", out var sqProp) ? sqProp.GetInt32() : 50, 10, 90);
                            int delayMs = 1000 / fps;
                            var sToken = streamCts.Token;
                            _ = Task.Run(async () =>
                            {
                                while (!sToken.IsCancellationRequested && !ct.IsCancellationRequested)
                                {
                                    var frame = ScreenCaptureEngine.CaptureFullScreen(streamQual, 1280, 720);
                                    if (frame != null)
                                    {
                                        string frameB64 = Convert.ToBase64String(frame);
                                        await SendJsonFrameAsync(new { type = "DESKTOP_FRAME", frameB64 });
                                    }
                                    try { await Task.Delay(delayMs, sToken); } catch { break; }
                                }
                            }, sToken);
                            break;

                        case "STOP_SCREEN_STREAM":
                            streamCts?.Cancel();
                            streamCts = null;
                            break;

                        case "AUDIO_SESSIONS_GET":
                            var sessions = AdvancedAudioController.GetAppAudioSessions();
                            await SendJsonFrameAsync(new { type = "AUDIO_SESSIONS_RESPONSE", requestId = reqId, sessions });
                            break;

                        case "AUDIO_APP_VOLUME_SET":
                            int appPid = doc.RootElement.GetProperty("pid").GetInt32();
                            int volPct = doc.RootElement.GetProperty("volume").GetInt32();
                            bool volOk = AdvancedAudioController.SetAppVolume(appPid, volPct);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = volOk });
                            break;

                        case "AUDIO_APP_MUTE_SET":
                            int mutePid = doc.RootElement.GetProperty("pid").GetInt32();
                            bool isMuted = doc.RootElement.GetProperty("isMuted").GetBoolean();
                            bool muteOk = AdvancedAudioController.SetAppMute(mutePid, isMuted);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = muteOk });
                            break;

                        case "AUDIO_DEVICES_GET":
                            bool isRender = !doc.RootElement.TryGetProperty("isInput", out var inProp) || !inProp.GetBoolean();
                            var devices = AdvancedAudioController.GetAudioDevices(isRender);
                            await SendJsonFrameAsync(new { type = "AUDIO_DEVICES_RESPONSE", requestId = reqId, devices });
                            break;

                        case "AUDIO_DEFAULT_DEVICE_SET":
                            string devId = doc.RootElement.GetProperty("deviceId").GetString() ?? "";
                            bool devOk = AdvancedAudioController.SetDefaultAudioDevice(devId);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = devOk });
                            break;

                        case "MIC_GET_STATE":
                            var micState = AdvancedAudioController.GetMicrophoneState();
                            await SendJsonFrameAsync(new { type = "MIC_STATE_RESPONSE", requestId = reqId, level = micState.Level, isMuted = micState.IsMuted });
                            break;

                        case "MIC_SET_STATE":
                            int micLevel = doc.RootElement.TryGetProperty("level", out var mlProp) ? mlProp.GetInt32() : 50;
                            bool? micMute = doc.RootElement.TryGetProperty("isMuted", out var mmProp) ? mmProp.GetBoolean() : null;
                            bool micOk = AdvancedAudioController.SetMicrophoneState(micLevel, micMute);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = micOk });
                            break;

                        case "MEDIA_CONTROL":
                            string mediaAction = doc.RootElement.GetProperty("action").GetString() ?? "";
                            long? seekSec = doc.RootElement.TryGetProperty("seek", out var skProp) ? skProp.GetInt64() : null;
                            bool mOk = await MediaSessionController.ExecuteMediaControlAsync(mediaAction, seekSec);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = mOk });
                            break;

                        case "MEDIA_GET_METADATA":
                            var meta = await MediaSessionController.GetCurrentMetadataAsync();
                            await SendJsonFrameAsync(new
                            {
                                type = "MEDIA_METADATA_UPDATE",
                                requestId = reqId,
                                title = meta.Title,
                                artist = meta.Artist,
                                album = meta.Album,
                                isPlaying = meta.IsPlaying,
                                position = meta.PositionSeconds,
                                duration = meta.DurationSeconds,
                                thumbnail = meta.ThumbnailBase64
                            });
                            break;

                        case "CLIPBOARD_SET":
                            string clipText = doc.RootElement.GetProperty("text").GetString() ?? "";
                            clipboardController?.SetText(clipText);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = true });
                            break;

                        case "CLIPBOARD_GET":
                            string curText = ClipboardController.GetCurrentText();
                            await SendJsonFrameAsync(new { type = "CLIPBOARD_SYNC", requestId = reqId, text = curText, source = "PC" });
                            break;

                        case "CLIPBOARD_SIMULATE_COPY":
                            ClipboardController.SimulateCopy();
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = true });
                            break;

                        case "CLIPBOARD_SIMULATE_PASTE":
                            ClipboardController.SimulatePaste();
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = true });
                            break;

                        case "NOTIFICATION_DISMISS":
                            uint notifId = doc.RootElement.GetProperty("id").GetUInt32();
                            bool disOk = await NotificationController.DismissNotificationAsync(notifId);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = disOk });
                            break;

                        case "NOTIFICATION_SHOW_DESKTOP":
                            string nTitle = doc.RootElement.GetProperty("title").GetString() ?? "";
                            string nBody = doc.RootElement.GetProperty("body").GetString() ?? "";
                            string nApp = doc.RootElement.TryGetProperty("app", out var naProp) ? (naProp.GetString() ?? "") : "Phone";
                            NotificationController.ShowToastOnDesktop(nTitle, nBody, nApp);
                            break;

                        case "TERMINAL_START":
                            string shell = doc.RootElement.TryGetProperty("shell", out var shProp) ? (shProp.GetString() ?? "powershell") : "powershell";
                            string? initialDir = doc.RootElement.TryGetProperty("initialDir", out var idProp) ? idProp.GetString() : null;
                            string? termId = doc.RootElement.TryGetProperty("terminalId", out var tidProp) ? tidProp.GetString() : null;
                            var tInfo = terminalMgr.StartSession(shell, initialDir, termId);
                            await SendJsonFrameAsync(new { type = "TERMINAL_START_RESPONSE", requestId = reqId, terminal = tInfo });
                            break;

                        case "TERMINAL_INPUT":
                            string targetTermId = doc.RootElement.GetProperty("terminalId").GetString() ?? "";
                            string termInput = doc.RootElement.GetProperty("data").GetString() ?? "";
                            terminalMgr.SendInput(targetTermId, termInput);
                            break;

                        case "TERMINAL_CLOSE":
                            string closeTermId = doc.RootElement.GetProperty("terminalId").GetString() ?? "";
                            terminalMgr.CloseSession(closeTermId);
                            break;

                        case "TERMINAL_LIST":
                            var termList = terminalMgr.ListSessions();
                            await SendJsonFrameAsync(new { type = "TERMINAL_LIST_RESPONSE", requestId = reqId, sessions = termList });
                            break;

                        case "APP_GET_INSTALLED":
                            var installed = ApplicationManager.GetInstalledApplications();
                            await SendJsonFrameAsync(new { type = "APP_INSTALLED_RESPONSE", requestId = reqId, apps = installed });
                            break;

                        case "APP_LAUNCH":
                            string appPath = doc.RootElement.GetProperty("path").GetString() ?? "";
                            string? appArgs = doc.RootElement.TryGetProperty("args", out var aProp) ? aProp.GetString() : null;
                            bool launchOk = ApplicationManager.LaunchApplication(appPath, appArgs);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = launchOk });
                            break;

                        case "APP_GET_WINDOWS":
                            var winInfoList = ApplicationManager.GetRunningWindows();
                            await SendJsonFrameAsync(new { type = "APP_WINDOWS_RESPONSE", requestId = reqId, windows = winInfoList });
                            break;

                        case "APP_SWITCH_WINDOW":
                            long swHwnd = doc.RootElement.GetProperty("hwnd").GetInt64();
                            bool swOk = ApplicationManager.SwitchWindow(new IntPtr(swHwnd));
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = swOk });
                            break;

                        case "APP_SET_WINDOW_STATE":
                            long stHwnd = doc.RootElement.GetProperty("hwnd").GetInt64();
                            string winState = doc.RootElement.GetProperty("state").GetString() ?? "restore";
                            bool stOk = ApplicationManager.SetWindowState(new IntPtr(stHwnd), winState);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = stOk });
                            break;

                        case "APP_CLOSE_WINDOW":
                            long clHwnd = doc.RootElement.GetProperty("hwnd").GetInt64();
                            bool forceClose = doc.RootElement.TryGetProperty("force", out var fcProp) && fcProp.GetBoolean();
                            bool clOk = ApplicationManager.CloseWindow(new IntPtr(clHwnd), forceClose);
                            await SendJsonFrameAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = clOk });
                            break;
                    }
                }
                catch { }
            }
        }

        streamCts?.Cancel();
    }

    private static async Task WriteFrameRawAsync(Stream pipe, byte[] frame, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        lenBuf[0] = (byte)(frame.Length >> 24);
        lenBuf[1] = (byte)(frame.Length >> 16);
        lenBuf[2] = (byte)(frame.Length >> 8);
        lenBuf[3] = (byte)frame.Length;
        await pipe.WriteAsync(lenBuf, 0, 4, ct);
        await pipe.WriteAsync(frame, 0, frame.Length, ct);
        await pipe.FlushAsync(ct);
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
