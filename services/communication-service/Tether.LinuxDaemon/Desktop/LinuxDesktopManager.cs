using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Common;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Desktop;

public sealed record DesktopWindowInfo
{
    [JsonPropertyName("hwnd")] public long Hwnd { get; init; }
    [JsonPropertyName("id")] public long Id => Hwnd;
    [JsonPropertyName("title")] public string Title { get; init; } = "";
    [JsonPropertyName("processName")] public string ProcessName { get; init; } = "";
    [JsonPropertyName("processId")] public int ProcessId { get; init; }
    [JsonPropertyName("x")] public int X { get; init; } = 0;
    [JsonPropertyName("y")] public int Y { get; init; } = 0;
    [JsonPropertyName("width")] public int Width { get; init; } = 1920;
    [JsonPropertyName("height")] public int Height { get; init; } = 1080;
    [JsonPropertyName("iconB64")] public string? IconB64 { get; init; }
}

public sealed class LinuxDesktopManager
{
    private readonly ITetherLogger _logger;

    public LinuxDesktopManager(ITetherLogger logger)
    {
        _logger = logger;
    }

    /// <summary>Returns the X11 desktop size, or (0,0) when it cannot be determined.</summary>
    public (int Width, int Height) GetDesktopGeometry()
    {
        try
        {
            var psi = PlatformDetection.CreateSessionProcessInfo("wmctrl", new[] { "-d" }, redirectOutput: true);
            using var p = Process.Start(psi);
            if (p != null)
            {
                bool exited = p.WaitForExit(1000);
                string output = p.StandardOutput.ReadToEnd();
                if (!exited)
                {
                    try { p.Kill(true); } catch { }
                    _logger.Warning("LinuxDesktopManager: wmctrl -d timed out.");
                    return (0, 0);
                }
                if (p.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    // Look for: DG: 1920x1080
                    var match = Regex.Match(output, @"DG:\s*(\d+)x(\d+)");
                    if (match.Success &&
                        int.TryParse(match.Groups[1].Value, out int w) &&
                        int.TryParse(match.Groups[2].Value, out int h))
                    {
                        return (Math.Max(1, w), Math.Max(1, h));
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxDesktopManager: desktop geometry query failed: {ex.Message}");
        }

        return (0, 0);
    }

    public IReadOnlyList<DesktopWindowInfo> GetDesktopWindows()
    {
        var (desktopW, desktopH) = GetDesktopGeometry();
        var windows = new List<DesktopWindowInfo>
        {
            new()
            {
                Hwnd = 0L,
                Title = "Entire Screen / Desktop",
                ProcessName = "desktop",
                ProcessId = 0,
                X = 0,
                Y = 0,
                Width = desktopW,
                Height = desktopH
            }
        };

        // Query real X11 / XWayland windows via wmctrl, as the desktop user.
        try
        {
            var psi = PlatformDetection.CreateSessionProcessInfo("wmctrl", new[] { "-l", "-p", "-G" }, redirectOutput: true);
            using var p = Process.Start(psi);
            if (p != null)
            {
                bool exited = p.WaitForExit(1000);
                string output = p.StandardOutput.ReadToEnd();
                if (!exited)
                {
                    try { p.Kill(true); } catch { }
                    _logger.Warning("LinuxDesktopManager: wmctrl -l timed out.");
                    return windows;
                }
                if (p.ExitCode != 0)
                {
                    _logger.Info($"LinuxDesktopManager: window enumeration unavailable (wmctrl exit {p.ExitCode}).");
                    return windows;
                }
                if (!string.IsNullOrWhiteSpace(output))
                {
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 8)
                        {
                            long hwnd = 0;
                            try { hwnd = Convert.ToInt64(parts[0], 16); } catch { }
                            int pid = 0;
                            int.TryParse(parts[2], out pid);
                            int x = 0, y = 0, w = 0, h = 0;
                            int.TryParse(parts[3], out x);
                            int.TryParse(parts[4], out y);
                            int.TryParse(parts[5], out w);
                            int.TryParse(parts[6], out h);
                            string title = parts.Length > 8 ? string.Join(" ", parts.Skip(8)).Trim() : parts[7];

                            if (hwnd != 0 && !string.IsNullOrEmpty(title) && w > 0 && h > 0)
                            {
                                string procName = "window";
                                try
                                {
                                    if (pid > 0)
                                    {
                                        using var proc = Process.GetProcessById(pid);
                                        procName = proc.ProcessName;
                                    }
                                }
                                catch { }

                                windows.Add(new DesktopWindowInfo
                                {
                                    Hwnd = hwnd,
                                    Title = title,
                                    ProcessName = procName,
                                    ProcessId = pid,
                                    X = Math.Max(0, x),
                                    Y = Math.Max(0, y),
                                    Width = w,
                                    Height = h
                                });
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxDesktopManager: window enumeration failed: {ex.Message}");
        }

        return windows;
    }

    public async Task<byte[]> CaptureScreenshotAsync(int quality, long windowId, CancellationToken ct)
    {
        int q = Math.Clamp(quality, 10, 100);
        return await CaptureJpegFrameAsync(q, windowId, ct);
    }

    public async Task StreamDesktopAsync(
        int fps,
        int quality,
        long windowId,
        Func<byte[], CancellationToken, Task> onFrameAsync,
        CancellationToken ct)
    {
        int targetFps = Math.Clamp(fps, 1, 30);
        int targetQual = Math.Clamp(quality, 10, 95);
        int intervalMs = Math.Max(33, 1000 / targetFps);

        _logger.Info($"LinuxDesktopManager: Starting desktop MJPEG stream ({targetFps} FPS, Quality {targetQual}, Target Window={windowId}).");

        try
        {
            int consecutiveFailures = 0;
            while (!ct.IsCancellationRequested)
            {
                var stopwatch = Stopwatch.StartNew();
                byte[] frame = await CaptureJpegFrameAsync(targetQual, windowId, ct);

                if (frame.Length > 0)
                {
                    consecutiveFailures = 0;
                    await onFrameAsync(frame, ct);
                }
                else
                {
                    consecutiveFailures++;
                    if (consecutiveFailures >= 10)
                    {
                        _logger.Warning("LinuxDesktopManager: Desktop capture unavailable or continuously failing. Stream ended.");
                        break;
                    }
                    await Task.Delay(500, ct);
                    continue;
                }

                stopwatch.Stop();
                int remaining = intervalMs - (int)stopwatch.ElapsedMilliseconds;
                if (remaining > 0)
                {
                    await Task.Delay(remaining, ct);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal stream termination
        }
        finally
        {
            _logger.Info("LinuxDesktopManager: Desktop MJPEG stream session terminated.");
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern uint geteuid();

    /// <summary>
    /// Only distro-owned, non-symlinked, non-group/other-writable ffmpeg binaries are executed.
    /// /usr/local and /snap are deliberately excluded because a non-root user can write there.
    /// </summary>
    private static string? ResolveTrustedFfmpeg()
    {
        foreach (var path in new[] { "/usr/bin/ffmpeg", "/bin/ffmpeg" })
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) continue;
                if (info.LinkTarget != null) continue;
                var mode = info.UnixFileMode;
                if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0) continue;
                return path;
            }
            catch { }
        }
        return null;
    }

    public async Task<byte[]> CaptureJpegFrameAsync(int quality, long windowId, CancellationToken ct)
    {
        var session = PlatformDetection.GetActiveSessionInfo();
        string display = !string.IsNullOrEmpty(session.DisplayName) ? session.DisplayName : ":0";

        string? ffmpeg = ResolveTrustedFfmpeg();
        if (ffmpeg == null)
        {
            _logger.Warning("LinuxDesktopManager: ffmpeg is not installed; screen capture unavailable.");
            return Array.Empty<byte>();
        }

        try
        {
            string tmpFile = Path.Combine(Path.GetTempPath(), $"tether_cap_{Guid.NewGuid():N}.jpg");
            int qscale = Math.Clamp(31 - (quality * 30 / 100), 2, 31); // ffmpeg mjpeg q:v 2 (best) to 31 (lowest)

            var args = new List<string>();

            // X11 Screen or Window Capture
            if (session.DisplayServer == DisplayServer.X11 || !string.IsNullOrEmpty(session.DisplayName))
            {
                args.Add("-f");
                args.Add("x11grab");

                int frameW = 0, frameH = 0;
                string input;
                var targetWin = windowId > 0
                    ? GetDesktopWindows().FirstOrDefault(w => w.Hwnd == windowId)
                    : null;

                if (targetWin != null)
                {
                    frameW = targetWin.Width;
                    frameH = targetWin.Height;
                    input = $"{display}.0+{targetWin.X},{targetWin.Y}";
                }
                else
                {
                    (frameW, frameH) = GetDesktopGeometry();
                    input = $"{display}.0";
                }

                // Without a reliable size, let x11grab probe the display itself.
                if (frameW > 0 && frameH > 0)
                {
                    args.Add("-video_size");
                    args.Add($"{frameW}x{frameH}");
                }
                args.Add("-i");
                args.Add(input);
            }
            else
            {
                // Native Wayland compositors only expose screen content through the XDG Desktop
                // Portal (ScreenCast). Until that portal client exists, refuse rather than
                // bypassing the compositor's security model with a root KMS/kmsgrab capture.
                if (session.DisplayServer == DisplayServer.Wayland)
                {
                    _logger.Warning("LinuxDesktopManager: Pure Wayland session without XWayland; screen capture requires an XDG Desktop Portal ScreenCast grant, which is not implemented. Refusing.");
                }
                return Array.Empty<byte>();
            }

            args.Add("-frames:v");
            args.Add("1");
            args.Add("-q:v");
            args.Add(qscale.ToString());
            args.Add("-y");
            args.Add(tmpFile);

            var psi = new ProcessStartInfo
            {
                FileName = ffmpeg,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            PlatformDetection.ApplySessionEnvironment(psi, session);

            // The daemon runs as root; ffmpeg only needs the user's X session. Drop privileges so a
            // capture failure can never become a root file-write primitive.
            bool isRoot = OperatingSystem.IsLinux() && geteuid() == 0;
            if (isRoot)
            {
                string? sessionUser = !string.IsNullOrEmpty(session.UserName) && session.UserName != "root" ? session.UserName : null;
                if (sessionUser == null)
                {
                    _logger.Warning("LinuxDesktopManager: Refusing screen capture as root without an active non-root session user.");
                    return Array.Empty<byte>();
                }
                var runPsi = new ProcessStartInfo
                {
                    FileName = "/usr/sbin/runuser",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                if (!File.Exists(runPsi.FileName)) runPsi.FileName = "/sbin/runuser";
                foreach (System.Collections.DictionaryEntry kv in psi.EnvironmentVariables) runPsi.EnvironmentVariables[(string)kv.Key] = (string?)kv.Value;
                runPsi.ArgumentList.Add("-u");
                runPsi.ArgumentList.Add(sessionUser);
                runPsi.ArgumentList.Add("--");
                runPsi.ArgumentList.Add(ffmpeg);
                foreach (var a in args) runPsi.ArgumentList.Add(a);
                psi = runPsi;
            }
            else
            {
                foreach (var a in args) psi.ArgumentList.Add(a);
            }

            using var p = Process.Start(psi);
            if (p != null)
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                try
                {
                    await p.WaitForExitAsync(timeoutCts.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    try { p.Kill(true); } catch { }
                    _logger.Warning("LinuxDesktopManager: ffmpeg capture timed out.");
                    try { if (File.Exists(tmpFile)) File.Delete(tmpFile); } catch { }
                    return Array.Empty<byte>();
                }

                if (p.ExitCode == 0 && File.Exists(tmpFile))
                {
                    byte[] bytes = await File.ReadAllBytesAsync(tmpFile, ct);
                    try { File.Delete(tmpFile); } catch { }
                    if (bytes.Length > 0)
                    {
                        return bytes;
                    }
                }
            }
            try { if (File.Exists(tmpFile)) File.Delete(tmpFile); } catch { }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxDesktopManager capture error: {ex.Message}");
        }

        // Return empty on failure. Never disguise failure with synthetic output.
        return Array.Empty<byte>();
    }
}
