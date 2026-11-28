using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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

    public (int Width, int Height) GetDesktopGeometry()
    {
        try
        {
            var session = PlatformDetection.GetActiveSessionInfo();
            var psi = new ProcessStartInfo
            {
                FileName = "wmctrl",
                Arguments = "-d",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            if (!string.IsNullOrEmpty(session.DisplayName)) psi.EnvironmentVariables["DISPLAY"] = session.DisplayName;
            string? xauth = session.XdgRuntimeDir != null ? Path.Combine(session.XdgRuntimeDir, "Xauthority") : null;
            if (xauth != null && File.Exists(xauth)) psi.EnvironmentVariables["XAUTHORITY"] = xauth;

            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(500);
                if (p.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    // Look for: DG: 1920x1080
                    var match = Regex.Match(output, @"DG:\s*(\d+)x(\d+)");
                    if (match.Success &&
                        int.TryParse(match.Groups[1].Value, out int w) &&
                        int.TryParse(match.Groups[2].Value, out int h))
                    {
                        return (Math.Max(640, w), Math.Max(480, h));
                    }
                }
            }
        }
        catch { }

        return (1920, 1080);
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

        // Query real X11 / XWayland windows via wmctrl
        try
        {
            var session = PlatformDetection.GetActiveSessionInfo();
            var psi = new ProcessStartInfo
            {
                FileName = "wmctrl",
                Arguments = "-l -p -G",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            if (!string.IsNullOrEmpty(session.DisplayName)) psi.EnvironmentVariables["DISPLAY"] = session.DisplayName;
            string? xauth = session.XdgRuntimeDir != null ? Path.Combine(session.XdgRuntimeDir, "Xauthority") : null;
            if (xauth != null && File.Exists(xauth)) psi.EnvironmentVariables["XAUTHORITY"] = xauth;

            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(1000);
                if (p.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
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
                            int x = 0, y = 0, w = 1920, h = 1080;
                            int.TryParse(parts[3], out x);
                            int.TryParse(parts[4], out y);
                            int.TryParse(parts[5], out w);
                            int.TryParse(parts[6], out h);
                            string title = parts.Length > 8 ? string.Join(" ", parts.Skip(8)).Trim() : parts[7];

                            if (hwnd != 0 && !string.IsNullOrEmpty(title))
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
                                    Width = Math.Max(100, w),
                                    Height = Math.Max(100, h)
                                });
                            }
                        }
                    }
                }
            }
        }
        catch { }

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

    public async Task<byte[]> CaptureJpegFrameAsync(int quality, long windowId, CancellationToken ct)
    {
        var session = PlatformDetection.GetActiveSessionInfo();
        string display = !string.IsNullOrEmpty(session.DisplayName) ? session.DisplayName : ":0";

        // ffmpeg is exposed by distro packages, snap/flatpak and /usr/local; probe PATH-like locations.
        string ffmpeg = new[] { "/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/bin/ffmpeg", "/snap/bin/ffmpeg" }
            .FirstOrDefault(File.Exists) ?? "";
        if (ffmpeg.Length == 0)
        {
            _logger.Warning("LinuxDesktopManager: ffmpeg is not installed; screen capture unavailable.");
            return Array.Empty<byte>();
        }

        try
        {
            string tmpFile = Path.Combine(Path.GetTempPath(), $"tether_cap_{Guid.NewGuid():N}.jpg");
            int qscale = Math.Clamp(31 - (quality * 30 / 100), 2, 31); // ffmpeg mjpeg q:v 2 (best) to 31 (lowest)

            var psi = new ProcessStartInfo
            {
                FileName = ffmpeg,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            if (!string.IsNullOrEmpty(session.DisplayName)) psi.EnvironmentVariables["DISPLAY"] = session.DisplayName;
            string? xauth = session.XdgRuntimeDir != null ? Path.Combine(session.XdgRuntimeDir, "Xauthority") : null;
            if (xauth != null && File.Exists(xauth)) psi.EnvironmentVariables["XAUTHORITY"] = xauth;

            // X11 Screen or Window Capture
            if (session.DisplayServer == DisplayServer.X11 || !string.IsNullOrEmpty(session.DisplayName))
            {
                psi.ArgumentList.Add("-f");
                psi.ArgumentList.Add("x11grab");

                if (windowId > 0)
                {
                    var windows = GetDesktopWindows();
                    var targetWin = windows.FirstOrDefault(w => w.Hwnd == windowId);
                    if (targetWin != null)
                    {
                        psi.ArgumentList.Add("-video_size");
                        psi.ArgumentList.Add($"{targetWin.Width}x{targetWin.Height}");
                        psi.ArgumentList.Add("-i");
                        psi.ArgumentList.Add($"{display}.0+{targetWin.X},{targetWin.Y}");
                    }
                    else
                    {
                        var (dw, dh) = GetDesktopGeometry();
                        psi.ArgumentList.Add("-video_size");
                        psi.ArgumentList.Add($"{dw}x{dh}");
                        psi.ArgumentList.Add("-i");
                        psi.ArgumentList.Add($"{display}.0");
                    }
                }
                else
                {
                    var (dw, dh) = GetDesktopGeometry();
                    psi.ArgumentList.Add("-video_size");
                    psi.ArgumentList.Add($"{dw}x{dh}");
                    psi.ArgumentList.Add("-i");
                    psi.ArgumentList.Add($"{display}.0");
                }
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

            psi.ArgumentList.Add("-frames:v");
            psi.ArgumentList.Add("1");
            psi.ArgumentList.Add("-q:v");
            psi.ArgumentList.Add(qscale.ToString());
            psi.ArgumentList.Add("-y");
            psi.ArgumentList.Add(tmpFile);

            using var p = Process.Start(psi);
            if (p != null)
            {
                await p.WaitForExitAsync(ct);
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
