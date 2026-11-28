using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Desktop;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Capabilities;

public sealed record LinuxInstalledApp
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("path")] public string Path { get; init; } = "";
    [JsonPropertyName("iconB64")] public string? IconB64 { get; init; }
}

public sealed record LinuxRunningWindow
{
    [JsonPropertyName("hwnd")] public long Hwnd { get; init; }
    [JsonPropertyName("title")] public string Title { get; init; } = "";
    [JsonPropertyName("processName")] public string ProcessName { get; init; } = "";
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("width")] public int Width { get; init; }
    [JsonPropertyName("height")] public int Height { get; init; }
    [JsonPropertyName("isMinimized")] public bool IsMinimized { get; init; }
    [JsonPropertyName("isMaximized")] public bool IsMaximized { get; init; }
    [JsonPropertyName("iconB64")] public string? IconB64 { get; init; }
}

public static class LinuxApplicationManager
{
    public static List<LinuxInstalledApp> GetInstalledApps(ITetherLogger logger)
    {
        var apps = new Dictionary<string, LinuxInstalledApp>(StringComparer.OrdinalIgnoreCase);

        var searchDirs = new List<string> { "/usr/share/applications", "/usr/local/share/applications" };
        var session = PlatformDetection.GetActiveSessionInfo();
        if (!string.IsNullOrEmpty(session.UserName))
        {
            searchDirs.Add($"/home/{session.UserName}/.local/share/applications");
        }

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*.desktop"))
                {
                    try
                    {
                        var app = ParseDesktopFile(file);
                        if (app != null && !string.IsNullOrWhiteSpace(app.Name) && !apps.ContainsKey(app.Name))
                        {
                            apps[app.Name] = app;
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                logger.Debug($"LinuxApplicationManager: Failed reading {dir}: {ex.Message}");
            }
        }

        return apps.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static LinuxInstalledApp? ParseDesktopFile(string path)
    {
        string? name = null;
        string? exec = null;
        string? icon = null;
        bool noDisplay = false;
        bool isApplication = false;

        foreach (var rawLine in File.ReadLines(path))
        {
            string line = rawLine.Trim();
            if (line.StartsWith("[") && line != "[Desktop Entry]")
            {
                break; // only parse [Desktop Entry] section
            }

            if (line.StartsWith("Type=", StringComparison.OrdinalIgnoreCase))
            {
                if (line.Substring(5).Trim().Equals("Application", StringComparison.OrdinalIgnoreCase))
                {
                    isApplication = true;
                }
            }
            else if (line.StartsWith("Name=", StringComparison.OrdinalIgnoreCase) && name == null)
            {
                name = line.Substring(5).Trim();
            }
            else if (line.StartsWith("Exec=", StringComparison.OrdinalIgnoreCase) && exec == null)
            {
                exec = line.Substring(5).Trim();
            }
            else if (line.StartsWith("Icon=", StringComparison.OrdinalIgnoreCase) && icon == null)
            {
                icon = line.Substring(5).Trim();
            }
            else if (line.StartsWith("NoDisplay=", StringComparison.OrdinalIgnoreCase))
            {
                if (bool.TryParse(line.Substring(10).Trim(), out bool nd) && nd)
                {
                    noDisplay = true;
                }
            }
        }

        if (!isApplication || noDisplay || string.IsNullOrEmpty(name))
        {
            return null;
        }

        // Clean exec flags (%u, %f, %U, %F, etc.)
        string cleanExec = exec != null ? Regex.Replace(exec, @"%[a-zA-Z]", "").Trim() : Path.GetFileNameWithoutExtension(path);

        string? iconB64 = ResolveIconBase64(icon);

        return new LinuxInstalledApp
        {
            Name = name,
            Path = cleanExec,
            IconB64 = iconB64
        };
    }

    private static string? ResolveIconBase64(string? iconName)
    {
        if (string.IsNullOrWhiteSpace(iconName)) return null;

        try
        {
            // If already absolute path
            if (File.Exists(iconName))
            {
                if (iconName.EndsWith(".png", StringComparison.OrdinalIgnoreCase) && new FileInfo(iconName).Length <= 200_000)
                {
                    return Convert.ToBase64String(File.ReadAllBytes(iconName));
                }
            }

            // Check /usr/share/pixmaps
            string pixmapPath = $"/usr/share/pixmaps/{iconName}.png";
            if (File.Exists(pixmapPath) && new FileInfo(pixmapPath).Length <= 200_000)
            {
                return Convert.ToBase64String(File.ReadAllBytes(pixmapPath));
            }
        }
        catch { }

        return null;
    }

    private static readonly Regex WindowIdPattern = new(@"^(0x[0-9a-fA-F]{1,16}|[0-9]{1,10})$", RegexOptions.Compiled);

    public static List<LinuxRunningWindow> GetRunningWindows(ITetherLogger logger)
    {
        var windows = new List<LinuxRunningWindow>();

        var session = PlatformDetection.GetActiveSessionInfo();
        if (string.IsNullOrEmpty(session.DisplayName) && session.DisplayServer == DisplayServer.Wayland)
        {
            // Wayland deliberately does not expose global window enumeration; XWayland is unknown here.
            logger.Info("LinuxApplicationManager: Window enumeration is not supported on this pure Wayland session.");
            return windows;
        }

        try
        {
            var psi = PlatformDetection.CreateSessionProcessInfo("wmctrl", new[] { "-l", "-p", "-G", "-x" }, redirectOutput: true);
            using var p = Process.Start(psi);
            if (p != null)
            {
                bool exited = p.WaitForExit(1500);
                string output = p.StandardOutput.ReadToEnd();
                if (!exited)
                {
                    try { p.Kill(true); } catch { }
                    logger.Warning("LinuxApplicationManager: wmctrl timed out.");
                    return windows;
                }
                if (p.ExitCode != 0)
                {
                    logger.Warning($"LinuxApplicationManager: wmctrl failed (exit {p.ExitCode}); window list unavailable.");
                    return windows;
                }

                // Format with -G: <winId> <desk> <pid> <x> <y> <w> <h> <class> <client> <title>
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = Regex.Split(line.Trim(), @"\s+");
                    if (parts.Length >= 9)
                    {
                        string idHex = parts[0];
                        long hwnd = 0;
                        if (idHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        {
                            long.TryParse(idHex.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out hwnd);
                        }

                        int.TryParse(parts[2], out int pid);
                        int.TryParse(parts[5], out int width);
                        int.TryParse(parts[6], out int height);
                        string procName = parts[7];
                        string title = string.Join(" ", parts.Skip(9));

                        windows.Add(new LinuxRunningWindow
                        {
                            Hwnd = hwnd > 0 ? hwnd : (pid > 0 ? pid : 1),
                            Title = string.IsNullOrWhiteSpace(title) ? procName : title,
                            ProcessName = procName,
                            Pid = pid,
                            Width = Math.Max(0, width),
                            Height = Math.Max(0, height),
                            IsMinimized = false,
                            IsMaximized = false
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"LinuxApplicationManager: wmctrl error: {ex.Message}");
        }

        return windows;
    }

    public static async Task<bool> LaunchAppAsync(string appNameOrExec, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(appNameOrExec)) return false;

        try
        {
            // If desktop file id, try gtk-launch
            string clean = appNameOrExec.Trim();
            if (clean.EndsWith(".desktop", StringComparison.OrdinalIgnoreCase))
            {
                clean = clean.Substring(0, clean.Length - 8);
            }

            var psi = PlatformDetection.CreateSessionProcessInfo("gtk-launch", new[] { clean });
            using (var p = Process.Start(psi))
            {
                if (p != null)
                {
                    await p.WaitForExitAsync();
                    if (p.ExitCode == 0) return true;
                }
            }

            // Fallback: spawn the binary directly, still as the desktop user.
            string exe = clean.Split(' ')[0];
            if (string.IsNullOrWhiteSpace(exe)) return false;
            var directArgs = clean.Length > exe.Length
                ? clean.Substring(exe.Length).Split(' ', StringSplitOptions.RemoveEmptyEntries)
                : Array.Empty<string>();

            var psiDirect = PlatformDetection.CreateSessionProcessInfo(exe, directArgs);
            using var pDirect = Process.Start(psiDirect);
            return pDirect != null;
        }
        catch (Exception ex)
        {
            logger.Warning($"LinuxApplicationManager: LaunchAppAsync '{appNameOrExec}' error: {ex.Message}");
            return false;
        }
    }

    public static async Task<bool> ActivateWindowAsync(string windowIdOrPid, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(windowIdOrPid)) return false;

        try
        {
            string id = windowIdOrPid.Trim();
            if (!WindowIdPattern.IsMatch(id)) return false;

            var psi = PlatformDetection.CreateSessionProcessInfo("wmctrl", new[] { "-i", "-a", id });
            using var p = Process.Start(psi);
            if (p != null)
            {
                await p.WaitForExitAsync();
                return p.ExitCode == 0;
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"LinuxApplicationManager: ActivateWindowAsync '{windowIdOrPid}' error: {ex.Message}");
        }

        return false;
    }

    public static async Task<bool> CloseWindowAsync(string windowId, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(windowId)) return false;

        try
        {
            string id = windowId.Trim();
            if (!WindowIdPattern.IsMatch(id)) return false;

            // Ask the window manager to close the window. Never kill an arbitrary pid:
            // the value is a window id from the enumeration, not a process id.
            var psi = PlatformDetection.CreateSessionProcessInfo("wmctrl", new[] { "-i", "-c", id });
            using var p = Process.Start(psi);
            if (p != null)
            {
                await p.WaitForExitAsync();
                return p.ExitCode == 0;
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"LinuxApplicationManager: CloseWindowAsync '{windowId}' error: {ex.Message}");
        }

        return false;
    }

    public static async Task<bool> SetWindowStateAsync(string windowId, string state, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(windowId) || string.IsNullOrWhiteSpace(state)) return false;
        string id = windowId.Trim();
        if (!WindowIdPattern.IsMatch(id)) return false;

        string normalized = state.Trim().ToLowerInvariant();
        if (normalized is "snap_left" or "left") normalized = "left";
        else if (normalized is "snap_right" or "right") normalized = "right";

        string[] args;
        switch (normalized)
        {
            case "left":
            case "right":
                var (desktopW, desktopH) = new LinuxDesktopManager(logger).GetDesktopGeometry();
                if (desktopW <= 0 || desktopH <= 0) return false;
                int x = normalized == "left" ? 0 : desktopW / 2;
                args = new[] { "-i", "-r", id, "-e", $"0,{x},0,{desktopW / 2},{desktopH}" };
                break;
            case "maximize":
                args = new[] { "-i", "-r", id, "-b", "add,maximized_vert,maximized_horz" };
                break;
            case "minimize":
                args = new[] { "-i", "-r", id, "-b", "add,hidden" };
                break;
            case "restore":
                args = new[] { "-i", "-r", id, "-b", "remove,maximized_vert,maximized_horz" };
                break;
            default:
                return false;
        }

        try
        {
            var psi = PlatformDetection.CreateSessionProcessInfo("wmctrl", args);
            using var p = Process.Start(psi);
            if (p != null)
            {
                await p.WaitForExitAsync();
                return p.ExitCode == 0;
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"LinuxApplicationManager: SetWindowStateAsync '{windowId}' error: {ex.Message}");
        }
        return false;
    }
}
