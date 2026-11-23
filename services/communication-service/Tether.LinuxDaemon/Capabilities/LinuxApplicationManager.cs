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
    [JsonPropertyName("isMinimized")] public bool IsMinimized { get; init; }
    [JsonPropertyName("isMaximized")] public bool IsMaximized { get; init; }
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

    public static List<LinuxRunningWindow> GetRunningWindows(ITetherLogger logger)
    {
        var windows = new List<LinuxRunningWindow>();

        try
        {
            var session = PlatformDetection.GetActiveSessionInfo();
            string uidStr = session.Uid > 0 ? session.Uid.ToString() : "1000";

            // Try wmctrl -l -p -x
            var psi = new ProcessStartInfo
            {
                FileName = "wmctrl",
                Arguments = "-l -p -x",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.EnvironmentVariables["DISPLAY"] = ":0";
            psi.EnvironmentVariables["XDG_RUNTIME_DIR"] = $"/run/user/{uidStr}";

            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(1000);

                // Format: <winId> <desk> <pid> <class> <client> <title>
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = Regex.Split(line.Trim(), @"\s+");
                    if (parts.Length >= 5)
                    {
                        string idHex = parts[0];
                        long hwnd = 0;
                        if (idHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        {
                            long.TryParse(idHex.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out hwnd);
                        }

                        int.TryParse(parts[2], out int pid);
                        string procName = parts[3];
                        string title = string.Join(" ", parts.Skip(5));

                        windows.Add(new LinuxRunningWindow
                        {
                            Hwnd = hwnd > 0 ? hwnd : (pid > 0 ? pid : 1),
                            Title = string.IsNullOrWhiteSpace(title) ? procName : title,
                            ProcessName = procName,
                            Pid = pid,
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
            var session = PlatformDetection.GetActiveSessionInfo();
            string uidStr = session.Uid > 0 ? session.Uid.ToString() : "1000";

            // If desktop file id, try gtk-launch
            string clean = appNameOrExec.Trim();
            if (clean.EndsWith(".desktop", StringComparison.OrdinalIgnoreCase))
            {
                clean = clean.Substring(0, clean.Length - 8);
            }

            var psi = new ProcessStartInfo
            {
                FileName = "gtk-launch",
                Arguments = $"\"{clean}\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = $"unix:path=/run/user/{uidStr}/bus";
            psi.EnvironmentVariables["DISPLAY"] = ":0";
            psi.EnvironmentVariables["WAYLAND_DISPLAY"] = "wayland-0";
            psi.EnvironmentVariables["XDG_RUNTIME_DIR"] = $"/run/user/{uidStr}";

            using var p = Process.Start(psi);
            if (p != null)
            {
                await p.WaitForExitAsync();
                if (p.ExitCode == 0) return true;
            }

            // Fallback: spawn binary directly
            var psiDirect = new ProcessStartInfo
            {
                FileName = clean.Split(' ')[0],
                Arguments = clean.Contains(' ') ? clean.Substring(clean.IndexOf(' ') + 1) : "",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psiDirect.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = $"unix:path=/run/user/{uidStr}/bus";
            psiDirect.EnvironmentVariables["DISPLAY"] = ":0";
            psiDirect.EnvironmentVariables["WAYLAND_DISPLAY"] = "wayland-0";
            psiDirect.EnvironmentVariables["XDG_RUNTIME_DIR"] = $"/run/user/{uidStr}";

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

            // Try wmctrl -i -a <id>
            var psi = new ProcessStartInfo
            {
                FileName = "wmctrl",
                Arguments = $"-i -a {id}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
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

    public static async Task<bool> CloseWindowAsync(string windowIdOrPid, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(windowIdOrPid)) return false;

        try
        {
            string id = windowIdOrPid.Trim();

            // 1. Try wmctrl -i -c <hex>
            if (id.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "wmctrl",
                    Arguments = $"-i -c {id}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p != null)
                {
                    await p.WaitForExitAsync();
                    if (p.ExitCode == 0) return true;
                }
            }

            // 2. Try kill by pid
            if (int.TryParse(id, out int pid) && pid > 1)
            {
                var proc = Process.GetProcessById(pid);
                proc.Kill();
                return true;
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"LinuxApplicationManager: CloseWindowAsync '{windowIdOrPid}' error: {ex.Message}");
        }

        return false;
    }
}
