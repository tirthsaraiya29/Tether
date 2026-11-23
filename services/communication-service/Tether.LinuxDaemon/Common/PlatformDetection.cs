using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Tether.LinuxDaemon.Common;

public enum DisplayServer
{
    Unknown,
    Wayland,
    X11,
    Headless
}

public enum DesktopEnvironment
{
    Unknown,
    Gnome,
    Kde,
    Xfce,
    Other
}

public sealed class LinuxSessionInfo
{
    public uint SessionId { get; init; }
    public uint Uid { get; init; }
    public string UserName { get; init; } = "";
    public DisplayServer DisplayServer { get; init; } = DisplayServer.Unknown;
    public DesktopEnvironment DesktopEnvironment { get; init; } = DesktopEnvironment.Unknown;
    public string? DisplayName { get; init; }
    public string? WaylandDisplay { get; init; }
    public string? XdgRuntimeDir { get; init; }
    public bool IsLocked { get; init; }
}

public static class PlatformDetection
{
    [DllImport("libc", SetLastError = true)]
    private static extern uint geteuid();

    public static bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

    public static bool IsRoot => IsLinux && geteuid() == 0;

    public static string GetDistributionName()
    {
        if (!IsLinux) return "Non-Linux";

        try
        {
            if (File.Exists("/etc/os-release"))
            {
                foreach (var line in File.ReadAllLines("/etc/os-release"))
                {
                    if (line.StartsWith("PRETTY_NAME=", StringComparison.OrdinalIgnoreCase))
                    {
                        return line.Substring("PRETTY_NAME=".Length).Trim('"', '\'');
                    }
                }
            }
        }
        catch { }

        return "Linux (Generic)";
    }

    public static LinuxSessionInfo GetActiveSessionInfo()
    {
        uint uid = 1000;
        string userName = Environment.UserName;
        uint sessionId = 1;
        DisplayServer displayServer = DisplayServer.Unknown;
        DesktopEnvironment de = DesktopEnvironment.Unknown;
        string? display = Environment.GetEnvironmentVariable("DISPLAY");
        string? waylandDisplay = Environment.GetEnvironmentVariable("WAYLAND_DISPLAY");
        string? xdgRuntime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        bool isLocked = false;

        string currentDesktop = Environment.GetEnvironmentVariable("XDG_CURRENT_DESKTOP") ?? "";
        if (currentDesktop.Contains("GNOME", StringComparison.OrdinalIgnoreCase)) de = DesktopEnvironment.Gnome;
        else if (currentDesktop.Contains("KDE", StringComparison.OrdinalIgnoreCase)) de = DesktopEnvironment.Kde;
        else if (currentDesktop.Contains("XFCE", StringComparison.OrdinalIgnoreCase)) de = DesktopEnvironment.Xfce;
        else if (!string.IsNullOrEmpty(currentDesktop)) de = DesktopEnvironment.Other;

        // Try querying systemd loginctl for active graphical session
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "loginctl",
                Arguments = "list-sessions --no-legend",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(1000);

                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var tokens = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (tokens.Length >= 3)
                    {
                        if (uint.TryParse(tokens[0], out var sid))
                        {
                            var sInfo = QuerySessionDetails(sid);
                            if (sInfo != null && (sInfo.DisplayServer == DisplayServer.Wayland || sInfo.DisplayServer == DisplayServer.X11))
                            {
                                return sInfo;
                            }
                        }
                    }
                }
            }
        }
        catch { }

        if (!string.IsNullOrEmpty(waylandDisplay))
        {
            displayServer = DisplayServer.Wayland;
        }
        else if (!string.IsNullOrEmpty(display))
        {
            displayServer = DisplayServer.X11;
        }

        return new LinuxSessionInfo
        {
            SessionId = sessionId,
            Uid = uid,
            UserName = userName,
            DisplayServer = displayServer,
            DesktopEnvironment = de,
            DisplayName = display,
            WaylandDisplay = waylandDisplay,
            XdgRuntimeDir = xdgRuntime ?? $"/run/user/{uid}",
            IsLocked = isLocked
        };
    }

    private static LinuxSessionInfo? QuerySessionDetails(uint sessionId)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "loginctl",
                Arguments = $"show-session {sessionId}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return null;

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(1000);

            uint uid = 1000;
            string userName = "";
            string type = "";
            string state = "";
            string display = "";
            bool lockedHint = false;

            foreach (var rawLine in output.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("User=")) uint.TryParse(line.Substring(5), out uid);
                else if (line.StartsWith("Name=")) userName = line.Substring(5);
                else if (line.StartsWith("Type=")) type = line.Substring(5);
                else if (line.StartsWith("State=")) state = line.Substring(6);
                else if (line.StartsWith("Display=")) display = line.Substring(8);
                else if (line.StartsWith("LockedHint=")) lockedHint = line.Substring(11).Equals("yes", StringComparison.OrdinalIgnoreCase);
            }

            DisplayServer ds = type.ToLowerInvariant() switch
            {
                "wayland" => DisplayServer.Wayland,
                "x11" => DisplayServer.X11,
                "tty" => DisplayServer.Headless,
                _ => DisplayServer.Unknown
            };

            return new LinuxSessionInfo
            {
                SessionId = sessionId,
                Uid = uid,
                UserName = userName,
                DisplayServer = ds,
                DesktopEnvironment = DesktopEnvironment.Gnome,
                DisplayName = !string.IsNullOrEmpty(display) ? display : (ds == DisplayServer.X11 ? ":0" : null),
                WaylandDisplay = (ds == DisplayServer.Wayland) ? "wayland-0" : null,
                XdgRuntimeDir = $"/run/user/{uid}",
                IsLocked = lockedHint
            };
        }
        catch
        {
            return null;
        }
    }
}
