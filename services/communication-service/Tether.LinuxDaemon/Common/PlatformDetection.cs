using System;
using System.Collections.Generic;
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

    public static string? GetUserHomeDirectory(string? userName)
    {
        if (string.IsNullOrEmpty(userName)) return null;

        try
        {
            foreach (var line in File.ReadLines("/etc/passwd"))
            {
                var parts = line.Split(':');
                if (parts.Length >= 7 && parts[0] == userName && !string.IsNullOrEmpty(parts[5]))
                {
                    return parts[5];
                }
            }
        }
        catch { }

        foreach (var candidate in new[] { $"/home/{userName}", $"/var/home/{userName}" })
        {
            if (Directory.Exists(candidate)) return candidate;
        }
        return null;
    }

    /// <summary>
    /// Populates the environment a desktop tool needs to reach the user's session
    /// (display, X authorisation cookie, session bus, runtime dir).
    /// </summary>
    public static void ApplySessionEnvironment(ProcessStartInfo psi, LinuxSessionInfo session)
    {
        string runtimeDir = !string.IsNullOrEmpty(session.XdgRuntimeDir)
            ? session.XdgRuntimeDir
            : $"/run/user/{session.Uid}";

        psi.Environment["XDG_RUNTIME_DIR"] = runtimeDir;
        psi.Environment["DBUS_SESSION_BUS_ADDRESS"] = $"unix:path={runtimeDir}/bus";
        if (!string.IsNullOrEmpty(session.DisplayName)) psi.Environment["DISPLAY"] = session.DisplayName;
        if (!string.IsNullOrEmpty(session.WaylandDisplay)) psi.Environment["WAYLAND_DISPLAY"] = session.WaylandDisplay;

        string? xauth = Path.Combine(runtimeDir, "Xauthority");
        if (!File.Exists(xauth))
        {
            string? home = GetUserHomeDirectory(session.UserName);
            string? homeXauth = home != null ? Path.Combine(home, ".Xauthority") : null;
            xauth = homeXauth != null && File.Exists(homeXauth) ? homeXauth : null;
        }
        if (xauth != null) psi.Environment["XAUTHORITY"] = xauth;
    }

    /// <summary>
    /// Builds a ProcessStartInfo that runs a tool as the active desktop user. The daemon is
    /// root, so running display/audio clients directly would target root's empty session.
    /// </summary>
    public static ProcessStartInfo CreateSessionProcessInfo(string tool, IReadOnlyList<string> args, bool redirectOutput = false)
    {
        var session = GetActiveSessionInfo();
        var psi = new ProcessStartInfo
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = redirectOutput,
            RedirectStandardError = redirectOutput
        };

        bool dropPrivileges = IsRoot && !string.IsNullOrEmpty(session.UserName) && session.UserName != "root";
        if (dropPrivileges)
        {
            psi.FileName = File.Exists("/usr/sbin/runuser") ? "/usr/sbin/runuser" : "/sbin/runuser";
            psi.ArgumentList.Add("-u");
            psi.ArgumentList.Add(session.UserName);
            psi.ArgumentList.Add("--");
        }
        else
        {
            psi.FileName = tool;
        }

        psi.ArgumentList.Add(tool);
        foreach (var a in args) psi.ArgumentList.Add(a);
        ApplySessionEnvironment(psi, session);
        return psi;
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
