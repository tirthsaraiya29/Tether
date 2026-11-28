using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
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
    public string? XAuthority { get; init; }
    public string? DesktopName { get; init; }
    public bool IsLocked { get; init; }
    public bool IsActive { get; init; }
    public bool IsRemote { get; init; }
    public int LeaderProcessId { get; init; }
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

        string? xauth = session.XAuthority ?? Path.Combine(runtimeDir, "Xauthority");
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
        var candidates = new List<LinuxSessionInfo>();
        try
        {
            string sessions = RunLoginCtl("list-sessions", "--no-legend", "--no-pager");
            foreach (string line in sessions.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                string[] fields = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length == 0 || !uint.TryParse(fields[0], out uint id)) continue;
                var candidate = QuerySessionDetails(id);
                if (candidate != null && candidate.IsActive && !candidate.IsRemote &&
                    (candidate.DisplayServer == DisplayServer.Wayland || candidate.DisplayServer == DisplayServer.X11))
                    candidates.Add(candidate);
            }
        }
        catch { }

        // Prefer a session with a real display endpoint and a live session leader.
        var selected = candidates
            .OrderByDescending(s => s.DisplayServer == DisplayServer.Wayland
                ? !string.IsNullOrWhiteSpace(s.WaylandDisplay)
                : !string.IsNullOrWhiteSpace(s.DisplayName))
            .ThenByDescending(s => s.LeaderProcessId > 0)
            .FirstOrDefault();
        if (selected != null) return selected;

        // No logind session (containers/minimal systems): use the daemon's real UID and
        // inherited environment. Never guess UID 1000, :0, wayland-0, or GNOME.
        uint uid = IsLinux ? geteuid() : 0;
        string user = GetUserNameForUid(uid) ?? Environment.UserName;
        string? display = Environment.GetEnvironmentVariable("DISPLAY");
        string? wayland = Environment.GetEnvironmentVariable("WAYLAND_DISPLAY");
        string? runtime = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        string desktop = Environment.GetEnvironmentVariable("XDG_CURRENT_DESKTOP") ?? "";
        var server = !string.IsNullOrWhiteSpace(wayland) ? DisplayServer.Wayland
            : !string.IsNullOrWhiteSpace(display) ? DisplayServer.X11
            : DisplayServer.Headless;
        if (string.IsNullOrWhiteSpace(wayland) && server == DisplayServer.Wayland)
            wayland = FindWaylandSocket(runtime ?? $"/run/user/{uid}");

        return new LinuxSessionInfo
        {
            SessionId = 0,
            Uid = uid,
            UserName = user,
            DisplayServer = server,
            DesktopEnvironment = ParseDesktopEnvironment(desktop),
            DesktopName = desktop,
            DisplayName = display,
            WaylandDisplay = wayland,
            XdgRuntimeDir = runtime ?? (Directory.Exists($"/run/user/{uid}") ? $"/run/user/{uid}" : null),
            IsActive = server != DisplayServer.Headless
        };
    }

    private static LinuxSessionInfo? QuerySessionDetails(uint sessionId)
    {
        try
        {
            string output = RunLoginCtl("show-session", sessionId.ToString(), "--no-pager");
            if (string.IsNullOrWhiteSpace(output)) return null;

            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in output.Split('\n'))
            {
                int equals = raw.IndexOf('=');
                if (equals > 0) values[raw[..equals].Trim()] = raw[(equals + 1)..].Trim();
            }

            uint.TryParse(Value(values, "User"), out uint uid);
            int.TryParse(Value(values, "Leader"), out int leader);
            string name = Value(values, "Name");
            string type = Value(values, "Type");
            string state = Value(values, "State");
            bool active = Value(values, "Active").Equals("yes", StringComparison.OrdinalIgnoreCase)
                || state.Equals("active", StringComparison.OrdinalIgnoreCase);
            bool remote = Value(values, "Remote").Equals("yes", StringComparison.OrdinalIgnoreCase);
            bool locked = Value(values, "LockedHint").Equals("yes", StringComparison.OrdinalIgnoreCase);

            var env = leader > 0 ? ReadProcessEnvironment(leader) : new Dictionary<string, string>();
            string? runtime = EnvironmentValue(env, "XDG_RUNTIME_DIR");
            if (string.IsNullOrWhiteSpace(runtime) && Directory.Exists($"/run/user/{uid}"))
                runtime = $"/run/user/{uid}";

            string? display = EnvironmentValue(env, "DISPLAY") ?? NullIfEmpty(Value(values, "Display"));
            string? wayland = EnvironmentValue(env, "WAYLAND_DISPLAY");
            if (type.Equals("wayland", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(wayland))
                wayland = FindWaylandSocket(runtime);

            string desktop = Value(values, "Desktop");
            if (string.IsNullOrWhiteSpace(desktop))
                desktop = EnvironmentValue(env, "XDG_CURRENT_DESKTOP") ?? EnvironmentValue(env, "DESKTOP_SESSION") ?? "";

            string? xauth = EnvironmentValue(env, "XAUTHORITY");
            var server = type.ToLowerInvariant() switch
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
                UserName = string.IsNullOrWhiteSpace(name) ? GetUserNameForUid(uid) ?? "" : name,
                DisplayServer = server,
                DesktopEnvironment = ParseDesktopEnvironment(desktop),
                DesktopName = desktop,
                DisplayName = display,
                WaylandDisplay = wayland,
                XdgRuntimeDir = runtime,
                XAuthority = xauth,
                IsLocked = locked,
                IsActive = active,
                IsRemote = remote,
                LeaderProcessId = leader
            };
        }
        catch { return null; }
    }

    private static string RunLoginCtl(params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "loginctl",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            foreach (string arg in args) psi.ArgumentList.Add(arg);
            using var process = Process.Start(psi);
            if (process == null) return "";
            var stdout = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(1500))
            {
                try { process.Kill(true); } catch { }
                try { process.WaitForExit(500); } catch { }
                return "";
            }
            return stdout.GetAwaiter().GetResult();
        }
        catch { return ""; }
    }

    private static Dictionary<string, string> ReadProcessEnvironment(int pid)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            byte[] bytes = File.ReadAllBytes($"/proc/{pid}/environ");
            foreach (string entry in Encoding.UTF8.GetString(bytes).Split('\0', StringSplitOptions.RemoveEmptyEntries))
            {
                int equals = entry.IndexOf('=');
                if (equals > 0) result[entry[..equals]] = entry[(equals + 1)..];
            }
        }
        catch { }
        return result;
    }

    private static string? FindWaylandSocket(string? runtime)
    {
        if (string.IsNullOrWhiteSpace(runtime) || !Directory.Exists(runtime)) return null;
        try
        {
            return Directory.GetFiles(runtime, "wayland-*", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileName)
                .FirstOrDefault(name => !string.IsNullOrWhiteSpace(name));
        }
        catch { return null; }
    }

    private static string Value(Dictionary<string, string> values, string key) =>
        values.TryGetValue(key, out string? value) ? value : "";

    private static string? EnvironmentValue(Dictionary<string, string> values, string key) =>
        values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    private static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static string? GetUserNameForUid(uint uid)
    {
        try
        {
            foreach (string line in File.ReadLines("/etc/passwd"))
            {
                string[] parts = line.Split(':');
                if (parts.Length >= 7 && uint.TryParse(parts[2], out uint candidate) && candidate == uid)
                    return parts[0];
            }
        }
        catch { }
        return null;
    }

    private static DesktopEnvironment ParseDesktopEnvironment(string desktop)
    {
        if (desktop.Contains("GNOME", StringComparison.OrdinalIgnoreCase)) return DesktopEnvironment.Gnome;
        if (desktop.Contains("KDE", StringComparison.OrdinalIgnoreCase) || desktop.Contains("PLASMA", StringComparison.OrdinalIgnoreCase)) return DesktopEnvironment.Kde;
        if (desktop.Contains("XFCE", StringComparison.OrdinalIgnoreCase)) return DesktopEnvironment.Xfce;
        return string.IsNullOrWhiteSpace(desktop) ? DesktopEnvironment.Unknown : DesktopEnvironment.Other;
    }
}
