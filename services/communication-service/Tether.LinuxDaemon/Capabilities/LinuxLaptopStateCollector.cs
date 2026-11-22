using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Protocol;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Capabilities;

public static class LinuxLaptopStateCollector
{
    private static readonly object _wallpaperLock = new();
    private static string? _cachedWallpaperPath;
    private static DateTime _cachedWallpaperMtime;
    private static string? _cachedWallpaperB64;
    private static string? _cachedWallpaperHash;

    public static (int batteryLevel, bool isCharging) GetBatteryInfo(ITetherLogger? logger = null)
    {
        int batteryLevel = -1;
        bool isCharging = false;

        try
        {
            if (Directory.Exists("/sys/class/power_supply"))
            {
                var dirs = Directory.GetDirectories("/sys/class/power_supply");

                // Check battery level
                foreach (var dir in dirs)
                {
                    string name = Path.GetFileName(dir);
                    if (name.StartsWith("BAT", StringComparison.OrdinalIgnoreCase))
                    {
                        string capFile = Path.Combine(dir, "capacity");
                        if (File.Exists(capFile))
                        {
                            string capStr = File.ReadAllText(capFile).Trim();
                            if (int.TryParse(capStr, out int cap))
                            {
                                batteryLevel = Math.Clamp(cap, 0, 100);
                            }
                        }

                        string statFile = Path.Combine(dir, "status");
                        if (File.Exists(statFile))
                        {
                            string status = File.ReadAllText(statFile).Trim();
                            if (status.Equals("Charging", StringComparison.OrdinalIgnoreCase) ||
                                status.Equals("Full", StringComparison.OrdinalIgnoreCase))
                            {
                                isCharging = true;
                            }
                        }
                        break;
                    }
                }

                // Check AC adapter if not already detected charging
                if (!isCharging)
                {
                    foreach (var dir in dirs)
                    {
                        string name = Path.GetFileName(dir);
                        if (name.StartsWith("AC", StringComparison.OrdinalIgnoreCase) ||
                            name.StartsWith("ADP", StringComparison.OrdinalIgnoreCase))
                        {
                            string onlineFile = Path.Combine(dir, "online");
                            if (File.Exists(onlineFile))
                            {
                                string onlineStr = File.ReadAllText(onlineFile).Trim();
                                if (onlineStr == "1")
                                {
                                    isCharging = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger?.Debug($"LinuxLaptopStateCollector: Battery probe failed: {ex.Message}");
        }

        return (batteryLevel, isCharging);
    }

    public static string GetLockState(ITetherLogger? logger = null)
    {
        try
        {
            var session = PlatformDetection.GetActiveSessionInfo();
            if (session.SessionId == 0)
            {
                return "UNKNOWN";
            }

            var psi = new ProcessStartInfo
            {
                FileName = "loginctl",
                Arguments = $"show-session {session.SessionId} -p LockedHint --value",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = p.StandardOutput.ReadToEnd().Trim();
                p.WaitForExit(1000);
                if (output.Equals("yes", StringComparison.OrdinalIgnoreCase))
                {
                    return "LOCKED";
                }
                if (output.Equals("no", StringComparison.OrdinalIgnoreCase))
                {
                    return "UNLOCKED";
                }
            }
        }
        catch (Exception ex)
        {
            logger?.Debug($"LinuxLaptopStateCollector: Lock state check failed: {ex.Message}");
        }

        return "UNKNOWN";
    }

    public static string? DetectWallpaperPath(ITetherLogger? logger = null)
    {
        var session = PlatformDetection.GetActiveSessionInfo();

        // 1. Try GNOME gsettings if session user is available
        if (!string.IsNullOrEmpty(session.UserName))
        {
            try
            {
                string uidStr = session.Uid > 0 ? session.Uid.ToString() : "1000";
                string dbusBus = $"unix:path=/run/user/{uidStr}/bus";

                string[] keys = { "picture-uri-dark", "picture-uri" };
                foreach (var key in keys)
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "gsettings",
                        Arguments = $"get org.gnome.desktop.background {key}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    psi.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = dbusBus;

                    using var p = Process.Start(psi);
                    if (p != null)
                    {
                        string outStr = p.StandardOutput.ReadToEnd().Trim();
                        p.WaitForExit(1000);
                        outStr = outStr.Trim('\'', '\"');
                        if (outStr.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                        {
                            outStr = Uri.UnescapeDataString(outStr.Substring(7));
                        }
                        if (File.Exists(outStr))
                        {
                            return outStr;
                        }
                    }
                }
            }
            catch { }
        }

        // 2. Try KDE Plasma config
        try
        {
            string plasmaConfig = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".config/plasma-org.kde.plasma.desktop-appletsrc");
            if (File.Exists(plasmaConfig))
            {
                foreach (var line in File.ReadLines(plasmaConfig))
                {
                    if (line.TrimStart().StartsWith("Image=", StringComparison.OrdinalIgnoreCase))
                    {
                        string path = line.Substring(line.IndexOf('=') + 1).Trim();
                        if (path.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                        {
                            path = Uri.UnescapeDataString(path.Substring(7));
                        }
                        if (File.Exists(path))
                        {
                            return path;
                        }
                    }
                }
            }
        }
        catch { }

        // 3. Try standard Fedora / Linux background directories
        string[] searchDirs = { "/usr/share/backgrounds/gnome", "/usr/share/backgrounds", "/usr/share/wallpapers" };
        foreach (var sDir in searchDirs)
        {
            if (Directory.Exists(sDir))
            {
                var files = Directory.GetFiles(sDir);
                var validFile = files.FirstOrDefault(f => f.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
                                                          f.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
                                                          f.EndsWith(".jxl", StringComparison.OrdinalIgnoreCase) ||
                                                          f.EndsWith(".webp", StringComparison.OrdinalIgnoreCase));
                if (validFile != null) return validFile;
            }
        }

        return null;
    }

    public static (string? b64, string? hash) GetWallpaperThumbnail(ITetherLogger? logger = null)
    {
        lock (_wallpaperLock)
        {
            try
            {
                string? wallpaperPath = DetectWallpaperPath(logger);
                if (string.IsNullOrEmpty(wallpaperPath) || !File.Exists(wallpaperPath))
                {
                    return (_cachedWallpaperB64, _cachedWallpaperHash);
                }

                var fileInfo = new FileInfo(wallpaperPath);
                if (_cachedWallpaperPath == wallpaperPath &&
                    _cachedWallpaperMtime == fileInfo.LastWriteTimeUtc &&
                    !string.IsNullOrEmpty(_cachedWallpaperB64))
                {
                    return (_cachedWallpaperB64, _cachedWallpaperHash);
                }

                // If it's already a small jpg/png, read directly; otherwise use magick / convert / ffmpeg
                byte[]? thumbBytes = null;
                string tempOut = Path.Combine(Path.GetTempPath(), $"tether_wp_{Guid.NewGuid():N}.jpg");

                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "magick",
                        Arguments = $"\"{wallpaperPath}\" -resize 640x400> \"{tempOut}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using (var p = Process.Start(psi))
                    {
                        p?.WaitForExit(2000);
                    }

                    if (!File.Exists(tempOut) || new FileInfo(tempOut).Length == 0)
                    {
                        // Fallback to ffmpeg
                        var psiFfmpeg = new ProcessStartInfo
                        {
                            FileName = "ffmpeg",
                            Arguments = $"-y -i \"{wallpaperPath}\" -vf \"scale=640:-1\" -vframes 1 \"{tempOut}\"",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        using var pFf = Process.Start(psiFfmpeg);
                        pFf?.WaitForExit(2000);
                    }

                    if (File.Exists(tempOut) && new FileInfo(tempOut).Length > 0)
                    {
                        thumbBytes = File.ReadAllBytes(tempOut);
                    }
                }
                finally
                {
                    try { if (File.Exists(tempOut)) File.Delete(tempOut); } catch { }
                }

                if (thumbBytes == null || thumbBytes.Length == 0)
                {
                    // If resize tool failed, and original file is <= 800KB, read directly
                    if (fileInfo.Length <= 800_000)
                    {
                        thumbBytes = File.ReadAllBytes(wallpaperPath);
                    }
                }

                if (thumbBytes != null && thumbBytes.Length > 0)
                {
                    string b64 = Convert.ToBase64String(thumbBytes);
                    byte[] hashBytes = SHA256.HashData(thumbBytes);
                    string hash = Convert.ToHexString(hashBytes);

                    _cachedWallpaperPath = wallpaperPath;
                    _cachedWallpaperMtime = fileInfo.LastWriteTimeUtc;
                    _cachedWallpaperB64 = b64;
                    _cachedWallpaperHash = hash;

                    return (b64, hash);
                }
            }
            catch (Exception ex)
            {
                logger?.Debug($"LinuxLaptopStateCollector: Wallpaper extraction failed: {ex.Message}");
            }

            return (null, null);
        }
    }

    public static LaptopStateFrame GetLaptopState(ITetherLogger logger)
    {
        var (bat, charging) = GetBatteryInfo(logger);
        string lockState = GetLockState(logger);
        var (wpB64, wpHash) = GetWallpaperThumbnail(logger);
        int vol = LinuxHardwareExecutor.GetSystemVolumeLevel(logger);
        bool isMuted = LinuxHardwareExecutor.GetSystemMute(logger);
        int bri = LinuxHardwareExecutor.GetBrightnessLevel(logger);

        return new LaptopStateFrame
        {
            Type = "LAPTOP_STATE",
            BatteryLevel = bat,
            BatteryPercent = bat,
            IsCharging = charging,
            LockState = lockState,
            WallpaperB64 = wpB64,
            WallpaperHash = wpHash,
            VolumeLevel = vol,
            IsMuted = isMuted,
            BrightnessLevel = bri,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
        };
    }
}
