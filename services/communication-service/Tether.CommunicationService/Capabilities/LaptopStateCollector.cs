using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using Tether.CommunicationService.Sessions;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Capabilities;

public sealed record LaptopSnapshot
{
    [JsonPropertyName("batteryLevel")] public int BatteryLevel { get; init; } = -1;
    [JsonPropertyName("isCharging")] public bool IsCharging { get; init; }
    [JsonPropertyName("lockState")] public string LockState { get; init; } = "UNKNOWN";
    [JsonPropertyName("wallpaperB64")] public string? WallpaperB64 { get; init; }
    [JsonPropertyName("wallpaperHash")] public string? WallpaperHash { get; init; }
}

public static class LaptopStateCollector
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS sps);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();

    private static readonly object _lock = new();
    private static SessionManager? _sessionManager;
    private static ITetherLogger? _logger;
    private static bool _eventsSubscribed = false;

    public static void Initialize(SessionManager sessionManager, ITetherLogger logger)
    {
        _sessionManager = sessionManager;
        _logger = logger;

        lock (_lock)
        {
            if (!_eventsSubscribed)
            {
                _eventsSubscribed = true;
                try
                {
                    SystemEvents.PowerModeChanged += OnPowerModeOrSessionChanged;
                    SystemEvents.SessionSwitch += OnPowerModeOrSessionChanged;
                }
                catch { }
            }
        }
    }

    private static void OnPowerModeOrSessionChanged(object? sender, EventArgs e)
    {
        if (_sessionManager != null && _logger != null)
        {
            try
            {
                var snap = GetLaptopSnapshot(_logger);
                _sessionManager.BroadcastLaptopState(snap);
            }
            catch { }
        }
    }

    private static string DetectLockStateDirect()
    {
        try
        {
            uint activeSession = WTSGetActiveConsoleSessionId();
            if (activeSession == 0xFFFFFFFF)
            {
                return "LOCKED";
            }

            var logonProcesses = Process.GetProcessesByName("LogonUI");
            if (logonProcesses.Length > 0)
            {
                foreach (var p in logonProcesses) { try { p.Dispose(); } catch { } }
                return "LOCKED";
            }

            return "UNLOCKED";
        }
        catch
        {
            return "UNLOCKED";
        }
    }

    private static (string? b64, string? hash) ReadWallpaperDirect(int maxW = 640, int maxH = 400)
    {
        try
        {
            string? wallpaperPath = null;

            // Search user profiles under C:\Users
            string usersDir = @"C:\Users";
            if (Directory.Exists(usersDir))
            {
                var userFolders = Directory.GetDirectories(usersDir);
                foreach (var userFolder in userFolders)
                {
                    string folderName = Path.GetFileName(userFolder);
                    if (folderName.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                        folderName.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                        folderName.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                        folderName.StartsWith("."))
                    {
                        continue;
                    }

                    // Check TranscodedWallpaper
                    string transcoded = Path.Combine(userFolder, @"AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper");
                    if (File.Exists(transcoded) && new FileInfo(transcoded).Length > 0)
                    {
                        wallpaperPath = transcoded;
                        break;
                    }

                    // Check CachedFiles
                    string cachedDir = Path.Combine(userFolder, @"AppData\Roaming\Microsoft\Windows\Themes\CachedFiles");
                    if (Directory.Exists(cachedDir))
                    {
                        var files = Directory.GetFiles(cachedDir);
                        if (files.Length > 0 && File.Exists(files[0]))
                        {
                            wallpaperPath = files[0];
                            break;
                        }
                    }
                }
            }

            // Fallback to system default wallpaper if no user wallpaper found
            if (string.IsNullOrEmpty(wallpaperPath))
            {
                string sysDefault = @"C:\Windows\Web\Wallpaper\Windows\img0.jpg";
                if (File.Exists(sysDefault))
                {
                    wallpaperPath = sysDefault;
                }
            }

            if (string.IsNullOrEmpty(wallpaperPath) || !File.Exists(wallpaperPath))
            {
                return (null, null);
            }

            byte[] fileBytes = File.ReadAllBytes(wallpaperPath);
            if (fileBytes.Length == 0) return (null, null);

            using var msOutput = new MemoryStream();

            try
            {
                using var srcMs = new MemoryStream(fileBytes);
                using var src = Image.FromStream(srcMs);
                int origW = src.Width;
                int origH = src.Height;

                double ratioX = (double)maxW / origW;
                double ratioY = (double)maxH / origH;
                double ratio = Math.Min(ratioX, ratioY);

                int newW = Math.Max(1, (int)(origW * ratio));
                int newH = Math.Max(1, (int)(origH * ratio));

                using var destImage = new Bitmap(newW, newH);
                using (var graphics = Graphics.FromImage(destImage))
                {
                    graphics.CompositingMode = CompositingMode.SourceCopy;
                    graphics.CompositingQuality = CompositingQuality.HighSpeed;
                    graphics.InterpolationMode = InterpolationMode.Bilinear;
                    graphics.SmoothingMode = SmoothingMode.HighSpeed;
                    graphics.PixelOffsetMode = PixelOffsetMode.HighSpeed;

                    using var wrapMode = new ImageAttributes();
                    wrapMode.SetWrapMode(WrapMode.TileFlipXY);
                    graphics.DrawImage(src, new Rectangle(0, 0, newW, newH), 0, 0, origW, origH, GraphicsUnit.Pixel, wrapMode);
                }

                destImage.Save(msOutput, ImageFormat.Jpeg);
            }
            catch
            {
                // Fallback: If image downscale fails, write raw bytes if small enough
                if (fileBytes.Length <= 800_000)
                {
                    msOutput.Write(fileBytes, 0, fileBytes.Length);
                }
            }

            byte[] finalBytes = msOutput.ToArray();
            if (finalBytes.Length == 0) return (null, null);

            string b64 = Convert.ToBase64String(finalBytes);
            using var sha256 = SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(finalBytes);
            string hash = Convert.ToHexString(hashBytes);

            return (b64, hash);
        }
        catch
        {
            return (null, null);
        }
    }

    public static LaptopSnapshot GetLaptopSnapshot(ITetherLogger logger)
    {
        int batteryLevel = -1;
        bool isCharging = false;

        if (GetSystemPowerStatus(out SYSTEM_POWER_STATUS sps))
        {
            if (sps.BatteryLifePercent != 255)
            {
                batteryLevel = sps.BatteryLifePercent;
            }
            isCharging = (sps.ACLineStatus == 1);
        }

        string lockState = DetectLockStateDirect();
        string? wallpaperB64 = null;
        string? wallpaperHash = null;

        // Try reading wallpaper directly from active user profile on disk
        var (dirB64, dirHash) = ReadWallpaperDirect();
        if (!string.IsNullOrEmpty(dirB64))
        {
            wallpaperB64 = dirB64;
            wallpaperHash = dirHash;
        }
        else
        {
            // Helper fallback
            string programDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether");
            try { Directory.CreateDirectory(programDataDir); } catch { }
            string stateFile = Path.Combine(programDataDir, "laptop_state.json");

            bool helperOk = HardwareExecutor.RunHelperAsUser(new[] { "dump-laptop-state", stateFile }, logger, out _);
            if (helperOk && File.Exists(stateFile))
            {
                try
                {
                    string jsonStr = File.ReadAllText(stateFile);
                    using var doc = JsonDocument.Parse(jsonStr);
                    if (doc.RootElement.TryGetProperty("lockState", out var lockProp) && lockState == "UNKNOWN")
                    {
                        lockState = lockProp.GetString() ?? "UNKNOWN";
                    }
                    if (doc.RootElement.TryGetProperty("wallpaperB64", out var wpB64Prop))
                    {
                        wallpaperB64 = wpB64Prop.GetString();
                    }
                    if (doc.RootElement.TryGetProperty("wallpaperHash", out var wpHashProp))
                    {
                        wallpaperHash = wpHashProp.GetString();
                    }
                }
                catch { }
            }
        }

        return new LaptopSnapshot
        {
            BatteryLevel = batteryLevel,
            IsCharging = isCharging,
            LockState = lockState,
            WallpaperB64 = wallpaperB64,
            WallpaperHash = wallpaperHash
        };
    }
}
