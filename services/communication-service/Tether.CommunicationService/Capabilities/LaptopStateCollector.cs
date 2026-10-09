using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
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

    private static readonly object _lock = new();
    private static string? _cachedWallpaperHash;

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

        string lockState = "UNKNOWN";
        string? wallpaperB64 = null;
        string? wallpaperHash = null;

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
                if (doc.RootElement.TryGetProperty("lockState", out var lockProp))
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
            catch (Exception ex)
            {
                logger.Warning($"LaptopStateCollector: Failed reading state json: {ex.Message}");
            }
        }
        else
        {
            // Fallback lock state check via direct helper call if dump failed
            bool lockOk = HardwareExecutor.RunHelperAsUser(new[] { "get-lock-state" }, logger, out int exitCode);
            if (lockOk)
            {
                lockState = (exitCode == 0) ? "LOCKED" : "UNLOCKED";
            }
        }

        // Caching optimization: only include wallpaperB64 if it has changed since last emission
        lock (_lock)
        {
            if (!string.IsNullOrEmpty(wallpaperHash) && string.Equals(wallpaperHash, _cachedWallpaperHash, StringComparison.Ordinal))
            {
                wallpaperB64 = null;
            }
            else if (!string.IsNullOrEmpty(wallpaperHash) && !string.IsNullOrEmpty(wallpaperB64))
            {
                _cachedWallpaperHash = wallpaperHash;
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
