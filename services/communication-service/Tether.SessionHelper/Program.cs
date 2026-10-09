using System;
using System.IO;
using System.Text.Json;

namespace Tether.SessionHelper;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: Tether.SessionHelper <get-volume|set-volume|adjust-volume|toggle-mute|get-lock-state|dump-laptop-state> [value]");
            return 64;
        }

        try
        {
            switch (args[0].ToLowerInvariant())
            {
                case "get-volume":
                case "volume_get":
                    int cur = AudioController.GetMasterVolume();
                    Console.WriteLine($"OK {cur}");
                    return cur; // 0..100 == volume level

                case "set-volume":
                case "volume_set":
                    if (args.Length < 2 || !int.TryParse(args[1], out int target))
                    {
                        Console.Error.WriteLine("set-volume requires integer argument");
                        return 65;
                    }
                    AudioController.SetMasterVolume(Math.Clamp(target, 0, 100));
                    Console.WriteLine($"OK {target}");
                    return 0;

                case "adjust-volume":
                case "volume_adjust":
                    if (args.Length < 2 || !int.TryParse(args[1], out int delta))
                    {
                        Console.Error.WriteLine("adjust-volume requires integer argument");
                        return 65;
                    }
                    int nv = AudioController.AdjustMasterVolume(delta);
                    Console.WriteLine($"OK {nv}");
                    return 0;

                case "toggle-mute":
                case "volume_mute":
                    bool muted = AudioController.ToggleMute();
                    Console.WriteLine($"OK {muted}");
                    return 0;

                case "get-lock-state":
                case "lock_state_get":
                    bool isLocked = LockStateDetector.IsLocked();
                    string lockStr = isLocked ? "LOCKED" : "UNLOCKED";
                    Console.WriteLine($"OK {lockStr}");
                    return isLocked ? 0 : 1;

                case "dump-laptop-state":
                case "laptop_state_dump":
                    string outputPath = args.Length > 1 ? args[1] : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether", "laptop_state.json");
                    string lockState = LockStateDetector.GetLockStateString();
                    string? wallpaperPath = WallpaperReader.GetCurrentWallpaperPath();
                    var (wallpaperB64, wallpaperHash) = WallpaperReader.GetDownscaledWallpaperBase64AndHash();

                    var stateBlob = new
                    {
                        lockState = lockState,
                        wallpaperPath = wallpaperPath,
                        wallpaperB64 = wallpaperB64,
                        wallpaperHash = wallpaperHash
                    };

                    string dir = Path.GetDirectoryName(outputPath) ?? "";
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    File.WriteAllText(outputPath, JsonSerializer.Serialize(stateBlob));
                    Console.WriteLine("OK DUMPED");
                    return 0;

                default:
                    Console.Error.WriteLine($"unknown command: {args[0]}");
                    return 64;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ERROR {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }
}
