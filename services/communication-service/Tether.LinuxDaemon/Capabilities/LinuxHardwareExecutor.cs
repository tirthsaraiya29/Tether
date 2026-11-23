using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Security;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Capabilities;

public static class LinuxHardwareExecutor
{
    public static bool ExecuteCommand(string command, ITetherLogger logger, LinuxPamAuthServer pamServer, out int currentVol)
    {
        currentVol = -1;
        if (string.IsNullOrWhiteSpace(command)) return false;

        string cmdLower = command.Trim().ToLowerInvariant();
        logger.Info($"LinuxHardwareExecutor: Executing command '{command}'.");

        try
        {
            if (cmdLower == "lock" || cmdLower == "lock_workstation" || cmdLower == "lock_now")
            {
                return LockSession(logger);
            }

            if (cmdLower == "unlock")
            {
                var session = PlatformDetection.GetActiveSessionInfo();
                pamServer.ArmUnlockGrant(session.UserName, "phone-authorized-unlock", validitySeconds: 20);
                logger.Info($"LinuxHardwareExecutor: Workstation unlock grant armed for user '{session.UserName}'.");
                return true;
            }

            if (cmdLower == "sleep" || cmdLower == "suspend")
            {
                return RunSystemctl("suspend", logger);
            }

            if (cmdLower == "hibernate")
            {
                return RunSystemctl("hibernate", logger);
            }

            if (cmdLower == "reboot" || cmdLower == "restart")
            {
                return RunSystemctl("reboot", logger);
            }

            if (cmdLower == "shutdown" || cmdLower == "poweroff" || cmdLower == "halt")
            {
                return RunSystemctl("poweroff", logger);
            }

            // State and telemetry queries
            if (cmdLower is "volume_get" or "get_volume")
            {
                currentVol = GetSystemVolumeLevel(logger);
                return true;
            }

            if (cmdLower is "brightness_get" or "get_brightness")
            {
                return true;
            }

            if (cmdLower is "laptop_state_get" or "get_laptop_state")
            {
                return true;
            }

            // Volume controls
            if (cmdLower == "volume_mute" || cmdLower == "vol_mute" || cmdLower == "mute")
            {
                return SetVolumeMuteToggle(logger, out currentVol);
            }

            if (cmdLower == "volume_up" || cmdLower == "vol_up")
            {
                return AdjustVolume(logger, +5, out currentVol);
            }

            if (cmdLower == "volume_down" || cmdLower == "vol_down")
            {
                return AdjustVolume(logger, -5, out currentVol);
            }

            if (cmdLower.StartsWith("set_volume:") || cmdLower.StartsWith("volume_set:") || cmdLower.StartsWith("vol_set:"))
            {
                string valStr = command.Substring(command.IndexOf(':') + 1).Trim();
                if (int.TryParse(valStr, out int targetVol))
                {
                    return SetAbsoluteVolume(logger, targetVol, out currentVol);
                }
            }

            // Brightness controls
            if (cmdLower == "brightness_up" || cmdLower == "bright_up")
            {
                return AdjustBrightness(logger, +10);
            }

            if (cmdLower == "brightness_down" || cmdLower == "bright_down")
            {
                return AdjustBrightness(logger, -10);
            }

            if (cmdLower.StartsWith("set_brightness:") || cmdLower.StartsWith("brightness_set:") || cmdLower.StartsWith("bright_set:"))
            {
                string valStr = command.Substring(command.IndexOf(':') + 1).Trim();
                if (int.TryParse(valStr, out int targetBri))
                {
                    return SetAbsoluteBrightness(logger, targetBri);
                }
            }

            // Panic emergency lock
            if (cmdLower == "panic")
            {
                logger.Warning("LinuxHardwareExecutor: Panic lock triggered! Muting audio and locking session.");
                SetVolumeMute(logger, true, out _);
                return LockSession(logger);
            }

            logger.Warning($"LinuxHardwareExecutor: Unrecognized hardware command '{command}'.");
            return false;
        }
        catch (Exception ex)
        {
            logger.Error($"LinuxHardwareExecutor: Command '{command}' threw exception: {ex.Message}");
            return false;
        }
    }

    public static bool LockSession(ITetherLogger logger)
    {
        var session = PlatformDetection.GetActiveSessionInfo();

        // 1. Try loginctl lock-session
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "loginctl",
                Arguments = $"lock-session {session.SessionId}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(2000);
            if (p != null && p.ExitCode == 0)
            {
                logger.Info($"Locked session {session.SessionId} via loginctl.");
                return true;
            }
        }
        catch { }

        // 2. Try lock-sessions global
        try
        {
            var psiAll = new ProcessStartInfo
            {
                FileName = "loginctl",
                Arguments = "lock-sessions",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psiAll);
            p?.WaitForExit(2000);
            if (p != null && p.ExitCode == 0)
            {
                logger.Info("Locked sessions via loginctl lock-sessions.");
                return true;
            }
        }
        catch { }

        return false;
    }

    private static string RunProcessWithTimeout(string fileName, string arguments, int timeoutMs = 300)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return string.Empty;

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                return string.Empty;
            }

            return p.StandardOutput.ReadToEnd();
        }
        catch
        {
            return string.Empty;
        }
    }

    public static int GetSystemVolumeLevel(ITetherLogger logger)
    {
        // 1. Try wpctl
        string wpOut = RunProcessWithTimeout("wpctl", "get-volume @DEFAULT_AUDIO_SINK@", 300).Trim();
        if (!string.IsNullOrEmpty(wpOut))
        {
            var match = Regex.Match(wpOut, @"Volume:\s*([0-9\.]+)");
            if (match.Success && double.TryParse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture, out double vol))
            {
                return (int)Math.Round(vol * 100);
            }
        }

        // 2. Try amixer with strict timeout
        string amOut = RunProcessWithTimeout("amixer", "get Master", 300);
        if (!string.IsNullOrEmpty(amOut))
        {
            var match = Regex.Match(amOut, @"\[(\d+)%\]");
            if (match.Success && int.TryParse(match.Groups[1].Value, out int pct))
            {
                return pct;
            }
        }

        return 50;
    }

    public static bool GetSystemMute(ITetherLogger logger)
    {
        string wpOut = RunProcessWithTimeout("wpctl", "get-volume @DEFAULT_AUDIO_SINK@", 300);
        if (!string.IsNullOrEmpty(wpOut))
        {
            return wpOut.Contains("[MUTED]", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    public static bool SetVolumeMuteToggle(ITetherLogger logger, out int currentVol)
    {
        currentVol = GetSystemVolumeLevel(logger);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wpctl",
                Arguments = "set-mute @DEFAULT_AUDIO_SINK@ toggle",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
            return p != null && p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool SetVolumeMute(ITetherLogger logger, bool mute, out int currentVol)
    {
        currentVol = GetSystemVolumeLevel(logger);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wpctl",
                Arguments = $"set-mute @DEFAULT_AUDIO_SINK@ {(mute ? 1 : 0)}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
            return p != null && p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static bool AdjustVolume(ITetherLogger logger, int delta, out int currentVol)
    {
        int cur = GetSystemVolumeLevel(logger);
        int target = Math.Clamp(cur + delta, 0, 100);
        return SetAbsoluteVolume(logger, target, out currentVol);
    }

    public static bool SetAbsoluteVolume(ITetherLogger logger, int targetVol, out int currentVol)
    {
        targetVol = Math.Clamp(targetVol, 0, 100);
        currentVol = targetVol;
        double wpctlVol = targetVol / 100.0;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wpctl",
                Arguments = $"set-volume @DEFAULT_AUDIO_SINK@ {wpctlVol.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
            return p != null && p.ExitCode == 0;
        }
        catch (Exception ex)
        {
            logger.Warning($"wpctl set-volume failed: {ex.Message}");
            return false;
        }
    }

    public static int GetBrightnessLevel(ITetherLogger logger)
    {
        try
        {
            if (Directory.Exists("/sys/class/backlight"))
            {
                var dir = Directory.GetDirectories("/sys/class/backlight").FirstOrDefault();
                if (dir != null)
                {
                    string curFile = Path.Combine(dir, "brightness");
                    string maxFile = Path.Combine(dir, "max_brightness");
                    if (File.Exists(curFile) && File.Exists(maxFile))
                    {
                        if (double.TryParse(File.ReadAllText(curFile).Trim(), out double cur) &&
                            double.TryParse(File.ReadAllText(maxFile).Trim(), out double max) && max > 0)
                        {
                            return (int)Math.Round((cur / max) * 100);
                        }
                    }
                }
            }
        }
        catch { }

        return 100;
    }

    public static bool AdjustBrightness(ITetherLogger logger, int delta)
    {
        int cur = GetBrightnessLevel(logger);
        return SetAbsoluteBrightness(logger, Math.Clamp(cur + delta, 0, 100));
    }

    public static bool SetAbsoluteBrightness(ITetherLogger logger, int percent)
    {
        percent = Math.Clamp(percent, 1, 100);

        try
        {
            if (Directory.Exists("/sys/class/backlight"))
            {
                var dir = Directory.GetDirectories("/sys/class/backlight").FirstOrDefault();
                if (dir != null)
                {
                    string maxFile = Path.Combine(dir, "max_brightness");
                    string curFile = Path.Combine(dir, "brightness");
                    if (File.Exists(maxFile) && double.TryParse(File.ReadAllText(maxFile).Trim(), out double max) && max > 0)
                    {
                        long targetRaw = (long)Math.Round((percent / 100.0) * max);
                        File.WriteAllText(curFile, targetRaw.ToString());
                        return true;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"Direct backlight write error: {ex.Message}");
        }

        // Try brightnessctl if installed
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "brightnessctl",
                Arguments = $"set {percent}%",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
            return p != null && p.ExitCode == 0;
        }
        catch { }

        return false;
    }

    private static bool RunSystemctl(string action, ITetherLogger logger)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "systemctl",
                Arguments = action,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(3000);
            return p != null && p.ExitCode == 0;
        }
        catch (Exception ex)
        {
            logger.Error($"Failed running systemctl {action}: {ex.Message}");
            return false;
        }
    }
}
