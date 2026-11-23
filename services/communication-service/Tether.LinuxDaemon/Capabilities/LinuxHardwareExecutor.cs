using System;
using System.Collections.Generic;
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
            if (cmdLower == "panic" || cmdLower == "panic_lock")
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

    public static List<LinuxAudioDeviceInfo> GetAudioDevices(ITetherLogger logger)
    {
        var list = new List<LinuxAudioDeviceInfo>();

        // 1. Try wpctl status
        string wpOut = RunProcessWithTimeout("wpctl", "status", 1000);
        if (!string.IsNullOrWhiteSpace(wpOut))
        {
            bool inSinks = false;
            bool inSources = false;
            using var reader = new StringReader(wpOut);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                string trimmed = line.Trim();
                if (trimmed.Contains("Sinks:"))
                {
                    inSinks = true;
                    inSources = false;
                    continue;
                }
                if (trimmed.Contains("Sources:"))
                {
                    inSinks = false;
                    inSources = true;
                    continue;
                }
                if (trimmed.Contains("Filters:") || trimmed.Contains("Streams:") || trimmed.Contains("Video:") || trimmed.Contains("Settings:"))
                {
                    inSinks = false;
                    inSources = false;
                    continue;
                }

                if (inSinks || inSources)
                {
                    var match = Regex.Match(line, @"(\*?)\s*(\d+)\.\s+([^\[\n\r]+?)(?:\s+\[.*\])?$");
                    if (match.Success)
                    {
                        bool isDef = match.Groups[1].Value.Contains('*');
                        string id = match.Groups[2].Value.Trim();
                        string name = match.Groups[3].Value.Trim();
                        if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(name))
                        {
                            list.Add(new LinuxAudioDeviceInfo
                            {
                                Id = id,
                                Name = name,
                                IsDefault = isDef,
                                IsInput = inSources
                            });
                        }
                    }
                }
            }
        }

        if (list.Count > 0) return list;

        // 2. Fallback to pactl
        try
        {
            string defaultSink = RunProcessWithTimeout("pactl", "get-default-sink", 500).Trim();
            string sinksOut = RunProcessWithTimeout("pactl", "list short sinks", 500);
            if (!string.IsNullOrWhiteSpace(sinksOut))
            {
                foreach (var line in sinksOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('\t');
                    if (parts.Length >= 2)
                    {
                        string id = parts[0].Trim();
                        string name = parts[1].Trim();
                        list.Add(new LinuxAudioDeviceInfo
                        {
                            Id = id,
                            Name = name,
                            IsDefault = !string.IsNullOrEmpty(defaultSink) && (name == defaultSink || id == defaultSink),
                            IsInput = false
                        });
                    }
                }
            }

            string defaultSource = RunProcessWithTimeout("pactl", "get-default-source", 500).Trim();
            string sourcesOut = RunProcessWithTimeout("pactl", "list short sources", 500);
            if (!string.IsNullOrWhiteSpace(sourcesOut))
            {
                foreach (var line in sourcesOut.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('\t');
                    if (parts.Length >= 2)
                    {
                        string id = parts[0].Trim();
                        string name = parts[1].Trim();
                        if (name.EndsWith(".monitor", StringComparison.OrdinalIgnoreCase)) continue;

                        list.Add(new LinuxAudioDeviceInfo
                        {
                            Id = id,
                            Name = name,
                            IsDefault = !string.IsNullOrEmpty(defaultSource) && (name == defaultSource || id == defaultSource),
                            IsInput = true
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            logger.Warning($"LinuxHardwareExecutor: Failed enumerating audio devices via pactl fallback: {ex.Message}");
        }

        return list;
    }

    public static bool SetDefaultAudioDevice(string deviceId, bool isInput, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;

        // 1. Try wpctl set-default <id>
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wpctl",
                Arguments = $"set-default {deviceId}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
            if (p != null && p.ExitCode == 0) return true;
        }
        catch { }

        // 2. pactl fallback
        try
        {
            string subCmd = isInput ? "set-default-source" : "set-default-sink";
            var psi = new ProcessStartInfo
            {
                FileName = "pactl",
                Arguments = $"{subCmd} {deviceId}",
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

    public static (int gain, bool isMuted) GetMicrophoneState(ITetherLogger logger)
    {
        // 1. Try wpctl get-volume @DEFAULT_AUDIO_SOURCE@
        string wpOut = RunProcessWithTimeout("wpctl", "get-volume @DEFAULT_AUDIO_SOURCE@", 300);
        if (!string.IsNullOrEmpty(wpOut))
        {
            bool isMuted = wpOut.Contains("[MUTED]", StringComparison.OrdinalIgnoreCase);
            var match = Regex.Match(wpOut, @"Volume:\s*([0-9\.]+)");
            if (match.Success && double.TryParse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture, out double vol))
            {
                return ((int)Math.Round(vol * 100), isMuted);
            }
            return (100, isMuted);
        }

        // 2. Try amixer get Capture
        string amOut = RunProcessWithTimeout("amixer", "get Capture", 300);
        if (!string.IsNullOrEmpty(amOut))
        {
            bool isMuted = amOut.Contains("[off]", StringComparison.OrdinalIgnoreCase);
            var match = Regex.Match(amOut, @"\[(\d+)%\]");
            if (match.Success && int.TryParse(match.Groups[1].Value, out int pct))
            {
                return (pct, isMuted);
            }
        }

        return (50, false);
    }

    public static bool SetMicrophoneState(int gain, bool? mute, ITetherLogger logger)
    {
        bool success = true;

        if (mute.HasValue)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "wpctl",
                    Arguments = $"set-mute @DEFAULT_AUDIO_SOURCE@ {(mute.Value ? 1 : 0)}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(1000);
                if (p == null || p.ExitCode != 0) success = false;
            }
            catch
            {
                success = false;
            }
        }

        if (gain >= 0)
        {
            int clamped = Math.Clamp(gain, 0, 100);
            double frac = clamped / 100.0;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "wpctl",
                    Arguments = $"set-volume @DEFAULT_AUDIO_SOURCE@ {frac.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(1000);
                if (p == null || p.ExitCode != 0) success = false;
            }
            catch
            {
                success = false;
            }
        }

        return success;
    }

    public static List<LinuxAppAudioSession> GetAppAudioSessions(ITetherLogger logger)
    {
        var sessions = new List<LinuxAppAudioSession>();
        string pactlOut = RunProcessWithTimeout("pactl", "list sink-inputs", 1000);
        if (string.IsNullOrWhiteSpace(pactlOut)) return sessions;

        var blocks = pactlOut.Split("Sink Input #", StringSplitOptions.RemoveEmptyEntries);
        foreach (var block in blocks)
        {
            var lines = block.Split('\n');
            if (lines.Length == 0) continue;
            string id = lines[0].Trim();
            if (string.IsNullOrEmpty(id) || !char.IsDigit(id[0])) continue;

            int pid = 0;
            string appName = "Application";
            int vol = 100;
            bool isMuted = false;

            foreach (var rawLine in lines)
            {
                string line = rawLine.Trim();
                if (line.StartsWith("Mute:", StringComparison.OrdinalIgnoreCase))
                {
                    isMuted = line.Contains("yes", StringComparison.OrdinalIgnoreCase);
                }
                else if (line.StartsWith("Volume:", StringComparison.OrdinalIgnoreCase))
                {
                    var vMatch = Regex.Match(line, @"(\d+)%");
                    if (vMatch.Success && int.TryParse(vMatch.Groups[1].Value, out int pv))
                    {
                        vol = pv;
                    }
                }
                else if (line.Contains("application.name =", StringComparison.OrdinalIgnoreCase))
                {
                    var nMatch = Regex.Match(line, @"=\s*""([^""]+)""");
                    if (nMatch.Success) appName = nMatch.Groups[1].Value;
                }
                else if (line.Contains("application.process.id =", StringComparison.OrdinalIgnoreCase))
                {
                    var pMatch = Regex.Match(line, @"=\s*""?(\d+)""?");
                    if (pMatch.Success && int.TryParse(pMatch.Groups[1].Value, out int parsedPid))
                    {
                        pid = parsedPid;
                    }
                }
            }

            sessions.Add(new LinuxAppAudioSession
            {
                Id = id,
                Pid = pid,
                ProcessName = appName,
                VolumePercent = vol,
                IsMuted = isMuted
            });
        }

        return sessions;
    }

    public static bool SetAppVolume(string id, int volumePercent, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(id)) return false;
        int vol = Math.Clamp(volumePercent, 0, 150);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "pactl",
                Arguments = $"set-sink-input-volume {id} {vol}%",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
            return p != null && p.ExitCode == 0;
        }
        catch (Exception ex)
        {
            logger.Error($"SetAppVolume failed: {ex.Message}");
            return false;
        }
    }

    public static bool SetAppMute(string id, bool mute, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(id)) return false;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "pactl",
                Arguments = $"set-sink-input-mute {id} {(mute ? "1" : "0")}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1000);
            return p != null && p.ExitCode == 0;
        }
        catch (Exception ex)
        {
            logger.Error($"SetAppMute failed: {ex.Message}");
            return false;
        }
    }
}

public sealed class LinuxAudioDeviceInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public bool IsDefault { get; set; }
    public bool IsInput { get; set; }
}

public sealed class LinuxAppAudioSession
{
    public string Id { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int VolumePercent { get; set; } = 100;
    public bool IsMuted { get; set; }
}
