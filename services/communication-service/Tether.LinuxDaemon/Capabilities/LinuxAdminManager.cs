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

public sealed record LinuxSystemTelemetry
{
    [JsonPropertyName("cpuUsage")] public int CpuUsage { get; init; }
    [JsonPropertyName("usedRamMb")] public ulong UsedRamMb { get; init; }
    [JsonPropertyName("totalRamMb")] public ulong TotalRamMb { get; init; }
    [JsonPropertyName("freeDiskGb")] public double FreeDiskGb { get; init; }
    [JsonPropertyName("totalDiskGb")] public double TotalDiskGb { get; init; }
    [JsonPropertyName("uptimeSeconds")] public long UptimeSeconds { get; init; }
    [JsonPropertyName("networkSentKbps")] public double NetworkSentKbps { get; init; }
    [JsonPropertyName("networkReceivedKbps")] public double NetworkReceivedKbps { get; init; }
}

public sealed record LinuxHardwareSpecs
{
    [JsonPropertyName("cpuName")] public string CpuName { get; init; } = "";
    [JsonPropertyName("cpuCores")] public int CpuCores { get; init; }
    [JsonPropertyName("cpuLogicalProcessors")] public int CpuLogicalProcessors { get; init; }
    [JsonPropertyName("totalRamMb")] public ulong TotalRamMb { get; init; }
    [JsonPropertyName("osVersion")] public string OsVersion { get; init; } = "";
    [JsonPropertyName("gpuName")] public string GpuName { get; init; } = "";
    [JsonPropertyName("gpuMemoryMb")] public ulong GpuMemoryMb { get; init; }
}

public sealed record LinuxBatteryHealthState
{
    [JsonPropertyName("designedCapacityMwh")] public double DesignedCapacityMwh { get; init; }
    [JsonPropertyName("designCapacityMwh")] public double DesignCapacityMwh => DesignedCapacityMwh;
    [JsonPropertyName("fullChargeCapacityMwh")] public double FullChargeCapacityMwh { get; init; }
    [JsonPropertyName("wearLevelPercent")] public int WearLevelPercent { get; init; }
    [JsonPropertyName("wearLevelPct")] public int WearLevelPct => WearLevelPercent;
    [JsonPropertyName("cycleCount")] public int CycleCount { get; init; }
}

public sealed record LinuxPowerPlanInfo
{
    [JsonPropertyName("guid")] public string Guid { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("isActive")] public bool IsActive { get; init; }
}

public sealed record LinuxUsbDeviceInfo
{
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "OK";
}

public sealed record LinuxServiceDetails
{
    [JsonPropertyName("serviceName")] public string ServiceName { get; init; } = "";
    [JsonPropertyName("name")] public string Name => ServiceName;
    [JsonPropertyName("displayName")] public string DisplayName { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "";
    [JsonPropertyName("canStop")] public bool CanStop { get; init; } = true;
    [JsonPropertyName("canPauseAndContinue")] public bool CanPauseAndContinue { get; init; } = false;
}

public sealed record LinuxUpdateInfo
{
    [JsonPropertyName("pendingUpdatesCount")] public int PendingUpdatesCount { get; init; }
    [JsonPropertyName("pendingCount")] public int PendingCount => PendingUpdatesCount;
    [JsonPropertyName("isUpdateAvailable")] public bool IsUpdateAvailable { get; init; }
    [JsonPropertyName("isAvailable")] public bool IsAvailable => IsUpdateAvailable;
    [JsonPropertyName("titles")] public List<string> Titles { get; init; } = new();
    [JsonPropertyName("statusMessage")] public string StatusMessage { get; init; } = "OK";
}

public sealed class LinuxAdminManager
{
    private readonly ITetherLogger _logger;

    private static ulong _lastTotalJiffies;
    private static ulong _lastIdleJiffies;
    private static DateTime _lastCpuCheck = DateTime.MinValue;
    private static int _cachedCpuUsage = 0;

    private static ulong _lastNetRxBytes;
    private static ulong _lastNetTxBytes;
    private static DateTime _lastNetCheck = DateTime.MinValue;
    private static double _cachedNetRxKbps = 0;
    private static double _cachedNetTxKbps = 0;

    private static LinuxUpdateInfo? _cachedUpdateInfo;
    private static DateTime _lastUpdateCheck = DateTime.MinValue;
    private static readonly object _updateLock = new();

    public LinuxAdminManager(ITetherLogger logger)
    {
        _logger = logger;
        InitCpuJiffies();
        InitNetBytes();
    }

    private void InitCpuJiffies()
    {
        try
        {
            if (File.Exists("/proc/stat"))
            {
                string firstLine = File.ReadLines("/proc/stat").FirstOrDefault() ?? "";
                if (firstLine.StartsWith("cpu "))
                {
                    var tokens = firstLine.Substring(4).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    ulong idle = 0;
                    ulong total = 0;
                    for (int i = 0; i < tokens.Length; i++)
                    {
                        if (ulong.TryParse(tokens[i], out ulong v))
                        {
                            total += v;
                            if (i == 3 || i == 4) idle += v; // idle + iowait
                        }
                    }
                    _lastTotalJiffies = total;
                    _lastIdleJiffies = idle;
                    _lastCpuCheck = DateTime.UtcNow;
                }
            }
        }
        catch { }
    }

    private void InitNetBytes()
    {
        try
        {
            var (rx, tx) = ReadTotalNetBytes();
            _lastNetRxBytes = rx;
            _lastNetTxBytes = tx;
            _lastNetCheck = DateTime.UtcNow;
        }
        catch { }
    }

    public LinuxSystemTelemetry GetSystemTelemetry()
    {
        int cpu = GetCpuUsage();
        var (usedRam, totalRam) = GetRamUsage();
        var (freeDisk, totalDisk) = GetDiskUsage();
        long uptime = GetUptimeSeconds();
        var (rxKbps, txKbps) = GetNetworkThroughput();

        return new LinuxSystemTelemetry
        {
            CpuUsage = cpu,
            UsedRamMb = usedRam,
            TotalRamMb = totalRam,
            FreeDiskGb = freeDisk,
            TotalDiskGb = totalDisk,
            UptimeSeconds = uptime,
            NetworkSentKbps = txKbps,
            NetworkReceivedKbps = rxKbps
        };
    }

    public int GetCpuUsage()
    {
        try
        {
            if (!File.Exists("/proc/stat")) return _cachedCpuUsage;

            var now = DateTime.UtcNow;
            if ((now - _lastCpuCheck).TotalMilliseconds < 500)
            {
                return _cachedCpuUsage;
            }

            string firstLine = File.ReadLines("/proc/stat").FirstOrDefault() ?? "";
            if (firstLine.StartsWith("cpu "))
            {
                var tokens = firstLine.Substring(4).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                ulong idle = 0;
                ulong total = 0;
                for (int i = 0; i < tokens.Length; i++)
                {
                    if (ulong.TryParse(tokens[i], out ulong v))
                    {
                        total += v;
                        if (i == 3 || i == 4) idle += v;
                    }
                }

                ulong totalDiff = total - _lastTotalJiffies;
                ulong idleDiff = idle - _lastIdleJiffies;

                if (totalDiff > 0)
                {
                    ulong nonIdleDiff = totalDiff > idleDiff ? totalDiff - idleDiff : 0;
                    _cachedCpuUsage = Math.Clamp((int)Math.Round((nonIdleDiff * 100.0) / totalDiff), 0, 100);
                }

                _lastTotalJiffies = total;
                _lastIdleJiffies = idle;
                _lastCpuCheck = now;
            }
        }
        catch { }

        return _cachedCpuUsage;
    }

    public static (ulong usedRamMb, ulong totalRamMb) GetRamUsage()
    {
        ulong totalKb = 0;
        ulong availKb = 0;

        try
        {
            if (File.Exists("/proc/meminfo"))
            {
                foreach (var line in File.ReadLines("/proc/meminfo"))
                {
                    if (line.StartsWith("MemTotal:", StringComparison.OrdinalIgnoreCase))
                    {
                        totalKb = ParseMemKb(line);
                    }
                    else if (line.StartsWith("MemAvailable:", StringComparison.OrdinalIgnoreCase))
                    {
                        availKb = ParseMemKb(line);
                    }
                    if (totalKb > 0 && availKb > 0) break;
                }
            }
            else
            {
                // Fallback for non-Linux or systems where /proc/meminfo is inaccessible
                var memInfo = GC.GetGCMemoryInfo();
                if (memInfo.TotalAvailableMemoryBytes > 0)
                {
                    totalKb = (ulong)(memInfo.TotalAvailableMemoryBytes / 1024);
                    availKb = (ulong)((memInfo.TotalAvailableMemoryBytes - memInfo.MemoryLoadBytes) / 1024);
                }
                else
                {
                    totalKb = 8192 * 1024;
                    availKb = 4096 * 1024;
                }
            }
        }
        catch { }

        ulong usedKb = totalKb > availKb ? totalKb - availKb : 0;
        return (usedKb / 1024, totalKb / 1024);
    }

    private static ulong ParseMemKb(string line)
    {
        var match = Regex.Match(line, @"\d+");
        if (match.Success && ulong.TryParse(match.Value, out ulong kb))
        {
            return kb;
        }
        return 0;
    }

    public static (double freeDiskGb, double totalDiskGb) GetDiskUsage()
    {
        try
        {
            string rootPath = OperatingSystem.IsLinux() ? "/" : (Path.GetPathRoot(AppContext.BaseDirectory) ?? "C:\\");
            var drive = new DriveInfo(rootPath);
            double totalGb = Math.Round(drive.TotalSize / (1024.0 * 1024.0 * 1024.0), 2);
            double freeGb = Math.Round(drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0), 2);
            return (freeGb, totalGb);
        }
        catch
        {
            return (0, 0);
        }
    }

    public static long GetUptimeSeconds()
    {
        try
        {
            if (File.Exists("/proc/uptime"))
            {
                string first = File.ReadAllText("/proc/uptime").Trim().Split(' ')[0];
                if (double.TryParse(first, CultureInfo.InvariantCulture, out double secs))
                {
                    return (long)secs;
                }
            }
        }
        catch { }

        return (long)(Environment.TickCount64 / 1000);
    }

    private (double rxKbps, double txKbps) GetNetworkThroughput()
    {
        try
        {
            var now = DateTime.UtcNow;
            double elapsedSec = (now - _lastNetCheck).TotalSeconds;
            if (elapsedSec < 0.5)
            {
                return (_cachedNetRxKbps, _cachedNetTxKbps);
            }

            var (rx, tx) = ReadTotalNetBytes();
            if (_lastNetRxBytes > 0 && rx >= _lastNetRxBytes && elapsedSec > 0)
            {
                _cachedNetRxKbps = Math.Round(((rx - _lastNetRxBytes) * 8.0) / (1000.0 * elapsedSec), 1);
            }
            if (_lastNetTxBytes > 0 && tx >= _lastNetTxBytes && elapsedSec > 0)
            {
                _cachedNetTxKbps = Math.Round(((tx - _lastNetTxBytes) * 8.0) / (1000.0 * elapsedSec), 1);
            }

            _lastNetRxBytes = rx;
            _lastNetTxBytes = tx;
            _lastNetCheck = now;
        }
        catch { }

        return (_cachedNetRxKbps, _cachedNetTxKbps);
    }

    private static (ulong rxBytes, ulong txBytes) ReadTotalNetBytes()
    {
        ulong totalRx = 0;
        ulong totalTx = 0;

        try
        {
            if (File.Exists("/proc/net/dev"))
            {
                foreach (var line in File.ReadLines("/proc/net/dev").Skip(2))
                {
                    var parts = line.Trim().Split(':', 2);
                    if (parts.Length != 2) continue;

                    string iface = parts[0].Trim();
                    if (iface == "lo") continue;

                    var stats = parts[1].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (stats.Length >= 9)
                    {
                        if (ulong.TryParse(stats[0], out ulong rx)) totalRx += rx;
                        if (ulong.TryParse(stats[8], out ulong tx)) totalTx += tx;
                    }
                }
            }
        }
        catch { }

        return (totalRx, totalTx);
    }

    public LinuxHardwareSpecs GetHardwareSpecs()
    {
        string cpuName = "Unknown Linux Processor";
        try
        {
            if (File.Exists("/proc/cpuinfo"))
            {
                foreach (var line in File.ReadLines("/proc/cpuinfo"))
                {
                    if (line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(':', 2);
                        if (parts.Length == 2)
                        {
                            cpuName = parts[1].Trim();
                            break;
                        }
                    }
                }
            }
        }
        catch { }

        int cores = Environment.ProcessorCount;
        var (_, totalRam) = GetRamUsage();
        string distro = PlatformDetection.GetDistributionName();
        string osVersion = $"{distro} ({Environment.OSVersion.VersionString})";

        var (gpuName, gpuVram) = GetGpuInfo();

        return new LinuxHardwareSpecs
        {
            CpuName = cpuName,
            CpuCores = cores,
            CpuLogicalProcessors = cores,
            TotalRamMb = totalRam,
            OsVersion = osVersion,
            GpuName = gpuName,
            GpuMemoryMb = gpuVram
        };
    }

    private static (string name, ulong vramMb) GetGpuInfo()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "lspci",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(1000);

                var lines = output.Split('\n');
                var vgaLine = lines.FirstOrDefault(l => l.Contains("VGA compatible controller", StringComparison.OrdinalIgnoreCase) ||
                                                        l.Contains("3D controller", StringComparison.OrdinalIgnoreCase));
                if (vgaLine != null)
                {
                    var idx = vgaLine.IndexOf(':');
                    if (idx > 0 && idx < vgaLine.Length - 1)
                    {
                        string name = vgaLine.Substring(idx + 1).Trim();
                        return (name, 4096);
                    }
                }
            }
        }
        catch { }

        return ("Linux DRM Display Controller", 0);
    }

    public LinuxBatteryHealthState GetBatteryHealth()
    {
        double designCap = 0;
        double fullCap = 0;
        int cycleCount = 0;

        try
        {
            if (Directory.Exists("/sys/class/power_supply"))
            {
                foreach (var dir in Directory.GetDirectories("/sys/class/power_supply"))
                {
                    if (Path.GetFileName(dir).StartsWith("BAT", StringComparison.OrdinalIgnoreCase))
                    {
                        // Check energy or charge
                        string vMinFile = Path.Combine(dir, "voltage_min_design");
                        double vMin = 12.0;
                        if (File.Exists(vMinFile) && double.TryParse(File.ReadAllText(vMinFile).Trim(), out double vm) && vm > 0)
                        {
                            vMin = vm / 1_000_000.0; // uV to V
                        }

                        string cFullDesFile = Path.Combine(dir, "charge_full_design");
                        string cFullFile = Path.Combine(dir, "charge_full");
                        if (File.Exists(cFullDesFile) && double.TryParse(File.ReadAllText(cFullDesFile).Trim(), out double cDes) &&
                            File.Exists(cFullFile) && double.TryParse(File.ReadAllText(cFullFile).Trim(), out double cCur))
                        {
                            designCap = Math.Round((cDes * vMin) / 1000.0, 1);
                            fullCap = Math.Round((cCur * vMin) / 1000.0, 1);
                        }

                        string eFullDesFile = Path.Combine(dir, "energy_full_design");
                        string eFullFile = Path.Combine(dir, "energy_full");
                        if (File.Exists(eFullDesFile) && double.TryParse(File.ReadAllText(eFullDesFile).Trim(), out double eDes) &&
                            File.Exists(eFullFile) && double.TryParse(File.ReadAllText(eFullFile).Trim(), out double eCur))
                        {
                            designCap = Math.Round(eDes / 1000.0, 1);
                            fullCap = Math.Round(eCur / 1000.0, 1);
                        }

                        string cycleFile = Path.Combine(dir, "cycle_count");
                        if (File.Exists(cycleFile) && int.TryParse(File.ReadAllText(cycleFile).Trim(), out int cyc))
                        {
                            cycleCount = cyc;
                        }
                        break;
                    }
                }
            }
        }
        catch { }

        int wear = (designCap > 0 && fullCap > 0 && designCap >= fullCap)
            ? (int)Math.Round((1.0 - (fullCap / designCap)) * 100.0)
            : 0;

        return new LinuxBatteryHealthState
        {
            DesignedCapacityMwh = designCap,
            FullChargeCapacityMwh = fullCap,
            WearLevelPercent = wear,
            CycleCount = cycleCount
        };
    }

    public List<LinuxPowerPlanInfo> GetPowerPlans()
    {
        var plans = new List<LinuxPowerPlanInfo>();
        try
        {
            string govFile = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors";
            string curGovFile = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";

            string curGov = File.Exists(curGovFile) ? File.ReadAllText(curGovFile).Trim() : "";

            if (File.Exists(govFile))
            {
                var govs = File.ReadAllText(govFile).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var g in govs)
                {
                    plans.Add(new LinuxPowerPlanInfo
                    {
                        Guid = g,
                        Name = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(g),
                        IsActive = string.Equals(g, curGov, StringComparison.OrdinalIgnoreCase)
                    });
                }
            }
        }
        catch { }

        if (plans.Count == 0)
        {
            plans.Add(new LinuxPowerPlanInfo { Guid = "performance", Name = "Performance", IsActive = true });
            plans.Add(new LinuxPowerPlanInfo { Guid = "powersave", Name = "Power Saver", IsActive = false });
        }

        return plans;
    }

    public bool SetPowerPlan(string planGuidOrName)
    {
        try
        {
            string target = planGuidOrName.Trim().ToLowerInvariant();
            if (File.Exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"))
            {
                foreach (var file in Directory.GetFiles("/sys/devices/system/cpu/", "scaling_governor", SearchOption.AllDirectories))
                {
                    try { File.WriteAllText(file, target); } catch { }
                }
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxAdminManager: SetPowerPlan error: {ex.Message}");
        }
        return false;
    }

    public List<LinuxUsbDeviceInfo> GetUsbDevices()
    {
        var list = new List<LinuxUsbDeviceInfo>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "lsusb",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(1000);

                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    // Bus 001 Device 002: ID 8087:0026 Intel Corp. AX201 Bluetooth
                    var match = Regex.Match(line, @"ID\s+([0-9a-fA-F:]+)\s+(.+)");
                    if (match.Success)
                    {
                        list.Add(new LinuxUsbDeviceInfo
                        {
                            DeviceId = match.Groups[1].Value.Trim(),
                            Name = match.Groups[2].Value.Trim(),
                            Status = "OK"
                        });
                    }
                }
            }
        }
        catch { }

        return list;
    }

    public List<LinuxServiceDetails> GetServices()
    {
        var list = new List<LinuxServiceDetails>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "systemctl",
                Arguments = "list-units --type=service --no-legend --no-pager",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(2000);

                foreach (var rawLine in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var line = rawLine.Trim();
                    // accounts-daemon.service loaded active running Accounts Service
                    var parts = Regex.Split(line, @"\s+");
                    if (parts.Length >= 5 && parts[0].EndsWith(".service", StringComparison.OrdinalIgnoreCase))
                    {
                        string sName = parts[0].Substring(0, parts[0].Length - 8);
                        string status = parts[3];
                        string desc = string.Join(" ", parts.Skip(4));

                        list.Add(new LinuxServiceDetails
                        {
                            ServiceName = sName,
                            DisplayName = string.IsNullOrWhiteSpace(desc) ? sName : desc,
                            Status = status.Equals("running", StringComparison.OrdinalIgnoreCase) ? "Running" : "Stopped",
                            CanStop = true
                        });
                    }
                }
            }
        }
        catch { }

        return list;
    }

    public bool ControlService(string serviceName, string action)
    {
        string act = action.Trim().ToLowerInvariant();
        if (act != "start" && act != "stop" && act != "restart") return false;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "systemctl",
                Arguments = $"{act} {serviceName}.service",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                p.WaitForExit(3000);
                return p.ExitCode == 0;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxAdminManager: systemctl {act} {serviceName} error: {ex.Message}");
        }

        return false;
    }

    public LinuxUpdateInfo GetSystemUpdates()
    {
        lock (_updateLock)
        {
            var now = DateTime.UtcNow;
            if (_cachedUpdateInfo != null && (now - _lastUpdateCheck).TotalMinutes < 10)
            {
                return _cachedUpdateInfo;
            }

            var titles = new List<string>();
            bool isAvailable = false;

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "dnf",
                    Arguments = "check-update --quiet",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p != null)
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);

                    // exit code 100 indicates updates are available
                    if (p.ExitCode == 100 || !string.IsNullOrWhiteSpace(output))
                    {
                        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                        {
                            var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2 && !parts[0].StartsWith("Security", StringComparison.OrdinalIgnoreCase))
                            {
                                titles.Add($"{parts[0]} ({parts[1]})");
                            }
                        }
                        isAvailable = titles.Count > 0;
                    }
                }
            }
            catch { }

            _cachedUpdateInfo = new LinuxUpdateInfo
            {
                PendingUpdatesCount = titles.Count,
                IsUpdateAvailable = isAvailable,
                Titles = titles,
                StatusMessage = isAvailable ? $"{titles.Count} updates available" : "System is up to date"
            };
            _lastUpdateCheck = now;

            return _cachedUpdateInfo;
        }
    }
}
