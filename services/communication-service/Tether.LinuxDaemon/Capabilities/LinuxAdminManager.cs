using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Common;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Capabilities;

public sealed record LinuxSystemTelemetry
{
    [JsonPropertyName("cpuUsage")] public int CpuUsage { get; init; }
    [JsonPropertyName("totalRamMb")] public ulong TotalRamMb { get; init; }
    [JsonPropertyName("availRamMb")] public ulong AvailRamMb { get; init; }
    [JsonPropertyName("ramUsagePct")] public int RamUsagePct { get; init; }
    [JsonPropertyName("disks")] public List<LinuxDiskUsage> Disks { get; init; } = new();
    [JsonPropertyName("networks")] public List<LinuxNetworkInfo> Networks { get; init; } = new();
    [JsonPropertyName("gpuName")] public string GpuName { get; init; } = "";
    [JsonPropertyName("gpuVramMb")] public ulong GpuVramMb { get; init; }
    [JsonPropertyName("cpuCores")] public int CpuCores { get; init; }
    [JsonPropertyName("uptimeSeconds")] public long UptimeSeconds { get; init; }
}

public sealed record LinuxDiskUsage
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("volumeLabel")] public string VolumeLabel { get; init; } = "";
    [JsonPropertyName("totalGb")] public double TotalGb { get; init; }
    [JsonPropertyName("freeGb")] public double FreeGb { get; init; }
    [JsonPropertyName("format")] public string Format { get; init; } = "";
}

public sealed record LinuxNetworkInfo
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("description")] public string Description { get; init; } = "";
    [JsonPropertyName("type")] public string Type { get; init; } = "";
    [JsonPropertyName("bytesReceived")] public long BytesReceived { get; init; }
    [JsonPropertyName("bytesSent")] public long BytesSent { get; init; }
    [JsonPropertyName("speedMbps")] public long SpeedMbps { get; init; }
}

public sealed record LinuxHardwareSpecs
{
    [JsonPropertyName("processorName")] public string ProcessorName { get; init; } = "";
    [JsonPropertyName("coreCount")] public int CoreCount { get; init; }
    [JsonPropertyName("totalMemoryMb")] public ulong TotalMemoryMb { get; init; }
    [JsonPropertyName("gpuName")] public string GpuName { get; init; } = "";
    [JsonPropertyName("gpuVramMb")] public ulong GpuVramMb { get; init; }
    [JsonPropertyName("systemManufacturer")] public string SystemManufacturer { get; init; } = "";
    [JsonPropertyName("systemModel")] public string SystemModel { get; init; } = "";
    [JsonPropertyName("biosVersion")] public string BiosVersion { get; init; } = "";
    [JsonPropertyName("osDescription")] public string OsDescription { get; init; } = "";
    [JsonPropertyName("uptimeSeconds")] public long UptimeSeconds { get; init; }
}

public sealed record LinuxBatteryReport
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("batteryName")] public string BatteryName { get; init; } = "";
    [JsonPropertyName("manufacturer")] public string Manufacturer { get; init; } = "";
    [JsonPropertyName("serialNumber")] public string SerialNumber { get; init; } = "";
    [JsonPropertyName("chemistry")] public string Chemistry { get; init; } = "";
    [JsonPropertyName("designCapacityMwh")] public double DesignCapacityMwh { get; init; }
    [JsonPropertyName("fullChargeCapacityMwh")] public double FullChargeCapacityMwh { get; init; }
    [JsonPropertyName("cycleCount")] public int CycleCount { get; init; }
    [JsonPropertyName("healthPercent")] public int HealthPercent { get; init; }
    [JsonPropertyName("currentChargePercent")] public int CurrentChargePercent { get; init; }
    [JsonPropertyName("chargingStatus")] public string ChargingStatus { get; init; } = "";
    [JsonPropertyName("reportTimestamp")] public string ReportTimestamp { get; init; } = "";
    [JsonPropertyName("errorMessage")] public string ErrorMessage { get; init; } = "";
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

public sealed record LinuxPrinterInfo
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("port")] public string Port { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "Ready";
    [JsonPropertyName("jobsCount")] public int JobsCount { get; init; }
}

public sealed record LinuxUpdateInfo
{
    [JsonPropertyName("pendingUpdatesCount")] public int PendingUpdatesCount { get; init; }
    [JsonPropertyName("packageManager")] public string PackageManager { get; init; } = "";
    [JsonPropertyName("pendingCount")] public int PendingCount => PendingUpdatesCount;
    [JsonPropertyName("isUpdateAvailable")] public bool IsUpdateAvailable { get; init; }
    [JsonPropertyName("isAvailable")] public bool IsAvailable => IsUpdateAvailable;
    [JsonPropertyName("titles")] public List<string> Titles { get; init; } = new();
    [JsonPropertyName("statusMessage")] public string StatusMessage { get; init; } = "OK";
    [JsonPropertyName("checkSucceeded")] public bool CheckSucceeded { get; init; } = true;
}

public sealed class LinuxAdminManager
{
    private readonly ITetherLogger _logger;

    private static ulong _lastTotalJiffies;
    private static ulong _lastIdleJiffies;
    private static DateTime _lastCpuCheck = DateTime.MinValue;
    private static int _cachedCpuUsage = 0;

    private static LinuxUpdateInfo? _cachedUpdateInfo;
    private static DateTime _lastUpdateCheck = DateTime.MinValue;
    private static readonly object _updateLock = new();

    public LinuxAdminManager(ITetherLogger logger)
    {
        _logger = logger;
        InitCpuJiffies();
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

    public LinuxSystemTelemetry GetSystemTelemetry()
    {
        int cpu = GetCpuUsage();
        var (usedRam, totalRam) = GetRamUsage();
        var (gpuName, gpuVram) = GetGpuInfo();

        return new LinuxSystemTelemetry
        {
            CpuUsage = cpu,
            TotalRamMb = totalRam,
            AvailRamMb = totalRam > usedRam ? totalRam - usedRam : 0,
            RamUsagePct = totalRam > 0 ? (int)Math.Round(usedRam * 100.0 / totalRam) : 0,
            Disks = GetDiskUsage(),
            Networks = GetNetworkInterfaces(),
            GpuName = gpuName,
            GpuVramMb = gpuVram,
            CpuCores = Environment.ProcessorCount,
            UptimeSeconds = GetUptimeSeconds()
        };
    }

    private static List<LinuxNetworkInfo> GetNetworkInterfaces()
    {
        var list = new List<LinuxNetworkInfo>();
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up &&
                                     n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback))
            {
                var stats = ni.GetIPStatistics();
                list.Add(new LinuxNetworkInfo
                {
                    Name = ni.Name,
                    Description = ni.Description,
                    Type = ni.NetworkInterfaceType.ToString(),
                    BytesReceived = stats.BytesReceived,
                    BytesSent = stats.BytesSent,
                    SpeedMbps = ni.Speed > 0 ? ni.Speed / 1_000_000 : 0
                });
            }
        }
        catch { }
        return list;
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

    public static List<LinuxDiskUsage> GetDiskUsage()
    {
        var list = new List<LinuxDiskUsage>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable))
            {
                list.Add(new LinuxDiskUsage
                {
                    Name = drive.Name,
                    VolumeLabel = drive.VolumeLabel ?? "",
                    TotalGb = Math.Round(drive.TotalSize / (1024.0 * 1024.0 * 1024.0), 2),
                    FreeGb = Math.Round(drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0), 2),
                    Format = drive.DriveFormat
                });
            }
        }
        catch { }
        return list;
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
        string kernel = ReadTrimmedFile("/proc/sys/kernel/osrelease") ?? Environment.OSVersion.VersionString;
        string osDescription = $"{distro}, kernel {kernel} ({System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})";

        var (gpuName, gpuVram) = GetGpuInfo();

        return new LinuxHardwareSpecs
        {
            ProcessorName = cpuName,
            CoreCount = cores,
            TotalMemoryMb = totalRam,
            GpuName = gpuName,
            GpuVramMb = gpuVram,
            OsDescription = osDescription,
            UptimeSeconds = GetUptimeSeconds()
        };
    }

    private static string? ReadTrimmedFile(string path)
    {
        try { return File.Exists(path) ? File.ReadAllText(path).Trim() : null; }
        catch { return null; }
    }

    private static (string name, ulong vramMb) GetGpuInfo()
    {
        string name = "";
        try
        {
            var (exit, output) = RunCapture("lspci", "", 1000);
            if (exit == 0 && !string.IsNullOrWhiteSpace(output))
            {
                var lines = output.Split('\n');
                var vgaLine = lines.FirstOrDefault(l => l.Contains("VGA compatible controller", StringComparison.OrdinalIgnoreCase) ||
                                                        l.Contains("3D controller", StringComparison.OrdinalIgnoreCase));
                if (vgaLine != null)
                {
                    var idx = vgaLine.IndexOf(':');
                    if (idx > 0 && idx < vgaLine.Length - 1)
                    {
                        name = vgaLine.Substring(idx + 1).Trim();
                    }
                }
            }
        }
        catch { }

        // AMD exposes VRAM through sysfs; NVIDIA/Intel do not. Report 0 when unknown instead of guessing.
        ulong vramMb = 0;
        foreach (var card in Directory.Exists("/sys/class/drm") ? Directory.GetDirectories("/sys/class/drm", "card[0-9]") : Array.Empty<string>())
        {
            if (ulong.TryParse(ReadTrimmedFile(Path.Combine(card, "device", "mem_info_vram_total")), out ulong bytes) && bytes > 0)
            {
                vramMb = bytes / (1024 * 1024);
                break;
            }
        }

        return (name, vramMb);
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
                        // charge_* is in uAh and needs design voltage; energy_* is already in uWh.
                        string vMinFile = Path.Combine(dir, "voltage_min_design");
                        double? vMin = null;
                        if (File.Exists(vMinFile) && double.TryParse(File.ReadAllText(vMinFile).Trim(), out double vm) && vm > 0)
                        {
                            vMin = vm / 1_000_000.0; // uV to V
                        }

                        string cFullDesFile = Path.Combine(dir, "charge_full_design");
                        string cFullFile = Path.Combine(dir, "charge_full");
                        if (vMin.HasValue &&
                            File.Exists(cFullDesFile) && double.TryParse(File.ReadAllText(cFullDesFile).Trim(), out double cDes) &&
                            File.Exists(cFullFile) && double.TryParse(File.ReadAllText(cFullFile).Trim(), out double cCur))
                        {
                            designCap = Math.Round((cDes * vMin.Value) / 1000.0, 1);
                            fullCap = Math.Round((cCur * vMin.Value) / 1000.0, 1);
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

    private enum PowerBackend { None, PowerProfilesDaemon, AcpiPlatformProfile, CpufreqGovernor }

    private static string DisplayPowerName(string id) => id switch
    {
        "performance" => "Performance",
        "balanced" or "balance_performance" or "balance_power" => "Balanced",
        "power-saver" or "low-power" or "powersave" => "Power Saver",
        _ => CultureInfo.InvariantCulture.TextInfo.ToTitleCase(id.Replace('-', ' '))
    };

    private static string? RunTool(string file, string arguments, int timeoutMs)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = file,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (p == null) return null;

            var stdoutTask = ReadBoundedAsync(p.StandardOutput, MaxCapturedChars);
            _ = p.StandardError.ReadToEndAsync();

            bool exited = p.WaitForExit(timeoutMs);
            if (!exited)
            {
                try { p.Kill(true); } catch { }
                try { p.WaitForExit(1000); } catch { }
                return null;
            }

            string output = stdoutTask.GetAwaiter().GetResult();
            return p.ExitCode == 0 ? output : null;
        }
        catch { return null; }
    }

    private static List<LinuxPowerPlanInfo> QueryPowerPlans(out PowerBackend backend)
    {
        backend = PowerBackend.None;
        var plans = new List<LinuxPowerPlanInfo>();

        string? ppd = RunTool("powerprofilesctl", "list", 1500);
        if (!string.IsNullOrWhiteSpace(ppd))
        {
            backend = PowerBackend.PowerProfilesDaemon;
            foreach (var raw in ppd.Split('\n'))
            {
                var m = Regex.Match(raw, @"^\s*(\*)?\s*([a-z0-9-]+):");
                if (!m.Success) continue;
                string id = m.Groups[2].Value;
                if (plans.Any(p => p.Guid == id)) continue;
                plans.Add(new LinuxPowerPlanInfo { Guid = id, Name = DisplayPowerName(id), IsActive = m.Groups[1].Value == "*" });
            }
            if (plans.Count > 0) return plans;
            backend = PowerBackend.None;
        }

        string? choices = ReadTrimmedFile("/sys/firmware/acpi/platform_profile_choices");
        string? current = ReadTrimmedFile("/sys/firmware/acpi/platform_profile");
        if (!string.IsNullOrWhiteSpace(choices) && !string.IsNullOrWhiteSpace(current))
        {
            backend = PowerBackend.AcpiPlatformProfile;
            foreach (var id in choices.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                plans.Add(new LinuxPowerPlanInfo { Guid = id, Name = DisplayPowerName(id), IsActive = string.Equals(id, current, StringComparison.OrdinalIgnoreCase) });
            }
            return plans;
        }

        string? governors = ReadTrimmedFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors");
        string? activeGovernor = ReadTrimmedFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
        if (!string.IsNullOrWhiteSpace(governors))
        {
            backend = PowerBackend.CpufreqGovernor;
            foreach (var id in governors.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                plans.Add(new LinuxPowerPlanInfo { Guid = id, Name = DisplayPowerName(id), IsActive = string.Equals(id, activeGovernor, StringComparison.OrdinalIgnoreCase) });
            }
        }
        return plans;
    }

    public LinuxBatteryReport GenerateBatteryReport()
    {
        string batteryDir = "";
        try
        {
            batteryDir = Directory.Exists("/sys/class/power_supply")
                ? Directory.GetDirectories("/sys/class/power_supply").FirstOrDefault(d => Path.GetFileName(d).StartsWith("BAT", StringComparison.OrdinalIgnoreCase)) ?? ""
                : "";
        }
        catch { }

        if (string.IsNullOrEmpty(batteryDir))
        {
            return new LinuxBatteryReport
            {
                Success = false,
                ReportTimestamp = DateTimeOffset.UtcNow.ToString("u", CultureInfo.InvariantCulture),
                ErrorMessage = "No battery detected on this system."
            };
        }

        var health = GetBatteryHealth();
        string status = ReadTrimmedFile(Path.Combine(batteryDir, "status")) ?? "";
        int chargePercent = int.TryParse(ReadTrimmedFile(Path.Combine(batteryDir, "capacity")), out int c) ? c : 0;
        int healthPct = health.DesignedCapacityMwh > 0 && health.FullChargeCapacityMwh > 0
            ? (int)Math.Round(health.FullChargeCapacityMwh * 100.0 / health.DesignedCapacityMwh)
            : 0;

        return new LinuxBatteryReport
        {
            Success = true,
            BatteryName = ReadTrimmedFile(Path.Combine(batteryDir, "model_name")) ?? Path.GetFileName(batteryDir),
            Manufacturer = ReadTrimmedFile(Path.Combine(batteryDir, "manufacturer")) ?? "",
            SerialNumber = ReadTrimmedFile(Path.Combine(batteryDir, "serial_number")) ?? "",
            Chemistry = ReadTrimmedFile(Path.Combine(batteryDir, "technology")) ?? "",
            DesignCapacityMwh = health.DesignedCapacityMwh,
            FullChargeCapacityMwh = health.FullChargeCapacityMwh,
            CycleCount = health.CycleCount,
            HealthPercent = healthPct,
            CurrentChargePercent = chargePercent,
            ChargingStatus = status,
            ReportTimestamp = DateTimeOffset.UtcNow.ToString("u", CultureInfo.InvariantCulture)
        };
    }

    public List<LinuxPowerPlanInfo> GetPowerPlans() => QueryPowerPlans(out _);

    public bool SetPowerPlan(string planGuidOrName)
    {
        string requested = (planGuidOrName ?? "").Trim();
        if (requested.Length == 0 || requested.Length > 64) return false;

        var plans = QueryPowerPlans(out var backend);
        var target = plans.FirstOrDefault(p =>
            string.Equals(p.Guid, requested, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(p.Name, requested, StringComparison.OrdinalIgnoreCase));
        if (target == null || backend == PowerBackend.None)
        {
            _logger.Warning($"LinuxAdminManager: Power profile '{requested}' is not offered by the detected backend.");
            return false;
        }

        try
        {
            switch (backend)
            {
                case PowerBackend.PowerProfilesDaemon:
                    if (RunTool("powerprofilesctl", $"set {target.Guid}", 2000) == null) return false;
                    break;
                case PowerBackend.AcpiPlatformProfile:
                    File.WriteAllText("/sys/firmware/acpi/platform_profile", target.Guid);
                    break;
                case PowerBackend.CpufreqGovernor:
                    int applied = 0;
                    foreach (var file in Directory.GetFiles("/sys/devices/system/cpu/", "scaling_governor", SearchOption.AllDirectories))
                    {
                        try { File.WriteAllText(file, target.Guid); applied++; } catch { }
                    }
                    if (applied == 0) return false;
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxAdminManager: SetPowerPlan '{target.Guid}' failed: {ex.Message}");
            return false;
        }

        // Report success only if the system actually moved to the requested profile.
        bool confirmed = QueryPowerPlans(out _).Any(p => p.IsActive && string.Equals(p.Guid, target.Guid, StringComparison.OrdinalIgnoreCase));
        if (!confirmed)
        {
            _logger.Warning($"LinuxAdminManager: Power profile change to '{target.Guid}' was not confirmed by the backend.");
        }
        return confirmed;
    }

    public List<LinuxPrinterInfo> GetPrinters()
    {
        var list = new List<LinuxPrinterInfo>();
        if (!ExecutableExists("lpstat")) return list;

        var (exit, output) = RunCapture("lpstat", "-p -o", 3000);
        if (exit != 0 || string.IsNullOrWhiteSpace(output)) return list;

        var jobs = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();

            // printer Office is idle.  enabled since ...
            // printer Office disabled since ...
            // printer Office now printing Office-42. ...
            var match = Regex.Match(line, @"^printer\s+(\S+)\s+(.+)$", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                string name = match.Groups[1].Value;
                string rest = match.Groups[2].Value;
                string status = rest.StartsWith("now printing", StringComparison.OrdinalIgnoreCase) ? "Printing"
                    : rest.StartsWith("disabled", StringComparison.OrdinalIgnoreCase) ? "Stopped"
                    : "Ready";
                if (!list.Any(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
                {
                    list.Add(new LinuxPrinterInfo { Name = name, Status = status });
                }
                continue;
            }

            // Queued job: Office-42 user 1024 ...
            var jobMatch = Regex.Match(line, @"^(\S+?)-\d+\s+", RegexOptions.IgnoreCase);
            if (jobMatch.Success)
            {
                string printer = jobMatch.Groups[1].Value;
                jobs[printer] = jobs.TryGetValue(printer, out int count) ? count + 1 : 1;
            }
        }

        for (int i = 0; i < list.Count; i++)
        {
            if (jobs.TryGetValue(list[i].Name, out int jobCount))
            {
                list[i] = list[i] with { JobsCount = jobCount };
            }
        }
        return list;
    }

    public List<LinuxUsbDeviceInfo> GetUsbDevices()
    {
        var list = new List<LinuxUsbDeviceInfo>();
        try
        {
            var (exit, output) = RunCapture("lsusb", "", 1000);
            if (exit == 0 && !string.IsNullOrWhiteSpace(output))
            {
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
            var (exit, output) = RunCapture("systemctl", "list-units --type=service --no-legend --no-pager", 3000);
            if (exit == 0 && !string.IsNullOrWhiteSpace(output))
            {
                foreach (var rawLine in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    // Failed units are prefixed with a bullet (●) by systemctl.
                    var line = rawLine.Trim().TrimStart('●', '*', ' ');
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

    // Must start with an alphanumeric (or @/_) so a client cannot pass a leading '-' option.
    private static readonly Regex UnitNamePattern = new(@"^[A-Za-z0-9@_][A-Za-z0-9@._:-]{0,119}$", RegexOptions.Compiled);

    // Units whose loss would break the session, the desktop or the remote-control path itself.
    private static readonly HashSet<string> ProtectedUnits = new(StringComparer.OrdinalIgnoreCase)
    {
        "systemd-logind", "systemd-journald", "systemd-oomd", "systemd-udevd",
        "dbus", "dbus-broker", "polkit", "tether"
    };

    public bool ControlService(string serviceName, string action)
    {
        string act = (action ?? "").Trim().ToLowerInvariant();
        if (act != "start" && act != "stop" && act != "restart")
        {
            _logger.Warning($"LinuxAdminManager: Rejected service action '{act}'.");
            return false;
        }

        string name = (serviceName ?? "").Trim();
        if (name.EndsWith(".service", StringComparison.OrdinalIgnoreCase)) name = name[..^8];
        if (!UnitNamePattern.IsMatch(name) || name.Contains("..", StringComparison.Ordinal))
        {
            _logger.Warning($"LinuxAdminManager: Rejected malformed service name '{name}'.");
            return false;
        }
        if (ProtectedUnits.Contains(name))
        {
            _logger.Warning($"LinuxAdminManager: Refusing to control protected unit '{name}'.");
            return false;
        }
        if (!Directory.Exists("/run/systemd/system") || !ExecutableExists("systemctl"))
        {
            _logger.Warning("LinuxAdminManager: systemd is not available on this host.");
            return false;
        }

        var (exit, _) = RunCapture("systemctl", $"{act} {name}.service", 10000);
        if (exit != 0)
        {
            _logger.Warning($"LinuxAdminManager: systemctl {act} {name}.service failed (exit {exit}).");
        }
        return exit == 0;
    }

    private static bool ExecutableExists(string name) =>
        new[] { "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/" }
            .Any(dir => File.Exists(Path.Combine(dir, name)));

    // Bounds memory if a package manager emits an endless stream.
    private const int MaxCapturedChars = 4 * 1024 * 1024;

    /// <summary>
    /// Drains stdout concurrently while waiting, so the timeout is actually enforceable even if
    /// the child fills the pipe. Output is capped, and stderr is drained but discarded.
    /// </summary>
    private static (int exitCode, string output) RunCapture(string file, string arguments, int timeoutMs)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = file,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (p == null) return (-1, "");

            var stdoutTask = ReadBoundedAsync(p.StandardOutput, MaxCapturedChars);
            _ = p.StandardError.ReadToEndAsync();

            bool exited = p.WaitForExit(timeoutMs);
            if (!exited)
            {
                try { p.Kill(true); } catch { }
                try { p.WaitForExit(1000); } catch { }
            }

            string output = stdoutTask.GetAwaiter().GetResult();
            return exited ? (p.ExitCode, output) : (-1, output);
        }
        catch
        {
            return (-1, "");
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, int maxChars)
    {
        var sb = new StringBuilder();
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer)) > 0)
        {
            if (sb.Length < maxChars)
            {
                sb.Append(buffer, 0, Math.Min(read, maxChars - sb.Length));
            }
        }
        return sb.ToString();
    }

    private static List<string> ParseAptSimulation(string output) =>
        output.Split('\n')
            .Where(l => l.StartsWith("Inst ", StringComparison.Ordinal))
            .Select(l => l.Substring(5).Trim())
            .Where(l => l.Length > 0)
            .ToList();

    private static List<string> ParseDnfCheckUpdate(string output) =>
        output.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 2 && !l.StartsWith("Last metadata", StringComparison.OrdinalIgnoreCase) &&
                        !l.StartsWith("Security:", StringComparison.OrdinalIgnoreCase) && !l.StartsWith("Obsoleting", StringComparison.OrdinalIgnoreCase))
            .Where(l => l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).Length >= 2)
            .Select(l =>
            {
                var parts = l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                return $"{parts[0]} ({parts[1]})";
            })
            .ToList();

    private static List<string> ParsePacmanUpdates(string output) =>
        output.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Contains(" -> "))
            .ToList();

    private static List<string> ParseZypperUpdates(string output) =>
        output.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.StartsWith("v ", StringComparison.Ordinal) || l.StartsWith("| ", StringComparison.Ordinal))
            .Select(l => l.TrimStart('v', '|', ' '))
            .Where(l => l.Length > 0 && !l.StartsWith("Name", StringComparison.OrdinalIgnoreCase))
            .ToList();

    private static LinuxUpdateInfo CheckUpdatesOnce()
    {
        // Probe only for a package manager that is actually installed; never fan out to all of them.
        if (ExecutableExists("apt-get"))
        {
            var (exit, output) = RunCapture("apt-get", "-s -q upgrade", 15000);
            if (exit == 0)
            {
                var titles = ParseAptSimulation(output);
                return new LinuxUpdateInfo
                {
                    PackageManager = "apt",
                    PendingUpdatesCount = titles.Count,
                    IsUpdateAvailable = titles.Count > 0,
                    Titles = titles,
                    StatusMessage = titles.Count > 0 ? $"{titles.Count} updates available" : "System is up to date"
                };
            }
            return new LinuxUpdateInfo { PackageManager = "apt", PendingUpdatesCount = -1, CheckSucceeded = false, StatusMessage = "Update check failed: apt-get simulation returned an error (locked database or unreachable repository)." };
        }

        if (ExecutableExists("dnf"))
        {
            // dnf exits 100 when updates are pending, 0 when up to date.
            var (exit, output) = RunCapture("dnf", "-q check-update", 20000);
            if (exit == 0 || exit == 100)
            {
                var titles = exit == 100 ? ParseDnfCheckUpdate(output) : new List<string>();
                return new LinuxUpdateInfo
                {
                    PackageManager = "dnf",
                    PendingUpdatesCount = titles.Count,
                    IsUpdateAvailable = titles.Count > 0,
                    Titles = titles,
                    StatusMessage = titles.Count > 0 ? $"{titles.Count} updates available" : "System is up to date"
                };
            }
            return new LinuxUpdateInfo { PackageManager = "dnf", PendingUpdatesCount = -1, CheckSucceeded = false, StatusMessage = "Update check failed: dnf returned an error." };
        }

        if (ExecutableExists("zypper"))
        {
            var (exit, output) = RunCapture("zypper", "--non-interactive --quiet list-updates", 30000);
            if (exit == 0)
            {
                var titles = ParseZypperUpdates(output);
                return new LinuxUpdateInfo
                {
                    PackageManager = "zypper",
                    PendingUpdatesCount = titles.Count,
                    IsUpdateAvailable = titles.Count > 0,
                    Titles = titles,
                    StatusMessage = titles.Count > 0 ? $"{titles.Count} updates available" : "System is up to date"
                };
            }
            return new LinuxUpdateInfo { PackageManager = "zypper", PendingUpdatesCount = -1, CheckSucceeded = false, StatusMessage = "Update check failed: zypper returned an error." };
        }

        if (ExecutableExists("checkupdates"))
        {
            var (exit, output) = RunCapture("checkupdates", "", 30000);
            // checkupdates exits 2 when there is nothing to do.
            if (exit == 0 || exit == 2)
            {
                var titles = exit == 0 ? ParsePacmanUpdates(output) : new List<string>();
                return new LinuxUpdateInfo
                {
                    PackageManager = "pacman",
                    PendingUpdatesCount = titles.Count,
                    IsUpdateAvailable = titles.Count > 0,
                    Titles = titles,
                    StatusMessage = titles.Count > 0 ? $"{titles.Count} updates available" : "System is up to date"
                };
            }
            return new LinuxUpdateInfo { PackageManager = "pacman", PendingUpdatesCount = -1, CheckSucceeded = false, StatusMessage = "Update check failed: checkupdates returned an error." };
        }

        if (ExecutableExists("pacman"))
        {
            var (exit, output) = RunCapture("pacman", "-Qu", 15000);
            // pacman -Qu exits 1 when no upgrades are available.
            if (exit == 0 || exit == 1)
            {
                var titles = exit == 0 ? ParsePacmanUpdates(output) : new List<string>();
                return new LinuxUpdateInfo
                {
                    PackageManager = "pacman",
                    PendingUpdatesCount = titles.Count,
                    IsUpdateAvailable = titles.Count > 0,
                    Titles = titles,
                    StatusMessage = titles.Count > 0 ? $"{titles.Count} updates available" : "System is up to date"
                };
            }
            return new LinuxUpdateInfo { PackageManager = "pacman", PendingUpdatesCount = -1, CheckSucceeded = false, StatusMessage = "Update check failed: pacman returned an error." };
        }

        return new LinuxUpdateInfo { PendingUpdatesCount = -1, CheckSucceeded = false, StatusMessage = "No supported package manager detected (apt, dnf, zypper, pacman)." };
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

            _cachedUpdateInfo = CheckUpdatesOnce();
            _lastUpdateCheck = now;

            return _cachedUpdateInfo;
        }
    }
}
