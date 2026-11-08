using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Capabilities;

public sealed class WindowsAdminManager
{
    private readonly ITetherLogger _logger;

    private static WindowsUpdateInfo? _cachedUpdateInfo;
    private static DateTime _lastUpdateCheck = DateTime.MinValue;
    private static readonly object _updateLock = new();

    public WindowsAdminManager(ITetherLogger logger)
    {
        _logger = logger;
        try
        {
            if (GetSystemTimes(out var idleTime, out var kernelTime, out var userTime))
            {
                _lastIdle = idleTime.Value;
                _lastKernel = kernelTime.Value;
                _lastUser = userTime.Value;
                _lastTimesCheck = DateTime.UtcNow;
            }
        }
        catch { }
    }

    private static (string name, ulong vramMb) GetGpuInfo()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name, AdapterRAM FROM Win32_VideoController");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    string name = mo["Name"]?.ToString() ?? "";
                    ulong bytes = Convert.ToUInt64(mo["AdapterRAM"] ?? 0);
                    if (!string.IsNullOrEmpty(name))
                    {
                        return (name, bytes / (1024 * 1024));
                    }
                }
            }
        }
        catch { }
        return ("Standard Display Adapter", 0);
    }

    #region Win32 Memory & Times P/Invoke
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private class MEMORYSTATUSEX
    {
        public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out FILETIME lpIdleTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
        public ulong Value => ((ulong)dwHighDateTime << 32) | dwLowDateTime;
    }

    private static ulong _lastIdle;
    private static ulong _lastKernel;
    private static ulong _lastUser;
    private static DateTime _lastTimesCheck = DateTime.MinValue;
    private static int _cachedCpuUsage = 0;
    #endregion

    #region Win32 Power Schemes
    [DllImport("powrprof.dll", SetLastError = true)]
    private static extern uint PowerGetActiveScheme(IntPtr UserRootPowerKey, out IntPtr ActivePolicyGuid);

    [DllImport("powrprof.dll", SetLastError = true)]
    private static extern uint PowerSetActiveScheme(IntPtr UserRootPowerKey, ref Guid SchemeGuid);

    [DllImport("powrprof.dll", SetLastError = true)]
    private static extern uint PowerEnumerate(IntPtr RootPowerKey, IntPtr SchemeGuid, IntPtr SubGroupOfPowerSettingsGuid, uint AcessFlags, uint Index, IntPtr Buffer, ref uint BufferSize);

    [DllImport("powrprof.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint PowerReadFriendlyName(IntPtr RootPowerKey, ref Guid SchemeGuid, IntPtr SubGroupOfPowerSettingsGuid, IntPtr PowerSettingGuid, IntPtr Buffer, ref uint BufferSize);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);
    #endregion

    #region Win32 Printers
    [DllImport("winspool.drv", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool EnumPrinters(int flags, string? name, int level, IntPtr pPrinterEnum, int cbBuf, out int pcbNeeded, out int pcReturned);

    private const int PRINTER_ENUM_LOCAL = 0x00000002;
    private const int PRINTER_ENUM_CONNECTIONS = 0x00000004;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PRINTER_INFO_2
    {
        public string pServerName;
        public string pPrinterName;
        public string pShareName;
        public string pPortName;
        public string pDriverName;
        public string pComment;
        public string pLocation;
        public IntPtr pDevMode;
        public string pSepFile;
        public string pPrintProcessor;
        public string pDatatype;
        public string pParameters;
        public IntPtr pSecurityDescriptor;
        public uint Attributes;
        public uint Priority;
        public uint DefaultPriority;
        public uint StartTime;
        public uint UntilTime;
        public uint Status;
        public uint cJobs;
        public uint AveragePPM;
    }
    #endregion

    public SystemTelemetrySnapshot GetSystemTelemetry()
    {
        int cpuUsage = GetCpuUsagePercent();

        var memStatus = new MEMORYSTATUSEX();
        ulong totalPhysMb = 0;
        ulong availPhysMb = 0;
        int memoryLoadPct = 0;
        if (GlobalMemoryStatusEx(memStatus))
        {
            totalPhysMb = memStatus.ullTotalPhys / (1024 * 1024);
            availPhysMb = memStatus.ullAvailPhys / (1024 * 1024);
            memoryLoadPct = (int)memStatus.dwMemoryLoad;
        }

        var drives = new List<DiskUsageInfo>();
        try
        {
            foreach (var d in DriveInfo.GetDrives().Where(d => d.IsReady))
            {
                drives.Add(new DiskUsageInfo
                {
                    Name = d.Name,
                    VolumeLabel = d.VolumeLabel,
                    TotalGigabytes = (double)d.TotalSize / (1024 * 1024 * 1024),
                    FreeGigabytes = (double)d.AvailableFreeSpace / (1024 * 1024 * 1024),
                    Format = d.DriveFormat
                });
            }
        }
        catch { }

        var netList = new List<NetworkInterfaceInfo>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up))
            {
                var stats = ni.GetIPStatistics();
                netList.Add(new NetworkInterfaceInfo
                {
                    Name = ni.Name,
                    Description = ni.Description,
                    Type = ni.NetworkInterfaceType.ToString(),
                    BytesReceived = stats.BytesReceived,
                    BytesSent = stats.BytesSent,
                    SpeedMbps = ni.Speed / 1_000_000
                });
            }
        }
        catch { }

        var (gpuName, gpuVram) = GetGpuInfo();
        return new SystemTelemetrySnapshot
        {
            CpuUsagePercent = cpuUsage,
            TotalMemoryMb = totalPhysMb,
            AvailableMemoryMb = availPhysMb,
            MemoryUsagePercent = memoryLoadPct,
            Disks = drives,
            Networks = netList,
            GpuName = gpuName,
            GpuVramMb = gpuVram,
            CpuCores = Environment.ProcessorCount,
            UptimeSeconds = Environment.TickCount64 / 1000L,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
        };
    }

    private static int GetCpuUsagePercent()
    {
        try
        {
            if (GetSystemTimes(out var idleTime, out var kernelTime, out var userTime))
            {
                if (_lastTimesCheck != DateTime.MinValue)
                {
                    ulong usr = userTime.Value - _lastUser;
                    ulong ker = kernelTime.Value - _lastKernel;
                    ulong idl = idleTime.Value - _lastIdle;

                    ulong sys = ker + usr;
                    if (sys > 0)
                    {
                        ulong cpu = (sys - idl) * 100 / sys;
                        _cachedCpuUsage = Math.Clamp((int)cpu, 0, 100);
                    }
                }

                _lastIdle = idleTime.Value;
                _lastKernel = kernelTime.Value;
                _lastUser = userTime.Value;
                _lastTimesCheck = DateTime.UtcNow;
            }
        }
        catch { }
        return _cachedCpuUsage;
    }

    public BatteryHealthInfo GetBatteryHealth()
    {
        var info = new BatteryHealthInfo();
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\WMI", "SELECT * FROM BatteryStaticData");
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    info.DesignedCapacityMwh = Convert.ToDouble(obj["DesignedCapacity"] ?? 0);
                }
                break;
            }

            using var fullSearcher = new ManagementObjectSearcher(@"root\WMI", "SELECT * FROM BatteryFullChargedCapacity");
            foreach (ManagementObject obj in fullSearcher.Get())
            {
                using (obj)
                {
                    info.FullChargeCapacityMwh = Convert.ToDouble(obj["FullChargedCapacity"] ?? 0);
                }
                break;
            }

            using var cycleSearcher = new ManagementObjectSearcher(@"root\WMI", "SELECT * FROM BatteryCycleCount");
            foreach (ManagementObject obj in cycleSearcher.Get())
            {
                using (obj)
                {
                    info.CycleCount = Convert.ToInt32(obj["CycleCount"] ?? 0);
                }
                break;
            }

            if (info.DesignedCapacityMwh > 0 && info.FullChargeCapacityMwh > 0)
            {
                info.WearLevelPercent = Math.Clamp((int)Math.Round((1.0 - (info.FullChargeCapacityMwh / info.DesignedCapacityMwh)) * 100.0), 0, 100);
            }
        }
        catch { }

        return info;
    }

    public HardwareSpecsInfo GetHardwareSpecs()
    {
        var info = new HardwareSpecsInfo
        {
            CoreCount = Environment.ProcessorCount,
            OsDescription = RuntimeInformation.OSDescription,
            UptimeSeconds = Environment.TickCount64 / 1000L
        };

        var memStatus = new MEMORYSTATUSEX();
        if (GlobalMemoryStatusEx(memStatus))
        {
            info.TotalMemoryMb = memStatus.ullTotalPhys / (1024 * 1024);
        }

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor ");
            info.ProcessorName = key?.GetValue("ProcessorNameString")?.ToString()?.Trim() ?? "Unknown Processor";
        }
        catch
        {
            info.ProcessorName = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "x64 Processor";
        }

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            info.SystemManufacturer = key?.GetValue("SystemManufacturer")?.ToString()?.Trim() ?? "";
            info.SystemModel = key?.GetValue("SystemProductName")?.ToString()?.Trim() ?? "";
            info.BiosVersion = key?.GetValue("BIOSVersion")?.ToString()?.Trim() ?? "";
        }
        catch { }

        var (gpu, vram) = GetGpuInfo();
        info.GpuName = gpu;
        info.GpuVramMb = vram;

        return info;
    }

    public BatteryReportDetails GenerateBatteryReport()
    {
        var report = new BatteryReportDetails();
        string tempXml = Path.Combine(Path.GetTempPath(), $"tether-battery-report-{Guid.NewGuid():N}.xml");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powercfg.exe",
                Arguments = $"/batteryreport /xml /output \"{tempXml}\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(10000);

            if (File.Exists(tempXml))
            {
                var doc = new System.Xml.XmlDocument();
                doc.Load(tempXml);

                var batteryNode = doc.SelectSingleNode("//Batteries/Battery");
                if (batteryNode != null)
                {
                    report.BatteryName = batteryNode.SelectSingleNode("Id")?.InnerText?.Trim() ?? "Main Battery";
                    report.Manufacturer = batteryNode.SelectSingleNode("Manufacturer")?.InnerText?.Trim() ?? "";
                    report.SerialNumber = batteryNode.SelectSingleNode("SerialNumber")?.InnerText?.Trim() ?? "";
                    report.Chemistry = batteryNode.SelectSingleNode("Chemistry")?.InnerText?.Trim() ?? "LIon";

                    double.TryParse(batteryNode.SelectSingleNode("DesignCapacity")?.InnerText, out double design);
                    double.TryParse(batteryNode.SelectSingleNode("FullChargeCapacity")?.InnerText, out double full);
                    int.TryParse(batteryNode.SelectSingleNode("CycleCount")?.InnerText, out int cycles);

                    report.DesignCapacityMwh = design;
                    report.FullChargeCapacityMwh = full;
                    report.CycleCount = cycles;

                    if (design > 0 && full > 0)
                    {
                        report.HealthPercent = Math.Clamp((int)Math.Round((full / design) * 100.0), 0, 100);
                    }
                    else
                    {
                        report.HealthPercent = 100;
                    }

                    report.ReportTimestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
                    report.Success = true;
                }
            }
        }
        catch (Exception ex)
        {
            report.ErrorMessage = ex.Message;
        }
        finally
        {
            try { if (File.Exists(tempXml)) File.Delete(tempXml); } catch { }
        }

        if (!report.Success)
        {
            var health = GetBatteryHealth();
            report.DesignCapacityMwh = health.DesignedCapacityMwh;
            report.FullChargeCapacityMwh = health.FullChargeCapacityMwh;
            report.CycleCount = health.CycleCount;
            report.HealthPercent = health.DesignedCapacityMwh > 0
                ? Math.Clamp((int)Math.Round((health.FullChargeCapacityMwh / health.DesignedCapacityMwh) * 100.0), 0, 100)
                : 100;
            report.BatteryName = "Primary Battery";
            report.Chemistry = "Lithium";
            report.ReportTimestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
            report.Success = report.DesignCapacityMwh > 0;
        }

        return report;
    }

    public List<PowerPlanInfo> GetPowerPlans()
    {
        var list = new List<PowerPlanInfo>();
        IntPtr activeGuidPtr = IntPtr.Zero;
        Guid activeGuid = Guid.Empty;

        if (PowerGetActiveScheme(IntPtr.Zero, out activeGuidPtr) == 0 && activeGuidPtr != IntPtr.Zero)
        {
            try { activeGuid = Marshal.PtrToStructure<Guid>(activeGuidPtr); }
            finally { LocalFree(activeGuidPtr); }
        }

        uint index = 0;
        uint bufferSize = 16;
        IntPtr guidBuffer = Marshal.AllocHGlobal(16);

        try
        {
            while (PowerEnumerate(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 16 /* ACCESS_SCHEME */, index, guidBuffer, ref bufferSize) == 0)
            {
                var schemeGuid = Marshal.PtrToStructure<Guid>(guidBuffer);
                string name = GetPowerPlanName(schemeGuid);

                list.Add(new PowerPlanInfo
                {
                    Guid = schemeGuid.ToString(),
                    Name = string.IsNullOrEmpty(name) ? "Power Plan " + (index + 1) : name,
                    IsActive = schemeGuid == activeGuid
                });

                index++;
                bufferSize = 16;
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(guidBuffer);
        }

        // Fallback for Session 0 (SYSTEM) where PowerEnumerate may return no plans
        if (list.Count == 0)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powercfg.exe",
                    Arguments = "/list",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p != null)
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(3000);
                    var matches = System.Text.RegularExpressions.Regex.Matches(
                        output,
                        @"(?:Power Scheme\s+)?GUID:\s+([a-fA-F0-9\-]+)\s+\(([^)]+)\)(\s+\*)?",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

                    foreach (System.Text.RegularExpressions.Match m in matches)
                    {
                        list.Add(new PowerPlanInfo
                        {
                            Guid = m.Groups[1].Value.Trim(),
                            Name = m.Groups[2].Value.Trim(),
                            IsActive = m.Groups[3].Success
                        });
                    }
                }
            }
            catch { }
        }

        if (list.Count == 0)
        {
            list.Add(new PowerPlanInfo
            {
                Guid = "381b4222-f694-41f0-9685-ff5bb260df2e",
                Name = "Balanced",
                IsActive = true
            });
            list.Add(new PowerPlanInfo
            {
                Guid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
                Name = "High Performance",
                IsActive = false
            });
            list.Add(new PowerPlanInfo
            {
                Guid = "a1841308-3541-4fab-bc81-f71556f20b4a",
                Name = "Power Saver",
                IsActive = false
            });
        }

        return list;
    }

    public bool SetActivePowerPlan(string guidString)
    {
        if (Guid.TryParse(guidString, out var guid))
        {
            if (PowerSetActiveScheme(IntPtr.Zero, ref guid) == 0) return true;

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powercfg.exe",
                    Arguments = $"/setactive {guidString}",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(3000);
                return p?.ExitCode == 0;
            }
            catch { }
        }
        return false;
    }

    private static string GetPowerPlanName(Guid schemeGuid)
    {
        uint nameSize = 0;
        PowerReadFriendlyName(IntPtr.Zero, ref schemeGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref nameSize);
        if (nameSize == 0) return "";

        IntPtr nameBuf = Marshal.AllocHGlobal((int)nameSize);
        try
        {
            if (PowerReadFriendlyName(IntPtr.Zero, ref schemeGuid, IntPtr.Zero, IntPtr.Zero, nameBuf, ref nameSize) == 0)
            {
                return Marshal.PtrToStringUni(nameBuf) ?? "";
            }
            return "";
        }
        finally
        {
            Marshal.FreeHGlobal(nameBuf);
        }
    }

    public List<PrinterDeviceDetails> GetPrinters()
    {
        var list = new List<PrinterDeviceDetails>();
        int flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
        EnumPrinters(flags, null, 2, IntPtr.Zero, 0, out int needed, out int count);
        if (needed <= 0) return list;

        IntPtr pBuf = Marshal.AllocHGlobal(needed);
        try
        {
            if (EnumPrinters(flags, null, 2, pBuf, needed, out _, out count))
            {
                int structSize = Marshal.SizeOf(typeof(PRINTER_INFO_2));
                for (int i = 0; i < count; i++)
                {
                    var info = Marshal.PtrToStructure<PRINTER_INFO_2>(pBuf + (i * structSize));
                    list.Add(new PrinterDeviceDetails
                    {
                        Name = info.pPrinterName ?? "",
                        PortName = info.pPortName ?? "",
                        Status = info.Status switch
                        {
                            0 => "Ready",
                            0x00000001 => "Paused",
                            0x00000002 => "Error",
                            0x00000004 => "Pending Deletion",
                            0x00000008 => "Paper Jam",
                            0x00000010 => "Paper Out",
                            0x00000080 => "Offline",
                            0x00000100 => "Busy",
                            0x00000400 => "Printing",
                            _ => "Active"
                        },
                        JobsCount = (int)info.cJobs
                    });
                }
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(pBuf);
        }

        return list;
    }

    public List<UsbDeviceInfo> GetUsbDevices()
    {
        var list = new List<UsbDeviceInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\CIMV2", "SELECT DeviceID, Name, Description, Status FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'");
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    string name = Convert.ToString(obj["Name"]) ?? "";
                    string devId = Convert.ToString(obj["DeviceID"]) ?? "";
                    string status = Convert.ToString(obj["Status"]) ?? "OK";
                    if (string.IsNullOrEmpty(name)) continue;

                    // Filter out internal root hubs, generic hubs, composite devices, virtual router PDOs
                    if (devId.StartsWith(@"USB\ROOT_HUB", StringComparison.OrdinalIgnoreCase) ||
                        devId.StartsWith(@"USB4\ROOT_", StringComparison.OrdinalIgnoreCase) ||
                        devId.Contains("VIRTUAL_POWER", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Root Hub", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Generic USB Hub", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Composite Device", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Root Router", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Host Controller", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    list.Add(new UsbDeviceInfo
                    {
                        DeviceId = devId,
                        Name = name,
                        Status = status
                    });
                }
            }
        }
        catch { }
        return list;
    }

    public List<WindowsServiceDetails> GetServices(string? search = null)
    {
        var list = new List<WindowsServiceDetails>();
        try
        {
            foreach (var sc in ServiceController.GetServices())
            {
                try
                {
                    if (!string.IsNullOrEmpty(search) &&
                        !sc.ServiceName.Contains(search, StringComparison.OrdinalIgnoreCase) &&
                        !sc.DisplayName.Contains(search, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    bool canStop = false;
                    bool canPause = false;
                    try { canStop = sc.CanStop; } catch { }
                    try { canPause = sc.CanPauseAndContinue; } catch { }

                    list.Add(new WindowsServiceDetails
                    {
                        ServiceName = sc.ServiceName,
                        DisplayName = sc.DisplayName,
                        Status = sc.Status.ToString(),
                        CanStop = canStop,
                        CanPauseAndContinue = canPause
                    });
                }
                catch { }
            }
        }
        catch { }
        return list.OrderBy(s => s.DisplayName).ToList();
    }

    public bool ControlService(string serviceName, string action)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            switch (action.ToLowerInvariant())
            {
                case "start":
                    if (sc.Status == ServiceControllerStatus.Stopped)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(5));
                        return true;
                    }
                    break;
                case "stop":
                    if (sc.CanStop)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                        return true;
                    }
                    break;
                case "restart":
                    if (sc.CanStop)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(5));
                        return true;
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"WindowsAdminManager: ControlService failed for {serviceName} ({action}): {ex.Message}");
        }
        return false;
    }

    public WindowsUpdateInfo CheckWindowsUpdates()
    {
        lock (_updateLock)
        {
            if (_cachedUpdateInfo != null && (DateTime.UtcNow - _lastUpdateCheck).TotalMinutes < 5)
            {
                return _cachedUpdateInfo;
            }
        }

        var info = new WindowsUpdateInfo();
        try
        {
            Type? sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
            if (sessionType != null)
            {
                dynamic? updateSession = Activator.CreateInstance(sessionType);
                if (updateSession != null)
                {
                    dynamic searcher = updateSession.CreateUpdateSearcher();
                    dynamic searchResult = searcher.Search("IsInstalled=0 and IsHidden=0");
                    dynamic updates = searchResult.Updates;
                    int count = updates.Count;
                    info.PendingUpdatesCount = count;
                    info.IsUpdateAvailable = count > 0;

                    for (int i = 0; i < Math.Min(count, 15); i++)
                    {
                        dynamic update = updates.Item(i);
                        info.Titles.Add((string)update.Title);
                    }
                }
            }
        }
        catch
        {
            info.StatusMessage = "Windows Update COM query completed or unavailable.";
        }

        lock (_updateLock)
        {
            _cachedUpdateInfo = info;
            _lastUpdateCheck = DateTime.UtcNow;
        }

        return info;
    }
}

public sealed class SystemTelemetrySnapshot
{
    public int CpuUsagePercent { get; set; }
    public int CpuUsage => CpuUsagePercent;
    public ulong TotalMemoryMb { get; set; }
    public ulong TotalRamMb => TotalMemoryMb;
    public ulong AvailableMemoryMb { get; set; }
    public ulong AvailRamMb => AvailableMemoryMb;
    public int MemoryUsagePercent { get; set; }
    public int RamUsagePct => MemoryUsagePercent;
    public List<DiskUsageInfo> Disks { get; set; } = new();
    public List<NetworkInterfaceInfo> Networks { get; set; } = new();
    public string GpuName { get; set; } = string.Empty;
    public ulong GpuVramMb { get; set; }
    public int CpuCores { get; set; }
    public long UptimeSeconds { get; set; }
    public long Timestamp { get; set; }
}

public sealed class HardwareSpecsInfo
{
    public string ProcessorName { get; set; } = string.Empty;
    public int CoreCount { get; set; }
    public ulong TotalMemoryMb { get; set; }
    public string GpuName { get; set; } = string.Empty;
    public ulong GpuVramMb { get; set; }
    public string SystemManufacturer { get; set; } = string.Empty;
    public string SystemModel { get; set; } = string.Empty;
    public string BiosVersion { get; set; } = string.Empty;
    public string OsDescription { get; set; } = string.Empty;
    public long UptimeSeconds { get; set; }
}

public sealed class BatteryReportDetails
{
    public bool Success { get; set; }
    public string BatteryName { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Chemistry { get; set; } = string.Empty;
    public double DesignCapacityMwh { get; set; }
    public double FullChargeCapacityMwh { get; set; }
    public int CycleCount { get; set; }
    public int HealthPercent { get; set; }
    public string ReportTimestamp { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
}

public sealed class DiskUsageInfo
{
    public string Name { get; set; } = string.Empty;
    public string VolumeLabel { get; set; } = string.Empty;
    public double TotalGigabytes { get; set; }
    public double FreeGigabytes { get; set; }
    public string Format { get; set; } = string.Empty;
}

public sealed class NetworkInterfaceInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public long BytesReceived { get; set; }
    public long BytesSent { get; set; }
    public long SpeedMbps { get; set; }
}

public sealed class BatteryHealthInfo
{
    public double DesignedCapacityMwh { get; set; }
    public double DesignCapacityMwh => DesignedCapacityMwh;
    public double FullChargeCapacityMwh { get; set; }
    public int WearLevelPercent { get; set; }
    public int WearLevelPct => WearLevelPercent;
    public int CycleCount { get; set; }
}

public sealed class PowerPlanInfo
{
    public string Guid { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public bool IsActive { get; set; }
}

public sealed class PrinterDeviceDetails
{
    public string Name { get; set; } = string.Empty;
    public string PortName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public int JobsCount { get; set; }
}

public sealed class UsbDeviceInfo
{
    public string DeviceId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
}

public sealed class WindowsServiceDetails
{
    public string ServiceName { get; set; } = string.Empty;
    public string Name => ServiceName;
    public string DisplayName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public bool CanStop { get; set; }
    public bool CanPauseAndContinue { get; set; }
}

public sealed class WindowsUpdateInfo
{
    public int PendingUpdatesCount { get; set; }
    public int PendingCount => PendingUpdatesCount;
    public bool IsUpdateAvailable { get; set; }
    public bool IsAvailable => IsUpdateAvailable;
    public List<string> Titles { get; set; } = new();
    public string StatusMessage { get; set; } = "OK";
}
