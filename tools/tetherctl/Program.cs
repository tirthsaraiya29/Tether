using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Capabilities;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Security;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Logging;

namespace Tether.Cli;

public static class Program
{
    private sealed class ConsoleLogger : ITetherLogger
    {
        public void Debug(string message) { }
        public void Info(string message) => Console.WriteLine(message);
        public void Warning(string message) => Console.Error.WriteLine($"[WARN] {message}");
        public void Error(string message) => Console.Error.WriteLine($"[ERROR] {message}");
        public void Error(string message, Exception? ex) => Console.Error.WriteLine($"[ERROR] {message} {ex?.Message}");
    }

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            PrintUsage();
            return 0;
        }

        string cmd = args[0].ToLowerInvariant();
        var logger = new ConsoleLogger();
        var config = LinuxDaemonConfig.Load();

        try
        {
            switch (cmd)
            {
                case "status":
                    return await HandleStatusAsync(config, logger);

                case "devices":
                    return HandleDevices(config, logger);

                case "pairing" or "pair":
                    return HandlePairing(config, logger);

                case "unpair":
                    if (args.Length < 2)
                    {
                        Console.Error.WriteLine("Error: Device ID or fingerprint is required. Example: tetherctl unpair <deviceId>");
                        return 1;
                    }
                    return HandleUnpair(args[1], config, logger);

                case "lock":
                    return HandleLock(logger);

                case "unlock":
                    return HandleUnlock(config, logger);

                case "restart":
                    return HandleRestart(config);

                case "greeter" or "tile":
                    return HandleGreeter(args.Skip(1).ToArray());

                case "recover" or "recovery":
                    return HandleRecovery(args.Skip(1).ToArray(), config, logger);

                case "pam-status":
                    return HandlePamStatus(logger);

                case "pam-restore":
                    return HandlePamRestore(logger);

                case "logs":
                    return HandleLogs(args.Skip(1).ToArray());

                case "version" or "--version" or "-v":
                    Console.WriteLine("Tether Linux CLI (tetherctl) v2.0-production");
                    return 0;

                default:
                    Console.Error.WriteLine($"Unknown command '{cmd}'. Run 'tetherctl help' for available commands.");
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error executing command: {ex.Message}");
            return 1;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"Tether Linux Command-Line Utility (tetherctl)
Usage: tetherctl <command> [arguments]

Commands:
  status        Display daemon status, session info, and hardware metrics
  devices       List all paired Android companion devices
  unpair <id>   Unpair and revoke a trusted device by Device ID or Fingerprint
  pairing       Show pairing instructions and local discovery network endpoints
  lock          Immediately lock the current graphical desktop session
  unlock        Arm a one-time workstation unlock grant for PAM
  greeter       Launch the graphical or CLI Tether Login & Greeter tile
  restart       Restart the background Tether systemd daemon
  recover       Check PAM configuration health or restore pristine PAM files
  logs [-f]     Show recent daemon logs from systemd journal
  version       Show version information");
    }

    private static async Task<int> HandleStatusAsync(LinuxDaemonConfig config, ITetherLogger logger)
    {
        Console.WriteLine("=== Tether Linux Host Status ===");
        var session = PlatformDetection.GetActiveSessionInfo();
        Console.WriteLine($"Distribution:      {PlatformDetection.GetDistributionName()}");
        Console.WriteLine($"Display Server:    {session.DisplayServer}");
        Console.WriteLine($"Desktop Env:       {session.DesktopEnvironment}");
        Console.WriteLine($"Active Session:    User={session.UserName} (Id={session.SessionId}, Uid={session.Uid})");

        // Systemd status
        bool isServiceRunning = false;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "systemctl",
                Arguments = "is-active tether",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                string outStr = p.StandardOutput.ReadToEnd().Trim();
                p.WaitForExit(1000);
                isServiceRunning = outStr == "active";
            }
        }
        catch { }

        Console.WriteLine($"Daemon Service:    {(isServiceRunning ? "ACTIVE (Running)" : "INACTIVE (Stopped)")}");
        Console.WriteLine($"PAM Auth Socket:   {(File.Exists(config.PamSocketPath) ? "ONLINE" : "OFFLINE")}");

        // Live status query over daemon IPC
        if (File.Exists(config.PamSocketPath))
        {
            try
            {
                using var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                sock.Connect(new UnixDomainSocketEndPoint(config.PamSocketPath));
                var req = new { action = "STATUS_REQUEST" };
                byte[] reqBytes = JsonSerializer.SerializeToUtf8Bytes(req);
                byte[] lenBytes = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(lenBytes, reqBytes.Length);
                sock.Send(lenBytes);
                sock.Send(reqBytes);

                byte[] respLenBytes = new byte[4];
                int r1 = sock.Receive(respLenBytes);
                if (r1 == 4)
                {
                    int rLen = BinaryPrimitives.ReadInt32BigEndian(respLenBytes);
                    byte[] rBody = new byte[rLen];
                    int r2 = sock.Receive(rBody);
                    using var doc = JsonDocument.Parse(rBody.AsMemory(0, r2));
                    bool phoneConnected = doc.RootElement.TryGetProperty("phoneConnected", out var pProp) && pProp.GetBoolean();
                    string devName = doc.RootElement.TryGetProperty("connectedDeviceName", out var dProp) ? (dProp.GetString() ?? "") : "";
                    bool grantActive = doc.RootElement.TryGetProperty("grantActive", out var gProp) && gProp.GetBoolean();

                    Console.WriteLine($"Phone Connection:  {(phoneConnected ? ($"CONNECTED ({devName})") : "DISCONNECTED")}");
                    Console.WriteLine($"Mobile Unlock:     {(grantActive ? "ARMED (Grant Active)" : (phoneConnected ? "READY" : "STANDBY"))}");
                }
            }
            catch { }
        }

        // Admin telemetry
        var adminMgr = new LinuxAdminManager(logger);
        var telem = adminMgr.GetSystemTelemetry();
        Console.WriteLine($"CPU Usage:         {telem.CpuUsage}%");
        Console.WriteLine($"Memory Usage:      {telem.UsedRamMb} MB / {telem.TotalRamMb} MB");
        Console.WriteLine($"Disk Free:         {telem.FreeDiskGb} GB / {telem.TotalDiskGb} GB");
        Console.WriteLine($"System Uptime:     {TimeSpan.FromSeconds(telem.UptimeSeconds):d\\d\\ hh\\:mm\\:ss}");

        // Paired devices count
        try
        {
            var trustStore = new LinuxTrustStore(logger, config);
            var devices = trustStore.All();
            Console.WriteLine($"Paired Devices:    {devices.Count}");
        }
        catch { }

        return 0;
    }

    private static int HandleDevices(LinuxDaemonConfig config, ITetherLogger logger)
    {
        var trustStore = new LinuxTrustStore(logger, config);
        var devices = trustStore.All();

        Console.WriteLine($"=== Paired Android Devices ({devices.Count}) ===");
        if (devices.Count == 0)
        {
            Console.WriteLine("No Android devices are currently paired.");
            return 0;
        }

        foreach (var dev in devices)
        {
            Console.WriteLine($"- Name:        {dev.DisplayName}");
            Console.WriteLine($"  Device ID:   {dev.DeviceId}");
            Console.WriteLine($"  Fingerprint: {dev.Fingerprint}");
            Console.WriteLine($"  Paired At:   {dev.PairedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine();
        }

        return 0;
    }

    private static int HandlePairing(LinuxDaemonConfig config, ITetherLogger logger)
    {
        Console.WriteLine("=== Tether Linux Pairing Guide ===");
        Console.WriteLine("1. Ensure your Android phone and Linux machine are on the same local network or hotspot.");
        Console.WriteLine("2. Open the Tether Android app and tap 'INITIATE PAIRING' or enter the host IP.");
        Console.WriteLine("3. When prompted on your phone, enter the 6-digit PIN displayed on the daemon console screen or in desktop notification.");
        Console.WriteLine();
        Console.WriteLine("=== Active Discovery Network Endpoints ===");
        var targets = Tether.LinuxDaemon.Discovery.LinuxUdpDiscovery.GetDiscoveryTargetEndPoints(Tether.LinuxDaemon.Discovery.LinuxUdpDiscovery.UdpPort);
        foreach (var t in targets)
        {
            Console.WriteLine($"  - Directed Broadcast: {t.Address}:{t.Port}");
        }
        Console.WriteLine($"  Control Port: {config.ControlPort} (TLS 1.3)");
        Console.WriteLine();
        return 0;
    }

    private static int HandleUnpair(string target, LinuxDaemonConfig config, ITetherLogger logger)
    {
        var trustStore = new LinuxTrustStore(logger, config);
        var devices = trustStore.All();

        var match = devices.FirstOrDefault(d => string.Equals(d.DeviceId, target, StringComparison.OrdinalIgnoreCase) ||
                                                string.Equals(d.Fingerprint, target, StringComparison.OrdinalIgnoreCase));
        if (match == null)
        {
            Console.Error.WriteLine($"Error: No paired device found matching '{target}'.");
            return 1;
        }

        bool removed = trustStore.Remove(match.Fingerprint);
        if (removed)
        {
            Console.WriteLine($"Successfully removed and revoked device '{match.DisplayName}' ({match.Fingerprint}).");
            return 0;
        }

        Console.Error.WriteLine($"Error: Failed to remove device '{match.Fingerprint}'.");
        return 1;
    }

    private static int HandleLock(ITetherLogger logger)
    {
        Console.WriteLine("Locking graphical session...");
        bool locked = LinuxHardwareExecutor.LockSession(logger);
        if (locked)
        {
            Console.WriteLine("Workstation session locked.");
            return 0;
        }

        Console.Error.WriteLine("Failed to lock session via loginctl.");
        return 1;
    }

    private static int HandleUnlock(LinuxDaemonConfig config, ITetherLogger logger)
    {
        var session = PlatformDetection.GetActiveSessionInfo();
        if (string.IsNullOrEmpty(session.UserName))
        {
            Console.Error.WriteLine("Error: Unable to identify active user session.");
            return 1;
        }

        if (!File.Exists(config.PamSocketPath))
        {
            Console.Error.WriteLine($"Error: PAM auth socket '{config.PamSocketPath}' is not active. Is tether.service running?");
            return 1;
        }

        try
        {
            using var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            sock.Connect(new UnixDomainSocketEndPoint(config.PamSocketPath));

            var req = new
            {
                action = "REQUEST_PHONE_AUTH",
                user = session.UserName
            };
            byte[] reqBytes = JsonSerializer.SerializeToUtf8Bytes(req);
            byte[] packet = new byte[4 + reqBytes.Length];
            BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(0, 4), reqBytes.Length);
            reqBytes.CopyTo(packet.AsSpan(4));
            sock.Send(packet);

            byte[] lenBytes = new byte[4];
            int read = sock.Receive(lenBytes);
            if (read == 4)
            {
                int respLen = BinaryPrimitives.ReadInt32BigEndian(lenBytes);
                if (respLen > 0 && respLen <= 4096)
                {
                    byte[] respBuf = new byte[respLen];
                    int total = 0;
                    while (total < respLen)
                    {
                        int n = sock.Receive(respBuf, total, respLen - total, SocketFlags.None);
                        if (n <= 0) break;
                        total += n;
                    }

                    using var doc = JsonDocument.Parse(respBuf.AsMemory(0, total));
                    string status = doc.RootElement.TryGetProperty("status", out var sProp) ? (sProp.GetString() ?? "") : "";
                    string message = doc.RootElement.TryGetProperty("message", out var mProp) ? (mProp.GetString() ?? "") : "";
                    string reason = doc.RootElement.TryGetProperty("reason", out var rProp) ? (rProp.GetString() ?? "") : "";

                    if (status == "PROMPTED")
                    {
                        Console.WriteLine($"Unlock authorization request dispatched to connected phone for user '{session.UserName}'.");
                        Console.WriteLine("Please approve the unlock request on your phone.");
                        return 0;
                    }
                    else if (status == "PHONE_DISCONNECTED")
                    {
                        Console.Error.WriteLine("Error: No paired phone is currently connected to authenticate the unlock request.");
                        return 1;
                    }
                    else
                    {
                        Console.Error.WriteLine($"Error: Unlock request rejected: {(!string.IsNullOrEmpty(reason) ? reason : message)}");
                        return 1;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error communicating with PAM auth socket: {ex.Message}");
            return 1;
        }

        Console.Error.WriteLine("Failed to request phone unlock authorization.");
        return 1;
    }

    private static int HandleRestart(LinuxDaemonConfig config)
    {
        Console.WriteLine("Requesting tether.service restart...");
        if (File.Exists(config.PamSocketPath))
        {
            try
            {
                using var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                sock.Connect(new UnixDomainSocketEndPoint(config.PamSocketPath));
                var req = new { action = "RESTART_REQUEST" };
                byte[] reqBytes = JsonSerializer.SerializeToUtf8Bytes(req);
                byte[] lenBytes = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(lenBytes, reqBytes.Length);
                sock.Send(lenBytes);
                sock.Send(reqBytes);

                byte[] respLenBytes = new byte[4];
                int r1 = sock.Receive(respLenBytes);
                if (r1 == 4)
                {
                    int rLen = BinaryPrimitives.ReadInt32BigEndian(respLenBytes);
                    byte[] rBody = new byte[rLen];
                    int r2 = sock.Receive(rBody);
                    using var doc = JsonDocument.Parse(rBody.AsMemory(0, r2));
                    string status = doc.RootElement.TryGetProperty("status", out var sProp) ? (sProp.GetString() ?? "") : "";
                    if (status == "RESTARTING")
                    {
                        Console.WriteLine("Tether background daemon restart signal accepted via secure IPC.");
                        return 0;
                    }
                }
            }
            catch { }
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "systemctl",
                Arguments = "restart tether.service",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(5000);
            if (p != null && p.ExitCode == 0)
            {
                Console.WriteLine("Tether Linux Daemon successfully restarted.");
                return 0;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to restart service: {ex.Message}");
        }
        return 1;
    }

    private static int HandleGreeter(string[] args)
    {
        string greeterPath = "/usr/local/bin/tether-greeter";
        if (!File.Exists(greeterPath))
        {
            // Relative fallback in repo
            greeterPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../tools/tether-greeter/tether-greeter"));
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = File.Exists(greeterPath) ? greeterPath : "python3",
                UseShellExecute = false
            };
            bool isExecutable = OperatingSystem.IsLinux() && File.GetUnixFileMode(greeterPath).HasFlag(UnixFileMode.UserExecute);
            if (!File.Exists(greeterPath) || !isExecutable)
            {
                psi.ArgumentList.Add("tools/tether-greeter/tether-greeter");
            }
            foreach (var arg in args)
            {
                psi.ArgumentList.Add(arg);
            }
            using var p = Process.Start(psi);
            p?.WaitForExit();
            return p?.ExitCode ?? 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error launching greeter tile: {ex.Message}");
            return 1;
        }
    }

    private static int HandleLogs(string[] args)
    {
        string arguments = "-u tether.service -n 50 --no-pager";
        if (args.Contains("-f") || args.Contains("--follow"))
        {
            arguments = "-u tether.service -f";
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "journalctl",
                Arguments = arguments,
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            return p?.ExitCode ?? 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error reading logs: {ex.Message}");
            return 1;
        }
    }

    private static int HandleRecovery(string[] args, LinuxDaemonConfig config, ITetherLogger logger)
    {
        if (args.Length > 0 && args[0] is "--restore-pam" or "restore" or "restore-pam")
        {
            return HandlePamRestore(logger);
        }

        return HandlePamStatus(logger);
    }

    private static int HandlePamStatus(ITetherLogger logger)
    {
        Console.WriteLine("=== Tether PAM & Authentication Health Check ===");

        // 1. Check pam_tether.so
        string[] searchPaths = new[]
        {
            "/usr/lib64/security/pam_tether.so",
            "/lib/x86_64-linux-gnu/security/pam_tether.so",
            "/usr/lib/security/pam_tether.so"
        };
        string? foundSo = searchPaths.FirstOrDefault(File.Exists);
        if (foundSo != null)
        {
            Console.WriteLine($"[OK] Native PAM module found: {foundSo}");
        }
        else
        {
            Console.WriteLine("[WARN] Native pam_tether.so shared library not found in standard security paths!");
        }

        // 2. Check PAM configs
        string[] pamConfigs = new[]
        {
            "/etc/pam.d/gdm-password",
            "/etc/pam.d/sddm",
            "/etc/pam.d/lightdm"
        };

        foreach (var file in pamConfigs)
        {
            if (File.Exists(file))
            {
                bool hasTether = false;
                try
                {
                    hasTether = File.ReadAllLines(file).Any(l => l.Contains("pam_tether.so"));
                }
                catch { }

                bool hasBackup = File.Exists(file + ".tether-orig");
                Console.WriteLine($"[INFO] {file}: Configured={hasTether}, Pristine Backup Present={hasBackup}");
            }
        }

        // 3. Check auth socket
        string sockPath = "/run/tether/auth.sock";
        if (File.Exists(sockPath))
        {
            Console.WriteLine($"[OK] PAM auth socket present: {sockPath}");
        }
        else
        {
            Console.WriteLine($"[INFO] PAM auth socket '{sockPath}' not active (starts when daemon is running).");
        }

        Console.WriteLine("\nTo restore pristine PAM configs: sudo tetherctl recover --restore-pam");
        return 0;
    }

    private static int HandlePamRestore(ITetherLogger logger)
    {
        if (OperatingSystem.IsLinux() && geteuid() != 0)
        {
            Console.Error.WriteLine("Error: Restoring PAM configuration requires root privileges. Please run: sudo tetherctl recover --restore-pam");
            return 1;
        }

        Console.WriteLine("=== Restoring Pristine PAM Configurations ===");

        string[] pamConfigs = new[]
        {
            "/etc/pam.d/gdm-password",
            "/etc/pam.d/sddm",
            "/etc/pam.d/lightdm"
        };

        int restoredCount = 0;
        foreach (var file in pamConfigs)
        {
            string backup = file + ".tether-orig";
            if (File.Exists(backup))
            {
                try
                {
                    File.Copy(backup, file, overwrite: true);
                    File.Delete(backup);
                    Console.WriteLine($"[OK] Restored pristine backup: {backup} -> {file}");
                    restoredCount++;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[ERROR] Failed to restore {file}: {ex.Message}");
                }
            }
            else if (File.Exists(file))
            {
                try
                {
                    var lines = File.ReadAllLines(file).Where(l => !l.Contains("pam_tether.so")).ToArray();
                    File.WriteAllLines(file, lines);
                    Console.WriteLine($"[OK] Stripped pam_tether.so entries from: {file}");
                    restoredCount++;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[ERROR] Failed to clean {file}: {ex.Message}");
                }
            }
        }

        Console.WriteLine($"PAM restoration complete. ({restoredCount} file(s) processed)");
        return 0;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern uint geteuid();
}
