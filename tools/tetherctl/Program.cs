using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
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
                    return HandleRestart();

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
  lock          Immediately lock the current graphical desktop session
  unlock        Arm a one-time workstation unlock grant for PAM
  restart       Restart the background Tether systemd daemon
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
                type = "ARM_GRANT",
                username = session.UserName,
                deviceId = "cli-local",
                validitySeconds = 30
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
                    bool ok = doc.RootElement.TryGetProperty("success", out var sProp) && sProp.GetBoolean();
                    if (ok)
                    {
                        Console.WriteLine($"Workstation unlock grant successfully armed for user '{session.UserName}' (valid for 30s).");
                        return 0;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error communicating with PAM auth socket: {ex.Message}");
            return 1;
        }

        Console.Error.WriteLine("Failed to arm unlock grant.");
        return 1;
    }

    private static int HandleRestart()
    {
        Console.WriteLine("Restarting tether.service...");
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
}
