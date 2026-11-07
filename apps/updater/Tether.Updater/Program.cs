using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Microsoft.Win32;

namespace Tether.Updater
{
    public class ManifestFileEntry
    {
        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;

        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = string.Empty;

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("isService")]
        public bool IsService { get; set; }

        [JsonPropertyName("isCredProv")]
        public bool IsCredProv { get; set; }
    }

    public class UpdateManifest
    {
        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        [JsonPropertyName("publishedAt")]
        public string PublishedAt { get; set; } = string.Empty;

        [JsonPropertyName("files")]
        public List<ManifestFileEntry> Files { get; set; } = new();
    }

    internal class Program
    {
        private const string ServiceName = "TetherCommService";

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);
        private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

        static int Main(string[] args)
        {
            string stagingDir = string.Empty;
            string targetDir = string.Empty;
            string manifestPath = string.Empty;
            bool restartUi = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--staging" && i + 1 < args.Length) stagingDir = args[++i];
                else if (args[i] == "--target" && i + 1 < args.Length) targetDir = args[++i];
                else if (args[i] == "--manifest" && i + 1 < args.Length) manifestPath = args[++i];
                else if (args[i] == "--restart-ui") restartUi = true;
            }

            if (string.IsNullOrEmpty(targetDir))
            {
                targetDir = AppDomain.CurrentDomain.BaseDirectory;
            }

            if (string.IsNullOrEmpty(stagingDir) || !Directory.Exists(stagingDir))
            {
                TraceLog($"Staging directory not found: {stagingDir}");
                return 1;
            }

            TraceLog($"Starting Tether Smart Differential Updater...");
            TraceLog($"Target: {targetDir}");
            TraceLog($"Staging: {stagingDir}");

            // 1. Wait for Tether.DesktopUI to terminate
            WaitForProcessesToExit("Tether.DesktopUI", 10000);

            // 2. Read manifest
            UpdateManifest? manifest = null;
            if (File.Exists(manifestPath))
            {
                try
                {
                    string json = File.ReadAllText(manifestPath);
                    manifest = JsonSerializer.Deserialize<UpdateManifest>(json);
                }
                catch (Exception ex)
                {
                    TraceLog($"Failed to parse manifest: {ex.Message}");
                }
            }

            // 3. Scan and determine strictly modified files
            var filesToUpdate = new List<Tuple<string, string, bool>>(); // <source, dest, isService>
            bool serviceRestartNeeded = false;
            string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);

            if (manifest != null && manifest.Files.Count > 0)
            {
                TraceLog($"Evaluating {manifest.Files.Count} files from manifest...");
                foreach (var entry in manifest.Files)
                {
                    string sourceFile = Path.Combine(stagingDir, entry.Path);
                    if (!File.Exists(sourceFile)) continue;

                    string destFile = entry.IsCredProv 
                        ? Path.Combine(sysDir, Path.GetFileName(entry.Path)) 
                        : Path.Combine(targetDir, entry.Path);

                    bool changed = false;
                    if (!File.Exists(destFile))
                    {
                        changed = true;
                    }
                    else
                    {
                        var destInfo = new FileInfo(destFile);
                        if (destInfo.Length != entry.Size)
                        {
                            changed = true;
                        }
                        else
                        {
                            string localHash = ComputeSha256(destFile);
                            if (!string.Equals(localHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                            {
                                changed = true;
                            }
                        }
                    }

                    if (changed)
                    {
                        TraceLog($"[MODIFIED] {entry.Path}");
                        filesToUpdate.Add(Tuple.Create(sourceFile, destFile, entry.IsService));
                        if (entry.IsService)
                        {
                            serviceRestartNeeded = true;
                        }
                    }
                    else
                    {
                        TraceLog($"[UNCHANGED - SKIPPED] {entry.Path}");
                    }
                }
            }
            else
            {
                // Fallback: compare all files present in staging directory
                TraceLog("No manifest found. Comparing all staging files via SHA-256...");
                var stagedFiles = Directory.GetFiles(stagingDir, "*.*", SearchOption.AllDirectories);
                foreach (var sFile in stagedFiles)
                {
                    string relPath = Path.GetRelativePath(stagingDir, sFile);
                    string dFile = Path.Combine(targetDir, relPath);

                    bool changed = false;
                    if (!File.Exists(dFile))
                    {
                        changed = true;
                    }
                    else
                    {
                        string sHash = ComputeSha256(sFile);
                        string dHash = ComputeSha256(dFile);
                        if (!string.Equals(sHash, dHash, StringComparison.OrdinalIgnoreCase))
                        {
                            changed = true;
                        }
                    }

                    if (changed)
                    {
                        bool isSvc = relPath.Contains("CommunicationService") || relPath.Contains("Tether.Shared");
                        filesToUpdate.Add(Tuple.Create(sFile, dFile, isSvc));
                        if (isSvc) serviceRestartNeeded = true;
                    }
                }
            }

            TraceLog($"Summary: {filesToUpdate.Count} files marked for differential overwrite.");

            // 4. Stop service ONLY if a service binary changed
            bool wasServiceStopped = false;
            if (serviceRestartNeeded)
            {
                wasServiceStopped = StopServiceSafely(ServiceName, 8000);
            }

            // 5. Overwrite strictly modified files
            foreach (var item in filesToUpdate)
            {
                string src = item.Item1;
                string dst = item.Item2;

                try
                {
                    string? dir = Path.GetDirectoryName(dst);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    // Try direct overwrite with retries
                    bool written = false;
                    for (int attempt = 0; attempt < 5; attempt++)
                    {
                        try
                        {
                            File.Copy(src, dst, overwrite: true);
                            written = true;
                            break;
                        }
                        catch (IOException)
                        {
                            // If locked, rename old file to .old
                            try
                            {
                                string oldBackup = dst + $".old_{Guid.NewGuid():N}";
                                if (File.Exists(dst))
                                {
                                    File.Move(dst, oldBackup);
                                    MoveFileEx(oldBackup, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                                }
                                File.Copy(src, dst, overwrite: true);
                                written = true;
                                break;
                            }
                            catch
                            {
                                Thread.Sleep(400);
                            }
                        }
                    }

                    if (written)
                    {
                        TraceLog($"Successfully updated: {Path.GetFileName(dst)}");
                    }
                    else
                    {
                        TraceLog($"WARNING: Could not overwrite {dst}");
                    }
                }
                catch (Exception ex)
                {
                    TraceLog($"Error writing file {dst}: {ex.Message}");
                }
            }

            // 6. Update Version in Registry
            if (manifest != null && !string.IsNullOrWhiteSpace(manifest.Version))
            {
                try
                {
                    using var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether");
                    key?.SetValue("Version", manifest.Version);
                    TraceLog($"Registry updated: Tether Version = {manifest.Version}");
                }
                catch (Exception ex)
                {
                    TraceLog($"Failed to write registry version: {ex.Message}");
                }
            }

            // 7. Restart service if previously stopped
            if (wasServiceStopped)
            {
                StartServiceSafely(ServiceName, 8000);
            }

            // 8. Relaunch Tether Desktop UI
            if (restartUi)
            {
                string uiExe = Path.Combine(targetDir, "Tether.DesktopUI.exe");
                if (File.Exists(uiExe))
                {
                    TraceLog($"Relaunching Desktop UI: {uiExe}");
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = uiExe,
                        UseShellExecute = true
                    });
                }
            }

            // 9. Clean up staging directory
            try
            {
                string? parentTemp = Path.GetDirectoryName(stagingDir);
                if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, true);
            }
            catch {}

            TraceLog("Update complete. Exiting.");
            return 0;
        }

        private static bool StopServiceSafely(string serviceName, int timeoutMs)
        {
            try
            {
                using var sc = new ServiceController(serviceName);
                if (sc.Status == ServiceControllerStatus.Running || sc.Status == ServiceControllerStatus.StartPending)
                {
                    TraceLog($"Stopping service '{serviceName}'...");
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(timeoutMs));
                    TraceLog($"Service '{serviceName}' stopped.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                TraceLog($"Service stop skipped or failed: {ex.Message}");
            }
            return false;
        }

        private static void StartServiceSafely(string serviceName, int timeoutMs)
        {
            try
            {
                using var sc = new ServiceController(serviceName);
                if (sc.Status == ServiceControllerStatus.Stopped)
                {
                    TraceLog($"Starting service '{serviceName}'...");
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(timeoutMs));
                    TraceLog($"Service '{serviceName}' started.");
                }
            }
            catch (Exception ex)
            {
                TraceLog($"Service start failed: {ex.Message}");
            }
        }

        private static void WaitForProcessesToExit(string processName, int timeoutMs)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                var procs = Process.GetProcessesByName(processName);
                if (procs.Length == 0) return;
                Thread.Sleep(300);
            }
        }

        private static string ComputeSha256(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                byte[] hash = sha256.ComputeHash(stream);
                return Convert.ToHexString(hash).ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        private static void TraceLog(string msg)
        {
            string line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
            Console.WriteLine(line);
            try
            {
                string logFile = Path.Combine(Path.GetTempPath(), "TetherUpdate.log");
                File.AppendAllText(logFile, line + Environment.NewLine);
            }
            catch {}
        }
    }
}
