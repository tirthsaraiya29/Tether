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

    public class Program
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
            if (!LockdownStagingAcl(stagingDir, manifestPath))
            {
                TraceLog("SECURITY ERROR: Failed to enforce strict staging ACL lockdown or reparse point detected. Aborting update (fail-closed).");
                return 12;
            }

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

            // 3. Validate manifest strictly (fail-closed)
            if (manifest == null || manifest.Files == null || manifest.Files.Count == 0)
            {
                TraceLog("SECURITY ERROR: Update manifest is missing, invalid, or empty. Aborting update (fail-closed).");
                return 2;
            }

            var filesToUpdate = new List<Tuple<string, string, bool, string>>(); // <source, dest, isService, sha256>
            bool serviceRestartNeeded = false;
            string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string stagingPrefix = Path.GetFullPath(stagingDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string targetPrefix = Path.GetFullPath(targetDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            TraceLog($"Evaluating {manifest.Files.Count} files from manifest with strict hash and containment validation...");

            // First pass: Validate ALL staged files before any modifications or service actions
            foreach (var entry in manifest.Files)
            {
                if (string.IsNullOrWhiteSpace(entry.Path) || string.IsNullOrWhiteSpace(entry.Sha256) || entry.Size < 0)
                {
                    TraceLog($"SECURITY ERROR: Manifest contains invalid file entry '{entry.Path}'. Aborting.");
                    return 3;
                }

                // Block traversal, alternate data streams, rooted paths
                if (entry.Path.Contains("..") || entry.Path.Contains(':') || Path.IsPathRooted(entry.Path))
                {
                    TraceLog($"SECURITY ERROR: Path traversal or invalid characters detected in entry '{entry.Path}'. Aborting.");
                    return 4;
                }

                string sourceFile = Path.GetFullPath(Path.Combine(stagingDir, entry.Path));
                if (!sourceFile.StartsWith(stagingPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    TraceLog($"SECURITY ERROR: Source file '{entry.Path}' escapes staging directory. Aborting.");
                    return 5;
                }

                if (!File.Exists(sourceFile))
                {
                    TraceLog($"SECURITY ERROR: Declared update file missing from staging: '{entry.Path}'. Aborting.");
                    return 6;
                }

                if ((File.GetAttributes(sourceFile) & FileAttributes.ReparsePoint) != 0)
                {
                    TraceLog($"SECURITY ERROR: Staged file '{entry.Path}' is a reparse point. Aborting.");
                    return 7;
                }

                // Mandatory size verification against manifest
                var sInfo = new FileInfo(sourceFile);
                if (sInfo.Length != entry.Size)
                {
                    TraceLog($"SECURITY ERROR: Staged file '{entry.Path}' size mismatch (expected {entry.Size}, actual {sInfo.Length}). Aborting.");
                    return 8;
                }

                // Mandatory cryptographic hash verification against manifest
                string sourceHash = ComputeSha256(sourceFile);
                if (!string.Equals(sourceHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    TraceLog($"SECURITY ERROR: Staged file '{entry.Path}' hash mismatch (expected {entry.Sha256}, actual {sourceHash}). Aborting.");
                    return 9;
                }

                // Destination resolution and strict containment check
                string destFile;
                if (entry.IsCredProv)
                {
                    if (!string.Equals(entry.Path, "TetherCredentialProvider.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        TraceLog($"SECURITY ERROR: Credential Provider entry '{entry.Path}' is invalid. Aborting.");
                        return 11;
                    }
                    if (!Tether.Shared.Security.AuthenticodeVerifier.VerifyFileAuthenticode(sourceFile))
                    {
                        TraceLog($"SECURITY ERROR: Staged Credential Provider source '{sourceFile}' failed Authenticode/publisher verification. Aborting.");
                        return 13;
                    }
                    destFile = Path.Combine(sysDir, "TetherCredentialProvider.dll");
                }
                else
                {
                    destFile = Path.GetFullPath(Path.Combine(targetDir, entry.Path));
                    if (!destFile.StartsWith(targetPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        TraceLog($"SECURITY ERROR: Destination file '{destFile}' escapes target application directory. Aborting.");
                        return 10;
                    }
                }

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
                    TraceLog($"[MODIFIED & VERIFIED] {entry.Path}");
                    filesToUpdate.Add(Tuple.Create(sourceFile, destFile, entry.IsService, entry.Sha256));
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
                string expectedSha256 = item.Item4;

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
                            written = CopyFileVerified(src, dst, expectedSha256);
                            if (!written) break;
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
                            written = CopyFileVerified(src, dst, expectedSha256);
                            if (!written) break;
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

        public static bool LockdownStagingAcl(string stagingDir, string manifestPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(stagingDir) || !Directory.Exists(stagingDir))
                {
                    TraceLog("Staging ACL error: staging directory does not exist.");
                    return false;
                }

                // Reject reparse points on staging directory
                var stagingDi = new DirectoryInfo(stagingDir);
                if ((stagingDi.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    TraceLog("Staging ACL error: staging directory is a reparse point.");
                    return false;
                }

                var systemSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                var adminSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

                var ds = stagingDi.GetAccessControl();
                ds.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                foreach (System.Security.AccessControl.FileSystemAccessRule r in ds.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                {
                    ds.RemoveAccessRule(r);
                }
                ds.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(systemSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                ds.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(adminSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                stagingDi.SetAccessControl(ds);

                if (!string.IsNullOrEmpty(manifestPath) && File.Exists(manifestPath))
                {
                    var fi = new FileInfo(manifestPath);
                    if ((fi.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        TraceLog("Staging ACL error: manifest file is a reparse point.");
                        return false;
                    }
                    var fs = fi.GetAccessControl();
                    fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                    foreach (System.Security.AccessControl.FileSystemAccessRule r in fs.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                    {
                        fs.RemoveAccessRule(r);
                    }
                    fs.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(systemSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                    fs.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(adminSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                    fi.SetAccessControl(fs);
                }
                return true;
            }
            catch (Exception ex)
            {
                TraceLog($"SECURITY ERROR: could not enforce staging ACL: {ex.Message}");
                return false;
            }
        }

        private static bool CopyFileVerified(string src, string dst, string expectedHash)
        {
            try
            {
                using var srcStream = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var sha = SHA256.Create();
                byte[] hashBytes = sha.ComputeHash(srcStream);
                string actualHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    TraceLog($"SECURITY ERROR: Point-of-use hash mismatch for {src} (expected {expectedHash}, actual {actualHash})");
                    return false;
                }
                srcStream.Position = 0;
                using var dstStream = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None);
                srcStream.CopyTo(dstStream);
                return true;
            }
            catch (Exception ex)
            {
                TraceLog($"Error copying verified file from {src} to {dst}: {ex.Message}");
                return false;
            }
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
