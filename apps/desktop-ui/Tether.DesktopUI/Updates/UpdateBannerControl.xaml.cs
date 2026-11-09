using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Tether.Shared.Security;

namespace Tether.DesktopUI.Updates
{
    public partial class UpdateBannerControl : UserControl
    {
        private UpdateCheckResult? _currentUpdate;
        private readonly UpdateWatcherService _watcherService;
        private bool _isUpdating;

        public event Action? RequestShutdownForUpdate;

        public UpdateBannerControl()
        {
            InitializeComponent();
            _watcherService = new UpdateWatcherService();
        }

        public UpdateBannerControl(UpdateWatcherService watcherService)
        {
            InitializeComponent();
            _watcherService = watcherService;
        }

        public void BindUpdateResult(UpdateCheckResult result)
        {
            _currentUpdate = result;
            Dispatcher.Invoke(() =>
            {
                TxtVersionBadge.Text = $"v{result.LatestVersion}";
                
                if (result.ChangedFilesCount > 0)
                {
                    double mb = result.TotalDownloadBytes / (1024.0 * 1024.0);
                    TxtDescription.Text = $"Smart delta update ready: {result.ChangedFilesCount} modified binaries ({mb:F1} MB). Local unchanged files will be preserved.";
                }
                else
                {
                    TxtDescription.Text = "A critical security and system update is ready to install.";
                }

                TxtReleaseNotes.Text = string.IsNullOrWhiteSpace(result.ReleaseNotes) 
                    ? "Security fixes, performance hardening, and stability improvements." 
                    : result.ReleaseNotes;

                Visibility = Visibility.Visible;
            });
        }

        private void BtnToggleNotes_Click(object sender, RoutedEventArgs e)
        {
            if (NotesBorder.Visibility == Visibility.Visible)
            {
                NotesBorder.Visibility = Visibility.Collapsed;
                TxtNotesChevron.Text = "\uE70D"; // Chevron down
            }
            else
            {
                NotesBorder.Visibility = Visibility.Visible;
                TxtNotesChevron.Text = "\uE70E"; // Chevron up
            }
        }

        private void BtnRemindMenu_Click(object sender, RoutedEventArgs e)
        {
            if (BtnRemindMenu.ContextMenu != null)
            {
                BtnRemindMenu.ContextMenu.PlacementTarget = BtnRemindMenu;
                BtnRemindMenu.ContextMenu.IsOpen = true;
            }
        }

        private void MenuItem_Remind_Click(object sender, RoutedEventArgs e)
        {
            if (_currentUpdate == null || Visibility != Visibility.Visible) return;

            if (sender is MenuItem item && item.Tag is string tagStr && int.TryParse(tagStr, out int hours))
            {
                _watcherService.Snooze(TimeSpan.FromHours(hours), _currentUpdate.LatestVersion);
                Visibility = Visibility.Collapsed;
            }
        }

        private async void BtnUpdateNow_Click(object sender, RoutedEventArgs e)
        {
            if (_currentUpdate == null || _isUpdating) return;
            _isUpdating = true;
            BtnUpdateNow.IsEnabled = false;
            TxtUpdateBtnLabel.Text = "Downloading...";

            try
            {
                await LaunchSmartUpdaterAsync(_currentUpdate);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Update initiation failed: {ex.Message}", "Tether Update Error", MessageBoxButton.OK, MessageBoxImage.Error);
                BtnUpdateNow.IsEnabled = true;
                TxtUpdateBtnLabel.Text = "Update Now";
                _isUpdating = false;
            }
        }

        private async Task LaunchSmartUpdaterAsync(UpdateCheckResult update)
        {
            string tempDir = Path.Combine(Path.GetTempPath(), $"TetherUpdate_{update.LatestVersion}");
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
            Directory.CreateDirectory(tempDir);

            using var client = new HttpClient();
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Tether-Desktop-Updater/1.0");

            if (string.IsNullOrEmpty(update.ManifestDownloadUrl))
            {
                throw new InvalidOperationException("Update manifest URL is missing. Updates cannot proceed without an authenticated manifest.");
            }

            string manifestPath = Path.Combine(tempDir, "update-manifest.json");
            string signaturePath = Path.Combine(tempDir, "update-manifest.json.sig");

            TxtUpdateBtnLabel.Text = "Verifying manifest...";
            byte[] manifestBytes = await client.GetByteArrayAsync(update.ManifestDownloadUrl);
            string sigUrl = update.SignatureDownloadUrl ?? (update.ManifestDownloadUrl + ".sig");
            byte[] signatureBytes = await client.GetByteArrayAsync(sigUrl);

            if (manifestBytes == null || manifestBytes.Length == 0 || signatureBytes == null || signatureBytes.Length == 0)
            {
                throw new InvalidOperationException("Update manifest or detached signature is missing or empty. Aborting update (fail-closed).");
            }

            // 1. Enforce detached cryptographic signature verification on raw bytes against pinned key BEFORE deserialization
            if (!AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, signatureBytes))
            {
                throw new InvalidOperationException("Cryptographic signature verification failed: update-manifest.json signature is invalid or forged. Aborting update (fail-closed).");
            }

            await File.WriteAllBytesAsync(manifestPath, manifestBytes);
            await File.WriteAllBytesAsync(signaturePath, signatureBytes);

            // 2. Deserialize authenticated manifest
            var manifest = JsonSerializer.Deserialize<UpdateManifest>(manifestBytes);
            if (manifest == null || manifest.Files == null)
            {
                throw new InvalidOperationException("Authenticated update manifest is malformed or empty.");
            }

            // Prefer zip payload for differential file extraction
            string payloadZip = Path.Combine(tempDir, "update_payload.zip");
            string downloadUrl = update.ZipDownloadUrl ?? update.InstallerDownloadUrl ?? string.Empty;

            if (string.IsNullOrEmpty(downloadUrl))
            {
                throw new InvalidOperationException("No download package found for this release.");
            }

            TxtUpdateBtnLabel.Text = "Fetching payload...";
            using (var s = await client.GetStreamAsync(downloadUrl))
            using (var fs = new FileStream(payloadZip, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await s.CopyToAsync(fs);
            }

            // 3. Staged Payload Hash Pre-Verification (F2.3)
            if (!string.IsNullOrWhiteSpace(manifest.PayloadSha256))
            {
                TxtUpdateBtnLabel.Text = "Verifying payload...";
                string actualPayloadHash = ComputeSha256(payloadZip);
                if (!string.Equals(actualPayloadHash, manifest.PayloadSha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"Payload SHA-256 hash verification failed! Expected {manifest.PayloadSha256}, actual {actualPayloadHash}. Aborting update.");
                }
            }

            // If it's a zip archive, extract files into staging directory
            string stagingDir = Path.Combine(tempDir, "staged");
            Directory.CreateDirectory(stagingDir);

            if (downloadUrl.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                TxtUpdateBtnLabel.Text = "Extracting...";
                ZipFile.ExtractToDirectory(payloadZip, stagingDir, overwriteFiles: true);

                // Pre-verify extracted files against authenticated manifest before elevation
                string stagingPrefix = Path.GetFullPath(stagingDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                foreach (var entry in manifest.Files)
                {
                    if (entry.Path.Contains("..") || entry.Path.Contains(':') || Path.IsPathRooted(entry.Path))
                    {
                        throw new InvalidOperationException($"Path traversal attempt in manifest entry '{entry.Path}'.");
                    }
                    string stagedFile = Path.GetFullPath(Path.Combine(stagingDir, entry.Path));
                    if (!stagedFile.StartsWith(stagingPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException($"Staged file '{entry.Path}' escapes staging directory.");
                    }
                    if (!File.Exists(stagedFile))
                    {
                        throw new InvalidOperationException($"Declared update file missing from extracted payload: '{entry.Path}'.");
                    }
                    if ((File.GetAttributes(stagedFile) & FileAttributes.ReparsePoint) != 0)
                    {
                        throw new InvalidOperationException($"Staged file '{entry.Path}' is a reparse point.");
                    }
                    string stagedHash = ComputeSha256(stagedFile);
                    if (!string.Equals(stagedHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException($"Staged file '{entry.Path}' hash mismatch: expected {entry.Sha256}, actual {stagedHash}.");
                    }
                    if (entry.IsCredProv && !AuthenticodeVerifier.VerifyFileAuthenticode(stagedFile))
                    {
                        throw new InvalidOperationException($"Staged Credential Provider '{stagedFile}' failed Authenticode pinned publisher verification.");
                    }
                }
            }
            else
            {
                // Full installer fallback: run silent Inno Setup installer
                VerifyInstallerAuthenticode(payloadZip);
                Process.Start(new ProcessStartInfo
                {
                    FileName = payloadZip,
                    Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                    UseShellExecute = true,
                    Verb = "runas"
                });
                RequestShutdownForUpdate?.Invoke();
                Application.Current.Shutdown();
                return;
            }

            // Verify Tether.Updater.exe in local app directory. Do not execute unverified staged binaries with elevation.
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string updaterExe = Path.Combine(appDir, "Tether.Updater.exe");
            if (!File.Exists(updaterExe))
            {
                TxtUpdateBtnLabel.Text = "Updater missing";
                throw new FileNotFoundException("Tether.Updater.exe not found in application directory. Unverified binaries will not be elevated from temp directories.");
            }

            // Verify Authenticode of Tether.Updater.exe before elevation (fails closed in production)
            if (!UpdateEnvironment.IsDebugOrDevEnvironment())
            {
                if (!AuthenticodeVerifier.VerifyFileAuthenticode(updaterExe))
                {
                    TxtUpdateBtnLabel.Text = "Updater verification failed";
                    throw new InvalidOperationException("Tether.Updater.exe failed Authenticode pinned publisher verification. Unverified binaries will not be elevated.");
                }
            }

            // Launch updater with elevation including detached signature argument
            var startInfo = new ProcessStartInfo
            {
                FileName = updaterExe,
                Arguments = $"--staging \"{stagingDir}\" --target \"{appDir}\" --manifest \"{manifestPath}\" --signature \"{signaturePath}\" --restart-ui",
                UseShellExecute = true,
                Verb = "runas"
            };

            Process.Start(startInfo);
            RequestShutdownForUpdate?.Invoke();
            Application.Current.Shutdown();
        }

        private static void VerifyInstallerAuthenticode(string installerPath)
        {
            if (!AuthenticodeVerifier.VerifyFileAuthenticode(installerPath))
            {
                throw new InvalidOperationException("Installer signature verification failed: file is unsigned, tampered, or not signed by trusted Tether publisher.");
            }
        }

        private static string ComputeSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var fs = File.OpenRead(filePath);
            byte[] hash = sha.ComputeHash(fs);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}
