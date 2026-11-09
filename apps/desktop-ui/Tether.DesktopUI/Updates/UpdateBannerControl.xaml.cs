using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

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

            string manifestPath = Path.Combine(tempDir, "update-manifest.json");
            if (!string.IsNullOrEmpty(update.ManifestDownloadUrl))
            {
                byte[] manifestBytes = await client.GetByteArrayAsync(update.ManifestDownloadUrl);
                await File.WriteAllBytesAsync(manifestPath, manifestBytes);
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

            // If it's a zip archive, extract files into staging directory
            string stagingDir = Path.Combine(tempDir, "staged");
            Directory.CreateDirectory(stagingDir);

            if (downloadUrl.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                TxtUpdateBtnLabel.Text = "Extracting...";
                ZipFile.ExtractToDirectory(payloadZip, stagingDir, overwriteFiles: true);
            }
            else
            {
                // Full installer fallback: run silent Inno Setup installer
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

            // Launch updater with elevation
            var startInfo = new ProcessStartInfo
            {
                FileName = updaterExe,
                Arguments = $"--staging \"{stagingDir}\" --target \"{appDir}\" --manifest \"{manifestPath}\" --restart-ui",
                UseShellExecute = true,
                Verb = "runas"
            };

            Process.Start(startInfo);
            RequestShutdownForUpdate?.Invoke();
            Application.Current.Shutdown();
        }
    }
}
