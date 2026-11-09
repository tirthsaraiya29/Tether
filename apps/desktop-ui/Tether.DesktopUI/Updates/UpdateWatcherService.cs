using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Tether.Shared.Security;

namespace Tether.DesktopUI.Updates
{
    public class UpdateWatcherService : IDisposable
    {
        private const string RepoOwner = "tirthsaraiya29";
        private const string RepoName = "Tether";
        private const string GitHubApiUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest";
        private const string RegistrySubKey = @"Software\Tether\Updates";

        private static readonly HttpClient _httpClient = new HttpClient();
        private Timer? _backgroundTimer;
        private bool _isDisposed;
        private string? _cachedETag;
        private DateTime _lastCheckUtc = DateTime.MinValue;

        public event Action<UpdateCheckResult>? UpdateDetected;

        static UpdateWatcherService()
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Tether-Desktop-UpdateWatcher/1.0");
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github.v3+json"));
            _httpClient.Timeout = TimeSpan.FromSeconds(10);
        }

        public UpdateWatcherService()
        {
            LoadCacheFromRegistry();
        }

        /// <summary>
        /// Starts the update watcher. Checks on startup (after initial delay) and periodically in background.
        /// </summary>
        public void Start()
        {
            if (UpdateEnvironment.IsDebugOrDevEnvironment())
            {
                Debug.WriteLine("[UpdateWatcherService] Running in Debug/Dev environment - update watcher disabled.");
                return;
            }

            // Initial deferred check after 3 seconds, followed by periodic check every 4 hours
            _backgroundTimer = new Timer(async _ =>
            {
                await CheckForUpdateAsync(force: false);
            }, null, TimeSpan.FromSeconds(3), TimeSpan.FromHours(4));
        }

        /// <summary>
        /// Checks GitHub releases for an update. Debounced so it doesn't poll aggressively.
        /// </summary>
        public async Task<UpdateCheckResult?> CheckForUpdateAsync(bool force = false)
        {
            if (UpdateEnvironment.IsDebugOrDevEnvironment())
            {
                return null;
            }

            // Debounce: don't check more than once every 15 minutes unless forced
            if (!force && (DateTime.UtcNow - _lastCheckUtc).TotalMinutes < 15)
            {
                return null;
            }

            try
            {
                _lastCheckUtc = DateTime.UtcNow;

                using var request = new HttpRequestMessage(HttpMethod.Get, GitHubApiUrl);
                if (!string.IsNullOrWhiteSpace(_cachedETag) && !force)
                {
                    request.Headers.IfNoneMatch.Add(new EntityTagHeaderValue(_cachedETag));
                }

                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

                if (response.StatusCode == HttpStatusCode.NotModified)
                {
                    Debug.WriteLine("[UpdateWatcherService] 304 Not Modified - no new release.");
                    return null;
                }

                if (!response.IsSuccessStatusCode)
                {
                    Debug.WriteLine($"[UpdateWatcherService] GitHub API responded with {response.StatusCode}");
                    return null;
                }

                if (response.Headers.ETag != null)
                {
                    _cachedETag = response.Headers.ETag.Tag;
                    SaveCacheToRegistry();
                }

                string json = await response.Content.ReadAsStringAsync();
                var release = JsonSerializer.Deserialize<GitHubRelease>(json);
                if (release == null || string.IsNullOrWhiteSpace(release.TagName))
                {
                    return null;
                }

                string remoteTag = release.TagName.TrimStart('v', 'V');
                string currentVersion = GetCurrentInstalledVersion();

                if (!IsNewerVersion(currentVersion, remoteTag))
                {
                    Debug.WriteLine($"[UpdateWatcherService] App is up to date: local={currentVersion}, remote={remoteTag}");
                    return null;
                }

                // Check if this version is currently snoozed
                if (!force && IsSnoozed(remoteTag))
                {
                    Debug.WriteLine($"[UpdateWatcherService] Update {remoteTag} is currently snoozed.");
                    return null;
                }

                var result = new UpdateCheckResult
                {
                    IsUpdateAvailable = true,
                    CurrentVersion = currentVersion,
                    LatestVersion = remoteTag,
                    ReleaseNotes = release.Body,
                    ReleaseUrl = release.HtmlUrl
                };

                // Locate relevant assets
                foreach (var asset in release.Assets)
                {
                    if (asset.Name.EndsWith("-update.zip", StringComparison.OrdinalIgnoreCase) ||
                        asset.Name.StartsWith("Tether-Update", StringComparison.OrdinalIgnoreCase))
                    {
                        result.ZipDownloadUrl = asset.BrowserDownloadUrl;
                    }
                    else if (asset.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        result.InstallerDownloadUrl = asset.BrowserDownloadUrl;
                    }
                    else if (asset.Name.Equals("update-manifest.json", StringComparison.OrdinalIgnoreCase))
                    {
                        result.ManifestDownloadUrl = asset.BrowserDownloadUrl;
                    }
                    else if (asset.Name.Equals("update-manifest.json.sig", StringComparison.OrdinalIgnoreCase) ||
                             asset.Name.Equals("update-manifest.sig", StringComparison.OrdinalIgnoreCase))
                    {
                        result.SignatureDownloadUrl = asset.BrowserDownloadUrl;
                    }
                }

                // If manifest is available, enforce raw detached signature verification before deserialization
                if (!string.IsNullOrEmpty(result.ManifestDownloadUrl))
                {
                    bool manifestOk = await ValidateAndComputeDifferentialFilesAsync(result);
                    if (!manifestOk)
                    {
                        Debug.WriteLine("[UpdateWatcherService] SECURITY ALERT: Manifest signature verification failed or signature missing. Rejecting update (fail-closed).");
                        return null;
                    }
                }
                else
                {
                    // Fail-closed: Updates require an authenticated manifest
                    Debug.WriteLine("[UpdateWatcherService] SECURITY ALERT: Release does not include an update manifest. Rejecting update (fail-closed).");
                    return null;
                }

                // Alert subscribers on UI thread
                UpdateDetected?.Invoke(result);

                return result;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UpdateWatcherService] Check failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Validates the remote update manifest signature against PinnedManifestPublicKey BEFORE deserializing,
        /// then computes differential files to overwrite. Fails closed if signature is missing, forged, or invalid.
        /// </summary>
        private async Task<bool> ValidateAndComputeDifferentialFilesAsync(UpdateCheckResult result)
        {
            try
            {
                if (string.IsNullOrEmpty(result.ManifestDownloadUrl))
                {
                    return false;
                }

                // 1. Download raw manifest bytes
                byte[] manifestBytes = await _httpClient.GetByteArrayAsync(result.ManifestDownloadUrl);
                if (manifestBytes == null || manifestBytes.Length == 0)
                {
                    Debug.WriteLine("[UpdateWatcherService] Empty manifest bytes downloaded.");
                    return false;
                }

                // 2. Download detached signature bytes
                string sigUrl = result.SignatureDownloadUrl ?? (result.ManifestDownloadUrl + ".sig");
                byte[]? signatureBytes = null;
                try
                {
                    signatureBytes = await _httpClient.GetByteArrayAsync(sigUrl);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[UpdateWatcherService] Failed to fetch manifest signature from {sigUrl}: {ex.Message}");
                    return false;
                }

                if (signatureBytes == null || signatureBytes.Length == 0)
                {
                    Debug.WriteLine("[UpdateWatcherService] Detached manifest signature is missing or empty.");
                    return false;
                }

                // 3. Cryptographic detached signature check on raw bytes BEFORE deserializing or trusting any fields
                bool isSignatureValid = AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, signatureBytes);
                if (!isSignatureValid)
                {
                    Debug.WriteLine("[UpdateWatcherService] SECURITY ERROR: Manifest signature verification against PinnedManifestPublicKey failed!");
                    return false;
                }

                // 4. Manifest verified authentic: now safe to deserialize
                var manifest = JsonSerializer.Deserialize<UpdateManifest>(manifestBytes);
                if (manifest == null || manifest.Files == null || manifest.Files.Count == 0)
                {
                    Debug.WriteLine("[UpdateWatcherService] Manifest JSON deserialization produced null or empty files.");
                    return false;
                }

                result.PayloadSha256 = manifest.PayloadSha256;

                string installDir = AppDomain.CurrentDomain.BaseDirectory;
                string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);

                var changedFiles = new List<ManifestFileEntry>();
                long totalBytes = 0;

                foreach (var entry in manifest.Files)
                {
                    string localPath = entry.IsCredProv 
                        ? Path.Combine(sysDir, Path.GetFileName(entry.Path)) 
                        : Path.Combine(installDir, entry.Path);

                    bool needsUpdate = false;
                    if (!File.Exists(localPath))
                    {
                        needsUpdate = true;
                    }
                    else
                    {
                        var fileInfo = new FileInfo(localPath);
                        if (fileInfo.Length != entry.Size)
                        {
                            needsUpdate = true;
                        }
                        else
                        {
                            string localHash = ComputeSha256(localPath);
                            if (!string.Equals(localHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                            {
                                needsUpdate = true;
                            }
                        }
                    }

                    if (needsUpdate)
                    {
                        changedFiles.Add(entry);
                        totalBytes += entry.Size;
                    }
                }

                result.ChangedFiles = changedFiles;
                result.ChangedFilesCount = changedFiles.Count;
                result.TotalDownloadBytes = totalBytes;
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UpdateWatcherService] Differential calculation error: {ex.Message}");
                return false;
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

        public static bool IsNewerVersion(string currentVer, string remoteVer)
        {
            if (string.IsNullOrWhiteSpace(remoteVer)) return false;
            if (string.IsNullOrWhiteSpace(currentVer)) return true;

            string[] cParts = currentVer.Split('-');
            string[] rParts = remoteVer.Split('-');

            if (Version.TryParse(cParts[0], out Version? c) && Version.TryParse(rParts[0], out Version? r))
            {
                return r > c;
            }

            return string.Compare(remoteVer, currentVer, StringComparison.OrdinalIgnoreCase) > 0;
        }

        public string GetCurrentInstalledVersion()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether");
                if (key != null)
                {
                    string? ver = key.GetValue("Version") as string;
                    if (!string.IsNullOrWhiteSpace(ver)) return ver;
                }
            }
            catch {}

            var assemblyVer = typeof(UpdateWatcherService).Assembly.GetName().Version;
            return assemblyVer != null ? $"{assemblyVer.Major}.{assemblyVer.Minor}.{assemblyVer.Build}" : "1.0.0";
        }

        public void Snooze(TimeSpan duration, string version)
        {
            DateTime snoozeUntil = DateTime.UtcNow.Add(duration);
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(RegistrySubKey);
                key.SetValue("SnoozeUntilUtc", snoozeUntil.ToString("O"));
                key.SetValue("SnoozedVersion", version);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[UpdateWatcherService] Failed to persist snooze: {ex.Message}");
            }
        }

        private bool IsSnoozed(string remoteVersion)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegistrySubKey);
                if (key == null) return false;

                string? snoozedVer = key.GetValue("SnoozedVersion") as string;
                string? untilStr = key.GetValue("SnoozeUntilUtc") as string;

                if (string.IsNullOrWhiteSpace(snoozedVer) || string.IsNullOrWhiteSpace(untilStr))
                    return false;

                if (DateTime.TryParse(untilStr, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime snoozeUntil))
                {
                    // If a newer release came out than the snoozed one, invalidate snooze!
                    if (IsNewerVersion(snoozedVer, remoteVersion))
                    {
                        return false;
                    }

                    return DateTime.UtcNow < snoozeUntil;
                }
            }
            catch {}

            return false;
        }

        private void LoadCacheFromRegistry()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegistrySubKey);
                if (key != null)
                {
                    _cachedETag = key.GetValue("CachedETag") as string;
                }
            }
            catch {}
        }

        private void SaveCacheToRegistry()
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(RegistrySubKey);
                if (!string.IsNullOrWhiteSpace(_cachedETag))
                {
                    key.SetValue("CachedETag", _cachedETag);
                }
            }
            catch {}
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            _backgroundTimer?.Dispose();
        }
    }
}
