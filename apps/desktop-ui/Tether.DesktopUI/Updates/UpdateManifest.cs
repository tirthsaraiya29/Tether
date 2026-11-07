using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Tether.DesktopUI.Updates
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

    public class UpdateCheckResult
    {
        public bool IsUpdateAvailable { get; set; }
        public string CurrentVersion { get; set; } = string.Empty;
        public string LatestVersion { get; set; } = string.Empty;
        public string ReleaseNotes { get; set; } = string.Empty;
        public string ReleaseUrl { get; set; } = string.Empty;
        public string? ZipDownloadUrl { get; set; }
        public string? InstallerDownloadUrl { get; set; }
        public string? ManifestDownloadUrl { get; set; }
        public int ChangedFilesCount { get; set; }
        public long TotalDownloadBytes { get; set; }
        public List<ManifestFileEntry> ChangedFiles { get; set; } = new();
    }

    public class GitHubAsset
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("size")]
        public long Size { get; set; }

        [JsonPropertyName("browser_download_url")]
        public string BrowserDownloadUrl { get; set; } = string.Empty;
    }

    public class GitHubRelease
    {
        [JsonPropertyName("tag_name")]
        public string TagName { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("body")]
        public string Body { get; set; } = string.Empty;

        [JsonPropertyName("html_url")]
        public string HtmlUrl { get; set; } = string.Empty;

        [JsonPropertyName("published_at")]
        public string PublishedAt { get; set; } = string.Empty;

        [JsonPropertyName("assets")]
        public List<GitHubAsset> Assets { get; set; } = new();
    }
}
