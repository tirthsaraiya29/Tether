using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Tether.FileTransfer.Protocol;
using Tether.Shared.Logging;

namespace Tether.FileTransfer;

public sealed record FilesystemRootItem
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public required string RootType { get; init; }
    public bool IsReadable { get; init; } = true;
}

public sealed record DirectoryListingItem
{
    public required string Name { get; init; }
    public required string RelativePath { get; init; }
    public required bool IsDirectory { get; init; }
    public long FileSize { get; init; }
    public long LastModifiedMs { get; init; }
    public bool IsReadable { get; init; } = true;
}

public sealed class FileSystemBrowser
{
    private readonly ITetherLogger _logger;

    public FileSystemBrowser(ITetherLogger logger)
    {
        _logger = logger;
    }

    public List<FilesystemRootItem> GetPermittedRoots()
    {
        var roots = new List<FilesystemRootItem>();
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        AddRootIfValid(roots, "Downloads", Path.Combine(userProfile, "Downloads"), "DOWNLOADS");
        AddRootIfValid(roots, "Documents", Path.Combine(userProfile, "Documents"), "DOCUMENTS");
        AddRootIfValid(roots, "Pictures", Path.Combine(userProfile, "Pictures"), "PICTURES");
        AddRootIfValid(roots, "Videos", Path.Combine(userProfile, "Videos"), "VIDEOS");
        AddRootIfValid(roots, "Desktop", Path.Combine(userProfile, "Desktop"), "DESKTOP");

        // Enumerate all ready mounted logical drives
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady)
                {
                    string label = string.IsNullOrWhiteSpace(drive.VolumeLabel)
                        ? $"Drive ({drive.Name.TrimEnd('\\')})"
                        : $"{drive.VolumeLabel} ({drive.Name.TrimEnd('\\')})";
                    AddRootIfValid(roots, label, drive.RootDirectory.FullName, "DRIVE");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"FileSystemBrowser: Error enumerating system drives: {ex.Message}");
        }

        // Custom roots from settings.json
        try
        {
            string settingsFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tether", "settings.json");

            if (File.Exists(settingsFile))
            {
                var doc = JsonDocument.Parse(File.ReadAllText(settingsFile));
                if (doc.RootElement.TryGetProperty("DownloadPath", out var pathProp))
                {
                    string customPath = pathProp.GetString() ?? "";
                    if (!string.IsNullOrWhiteSpace(customPath))
                    {
                        AddRootIfValid(roots, new DirectoryInfo(customPath).Name, customPath, "CUSTOM");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"FileSystemBrowser: Error reading custom settings root: {ex.Message}");
        }

        return roots;
    }

    public List<DirectoryListingItem> ListDirectory(string requestedPath)
    {
        string canonicalPath = GetCanonicalValidatedPath(requestedPath);

        if (!Directory.Exists(canonicalPath))
        {
            throw new DirectoryNotFoundException($"Directory not found or inaccessible: {requestedPath}");
        }

        var results = new List<DirectoryListingItem>();
        var dirInfo = new DirectoryInfo(canonicalPath);

        foreach (var subDir in dirInfo.GetDirectories())
        {
            try
            {
                if ((subDir.Attributes & FileAttributes.Hidden) != 0 || (subDir.Attributes & FileAttributes.System) != 0)
                    continue;

                results.Add(new DirectoryListingItem
                {
                    Name = subDir.Name,
                    RelativePath = subDir.FullName,
                    IsDirectory = true,
                    FileSize = 0L,
                    LastModifiedMs = subDir.LastWriteTimeUtc.Ticks / TimeSpan.TicksPerMillisecond,
                    IsReadable = true
                });
            }
            catch (Exception ex)
            {
                _logger.Warning($"FileSystemBrowser: Skipping directory {subDir.Name}: {ex.Message}");
            }
        }

        foreach (var file in dirInfo.GetFiles())
        {
            try
            {
                if ((file.Attributes & FileAttributes.Hidden) != 0 || (file.Attributes & FileAttributes.System) != 0)
                    continue;

                results.Add(new DirectoryListingItem
                {
                    Name = file.Name,
                    RelativePath = file.FullName,
                    IsDirectory = false,
                    FileSize = file.Length,
                    LastModifiedMs = file.LastWriteTimeUtc.Ticks / TimeSpan.TicksPerMillisecond,
                    IsReadable = true
                });
            }
            catch (Exception ex)
            {
                _logger.Warning($"FileSystemBrowser: Skipping file {file.Name}: {ex.Message}");
            }
        }

        return results.OrderByDescending(r => r.IsDirectory).ThenBy(r => r.Name).ToList();
    }

    public string GetCanonicalValidatedPath(string requestedPath)
    {
        if (string.IsNullOrWhiteSpace(requestedPath))
        {
            throw new ArgumentException("Requested path cannot be empty.");
        }

        string fullPath = Path.GetFullPath(requestedPath);
        var permittedRoots = GetPermittedRoots();

        bool isInsideRoot = false;
        foreach (var root in permittedRoots)
        {
            string rootCanonical = Path.GetFullPath(root.Path);
            if (!rootCanonical.EndsWith(Path.DirectorySeparatorChar.ToString()))
            {
                rootCanonical += Path.DirectorySeparatorChar;
            }

            string targetCanonical = fullPath;
            if (!targetCanonical.EndsWith(Path.DirectorySeparatorChar.ToString()) && Directory.Exists(targetCanonical))
            {
                targetCanonical += Path.DirectorySeparatorChar;
            }

            if (targetCanonical.StartsWith(rootCanonical, StringComparison.OrdinalIgnoreCase) ||
                fullPath.Equals(Path.GetFullPath(root.Path), StringComparison.OrdinalIgnoreCase))
            {
                isInsideRoot = true;
                break;
            }
        }

        if (!isInsideRoot)
        {
            _logger.Warning($"FileSystemBrowser: Access denied - Path '{requestedPath}' is outside permitted roots.");
            throw new UnauthorizedAccessException($"Access denied: Path '{requestedPath}' is outside authorized roots.");
        }

        return fullPath;
    }

    private static void AddRootIfValid(List<FilesystemRootItem> list, string name, string path, string type)
    {
        try
        {
            if (Directory.Exists(path) && !list.Any(r => r.Path.Equals(path, StringComparison.OrdinalIgnoreCase)))
            {
                list.Add(new FilesystemRootItem
                {
                    Name = name,
                    Path = path,
                    RootType = type,
                    IsReadable = true
                });
            }
        }
        catch { }
    }
}
