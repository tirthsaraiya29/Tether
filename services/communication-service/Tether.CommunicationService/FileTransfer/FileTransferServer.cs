using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Trust;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.FileTransfer;

public class FileTransferServer : IHostedService
{
    private const long MaxUploadSizeBytes = 4L * 1024L * 1024L * 1024L; // 4 GB per transfer
    private const long MinimumDiskBufferBytes = 250L * 1024L * 1024L;   // 250 MB free space safety margin
    private const int MaxConcurrentTransfers = 4;

    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly TokenStore _tokenStore;
    private readonly SessionManager _sessionManager;
    private readonly TrustStore _trustStore;
    private readonly Tether.CommunicationService.Transport.InputForwarder _inputForwarder;
    private WebApplication? _app;

    private static readonly SemaphoreSlim _transferThrottle = new(MaxConcurrentTransfers, MaxConcurrentTransfers);
    private static readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pendingRequests = new();

    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private static readonly string[] BlockedDirectoryPrefixes = InitializeBlockedPrefixes();

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHFileOperation(ref SHFILEOPSTRUCT lpFileOp);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCT
    {
        public IntPtr hwnd;
        public uint wFunc;
        public string pFrom;
        public string? pTo;
        public ushort fFlags;
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        public string? lpszProgressTitle;
    }

    private const uint FO_DELETE = 0x0003;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_SILENT = 0x0004;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);

    #region Win32 Final Path Resolution
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle hFile,
        [Out] StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_NAME_NORMALIZED = 0x0;

    private static string? GetFinalResolvedPath(string path)
    {
        using var handle = CreateFile(
            path,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            return null;
        }

        var sb = new StringBuilder(1024);
        uint result = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, FILE_NAME_NORMALIZED);
        if (result == 0 || result >= sb.Capacity)
        {
            return null;
        }

        string resolved = sb.ToString();
        if (resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + resolved[8..];
        }
        if (resolved.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            return resolved[4..];
        }
        return resolved;
    }
    #endregion

    public FileTransferServer(ITetherLogger logger, WindowsIdentity identity, TokenStore tokenStore, SessionManager sessionManager, TrustStore trustStore, Tether.CommunicationService.Transport.InputForwarder inputForwarder)
    {
        _logger = logger;
        _identity = identity;
        _tokenStore = tokenStore;
        _sessionManager = sessionManager;
        _trustStore = trustStore;
        _inputForwarder = inputForwarder;
    }

    private static string[] InitializeBlockedPrefixes()
    {
        var list = new List<string>();

        void AddIfValid(string? path)
        {
            if (!string.IsNullOrWhiteSpace(path))
            {
                try
                {
                    var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    list.Add(full);
                }
                catch { }
            }
        }

        AddIfValid(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        AddIfValid(Environment.GetFolderPath(Environment.SpecialFolder.System));
        AddIfValid(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        AddIfValid(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        AddIfValid(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether"));
        AddIfValid(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tether"));
        AddIfValid(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Tether"));
        AddIfValid(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        AddIfValid(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool IsPathInBlockedPrefix(string normalizedPath)
    {
        string pathWithSep = normalizedPath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

        foreach (var blocked in BlockedDirectoryPrefixes)
        {
            string blockedWithSep = blocked + Path.DirectorySeparatorChar;
            if (pathWithSep.StartsWith(blockedWithSep, StringComparison.OrdinalIgnoreCase) ||
                normalizedPath.Equals(blocked, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (normalizedPath.Contains("System Volume Information", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static bool HasReparsePointInHierarchy(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var fi = new FileInfo(path);
                if (fi.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    return true;
                }
            }

            var dir = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path).Directory;
            while (dir != null && dir.Parent != null)
            {
                if (dir.Exists && dir.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    return true;
                }
                dir = dir.Parent;
            }
        }
        catch
        {
            return true;
        }

        return false;
    }

    private static bool IsCrossUserProfileAccess(string normalizedPath)
    {
        try
        {
            string? sysDrive = Environment.GetEnvironmentVariable("SystemDrive");
            string usersDir = !string.IsNullOrEmpty(sysDrive) ? Path.Combine(sysDrive, "Users") : @"C:\Users";
            string usersPrefix = usersDir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            if (!normalizedPath.StartsWith(usersPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string publicDir = Path.Combine(usersDir, "Public") + Path.DirectorySeparatorChar;
            if (normalizedPath.StartsWith(publicDir, StringComparison.OrdinalIgnoreCase) ||
                normalizedPath.Equals(Path.Combine(usersDir, "Public"), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string? activeProfile = Tether.CommunicationService.Capabilities.LaptopStateCollector.GetActiveConsoleUserProfilePath();
            if (string.IsNullOrEmpty(activeProfile))
            {
                activeProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            }

            if (!string.IsNullOrEmpty(activeProfile))
            {
                string activePrefix = activeProfile.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (normalizedPath.StartsWith(activePrefix, StringComparison.OrdinalIgnoreCase) ||
                    normalizedPath.Equals(activeProfile, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            string currentProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(currentProfile))
            {
                string currentPrefix = currentProfile.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (normalizedPath.StartsWith(currentPrefix, StringComparison.OrdinalIgnoreCase) ||
                    normalizedPath.Equals(currentProfile, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool TryGetValidPath(string? inputPath, out string fullPath, bool isUpload = false)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            return false;
        }

        try
        {
            if (inputPath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                return false;
            }

            // Block UNC network paths
            if (inputPath.StartsWith(@"\\") || inputPath.StartsWith("//"))
            {
                return false;
            }

            // Block Alternate Data Streams (ADS)
            if (inputPath.Length > 2 && inputPath.IndexOf(':', 2) >= 0)
            {
                return false;
            }

            var normalized = Path.GetFullPath(inputPath);
            if (!Path.IsPathRooted(normalized))
            {
                return false;
            }

            // Block DOS device reserved names
            string fileName = Path.GetFileNameWithoutExtension(normalized);
            if (ReservedDeviceNames.Contains(fileName))
            {
                return false;
            }

            // Block lexical root traversal into system-protected paths
            if (IsPathInBlockedPrefix(normalized) || IsCrossUserProfileAccess(normalized))
            {
                return false;
            }

            // Reject any reparse points in path hierarchy
            if (HasReparsePointInHierarchy(normalized))
            {
                return false;
            }

            // Validate resolved physical destination via OS file handle
            if (File.Exists(normalized) || Directory.Exists(normalized))
            {
                string? physicalPath = GetFinalResolvedPath(normalized);
                if (physicalPath == null || IsPathInBlockedPrefix(physicalPath) || IsCrossUserProfileAccess(physicalPath))
                {
                    return false;
                }
            }
            else if (isUpload)
            {
                // For new uploads, verify the parent container resolution
                string? parentDir = Path.GetDirectoryName(normalized);
                while (!string.IsNullOrEmpty(parentDir) && !Directory.Exists(parentDir))
                {
                    parentDir = Path.GetDirectoryName(parentDir);
                }

                if (!string.IsNullOrEmpty(parentDir))
                {
                    if (HasReparsePointInHierarchy(parentDir))
                    {
                        return false;
                    }

                    string? physicalParent = GetFinalResolvedPath(parentDir);
                    if (physicalParent == null || IsPathInBlockedPrefix(physicalParent) || IsCrossUserProfileAccess(physicalParent))
                    {
                        return false;
                    }
                }
            }

            fullPath = normalized;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static void HandleRemoteResponse(string type, string rawJson)
    {
        string requestId = "";
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            if (doc.RootElement.TryGetProperty("requestId", out var reqProp))
            {
                requestId = reqProp.GetString() ?? "";
            }
        }
        catch { }

        if (!string.IsNullOrEmpty(requestId) && _pendingRequests.TryGetValue(requestId, out var tcs))
        {
            tcs.TrySetResult(rawJson);
            _pendingRequests.TryRemove(requestId, out _);
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_identity.Certificate == null)
        {
            _logger.Error("FileTransferServer: Failed to start HTTPS listener because identity certificate is unavailable.");
            throw new InvalidOperationException("Identity certificate is required for HTTPS FileTransferServer.");
        }

        _tokenStore.GetOrCreateLocalUiToken();

        var builder = WebApplication.CreateBuilder();

        builder.WebHost.UseKestrel(options =>
        {
            options.Limits.MaxRequestBodySize = MaxUploadSizeBytes;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);

            options.ListenAnyIP(37124, listenOptions =>
            {
                listenOptions.UseHttps(httpsOptions =>
                {
                    if (_identity.Certificate != null && _identity.Certificate.HasPrivateKey)
                    {
                        httpsOptions.ServerCertificateSelector = (connectionContext, name) => _identity.Certificate;
                    }
                    else
                    {
                        httpsOptions.ServerCertificate = _identity.Certificate;
                    }
                    httpsOptions.ClientCertificateMode = ClientCertificateMode.NoCertificate;
                });
            });
        });

        builder.Services.AddSingleton(_logger);
        builder.Services.AddSingleton(_identity);
        builder.Services.AddSingleton(_tokenStore);
        builder.Services.AddSingleton(_trustStore);
        builder.Services.AddAuthorization();

        _app = builder.Build();

        _app.UseMiddleware<FileTransferAuthMiddleware>();

        _app.MapGet("/api/fs/list", (string? path) =>
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                {
                    var drives = DriveInfo.GetDrives()
                        .Where(d => d.IsReady && d.DriveType != DriveType.CDRom)
                        .Select(d => new
                        {
                            name = d.Name,
                            path = d.Name,
                            isDirectory = true,
                            size = d.TotalSize,
                            lastModified = (DateTimeOffset?)null
                        }).ToList();
                    return Results.Ok(drives);
                }

                if (!TryGetValidPath(path, out var fullPath) || !Directory.Exists(fullPath))
                {
                    return Results.NotFound(new { error = "Directory not found or access restricted" });
                }

                var dirInfo = new DirectoryInfo(fullPath);
                var entries = new List<object>();

                foreach (var dir in dirInfo.GetDirectories().Take(2000))
                {
                    if ((dir.Attributes & FileAttributes.ReparsePoint) != 0 || (dir.Attributes & FileAttributes.Hidden) != 0)
                    {
                        continue;
                    }

                    if (IsPathInBlockedPrefix(dir.FullName))
                    {
                        continue;
                    }

                    entries.Add(new
                    {
                        name = dir.Name,
                        path = dir.FullName,
                        isDirectory = true,
                        size = 0L,
                        lastModified = (DateTimeOffset)dir.LastWriteTimeUtc
                    });
                }

                foreach (var file in dirInfo.GetFiles().Take(5000))
                {
                    if ((file.Attributes & FileAttributes.ReparsePoint) != 0 || (file.Attributes & FileAttributes.Hidden) != 0)
                    {
                        continue;
                    }

                    entries.Add(new
                    {
                        name = file.Name,
                        path = file.FullName,
                        isDirectory = false,
                        size = file.Length,
                        lastModified = (DateTimeOffset)file.LastWriteTimeUtc
                    });
                }

                return Results.Ok(entries);
            }
            catch (Exception ex)
            {
                _logger.Error($"Error listing directory {path}: {ex.Message}");
                return Results.Problem("Directory listing failed or access denied");
            }
        });

        _app.MapGet("/api/fs/download", async (string path, HttpContext context) =>
        {
            if (!await _transferThrottle.WaitAsync(TimeSpan.FromSeconds(5)))
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            try
            {
                if (!TryGetValidPath(path, out var fullPath) || !File.Exists(fullPath))
                {
                    return Results.NotFound("File not found or access restricted");
                }

                var fi = new FileInfo(fullPath);
                if (fi.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    return Results.BadRequest("Access to reparse points is denied");
                }

                string hashHex = ComputeSha512Hex(fullPath);
                context.Response.Headers["X-Tether-File-SHA512"] = hashHex;

                return Results.File(fullPath, "application/octet-stream", enableRangeProcessing: true);
            }
            catch (Exception ex)
            {
                _logger.Error($"Error downloading {path}: {ex.Message}");
                return Results.Problem("File download failed");
            }
            finally
            {
                _transferThrottle.Release();
            }
        });

        _app.MapPost("/api/fs/upload", async (string path, HttpContext context) =>
        {
            if (!await _transferThrottle.WaitAsync(TimeSpan.FromSeconds(5)))
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            string tempPath = "";
            try
            {
                if (!TryGetValidPath(path, out var fullPath, isUpload: true))
                {
                    return Results.BadRequest("Destination path is invalid, restricted, or traverses a reparse point");
                }

                // Disallow overwriting read-only, hidden, or reparse point files
                if (File.Exists(fullPath))
                {
                    var existingAttrs = File.GetAttributes(fullPath);
                    if ((existingAttrs & FileAttributes.ReparsePoint) != 0 ||
                        (existingAttrs & FileAttributes.ReadOnly) != 0 ||
                        (existingAttrs & FileAttributes.System) != 0)
                    {
                        return Results.BadRequest("Cannot overwrite protected or reparse destination file");
                    }
                }

                // Check free space on target volume
                string? root = Path.GetPathRoot(fullPath);
                if (!string.IsNullOrEmpty(root))
                {
                    var drive = new DriveInfo(root);
                    if (drive.IsReady)
                    {
                        long expectedLength = context.Request.ContentLength ?? 0L;
                        long requiredSpace = expectedLength + MinimumDiskBufferBytes;
                        if (drive.AvailableFreeSpace < requiredSpace)
                        {
                            _logger.Warning($"Upload rejected: Insufficient disk space on drive {drive.Name}.");
                            return Results.StatusCode(StatusCodes.Status507InsufficientStorage);
                        }
                    }
                }

                string expectedHashHex = context.Request.Headers["X-Tether-File-SHA512"].ToString().Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(expectedHashHex) || expectedHashHex.Length != 128 || !expectedHashHex.All(Uri.IsHexDigit))
                {
                    return Results.BadRequest("Missing or malformed required header: X-Tether-File-SHA512");
                }

                var dir = Path.GetDirectoryName(fullPath);
                if (dir != null && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                tempPath = fullPath + $".tether_tmp_{Guid.NewGuid():N}";
                if (!TryGetValidPath(tempPath, out _, isUpload: true))
                {
                    return Results.BadRequest("Temporary upload path is invalid or restricted");
                }

                using (var sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
                using (var tempStream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true))
                {
                    var buffer = new byte[81920];
                    int bytesRead;
                    long totalBytesRead = 0L;

                    while ((bytesRead = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length, context.RequestAborted)) > 0)
                    {
                        totalBytesRead += bytesRead;
                        if (totalBytesRead > MaxUploadSizeBytes)
                        {
                            try { File.Delete(tempPath); } catch { }
                            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                        }

                        await tempStream.WriteAsync(buffer, 0, bytesRead, context.RequestAborted);
                        sha512.AppendData(buffer, 0, bytesRead);
                    }

                    byte[] actualHash = sha512.GetHashAndReset();
                    string actualHashHex = Convert.ToHexString(actualHash).ToLowerInvariant();

                    if (!string.Equals(expectedHashHex, actualHashHex, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.Warning($"SHA-512 check failed for upload to {fullPath}. Expected: {expectedHashHex}, Actual: {actualHashHex}");
                        try { File.Delete(tempPath); } catch { }
                        return Results.BadRequest("Integrity check failed: SHA-512 mismatch");
                    }
                }

                if (!TryGetValidPath(fullPath, out _, isUpload: true))
                {
                    try { File.Delete(tempPath); } catch { }
                    return Results.BadRequest("Destination path failed revalidation");
                }

                if (File.Exists(fullPath))
                {
                    var destAttrs = File.GetAttributes(fullPath);
                    if ((destAttrs & (FileAttributes.ReparsePoint | FileAttributes.ReadOnly | FileAttributes.System)) != 0)
                    {
                        try { File.Delete(tempPath); } catch { }
                        return Results.BadRequest("Cannot overwrite protected or reparse destination file");
                    }
                }

                if ((File.GetAttributes(tempPath) & FileAttributes.ReparsePoint) != 0)
                {
                    try { File.Delete(tempPath); } catch { }
                    return Results.BadRequest("Temporary file became a reparse point");
                }

                File.Move(tempPath, fullPath, overwrite: true);
                return Results.Ok();
            }
            catch (OperationCanceledException)
            {
                if (!string.IsNullOrEmpty(tempPath) && File.Exists(tempPath))
                {
                    try { File.Delete(tempPath); } catch { }
                }
                return Results.StatusCode(StatusCodes.Status408RequestTimeout);
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrEmpty(tempPath) && File.Exists(tempPath))
                {
                    try { File.Delete(tempPath); } catch { }
                }
                _logger.Error($"Error uploading {path}: {ex.Message}");
                return Results.Problem("File upload failed");
            }
            finally
            {
                _transferThrottle.Release();
            }
        });

        // Remote proxy endpoints
        _app.MapPost("/api/fs/remote/list", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var reqJson = await reader.ReadToEndAsync();
            var path = "";
            try { path = JsonDocument.Parse(reqJson).RootElement.GetProperty("path").GetString(); } catch { }

            string reqId = Guid.NewGuid().ToString();
            var tcs = new TaskCompletionSource<string>();
            _pendingRequests[reqId] = tcs;

            _sessionManager.BroadcastRawFrame(JsonSerializer.Serialize(new { type = "FS_LIST", requestId = reqId, path = path }));

            var completedTask = await Task.WhenAny(tcs.Task, Task.Delay(5000));
            if (completedTask == tcs.Task)
            {
                var resultJson = await tcs.Task;
                try
                {
                    var items = JsonDocument.Parse(resultJson).RootElement.GetProperty("items");
                    return Results.Content(items.GetRawText(), "application/json");
                }
                catch { return Results.Ok(new object[0]); }
            }
            else
            {
                _pendingRequests.TryRemove(reqId, out _);
                return Results.Problem("Timeout waiting for Android");
            }
        });

        _app.MapPost("/api/fs/remote/download", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var reqJson = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(reqJson).RootElement;
            var remotePath = doc.GetProperty("remotePath").GetString() ?? "";
            var localDir = doc.GetProperty("localDir").GetString() ?? "";

            string reqId = Guid.NewGuid().ToString();
            var tcs = new TaskCompletionSource<string>();
            _pendingRequests[reqId] = tcs;

            var activeDevice = _sessionManager.GetActiveSessions().Select(s => s.Device).FirstOrDefault(d => d != null);
            string targetFingerprint = activeDevice?.Fingerprint ?? "";
            var token = _tokenStore.GenerateToken(TimeSpan.FromMinutes(10), targetFingerprint);
            var fileName = Path.GetFileName(remotePath);
            var windowsDestPath = Path.Combine(localDir, fileName);

            _sessionManager.BroadcastRawFrame(JsonSerializer.Serialize(new
            {
                type = "FS_SEND_FILE",
                requestId = reqId,
                androidPath = remotePath,
                windowsDestPath = windowsDestPath,
                token = token
            }));
            return Results.Ok();
        });

        _app.MapPost("/api/fs/remote/upload", async (HttpContext context) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            var reqJson = await reader.ReadToEndAsync();
            var doc = JsonDocument.Parse(reqJson).RootElement;
            var localPath = doc.GetProperty("localPath").GetString() ?? "";
            var remoteDir = doc.GetProperty("remoteDir").GetString() ?? "";

            string reqId = Guid.NewGuid().ToString();
            var tcs = new TaskCompletionSource<string>();
            _pendingRequests[reqId] = tcs;

            var activeDevice = _sessionManager.GetActiveSessions().Select(s => s.Device).FirstOrDefault(d => d != null);
            string targetFingerprint = activeDevice?.Fingerprint ?? "";
            var token = _tokenStore.GenerateToken(TimeSpan.FromMinutes(10), targetFingerprint);
            var fileName = Path.GetFileName(localPath);

            _sessionManager.BroadcastRawFrame(JsonSerializer.Serialize(new
            {
                type = "FS_RECEIVE_FILE",
                requestId = reqId,
                windowsPath = localPath,
                fileName = fileName,
                token = token
            }));
            return Results.Ok();
        });

        // Remote Desktop Streaming Endpoint (MJPEG)
        _app.MapGet("/api/desktop/stream", async (HttpContext context, int? fps, int? quality) =>
        {
            context.Response.Headers["Content-Type"] = "multipart/x-mixed-replace; boundary=--frame";
            context.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            context.Response.Headers["Connection"] = "close";

            int targetFps = Math.Clamp(fps ?? 15, 1, 30);
            int targetQual = Math.Clamp(quality ?? 50, 10, 90);

            _inputForwarder.PostToHelper(new { type = "START_SCREEN_STREAM", fps = targetFps, quality = targetQual });

            var stream = context.Response.Body;
            var frameChannel = System.Threading.Channels.Channel.CreateBounded<byte[]>(
                new System.Threading.Channels.BoundedChannelOptions(2) { FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest });

            Action<string> onFrame = b64 =>
            {
                try
                {
                    byte[] bytes = Convert.FromBase64String(b64);
                    frameChannel.Writer.TryWrite(bytes);
                }
                catch { }
            };

            _inputForwarder.OnDesktopFrameReceived += onFrame;

            try
            {
                while (!context.RequestAborted.IsCancellationRequested)
                {
                    var frame = await frameChannel.Reader.ReadAsync(context.RequestAborted);
                    var header = Encoding.ASCII.GetBytes($"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {frame.Length}\r\n\r\n");
                    await stream.WriteAsync(header, context.RequestAborted);
                    await stream.WriteAsync(frame, context.RequestAborted);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), context.RequestAborted);
                    await stream.FlushAsync(context.RequestAborted);
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                _inputForwarder.OnDesktopFrameReceived -= onFrame;
                _inputForwarder.PostToHelper(new { type = "STOP_SCREEN_STREAM" });
            }
        });

        // Remote Desktop Screenshot Endpoint
        _app.MapGet("/api/desktop/screenshot", async (HttpContext context, long? windowId, int? quality) =>
        {
            string reqId = Guid.NewGuid().ToString("N");
            int q = Math.Clamp(quality ?? 75, 10, 100);
            string? resJson = await _inputForwarder.RequestAsync(
                new { type = "SCREENSHOT_REQUEST", hwnd = windowId ?? 0L, quality = q, requestId = reqId },
                reqId,
                TimeSpan.FromSeconds(5),
                context.RequestAborted);

            if (resJson != null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(resJson);
                    string b64 = doc.RootElement.TryGetProperty("imageB64", out var imgProp) ? (imgProp.GetString() ?? "") : "";
                    if (!string.IsNullOrEmpty(b64))
                    {
                        byte[] bytes = Convert.FromBase64String(b64);
                        return Results.File(bytes, "image/jpeg");
                    }
                }
                catch { }
            }
            return Results.Problem("Screenshot capture failed or timed out.");
        });

        // Active Windows List Endpoint
        _app.MapGet("/api/desktop/windows", async (HttpContext context) =>
        {
            string reqId = Guid.NewGuid().ToString("N");
            string? resJson = await _inputForwarder.RequestAsync(
                new { type = "WINDOWS_LIST_REQUEST", requestId = reqId },
                reqId,
                TimeSpan.FromSeconds(5),
                context.RequestAborted);

            if (resJson != null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(resJson);
                    if (doc.RootElement.TryGetProperty("windows", out var windows))
                    {
                        return Results.Content(windows.GetRawText(), "application/json");
                    }
                }
                catch { }
            }
            return Results.Ok(Array.Empty<object>());
        });

        // Installed Applications Catalog Endpoint
        _app.MapGet("/api/apps/catalog", async (HttpContext context) =>
        {
            string reqId = Guid.NewGuid().ToString("N");
            string? resJson = await _inputForwarder.RequestAsync(
                new { type = "APP_GET_INSTALLED", requestId = reqId },
                reqId,
                TimeSpan.FromSeconds(5),
                context.RequestAborted);

            if (resJson != null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(resJson);
                    if (doc.RootElement.TryGetProperty("apps", out var apps))
                    {
                        return Results.Content(apps.GetRawText(), "application/json");
                    }
                }
                catch { }
            }
            return Results.Ok(Array.Empty<object>());
        });

        // Advanced File Search
        _app.MapGet("/api/fs/search", (string? path, string? query, bool? recursive, int? maxResults) =>
        {
            try
            {
                string rootPath = string.IsNullOrWhiteSpace(path)
                    ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                    : path;

                if (!TryGetValidPath(rootPath, out var fullPath) || !Directory.Exists(fullPath))
                {
                    return Results.NotFound(new { error = "Directory not found or access restricted" });
                }

                string q = query?.Trim() ?? "";
                int limit = Math.Clamp(maxResults ?? 100, 1, 500);
                bool isRec = recursive ?? true;
                var results = new List<object>();

                var searchOption = isRec ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                var dirInfo = new DirectoryInfo(fullPath);

                foreach (var file in dirInfo.EnumerateFiles("*", searchOption))
                {
                    if (results.Count >= limit) break;
                    if ((file.Attributes & FileAttributes.ReparsePoint) != 0 || (file.Attributes & FileAttributes.Hidden) != 0) continue;
                    if (IsPathInBlockedPrefix(file.FullName)) continue;

                    if (string.IsNullOrEmpty(q) || file.Name.Contains(q, StringComparison.OrdinalIgnoreCase))
                    {
                        results.Add(new
                        {
                            name = file.Name,
                            path = file.FullName,
                            isDirectory = false,
                            size = file.Length,
                            lastModified = (DateTimeOffset)file.LastWriteTimeUtc
                        });
                    }
                }

                return Results.Ok(results);
            }
            catch (Exception ex)
            {
                _logger.Error($"Search error: {ex.Message}");
                return Results.Problem("Search failed");
            }
        });

        // File Rename
        _app.MapPost("/api/fs/rename", (RenamePayload req) =>
        {
            if (string.IsNullOrWhiteSpace(req.Path) || string.IsNullOrWhiteSpace(req.NewName))
            {
                return Results.BadRequest(new { error = "Missing path or newName" });
            }

            if (req.NewName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                return Results.BadRequest(new { error = "Invalid new file name" });
            }

            if (!TryGetValidPath(req.Path, out var fullPath))
            {
                return Results.BadRequest(new { error = "Invalid path or access restricted" });
            }

            string dir = Path.GetDirectoryName(fullPath) ?? "";
            string newPath = Path.Combine(dir, req.NewName);
            if (!TryGetValidPath(newPath, out var validNewPath, isUpload: true))
            {
                return Results.BadRequest(new { error = "Invalid new path or access restricted" });
            }

            try
            {
                if (File.Exists(fullPath))
                {
                    File.Move(fullPath, validNewPath);
                    return Results.Ok(new { success = true, newPath = validNewPath });
                }
                else if (Directory.Exists(fullPath))
                {
                    Directory.Move(fullPath, validNewPath);
                    return Results.Ok(new { success = true, newPath = validNewPath });
                }
                return Results.NotFound(new { error = "File or directory not found" });
            }
            catch (Exception ex)
            {
                return Results.Problem($"Rename failed: {ex.Message}");
            }
        });

        // File Move
        _app.MapPost("/api/fs/move", (MovePayload req) =>
        {
            if (!TryGetValidPath(req.SourcePath, out var srcPath) || !TryGetValidPath(req.DestinationPath, out var dstPath, isUpload: true))
            {
                return Results.BadRequest(new { error = "Invalid source or destination path" });
            }

            try
            {
                if (File.Exists(srcPath))
                {
                    string finalDst = Directory.Exists(dstPath) ? Path.Combine(dstPath, Path.GetFileName(srcPath)) : dstPath;
                    if (!TryGetValidPath(finalDst, out var validFinalDst, isUpload: true))
                    {
                        return Results.BadRequest(new { error = "Invalid destination path" });
                    }
                    File.Move(srcPath, validFinalDst);
                    return Results.Ok(new { success = true, destination = validFinalDst });
                }
                else if (Directory.Exists(srcPath))
                {
                    string finalDst = Directory.Exists(dstPath) ? Path.Combine(dstPath, Path.GetFileName(srcPath)) : dstPath;
                    if (!TryGetValidPath(finalDst, out var validFinalDst, isUpload: true))
                    {
                        return Results.BadRequest(new { error = "Invalid destination path" });
                    }
                    Directory.Move(srcPath, validFinalDst);
                    return Results.Ok(new { success = true, destination = validFinalDst });
                }
                return Results.NotFound(new { error = "Source not found" });
            }
            catch (Exception ex)
            {
                return Results.Problem($"Move failed: {ex.Message}");
            }
        });

        // File Delete (Recycle Bin / Permanent)
        _app.MapPost("/api/fs/delete", (DeletePayload req) =>
        {
            if (!TryGetValidPath(req.Path, out var fullPath))
            {
                return Results.BadRequest(new { error = "Invalid path or access restricted" });
            }

            try
            {
                if (req.Permanent)
                {
                    if (File.Exists(fullPath)) File.Delete(fullPath);
                    else if (Directory.Exists(fullPath)) Directory.Delete(fullPath, true);
                    else return Results.NotFound(new { error = "Item not found" });
                }
                else
                {
                    var shf = new SHFILEOPSTRUCT
                    {
                        wFunc = FO_DELETE,
                        pFrom = fullPath + '\0' + '\0',
                        fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT
                    };
                    int hr = SHFileOperation(ref shf);
                    if (hr != 0)
                    {
                        return Results.Problem($"Failed to move item to Recycle Bin (error code {hr})");
                    }
                }
                return Results.Ok(new { success = true });
            }
            catch (Exception ex)
            {
                return Results.Problem($"Delete failed: {ex.Message}");
            }
        });

        // Directory Creation
        _app.MapPost("/api/fs/mkdir", (MkdirPayload req) =>
        {
            if (string.IsNullOrWhiteSpace(req.Path) || string.IsNullOrWhiteSpace(req.Name))
            {
                return Results.BadRequest(new { error = "Missing path or name" });
            }

            if (req.Name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                return Results.BadRequest(new { error = "Invalid directory name" });
            }

            if (!TryGetValidPath(req.Path, out var fullPath) || !Directory.Exists(fullPath))
            {
                return Results.BadRequest(new { error = "Invalid parent path" });
            }

            string newDir = Path.Combine(fullPath, req.Name);
            try
            {
                Directory.CreateDirectory(newDir);
                return Results.Ok(new { success = true, path = newDir });
            }
            catch (Exception ex)
            {
                return Results.Problem($"Create directory failed: {ex.Message}");
            }
        });

        // Recycle Bin Empty
        _app.MapPost("/api/fs/recycle-bin/empty", () =>
        {
            try
            {
                SHEmptyRecycleBin(IntPtr.Zero, null, 7);
                return Results.Ok(new { success = true });
            }
            catch (Exception ex)
            {
                return Results.Problem($"Empty recycle bin failed: {ex.Message}");
            }
        });

        // Resumable Chunked Upload
        _app.MapPost("/api/fs/upload-resumable", async (string path, long offset, long totalSize, string? hash, HttpContext context) =>
        {
            if (!await _transferThrottle.WaitAsync(TimeSpan.FromSeconds(5)))
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            try
            {
                if (offset < 0 || totalSize <= 0 || totalSize > MaxUploadSizeBytes)
                {
                    return Results.BadRequest("Invalid offset or totalSize exceeding limits");
                }

                if (!TryGetValidPath(path, out var fullPath, isUpload: true))
                {
                    return Results.BadRequest("Destination path is invalid or restricted");
                }

                string? rootDir = Path.GetPathRoot(fullPath);
                if (!string.IsNullOrEmpty(rootDir))
                {
                    try
                    {
                        var drive = new DriveInfo(rootDir);
                        if (drive.AvailableFreeSpace < totalSize)
                        {
                            return Results.StatusCode(StatusCodes.Status507InsufficientStorage);
                        }
                    }
                    catch { }
                }

                string partPath = fullPath + ".tether_part";
                if (!TryGetValidPath(partPath, out _, isUpload: true))
                {
                    return Results.BadRequest("Part path is invalid or restricted");
                }

                var dir = Path.GetDirectoryName(fullPath);
                if (dir != null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

                if (File.Exists(partPath))
                {
                    var partAttrs = File.GetAttributes(partPath);
                    if ((partAttrs & FileAttributes.ReparsePoint) != 0)
                    {
                        try { File.Delete(partPath); } catch { }
                        return Results.BadRequest("Part file cannot be a reparse point");
                    }
                }

                using (var fs = new FileStream(partPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None))
                {
                    if (offset > fs.Length)
                    {
                        return Results.BadRequest($"Offset {offset} is beyond current part length {fs.Length}");
                    }
                    if (offset < fs.Length)
                    {
                        fs.SetLength(offset);
                    }
                    fs.Seek(offset, SeekOrigin.Begin);
                    await context.Request.Body.CopyToAsync(fs, context.RequestAborted);
                }

                var fi = new FileInfo(partPath);
                if (fi.Length > totalSize)
                {
                    try { File.Delete(partPath); } catch { }
                    return Results.BadRequest("Uploaded data exceeded declared total size");
                }

                if (fi.Length == totalSize)
                {
                    if (string.IsNullOrWhiteSpace(hash))
                    {
                        try { File.Delete(partPath); } catch { }
                        return Results.BadRequest("Hash required for upload completion");
                    }

                    string computed = ComputeSha512Hex(partPath);
                    if (!string.Equals(computed, hash.Trim(), StringComparison.OrdinalIgnoreCase))
                    {
                        try { File.Delete(partPath); } catch { }
                        return Results.BadRequest("Checksum mismatch for completed upload");
                    }

                    if (!TryGetValidPath(fullPath, out _, isUpload: true))
                    {
                        try { File.Delete(partPath); } catch { }
                        return Results.BadRequest("Destination path failed revalidation");
                    }

                    if (File.Exists(fullPath))
                    {
                        var targetFi = new FileInfo(fullPath);
                        if ((targetFi.Attributes & (FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.ReparsePoint | FileAttributes.System)) != 0)
                        {
                            try { File.Delete(partPath); } catch { }
                            return Results.BadRequest("Destination file is read-only, hidden, or reparse point");
                        }
                    }

                    if ((File.GetAttributes(partPath) & FileAttributes.ReparsePoint) != 0)
                    {
                        try { File.Delete(partPath); } catch { }
                        return Results.BadRequest("Part file became a reparse point");
                    }

                    File.Move(partPath, fullPath, overwrite: true);
                    return Results.Ok(new { completed = true, totalSize = fi.Length });
                }

                return Results.Ok(new { completed = false, currentOffset = fi.Length });
            }
            catch (Exception ex)
            {
                return Results.Problem($"Chunk upload failed: {ex.Message}");
            }
            finally
            {
                _transferThrottle.Release();
            }
        });

        await _app.StartAsync(cancellationToken);
        _logger.Info("FileTransferServer started on port 37124.");
    }

    public static string ComputeSha512Hex(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        byte[] hash = SHA512.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_app != null)
        {
            await _app.StopAsync(cancellationToken);
            await _app.DisposeAsync();
            _logger.Info("FileTransferServer stopped.");
        }
    }
}

public sealed class RenamePayload
{
    public string Path { get; set; } = string.Empty;
    public string NewName { get; set; } = string.Empty;
}

public sealed class MovePayload
{
    public string SourcePath { get; set; } = string.Empty;
    public string DestinationPath { get; set; } = string.Empty;
}

public sealed class DeletePayload
{
    public string Path { get; set; } = string.Empty;
    public bool Permanent { get; set; }
}

public sealed class MkdirPayload
{
    public string Path { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}
