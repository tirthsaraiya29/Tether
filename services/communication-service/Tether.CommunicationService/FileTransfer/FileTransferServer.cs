using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Transport;
using Tether.CommunicationService.Trust;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Tether.Shared.Network;

namespace Tether.CommunicationService.FileTransfer;

public class FileTransferServer : IHostedService
{
    private const long MaxUploadSizeBytes = 4L * 1024L * 1024L * 1024L; // 4 GB per transfer
    internal const int MaxJsonPayloadSizeBytes = 64 * 1024;               // 64 KB limit for JSON control payloads
    private const long MinimumDiskBufferBytes = 250L * 1024L * 1024L;   // 250 MB free space safety margin
    private const int MaxConcurrentTransfers = 4;

    internal static async Task<(bool Success, string? Content, IResult? ErrorResult)> ReadBoundedJsonBodyAsync(HttpContext context, int maxBytes = MaxJsonPayloadSizeBytes)
    {
        var maxBodyFeature = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
        if (maxBodyFeature != null && !maxBodyFeature.IsReadOnly)
        {
            maxBodyFeature.MaxRequestBodySize = maxBytes;
        }

        if (context.Request.ContentLength.HasValue && context.Request.ContentLength.Value > maxBytes)
        {
            return (false, null, Results.StatusCode(StatusCodes.Status413PayloadTooLarge));
        }

        using var ms = new MemoryStream();
        var buffer = new byte[4096];
        int totalRead = 0;
        int read;
        while ((read = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            totalRead += read;
            if (totalRead > maxBytes)
            {
                return (false, null, Results.StatusCode(StatusCodes.Status413PayloadTooLarge));
            }
            ms.Write(buffer, 0, read);
        }

        return (true, Encoding.UTF8.GetString(ms.ToArray()), null);
    }

    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly TokenStore _tokenStore;
    private readonly SessionManager _sessionManager;
    private readonly TrustStore _trustStore;
    private readonly Tether.CommunicationService.Transport.InputForwarder _inputForwarder;
    private readonly IEventBus? _eventBus;
    private WebApplication? _app;

    private static readonly SemaphoreSlim _transferThrottle = new(MaxConcurrentTransfers, MaxConcurrentTransfers);

    internal sealed class PendingRemoteRequest
    {
        public required string RequestId { get; init; }
        public required TaskCompletionSource<string> Tcs { get; init; }
        public required string ExpectedSessionId { get; init; }
        public required string ExpectedFingerprint { get; init; }
        public required string ExpectedOperation { get; init; }
        public required DateTime CreatedAtUtc { get; init; }
        public CancellationTokenRegistration CancellationTokenRegistration { get; init; }
    }

    private static readonly ConcurrentDictionary<string, PendingRemoteRequest> _pendingRequests = new();

    internal static void RegisterPendingRequest(string requestId, PendingRemoteRequest request) => _pendingRequests[requestId] = request;
    internal static bool HasPendingRequest(string requestId) => _pendingRequests.ContainsKey(requestId);
    internal static void ClearPendingRequestsForTest() => _pendingRequests.Clear();

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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int FileInformationClass,
        IntPtr lpFileInformation,
        uint dwBufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint dwVolumeSerialNumber;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint nNumberOfLinks;
        public uint nFileIndexHigh;
        public uint nFileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DISPOSITION_INFO
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
    }

    private const int FileRenameInfo = 3;
    private const int FileDispositionInfo = 4;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint DELETE = 0x00010000;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint FILE_LIST_DIRECTORY = 0x0001;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint FILE_SHARE_NONE = 0x00000000;
    private const uint CREATE_NEW = 1;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_NAME_NORMALIZED = 0x0;

    public static string? GetFinalResolvedPath(SafeFileHandle handle)
    {
        if (handle.IsInvalid || handle.IsClosed)
        {
            return null;
        }

        var sb = new StringBuilder(1024);
        uint result = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, FILE_NAME_NORMALIZED);
        if (result >= sb.Capacity)
        {
            sb.EnsureCapacity((int)result + 1);
            result = GetFinalPathNameByHandle(handle, sb, (uint)sb.Capacity, FILE_NAME_NORMALIZED);
        }

        if (result == 0)
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

        return GetFinalResolvedPath(handle);
    }

    public static bool PromoteFileHandle(SafeFileHandle handle, string destinationFullPath, bool replaceIfExists = true)
    {
        if (handle.IsInvalid || handle.IsClosed)
        {
            return false;
        }

        int nameByteLen = destinationFullPath.Length * sizeof(char);
        int bufferSize = 20 + nameByteLen + sizeof(char);
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            for (int i = 0; i < bufferSize; i++)
            {
                Marshal.WriteByte(buffer, i, 0);
            }

            // ReplaceIfExists (1 = true, 0 = false)
            Marshal.WriteByte(buffer, 0, (byte)(replaceIfExists ? 1 : 0));
            // RootDirectory = IntPtr.Zero (offsets 8..15 already zero)
            // FileNameLength in bytes
            Marshal.WriteInt32(buffer, 16, nameByteLen);
            // FileName Unicode characters starting at offset 20
            IntPtr destNamePtr = IntPtr.Add(buffer, 20);
            char[] chars = destinationFullPath.ToCharArray();
            Marshal.Copy(chars, 0, destNamePtr, chars.Length);

            return SetFileInformationByHandle(handle, FileRenameInfo, buffer, (uint)bufferSize);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static bool DeleteHandle(SafeFileHandle handle)
    {
        if (handle.IsInvalid || handle.IsClosed)
        {
            return false;
        }

        var dispInfo = new FILE_DISPOSITION_INFO { DeleteFile = true };
        int size = Marshal.SizeOf(dispInfo);
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(dispInfo, ptr, false);
            return SetFileInformationByHandle(handle, FileDispositionInfo, ptr, (uint)size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    public static bool ValidateHandleSecurity(
        SafeFileHandle handle,
        string? expectedRootDirectory,
        uint? expectedVolumeSerial,
        out string resolvedPath,
        out uint volumeSerialNumber,
        bool allowReparsePoint = false)
    {
        resolvedPath = string.Empty;
        volumeSerialNumber = 0;

        if (handle == null || handle.IsInvalid || handle.IsClosed)
        {
            return false;
        }

        if (!GetFileInformationByHandle(handle, out var info))
        {
            return false;
        }

        volumeSerialNumber = info.dwVolumeSerialNumber;

        if (!allowReparsePoint && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            return false;
        }

        if (expectedVolumeSerial.HasValue && volumeSerialNumber != expectedVolumeSerial.Value)
        {
            return false;
        }

        string? finalPath = GetFinalResolvedPath(handle);
        if (string.IsNullOrEmpty(finalPath))
        {
            return false;
        }

        if (finalPath.StartsWith(@"\\") || finalPath.StartsWith("//"))
        {
            return false;
        }

        if (IsPathInBlockedPrefix(finalPath) || IsCrossUserProfileAccess(finalPath))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(expectedRootDirectory))
        {
            try
            {
                string expectedRootWithSep = Path.GetFullPath(expectedRootDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
                string finalPathWithSep = Path.GetFullPath(finalPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

                if (!finalPathWithSep.StartsWith(expectedRootWithSep, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(Path.GetFullPath(finalPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                                  Path.GetFullPath(expectedRootDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                                  StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        if (!allowReparsePoint && HasReparsePointInHierarchy(finalPath))
        {
            return false;
        }

        resolvedPath = finalPath;
        return true;
    }

    public static bool DeleteDirectoryRecursiveSafe(string directoryPath, string rootBoundaryPath, uint expectedVolumeSerial)
    {
        string[] entries;
        try
        {
            entries = Directory.GetFileSystemEntries(directoryPath);
        }
        catch
        {
            return false;
        }

        foreach (var entry in entries)
        {
            SafeFileHandle hChild = CreateFile(
                entry,
                DELETE | FILE_LIST_DIRECTORY | GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero);

            if (hChild.IsInvalid)
            {
                hChild = CreateFile(
                    entry,
                    DELETE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    IntPtr.Zero);
            }

            if (hChild.IsInvalid)
            {
                return false;
            }

            if (!GetFileInformationByHandle(hChild, out var childInfo))
            {
                hChild.Dispose();
                return false;
            }

            bool isReparse = (childInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
            bool isDir = (childInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

            if ((childInfo.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0)
            {
                try { File.SetAttributes(entry, (FileAttributes)(childInfo.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY)); } catch { }
            }

            if (isReparse)
            {
                if (!ValidateHandleSecurity(hChild, rootBoundaryPath, expectedVolumeSerial, out _, out _, allowReparsePoint: true))
                {
                    hChild.Dispose();
                    return false;
                }

                bool deleted = DeleteHandle(hChild);
                hChild.Dispose();
                if (!deleted) return false;
            }
            else if (isDir)
            {
                if (!ValidateHandleSecurity(hChild, rootBoundaryPath, expectedVolumeSerial, out string childResolved, out _, allowReparsePoint: false))
                {
                    hChild.Dispose();
                    return false;
                }

                hChild.Dispose();
                if (!DeleteDirectoryRecursiveSafe(childResolved, rootBoundaryPath, expectedVolumeSerial))
                {
                    return false;
                }
            }
            else
            {
                if (!ValidateHandleSecurity(hChild, rootBoundaryPath, expectedVolumeSerial, out _, out _, allowReparsePoint: false))
                {
                    hChild.Dispose();
                    return false;
                }

                bool deleted = DeleteHandle(hChild);
                hChild.Dispose();
                if (!deleted) return false;
            }
        }

        using var hDir = CreateFile(
            directoryPath,
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);

        if (hDir.IsInvalid)
        {
            return false;
        }

        if (!ValidateHandleSecurity(hDir, rootBoundaryPath, expectedVolumeSerial, out _, out _, allowReparsePoint: true))
        {
            return false;
        }

        return DeleteHandle(hDir);
    }

    public static bool IsValidFingerprint(string? fp)
    {
        if (string.IsNullOrWhiteSpace(fp)) return false;
        fp = fp.Trim();
        if (fp.Length == 95 && fp.Count(c => c == ':') == 31)
        {
            var parts = fp.Split(':');
            return parts.Length == 32 && parts.All(p => p.Length == 2 && p.All(Uri.IsHexDigit));
        }
        if (fp.Length == 64 && fp.All(Uri.IsHexDigit))
        {
            return true;
        }
        return false;
    }
    #endregion

    public FileTransferServer(
        ITetherLogger logger,
        WindowsIdentity identity,
        TokenStore tokenStore,
        SessionManager sessionManager,
        TrustStore trustStore,
        Tether.CommunicationService.Transport.InputForwarder inputForwarder,
        IEventBus? eventBus = null)
    {
        _logger = logger;
        _identity = identity;
        _tokenStore = tokenStore;
        _sessionManager = sessionManager;
        _trustStore = trustStore;
        _inputForwarder = inputForwarder;
        _eventBus = eventBus;
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
            normalizedPath.Contains("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("TetherUpdate", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("TetherE2E_Staging", StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.Contains("Tether_Staging", StringComparison.OrdinalIgnoreCase))
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

            try
            {
                using var profileListKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
                if (profileListKey != null)
                {
                    var profilesDirVal = profileListKey.GetValue("ProfilesDirectory") as string;
                    if (!string.IsNullOrEmpty(profilesDirVal))
                    {
                        profilesDirVal = Environment.ExpandEnvironmentVariables(profilesDirVal).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                        if (normalizedPath.StartsWith(profilesDirVal, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }

                    foreach (var subKeyName in profileListKey.GetSubKeyNames())
                    {
                        using var subKey = profileListKey.OpenSubKey(subKeyName);
                        if (subKey?.GetValue("ProfileImagePath") is string rawPath && !string.IsNullOrWhiteSpace(rawPath))
                        {
                            string profilePath = Environment.ExpandEnvironmentVariables(rawPath);
                            if (string.Equals(profilePath, activeProfile, StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }
                            string profPrefix = profilePath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                            if (normalizedPath.StartsWith(profPrefix, StringComparison.OrdinalIgnoreCase) ||
                                normalizedPath.Equals(profilePath, StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }

            if (normalizedPath.StartsWith(usersPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
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

            // Block dot-dot path traversal sequences and DOS device reserved names in segments
            var segments = inputPath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var seg in segments)
            {
                if (seg == "..")
                {
                    return false;
                }

                string segBase = Path.GetFileNameWithoutExtension(seg);
                if (ReservedDeviceNames.Contains(seg) || ReservedDeviceNames.Contains(segBase))
                {
                    return false;
                }
            }

            var normalized = Path.GetFullPath(inputPath);
            if (!Path.IsPathRooted(normalized) || normalized.StartsWith(@"\\"))
            {
                return false;
            }

            // Block DOS device reserved names on normalized name
            string fileName = Path.GetFileNameWithoutExtension(normalized);
            if (ReservedDeviceNames.Contains(fileName) || ReservedDeviceNames.Contains(Path.GetFileName(normalized)))
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

    public static void CancelPendingRequestsForSession(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return;

        foreach (var kvp in _pendingRequests)
        {
            if (string.Equals(kvp.Value.ExpectedSessionId, sessionId, StringComparison.Ordinal))
            {
                if (_pendingRequests.TryRemove(kvp.Key, out var pending))
                {
                    try { pending.CancellationTokenRegistration.Dispose(); } catch { }
                    pending.Tcs.TrySetException(new IOException("Device session disconnected"));
                }
            }
        }
    }

    public static bool HandleRemoteResponse(string type, string rawJson, string? callerFingerprint, string? callerSessionId)
    {
        if (string.IsNullOrWhiteSpace(callerFingerprint) || !IsValidFingerprint(callerFingerprint))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(callerSessionId))
        {
            return false;
        }

        string requestId = "";
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            if (doc.RootElement.TryGetProperty("requestId", out var reqProp))
            {
                requestId = reqProp.GetString() ?? "";
            }
        }
        catch
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(requestId))
        {
            return false;
        }

        if (!_pendingRequests.TryGetValue(requestId, out var pending))
        {
            return false;
        }

        if (!string.Equals(pending.ExpectedSessionId, callerSessionId, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.Equals(pending.ExpectedFingerprint, callerFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool opMatches = pending.ExpectedOperation switch
        {
            "FS_LIST" => string.Equals(type, "FS_LIST_RESULT", StringComparison.OrdinalIgnoreCase),
            "FS_SEND_FILE" => string.Equals(type, "FS_DOWNLOAD_RESULT", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(type, "FS_TRANSFER_STATUS", StringComparison.OrdinalIgnoreCase),
            "FS_RECEIVE_FILE" => string.Equals(type, "FS_UPLOAD_RESULT", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(type, "FS_TRANSFER_STATUS", StringComparison.OrdinalIgnoreCase),
            _ => string.Equals(type, pending.ExpectedOperation, StringComparison.OrdinalIgnoreCase)
        };

        if (!opMatches)
        {
            return false;
        }

        if (!_pendingRequests.TryRemove(requestId, out var consumed))
        {
            return false;
        }

        try { consumed.CancellationTokenRegistration.Dispose(); } catch { }
        consumed.Tcs.TrySetResult(rawJson);
        return true;
    }

    private IResult? TryResolveTargetSession(
        JsonElement root,
        out TetherSession? targetSession,
        out string targetFingerprint)
    {
        targetSession = null;
        targetFingerprint = string.Empty;

        string? targetDevice = null;
        bool hasTargetSpecified = false;

        if (root.TryGetProperty("fingerprint", out var fProp))
        {
            hasTargetSpecified = true;
            targetDevice = fProp.GetString();
            if (string.IsNullOrWhiteSpace(targetDevice) || !IsValidFingerprint(targetDevice))
            {
                return Results.BadRequest(new { error = "Invalid, missing, or malformed device fingerprint" });
            }
        }
        else if (root.TryGetProperty("deviceId", out var dProp))
        {
            hasTargetSpecified = true;
            targetDevice = dProp.GetString();
            if (string.IsNullOrWhiteSpace(targetDevice))
            {
                return Results.BadRequest(new { error = "Invalid, missing, or empty deviceId" });
            }
        }

        var pairedSessions = _sessionManager.GetActiveSessions()
            .Where(s => s.Device != null && s.Device.TrustState == DeviceTrustState.Paired)
            .ToList();

        if (hasTargetSpecified)
        {
            targetSession = pairedSessions.FirstOrDefault(s =>
                string.Equals(s.Device?.Fingerprint, targetDevice, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s.Device?.DeviceId, targetDevice, StringComparison.OrdinalIgnoreCase));

            if (targetSession?.Device == null)
            {
                return Results.NotFound(new { error = "No connected companion device matching target" });
            }
        }
        else
        {
            if (pairedSessions.Count == 0)
            {
                return Results.NotFound(new { error = "No connected companion device available" });
            }
            if (pairedSessions.Count > 1)
            {
                return Results.BadRequest(new { error = "Ambiguous target: multiple devices connected. Explicit deviceId or fingerprint required." });
            }
            targetSession = pairedSessions[0];
        }

        targetFingerprint = targetSession.Device!.Fingerprint;
        return null;
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

            options.ListenAnyIP(NetworkConstants.FileTransferPort, listenOptions =>
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

                using var hDir = CreateFile(
                    fullPath,
                    FILE_LIST_DIRECTORY | GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (hDir.IsInvalid || !ValidateHandleSecurity(hDir, null, null, out var resolvedDirPath, out _, allowReparsePoint: false))
                {
                    return Results.NotFound(new { error = "Directory not found or access restricted" });
                }

                var dirInfo = new DirectoryInfo(resolvedDirPath);
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

                var handle = CreateFile(
                    fullPath,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    return Results.NotFound("File not found or access restricted");
                }

                if (!ValidateHandleSecurity(handle, null, null, out string resolvedPath, out _, allowReparsePoint: false))
                {
                    handle.Dispose();

                    return Results.BadRequest("Access denied: File failed target resolution or points to a restricted location");
                }

                if (GetFileInformationByHandle(handle, out var hInfo) && (hInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    handle.Dispose();
                    return Results.BadRequest("Access denied: Cannot download a directory");
                }

                var fs = new FileStream(handle, FileAccess.Read, 81920, isAsync: true);

                long totalBytes = fs.Length;
                byte[] hash = await SHA512.HashDataAsync(fs, context.RequestAborted);
                string hashHex = Convert.ToHexString(hash).ToLowerInvariant();
                fs.Seek(0, SeekOrigin.Begin);

                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = "application/octet-stream";
                context.Response.ContentLength = totalBytes;
                context.Response.Headers["X-Tether-File-SHA512"] = hashHex;

                long totalSent = 0L;
                var sw = Stopwatch.StartNew();
                long lastProgressTick = 0;
                string fileName = Path.GetFileName(resolvedPath);

                await using (fs)
                {
                    byte[] buffer = new byte[81920];
                    int bytesRead;
                    while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length, context.RequestAborted)) > 0)
                    {
                        await context.Response.Body.WriteAsync(buffer.AsMemory(0, bytesRead), context.RequestAborted);
                        totalSent += bytesRead;

                        long nowMs = sw.ElapsedMilliseconds;
                        if (nowMs - lastProgressTick >= 250 || totalSent >= totalBytes)
                        {
                            lastProgressTick = nowMs;
                            double elapsedSec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                            long speedBps = (long)(totalSent / elapsedSec);
                            long etaSec = (speedBps > 0 && totalBytes > totalSent) ? (totalBytes - totalSent) / speedBps : 0L;

                            _eventBus?.Publish(new TetherEvent
                            {
                                EventType = TetherEventType.FILE_TRANSFER_PROGRESS,
                                PayloadJson = JsonSerializer.Serialize(new FileTransferProgressPayload
                                {
                                    FileName = fileName,
                                    BytesTransferred = totalSent,
                                    TotalBytes = totalBytes,
                                    SpeedBps = speedBps,
                                    EtaSec = etaSec,
                                    IsUpload = true
                                })
                            });
                        }
                    }
                    await context.Response.Body.FlushAsync(context.RequestAborted);
                }

                _eventBus?.Publish(new TetherEvent
                {
                    EventType = TetherEventType.FILE_TRANSFER_COMPLETED,
                    PayloadJson = JsonSerializer.Serialize(new FileTransferProgressPayload
                    {
                        FileName = fileName,
                        SavedPath = fullPath,
                        TotalBytes = totalSent,
                        IsUpload = true
                    })
                });

                _inputForwarder.PostToHelper(new
                {
                    type = "NOTIFICATION_SHOW_DESKTOP",
                    title = "File Sent to Phone",
                    body = $"{fileName} was sent to your phone",
                    app = "Tether File Transfer"
                });

                return Results.Empty;
            }
            catch (OperationCanceledException)
            {
                return Results.Empty;
            }
            catch (Exception ex)
            {
                _logger.Error($"Error downloading {path}: {ex.Message}");
                _eventBus?.Publish(new TetherEvent
                {
                    EventType = TetherEventType.FILE_TRANSFER_FAILED,
                    PayloadJson = JsonSerializer.Serialize(new FileTransferProgressPayload
                    {
                        FileName = Path.GetFileName(path),
                        Error = ex.Message,
                        IsUpload = true
                    })
                });
                if (!context.Response.HasStarted)
                {
                    return Results.Problem("File download failed");
                }
                return Results.Empty;
            }
            finally
            {
                _transferThrottle.Release();
            }
        });

        _app.MapPost("/api/fs/upload", async (string? path, HttpContext context) =>
        {
            if (!await _transferThrottle.WaitAsync(TimeSpan.FromSeconds(5)))
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }

            string tempPath = "";
            try
            {
                string fileNameHeader = context.Request.Headers["X-Tether-File-Name"].ToString().Trim();
                if (string.IsNullOrWhiteSpace(path))
                {
                    string safeName = !string.IsNullOrWhiteSpace(fileNameHeader)
                        ? Path.GetFileName(fileNameHeader)
                        : $"tether_received_{DateTime.Now:yyyyMMdd_HHmmss}";
                    string? activeProfile = Tether.CommunicationService.Capabilities.LaptopStateCollector.GetActiveConsoleUserProfilePath();
                    if (string.IsNullOrEmpty(activeProfile) || !Directory.Exists(activeProfile))
                    {
                        activeProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    }
                    string downloadsDir = Path.Combine(activeProfile, "Downloads");
                    if (!Directory.Exists(downloadsDir)) Directory.CreateDirectory(downloadsDir);
                    path = Path.Combine(downloadsDir, safeName);
                }
                else if (Directory.Exists(path))
                {
                    string safeName = !string.IsNullOrWhiteSpace(fileNameHeader)
                        ? Path.GetFileName(fileNameHeader)
                        : $"tether_received_{DateTime.Now:yyyyMMdd_HHmmss}";
                    path = Path.Combine(path, safeName);
                }

                if (!TryGetValidPath(path, out var fullPath, isUpload: true))
                {
                    return Results.BadRequest("Destination path is invalid, restricted, or traverses a reparse point");
                }

                if (Directory.Exists(fullPath))
                {
                    string safeName = !string.IsNullOrWhiteSpace(fileNameHeader)
                        ? Path.GetFileName(fileNameHeader)
                        : $"tether_received_{DateTime.Now:yyyyMMdd_HHmmss}";
                    fullPath = Path.Combine(fullPath, safeName);
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

                // Destination pre-validation before creating temp file
                if (!TryGetValidPath(fullPath, out _, isUpload: true))
                {
                    return Results.BadRequest("Destination path failed validation");
                }

                if (HasReparsePointInHierarchy(fullPath))
                {
                    return Results.BadRequest("Destination hierarchy contains reparse points");
                }

                if (File.Exists(fullPath))
                {
                    var destAttrs = File.GetAttributes(fullPath);
                    if ((destAttrs & (FileAttributes.ReparsePoint | FileAttributes.ReadOnly | FileAttributes.System | FileAttributes.Hidden)) != 0)
                    {
                        return Results.BadRequest("Cannot overwrite protected or reparse destination file");
                    }
                }

                var handle = CreateFile(
                    tempPath,
                    GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
                    FILE_SHARE_NONE,
                    IntPtr.Zero,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    _logger.Error($"Failed to create temporary file {tempPath}: Win32 error {err}");
                    return Results.Problem("Failed to create temporary upload file");
                }

                using (handle)
                using (var tempStream = new FileStream(handle, FileAccess.ReadWrite, 81920, false))
                {
                    var buffer = new byte[81920];
                    int bytesRead;
                    long totalBytesRead = 0L;
                    long expectedTotal = context.Request.ContentLength ?? 0L;
                    var sw = Stopwatch.StartNew();
                    long lastProgressTick = 0;
                    string fileName = Path.GetFileName(fullPath);

                    while ((bytesRead = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length, context.RequestAborted)) > 0)
                    {
                        totalBytesRead += bytesRead;
                        if (totalBytesRead > MaxUploadSizeBytes)
                        {
                            tempStream.Dispose();
                            try { File.Delete(tempPath); } catch { }
                            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                        }

                        await tempStream.WriteAsync(buffer, 0, bytesRead, context.RequestAborted);

                        long nowMs = sw.ElapsedMilliseconds;
                        if (nowMs - lastProgressTick >= 250 || (expectedTotal > 0 && totalBytesRead >= expectedTotal))
                        {
                            lastProgressTick = nowMs;
                            double elapsedSec = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                            long speedBps = (long)(totalBytesRead / elapsedSec);
                            long etaSec = (speedBps > 0 && expectedTotal > totalBytesRead) ? (expectedTotal - totalBytesRead) / speedBps : 0L;

                            _eventBus?.Publish(new TetherEvent
                            {
                                EventType = TetherEventType.FILE_TRANSFER_PROGRESS,
                                PayloadJson = JsonSerializer.Serialize(new FileTransferProgressPayload
                                {
                                    FileName = fileName,
                                    BytesTransferred = totalBytesRead,
                                    TotalBytes = expectedTotal,
                                    SpeedBps = speedBps,
                                    EtaSec = etaSec,
                                    IsUpload = false
                                })
                            });
                        }
                    }

                    await tempStream.FlushAsync(context.RequestAborted);

                    // Verify content hash directly from open locked handle
                    tempStream.Seek(0, SeekOrigin.Begin);
                    using var sha512 = SHA512.Create();
                    byte[] actualHash = sha512.ComputeHash(tempStream);
                    string actualHashHex = Convert.ToHexString(actualHash).ToLowerInvariant();

                    if (!string.Equals(expectedHashHex, actualHashHex, StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.Warning($"SHA-512 check failed for upload to {fullPath}. Expected: {expectedHashHex}, Actual: {actualHashHex}");
                        tempStream.Dispose();
                        try { File.Delete(tempPath); } catch { }
                        return Results.BadRequest("Integrity check failed: SHA-512 mismatch");
                    }

                    // Reparse-point and symlink checks on the open file handle
                    if (!GetFileInformationByHandle(handle, out var handleInfo) ||
                        (handleInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    {
                        tempStream.Dispose();
                        try { File.Delete(tempPath); } catch { }
                        return Results.BadRequest("Temporary file became a reparse point");
                    }

                    string? resolvedTemp = GetFinalResolvedPath(handle);
                    if (resolvedTemp == null || !string.Equals(resolvedTemp, Path.GetFullPath(tempPath), StringComparison.OrdinalIgnoreCase))
                    {
                        tempStream.Dispose();
                        try { File.Delete(tempPath); } catch { }
                        return Results.BadRequest("Temporary file resolved path mismatch or symlink detected");
                    }

                    // Target destination checks immediately prior to promotion while handle remains locked
                    if (!TryGetValidPath(fullPath, out _, isUpload: true))
                    {
                        tempStream.Dispose();
                        try { File.Delete(tempPath); } catch { }
                        return Results.BadRequest("Destination path failed revalidation");
                    }

                    if (HasReparsePointInHierarchy(fullPath))
                    {
                        tempStream.Dispose();
                        try { File.Delete(tempPath); } catch { }
                        return Results.BadRequest("Destination hierarchy contains reparse points");
                    }

                    if (File.Exists(fullPath))
                    {
                        var destAttrs = File.GetAttributes(fullPath);
                        if ((destAttrs & (FileAttributes.ReparsePoint | FileAttributes.ReadOnly | FileAttributes.System | FileAttributes.Hidden)) != 0)
                        {
                            tempStream.Dispose();
                            try { File.Delete(tempPath); } catch { }
                            return Results.BadRequest("Cannot overwrite protected or reparse destination file");
                        }
                    }

                    // Atomically promote the open handle to destination (strictly fail closed, zero copy fallback)
                    if (!PromoteFileHandle(handle, fullPath))
                    {
                        int err = Marshal.GetLastWin32Error();
                        _logger.Error($"Atomic promotion of {tempPath} to {fullPath} failed: Win32 error {err}");
                        tempStream.Dispose();
                        try { File.Delete(tempPath); } catch { }
                        return Results.Problem($"Atomic file promotion failed (Win32 error {err})");
                    }

                    _eventBus?.Publish(new TetherEvent
                    {
                        EventType = TetherEventType.FILE_TRANSFER_COMPLETED,
                        PayloadJson = JsonSerializer.Serialize(new FileTransferProgressPayload
                        {
                            FileName = fileName,
                            SavedPath = fullPath,
                            TotalBytes = totalBytesRead,
                            IsUpload = false
                        })
                    });

                    _inputForwarder.PostToHelper(new
                    {
                        type = "NOTIFICATION_SHOW_DESKTOP",
                        title = "File Received",
                        body = $"{fileName} saved to {fullPath}",
                        app = "Tether File Transfer"
                    });
                }

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
                _eventBus?.Publish(new TetherEvent
                {
                    EventType = TetherEventType.FILE_TRANSFER_FAILED,
                    PayloadJson = JsonSerializer.Serialize(new FileTransferProgressPayload
                    {
                        FileName = Path.GetFileName(path ?? "Upload"),
                        Error = ex.Message,
                        IsUpload = false
                    })
                });
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
            var (success, reqJson, errorResult) = await ReadBoundedJsonBodyAsync(context);
            if (!success) return errorResult!;

            string path = "";
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(reqJson!);
                if (doc.RootElement.TryGetProperty("path", out var pProp))
                {
                    path = pProp.GetString() ?? "";
                }
            }
            catch
            {
                return Results.BadRequest(new { error = "Invalid JSON payload" });
            }

            using (doc)
            {
                var resolveError = TryResolveTargetSession(doc.RootElement, out var targetSession, out string targetFingerprint);
                if (resolveError != null) return resolveError;

                string reqId = Guid.NewGuid().ToString();
                var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, timeoutCts.Token);

                var ctr = linkedCts.Token.Register(() =>
                {
                    if (_pendingRequests.TryRemove(reqId, out var removed))
                    {
                        removed.Tcs.TrySetCanceled();
                    }
                });

                var pending = new PendingRemoteRequest
                {
                    RequestId = reqId,
                    Tcs = tcs,
                    ExpectedSessionId = targetSession!.SessionId,
                    ExpectedFingerprint = targetFingerprint,
                    ExpectedOperation = "FS_LIST",
                    CreatedAtUtc = DateTime.UtcNow,
                    CancellationTokenRegistration = ctr
                };
                _pendingRequests[reqId] = pending;

                try
                {
                    bool sent = _sessionManager.SendRawFrameToDevice(targetFingerprint, JsonSerializer.Serialize(new { type = "FS_LIST", requestId = reqId, path = path }));
                    if (!sent)
                    {
                        if (_pendingRequests.TryRemove(reqId, out var removed))
                        {
                            try { removed.CancellationTokenRegistration.Dispose(); } catch { }
                        }
                        return Results.Problem("Failed to deliver request to target companion device");
                    }

                    var resultJson = await tcs.Task;
                    try
                    {
                        var items = JsonDocument.Parse(resultJson).RootElement.GetProperty("items");
                        return Results.Content(items.GetRawText(), "application/json");
                    }
                    catch
                    {
                        return Results.Ok(new object[0]);
                    }
                }
                catch (OperationCanceledException)
                {
                    return Results.StatusCode(StatusCodes.Status408RequestTimeout);
                }
                catch (IOException ex) when (ex.Message.Contains("disconnected"))
                {
                    return Results.Problem("Target companion device disconnected", statusCode: StatusCodes.Status502BadGateway);
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error in remote list: {ex.Message}");
                    return Results.Problem("Remote list failed");
                }
                finally
                {
                    if (_pendingRequests.TryRemove(reqId, out var removed))
                    {
                        try { removed.CancellationTokenRegistration.Dispose(); } catch { }
                    }
                }
            }
        });

        _app.MapPost("/api/fs/remote/download", async (HttpContext context) =>
        {
            var (success, reqJson, errorResult) = await ReadBoundedJsonBodyAsync(context);
            if (!success) return errorResult!;

            JsonDocument doc;
            string remotePath = "";
            string localDir = "";
            try
            {
                doc = JsonDocument.Parse(reqJson!);
                if (doc.RootElement.TryGetProperty("remotePath", out var rpProp)) remotePath = rpProp.GetString() ?? "";
                if (doc.RootElement.TryGetProperty("localDir", out var ldProp)) localDir = ldProp.GetString() ?? "";
            }
            catch
            {
                return Results.BadRequest(new { error = "Invalid JSON payload" });
            }

            using (doc)
            {
                if (string.IsNullOrWhiteSpace(remotePath) || string.IsNullOrWhiteSpace(localDir))
                {
                    return Results.BadRequest(new { error = "Missing remotePath or localDir" });
                }

                if (!TryGetValidPath(localDir, out var validLocalDir) || !Directory.Exists(validLocalDir))
                {
                    return Results.BadRequest(new { error = "Invalid or restricted local destination directory" });
                }

                var resolveError = TryResolveTargetSession(doc.RootElement, out var targetSession, out string targetFingerprint);
                if (resolveError != null) return resolveError;

                string reqId = Guid.NewGuid().ToString();
                var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, timeoutCts.Token);

                var ctr = linkedCts.Token.Register(() =>
                {
                    if (_pendingRequests.TryRemove(reqId, out var removed))
                    {
                        removed.Tcs.TrySetCanceled();
                    }
                });

                var pending = new PendingRemoteRequest
                {
                    RequestId = reqId,
                    Tcs = tcs,
                    ExpectedSessionId = targetSession!.SessionId,
                    ExpectedFingerprint = targetFingerprint,
                    ExpectedOperation = "FS_SEND_FILE",
                    CreatedAtUtc = DateTime.UtcNow,
                    CancellationTokenRegistration = ctr
                };
                _pendingRequests[reqId] = pending;

                try
                {
                    var token = _tokenStore.GenerateToken(TimeSpan.FromMinutes(10), targetFingerprint, new[] { "FILES" });
                    var fileName = Path.GetFileName(remotePath);
                    var windowsDestPath = Path.Combine(validLocalDir, fileName);

                    bool sent = _sessionManager.SendRawFrameToDevice(targetFingerprint, JsonSerializer.Serialize(new
                    {
                        type = "FS_SEND_FILE",
                        requestId = reqId,
                        androidPath = remotePath,
                        windowsDestPath = windowsDestPath,
                        token = token
                    }));

                    if (!sent)
                    {
                        if (_pendingRequests.TryRemove(reqId, out var removed))
                        {
                            try { removed.CancellationTokenRegistration.Dispose(); } catch { }
                        }
                        return Results.Problem("Failed to deliver request to target companion device");
                    }

                    var resultJson = await tcs.Task;
                    try
                    {
                        var status = JsonDocument.Parse(resultJson).RootElement.GetProperty("status").GetString();
                        if (string.Equals(status, "SUCCESS", StringComparison.OrdinalIgnoreCase))
                        {
                            return Results.Ok();
                        }
                        return Results.Problem("Remote download reported error");
                    }
                    catch
                    {
                        return Results.Ok();
                    }
                }
                catch (OperationCanceledException)
                {
                    return Results.StatusCode(StatusCodes.Status408RequestTimeout);
                }
                catch (IOException ex) when (ex.Message.Contains("disconnected"))
                {
                    return Results.Problem("Target companion device disconnected", statusCode: StatusCodes.Status502BadGateway);
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error in remote download: {ex.Message}");
                    return Results.Problem("Remote download failed");
                }
                finally
                {
                    if (_pendingRequests.TryRemove(reqId, out var removed))
                    {
                        try { removed.CancellationTokenRegistration.Dispose(); } catch { }
                    }
                }
            }
        });

        _app.MapPost("/api/fs/remote/upload", async (HttpContext context) =>
        {
            var (success, reqJson, errorResult) = await ReadBoundedJsonBodyAsync(context);
            if (!success) return errorResult!;

            JsonDocument doc;
            string localPath = "";
            string remoteDir = "";
            try
            {
                doc = JsonDocument.Parse(reqJson!);
                if (doc.RootElement.TryGetProperty("localPath", out var lpProp)) localPath = lpProp.GetString() ?? "";
                if (doc.RootElement.TryGetProperty("remoteDir", out var rdProp)) remoteDir = rdProp.GetString() ?? "";
            }
            catch
            {
                return Results.BadRequest(new { error = "Invalid JSON payload" });
            }

            using (doc)
            {
                if (string.IsNullOrWhiteSpace(localPath) || string.IsNullOrWhiteSpace(remoteDir))
                {
                    return Results.BadRequest(new { error = "Missing localPath or remoteDir" });
                }

                if (!TryGetValidPath(localPath, out var validLocalPath) || !File.Exists(validLocalPath))
                {
                    return Results.BadRequest(new { error = "Invalid or restricted local source file" });
                }

                var resolveError = TryResolveTargetSession(doc.RootElement, out var targetSession, out string targetFingerprint);
                if (resolveError != null) return resolveError;

                string reqId = Guid.NewGuid().ToString();
                var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, timeoutCts.Token);

                var ctr = linkedCts.Token.Register(() =>
                {
                    if (_pendingRequests.TryRemove(reqId, out var removed))
                    {
                        removed.Tcs.TrySetCanceled();
                    }
                });

                var pending = new PendingRemoteRequest
                {
                    RequestId = reqId,
                    Tcs = tcs,
                    ExpectedSessionId = targetSession!.SessionId,
                    ExpectedFingerprint = targetFingerprint,
                    ExpectedOperation = "FS_RECEIVE_FILE",
                    CreatedAtUtc = DateTime.UtcNow,
                    CancellationTokenRegistration = ctr
                };
                _pendingRequests[reqId] = pending;

                try
                {
                    var token = _tokenStore.GenerateToken(TimeSpan.FromMinutes(10), targetFingerprint, new[] { "FILES" });
                    var fileName = Path.GetFileName(validLocalPath);

                    bool sent = _sessionManager.SendRawFrameToDevice(targetFingerprint, JsonSerializer.Serialize(new
                    {
                        type = "FS_RECEIVE_FILE",
                        requestId = reqId,
                        windowsPath = validLocalPath,
                        fileName = fileName,
                        token = token
                    }));

                    if (!sent)
                    {
                        if (_pendingRequests.TryRemove(reqId, out var removed))
                        {
                            try { removed.CancellationTokenRegistration.Dispose(); } catch { }
                        }
                        return Results.Problem("Failed to deliver request to target companion device");
                    }

                    var resultJson = await tcs.Task;
                    try
                    {
                        var status = JsonDocument.Parse(resultJson).RootElement.GetProperty("status").GetString();
                        if (string.Equals(status, "SUCCESS", StringComparison.OrdinalIgnoreCase))
                        {
                            return Results.Ok();
                        }
                        return Results.Problem("Remote upload reported error");
                    }
                    catch
                    {
                        return Results.Ok();
                    }
                }
                catch (OperationCanceledException)
                {
                    return Results.StatusCode(StatusCodes.Status408RequestTimeout);
                }
                catch (IOException ex) when (ex.Message.Contains("disconnected"))
                {
                    return Results.Problem("Target companion device disconnected", statusCode: StatusCodes.Status502BadGateway);
                }
                catch (Exception ex)
                {
                    _logger.Error($"Error in remote upload: {ex.Message}");
                    return Results.Problem("Remote upload failed");
                }
                finally
                {
                    if (_pendingRequests.TryRemove(reqId, out var removed))
                    {
                        try { removed.CancellationTokenRegistration.Dispose(); } catch { }
                    }
                }
            }
        });
        // Remote Desktop Streaming Endpoint (MJPEG)
        _app.MapGet("/api/desktop/stream", async (HttpContext context, int? fps, int? quality, long? windowId) =>
        {
            context.Response.Headers["Content-Type"] = "multipart/x-mixed-replace; boundary=--frame";
            context.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            context.Response.Headers["Connection"] = "close";

            int targetFps = Math.Clamp(fps ?? 15, 1, 30);
            int targetQual = Math.Clamp(quality ?? 50, 10, 90);
            long targetHwnd = windowId ?? 0L;

            _inputForwarder.PostToHelper(new { type = "START_SCREEN_STREAM", fps = targetFps, quality = targetQual, hwnd = targetHwnd });

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

                using var hDir = CreateFile(
                    fullPath,
                    FILE_LIST_DIRECTORY | GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (hDir.IsInvalid || !ValidateHandleSecurity(hDir, null, null, out var resolvedDirPath, out _, allowReparsePoint: false))
                {
                    return Results.NotFound(new { error = "Directory not found or access restricted" });
                }

                string q = query?.Trim() ?? "";
                int limit = Math.Clamp(maxResults ?? 100, 1, 500);
                bool isRec = recursive ?? true;
                var results = new List<object>();

                var dirStack = new Stack<string>();
                dirStack.Push(resolvedDirPath);

                while (dirStack.Count > 0 && results.Count < limit)
                {
                    string currentDirPath = dirStack.Pop();
                    DirectoryInfo currentDirInfo;
                    try
                    {
                        currentDirInfo = new DirectoryInfo(currentDirPath);
                    }
                    catch
                    {
                        continue;
                    }

                    try
                    {
                        foreach (var file in currentDirInfo.EnumerateFiles())
                        {
                            if (results.Count >= limit) break;
                            if ((file.Attributes & FileAttributes.ReparsePoint) != 0 || (file.Attributes & FileAttributes.Hidden) != 0) continue;
                            if (IsPathInBlockedPrefix(file.FullName) || IsCrossUserProfileAccess(file.FullName)) continue;

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

                        if (isRec)
                        {
                            foreach (var subDir in currentDirInfo.EnumerateDirectories())
                            {
                                if ((subDir.Attributes & FileAttributes.ReparsePoint) != 0 || (subDir.Attributes & FileAttributes.Hidden) != 0) continue;
                                if (IsPathInBlockedPrefix(subDir.FullName) || IsCrossUserProfileAccess(subDir.FullName)) continue;
                                dirStack.Push(subDir.FullName);
                            }
                        }
                    }
                    catch
                    {
                        // Skip inaccessible subdirectories
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
        _app.MapPost("/api/fs/rename", async (HttpContext context) =>
        {
            var (success, content, errorResult) = await ReadBoundedJsonBodyAsync(context);
            if (!success) return errorResult!;
            RenamePayload? req;
            try { req = JsonSerializer.Deserialize<RenamePayload>(content!); }
            catch { return Results.BadRequest(new { error = "Invalid JSON payload" }); }

            if (req == null || string.IsNullOrWhiteSpace(req.Path) || string.IsNullOrWhiteSpace(req.NewName))
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
                using var hDstParent = CreateFile(
                    dir,
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (hDstParent.IsInvalid || !ValidateHandleSecurity(hDstParent, null, null, out _, out uint dstVolumeSerial, allowReparsePoint: false))
                {
                    return Results.BadRequest(new { error = "Destination directory failed security validation" });
                }

                if (File.Exists(fullPath))
                {
                    using var hFile = CreateFile(
                        fullPath,
                        GENERIC_READ | DELETE,
                        FILE_SHARE_READ,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        IntPtr.Zero);

                    if (hFile.IsInvalid)
                    {
                        return Results.Problem("Failed to open file for rename");
                    }

                    if (!ValidateHandleSecurity(hFile, null, null, out _, out uint srcVolumeSerial, allowReparsePoint: false))
                    {
                        return Results.BadRequest(new { error = "Target path failed final resolution or access restricted" });
                    }

                    if (srcVolumeSerial != dstVolumeSerial)
                    {
                        return Results.BadRequest(new { error = "Cross-volume moves are not supported for atomic handle operations" });
                    }

                    if (!PromoteFileHandle(hFile, validNewPath, replaceIfExists: true))
                    {
                        return Results.Problem("Atomic file rename failed");
                    }
                    return Results.Ok(new { success = true, newPath = validNewPath });
                }
                else if (Directory.Exists(fullPath))
                {
                    using var hDir = CreateFile(
                        fullPath,
                        DELETE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        IntPtr.Zero);

                    if (hDir.IsInvalid)
                    {
                        return Results.Problem("Failed to open directory for rename");
                    }

                    if (!ValidateHandleSecurity(hDir, null, null, out _, out uint srcVolumeSerial, allowReparsePoint: false))
                    {
                        return Results.BadRequest(new { error = "Target directory failed final resolution or access restricted" });
                    }

                    if (srcVolumeSerial != dstVolumeSerial)
                    {
                        return Results.BadRequest(new { error = "Cross-volume moves are not supported for atomic handle operations" });
                    }

                    if (!PromoteFileHandle(hDir, validNewPath, replaceIfExists: false))
                    {
                        return Results.Problem("Atomic directory rename failed");
                    }
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
        _app.MapPost("/api/fs/move", async (HttpContext context) =>
        {
            var (success, content, errorResult) = await ReadBoundedJsonBodyAsync(context);
            if (!success) return errorResult!;
            MovePayload? req;
            try { req = JsonSerializer.Deserialize<MovePayload>(content!); }
            catch { return Results.BadRequest(new { error = "Invalid JSON payload" }); }

            if (req == null || !TryGetValidPath(req.SourcePath, out var srcPath) || !TryGetValidPath(req.DestinationPath, out var dstPath, isUpload: true))
            {
                return Results.BadRequest(new { error = "Invalid source or destination path" });
            }

            try
            {
                string finalDst = Directory.Exists(dstPath) ? Path.Combine(dstPath, Path.GetFileName(srcPath)) : dstPath;
                if (!TryGetValidPath(finalDst, out var validFinalDst, isUpload: true))
                {
                    return Results.BadRequest(new { error = "Invalid destination path" });
                }

                string dstParent = Path.GetDirectoryName(validFinalDst) ?? "";
                using var hDstParent = CreateFile(
                    dstParent,
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (hDstParent.IsInvalid || !ValidateHandleSecurity(hDstParent, null, null, out _, out uint dstVolumeSerial, allowReparsePoint: false))
                {
                    return Results.BadRequest(new { error = "Destination directory failed security validation" });
                }

                if (File.Exists(srcPath))
                {
                    using var hSrc = CreateFile(
                        srcPath,
                        GENERIC_READ | DELETE,
                        FILE_SHARE_READ,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        IntPtr.Zero);

                    if (hSrc.IsInvalid)
                    {
                        return Results.Problem("Failed to open source file for move");
                    }

                    if (!ValidateHandleSecurity(hSrc, null, null, out _, out uint srcVolumeSerial, allowReparsePoint: false))
                    {
                        return Results.BadRequest(new { error = "Source path failed final resolution or access restricted" });
                    }

                    if (srcVolumeSerial != dstVolumeSerial)
                    {
                        return Results.BadRequest(new { error = "Cross-volume moves are not supported for atomic handle operations" });
                    }

                    if (!PromoteFileHandle(hSrc, validFinalDst, replaceIfExists: true))
                    {
                        return Results.Problem("Atomic file move failed");
                    }
                    return Results.Ok(new { success = true, destination = validFinalDst });
                }
                else if (Directory.Exists(srcPath))
                {
                    using var hDir = CreateFile(
                        srcPath,
                        DELETE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        IntPtr.Zero);

                    if (hDir.IsInvalid)
                    {
                        return Results.Problem("Failed to open source directory for move");
                    }

                    if (!ValidateHandleSecurity(hDir, null, null, out _, out uint srcVolumeSerial, allowReparsePoint: false))
                    {
                        return Results.BadRequest(new { error = "Source directory failed final resolution or access restricted" });
                    }

                    if (srcVolumeSerial != dstVolumeSerial)
                    {
                        return Results.BadRequest(new { error = "Cross-volume moves are not supported for atomic handle operations" });
                    }

                    if (!PromoteFileHandle(hDir, validFinalDst, replaceIfExists: false))
                    {
                        return Results.Problem("Atomic directory move failed");
                    }
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
        _app.MapPost("/api/fs/delete", async (HttpContext context) =>
        {
            var (success, content, errorResult) = await ReadBoundedJsonBodyAsync(context);
            if (!success) return errorResult!;
            DeletePayload? req;
            try { req = JsonSerializer.Deserialize<DeletePayload>(content!); }
            catch { return Results.BadRequest(new { error = "Invalid JSON payload" }); }

            if (req == null || !TryGetValidPath(req.Path, out var fullPath))
            {
                return Results.BadRequest(new { error = "Invalid path or access restricted" });
            }

            try
            {
                if (req.Permanent)
                {
                    if (File.Exists(fullPath))
                    {
                        using var hFile = CreateFile(
                            fullPath,
                            DELETE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            IntPtr.Zero,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS,
                            IntPtr.Zero);

                        if (hFile.IsInvalid)
                        {
                            return Results.Problem("Failed to open file for deletion");
                        }

                        if (!ValidateHandleSecurity(hFile, null, null, out string resolved, out _, allowReparsePoint: false))
                        {
                            return Results.BadRequest(new { error = "Target path failed final resolution or access restricted" });
                        }

                        try
                        {
                            var attrs = File.GetAttributes(fullPath);
                            if ((attrs & FileAttributes.ReadOnly) != 0)
                            {
                                File.SetAttributes(fullPath, attrs & ~FileAttributes.ReadOnly);
                            }
                        }
                        catch { }

                        if (!DeleteHandle(hFile))
                        {
                            return Results.Problem("Failed to delete file atomically via handle");
                        }
                    }
                    else if (Directory.Exists(fullPath))
                    {
                        using var hDir = CreateFile(
                            fullPath,
                            DELETE | FILE_LIST_DIRECTORY,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            IntPtr.Zero,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                            IntPtr.Zero);

                        if (hDir.IsInvalid)
                        {
                            return Results.Problem("Failed to open directory for deletion");
                        }

                        if (!ValidateHandleSecurity(hDir, null, null, out string resolvedRoot, out uint rootVolumeSerial, allowReparsePoint: false))
                        {
                            return Results.BadRequest(new { error = "Target directory failed final resolution or access restricted" });
                        }

                        hDir.Dispose();

                        if (!DeleteDirectoryRecursiveSafe(resolvedRoot, resolvedRoot, rootVolumeSerial))
                        {
                            return Results.Problem("Failed to safely delete directory hierarchy");
                        }
                    }
                    else return Results.NotFound(new { error = "Item not found" });
                }
                else
                {
                    using var hObj = CreateFile(
                        fullPath,
                        0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS,
                        IntPtr.Zero);

                    if (!hObj.IsInvalid)
                    {
                        if (!ValidateHandleSecurity(hObj, null, null, out _, out _, allowReparsePoint: false))
                        {
                            return Results.BadRequest(new { error = "Target path failed final resolution or access restricted" });
                        }
                    }

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
        _app.MapPost("/api/fs/mkdir", async (HttpContext context) =>
        {
            var (success, content, errorResult) = await ReadBoundedJsonBodyAsync(context);
            if (!success) return errorResult!;
            MkdirPayload? req;
            try { req = JsonSerializer.Deserialize<MkdirPayload>(content!); }
            catch { return Results.BadRequest(new { error = "Invalid JSON payload" }); }

            if (req == null || string.IsNullOrWhiteSpace(req.Path) || string.IsNullOrWhiteSpace(req.Name))
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

            using var hParent = CreateFile(
                fullPath,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);

            if (hParent.IsInvalid || !ValidateHandleSecurity(hParent, null, null, out _, out _, allowReparsePoint: false))
            {
                return Results.BadRequest(new { error = "Parent directory failed security validation" });
            }

            string newDir = Path.Combine(fullPath, req.Name);
            if (!TryGetValidPath(newDir, out var validNewDir, isUpload: true))
            {
                return Results.BadRequest(new { error = "Invalid directory path or access restricted" });
            }

            try
            {
                Directory.CreateDirectory(validNewDir);

                using var hNew = CreateFile(
                    validNewDir,
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    IntPtr.Zero);

                if (hNew.IsInvalid || !ValidateHandleSecurity(hNew, fullPath, null, out _, out _, allowReparsePoint: false))
                {
                    try { Directory.Delete(validNewDir); } catch { }
                    return Results.BadRequest(new { error = "Created directory failed security containment" });
                }

                return Results.Ok(new { success = true, path = validNewDir });
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

                    if (!TryGetValidPath(fullPath, out _, isUpload: true))
                    {
                        try { File.Delete(partPath); } catch { }
                        return Results.BadRequest("Destination path failed revalidation");
                    }

                    if (HasReparsePointInHierarchy(fullPath))
                    {
                        try { File.Delete(partPath); } catch { }
                        return Results.BadRequest("Destination hierarchy contains reparse points");
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

                    // Hold exclusive locked file handle with DELETE access from verification through atomic promotion to defeat TOCTOU
                    var handle = CreateFile(
                        partPath,
                        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
                        FILE_SHARE_NONE,
                        IntPtr.Zero,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        IntPtr.Zero);

                    if (handle.IsInvalid)
                    {
                        int err = Marshal.GetLastWin32Error();
                        _logger.Error($"Failed to lock part file {partPath} for promotion: Win32 error {err}");
                        try { File.Delete(partPath); } catch { }
                        return Results.Problem("Failed to lock part file for promotion");
                    }

                    using (handle)
                    using (var fsVerify = new FileStream(handle, FileAccess.ReadWrite, 81920, false))
                    {
                        // Reparse-point check directly on the open file handle
                        if (!GetFileInformationByHandle(handle, out var partInfo) ||
                            (partInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                        {
                            fsVerify.Dispose();
                            try { File.Delete(partPath); } catch { }
                            return Results.BadRequest("Part file became a reparse point");
                        }

                        // Verify resolved physical path matches expected part path
                        string? resolvedPart = GetFinalResolvedPath(handle);
                        if (resolvedPart == null || !string.Equals(resolvedPart, Path.GetFullPath(partPath), StringComparison.OrdinalIgnoreCase))
                        {
                            fsVerify.Dispose();
                            try { File.Delete(partPath); } catch { }
                            return Results.BadRequest("Part file resolved path mismatch or symlink detected");
                        }

                        // Compute SHA-512 directly from open locked handle
                        fsVerify.Seek(0, SeekOrigin.Begin);
                        using var sha512 = SHA512.Create();
                        byte[] hashBytes = sha512.ComputeHash(fsVerify);
                        string computed = Convert.ToHexString(hashBytes).ToLowerInvariant();
                        if (!string.Equals(computed, hash.Trim(), StringComparison.OrdinalIgnoreCase))
                        {
                            fsVerify.Dispose();
                            try { File.Delete(partPath); } catch { }
                            return Results.BadRequest("Checksum mismatch for completed upload");
                        }

                        // Target destination checks immediately prior to promotion while handle remains locked
                        if (!TryGetValidPath(fullPath, out _, isUpload: true))
                        {
                            fsVerify.Dispose();
                            try { File.Delete(partPath); } catch { }
                            return Results.BadRequest("Destination path failed revalidation");
                        }

                        if (HasReparsePointInHierarchy(fullPath))
                        {
                            fsVerify.Dispose();
                            try { File.Delete(partPath); } catch { }
                            return Results.BadRequest("Destination hierarchy contains reparse points");
                        }

                        if (File.Exists(fullPath))
                        {
                            var targetFi = new FileInfo(fullPath);
                            if ((targetFi.Attributes & (FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.ReparsePoint | FileAttributes.System)) != 0)
                            {
                                fsVerify.Dispose();
                                try { File.Delete(partPath); } catch { }
                                return Results.BadRequest("Destination file is read-only, hidden, or reparse point");
                            }
                        }

                        // Atomically promote the open handle to destination (strictly fail closed, zero copy fallback)
                        if (!PromoteFileHandle(handle, fullPath))
                        {
                            int err = Marshal.GetLastWin32Error();
                            _logger.Error($"Atomic promotion of {partPath} to {fullPath} failed: Win32 error {err}");
                            fsVerify.Dispose();
                            try { File.Delete(partPath); } catch { }
                            return Results.Problem($"Atomic file promotion failed (Win32 error {err})");
                        }
                    }

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
        _logger.Info($"FileTransferServer started on port {NetworkConstants.FileTransferPort}.");
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
