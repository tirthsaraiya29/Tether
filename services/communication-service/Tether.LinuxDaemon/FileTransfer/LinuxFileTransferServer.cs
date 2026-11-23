using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Config;
using Tether.Shared.Logging;
using Tether.Shared.Security;

namespace Tether.LinuxDaemon.FileTransfer;

public sealed class LinuxFileTransferServer : IHostedService
{
    private const long MaxUploadSizeBytes = 4L * 1024L * 1024L * 1024L; // 4 GB limit

    private readonly ITetherLogger _logger;
    private readonly IHostIdentity _identity;
    private readonly LinuxDaemonConfig _config;
    private readonly LinuxTokenStore _tokenStore;
    private WebApplication? _app;

    [DllImport("libc", SetLastError = true, EntryPoint = "realpath")]
    private static extern IntPtr realpath(string path, IntPtr resolvedPath);

    [DllImport("libc", SetLastError = true, EntryPoint = "free")]
    private static extern void libc_free(IntPtr ptr);

    public LinuxFileTransferServer(
        ITetherLogger logger,
        IHostIdentity identity,
        LinuxDaemonConfig config,
        LinuxTokenStore tokenStore)
    {
        _logger = logger;
        _identity = identity;
        _config = config;
        _tokenStore = tokenStore;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var builder = WebApplication.CreateBuilder();

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.IPv6Any, _config.FileTransferPort, listenOptions =>
            {
                listenOptions.UseHttps(new HttpsConnectionAdapterOptions
                {
                    ServerCertificate = _identity.Certificate,
                    ClientCertificateMode = ClientCertificateMode.NoCertificate,
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                });
            });
            options.Limits.MaxRequestBodySize = MaxUploadSizeBytes;
        });

        builder.Services.AddRouting();

        _app = builder.Build();

        // Middleware: Token Validation
        _app.Use(async (context, next) =>
        {
            // Allow health / ping check without token
            if (context.Request.Path == "/health")
            {
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync("OK");
                return;
            }

            string? token = null;
            string? authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                token = authHeader.Substring(7).Trim();
            }
            else
            {
                token = context.Request.Headers["X-Tether-Token"].FirstOrDefault();
            }

            if (string.IsNullOrEmpty(token) && context.Request.Query.ContainsKey("token"))
            {
                token = context.Request.Query["token"].FirstOrDefault();
            }

            if (string.IsNullOrEmpty(token) || !_tokenStore.TryGetToken(token, out var tokenInfo) || tokenInfo == null)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Invalid or expired transfer token" });
                return;
            }

            if (!tokenInfo.Capabilities.Contains("*") && !tokenInfo.Capabilities.Contains("FILES"))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new { error = "Forbidden: Token lacks FILES capability" });
                return;
            }

            string? clientDeviceFp = context.Request.Headers["X-Tether-Device"].FirstOrDefault();
            if (!string.IsNullOrEmpty(clientDeviceFp) && !string.IsNullOrEmpty(tokenInfo.DeviceFingerprint) &&
                !string.Equals(clientDeviceFp, tokenInfo.DeviceFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new { error = "Forbidden: Device mismatch for transfer token" });
                return;
            }

            context.Items["TokenInfo"] = tokenInfo;
            context.Items["DeviceFingerprint"] = tokenInfo.DeviceFingerprint;

            await next();
        });

        // 1. Directory Browser endpoint
        _app.MapGet("/api/files/browse", (HttpContext ctx, string? path) =>
        {
            string baseDir = GetUserAllowedBaseDirectory();
            string targetDir = string.IsNullOrWhiteSpace(path)
                ? baseDir
                : Path.GetFullPath(Path.Combine(baseDir, path.TrimStart('/', '\\')));

            if (!IsPathSafe(targetDir, baseDir))
            {
                return Results.BadRequest(new { error = "Access denied: Path traversal outside allowed directories." });
            }

            if (!Directory.Exists(targetDir))
            {
                return Results.NotFound(new { error = "Directory not found." });
            }

            try
            {
                var di = new DirectoryInfo(targetDir);
                var entries = di.EnumerateFileSystemInfos()
                    .Where(f => !f.Name.StartsWith(".")) // hide dotfiles
                    .Where(f => IsPathSafe(f.FullName, baseDir)) // hide symlinks escaping base
                    .Select(f => new
                    {
                        name = f.Name,
                        path = Path.GetRelativePath(baseDir, f.FullName).Replace('\\', '/'),
                        isDir = (f.Attributes & FileAttributes.Directory) != 0,
                        size = (f.Attributes & FileAttributes.Directory) != 0 ? 0 : ((FileInfo)f).Length,
                        modifiedUtc = f.LastWriteTimeUtc
                    })
                    .OrderByDescending(f => f.isDir)
                    .ThenBy(f => f.name)
                    .ToList();

                return Results.Ok(new { currentPath = Path.GetRelativePath(baseDir, targetDir).Replace('\\', '/'), entries });
            }
            catch (Exception ex)
            {
                return Results.Problem(ex.Message);
            }
        });

        // 2. File Download endpoint
        _app.MapGet("/api/files/download", (HttpContext ctx, string path) =>
        {
            if (string.IsNullOrWhiteSpace(path)) return Results.BadRequest(new { error = "Missing file path" });

            string baseDir = GetUserAllowedBaseDirectory();
            string targetFile = Path.GetFullPath(Path.Combine(baseDir, path.TrimStart('/', '\\')));

            if (!IsPathSafe(targetFile, baseDir))
            {
                return Results.BadRequest(new { error = "Access denied: Path traversal outside allowed directories." });
            }

            if (!File.Exists(targetFile))
            {
                return Results.NotFound(new { error = "File not found" });
            }

            return Results.File(targetFile, "application/octet-stream", enableRangeProcessing: true, fileDownloadName: Path.GetFileName(targetFile));
        });

        // 3. File Upload endpoint
        _app.MapPost("/api/files/upload", async (HttpContext ctx, string? path) =>
        {
            string baseDir = GetUserAllowedBaseDirectory();
            string uploadDir = string.IsNullOrWhiteSpace(path)
                ? Path.Combine(baseDir, "Downloads", "Tether")
                : Path.GetFullPath(Path.Combine(baseDir, path.TrimStart('/', '\\')));

            if (!IsPathSafe(uploadDir, baseDir))
            {
                return Results.BadRequest(new { error = "Access denied: Path traversal outside allowed directories." });
            }

            Directory.CreateDirectory(uploadDir);

            if (!ctx.Request.HasFormContentType)
            {
                return Results.BadRequest(new { error = "Expected multipart form content." });
            }

            var form = await ctx.Request.ReadFormAsync();
            var file = form.Files.FirstOrDefault();
            if (file == null || file.Length == 0)
            {
                return Results.BadRequest(new { error = "No file provided in request." });
            }

            string safeFileName = Path.GetFileName(file.FileName).Trim();
            if (string.IsNullOrEmpty(safeFileName) || safeFileName.Contains('\0') ||
                safeFileName.StartsWith('.') || safeFileName.Length > 255)
            {
                return Results.BadRequest(new { error = "Invalid or prohibited file name." });
            }

            string destPath = Path.Combine(uploadDir, safeFileName);
            if (!IsPathSafe(destPath, baseDir))
            {
                return Results.BadRequest(new { error = "Access denied: Path traversal outside allowed directories." });
            }

            string tempFileName = $".tether_upload_{Guid.NewGuid():N}.tmp";
            string tempPath = Path.Combine(uploadDir, tempFileName);

            try
            {
                await using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
                {
                    await file.CopyToAsync(stream);
                    await stream.FlushAsync();
                }

                if (OperatingSystem.IsLinux())
                {
                    try
                    {
                        File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    }
                    catch { }
                }

                File.Move(tempPath, destPath, overwrite: true);
            }
            catch
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                throw;
            }

            return Results.Ok(new { success = true, fileName = safeFileName, size = file.Length });
        });

        await _app.StartAsync(cancellationToken);
        _logger.Info($"Linux File Transfer HTTPS server active on port {_config.FileTransferPort} (TLS 1.3).");
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_app != null)
        {
            await _app.StopAsync(cancellationToken);
            await _app.DisposeAsync();
            _app = null;
        }
    }

    private static string GetUserAllowedBaseDirectory()
    {
        var session = PlatformDetection.GetActiveSessionInfo();
        string homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (session.UserName != "root" && !string.IsNullOrEmpty(session.UserName))
        {
            string userHome = $"/home/{session.UserName}";
            if (Directory.Exists(userHome)) return userHome;
        }
        return homeDir;
    }

    public static string? ResolveCanonicalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;

        if (OperatingSystem.IsLinux())
        {
            try
            {
                IntPtr resolved = realpath(path, IntPtr.Zero);
                if (resolved != IntPtr.Zero)
                {
                    try
                    {
                        return Marshal.PtrToStringUTF8(resolved);
                    }
                    finally
                    {
                        libc_free(resolved);
                    }
                }
            }
            catch { }
        }

        try
        {
            string full = Path.GetFullPath(path);
            if (File.Exists(full))
            {
                var fi = new FileInfo(full);
                var target = fi.ResolveLinkTarget(returnFinalTarget: true);
                if (target != null) return Path.GetFullPath(target.FullName);
            }
            else if (Directory.Exists(full))
            {
                var di = new DirectoryInfo(full);
                var target = di.ResolveLinkTarget(returnFinalTarget: true);
                if (target != null) return Path.GetFullPath(target.FullName);
            }
            return full;
        }
        catch
        {
            return null;
        }
    }

    public static bool IsPathSafe(string fullPath, string baseDir)
    {
        if (string.IsNullOrWhiteSpace(fullPath) || string.IsNullOrWhiteSpace(baseDir)) return false;

        string? canonicalBase = ResolveCanonicalPath(baseDir);
        if (string.IsNullOrEmpty(canonicalBase)) return false;

        string basePrefix = canonicalBase.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

        string? canonicalTarget = ResolveCanonicalPath(fullPath);
        if (string.IsNullOrEmpty(canonicalTarget))
        {
            // Path does not exist yet (e.g. upload dest): validate parent directory
            string? parent = Path.GetDirectoryName(fullPath);
            if (string.IsNullOrEmpty(parent)) return false;

            string? canonicalParent = ResolveCanonicalPath(parent);
            if (string.IsNullOrEmpty(canonicalParent)) return false;

            string parentWithSep = canonicalParent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            bool parentSafe = parentWithSep.StartsWith(basePrefix, OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase)
                              || string.Equals(canonicalParent, canonicalBase, OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
            if (!parentSafe) return false;

            string fileName = Path.GetFileName(fullPath);
            if (fileName.Contains('\0') || fileName.Contains('/') || fileName.Contains('\\') || fileName == ".." || fileName == ".")
                return false;

            canonicalTarget = Path.Combine(canonicalParent, fileName);
        }

        // Disallow system directories
        string norm = canonicalTarget.Replace('\\', '/');
        if (norm.StartsWith("/etc") || norm.StartsWith("/proc") ||
            norm.StartsWith("/sys") || norm.StartsWith("/dev") ||
            norm.StartsWith("/root") || norm.StartsWith("/bin") ||
            norm.StartsWith("/sbin") || norm.StartsWith("/usr") ||
            norm.StartsWith("/boot") || norm.StartsWith("/run") ||
            norm.StartsWith("/var/run") || norm.StartsWith("/var/lib"))
        {
            return false;
        }

        string targetWithSep = canonicalTarget.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return targetWithSep.StartsWith(basePrefix, OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase)
               || string.Equals(canonicalTarget, canonicalBase, OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
    }
}
