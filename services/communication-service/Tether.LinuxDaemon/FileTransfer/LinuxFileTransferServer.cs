using System;
using System.IO;
using System.Linq;
using System.Net;
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

            string? token = context.Request.Headers["X-Tether-Token"].FirstOrDefault();
            if (string.IsNullOrEmpty(token) && context.Request.Query.ContainsKey("token"))
            {
                token = context.Request.Query["token"].FirstOrDefault();
            }

            if (string.IsNullOrEmpty(token) || !_tokenStore.ValidateToken(token, "FILES"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Invalid or expired transfer token" });
                return;
            }

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

            string safeFileName = Path.GetFileName(file.FileName);
            string destPath = Path.Combine(uploadDir, safeFileName);

            using (var stream = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await file.CopyToAsync(stream);
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

    private static bool IsPathSafe(string fullPath, string baseDir)
    {
        string canonicalBase = Path.GetFullPath(baseDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string canonicalTarget = Path.GetFullPath(fullPath);

        // Disallow system directories
        if (canonicalTarget.StartsWith("/etc") || canonicalTarget.StartsWith("/proc") ||
            canonicalTarget.StartsWith("/sys") || canonicalTarget.StartsWith("/dev") ||
            canonicalTarget.StartsWith("/root"))
        {
            return false;
        }

        return canonicalTarget.StartsWith(canonicalBase, StringComparison.Ordinal);
    }
}
