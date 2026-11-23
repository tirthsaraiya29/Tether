using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
using Tether.LinuxDaemon.Desktop;
using Tether.LinuxDaemon.Trust;
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
    private readonly LinuxTrustStore? _trustStore;
    private readonly LinuxDesktopManager _desktopManager;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seenProofs = new();
    private WebApplication? _app;

    [DllImport("libc", SetLastError = true, EntryPoint = "realpath")]
    private static extern IntPtr realpath(string path, IntPtr resolvedPath);

    [DllImport("libc", SetLastError = true, EntryPoint = "free")]
    private static extern void libc_free(IntPtr ptr);

    public LinuxFileTransferServer(
        ITetherLogger logger,
        IHostIdentity identity,
        LinuxDaemonConfig config,
        LinuxTokenStore tokenStore,
        LinuxTrustStore? trustStore = null,
        LinuxDesktopManager? desktopManager = null)
    {
        _logger = logger;
        _identity = identity;
        _config = config;
        _tokenStore = tokenStore;
        _trustStore = trustStore;
        _desktopManager = desktopManager ?? new LinuxDesktopManager(logger);
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

        // Middleware: Token Validation and Cryptographic Client Proof Verification
        _app.Use(async (context, next) =>
        {
            // Allow health check without token
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

            // Capability check: FILES or DESKTOP or wildcard
            bool isDesktopPath = context.Request.Path.StartsWithSegments("/api/desktop");
            bool hasCap = tokenInfo.Capabilities.Contains("*") ||
                          tokenInfo.Capabilities.Contains("FILES") ||
                          (isDesktopPath && tokenInfo.Capabilities.Contains("DESKTOP"));
            if (!hasCap)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new { error = "Forbidden: Token lacks required capability" });
                return;
            }

            // Client device fingerprint check
            string? clientDeviceFp = context.Request.Headers["X-Tether-Device"].FirstOrDefault();
            if (!string.IsNullOrEmpty(clientDeviceFp) && !string.IsNullOrEmpty(tokenInfo.DeviceFingerprint) &&
                !string.Equals(clientDeviceFp, tokenInfo.DeviceFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new { error = "Forbidden: Device mismatch for transfer token" });
                return;
            }

            // TETH-SEC-LNX-003: Mandatory Cryptographic Client Proof & Timestamp Validation (Strict Fail-Closed)
            bool isLoopback = context.Connection.RemoteIpAddress == null || IPAddress.IsLoopback(context.Connection.RemoteIpAddress);
            if (isLoopback && tokenInfo.DeviceFingerprint == "LOCAL_UI")
            {
                context.Items["TokenInfo"] = tokenInfo;
                context.Items["DeviceFingerprint"] = tokenInfo.DeviceFingerprint;
                await next();
                return;
            }

            if (!context.Request.Headers.TryGetValue("X-Tether-Client-Proof", out var proofHeader) ||
                !context.Request.Headers.TryGetValue("X-Tether-Client-Timestamp", out var tsHeader))
            {
                _logger.Warning($"LinuxFileTransferServer: Missing mandatory client proof headers from {context.Connection.RemoteIpAddress}");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Missing mandatory client proof headers (X-Tether-Client-Proof, X-Tether-Client-Timestamp)" });
                return;
            }

            string proofBase64 = proofHeader.ToString().Trim();
            string tsStr = tsHeader.ToString().Trim();
            string clientWinSpki = context.Request.Headers.TryGetValue("X-Tether-Client-WinSpki", out var spkiH)
                ? spkiH.ToString().Trim()
                : "";

            if (string.IsNullOrEmpty(proofBase64))
            {
                _logger.Warning($"LinuxFileTransferServer: Empty client proof header from {context.Connection.RemoteIpAddress}");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Empty client proof" });
                return;
            }

            if (!long.TryParse(tsStr, out long tsMs))
            {
                _logger.Warning($"LinuxFileTransferServer: Malformed timestamp header '{tsStr}' from {context.Connection.RemoteIpAddress}");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Malformed timestamp header" });
                return;
            }

            var clientTime = DateTimeOffset.FromUnixTimeMilliseconds(tsMs);
            var timeDelta = Math.Abs((DateTimeOffset.UtcNow - clientTime).TotalMinutes);
            if (timeDelta > 5)
            {
                _logger.Warning($"LinuxFileTransferServer: Client timestamp out of bounds ({timeDelta:F1} mins delta) from {context.Connection.RemoteIpAddress}");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Request timestamp expired or clock skew out of bounds (> 5 minutes)" });
                return;
            }

            // Replay detection (5-minute sliding window)
            if (_seenProofs.ContainsKey(proofBase64))
            {
                _logger.Warning($"LinuxFileTransferServer: Replayed client proof detected from {context.Connection.RemoteIpAddress}");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Replayed client proof" });
                return;
            }

            if (_seenProofs.Count > 1000)
            {
                var cutoff = DateTimeOffset.UtcNow.AddMinutes(-6);
                var stale = _seenProofs.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList();
                foreach (var k in stale) _seenProofs.TryRemove(k, out _);
            }
            _seenProofs[proofBase64] = DateTimeOffset.UtcNow;

            // Trust store & device binding verification
            if (_trustStore == null)
            {
                _logger.Warning($"LinuxFileTransferServer: Trust store unavailable while verifying {tokenInfo.DeviceFingerprint}");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Trust store unavailable" });
                return;
            }

            if (string.IsNullOrEmpty(tokenInfo.DeviceFingerprint))
            {
                _logger.Warning("LinuxFileTransferServer: Token lacks device fingerprint binding.");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Token not bound to any device" });
                return;
            }

            var pairedPhone = _trustStore.FindByFingerprint(tokenInfo.DeviceFingerprint);
            if (pairedPhone == null || string.IsNullOrEmpty(pairedPhone.PublicKeySpkiBase64))
            {
                _logger.Warning($"LinuxFileTransferServer: Device '{tokenInfo.DeviceFingerprint}' not found in trust store.");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Device not paired or untrusted" });
                return;
            }

            string hostSpki = _identity.GetPublicKeySpkiBase64();
            var proofCandidates = new List<string> { $"{token}:{tsStr}:{hostSpki}" };
            if (!string.IsNullOrEmpty(clientWinSpki) && !string.Equals(clientWinSpki, hostSpki, StringComparison.Ordinal))
            {
                proofCandidates.Add($"{token}:{tsStr}:{clientWinSpki}");
            }
            proofCandidates.Add($"{token}:{tsStr}:");

            bool signatureVerified = false;
            foreach (var candidate in proofCandidates)
            {
                byte[] candidateBytes = Encoding.UTF8.GetBytes(candidate);
                if (VerifyClientProofSignature(pairedPhone.PublicKeySpkiBase64, candidateBytes, proofBase64))
                {
                    signatureVerified = true;
                    break;
                }
            }

            if (!signatureVerified)
            {
                _logger.Warning($"LinuxFileTransferServer: Client cryptographic proof verification failed for {tokenInfo.DeviceFingerprint}");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "Unauthorized: Invalid client proof signature" });
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

        // 4. Remote Desktop Stream (MJPEG multipart/x-mixed-replace)
        _app.MapGet("/api/desktop/stream", async (HttpContext ctx, int? fps, int? quality, long? windowId) =>
        {
            ctx.Response.Headers["Content-Type"] = "multipart/x-mixed-replace; boundary=--frame";
            ctx.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            ctx.Response.Headers["Connection"] = "close";

            int targetFps = Math.Clamp(fps ?? 15, 1, 30);
            int targetQual = Math.Clamp(quality ?? 50, 10, 95);
            long targetWindow = windowId ?? 0L;

            var stream = ctx.Response.Body;
            await _desktopManager.StreamDesktopAsync(targetFps, targetQual, targetWindow, async (frame, ct) =>
            {
                var header = Encoding.ASCII.GetBytes($"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {frame.Length}\r\n\r\n");
                await stream.WriteAsync(header, ct);
                await stream.WriteAsync(frame, ct);
                await stream.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), ct);
                await stream.FlushAsync(ct);
            }, ctx.RequestAborted);
        });

        // 5. Remote Desktop Screenshot Endpoint
        _app.MapGet("/api/desktop/screenshot", async (HttpContext ctx, long? windowId, int? quality) =>
        {
            int q = Math.Clamp(quality ?? 75, 10, 100);
            long targetWindow = windowId ?? 0L;

            byte[] bytes = await _desktopManager.CaptureScreenshotAsync(q, targetWindow, ctx.RequestAborted);
            if (bytes.Length > 0)
            {
                return Results.File(bytes, "image/jpeg");
            }
            return Results.Problem("Desktop capture unavailable: no accessible X11 display server or Wayland compositor stream.", statusCode: StatusCodes.Status503ServiceUnavailable);
        });

        // 6. Active Windows List Endpoint
        _app.MapGet("/api/desktop/windows", (HttpContext ctx) =>
        {
            var windows = _desktopManager.GetDesktopWindows();
            return Results.Ok(windows);
        });

        await _app.StartAsync(cancellationToken);
        _logger.Info($"Linux File Transfer & Desktop Streaming HTTPS server active on port {_config.FileTransferPort} (TLS 1.3).");
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

    public static bool VerifyClientProofSignature(string phoneSpkiBase64, byte[] data, string signatureBase64)
    {
        try
        {
            byte[] spkiDer = Convert.FromBase64String(phoneSpkiBase64);
            byte[] sigBytes = Convert.FromBase64String(signatureBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spkiDer, out _);

            if (ecdsa.VerifyData(data, sigBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
            {
                return true;
            }

            if (ecdsa.VerifyData(data, sigBytes, HashAlgorithmName.SHA256))
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
