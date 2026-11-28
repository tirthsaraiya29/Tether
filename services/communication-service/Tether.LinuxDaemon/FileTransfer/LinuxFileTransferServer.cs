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

            // Transfer tokens are only accepted from headers; query-string tokens leak through logs and proxies.

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

        // File transfer routes follow the same contract as the Windows service (/api/fs/*),
        // because the Android client speaks exactly one contract to both hosts.

        // 1. Directory listing. An empty path returns the browsable roots.
        _app.MapGet("/api/fs/list", (HttpContext ctx, string? path) =>
        {
            string baseDir = GetUserAllowedBaseDirectory();

            if (string.IsNullOrWhiteSpace(path))
            {
                return Results.Ok(new[]
                {
                    new { name = "Home", path = baseDir, isDirectory = true, size = 0L, lastModified = (DateTimeOffset?)null }
                });
            }

            if (!TryResolveClientPath(path, baseDir, out string targetDir))
            {
                return Results.BadRequest(new { error = "Access denied: path is outside the allowed directory." });
            }

            if (!Directory.Exists(targetDir))
            {
                return Results.NotFound(new { error = "Directory not found." });
            }

            try
            {
                var visible = new List<FileSystemInfo>();
                foreach (var f in new DirectoryInfo(targetDir).EnumerateFileSystemInfos())
                {
                    if (f.Name.StartsWith('.')) continue;
                    try
                    {
                        // Hide symlinks that escape the allowed root.
                        if (!IsPathSafe(f.FullName, baseDir)) continue;
                        visible.Add(f);
                    }
                    catch { }
                }

                var entries = visible
                    .OrderByDescending(f => (f.Attributes & FileAttributes.Directory) != 0)
                    .ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(f =>
                    {
                        bool isDir = (f.Attributes & FileAttributes.Directory) != 0;
                        return new
                        {
                            name = f.Name,
                            path = f.FullName,
                            isDirectory = isDir,
                            size = isDir ? 0L : ((FileInfo)f).Length,
                            lastModified = (DateTimeOffset)f.LastWriteTimeUtc
                        };
                    })
                    .ToList();

                return Results.Ok(entries);
            }
            catch (Exception ex)
            {
                _logger.Warning($"LinuxFileTransferServer: listing '{targetDir}' failed: {ex.Message}");
                return Results.Problem("Directory listing failed or access denied");
            }
        });

        // 2. File download.
        _app.MapGet("/api/fs/download", (HttpContext ctx, string path) =>
        {
            if (string.IsNullOrWhiteSpace(path)) return Results.BadRequest(new { error = "Missing file path" });

            string baseDir = GetUserAllowedBaseDirectory();
            if (!TryResolveClientPath(path, baseDir, out string targetFile) || !File.Exists(targetFile))
            {
                return Results.NotFound(new { error = "File not found or access restricted" });
            }

            return Results.File(targetFile, "application/octet-stream", enableRangeProcessing: true, fileDownloadName: Path.GetFileName(targetFile));
        });

        // 3. Raw-body file upload (headers X-Tether-File-Name / X-Tether-File-SHA512).
        _app.MapPost("/api/fs/upload", async (HttpContext ctx, string? path) =>
        {
            string baseDir = GetUserAllowedBaseDirectory();
            string fileNameHeader = ctx.Request.Headers["X-Tether-File-Name"].ToString().Trim();
            string expectedHash = ctx.Request.Headers["X-Tether-File-SHA512"].ToString().Trim().ToLowerInvariant();

            if (string.IsNullOrEmpty(expectedHash) || expectedHash.Length != 128 || !expectedHash.All(Uri.IsHexDigit))
            {
                return Results.BadRequest(new { error = "Missing or malformed required header: X-Tether-File-SHA512" });
            }

            string safeName = Path.GetFileName(fileNameHeader.Replace('\\', '/'));
            if (string.IsNullOrEmpty(safeName) || safeName.Contains('\0') || safeName.StartsWith('.') || safeName.Length > 255)
            {
                return Results.BadRequest(new { error = "Invalid or prohibited file name" });
            }

            string rawPath = (path ?? "").Replace('\\', '/');
            string destPath;
            if (string.IsNullOrWhiteSpace(rawPath))
            {
                destPath = Path.Combine(baseDir, "Downloads", safeName);
            }
            else if (!TryResolveClientPath(rawPath, baseDir, out string resolved))
            {
                return Results.BadRequest(new { error = "Access denied: destination is outside the allowed directory" });
            }
            else
            {
                // The client may send a directory or a full file path.
                destPath = Directory.Exists(resolved) || rawPath.EndsWith('/')
                    ? Path.Combine(resolved, safeName)
                    : resolved;
            }

            string? destDir = Path.GetDirectoryName(destPath);
            if (string.IsNullOrEmpty(destDir))
            {
                return Results.BadRequest(new { error = "Invalid destination path" });
            }

            // Lexical containment before creating any directory, then canonical verification.
            // The deepest existing ancestor is checked first so a symlinked parent cannot
            // redirect the root daemon's directory creation outside the home.
            if (!IsLexicallyInside(destPath, baseDir) || !TryEnsureSafeDirectory(destDir, baseDir))
            {
                return Results.BadRequest(new { error = "Access denied: destination is outside the allowed directory" });
            }

            string tempPath = Path.Combine(destDir, $".tether_upload_{Guid.NewGuid():N}.tmp");
            try
            {
                using var hasher = SHA512.Create();
                await using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
                {
                    var buffer = new byte[81920];
                    int read;
                    while ((read = await ctx.Request.Body.ReadAsync(buffer, ctx.RequestAborted)) > 0)
                    {
                        hasher.TransformBlock(buffer, 0, read, null, 0);
                        await stream.WriteAsync(buffer.AsMemory(0, read), ctx.RequestAborted);
                    }
                    hasher.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                    await stream.FlushAsync(ctx.RequestAborted);
                }

                string actualHash = Convert.ToHexString(hasher.Hash!).ToLowerInvariant();
                if (!string.Equals(actualHash, expectedHash, StringComparison.Ordinal))
                {
                    _logger.Warning($"LinuxFileTransferServer: upload hash mismatch for '{safeName}'.");
                    try { File.Delete(tempPath); } catch { }
                    return Results.BadRequest(new { error = "Uploaded content does not match X-Tether-File-SHA512" });
                }

                if (OperatingSystem.IsLinux())
                {
                    try { File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
                }

                File.Move(tempPath, destPath, overwrite: true);
                return Results.Ok(new { success = true, fileName = safeName, path = destPath });
            }
            catch (OperationCanceledException)
            {
                try { File.Delete(tempPath); } catch { }
                throw;
            }
            catch (Exception ex)
            {
                try { File.Delete(tempPath); } catch { }
                _logger.Warning($"LinuxFileTransferServer: upload failed: {ex.Message}");
                return Results.Problem("Upload failed");
            }
        });

        // 4. Search.
        _app.MapGet("/api/fs/search", (HttpContext ctx, string? path, string? query, bool? recursive, int? maxResults) =>
        {
            if (string.IsNullOrWhiteSpace(query)) return Results.Ok(Array.Empty<object>());

            string baseDir = GetUserAllowedBaseDirectory();
            if (!TryResolveClientPath(string.IsNullOrWhiteSpace(path) ? baseDir : path, baseDir, out string searchRoot) ||
                !Directory.Exists(searchRoot))
            {
                return Results.BadRequest(new { error = "Invalid search path or access restricted" });
            }

            int limit = Math.Clamp(maxResults ?? 200, 1, 2000);
            bool deep = recursive ?? true;
            var results = new List<object>();

            void Walk(string dir, int depth)
            {
                if (results.Count >= limit || depth > 32) return;
                try
                {
                    foreach (var f in new DirectoryInfo(dir).EnumerateFileSystemInfos())
                    {
                        if (results.Count >= limit) return;
                        if (f.Name.StartsWith('.')) continue;
                        if (!IsPathSafe(f.FullName, baseDir)) continue;
                        bool isDir = (f.Attributes & FileAttributes.Directory) != 0;
                        if (f.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add(new
                            {
                                name = f.Name,
                                path = f.FullName,
                                isDirectory = isDir,
                                size = isDir ? 0L : ((FileInfo)f).Length,
                                lastModified = (DateTimeOffset)f.LastWriteTimeUtc
                            });
                        }
                        if (isDir && deep) Walk(f.FullName, depth + 1);
                    }
                }
                catch { }
            }

            Walk(searchRoot, 0);
            return Results.Ok(results);
        });

        // 5. Create directory.
        _app.MapPost("/api/fs/mkdir", async (HttpContext ctx) =>
        {
            var (req, error) = await ReadJsonBodyAsync(ctx);
            if (error != null) return error;
            string parent = req!.Value.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
            string name = req.Value.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            if (!IsValidEntryName(name)) return Results.BadRequest(new { error = "Invalid directory name" });

            string baseDir = GetUserAllowedBaseDirectory();
            if (!TryResolveClientPath(parent, baseDir, out string parentDir) || !Directory.Exists(parentDir))
            {
                return Results.BadRequest(new { error = "Invalid parent path" });
            }

            string newDir = Path.Combine(parentDir, name);
            if (!IsLexicallyInside(newDir, baseDir) || !IsPathSafe(newDir, baseDir))
            {
                return Results.BadRequest(new { error = "Invalid directory path or access restricted" });
            }

            try { Directory.CreateDirectory(newDir); return Results.Ok(new { success = true, path = newDir }); }
            catch (Exception ex) { _logger.Warning($"mkdir '{newDir}' failed: {ex.Message}"); return Results.Problem("Failed to create directory"); }
        });

        // 6. Rename (same directory).
        _app.MapPost("/api/fs/rename", async (HttpContext ctx) =>
        {
            var (req, error) = await ReadJsonBodyAsync(ctx);
            if (error != null) return error;
            string path = req!.Value.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
            string newName = req.Value.TryGetProperty("newName", out var n) ? n.GetString() ?? "" : "";
            if (!IsValidEntryName(newName)) return Results.BadRequest(new { error = "Invalid new file name" });

            string baseDir = GetUserAllowedBaseDirectory();
            if (!TryResolveClientPath(path, baseDir, out string fullPath) || (!File.Exists(fullPath) && !Directory.Exists(fullPath)))
            {
                return Results.BadRequest(new { error = "Invalid path or access restricted" });
            }

            string? dir = Path.GetDirectoryName(fullPath);
            if (string.IsNullOrEmpty(dir)) return Results.BadRequest(new { error = "Invalid path" });
            string newPath = Path.Combine(dir, newName);
            if (!IsPathSafe(newPath, baseDir)) return Results.BadRequest(new { error = "Invalid new path or access restricted" });

            try
            {
                if (File.Exists(fullPath)) File.Move(fullPath, newPath, overwrite: true);
                else Directory.Move(fullPath, newPath);
                return Results.Ok(new { success = true, newPath });
            }
            catch (Exception ex) { _logger.Warning($"rename failed: {ex.Message}"); return Results.Problem("Rename failed"); }
        });

        // 7. Move.
        _app.MapPost("/api/fs/move", async (HttpContext ctx) =>
        {
            var (req, error) = await ReadJsonBodyAsync(ctx);
            if (error != null) return error;
            string source = req!.Value.TryGetProperty("sourcePath", out var s) ? s.GetString() ?? "" : "";
            string destination = req.Value.TryGetProperty("destinationPath", out var d) ? d.GetString() ?? "" : "";

            string baseDir = GetUserAllowedBaseDirectory();
            if (!TryResolveClientPath(source, baseDir, out string srcPath) || (!File.Exists(srcPath) && !Directory.Exists(srcPath)) ||
                !TryResolveClientPath(destination, baseDir, out string dstPath))
            {
                return Results.BadRequest(new { error = "Invalid source or destination path" });
            }

            string finalDst = Directory.Exists(dstPath) ? Path.Combine(dstPath, Path.GetFileName(srcPath)) : dstPath;
            if (!IsLexicallyInside(finalDst, baseDir) || !IsPathSafe(finalDst, baseDir))
            {
                return Results.BadRequest(new { error = "Invalid destination path" });
            }

            try
            {
                if (!TryEnsureSafeDirectory(Path.GetDirectoryName(finalDst)!, baseDir))
                {
                    return Results.BadRequest(new { error = "Invalid destination path" });
                }
                if (File.Exists(srcPath)) File.Move(srcPath, finalDst, overwrite: true);
                else Directory.Move(srcPath, finalDst);
                return Results.Ok(new { success = true, destination = finalDst });
            }
            catch (Exception ex) { _logger.Warning($"move failed: {ex.Message}"); return Results.Problem("Move failed"); }
        });

        // 8. Delete (permanent, or to the XDG trash).
        _app.MapPost("/api/fs/delete", async (HttpContext ctx) =>
        {
            var (req, error) = await ReadJsonBodyAsync(ctx);
            if (error != null) return error;
            string path = req!.Value.TryGetProperty("path", out var p) ? p.GetString() ?? "" : "";
            bool permanent = req.Value.TryGetProperty("permanent", out var perm) && perm.ValueKind == JsonValueKind.True;

            string baseDir = GetUserAllowedBaseDirectory();
            if (!TryResolveClientPath(path, baseDir, out string fullPath) || (!File.Exists(fullPath) && !Directory.Exists(fullPath)))
            {
                return Results.BadRequest(new { error = "Invalid path or access restricted" });
            }
            if (string.Equals(fullPath.TrimEnd('/'), baseDir.TrimEnd('/'), StringComparison.Ordinal))
            {
                return Results.BadRequest(new { error = "Refusing to delete the home directory" });
            }

            try
            {
                if (permanent)
                {
                    if (File.Exists(fullPath)) File.Delete(fullPath);
                    else Directory.Delete(fullPath, recursive: true);
                }
                else
                {
                    TrashPath(fullPath, baseDir);
                }
                return Results.Ok(new { success = true });
            }
            catch (Exception ex) { _logger.Warning($"delete failed: {ex.Message}"); return Results.Problem("Delete failed"); }
        });

        // 9. Empty the XDG trash.
        _app.MapPost("/api/fs/recycle-bin/empty", (HttpContext ctx) =>
        {
            string baseDir = GetUserAllowedBaseDirectory();
            try
            {
                foreach (var sub in new[] { ".local/share/Trash/files", ".local/share/Trash/info" })
                {
                    string dir = Path.Combine(baseDir, sub);
                    if (!Directory.Exists(dir)) continue;
                    foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
                    {
                        if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                        else File.Delete(entry);
                    }
                }
                return Results.Ok(new { success = true });
            }
            catch (Exception ex) { _logger.Warning($"trash empty failed: {ex.Message}"); return Results.Problem("Failed to empty trash"); }
        });

        // 10. Application catalog (same shape as the Windows endpoint).
        _app.MapGet("/api/apps/catalog", (HttpContext ctx) =>
        {
            var apps = Tether.LinuxDaemon.Capabilities.LinuxApplicationManager.GetInstalledApps(_logger);
            return Results.Ok(apps);
        });

        // 11. Remote Desktop Stream (MJPEG multipart/x-mixed-replace)
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

        // 12. Remote Desktop Screenshot Endpoint
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

        // 13. Active Windows List Endpoint
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
        if (!string.IsNullOrEmpty(session.UserName) && session.UserName != "root")
        {
            // Prefer the account's real home from /etc/passwd (handles /var/home etc.).
            try
            {
                foreach (var line in File.ReadLines("/etc/passwd"))
                {
                    var parts = line.Split(':');
                    if (parts.Length >= 7 && parts[0] == session.UserName &&
                        !string.IsNullOrEmpty(parts[5]) && Directory.Exists(parts[5]))
                    {
                        return parts[5];
                    }
                }
            }
            catch { }

            foreach (var candidate in new[] { $"/home/{session.UserName}", $"/var/home/{session.UserName}" })
            {
                if (Directory.Exists(candidate)) return candidate;
            }
        }

        // Fail closed rather than exposing root's home.
        return "/nonexistent-tether-home";
    }

    /// <summary>
    /// Normalises a client path (the Android client builds Windows-style separators) and
    /// confines it to the user's allowed root.
    /// </summary>
    private static bool TryResolveClientPath(string? rawPath, string baseDir, out string fullPath)
    {
        fullPath = "";
        if (string.IsNullOrWhiteSpace(rawPath)) return false;

        string normalized = rawPath.Replace('\\', '/').Trim();
        if (normalized.Contains('\0')) return false;
        foreach (var seg in normalized.Split('/'))
        {
            if (seg == "..") return false;
        }

        string combined = Path.IsPathRooted(normalized) ? normalized : Path.Combine(baseDir, normalized);
        try { fullPath = Path.GetFullPath(combined); }
        catch { return false; }

        return IsLexicallyInside(fullPath, baseDir) && IsPathSafe(fullPath, baseDir);
    }

    /// <summary>
    /// Creates a directory only after the nearest existing ancestor is proven to resolve
    /// inside the allowed root. Prevents a symlinked parent from redirecting root's mkdir.
    /// </summary>
    private static bool TryEnsureSafeDirectory(string dir, string baseDir)
    {
        try
        {
            string? existing = dir;
            while (!string.IsNullOrEmpty(existing) && !Directory.Exists(existing))
            {
                existing = Path.GetDirectoryName(existing);
            }
            if (string.IsNullOrEmpty(existing) || !IsPathSafe(existing, baseDir)) return false;
            Directory.CreateDirectory(dir);
            return IsPathSafe(dir, baseDir);
        }
        catch { return false; }
    }

    private static bool IsLexicallyInside(string fullPath, string baseDir)
    {
        try
        {
            string root = Path.GetFullPath(baseDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string target = Path.GetFullPath(fullPath);
            return string.Equals(target, root, StringComparison.Ordinal) ||
                   target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal);
        }
        catch { return false; }
    }

    private static bool IsValidEntryName(string name)
    {
        return !string.IsNullOrWhiteSpace(name) && name.Length <= 255 &&
               name != "." && name != ".." && !name.StartsWith('.') &&
               name.IndexOfAny(new[] { '/', '\\', '\0' }) < 0;
    }

    private static async Task<(JsonElement? Body, IResult? Error)> ReadJsonBodyAsync(HttpContext ctx)
    {
        if (!ctx.Request.HasJsonContentType())
        {
            return (null, Results.BadRequest(new { error = "Expected application/json body" }));
        }

        try
        {
            using var buffered = new MemoryStream();
            var buffer = new byte[8192];
            int read;
            while ((read = await ctx.Request.Body.ReadAsync(buffer, ctx.RequestAborted)) > 0)
            {
                if (buffered.Length + read > 64 * 1024)
                {
                    return (null, Results.BadRequest(new { error = "JSON payload too large" }));
                }
                buffered.Write(buffer, 0, read);
            }
            buffered.Position = 0;
            using var doc = await JsonDocument.ParseAsync(buffered, cancellationToken: ctx.RequestAborted);
            return (doc.RootElement.Clone(), null);
        }
        catch
        {
            return (null, Results.BadRequest(new { error = "Invalid JSON payload" }));
        }
    }

    /// <summary>Moves a path into the user's XDG trash instead of deleting it.</summary>
    private static void TrashPath(string fullPath, string baseDir)
    {
        string trashRoot = Path.Combine(baseDir, ".local", "share", "Trash");
        string filesDir = Path.Combine(trashRoot, "files");
        string infoDir = Path.Combine(trashRoot, "info");
        if (!TryEnsureSafeDirectory(filesDir, baseDir) || !TryEnsureSafeDirectory(infoDir, baseDir))
        {
            throw new IOException("Trash directory is outside the allowed root.");
        }

        string name = Path.GetFileName(fullPath);
        string candidate = name;
        int suffix = 1;
        while (File.Exists(Path.Combine(filesDir, candidate)) || Directory.Exists(Path.Combine(filesDir, candidate)))
        {
            candidate = $"{name}.{suffix++}";
        }

        string trashPath = Path.Combine(filesDir, candidate);
        if (File.Exists(fullPath)) File.Move(fullPath, trashPath);
        else Directory.Move(fullPath, trashPath);

        try
        {
            string encoded = string.Join("/", fullPath.Split('/').Select(Uri.EscapeDataString));
            File.WriteAllText(
                Path.Combine(infoDir, candidate + ".trashinfo"),
                $"[Trash Info]\nPath={encoded}\nDeletionDate={DateTime.Now:yyyy-MM-ddTHH:mm:ss}\n");
        }
        catch
        {
            // Do not leave a file in the trash without its restore metadata.
            try
            {
                if (Directory.Exists(trashPath)) Directory.Move(trashPath, fullPath);
                else File.Move(trashPath, fullPath);
            }
            catch { }
            throw;
        }
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
