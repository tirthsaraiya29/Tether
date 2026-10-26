using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
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
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly TokenStore _tokenStore;
    private readonly SessionManager _sessionManager;
    private readonly TrustStore _trustStore;
    private WebApplication? _app;

    private static readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pendingRequests = new();

    public FileTransferServer(ITetherLogger logger, WindowsIdentity identity, TokenStore tokenStore, SessionManager sessionManager, TrustStore trustStore)
    {
        _logger = logger;
        _identity = identity;
        _tokenStore = tokenStore;
        _sessionManager = sessionManager;
        _trustStore = trustStore;
    }

    public static bool TryGetValidPath(string? inputPath, out string fullPath)
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

            // Block UNC paths (e.g. \\server\share or //server/share)
            if (inputPath.StartsWith(@"\\") || inputPath.StartsWith("//"))
            {
                return false;
            }

            var normalized = Path.GetFullPath(inputPath);
            if (!Path.IsPathRooted(normalized))
            {
                return false;
            }

            // Block Windows system directories and Tether application internal store
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string progDataTether = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether");

            if (!string.IsNullOrEmpty(winDir) && (normalized.Equals(winDir, StringComparison.OrdinalIgnoreCase) || normalized.StartsWith(winDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            if (!string.IsNullOrEmpty(progDataTether) && (normalized.Equals(progDataTether, StringComparison.OrdinalIgnoreCase) || normalized.StartsWith(progDataTether + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
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

        // Initialize local loopback token for DesktopUI
        _tokenStore.GetOrCreateLocalUiToken();

        var builder = WebApplication.CreateBuilder();

        builder.WebHost.UseKestrel(options =>
        {
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
                    var drives = DriveInfo.GetDrives().Where(d => d.IsReady).Select(d => new
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
                    return Results.NotFound(new { error = "Directory not found" });
                }

                var dirInfo = new DirectoryInfo(fullPath);

                var entries = new List<object>();
                foreach (var dir in dirInfo.GetDirectories())
                {
                    entries.Add(new
                    {
                        name = dir.Name,
                        path = dir.FullName,
                        isDirectory = true,
                        size = 0L,
                        lastModified = (DateTimeOffset)dir.LastWriteTimeUtc
                    });
                }

                foreach (var file in dirInfo.GetFiles())
                {
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
                return Results.Problem(ex.Message);
            }
        });

        _app.MapGet("/api/fs/download", (string path, HttpContext context) =>
        {
            try
            {
                if (!TryGetValidPath(path, out var fullPath) || !File.Exists(fullPath))
                {
                    return Results.NotFound("File not found");
                }

                string hashHex = ComputeSha512Hex(fullPath);
                context.Response.Headers["X-Tether-File-SHA512"] = hashHex;

                var contentType = "application/octet-stream";
                return Results.File(fullPath, contentType, enableRangeProcessing: true);
            }
            catch (Exception ex)
            {
                _logger.Error($"Error downloading {path}: {ex.Message}");
                return Results.Problem(ex.Message);
            }
        });

        _app.MapPost("/api/fs/upload", async (string path, HttpContext context) =>
        {
            try
            {
                if (!TryGetValidPath(path, out var fullPath))
                {
                    return Results.BadRequest("Path is required or restricted");
                }

                var dir = Path.GetDirectoryName(fullPath);
                if (dir != null && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                string tempPath = fullPath + $".tmp_{Guid.NewGuid():N}";
                string expectedHashHex = context.Request.Headers["X-Tether-File-SHA512"].ToString().Trim().ToLowerInvariant();

                try
                {
                    using (var sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
                    using (var tempStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true))
                    {
                        var buffer = new byte[81920];
                        int bytesRead;
                        while ((bytesRead = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            await tempStream.WriteAsync(buffer, 0, bytesRead);
                            sha512.AppendData(buffer, 0, bytesRead);
                        }

                        byte[] actualHash = sha512.GetHashAndReset();
                        string actualHashHex = Convert.ToHexString(actualHash).ToLowerInvariant();

                        if (!string.IsNullOrEmpty(expectedHashHex) && !string.Equals(expectedHashHex, actualHashHex, StringComparison.OrdinalIgnoreCase))
                        {
                            _logger.Warning($"SHA-512 integrity check failed for upload to {fullPath}. Expected: {expectedHashHex}, Actual: {actualHashHex}");
                            try { File.Delete(tempPath); } catch { }
                            return Results.BadRequest("Integrity check failed: SHA-512 hash mismatch");
                        }
                    }

                    File.Move(tempPath, fullPath, overwrite: true);
                }
                catch
                {
                    if (File.Exists(tempPath))
                    {
                        try { File.Delete(tempPath); } catch { }
                    }
                    throw;
                }

                return Results.Ok();
            }
            catch (Exception ex)
            {
                _logger.Error($"Error uploading {path}: {ex.Message}");
                return Results.Problem(ex.Message);
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
                try {
                    var items = JsonDocument.Parse(resultJson).RootElement.GetProperty("items");
                    return Results.Content(items.GetRawText(), "application/json");
                } catch { return Results.Ok(new object[0]); }
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

            _sessionManager.BroadcastRawFrame(JsonSerializer.Serialize(new {
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

            _sessionManager.BroadcastRawFrame(JsonSerializer.Serialize(new {
                type = "FS_RECEIVE_FILE",
                requestId = reqId,
                windowsPath = localPath,
                fileName = fileName,
                token = token
            }));
            return Results.Ok();
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
