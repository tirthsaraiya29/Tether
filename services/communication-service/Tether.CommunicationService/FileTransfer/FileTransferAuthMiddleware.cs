using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Trust;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.FileTransfer;

public class FileTransferAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenStore _tokenStore;
    private readonly TrustStore? _trustStore;
    private readonly WindowsIdentity? _identity;
    private readonly ITetherLogger? _logger;

    public FileTransferAuthMiddleware(
        RequestDelegate next,
        TokenStore tokenStore,
        TrustStore? trustStore = null,
        WindowsIdentity? identity = null,
        ITetherLogger? logger = null)
    {
        _next = next;
        _tokenStore = tokenStore;
        _trustStore = trustStore;
        _identity = identity;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var remoteIp = context.Connection.RemoteIpAddress;
        _logger?.Info($"FileTransferAuthMiddleware: Incoming {context.Request.Method} request for {context.Request.Path} from {remoteIp}");

        if (!context.Request.Headers.TryGetValue("Authorization", out var authValues))
        {
            _logger?.Warning($"FileTransferAuthMiddleware: Missing Authorization header from {remoteIp}");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized: Missing Authorization header");
            return;
        }

        var authHeader = authValues.ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            _logger?.Warning($"FileTransferAuthMiddleware: Invalid Authorization scheme from {remoteIp}");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized: Invalid Authorization scheme");
            return;
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();
        if (string.IsNullOrEmpty(token))
        {
            _logger?.Warning($"FileTransferAuthMiddleware: Empty Bearer token from {remoteIp}");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized: Empty Bearer token");
            return;
        }

        bool isLoopback = remoteIp == null || IPAddress.IsLoopback(remoteIp);

        if (isLoopback)
        {
            if (_tokenStore.ValidateToken(token, "LOCAL_UI"))
            {
                var path = context.Request.Path.Value ?? "";
                if (path.StartsWith("/api/fs/download", StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith("/api/fs/upload", StringComparison.OrdinalIgnoreCase))
                {
                    _logger?.Warning($"FileTransferAuthMiddleware: Rejected privileged direct filesystem access via LOCAL_UI token from {remoteIp} for {path}");
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("Forbidden: Local UI tokens are not authorized for direct file read/write endpoints");
                    return;
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, "TetherLocalUI"),
                    new Claim("DeviceFingerprint", "LOCAL_UI")
                };

                var consoleUserSid = TokenStore.GetActiveConsoleUserSid();
                if (consoleUserSid != null)
                {
                    claims.Add(new Claim(ClaimTypes.PrimarySid, consoleUserSid.Value));
                }

                var identity = new ClaimsIdentity(claims, "Bearer");
                context.User = new ClaimsPrincipal(identity);
                await _next(context);
                return;
            }
        }

        var clientCert = context.Connection.ClientCertificate;
        if (clientCert == null)
        {
            try { clientCert = await context.Connection.GetClientCertificateAsync(); } catch { }
        }

        if (clientCert != null)
        {
            var now = DateTime.UtcNow;
            if (clientCert.NotBefore.ToUniversalTime() <= now && clientCert.NotAfter.ToUniversalTime() >= now)
            {
                string spkiBase64 = Convert.ToBase64String(ExportSpki(clientCert));
                string clientFingerprint = TrustStore.ComputeFingerprintOrNull(spkiBase64) ?? "";

                if (_trustStore == null || _trustStore.FindBySpkiBase64(spkiBase64) != null)
                {
                    if (_tokenStore.ValidateToken(token, clientFingerprint))
                    {
                        var identity = new ClaimsIdentity(new[] {
                            new Claim(ClaimTypes.Name, "TetherRemoteClient"),
                            new Claim("DeviceFingerprint", clientFingerprint)
                        }, "Bearer");
                        context.User = new ClaimsPrincipal(identity);
                        await _next(context);
                        return;
                    }
                }
            }
        }

        if (context.Request.Headers.TryGetValue("X-Tether-Client-Proof", out var proofHeader) &&
            context.Request.Headers.TryGetValue("X-Tether-Client-Timestamp", out var tsHeader))
        {
            string proofBase64 = proofHeader.ToString().Trim();
            string tsStr = tsHeader.ToString().Trim();
            string clientWinSpki = context.Request.Headers.TryGetValue("X-Tether-Client-WinSpki", out var spkiH)
                ? spkiH.ToString().Trim()
                : "";

            if (long.TryParse(tsStr, out long tsMs))
            {
                var clientTime = DateTimeOffset.FromUnixTimeMilliseconds(tsMs);
                var timeDelta = Math.Abs((DateTimeOffset.UtcNow - clientTime).TotalMinutes);

                if (timeDelta <= 5)
                {
                    if (_tokenStore.TryGetTokenMetadata(token, out var meta))
                    {
                        string? targetFingerprint = meta.DeviceFingerprint;
                        var allPaired = _trustStore?.All() ?? Array.Empty<TrustedPhone>();
                        var candidatePhones = !string.IsNullOrEmpty(targetFingerprint)
                            ? allPaired.Where(p => string.Equals(p.Fingerprint, targetFingerprint, StringComparison.OrdinalIgnoreCase) ||
                                                   string.Equals(p.DeviceId, targetFingerprint, StringComparison.OrdinalIgnoreCase)).ToList()
                            : allPaired.ToList();

                        foreach (var pairedPhone in candidatePhones)
                        {
                            string winSpki = _identity?.GetPublicKeySpkiBase64() ?? "";
                            var proofCandidates = new List<string> { $"{token}:{tsStr}:{winSpki}" };
                            if (!string.IsNullOrEmpty(clientWinSpki) && !string.Equals(clientWinSpki, winSpki, StringComparison.Ordinal))
                            {
                                proofCandidates.Add($"{token}:{tsStr}:{clientWinSpki}");
                            }
                            proofCandidates.Add($"{token}:{tsStr}:");

                            bool validProof = false;
                            foreach (var pData in proofCandidates.Distinct())
                            {
                                if (VerifyEcdsaSignature(pairedPhone.PublicKeySpkiBase64, Encoding.UTF8.GetBytes(pData), proofBase64))
                                {
                                    validProof = true;
                                    break;
                                }
                            }

                            if (validProof)
                            {
                                if (_tokenStore.ValidateToken(token, pairedPhone.Fingerprint) || _tokenStore.ValidateToken(token))
                                {
                                    _logger?.Info($"FileTransferAuthMiddleware: Authorized client '{pairedPhone.DisplayName}' ({pairedPhone.Fingerprint}) for {context.Request.Path}");
                                    var identity = new ClaimsIdentity(new[] {
                                        new Claim(ClaimTypes.Name, "TetherRemoteClient"),
                                        new Claim("DeviceFingerprint", pairedPhone.Fingerprint)
                                    }, "Bearer");
                                    context.User = new ClaimsPrincipal(identity);
                                    await _next(context);
                                    return;
                                }
                                else
                                {
                                    _logger?.Warning($"FileTransferAuthMiddleware: Token validation failed for client '{pairedPhone.DisplayName}' ({pairedPhone.Fingerprint})");
                                }
                            }
                            else
                            {
                                _logger?.Warning($"FileTransferAuthMiddleware: Signature verification failed for client candidate '{pairedPhone.DisplayName}' ({pairedPhone.Fingerprint})");
                            }
                        }
                    }
                    else
                    {
                        _logger?.Warning($"FileTransferAuthMiddleware: Token not found in TokenStore: '{token}'");
                    }
                }
                else
                {
                    _logger?.Warning($"FileTransferAuthMiddleware: Client timestamp delta ({timeDelta:F1}m) exceeds 5 min limit from {remoteIp}");
                }
            }
            else
            {
                _logger?.Warning($"FileTransferAuthMiddleware: Malformed timestamp header '{tsStr}' from {remoteIp}");
            }
        }
        else
        {
            _logger?.Warning($"FileTransferAuthMiddleware: Missing client proof headers from {remoteIp}");
        }

        _logger?.Warning($"FileTransferAuthMiddleware: Authorization failed for request {context.Request.Path} from {remoteIp}");
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Unauthorized: Token validation failed or invalid device binding");
    }

    public static bool VerifyEcdsaSignature(string spkiBase64, byte[] data, string signatureBase64)
    {
        try
        {
            byte[] spkiDer = Convert.FromBase64String(spkiBase64);
            byte[] signature = Convert.FromBase64String(signatureBase64);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spkiDer, out _);

            if (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
            {
                return true;
            }

            if (ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256))
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

    private static byte[] ExportSpki(X509Certificate2 cert)
    {
        using var ec = cert.GetECDsaPublicKey();
        if (ec != null) return ec.ExportSubjectPublicKeyInfo();

        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null) return rsa.ExportSubjectPublicKeyInfo();

        return Array.Empty<byte>();
    }
}