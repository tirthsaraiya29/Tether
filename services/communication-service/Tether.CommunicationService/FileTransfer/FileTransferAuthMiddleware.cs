using Microsoft.AspNetCore.Http;
using System;
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

namespace Tether.CommunicationService.FileTransfer;

public class FileTransferAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenStore _tokenStore;
    private readonly TrustStore? _trustStore;
    private readonly WindowsIdentity? _identity;

    public FileTransferAuthMiddleware(RequestDelegate next, TokenStore tokenStore, TrustStore? trustStore = null, WindowsIdentity? identity = null)
    {
        _next = next;
        _tokenStore = tokenStore;
        _trustStore = trustStore;
        _identity = identity;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var authValues))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized: Missing Authorization header");
            return;
        }

        var authHeader = authValues.ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized: Invalid Authorization scheme");
            return;
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();
        if (string.IsNullOrEmpty(token))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized: Empty Bearer token");
            return;
        }

        var remoteIp = context.Connection.RemoteIpAddress;
        bool isLoopback = remoteIp == null || IPAddress.IsLoopback(remoteIp);

        if (isLoopback)
        {
            if (_tokenStore.ValidateToken(token, "LOCAL_UI"))
            {
                var identity = new ClaimsIdentity(new[] {
                    new Claim(ClaimTypes.Name, "TetherLocalUI"),
                    new Claim("DeviceFingerprint", "LOCAL_UI")
                }, "Bearer");
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

            if (long.TryParse(tsStr, out long tsMs))
            {
                var clientTime = DateTimeOffset.FromUnixTimeMilliseconds(tsMs);
                if (Math.Abs((DateTimeOffset.UtcNow - clientTime).TotalMinutes) <= 3)
                {
                    if (_tokenStore.TryGetTokenMetadata(token, out var meta) && !string.IsNullOrEmpty(meta.DeviceFingerprint))
                    {
                        string expectedFingerprint = meta.DeviceFingerprint;
                        var pairedPhone = _trustStore?.All().FirstOrDefault(p =>
                            string.Equals(p.Fingerprint, expectedFingerprint, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(p.DeviceId, expectedFingerprint, StringComparison.OrdinalIgnoreCase));

                        if (pairedPhone != null)
                        {
                            string winSpki = _identity?.GetPublicKeySpkiBase64() ?? "";
                            string proofData = $"{token}:{tsStr}:{winSpki}";

                            if (VerifyEcdsaSignature(pairedPhone.PublicKeySpkiBase64, Encoding.UTF8.GetBytes(proofData), proofBase64))
                            {
                                if (_tokenStore.ValidateToken(token, expectedFingerprint))
                                {
                                    var identity = new ClaimsIdentity(new[] {
                                        new Claim(ClaimTypes.Name, "TetherRemoteClient"),
                                        new Claim("DeviceFingerprint", expectedFingerprint)
                                    }, "Bearer");
                                    context.User = new ClaimsPrincipal(identity);
                                    await _next(context);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }

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
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
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
