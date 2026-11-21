using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.FileTransfer;
using Tether.CommunicationService.Trust;
using Xunit;

namespace Tether.Tests;

public class TETH_SEC_001_FilesCapabilityTests
{
    private static X509Certificate2 CreateTestCertificate(out string spkiBase64)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=TetherTestPhone", ecdsa, HashAlgorithmName.SHA256);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-10), DateTimeOffset.UtcNow.AddHours(2));
        spkiBase64 = Convert.ToBase64String(cert.PublicKey.ExportSubjectPublicKeyInfo());
        return cert;
    }

    [Fact]
    public void TokenStore_TokenWithoutFilesCapability_RejectedByValidateToken()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromHours(1), "test-fp-1", new[] { "CLIPBOARD", "MEDIA" });

        bool hasFiles = tokenStore.ValidateToken(token, "test-fp-1", "FILES");
        Assert.False(hasFiles, "Token without FILES capability must be rejected when FILES is required.");

        bool hasClipboard = tokenStore.ValidateToken(token, "test-fp-1", "CLIPBOARD");
        Assert.True(hasClipboard, "Token should be valid for authorized capability CLIPBOARD.");
    }

    [Fact]
    public void TokenStore_TokenWithFilesCapability_AcceptedByValidateToken()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromHours(1), "test-fp-2", new[] { "FILES", "CLIPBOARD" });

        bool hasFiles = tokenStore.ValidateToken(token, "test-fp-2", "FILES");
        Assert.True(hasFiles, "Token with explicit FILES capability must be accepted.");

        Assert.True(tokenStore.TryGetTokenMetadata(token, out var meta));
        Assert.Contains("FILES", meta.Capabilities);
    }

    [Fact]
    public void TokenStore_TokenWithWildcardCapability_AcceptedByValidateToken()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromHours(1), "test-fp-3", new[] { "*" });

        bool hasFiles = tokenStore.ValidateToken(token, "test-fp-3", "FILES");
        Assert.True(hasFiles, "Token with wildcard '*' capability must satisfy FILES requirement.");
    }

    private static void AddClientProofHeaders(HttpContext context, string token, ECDsa clientKey)
    {
        string tsStr = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        string pData = $"{token}:{tsStr}:";
        byte[] sig = clientKey.SignData(Encoding.UTF8.GetBytes(pData), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        context.Request.Headers["X-Tether-Client-Proof"] = Convert.ToBase64String(sig);
        context.Request.Headers["X-Tether-Client-Timestamp"] = tsStr;
    }

    [Fact]
    public async Task FileTransferAuthMiddleware_RejectsTokenWithoutFilesCapability_With403()
    {
        var logger = new TestLogger();
        var tokenStore = new TokenStore();
        string tempDir = Path.Combine(Path.GetTempPath(), "tether_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var trustStore = new TrustStore(logger, tempDir);
            using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string spki = Convert.ToBase64String(clientKey.ExportSubjectPublicKeyInfo());
            string fingerprint = TrustStore.ComputeFingerprintOrNull(spki) ?? "test-fp";

            trustStore.AddOrUpdate("dev-1", "TestPhone", spki, new[] { "CLIPBOARD", "NOTIFICATIONS" }, "2.0");
            string token = tokenStore.GenerateToken(TimeSpan.FromHours(1), fingerprint, new[] { "CLIPBOARD", "NOTIFICATIONS" });

            bool nextCalled = false;
            RequestDelegate next = (ctx) =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            };

            var middleware = new FileTransferAuthMiddleware(next, tokenStore, trustStore: trustStore, identity: null, logger: logger);

            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
            context.Request.Headers["Authorization"] = $"Bearer {token}";
            AddClientProofHeaders(context, token, clientKey);
            context.Request.Path = "/api/fs/list";
            context.Response.Body = new MemoryStream();

            await middleware.InvokeAsync(context);

            Assert.False(nextCalled, "Pipeline must NOT call next when FILES capability is missing.");
            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);

            context.Response.Body.Seek(0, SeekOrigin.Begin);
            string responseBody = await new StreamReader(context.Response.Body).ReadToEndAsync();
            Assert.Contains("Token lacks FILES capability", responseBody);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public async Task FileTransferAuthMiddleware_AcceptsTokenWithFilesCapability_CallsNext()
    {
        var logger = new TestLogger();
        var tokenStore = new TokenStore();
        string tempDir = Path.Combine(Path.GetTempPath(), "tether_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var trustStore = new TrustStore(logger, tempDir);
            using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string spki = Convert.ToBase64String(clientKey.ExportSubjectPublicKeyInfo());
            string fingerprint = TrustStore.ComputeFingerprintOrNull(spki) ?? "test-fp";

            trustStore.AddOrUpdate("dev-2", "TestPhone", spki, new[] { "FILES" }, "2.0");
            string token = tokenStore.GenerateToken(TimeSpan.FromHours(1), fingerprint, new[] { "FILES" });

            bool nextCalled = false;
            RequestDelegate next = (ctx) =>
            {
                nextCalled = true;
                ctx.Response.StatusCode = StatusCodes.Status200OK;
                return Task.CompletedTask;
            };

            var middleware = new FileTransferAuthMiddleware(next, tokenStore, trustStore: trustStore, identity: null, logger: logger);

            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
            context.Request.Headers["Authorization"] = $"Bearer {token}";
            AddClientProofHeaders(context, token, clientKey);
            context.Request.Path = "/api/fs/download";

            await middleware.InvokeAsync(context);

            Assert.True(nextCalled, "Pipeline must call next when token has FILES capability.");
            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public async Task FileTransferAuthMiddleware_AcceptsTokenWithWildcardCapability_CallsNext()
    {
        var logger = new TestLogger();
        var tokenStore = new TokenStore();
        string tempDir = Path.Combine(Path.GetTempPath(), "tether_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var trustStore = new TrustStore(logger, tempDir);
            using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string spki = Convert.ToBase64String(clientKey.ExportSubjectPublicKeyInfo());
            string fingerprint = TrustStore.ComputeFingerprintOrNull(spki) ?? "test-fp";

            trustStore.AddOrUpdate("dev-3", "TestPhone", spki, new[] { "*" }, "2.0");
            string token = tokenStore.GenerateToken(TimeSpan.FromHours(1), fingerprint, new[] { "*" });

            bool nextCalled = false;
            RequestDelegate next = (ctx) =>
            {
                nextCalled = true;
                ctx.Response.StatusCode = StatusCodes.Status200OK;
                return Task.CompletedTask;
            };

            var middleware = new FileTransferAuthMiddleware(next, tokenStore, trustStore: trustStore, identity: null, logger: logger);

            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
            context.Request.Headers["Authorization"] = $"Bearer {token}";
            AddClientProofHeaders(context, token, clientKey);
            context.Request.Path = "/api/fs/upload";

            await middleware.InvokeAsync(context);

            Assert.True(nextCalled, "Pipeline must call next when token has wildcard capability.");
            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void CapabilityManager_HasCapability_FilesValidation()
    {
        var logger = new TestLogger();
        var capManager = new CapabilityManager(logger);

        var deviceWithoutFiles = new TetherDevice
        {
            DeviceId = "dev1",
            DisplayName = "Phone1",
            Fingerprint = "fp1",
            PublicKeySpkiBase64 = "spki1",
            Capabilities = new List<string> { "CLIPBOARD", "MEDIA" }
        };
        var deviceWithFiles = new TetherDevice
        {
            DeviceId = "dev2",
            DisplayName = "Phone2",
            Fingerprint = "fp2",
            PublicKeySpkiBase64 = "spki2",
            Capabilities = new List<string> { "CLIPBOARD", "FILES" }
        };
        var deviceWithWildcard = new TetherDevice
        {
            DeviceId = "dev3",
            DisplayName = "Phone3",
            Fingerprint = "fp3",
            PublicKeySpkiBase64 = "spki3",
            Capabilities = new List<string> { "*" }
        };

        Assert.False(capManager.HasCapability(deviceWithoutFiles, "FILES"), "Device without FILES must be rejected.");
        Assert.True(capManager.HasCapability(deviceWithFiles, "FILES"), "Device with FILES must be approved.");
        Assert.True(capManager.HasCapability(deviceWithWildcard, "FILES"), "Device with '*' must be approved.");
    }
}
