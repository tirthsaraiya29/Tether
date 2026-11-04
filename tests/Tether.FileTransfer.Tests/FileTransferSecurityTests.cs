using System;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Tether.CommunicationService.FileTransfer;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Trust;
using Tether.DesktopUI;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.FileTransfer.Tests;

public class MockLogger : ITetherLogger
{
    public void Debug(string message) { }
    public void Info(string message) { }
    public void Warning(string message) { }
    public void Error(string message, Exception? exception = null) { }
}

public class DummyTlsFeature : ITlsConnectionFeature
{
    public X509Certificate2? ClientCertificate { get; set; }
    public Task<X509Certificate2?> GetClientCertificateAsync(System.Threading.CancellationToken cancellationToken)
        => Task.FromResult(ClientCertificate);
}

public class FileTransferSecurityTests
{
    private static X509Certificate2 CreateTestCert(string subjectName, TimeSpan validDuration)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(new X500DistinguishedName(subjectName), ec, HashAlgorithmName.SHA256);
        DateTimeOffset notBefore, notAfter;
        if (validDuration < TimeSpan.Zero)
        {
            notBefore = DateTimeOffset.UtcNow.AddDays(-10);
            notAfter = DateTimeOffset.UtcNow.AddDays(-1);
        }
        else
        {
            notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            notAfter = notBefore.Add(validDuration);
        }
        return req.CreateSelfSigned(notBefore, notAfter);
    }

    private static byte[] ExportSpki(X509Certificate2 cert)
    {
        using var ec = cert.GetECDsaPublicKey();
        if (ec != null) return ec.ExportSubjectPublicKeyInfo();
        using var rsa = cert.GetRSAPublicKey();
        if (rsa != null) return rsa.ExportSubjectPublicKeyInfo();
        return Array.Empty<byte>();
    }

    [Fact]
    public void TestTokenStore_GeneratesAndValidatesCryptographicToken()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10));

        Assert.NotNull(token);
        Assert.True(token.Length >= 32);
        Assert.True(tokenStore.ValidateToken(token));
    }

    [Fact]
    public void TestTokenStore_RejectsExpiredOrInvalidToken()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromMilliseconds(-100)); // already expired

        Assert.False(tokenStore.ValidateToken(token));
        Assert.False(tokenStore.ValidateToken("invalid_fake_token"));
        Assert.False(tokenStore.ValidateToken(""));
    }

    [Fact]
    public void TestTokenStore_LocalUiTokenCreationAndValidation()
    {
        var tokenStore = new TokenStore();
        string localToken = tokenStore.GetOrCreateLocalUiToken();

        Assert.NotNull(localToken);
        Assert.True(localToken.Length >= 32);
        Assert.True(tokenStore.ValidateToken(localToken, "LOCAL_UI"));
    }

    [Fact]
    public void TestTokenStore_EnforcesDeviceFingerprintBinding()
    {
        var tokenStore = new TokenStore();
        string deviceFp = "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00";
        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10), deviceFp);

        Assert.True(tokenStore.ValidateToken(token, deviceFp));
        Assert.False(tokenStore.ValidateToken(token, "WRONG:FINGERPRINT"));
        Assert.False(tokenStore.ValidateToken(token, "LOCAL_UI"));
    }

    [Fact]
    public void TestTokenStore_Revocation_InvalidatesTokenOnSubsequentValidation()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10));

        Assert.True(tokenStore.ValidateToken(token));
        Assert.True(tokenStore.RevokeToken(token));
        Assert.False(tokenStore.ValidateToken(token));
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_RejectsUnauthenticatedRequest()
    {
        var tokenStore = new TokenStore();
        var middleware = new FileTransferAuthMiddleware((innerCtx) => Task.CompletedTask, tokenStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.50");

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_RejectsUnauthenticatedLoopbackRequest()
    {
        var tokenStore = new TokenStore();
        var middleware = new FileTransferAuthMiddleware((innerCtx) => Task.CompletedTask, tokenStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Loopback;

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_AcceptsValidBearerToken()
    {
        var tokenStore = new TokenStore();
        string validToken = tokenStore.GetOrCreateLocalUiToken();

        bool innerPipelineExecuted = false;
        var middleware = new FileTransferAuthMiddleware((innerCtx) =>
        {
            innerPipelineExecuted = true;
            return Task.CompletedTask;
        }, tokenStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Loopback;
        httpContext.Request.Headers["Authorization"] = $"Bearer {validToken}";

        await middleware.InvokeAsync(httpContext);

        Assert.True(innerPipelineExecuted);
        Assert.NotNull(httpContext.User);
        Assert.True(httpContext.User.Identity?.IsAuthenticated);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_RejectsRemoteRequestWithoutClientCertificate()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10));

        var middleware = new FileTransferAuthMiddleware((innerCtx) => Task.CompletedTask, tokenStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_RejectsForwardedHeaderBypass()
    {
        var tokenStore = new TokenStore();
        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10));

        var middleware = new FileTransferAuthMiddleware((innerCtx) => Task.CompletedTask, tokenStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";
        httpContext.Request.Headers["X-Forwarded-For"] = "127.0.0.1";
        httpContext.Request.Headers["X-Real-IP"] = "127.0.0.1";

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_RejectsUnpairedClientCertificate()
    {
        var tokenStore = new TokenStore();
        var trustStore = new TrustStore(new MockLogger());
        trustStore.Clear();

        using var clientCert = CreateTestCert("CN=TetherAndroidDevice", TimeSpan.FromDays(1));
        string clientSpki = Convert.ToBase64String(ExportSpki(clientCert));
        string clientFp = TrustStore.ComputeFingerprintOrNull(clientSpki) ?? "";

        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10), clientFp);

        var middleware = new FileTransferAuthMiddleware((innerCtx) => Task.CompletedTask, tokenStore, trustStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        httpContext.Features.Set<ITlsConnectionFeature>(new DummyTlsFeature { ClientCertificate = clientCert });
        httpContext.Connection.ClientCertificate = clientCert;
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_AcceptsPairedClientCertificateAndMatchingToken()
    {
        var tokenStore = new TokenStore();
        var trustStore = new TrustStore(new MockLogger());
        trustStore.Clear();

        using var clientCert = CreateTestCert("CN=TetherAndroidDevice", TimeSpan.FromDays(1));
        string clientSpki = Convert.ToBase64String(ExportSpki(clientCert));

        var paired = trustStore.AddOrUpdate("PHONE_1", "Test Phone", clientSpki, new[] { "FILES" }, "2.0");

        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10), paired.Fingerprint);

        bool executed = false;
        var middleware = new FileTransferAuthMiddleware((innerCtx) =>
        {
            executed = true;
            return Task.CompletedTask;
        }, tokenStore, trustStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Response.Body = new MemoryStream();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        httpContext.Features.Set<ITlsConnectionFeature>(new DummyTlsFeature { ClientCertificate = clientCert });
        httpContext.Connection.ClientCertificate = clientCert;
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";

        await middleware.InvokeAsync(httpContext);

        httpContext.Response.Body.Seek(0, SeekOrigin.Begin);
        string respErr = new StreamReader(httpContext.Response.Body).ReadToEnd();

        Assert.True(executed, $"Middleware failed with status {httpContext.Response.StatusCode}: '{respErr}'");
        Assert.Equal(StatusCodes.Status200OK, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_AcceptsClientProofHeaderAndMatchingToken()
    {
        var tokenStore = new TokenStore();
        var trustStore = new TrustStore(new MockLogger());
        trustStore.Clear();

        using var clientCert = CreateTestCert("CN=TetherAndroidDevice", TimeSpan.FromDays(1));
        string clientSpki = Convert.ToBase64String(ExportSpki(clientCert));

        var paired = trustStore.AddOrUpdate("PHONE_1", "Test Phone", clientSpki, new[] { "FILES" }, "2.0");

        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10), paired.Fingerprint);
        string tsStr = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        string winSpki = "";
        string proofData = $"{token}:{tsStr}:{winSpki}";

        byte[] signatureBytes;
        using (var ecdsa = clientCert.GetECDsaPrivateKey()!)
        {
            signatureBytes = ecdsa.SignData(System.Text.Encoding.UTF8.GetBytes(proofData), HashAlgorithmName.SHA256);
        }
        string proofBase64 = Convert.ToBase64String(signatureBytes);

        bool executed = false;
        var middleware = new FileTransferAuthMiddleware((innerCtx) =>
        {
            executed = true;
            return Task.CompletedTask;
        }, tokenStore, trustStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";
        httpContext.Request.Headers["X-Tether-Client-Proof"] = proofBase64;
        httpContext.Request.Headers["X-Tether-Client-Timestamp"] = tsStr;

        await middleware.InvokeAsync(httpContext);

        Assert.True(executed);
        Assert.Equal(StatusCodes.Status200OK, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_RejectsTokenBoundToDifferentDevice()
    {
        var tokenStore = new TokenStore();
        var trustStore = new TrustStore(new MockLogger());
        trustStore.Clear();

        using var clientCert = CreateTestCert("CN=TetherAndroidDevice", TimeSpan.FromDays(1));
        string clientSpki = Convert.ToBase64String(ExportSpki(clientCert));

        var paired = trustStore.AddOrUpdate("PHONE_1", "Test Phone", clientSpki, new[] { "FILES" }, "2.0");

        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10), "OTHER_DEVICE_FP");

        var middleware = new FileTransferAuthMiddleware((innerCtx) => Task.CompletedTask, tokenStore, trustStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        httpContext.Features.Set<ITlsConnectionFeature>(new DummyTlsFeature { ClientCertificate = clientCert });
        httpContext.Connection.ClientCertificate = clientCert;
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
    }

    [Fact]
    public void TestDesktopUi_ValidateWindowsServiceCertificate_RejectsNullCert()
    {
        Assert.False(MainWindow.ValidateWindowsServiceCertificate(null));
    }

    [Fact]
    public void TestDesktopUi_ValidateWindowsServiceCertificate_RejectsCertWithWrongSubject()
    {
        using var cert = CreateTestCert("CN=Attacker Host", TimeSpan.FromDays(1));
        Assert.False(MainWindow.ValidateWindowsServiceCertificate(cert));
    }

    [Fact]
    public void TestDesktopUi_ValidateWindowsServiceCertificate_RejectsExpiredCert()
    {
        using var cert = CreateTestCert("CN=Tether Windows Identity", TimeSpan.FromDays(-1));
        Assert.False(MainWindow.ValidateWindowsServiceCertificate(cert));
    }

    [Fact]
    public void TestTryGetValidPath_ValidatesNormalPaths()
    {
        string tempDir = Path.GetTempPath();
        string testFile = Path.Combine(tempDir, "valid_test.txt");

        bool isValid = FileTransferServer.TryGetValidPath(testFile, out string fullPath);

        Assert.True(isValid);
        Assert.Equal(Path.GetFullPath(testFile), fullPath);
    }

    [Fact]
    public void TestTryGetValidPath_RejectsUncPaths()
    {
        bool isValid1 = FileTransferServer.TryGetValidPath(@"\\evil-server\share\file.txt", out _);
        bool isValid2 = FileTransferServer.TryGetValidPath(@"//evil-server/share/file.txt", out _);

        Assert.False(isValid1);
        Assert.False(isValid2);
    }

    [Fact]
    public void TestTryGetValidPath_RejectsPathTraversalDotDot()
    {
        string traversalPath = Path.Combine(Path.GetTempPath(), @"..\..\..\..\..\Windows\System32\cmd.exe");

        bool isValid = FileTransferServer.TryGetValidPath(traversalPath, out _);

        Assert.False(isValid);
    }

    [Fact]
    public void TestTryGetValidPath_RejectsWindowsSystemDirectories()
    {
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string sys32File = Path.Combine(winDir, @"System32\drivers\etc\hosts");

        bool isValid = FileTransferServer.TryGetValidPath(sys32File, out _);

        Assert.False(isValid);
    }

    [Fact]
    public void TestTryGetValidPath_RejectsTetherInternalDataStore()
    {
        string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string tetherTrustFile = Path.Combine(progData, @"Tether\trust.json");

        bool isValid = FileTransferServer.TryGetValidPath(tetherTrustFile, out _);

        Assert.False(isValid);
    }

    [Fact]
    public void TestWindowsIdentity_CertificateRetainsActivePrivateKey()
    {
        using var identity = new WindowsIdentity(new MockLogger());
        Assert.NotNull(identity.Certificate);
        Assert.True(identity.Certificate.HasPrivateKey);

        bool canSign = false;
        try
        {
            using var rsa = identity.Certificate.GetRSAPrivateKey();
            if (rsa != null)
            {
                byte[] sig = rsa.SignData(new byte[] { 1, 2, 3 }, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                canSign = sig.Length > 0;
            }
            else
            {
                using var ec = identity.Certificate.GetECDsaPrivateKey();
                if (ec != null)
                {
                    byte[] sig = ec.SignData(new byte[] { 1, 2, 3 }, HashAlgorithmName.SHA256);
                    canSign = sig.Length > 0;
                }
            }
        }
        catch { }

        Assert.True(canSign, "Windows identity certificate must retain an active private key that can perform cryptographic signatures.");
    }

    [Fact]
    public void TestFileTransferServer_ComputeSha512Hex_ComputesCorrectDigest()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "Tether Test File Content");
            string hashHex = FileTransferServer.ComputeSha512Hex(tempFile);

            Assert.NotNull(hashHex);
            Assert.Equal(128, hashHex.Length); // SHA-512 hex string is 128 characters
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_VerifiesProofDataWithWindowsSpki()
    {
        var tokenStore = new TokenStore();
        var trustStore = new TrustStore(new MockLogger());
        trustStore.Clear();

        using var identity = new WindowsIdentity(new MockLogger());
        using var clientCert = CreateTestCert("CN=TetherAndroidDevice", TimeSpan.FromDays(1));
        string clientSpki = Convert.ToBase64String(ExportSpki(clientCert));

        var paired = trustStore.AddOrUpdate("PHONE_1", "Test Phone", clientSpki, new[] { "FILES" }, "2.0");

        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10), paired.Fingerprint);
        string tsStr = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        string winSpki = identity.GetPublicKeySpkiBase64();
        string proofData = $"{token}:{tsStr}:{winSpki}";

        byte[] signatureBytes;
        using (var ecdsa = clientCert.GetECDsaPrivateKey()!)
        {
            signatureBytes = ecdsa.SignData(System.Text.Encoding.UTF8.GetBytes(proofData), HashAlgorithmName.SHA256);
        }
        string proofBase64 = Convert.ToBase64String(signatureBytes);

        bool executed = false;
        var middleware = new FileTransferAuthMiddleware((innerCtx) =>
        {
            executed = true;
            return Task.CompletedTask;
        }, tokenStore, trustStore, identity);

        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.168.1.100");
        httpContext.Request.Headers["Authorization"] = $"Bearer {token}";
        httpContext.Request.Headers["X-Tether-Client-Proof"] = proofBase64;
        httpContext.Request.Headers["X-Tether-Client-Timestamp"] = tsStr;

        await middleware.InvokeAsync(httpContext);

        Assert.True(executed);
        Assert.Equal(StatusCodes.Status200OK, httpContext.Response.StatusCode);
    }
}
