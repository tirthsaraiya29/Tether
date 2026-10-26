using System;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Tether.CommunicationService.FileTransfer;
using Xunit;

namespace Tether.FileTransfer.Tests;

public class FileTransferSecurityTests
{
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
        Assert.True(tokenStore.ValidateToken(localToken));
    }

    [Fact]
    public void TestTokenStore_EnforcesDeviceFingerprintBinding()
    {
        var tokenStore = new TokenStore();
        string deviceFp = "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00";
        string token = tokenStore.GenerateToken(TimeSpan.FromMinutes(10), deviceFp);

        Assert.True(tokenStore.ValidateToken(token, deviceFp));
        Assert.False(tokenStore.ValidateToken(token, "WRONG:FINGERPRINT"));
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

        // Even loopback requests MUST be rejected without a valid Bearer token
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Loopback;

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task TestFileTransferAuthMiddleware_AcceptsValidBearerToken()
    {
        var tokenStore = new TokenStore();
        string validToken = tokenStore.GenerateToken(TimeSpan.FromMinutes(10));

        bool innerPipelineExecuted = false;
        var middleware = new FileTransferAuthMiddleware((innerCtx) =>
        {
            innerPipelineExecuted = true;
            return Task.CompletedTask;
        }, tokenStore);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Authorization"] = $"Bearer {validToken}";

        await middleware.InvokeAsync(httpContext);

        Assert.True(innerPipelineExecuted);
        Assert.NotNull(httpContext.User);
        Assert.True(httpContext.User.Identity?.IsAuthenticated);
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

        // Must resolve to C:\Windows\System32\cmd.exe and be rejected
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
}
