using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Tether.LinuxDaemon.FileTransfer;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class FileTransferTests
{
    [Fact]
    public void TokenStore_GeneratesValidToken_AndValidatesCapabilities()
    {
        var store = new LinuxTokenStore();
        string token = store.GenerateToken(TimeSpan.FromMinutes(10), "fp-123", new[] { "FILES", "MEDIA" });

        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.True(store.ValidateToken(token, "FILES", "fp-123"));
        Assert.True(store.ValidateToken(token, "MEDIA", "fp-123"));

        // Wrong capability
        Assert.False(store.ValidateToken(token, "UNKNOWN_CAP", "fp-123"));

        // Wrong fingerprint
        Assert.False(store.ValidateToken(token, "FILES", "other-fp"));
    }

    [Fact]
    public void TokenStore_ExpiredToken_IsRejected()
    {
        var store = new LinuxTokenStore();
        string token = store.GenerateToken(TimeSpan.FromMilliseconds(-100), "fp-123", new[] { "FILES" });

        Assert.False(store.ValidateToken(token, "FILES", "fp-123"));
    }

    [Fact]
    public void TokenStore_RevokedToken_IsRejected()
    {
        var store = new LinuxTokenStore();
        string token = store.GenerateToken(TimeSpan.FromMinutes(10), "fp-123", new[] { "FILES" });

        Assert.True(store.ValidateToken(token, "FILES", "fp-123"));
        store.RevokeToken(token);
        Assert.False(store.ValidateToken(token, "FILES", "fp-123"));
    }

    [Fact]
    public void TokenStore_RevokeDeviceTokens_InvalidatesTargetDeviceOnly()
    {
        var store = new LinuxTokenStore();
        string dev1Token1 = store.GenerateToken(TimeSpan.FromMinutes(10), "dev-1", new[] { "FILES" });
        string dev1Token2 = store.GenerateToken(TimeSpan.FromMinutes(10), "dev-1", new[] { "FILES" });
        string dev2Token = store.GenerateToken(TimeSpan.FromMinutes(10), "dev-2", new[] { "FILES" });

        Assert.True(store.ValidateToken(dev1Token1, "FILES", "dev-1"));
        Assert.True(store.ValidateToken(dev1Token2, "FILES", "dev-1"));
        Assert.True(store.ValidateToken(dev2Token, "FILES", "dev-2"));

        store.RevokeDeviceTokens("dev-1");

        Assert.False(store.ValidateToken(dev1Token1, "FILES", "dev-1"));
        Assert.False(store.ValidateToken(dev1Token2, "FILES", "dev-1"));
        Assert.True(store.ValidateToken(dev2Token, "FILES", "dev-2"));
    }

    [Fact]
    public void TokenStore_MaxUses_EnforcesSingleOrLimitedUse()
    {
        var store = new LinuxTokenStore();
        string singleUseToken = store.GenerateToken(TimeSpan.FromMinutes(10), "dev-single", new[] { "FILES" }, maxUses: 1);

        // First use succeeds
        Assert.True(store.ValidateToken(singleUseToken, "FILES", "dev-single"));
        // Second use fails because token was single-use and evicted
        Assert.False(store.ValidateToken(singleUseToken, "FILES", "dev-single"));
    }

    [Fact]
    public void IsPathSafe_EnforcesBoundary_AndRejectsTraversal()
    {
        string tempBase = Path.Combine(Path.GetTempPath(), "tether_ft_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempBase);
        try
        {
            string safeSubDir = Path.Combine(tempBase, "Documents");
            Directory.CreateDirectory(safeSubDir);
            string safeFile = Path.Combine(safeSubDir, "test.txt");
            File.WriteAllText(safeFile, "hello");

            // Safe path within base
            Assert.True(LinuxFileTransferServer.IsPathSafe(safeFile, tempBase));
            Assert.True(LinuxFileTransferServer.IsPathSafe(safeSubDir, tempBase));
            Assert.True(LinuxFileTransferServer.IsPathSafe(tempBase, tempBase));

            // Lexical traversal attempt outside base
            string escapeAttempt = Path.Combine(tempBase, "..", "outside.txt");
            Assert.False(LinuxFileTransferServer.IsPathSafe(escapeAttempt, tempBase));

            string deepEscape = Path.Combine(tempBase, "Documents", "..", "..", "..", "etc", "passwd");
            Assert.False(LinuxFileTransferServer.IsPathSafe(deepEscape, tempBase));

            // System directories blocked
            Assert.False(LinuxFileTransferServer.IsPathSafe("/etc/shadow", tempBase));
            Assert.False(LinuxFileTransferServer.IsPathSafe("/proc/cpuinfo", tempBase));
            Assert.False(LinuxFileTransferServer.IsPathSafe("/sys/kernel", tempBase));

            // Null bytes rejected
            Assert.False(LinuxFileTransferServer.IsPathSafe(tempBase + "/test\0.txt", tempBase));
        }
        finally
        {
            try { Directory.Delete(tempBase, true); } catch { }
        }
    }

    [Fact]
    public void DesktopManager_GetDesktopWindows_ReturnsEntireScreenEntry()
    {
        var logger = new SerilogTetherLogger();
        var desktopManager = new Tether.LinuxDaemon.Desktop.LinuxDesktopManager(logger);

        var windows = desktopManager.GetDesktopWindows();
        Assert.NotNull(windows);
        Assert.NotEmpty(windows);

        // Entire screen entry (hwnd=0) must be present for full desktop streaming
        var fullScreen = windows.FirstOrDefault(w => w.Hwnd == 0L);
        Assert.NotNull(fullScreen);
        Assert.Equal("Entire Screen / Desktop", fullScreen.Title);
        Assert.True(fullScreen.Width > 0);
        Assert.True(fullScreen.Height > 0);
    }

    [Fact]
    public async Task DesktopManager_CaptureScreenshot_BehaviorMatchesDisplayAvailability()
    {
        var logger = new SerilogTetherLogger();
        var desktopManager = new Tether.LinuxDaemon.Desktop.LinuxDesktopManager(logger);

        using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(5));
        byte[] frame = await desktopManager.CaptureScreenshotAsync(quality: 75, windowId: 0, cts.Token);

        bool hasDisplay = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")) ||
                          !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY"));

        if (hasDisplay)
        {
            Assert.NotNull(frame);
            Assert.NotEmpty(frame);
            // Valid JPEG must start with SOI marker (0xFF, 0xD8) and end with EOI marker (0xFF, 0xD9)
            Assert.Equal(0xFF, frame[0]);
            Assert.Equal(0xD8, frame[1]);
            Assert.Equal(0xFF, frame[^2]);
            Assert.Equal(0xD9, frame[^1]);
        }
        else
        {
            // In headless environments without physical display or Xvfb, must fail closed without synthesizing fake frames
            Assert.NotNull(frame);
            Assert.Empty(frame);
        }
    }

    [Fact]
    public async Task DesktopManager_StreamDesktop_TerminatesCleanlyWhenCancelled()
    {
        var logger = new SerilogTetherLogger();
        var desktopManager = new Tether.LinuxDaemon.Desktop.LinuxDesktopManager(logger);

        int frameCount = 0;
        using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromMilliseconds(400));

        await desktopManager.StreamDesktopAsync(
            fps: 15,
            quality: 50,
            windowId: 0,
            (frameBytes, ct) =>
            {
                frameCount++;
                Assert.NotNull(frameBytes);
                Assert.True(frameBytes.Length > 0);
                return Task.CompletedTask;
            },
            cts.Token);

        // Streaming terminates gracefully on cancellation
        Assert.True(cts.IsCancellationRequested);
    }

    [Fact]
    public void FileTransferServer_VerifyClientProofSignature_ValidatesEcdsaP256()
    {
        using var phoneKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        byte[] phoneSpki = phoneKey.ExportSubjectPublicKeyInfo();
        string phoneSpkiBase64 = Convert.ToBase64String(phoneSpki);

        string challenge = "token_abc123:1700000000:win_spki_base64";
        byte[] challengeBytes = System.Text.Encoding.UTF8.GetBytes(challenge);

        byte[] signature = phoneKey.SignData(challengeBytes, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence);
        string sigBase64 = Convert.ToBase64String(signature);

        // Production method LinuxFileTransferServer.VerifyClientProofSignature must succeed with matching key
        bool verified = LinuxFileTransferServer.VerifyClientProofSignature(phoneSpkiBase64, challengeBytes, sigBase64);
        Assert.True(verified);

        // Production method must reject tampered data
        byte[] tamperedData = System.Text.Encoding.UTF8.GetBytes(challenge + "_tampered");
        bool tamperedVerified = LinuxFileTransferServer.VerifyClientProofSignature(phoneSpkiBase64, tamperedData, sigBase64);
        Assert.False(tamperedVerified);

        // Production method must reject signature with mismatched key
        using var otherKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        string otherSpkiBase64 = Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo());
        bool wrongKeyVerified = LinuxFileTransferServer.VerifyClientProofSignature(otherSpkiBase64, challengeBytes, sigBase64);
        Assert.False(wrongKeyVerified);
    }
}
