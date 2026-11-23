using System;
using System.IO;
using Tether.LinuxDaemon.FileTransfer;
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
}
