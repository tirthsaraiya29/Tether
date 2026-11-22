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
}
