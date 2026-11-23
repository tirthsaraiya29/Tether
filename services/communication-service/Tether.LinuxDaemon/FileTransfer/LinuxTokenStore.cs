using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Tether.LinuxDaemon.FileTransfer;

public sealed record LinuxTokenInfo(
    string Token,
    DateTimeOffset Expiry,
    string? DeviceFingerprint,
    IReadOnlySet<string> Capabilities,
    int MaxUses = 0,
    int UsedCount = 0);

public sealed class LinuxTokenStore
{
    private sealed class TokenMetaData
    {
        public DateTimeOffset Expiry { get; }
        public string? DeviceFingerprint { get; }
        public IReadOnlySet<string> Capabilities { get; }
        public int MaxUses { get; }
        public int UsedCount { get; set; }

        public TokenMetaData(DateTimeOffset expiry, string? deviceFingerprint, IReadOnlySet<string> capabilities, int maxUses = 0)
        {
            Expiry = expiry;
            DeviceFingerprint = deviceFingerprint;
            Capabilities = capabilities;
            MaxUses = maxUses;
            UsedCount = 0;
        }
    }

    private const int MaxActiveTokens = 1000;
    private readonly ConcurrentDictionary<string, TokenMetaData> _tokens = new(StringComparer.Ordinal);
    private readonly object _cleanupGate = new();

    public string GenerateToken(TimeSpan validFor, string? deviceFingerprint = null, IEnumerable<string>? capabilities = null, int maxUses = 0)
    {
        if (validFor > TimeSpan.FromHours(24))
        {
            validFor = TimeSpan.FromHours(24);
        }

        Cleanup();

        if (_tokens.Count >= MaxActiveTokens)
        {
            // Evict oldest
            var oldest = _tokens.OrderBy(kvp => kvp.Value.Expiry).Take(100).Select(kvp => kvp.Key).ToList();
            foreach (var key in oldest) _tokens.TryRemove(key, out _);
        }

        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var token = Convert.ToHexString(bytes).ToLowerInvariant();

        var capSet = capabilities != null
            ? new HashSet<string>(capabilities, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        _tokens[token] = new TokenMetaData(DateTimeOffset.UtcNow.Add(validFor), deviceFingerprint, capSet, maxUses);
        return token;
    }

    public bool ValidateToken(string token, string? requiredCapability = null, string? deviceFingerprint = null)
    {
        if (string.IsNullOrWhiteSpace(token)) return false;

        if (!_tokens.TryGetValue(token, out var meta)) return false;

        if (DateTimeOffset.UtcNow > meta.Expiry)
        {
            _tokens.TryRemove(token, out _);
            return false;
        }

        if (deviceFingerprint != null && meta.DeviceFingerprint != null &&
            !string.Equals(meta.DeviceFingerprint, deviceFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (requiredCapability != null && !meta.Capabilities.Contains("*") && !meta.Capabilities.Contains(requiredCapability))
        {
            return false;
        }

        lock (meta)
        {
            meta.UsedCount++;
            if (meta.MaxUses > 0 && meta.UsedCount >= meta.MaxUses)
            {
                _tokens.TryRemove(token, out _);
            }
        }

        return true;
    }

    public bool TryGetToken(string token, out LinuxTokenInfo? info)
    {
        info = null;
        if (string.IsNullOrWhiteSpace(token)) return false;

        if (!_tokens.TryGetValue(token, out var meta)) return false;

        if (DateTimeOffset.UtcNow > meta.Expiry)
        {
            _tokens.TryRemove(token, out _);
            return false;
        }

        lock (meta)
        {
            info = new LinuxTokenInfo(token, meta.Expiry, meta.DeviceFingerprint, meta.Capabilities, meta.MaxUses, meta.UsedCount);
        }
        return true;
    }

    public void RevokeToken(string token)
    {
        if (!string.IsNullOrEmpty(token))
        {
            _tokens.TryRemove(token, out _);
        }
    }

    public void RevokeDeviceTokens(string deviceFingerprint)
    {
        if (string.IsNullOrWhiteSpace(deviceFingerprint)) return;

        var tokensToRevoke = _tokens
            .Where(kvp => string.Equals(kvp.Value.DeviceFingerprint, deviceFingerprint, StringComparison.OrdinalIgnoreCase))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var t in tokensToRevoke)
        {
            _tokens.TryRemove(t, out _);
        }
    }

    private void Cleanup()
    {
        lock (_cleanupGate)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kvp in _tokens)
            {
                if (now > kvp.Value.Expiry)
                {
                    _tokens.TryRemove(kvp.Key, out _);
                }
            }
        }
    }
}
