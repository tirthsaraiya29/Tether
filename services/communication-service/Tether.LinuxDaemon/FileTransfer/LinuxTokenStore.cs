using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Tether.LinuxDaemon.FileTransfer;

public sealed class LinuxTokenStore
{
    private sealed record TokenMetaData(DateTimeOffset Expiry, string? DeviceFingerprint, IReadOnlySet<string> Capabilities);

    private readonly ConcurrentDictionary<string, TokenMetaData> _tokens = new(StringComparer.Ordinal);

    public string GenerateToken(TimeSpan validFor, string? deviceFingerprint = null, IEnumerable<string>? capabilities = null)
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var token = Convert.ToHexString(bytes).ToLowerInvariant();

        var capSet = capabilities != null
            ? new HashSet<string>(capabilities, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        _tokens[token] = new TokenMetaData(DateTimeOffset.UtcNow.Add(validFor), deviceFingerprint, capSet);
        Cleanup();
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

        return true;
    }

    public void RevokeToken(string token)
    {
        _tokens.TryRemove(token, out _);
    }

    private void Cleanup()
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
