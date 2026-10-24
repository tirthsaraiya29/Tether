using System;
using System.Collections.Concurrent;

namespace Tether.CommunicationService.FileTransfer;

public class TokenStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _tokens = new(StringComparer.Ordinal);

    public string GenerateToken(TimeSpan validFor)
    {
        var token = Guid.NewGuid().ToString("N");
        _tokens[token] = DateTimeOffset.UtcNow.Add(validFor);
        Cleanup();
        return token;
    }

    public bool ValidateToken(string token)
    {
        if (_tokens.TryGetValue(token, out var expiry))
        {
            if (DateTimeOffset.UtcNow <= expiry)
            {
                return true;
            }
            _tokens.TryRemove(token, out _);
        }
        return false;
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kvp in _tokens)
        {
            if (now > kvp.Value)
            {
                _tokens.TryRemove(kvp.Key, out _);
            }
        }
    }
}
