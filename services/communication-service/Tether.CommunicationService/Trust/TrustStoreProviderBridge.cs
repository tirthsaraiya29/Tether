using System;
using System.Linq;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Trust;

public interface ITrustStoreProvider
{
    bool IsPeerTrustedAndHasCapability(
        string spkiFingerprint,
        string requiredCapability,
        out string displayName);
}

public sealed class TrustStoreProviderBridge : ITrustStoreProvider
{
    private readonly TrustStore _trustStore;
    private readonly ITetherLogger _logger;

    public TrustStoreProviderBridge(TrustStore trustStore, ITetherLogger logger)
    {
        _trustStore = trustStore;
        _logger = logger;
    }

    public bool IsPeerTrustedAndHasCapability(
        string spkiFingerprint,
        string requiredCapability,
        out string displayName)
    {
        displayName = "Unknown Device";
        var all = _trustStore.All();
        var match = all.FirstOrDefault(p =>
            string.Equals(p.Fingerprint, spkiFingerprint, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(p.DeviceId, spkiFingerprint, StringComparison.OrdinalIgnoreCase));

        if (match == null)
        {
            _logger.Warning($"TrustStoreProviderBridge: Fingerprint {spkiFingerprint} not found in TrustStore.");
            return false;
        }

        displayName = match.DisplayName;
        bool hasCap = match.Capabilities.Contains(requiredCapability, StringComparer.OrdinalIgnoreCase) ||
                      match.Capabilities.Contains("ALL", StringComparer.OrdinalIgnoreCase);

        if (!hasCap)
        {
            _logger.Warning($"TrustStoreProviderBridge: Device '{match.DisplayName}' missing capability '{requiredCapability}'.");
        }

        return hasCap;
    }
}
