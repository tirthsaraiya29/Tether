using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Tether.CommunicationService.Transport;
using Tether.CommunicationService.Trust;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Devices;

/// <summary>
/// Thread-safe registry of persistent TetherDevice instances.
/// Hydrates paired devices from TrustStore on startup and manages online/offline state.
/// </summary>
public sealed class DeviceManager
{
    private readonly ITetherLogger _logger;
    private readonly TrustStore _trustStore;
    private readonly ConcurrentDictionary<string, TetherDevice> _devicesByFingerprint = new(StringComparer.OrdinalIgnoreCase);

    public DeviceManager(ITetherLogger logger, TrustStore trustStore)
    {
        _logger = logger;
        _trustStore = trustStore;
        HydrateFromTrustStore();
    }

    /// <summary>
    /// Loads all paired devices from TrustStore into memory on startup.
    /// All devices initially start in Disconnected state.
    /// </summary>
    public void HydrateFromTrustStore()
    {
        var pairedList = _trustStore.All();
        int count = 0;

        foreach (var trusted in pairedList)
        {
            var device = new TetherDevice
            {
                DeviceId = trusted.DeviceId,
                DisplayName = trusted.DisplayName,
                PublicKeySpkiBase64 = trusted.PublicKeySpkiBase64,
                Fingerprint = trusted.Fingerprint,
                TrustState = DeviceTrustState.Paired,
                OnlineState = DeviceOnlineState.Disconnected,
                Capabilities = trusted.Capabilities.ToList(),
                PairedAtUtc = trusted.PairedAtUtc,
                LastSeenUtc = trusted.LastSeenUtc,
                CurrentSession = null
            };

            _devicesByFingerprint[trusted.Fingerprint] = device;
            count++;
        }

        _logger.Info($"DeviceManager hydrated {count} paired device(s) from TrustStore.");
    }

    public IReadOnlyCollection<TetherDevice> GetAllDevices() =>
        _devicesByFingerprint.Values.ToArray();

    public IReadOnlyCollection<TetherDevice> GetPairedDevices() =>
        _devicesByFingerprint.Values.Where(d => d.TrustState == DeviceTrustState.Paired).ToArray();

    public TetherDevice? GetByFingerprint(string fingerprint)
    {
        if (string.IsNullOrEmpty(fingerprint)) return null;
        return _devicesByFingerprint.TryGetValue(fingerprint, out var dev) ? dev : null;
    }

    public TetherDevice GetOrAddUnpairedDevice(string fingerprint, string displayName, string spkiBase64, IEnumerable<string> capabilities)
    {
        return _devicesByFingerprint.AddOrUpdate(
            fingerprint,
            fp => new TetherDevice
            {
                DeviceId = fp,
                DisplayName = displayName,
                PublicKeySpkiBase64 = spkiBase64,
                Fingerprint = fp,
                TrustState = DeviceTrustState.Unpaired,
                OnlineState = DeviceOnlineState.Connecting,
                Capabilities = capabilities.ToList(),
                LastSeenUtc = DateTime.UtcNow
            },
            (fp, existing) =>
            {
                existing.DisplayName = displayName;
                existing.Capabilities = capabilities.ToList();
                existing.LastSeenUtc = DateTime.UtcNow;
                return existing;
            });
    }

    public TetherDevice PromoteToPaired(string fingerprint, string displayName, string spkiBase64, IEnumerable<string> capabilities)
    {
        // Add to TrustStore persistence
        _trustStore.AddOrUpdate(fingerprint, displayName, spkiBase64, capabilities, "2.0");

        var device = _devicesByFingerprint.AddOrUpdate(
            fingerprint,
            fp => new TetherDevice
            {
                DeviceId = fp,
                DisplayName = displayName,
                PublicKeySpkiBase64 = spkiBase64,
                Fingerprint = fp,
                TrustState = DeviceTrustState.Paired,
                OnlineState = DeviceOnlineState.Connected,
                Capabilities = capabilities.ToList(),
                PairedAtUtc = DateTime.UtcNow,
                LastSeenUtc = DateTime.UtcNow
            },
            (fp, existing) =>
            {
                existing.DisplayName = displayName;
                existing.TrustState = DeviceTrustState.Paired;
                existing.Capabilities = capabilities.ToList();
                existing.LastSeenUtc = DateTime.UtcNow;
                return existing;
            });

        _logger.Info($"DeviceManager: Device {fingerprint} ({displayName}) promoted to PAIRED.");
        return device;
    }

    public void MarkConnected(string fingerprint, TetherSession session)
    {
        if (_devicesByFingerprint.TryGetValue(fingerprint, out var device))
        {
            device.OnlineState = DeviceOnlineState.Connected;
            device.CurrentSession = session;
            device.LastSeenUtc = DateTime.UtcNow;
            _trustStore.Touch(fingerprint);
            _logger.Info($"DeviceManager: Device {fingerprint} ({device.DisplayName}) is now CONNECTED.");
        }
    }

    public void MarkDisconnected(string fingerprint, TetherSession session)
    {
        if (_devicesByFingerprint.TryGetValue(fingerprint, out var device))
        {
            if (device.CurrentSession == session || device.CurrentSession == null)
            {
                device.OnlineState = DeviceOnlineState.Disconnected;
                device.CurrentSession = null;
                device.LastSeenUtc = DateTime.UtcNow;
                _logger.Info($"DeviceManager: Device {fingerprint} ({device.DisplayName}) is now DISCONNECTED.");
            }
        }
    }

    public bool RemoveDevice(string fingerprint)
    {
        bool removedFromTrust = _trustStore.Remove(fingerprint);
        bool removedFromMem = _devicesByFingerprint.TryRemove(fingerprint, out _);
        if (removedFromTrust || removedFromMem)
        {
            _logger.Info($"DeviceManager: Device {fingerprint} removed.");
            return true;
        }
        return false;
    }
}
