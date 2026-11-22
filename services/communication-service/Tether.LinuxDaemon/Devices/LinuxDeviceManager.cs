using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Devices;

public sealed class LinuxDeviceManager
{
    private readonly ITetherLogger _logger;
    private readonly LinuxTrustStore _trustStore;
    private readonly ConcurrentDictionary<string, LinuxDevice> _devices = new(StringComparer.OrdinalIgnoreCase);

    public LinuxDeviceManager(ITetherLogger logger, LinuxTrustStore trustStore)
    {
        _logger = logger;
        _trustStore = trustStore;
        ReloadFromTrustStore();
    }

    public void ReloadFromTrustStore()
    {
        _devices.Clear();
        foreach (var record in _trustStore.All())
        {
            _devices[record.Fingerprint] = LinuxDevice.FromRecord(record);
        }
    }

    public bool IsDevicePaired(string fingerprint)
    {
        return _trustStore.FindByFingerprint(fingerprint) != null;
    }

    public LinuxDevice? GetDevice(string fingerprint)
    {
        if (_devices.TryGetValue(fingerprint, out var dev)) return dev;
        var record = _trustStore.FindByFingerprint(fingerprint);
        if (record != null)
        {
            dev = LinuxDevice.FromRecord(record);
            _devices[fingerprint] = dev;
            return dev;
        }
        return null;
    }

    public void MarkConnected(string fingerprint)
    {
        var dev = GetDevice(fingerprint);
        if (dev != null)
        {
            dev.IsConnected = true;
            dev.LastSeenUtc = DateTime.UtcNow;
            _trustStore.Touch(fingerprint);
        }
    }

    public void MarkDisconnected(string fingerprint)
    {
        if (_devices.TryGetValue(fingerprint, out var dev))
        {
            dev.IsConnected = false;
            dev.LastSeenUtc = DateTime.UtcNow;
            _trustStore.Touch(fingerprint);
        }
    }

    public IReadOnlyCollection<LinuxDevice> AllDevices() => _devices.Values.ToList();
}
