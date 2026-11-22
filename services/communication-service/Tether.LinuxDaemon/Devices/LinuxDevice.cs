using System;
using System.Collections.Generic;
using Tether.LinuxDaemon.Trust;

namespace Tether.LinuxDaemon.Devices;

public sealed class LinuxDevice
{
    public string DeviceId { get; init; } = "";
    public string DisplayName { get; set; } = "";
    public string Fingerprint { get; init; } = "";
    public string PublicKeySpkiBase64 { get; init; } = "";
    public List<string> Capabilities { get; set; } = new();
    public string ProtocolVersion { get; set; } = "2.0";
    public DateTime PairedAtUtc { get; init; }
    public DateTime LastSeenUtc { get; set; }
    public bool IsConnected { get; set; }

    public static LinuxDevice FromRecord(TrustedPhoneRecord r) => new()
    {
        DeviceId = r.DeviceId,
        DisplayName = r.DisplayName,
        Fingerprint = r.Fingerprint,
        PublicKeySpkiBase64 = r.PublicKeySpkiBase64,
        Capabilities = new List<string>(r.Capabilities),
        ProtocolVersion = r.ProtocolVersion,
        PairedAtUtc = r.PairedAtUtc,
        LastSeenUtc = r.LastSeenUtc,
        IsConnected = false
    };
}
