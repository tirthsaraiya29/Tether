using System;

namespace Tether.Shared.DTO;

public sealed class PairingRequestPayload
{
    public string RequestId { get; set; } = "";
    public string PhonePublicKeyBase64 { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public long TimestampUtcTicks { get; set; } = DateTime.UtcNow.Ticks;
}

public sealed class PairingDecisionPayload
{
    public string RequestId { get; set; } = "";
    public string PhonePublicKeyBase64 { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public bool Allowed { get; set; }
}