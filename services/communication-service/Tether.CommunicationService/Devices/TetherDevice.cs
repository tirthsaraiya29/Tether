using System;
using System.Collections.Generic;
using Tether.CommunicationService.Transport;

namespace Tether.CommunicationService.Devices;

public enum DeviceTrustState
{
    Unpaired,
    PairingPending,
    Paired,
    KeyMismatch
}

public enum DeviceOnlineState
{
    Disconnected,
    Connecting,
    Connected
}

/// <summary>
/// Persistent logical representation of a Tether peer (phone or tablet).
/// Survives network disconnections and Windows service restarts.
/// </summary>
public sealed class TetherDevice
{
    public string DeviceId { get; init; } = "";
    public string DisplayName { get; set; } = "";
    public string PublicKeySpkiBase64 { get; init; } = "";
    public string Fingerprint { get; init; } = "";
    public DeviceTrustState TrustState { get; set; } = DeviceTrustState.Unpaired;
    public DeviceOnlineState OnlineState { get; set; } = DeviceOnlineState.Disconnected;
    public List<string> Capabilities { get; set; } = new();
    public DateTime PairedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Active ephemeral TCP/TLS session reference (null when offline).
    /// </summary>
    public TetherSession? CurrentSession { get; set; }
}
