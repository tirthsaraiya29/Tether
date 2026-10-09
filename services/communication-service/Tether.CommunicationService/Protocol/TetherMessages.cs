using System.Text.Json.Serialization;

namespace Tether.CommunicationService.Protocol;

public static class HandshakeStatus
{
    public const string Paired = "PAIRED";
    public const string PairingPending = "PAIRING_PENDING";
    public const string PairingAccepted = "PAIRING_ACCEPTED";
    public const string PairingDenied = "PAIRING_DENIED";
    public const string Unpaired = "UNPAIRED";
}

public sealed record HandshakeInit
{
    [JsonPropertyName("type")] public string Type { get; init; } = "HANDSHAKE_INIT";
    [JsonPropertyName("version")] public string Version { get; init; } = "";
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = "";
    [JsonPropertyName("deviceName")] public string DeviceName { get; init; } = "";
    [JsonPropertyName("publicKey")] public string PublicKey { get; init; } = "";
    [JsonPropertyName("isPairingRequested")] public bool IsPairingRequested { get; init; }
    [JsonPropertyName("capabilities")] public string Capabilities { get; init; } = "";
}

public sealed record HandshakeResponse
{
    [JsonPropertyName("type")] public string Type { get; init; } = "HANDSHAKE_RESPONSE";
    [JsonPropertyName("version")] public string Version { get; init; } = "1.0";
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = "";
    [JsonPropertyName("deviceName")] public string DeviceName { get; init; } = "";
    [JsonPropertyName("publicKey")] public string PublicKey { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = HandshakeStatus.Unpaired;
    [JsonPropertyName("capabilities")] public string Capabilities { get; init; } = "";
    [JsonPropertyName("pqc")] public bool Pqc { get; init; }
    [JsonPropertyName("requestId")] public string? RequestId { get; init; }
    [JsonPropertyName("commitment")] public string? Commitment { get; init; }
}

public sealed record CommandExecute
{
    [JsonPropertyName("type")] public string Type { get; init; } = "COMMAND_EXECUTE";
    [JsonPropertyName("requestId")] public string RequestId { get; init; } = "";
    [JsonPropertyName("command")] public string Command { get; init; } = "";
    [JsonPropertyName("timestamp")] public long Timestamp { get; init; }
}

public sealed record ConfirmCommand
{
    [JsonPropertyName("type")] public string Type { get; init; } = "CONFIRM_COMMAND";
    [JsonPropertyName("confirmedCommand")] public string ConfirmedCommand { get; init; } = "";
}

public sealed record LaptopStateFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = "LAPTOP_STATE";
    [JsonPropertyName("batteryLevel")] public int BatteryLevel { get; init; } = -1;
    [JsonPropertyName("batteryPercent")] public int BatteryPercent { get; init; } = -1;
    [JsonPropertyName("isCharging")] public bool IsCharging { get; init; }
    [JsonPropertyName("lockState")] public string LockState { get; init; } = "UNKNOWN";
    [JsonPropertyName("wallpaperB64")] public string? WallpaperB64 { get; init; }
    [JsonPropertyName("wallpaperHash")] public string? WallpaperHash { get; init; }
    [JsonPropertyName("timestamp")] public long Timestamp { get; init; }
}

