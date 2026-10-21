using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tether.FileTransfer.Protocol;

public static class QuicTransportErrorCode
{
    public const long NO_ERROR = 0x00;
    public const long INTERNAL_ERROR = 0x01;
    public const long STREAM_CREATION_ERROR = 0x02;
    public const long CLOSED_CRITICAL_STREAM = 0x03;
    public const long PROTOCOL_VIOLATION = 0x0A;
    public const long CRYPTO_ERROR_BASE = 0x0100;
}

public enum FileTransferErrorCode
{
    UNAUTHORIZED_PEER = 0x10,
    MISSING_CAPABILITY = 0x11,
    PATH_TRAVERSAL_REJECTED = 0x12,
    DISK_FULL = 0x13,
    INTEGRITY_FAILED = 0x14,
    RESUME_PREFIX_MISMATCH = 0x15,
    SOURCE_FILE_CHANGED = 0x16,
    USER_CANCELLED = 0x17,
    SERVICE_TIMEOUT = 0x18
}

public enum FileTransferState
{
    IDLE,
    CONNECTING,
    REQUESTED,
    TRANSFERRING,
    PAUSED,
    VERIFYING,
    COMPLETED,
    FAILED,
    CANCELLED
}

public static class ControlMessageType
{
    public const string CONTROL_INIT = "CONTROL_INIT";
    public const string CONTROL_INIT_ACK = "CONTROL_INIT_ACK";
    public const string BROWSE_ROOTS_REQUEST = "BROWSE_ROOTS_REQUEST";
    public const string BROWSE_ROOTS_RESPONSE = "BROWSE_ROOTS_RESPONSE";
    public const string LIST_DIR_REQUEST = "LIST_DIR_REQUEST";
    public const string LIST_DIR_RESPONSE = "LIST_DIR_RESPONSE";
    public const string QUEUE_SYNC_REQUEST = "QUEUE_SYNC_REQUEST";
    public const string QUEUE_SYNC_SNAPSHOT = "QUEUE_SYNC_SNAPSHOT";
    public const string TRANSFER_REQUEST = "TRANSFER_REQUEST";
    public const string TRANSFER_RESPONSE = "TRANSFER_RESPONSE";
    public const string TRANSFER_RESUME_REQUEST = "TRANSFER_RESUME_REQUEST";
    public const string TRANSFER_RESUME_ACK = "TRANSFER_RESUME_ACK";
    public const string TRANSFER_PAUSE = "TRANSFER_PAUSE";
    public const string TRANSFER_CANCEL = "TRANSFER_CANCEL";
    public const string TRANSFER_COMPLETE = "TRANSFER_COMPLETE";
}

public static class DataChunkMessageType
{
    public const byte MSG_DATA_CHUNK = 0x01;
    public const byte MSG_DATA_END = 0x02;
}

public sealed record ControlInitFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.CONTROL_INIT;
    [JsonPropertyName("protocolVersion")] public string ProtocolVersion { get; init; } = "1.0";
    [JsonPropertyName("deviceId")] public string DeviceId { get; init; } = "";
}

public sealed record ControlInitAckFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.CONTROL_INIT_ACK;
    [JsonPropertyName("status")] public string Status { get; init; } = "OK";
    [JsonPropertyName("grantedCapabilities")] public string GrantedCapabilities { get; init; } = "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA";
}

public sealed record TransferRequestFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.TRANSFER_REQUEST;
    [JsonPropertyName("version")] public string Version { get; init; } = "1.0";
    [JsonPropertyName("transferId")] public string TransferId { get; init; } = "";
    [JsonPropertyName("fileName")] public string FileName { get; init; } = "";
    [JsonPropertyName("fileSize")] public long FileSize { get; init; }
    [JsonPropertyName("mimeType")] public string MimeType { get; init; } = "application/octet-stream";
    [JsonPropertyName("expectedSha512")] public string ExpectedSha512 { get; init; } = "";
    [JsonPropertyName("chunkSize")] public int ChunkSize { get; init; } = 65536;
    [JsonPropertyName("totalChunks")] public long TotalChunks { get; init; }
    [JsonPropertyName("sourceLastModified")] public long SourceLastModified { get; init; }
}

public sealed record TransferResponseFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.TRANSFER_RESPONSE;
    [JsonPropertyName("transferId")] public string TransferId { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "REJECTED"; // ACCEPTED, REJECTED
    [JsonPropertyName("resumeOffset")] public long ResumeOffset { get; init; }
    [JsonPropertyName("errorCode")] public int ErrorCode { get; init; }
    [JsonPropertyName("reason")] public string Reason { get; init; } = "";
}

public sealed record TransferResumeRequestFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.TRANSFER_RESUME_REQUEST;
    [JsonPropertyName("transferId")] public string TransferId { get; init; } = "";
    [JsonPropertyName("requestedOffset")] public long RequestedOffset { get; init; }
    [JsonPropertyName("sourceLastModified")] public long SourceLastModified { get; init; }
    [JsonPropertyName("sourceSize")] public long SourceSize { get; init; }
}

public sealed record TransferResumeAckFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.TRANSFER_RESUME_ACK;
    [JsonPropertyName("transferId")] public string TransferId { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "REJECTED"; // ACCEPTED, REJECTED
    [JsonPropertyName("resumeOffset")] public long ResumeOffset { get; init; }
    [JsonPropertyName("partialSha512")] public string PartialSha512 { get; init; } = "";
    [JsonPropertyName("errorCode")] public int ErrorCode { get; init; }
    [JsonPropertyName("reason")] public string Reason { get; init; } = "";
}

public sealed record TransferCancelFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.TRANSFER_CANCEL;
    [JsonPropertyName("transferId")] public string TransferId { get; init; } = "";
    [JsonPropertyName("reason")] public string Reason { get; init; } = "";
}

public sealed record TransferCompleteFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.TRANSFER_COMPLETE;
    [JsonPropertyName("transferId")] public string TransferId { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "SUCCESS"; // SUCCESS, FAILED
    [JsonPropertyName("errorCode")] public int ErrorCode { get; init; }
    [JsonPropertyName("reason")] public string Reason { get; init; } = "";
}

public sealed record TransferProgress
{
    public required string TransferId { get; init; }
    public required string FileName { get; init; }
    public required long FileSize { get; init; }
    public long BytesTransferred { get; init; }
    public double SpeedBytesPerSec { get; init; }
    public FileTransferState State { get; init; } = FileTransferState.IDLE;
    public bool IsIncoming { get; init; } = true;
    public string PeerName { get; init; } = "";
    public string? ErrorMessage { get; init; }
    public string? DestinationPath { get; init; }

    public float ProgressFraction => FileSize > 0 ? Math.Clamp((float)BytesTransferred / FileSize, 0f, 1f) : 0f;
    public int ProgressPercentage => (int)(ProgressFraction * 100);
    public double SpeedMbPerSec => SpeedBytesPerSec / (1024.0 * 1024.0);
    public long EtaSeconds => (SpeedBytesPerSec > 0 && FileSize > BytesTransferred)
        ? (long)((FileSize - BytesTransferred) / SpeedBytesPerSec)
        : 0L;
}

public sealed record BrowseRootsRequestFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.BROWSE_ROOTS_REQUEST;
    [JsonPropertyName("requestId")] public string RequestId { get; init; } = Guid.NewGuid().ToString();
}

public sealed record BrowseRootsResponseFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.BROWSE_ROOTS_RESPONSE;
    [JsonPropertyName("requestId")] public string RequestId { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "OK";
    [JsonPropertyName("roots")] public List<FilesystemRootItem> Roots { get; init; } = new();
    [JsonPropertyName("errorMessage")] public string? ErrorMessage { get; init; }
}

public sealed record ListDirRequestFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.LIST_DIR_REQUEST;
    [JsonPropertyName("requestId")] public string RequestId { get; init; } = Guid.NewGuid().ToString();
    [JsonPropertyName("path")] public string Path { get; init; } = "";
}

public sealed record ListDirResponseFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.LIST_DIR_RESPONSE;
    [JsonPropertyName("requestId")] public string RequestId { get; init; } = "";
    [JsonPropertyName("status")] public string Status { get; init; } = "OK";
    [JsonPropertyName("path")] public string Path { get; init; } = "";
    [JsonPropertyName("items")] public List<DirectoryListingItem> Items { get; init; } = new();
    [JsonPropertyName("errorMessage")] public string? ErrorMessage { get; init; }
}

public sealed record QueueSyncRequestFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.QUEUE_SYNC_REQUEST;
    [JsonPropertyName("requestId")] public string RequestId { get; init; } = Guid.NewGuid().ToString();
}

public sealed record QueueSyncSnapshotFrame
{
    [JsonPropertyName("type")] public string Type { get; init; } = ControlMessageType.QUEUE_SYNC_SNAPSHOT;
    [JsonPropertyName("requestId")] public string RequestId { get; init; } = "";
    [JsonPropertyName("items")] public List<DurableTransferItem> Items { get; init; } = new();
}
