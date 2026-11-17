namespace Tether.Shared.Events;

public class FileTransferProgressPayload
{
    public string FileName { get; set; } = string.Empty;
    public long BytesTransferred { get; set; }
    public long TotalBytes { get; set; }
    public long SpeedBps { get; set; }
    public long EtaSec { get; set; }
    public bool IsUpload { get; set; }
    public string? SavedPath { get; set; }
    public string? Error { get; set; }
}
