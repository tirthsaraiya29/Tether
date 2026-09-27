// services/communication-service/Tether.CommunicationService/Transport/FrameCodec.cs
using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Tether.CommunicationService.Transport;

/// <summary>
/// Wire format: 4-byte big-endian unsigned length + UTF-8 JSON payload. Max 1 MiB.
/// Android reference: DataOutputStream.writeInt(length) + bytes.
/// </summary>
public static class FrameCodec
{
    public const int MaxFrameBytes = 1024 * 1024;

    public static async Task<byte[]?> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        if (!await ReadExactAsync(stream, lenBuf, 0, 4, ct)) return null;

        var len = BinaryPrimitives.ReadInt32BigEndian(lenBuf);
        if (len <= 0 || len > MaxFrameBytes) return null;

        var body = new byte[len];
        if (!await ReadExactAsync(stream, body, 0, len, ct)) return null;
        return body;
    }

    public static async Task<JsonDocument?> ReadJsonFrameAsync(Stream stream, CancellationToken ct)
    {
        var bytes = await ReadFrameAsync(stream, ct);
        if (bytes is null) return null;
        try { return JsonDocument.Parse(bytes); }
        catch (JsonException) { return null; }
    }

    public static async Task WriteFrameAsync(Stream stream, byte[] body, CancellationToken ct)
    {
        if (body.Length <= 0 || body.Length > MaxFrameBytes)
            throw new InvalidOperationException($"Frame size {body.Length} out of range.");

        var lenBuf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(lenBuf, body.Length);
        await stream.WriteAsync(lenBuf, 0, 4, ct);
        await stream.WriteAsync(body, 0, body.Length, ct);
        await stream.FlushAsync(ct);
    }

    public static Task WriteJsonFrameAsync<T>(Stream stream, T payload, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        return WriteFrameAsync(stream, bytes, ct);
    }

    private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, int off, int len, CancellationToken ct)
    {
        int read = 0;
        while (read < len)
        {
            int n;
            try { n = await s.ReadAsync(buf.AsMemory(off + read, len - read), ct); }
            catch { return false; }
            if (n <= 0) return false;
            read += n;
        }
        return true;
    }
}