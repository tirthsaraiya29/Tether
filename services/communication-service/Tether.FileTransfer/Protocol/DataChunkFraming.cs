using System;
using System.Buffers.Binary;

namespace Tether.FileTransfer.Protocol;

public static class DataChunkFraming
{
    public const int HeaderSizeBytes = 41; // 4 + 1 + 16 + 8 + 8 + 4

    public sealed record ParsedChunkHeader(
        byte MsgType,
        Guid TransferId,
        long ChunkIndex,
        long Offset,
        int PayloadLength);

    public static byte[] SerializeChunk(
        Guid transferId,
        long chunkIndex,
        long offset,
        byte[] payload,
        int payloadOffset = 0,
        int payloadLength = -1)
    {
        if (payloadLength < 0) payloadLength = payload.Length - payloadOffset;

        int totalFrameLength = HeaderSizeBytes - 4 + payloadLength;
        byte[] buffer = new byte[HeaderSizeBytes + payloadLength];
        Span<byte> span = buffer;

        BinaryPrimitives.WriteInt32BigEndian(span[0..4], totalFrameLength);
        span[4] = DataChunkMessageType.MSG_DATA_CHUNK;

        WriteGuidBigEndian(span[5..21], transferId);
        BinaryPrimitives.WriteInt64BigEndian(span[21..29], chunkIndex);
        BinaryPrimitives.WriteInt64BigEndian(span[29..37], offset);
        BinaryPrimitives.WriteInt32BigEndian(span[37..41], payloadLength);

        if (payloadLength > 0)
        {
            Array.Copy(payload, payloadOffset, buffer, HeaderSizeBytes, payloadLength);
        }

        return buffer;
    }

    public static byte[] SerializeEndSignal(Guid transferId)
    {
        int totalFrameLength = HeaderSizeBytes - 4;
        byte[] buffer = new byte[HeaderSizeBytes];
        Span<byte> span = buffer;

        BinaryPrimitives.WriteInt32BigEndian(span[0..4], totalFrameLength);
        span[4] = DataChunkMessageType.MSG_DATA_END;

        WriteGuidBigEndian(span[5..21], transferId);
        BinaryPrimitives.WriteInt64BigEndian(span[21..29], 0L);
        BinaryPrimitives.WriteInt64BigEndian(span[29..37], 0L);
        BinaryPrimitives.WriteInt32BigEndian(span[37..41], 0);

        return buffer;
    }

    public static ParsedChunkHeader ParseHeader(ReadOnlySpan<byte> headerBytes)
    {
        if (headerBytes.Length < HeaderSizeBytes - 4)
        {
            throw new ArgumentException($"Header span size ({headerBytes.Length}) is smaller than required header payload size ({HeaderSizeBytes - 4}).");
        }

        byte msgType = headerBytes[0];
        Guid transferId = ReadGuidBigEndian(headerBytes[1..17]);
        long chunkIndex = BinaryPrimitives.ReadInt64BigEndian(headerBytes[17..25]);
        long offset = BinaryPrimitives.ReadInt64BigEndian(headerBytes[25..33]);
        int payloadLength = BinaryPrimitives.ReadInt32BigEndian(headerBytes[33..37]);

        return new ParsedChunkHeader(msgType, transferId, chunkIndex, offset, payloadLength);
    }

    private static void WriteGuidBigEndian(Span<byte> destination, Guid guid)
    {
        byte[] guidBytes = guid.ToByteArray();
        // Guid bytes in C# are little-endian for the first 3 components.
        // Convert to Big-Endian UUID layout matching Java's UUID (mostSigBits, leastSigBits)
        if (BitConverter.IsLittleEndian)
        {
            destination[0] = guidBytes[3];
            destination[1] = guidBytes[2];
            destination[2] = guidBytes[1];
            destination[3] = guidBytes[0];

            destination[4] = guidBytes[5];
            destination[5] = guidBytes[4];

            destination[6] = guidBytes[7];
            destination[7] = guidBytes[6];

            Array.Copy(guidBytes, 8, destination.Slice(8, 8).ToArray(), 0, 8);
            for (int i = 8; i < 16; i++)
            {
                destination[i] = guidBytes[i];
            }
        }
        else
        {
            guidBytes.CopyTo(destination);
        }
    }

    private static Guid ReadGuidBigEndian(ReadOnlySpan<byte> source)
    {
        byte[] bytes = new byte[16];
        if (BitConverter.IsLittleEndian)
        {
            bytes[0] = source[3];
            bytes[1] = source[2];
            bytes[2] = source[1];
            bytes[3] = source[0];

            bytes[4] = source[5];
            bytes[5] = source[4];

            bytes[6] = source[7];
            bytes[7] = source[6];

            for (int i = 8; i < 16; i++)
            {
                bytes[i] = source[i];
            }
        }
        else
        {
            source.Slice(0, 16).CopyTo(bytes);
        }

        return new Guid(bytes);
    }
}
