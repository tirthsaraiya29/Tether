using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Tether.FileTransfer.Protocol;
using Tether.FileTransfer.Receiver;
using Xunit;

namespace Tether.FileTransfer.Tests;

public class FileTransferTests
{
    [Fact]
    public void TransferRequestFrame_JsonSerialization_RoundTripsCorrectly()
    {
        var original = new TransferRequestFrame
        {
            TransferId = Guid.NewGuid().ToString(),
            FileName = "document.pdf",
            FileSize = 10485760L,
            MimeType = "application/pdf",
            ExpectedSha512 = "3C0123456789ABCDEF",
            ChunkSize = 65536,
            TotalChunks = 160,
            SourceLastModified = 1718000000000L
        };

        string json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<TransferRequestFrame>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.Type, deserialized.Type);
        Assert.Equal(original.TransferId, deserialized.TransferId);
        Assert.Equal(original.FileName, deserialized.FileName);
        Assert.Equal(original.FileSize, deserialized.FileSize);
        Assert.Equal(original.ExpectedSha512, deserialized.ExpectedSha512);
        Assert.Equal(original.ChunkSize, deserialized.ChunkSize);
    }

    [Fact]
    public void DataChunkFraming_SerializeAndParseHeader_MatchesExpectedFields()
    {
        Guid transferId = Guid.NewGuid();
        long chunkIndex = 42L;
        long offset = 2752512L;
        byte[] payload = new byte[1024];
        new Random(1234).NextBytes(payload);

        byte[] frame = DataChunkFraming.SerializeChunk(transferId, chunkIndex, offset, payload);

        Assert.True(frame.Length == DataChunkFraming.HeaderSizeBytes + payload.Length);

        // Header payload starts at byte offset 4 (after 4-byte total length prefix)
        var header = DataChunkFraming.ParseHeader(frame.AsSpan(4, DataChunkFraming.HeaderSizeBytes - 4));

        Assert.Equal(DataChunkMessageType.MSG_DATA_CHUNK, header.MsgType);
        Assert.Equal(transferId, header.TransferId);
        Assert.Equal(chunkIndex, header.ChunkIndex);
        Assert.Equal(offset, header.Offset);
        Assert.Equal(payload.Length, header.PayloadLength);
    }

    [Fact]
    public void DataChunkFraming_SerializeEndSignal_CreatesCorrectHeader()
    {
        Guid transferId = Guid.NewGuid();
        byte[] endFrame = DataChunkFraming.SerializeEndSignal(transferId);

        Assert.Equal(DataChunkFraming.HeaderSizeBytes, endFrame.Length);

        var header = DataChunkFraming.ParseHeader(endFrame.AsSpan(4, DataChunkFraming.HeaderSizeBytes - 4));

        Assert.Equal(DataChunkMessageType.MSG_DATA_END, header.MsgType);
        Assert.Equal(transferId, header.TransferId);
        Assert.Equal(0, header.PayloadLength);
    }

    [Theory]
    [InlineData("../../etc/passwd", "passwd")]
    [InlineData("..\\..\\Windows\\System32\\cmd.exe", "cmd.exe")]
    [InlineData("my:file?name*.pdf", "my_file_name_.pdf")]
    [InlineData("   ", "tether_received_file")]
    [InlineData(null, "tether_received_file")]
    public void FileTransferReceiver_SanitizeFilename_PreventsPathTraversalAndInvalidChars(string? input, string expected)
    {
        string result = FileTransferReceiver.SanitizeFilename(input);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void TransferProgress_CalculatesFractionAndSpeedCorrectly()
    {
        var progress = new TransferProgress
        {
            TransferId = "test-id",
            FileName = "test.iso",
            FileSize = 100 * 1024 * 1024, // 100 MB
            BytesTransferred = 50 * 1024 * 1024, // 50 MB
            SpeedBytesPerSec = 10 * 1024 * 1024, // 10 MB/s
            State = FileTransferState.TRANSFERRING
        };

        Assert.Equal(0.5f, progress.ProgressFraction);
        Assert.Equal(50, progress.ProgressPercentage);
        Assert.Equal(10.0, progress.SpeedMbPerSec);
        Assert.Equal(5L, progress.EtaSeconds);
    }

    [Fact]
    public void FileTransferManager_ComputeSpkiFingerprint_FormatsAsHexWithColons()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        string fp = FileTransferManager.ComputeSpkiFingerprint(cert);

        Assert.NotNull(fp);
        Assert.Contains(":", fp);
        Assert.Equal(32, fp.Split(':').Length); // SHA-256 is 32 bytes = 32 hex pairs
    }
}
