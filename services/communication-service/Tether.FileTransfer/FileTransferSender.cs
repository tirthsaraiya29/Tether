using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.FileTransfer.Protocol;
using Tether.FileTransfer.Receiver;
using Tether.Shared.Logging;

namespace Tether.FileTransfer;

public sealed class FileTransferSender
{
    private readonly ITetherLogger _logger;
    private readonly X509Certificate2 _clientCertificate;
    private readonly ITrustValidator _trustValidator;

    public FileTransferSender(ITetherLogger logger, X509Certificate2 clientCertificate, ITrustValidator trustValidator)
    {
        _logger = logger;
        _clientCertificate = clientCertificate;
        _trustValidator = trustValidator;
    }

    public async Task ProcessOutgoingQueueAsync(
        string targetIp,
        DurableTransferQueue queue,
        int port = FileTransferReceiver.DefaultPort,
        CancellationToken ct = default)
    {
        var pendingItems = queue.GetAllItems()
            .Where(i => !i.IsIncoming && (i.State == FileTransferState.REQUESTED || i.State == FileTransferState.FAILED))
            .ToList();

        if (pendingItems.Count == 0) return;

        // Pre-compute hashes and sizes to avoid stalling the socket later
        var preparedItems = new System.Collections.Generic.List<(DurableTransferItem Item, string Sha512, long Size)>();
        foreach (var item in pendingItems)
        {
            if (ct.IsCancellationRequested) return;
            if (!File.Exists(item.SourcePath) && !Directory.Exists(item.SourcePath))
            {
                queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: "Source path missing");
                continue;
            }
            try
            {
                string sha512 = ComputeSha512Hex(item.SourcePath);
                long size = new FileInfo(item.SourcePath).Length;
                preparedItems.Add((item, sha512, size));
            }
            catch (Exception ex)
            {
                 queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: $"Pre-processing failed: {ex.Message}");
            }
        }

        if (preparedItems.Count == 0) return;

        _logger.Info($"FileTransferSender: Attempting transport connection to {targetIp}:{port} for {preparedItems.Count} pending items...");

        using var tcpClient = new TcpClient();
        tcpClient.NoDelay = true;

        try
        {
            await tcpClient.ConnectAsync(targetIp, port, ct);
            using var sslStream = new SslStream(
                tcpClient.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (sender, cert, chain, errors) => {
                    if (cert is X509Certificate2 cert2) {
                        return _trustValidator.ValidatePeerPublicKey(cert2, out _, out _, out bool hasFiles) && hasFiles;
                    }
                    if (cert != null) {
                        return _trustValidator.ValidatePeerPublicKey(new X509Certificate2(cert), out _, out _, out bool hasFiles) && hasFiles;
                    }
                    return false;
                });

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = targetIp,
                ClientCertificates = new X509CertificateCollection { _clientCertificate },
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13
            };

            await sslStream.AuthenticateAsClientAsync(sslOptions, ct);
            _logger.Info($"FileTransferSender: TLS 1.3 authenticated to {targetIp}:{port}");

            // 1. Send CONTROL_INIT
            string myFingerprint = FileTransferManager.ComputeSpkiFingerprint(_clientCertificate);
            var initFrame = new ControlInitFrame { DeviceId = myFingerprint };
            await SendFrameAsync(sslStream, JsonSerializer.Serialize(initFrame), ct);

            byte[] ackFrame = await ReadFrameAsync(sslStream, ct);
            _logger.Info($"FileTransferSender: Received CONTROL_INIT_ACK");

            foreach (var prepared in preparedItems)
            {
                var item = prepared.Item;
                if (ct.IsCancellationRequested) break;
                if (!File.Exists(item.SourcePath) && !Directory.Exists(item.SourcePath))
                {
                    queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: "Source path missing");
                    continue;
                }

                queue.UpdateState(item.TransferId, FileTransferState.TRANSFERRING);

                try
                {
                    string sha512Hex = prepared.Sha512;
                    long fileSize = prepared.Size;
                    long chunkSize = 65536;
                    long totalChunks = fileSize > 0 ? (fileSize + chunkSize - 1) / chunkSize : 0;

                    var req = new TransferRequestFrame
                    {
                        TransferId = item.TransferId,
                        FileName = item.FileName,
                        FileSize = fileSize,
                        MimeType = "application/octet-stream",
                        ExpectedSha512 = sha512Hex,
                        ChunkSize = (int)chunkSize,
                        TotalChunks = totalChunks,
                        SourceLastModified = item.SourceLastModified
                    };

                    await SendFrameAsync(sslStream, JsonSerializer.Serialize(req), ct);

                    byte[] respBytes = await ReadFrameAsync(sslStream, ct);
                    string respJson = Encoding.UTF8.GetString(respBytes);
                    var resp = JsonSerializer.Deserialize<TransferResponseFrame>(respJson);

                    if (resp == null || resp.Status != "ACCEPTED")
                    {
                        _logger.Warning($"FileTransferSender: Transfer {item.TransferId} rejected by phone: {resp?.Reason}");
                        queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: resp?.Reason ?? "Rejected");
                        continue;
                    }

                    // 2. Stream binary data chunks
                    using (var fs = File.OpenRead(item.SourcePath))
                    {
                        byte[] buffer = new byte[chunkSize];
                        long bytesSent = 0;
                        long chunkIndex = 0;
                        int read;
                        var uuid = Guid.Parse(item.TransferId);

                        while ((read = await fs.ReadAsync(buffer, 0, buffer.Length, ct)) > 0)
                        {
                            byte[] chunkFrame = DataChunkFraming.SerializeChunk(uuid, chunkIndex++, bytesSent, buffer, 0, read);
                            await sslStream.WriteAsync(chunkFrame, 0, chunkFrame.Length, ct);
                            await sslStream.FlushAsync(ct);
                            bytesSent += read;

                            queue.UpdateState(item.TransferId, FileTransferState.TRANSFERRING, bytesTransferred: bytesSent);
                        }

                        byte[] endFrame = DataChunkFraming.SerializeEndSignal(uuid);
                        await sslStream.WriteAsync(endFrame, 0, endFrame.Length, ct);
                        await sslStream.FlushAsync(ct);
                    }

                    byte[] completeBytes = await ReadFrameAsync(sslStream, ct);
                    string completeJson = Encoding.UTF8.GetString(completeBytes);
                    using var completeDoc = JsonDocument.Parse(completeJson);
                    string status = completeDoc.RootElement.TryGetProperty("status", out var sProp) ? sProp.GetString() ?? "" : "";

                    if (status == "SUCCESS" || status == "OK")
                    {
                        queue.UpdateState(item.TransferId, FileTransferState.COMPLETED, bytesTransferred: fileSize);
                        _logger.Info($"FileTransferSender: Successfully completed transfer {item.FileName} ({fileSize} bytes)!");
                    }
                    else
                    {
                        string reason = completeDoc.RootElement.TryGetProperty("reason", out var rProp) ? rProp.GetString() ?? "Rejected" : "Rejected";
                        queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: reason);
                        _logger.Warning($"FileTransferSender: Transfer {item.TransferId} reported failure by receiver: {reason}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"FileTransferSender: Exception sending transfer {item.TransferId}: {ex.Message}");
                    queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"FileTransferSender: Connection to {targetIp}:{port} failed: {ex.Message}");
        }
    }

    private static async Task SendFrameAsync(SslStream stream, string jsonStr, CancellationToken ct)
    {
        byte[] payload = Encoding.UTF8.GetBytes(jsonStr);
        byte[] lenBytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(lenBytes, payload.Length);

        await stream.WriteAsync(lenBytes, 0, 4, ct);
        await stream.WriteAsync(payload, 0, payload.Length, ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<byte[]> ReadFrameAsync(SslStream stream, CancellationToken ct)
    {
        byte[] lenBytes = new byte[4];
        int read = await stream.ReadAsync(lenBytes, 0, 4, ct);
        if (read < 4) throw new EndOfStreamException("Failed reading frame length header");

        int len = BinaryPrimitives.ReadInt32BigEndian(lenBytes);
        byte[] payload = new byte[len];
        int offset = 0;
        while (offset < len)
        {
            int r = await stream.ReadAsync(payload, offset, len - offset, ct);
            if (r <= 0) break;
            offset += r;
        }
        return payload;
    }

    private static string ComputeSha512Hex(string path)
    {
        using var sha = SHA512.Create();
        using var fs = File.OpenRead(path);
        byte[] hash = sha.ComputeHash(fs);
        return Convert.ToHexString(hash);
    }
}
