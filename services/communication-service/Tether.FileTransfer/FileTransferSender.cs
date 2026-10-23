using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
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
    private readonly Action<TransferProgress>? _onProgressUpdate;

    public FileTransferSender(
        ITetherLogger logger,
        X509Certificate2 clientCertificate,
        ITrustValidator trustValidator,
        Action<TransferProgress>? onProgressUpdate = null)
    {
        _logger = logger;
        _clientCertificate = clientCertificate;
        _trustValidator = trustValidator;
        _onProgressUpdate = onProgressUpdate;
    }

    public async Task ProcessOutgoingQueueAsync(
        string targetIp,
        DurableTransferQueue queue,
        int port = FileTransferReceiver.DefaultPort,
        Action<TransferProgress>? progressCallback = null,
        CancellationToken ct = default)
    {
        var activeCallback = progressCallback ?? _onProgressUpdate;

        var allItems = queue.GetAllItems().Where(i => !i.IsIncoming).ToList();
        var pendingItems = allItems.Where(i =>
        {
            if (i.State == FileTransferState.REQUESTED) return true;
            if (i.State == FileTransferState.FAILED && i.RetryCount < 5)
            {
                // Exponential backoff based on RetryCount (5s, 10s, 20s, 40s, 80s)
                double backoffSec = Math.Pow(2, i.RetryCount) * 5.0;
                return (DateTime.UtcNow - i.LastUpdatedUtc).TotalSeconds >= backoffSec;
            }
            return false;
        }).ToList();

        if (pendingItems.Count == 0) return;

        // Pre-compute hashes and sizes to avoid stalling the socket later
        var preparedItems = new System.Collections.Generic.List<(DurableTransferItem Item, string Sha512, long Size)>();
        foreach (var item in pendingItems)
        {
            if (ct.IsCancellationRequested) return;
            if (!File.Exists(item.SourcePath) && !Directory.Exists(item.SourcePath))
            {
                string errMsg = "Source path missing";
                queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: errMsg);
                EmitProgress(activeCallback, item.TransferId, item.FileName, 0, 0, 0, FileTransferState.FAILED, errMsg);
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
                string errMsg = $"Pre-processing failed: {ex.Message}";
                queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: errMsg);
                EmitProgress(activeCallback, item.TransferId, item.FileName, 0, 0, 0, FileTransferState.FAILED, errMsg);
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
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13
            };

            // Workaround for ECDSA CNG key container issues
            if (_clientCertificate.HasPrivateKey)
            {
                sslOptions.LocalCertificateSelectionCallback = (sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers) => _clientCertificate;
                sslOptions.ClientCertificates = new X509CertificateCollection();
            }
            else
            {
                sslOptions.ClientCertificates = new X509CertificateCollection { _clientCertificate };
            }

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
                    string errMsg = "Source path missing";
                    queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: errMsg);
                    EmitProgress(activeCallback, item.TransferId, item.FileName, prepared.Size, 0, 0, FileTransferState.FAILED, errMsg);
                    continue;
                }

                queue.UpdateState(item.TransferId, FileTransferState.CONNECTING);
                EmitProgress(activeCallback, item.TransferId, item.FileName, prepared.Size, 0, 0, FileTransferState.CONNECTING, null);

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
                        string reason = resp?.Reason ?? "Rejected by phone";
                        _logger.Warning($"FileTransferSender: Transfer {item.TransferId} rejected by phone: {reason}");
                        queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: reason);
                        EmitProgress(activeCallback, item.TransferId, item.FileName, fileSize, 0, 0, FileTransferState.FAILED, reason);
                        continue;
                    }

                    // 2. Stream binary data chunks
                    long startTimeMs = Environment.TickCount64;
                    long lastEmitTimeMs = startTimeMs;

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

                            long nowMs = Environment.TickCount64;
                            if (nowMs - lastEmitTimeMs >= 100 || bytesSent == fileSize)
                            {
                                double elapsedSec = Math.Max(0.001, (nowMs - startTimeMs) / 1000.0);
                                double speed = bytesSent / elapsedSec;

                                queue.UpdateState(item.TransferId, FileTransferState.TRANSFERRING, bytesTransferred: bytesSent);
                                EmitProgress(activeCallback, item.TransferId, item.FileName, fileSize, bytesSent, speed, FileTransferState.TRANSFERRING, null);
                                lastEmitTimeMs = nowMs;
                            }
                        }

                        byte[] endFrame = DataChunkFraming.SerializeEndSignal(uuid);
                        await sslStream.WriteAsync(endFrame, 0, endFrame.Length, ct);
                        await sslStream.FlushAsync(ct);
                    }

                    EmitProgress(activeCallback, item.TransferId, item.FileName, fileSize, fileSize, 0, FileTransferState.VERIFYING, null);

                    byte[] completeBytes = await ReadFrameAsync(sslStream, ct);
                    string completeJson = Encoding.UTF8.GetString(completeBytes);
                    using var completeDoc = JsonDocument.Parse(completeJson);
                    string status = completeDoc.RootElement.TryGetProperty("status", out var sProp) ? sProp.GetString() ?? "" : "";

                    if (status == "SUCCESS" || status == "OK")
                    {
                        queue.UpdateState(item.TransferId, FileTransferState.COMPLETED, bytesTransferred: fileSize);
                        EmitProgress(activeCallback, item.TransferId, item.FileName, fileSize, fileSize, 0, FileTransferState.COMPLETED, null);
                        _logger.Info($"FileTransferSender: Successfully completed transfer {item.FileName} ({fileSize} bytes)!");
                    }
                    else
                    {
                        string reason = completeDoc.RootElement.TryGetProperty("reason", out var rProp) ? rProp.GetString() ?? "Rejected" : "Rejected";
                        queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: reason);
                        EmitProgress(activeCallback, item.TransferId, item.FileName, fileSize, fileSize, 0, FileTransferState.FAILED, reason);
                        _logger.Warning($"FileTransferSender: Transfer {item.TransferId} reported failure by receiver: {reason}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error($"FileTransferSender: Exception sending transfer {item.TransferId}: {ex.Message}");
                    queue.UpdateState(item.TransferId, FileTransferState.FAILED, errorMessage: ex.Message);
                    EmitProgress(activeCallback, item.TransferId, item.FileName, prepared.Size, 0, 0, FileTransferState.FAILED, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"FileTransferSender: Connection to {targetIp}:{port} failed: {ex.Message}");
            foreach (var prepared in preparedItems)
            {
                EmitProgress(activeCallback, prepared.Item.TransferId, prepared.Item.FileName, prepared.Size, 0, 0, FileTransferState.FAILED, ex.Message);
            }
        }
    }

    private static void EmitProgress(
        Action<TransferProgress>? callback,
        string transferId,
        string fileName,
        long fileSize,
        long bytesTransferred,
        double speedBytesPerSec,
        FileTransferState state,
        string? errorMessage)
    {
        if (callback == null) return;

        var progress = new TransferProgress
        {
            TransferId = transferId,
            FileName = fileName,
            FileSize = fileSize,
            BytesTransferred = bytesTransferred,
            SpeedBytesPerSec = speedBytesPerSec,
            State = state,
            IsIncoming = false,
            PeerName = "Phone",
            ErrorMessage = errorMessage,
            DestinationPath = null
        };

        callback(progress);
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

    public static string ComputeSha512Hex(string path)
    {
        using var sha = SHA512.Create();
        using var fs = File.OpenRead(path);
        byte[] hash = sha.ComputeHash(fs);
        return Convert.ToHexString(hash);
    }
}
