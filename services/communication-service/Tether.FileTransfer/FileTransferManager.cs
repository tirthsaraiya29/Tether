using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Tether.FileTransfer.Protocol;
using Tether.FileTransfer.Receiver;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.FileTransfer;

public interface ITrustStoreProvider
{
    bool IsPeerTrustedAndHasCapability(
        string spkiFingerprint,
        string requiredCapability,
        out string displayName);
}

public sealed class FileTransferManager : ITrustValidator, IDisposable
{
    private readonly ITetherLogger _logger;
    private readonly ITrustStoreProvider _trustStoreProvider;
    private readonly Action<TetherEvent>? _eventPublisher;
    private readonly X509Certificate2 _serverCertificate;

    private readonly ConcurrentDictionary<string, TransferProgress> _transfers = new(StringComparer.OrdinalIgnoreCase);
    private readonly FileSystemBrowser _fileSystemBrowser;
    private readonly DurableTransferQueue _durableQueue;
    private readonly FileTransferSender _sender;
    private FileTransferReceiver? _receiver;
    private bool _disposed;

    public FileTransferManager(
        ITetherLogger logger,
        ITrustStoreProvider trustStoreProvider,
        X509Certificate2 serverCertificate,
        Action<TetherEvent>? eventPublisher)
    {
        _logger = logger;
        _trustStoreProvider = trustStoreProvider;
        _serverCertificate = serverCertificate;
        _eventPublisher = eventPublisher;
        _fileSystemBrowser = new FileSystemBrowser(logger);
        _durableQueue = new DurableTransferQueue(logger);
        _sender = new FileTransferSender(logger, serverCertificate, this, OnProgressUpdate);
    }

    public FileSystemBrowser FileSystemBrowser => _fileSystemBrowser;
    public DurableTransferQueue DurableQueue => _durableQueue;

    public async System.Threading.Tasks.Task ProcessOutgoingQueueAsync(string phoneIp, System.Threading.CancellationToken ct = default)
    {
        await _sender.ProcessOutgoingQueueAsync(phoneIp, _durableQueue, FileTransferReceiver.DefaultPort, OnProgressUpdate, ct);
    }

    public async System.Threading.Tasks.Task RequestPhoneDbSyncAsync(string phoneIp, System.Threading.CancellationToken ct = default)
    {
        _logger.Info($"Requesting Phone DB Sync from {phoneIp}...");
        using var cts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromMinutes(5));

        using var client = new System.Net.Sockets.TcpClient();
        client.NoDelay = true;
        try
        {
            await client.ConnectAsync(phoneIp, FileTransferReceiver.DefaultPort, cts.Token);
            using var sslStream = new System.Net.Security.SslStream(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (s, c, ch, e) => true);

            var options = new System.Net.Security.SslClientAuthenticationOptions
            {
                TargetHost = phoneIp,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13
            };

            if (_serverCertificate.HasPrivateKey)
            {
                options.LocalCertificateSelectionCallback = (sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers) => _serverCertificate;
                options.ClientCertificates = new X509CertificateCollection();
            }
            else
            {
                options.ClientCertificates = new X509CertificateCollection { _serverCertificate };
            }

            await sslStream.AuthenticateAsClientAsync(options, cts.Token);

            var initFrame = new ControlInitFrame { DeviceId = "LOCAL_WIN" };
            byte[] initPayload = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(initFrame));
            byte[] lenBytes = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lenBytes, initPayload.Length);
            await sslStream.WriteAsync(lenBytes, cts.Token);
            await sslStream.WriteAsync(initPayload, cts.Token);
            await sslStream.FlushAsync(cts.Token);

            // Read Init Ack
            byte[] ackLenBytes = new byte[4];
            int ackRead = await sslStream.ReadAsync(ackLenBytes, 0, 4, cts.Token);
            if (ackRead < 4) throw new System.IO.EndOfStreamException("Failed reading init ack length");
            int ackLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(ackLenBytes);
            byte[] ackPayload = new byte[ackLen];
            int ackBytesRead = 0;
            while (ackBytesRead < ackLen)
            {
                int r = await sslStream.ReadAsync(ackPayload, ackBytesRead, ackLen - ackBytesRead, cts.Token);
                if (r <= 0) break;
                ackBytesRead += r;
            }

            // Send FS_DB_SYNC_REQUEST
            var syncReq = new FsDbSyncRequestFrame();
            byte[] reqPayload = System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(syncReq));
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lenBytes, reqPayload.Length);
            await sslStream.WriteAsync(lenBytes, cts.Token);
            await sslStream.WriteAsync(reqPayload, cts.Token);
            await sslStream.FlushAsync(cts.Token);

            _logger.Info("Sent FS_DB_SYNC_REQUEST to phone successfully. Awaiting response...");

            // Read FS_DB_SYNC_RESPONSE from phone
            byte[] respLenBytes = new byte[4];
            int respRead = await sslStream.ReadAsync(respLenBytes, 0, 4, cts.Token);
            if (respRead < 4) throw new System.IO.EndOfStreamException("Failed reading DB sync response length");
            int respLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(respLenBytes);
            byte[] respPayload = new byte[respLen];
            int respBytesRead = 0;
            while (respBytesRead < respLen)
            {
                int r = await sslStream.ReadAsync(respPayload, respBytesRead, respLen - respBytesRead, cts.Token);
                if (r <= 0) break;
                respBytesRead += r;
            }

            string respJson = System.Text.Encoding.UTF8.GetString(respPayload);
            var resp = JsonSerializer.Deserialize<FsDbSyncResponseFrame>(respJson);
            if (resp == null || resp.Status != "OK")
            {
                throw new Exception($"Phone returned non-OK DB sync response: {resp?.Status}");
            }

            _logger.Info($"FS_DB_SYNC completed successfully from phone ({resp.DbSize} bytes).");
        }
        catch (Exception ex)
        {
            _logger.Warning($"Failed sending or completing FS_DB_SYNC_REQUEST to phone: {ex.Message}");
            throw;
        }
    }

    public void Start(int port = FileTransferReceiver.DefaultPort)
    {
        _receiver = new FileTransferReceiver(_logger, this, _serverCertificate, OnProgressUpdate, _fileSystemBrowser, _durableQueue);
        _receiver.Start(port);
        _logger.Info("FileTransferManager initialized and receiver started.");
    }

    public void Stop()
    {
        _receiver?.Stop();
        _receiver?.Dispose();
        _receiver = null;
        _logger.Info("FileTransferManager stopped.");
    }

    public void CancelTransfer(string transferId)
    {
        _receiver?.CancelTransfer(transferId);

        if (_transfers.TryGetValue(transferId, out var existing))
        {
            var cancelled = existing with
            {
                State = FileTransferState.CANCELLED,
                ErrorMessage = "Cancelled by user"
            };
            OnProgressUpdate(cancelled);
        }
    }

    public IReadOnlyCollection<TransferProgress> GetAllTransfers() =>
        _transfers.Values.ToArray();

    public IReadOnlyCollection<TransferProgress> GetActiveTransfers() =>
        _transfers.Values.Where(t => t.State == FileTransferState.TRANSFERRING || t.State == FileTransferState.VERIFYING).ToArray();

    public bool ValidatePeerPublicKey(
        X509Certificate2 certificate,
        out string fingerprint,
        out string displayName,
        out bool hasFilesCapability)
    {
        fingerprint = ComputeSpkiFingerprint(certificate);
        return ValidatePeerByFingerprint(fingerprint, out displayName, out hasFilesCapability);
    }

    public bool ValidatePeerByFingerprint(
        string fingerprint,
        out string displayName,
        out bool hasFilesCapability)
    {
        bool trusted = _trustStoreProvider.IsPeerTrustedAndHasCapability(fingerprint, "FILES", out displayName);
        hasFilesCapability = trusted;

        if (!trusted)
        {
            _logger.Warning($"FileTransferManager: Peer authentication failed for fingerprint={fingerprint}");
        }

        return trusted;
    }

    private void OnProgressUpdate(TransferProgress progress)
    {
        _transfers[progress.TransferId] = progress;

        TetherEventType eventType = progress.State switch
        {
            FileTransferState.TRANSFERRING => TetherEventType.FILE_TRANSFER_PROGRESS,
            FileTransferState.VERIFYING => TetherEventType.FILE_TRANSFER_PROGRESS,
            FileTransferState.COMPLETED => TetherEventType.FILE_TRANSFER_COMPLETED,
            FileTransferState.FAILED => TetherEventType.FILE_TRANSFER_FAILED,
            FileTransferState.CANCELLED => TetherEventType.FILE_TRANSFER_CANCELLED,
            _ => TetherEventType.FILE_TRANSFER_PROGRESS
        };

        var evt = new TetherEvent
        {
            EventType = eventType,
            Source = "FileTransferManager",
            Timestamp = DateTime.UtcNow,
            PayloadJson = JsonSerializer.Serialize(progress)
        };

        _eventPublisher?.Invoke(evt);
    }

    public static string ComputeSpkiFingerprint(X509Certificate2 cert)
    {
        byte[] spkiDer;
        using var ec = cert.GetECDsaPublicKey();
        if (ec != null)
        {
            spkiDer = ec.ExportSubjectPublicKeyInfo();
        }
        else
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null)
            {
                spkiDer = rsa.ExportSubjectPublicKeyInfo();
            }
            else
            {
                spkiDer = cert.RawData;
            }
        }

        byte[] hash = SHA256.HashData(spkiDer);
        return string.Join(":", hash.Select(b => b.ToString("X2")));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
