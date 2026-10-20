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
    }

    public void Start(int port = FileTransferReceiver.DefaultPort)
    {
        _receiver = new FileTransferReceiver(_logger, this, _serverCertificate, OnProgressUpdate);
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
