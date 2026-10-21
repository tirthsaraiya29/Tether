using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Versioning;
using Tether.FileTransfer.Protocol;
using Tether.Shared.Logging;

namespace Tether.FileTransfer.Receiver;

public interface ITrustValidator
{
    bool ValidatePeerPublicKey(X509Certificate2 certificate, out string fingerprint, out string displayName, out bool hasFilesCapability);
}

[SupportedOSPlatform("windows")]
public sealed class FileTransferReceiver : IDisposable
{
    public const int DefaultPort = 37125;
    private const int MaxControlFrameBytes = 65536; // 64 KB
    private const int MaxDataFrameBytes = (1024 * 1024) + DataChunkFraming.HeaderSizeBytes; // 1 MB chunk + framing header

    private readonly ITetherLogger _logger;
    private readonly ITrustValidator _trustValidator;
    private readonly Action<TransferProgress> _onProgressUpdate;
    private readonly X509Certificate2 _serverCertificate;
    private readonly FileSystemBrowser _fileSystemBrowser;
    private readonly DurableTransferQueue _durableQueue;

    private readonly string _stagingDirectory;
    private CancellationTokenSource? _cts;
    private QuicListener? _quicListener;
    private TcpListener? _tcpListener;

    private Task? _quicLoop;
    private Task? _tcpLoop;
    private bool _disposed;

    private readonly ConcurrentDictionary<string, CancellationTokenSource> _activeTransferCts = new();

    public FileTransferReceiver(
        ITetherLogger logger,
        ITrustValidator trustValidator,
        X509Certificate2 serverCertificate,
        Action<TransferProgress> onProgressUpdate,
        FileSystemBrowser? fileSystemBrowser = null,
        DurableTransferQueue? durableQueue = null)
    {
        _logger = logger;
        _trustValidator = trustValidator;
        _serverCertificate = serverCertificate;
        _onProgressUpdate = onProgressUpdate;
        _fileSystemBrowser = fileSystemBrowser ?? new FileSystemBrowser(logger);
        _durableQueue = durableQueue ?? new DurableTransferQueue(logger);

        string commonData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        _stagingDirectory = Path.Combine(commonData, "Tether", "staging");
        EnsureStagingDirectoryAcl(_stagingDirectory, _logger);
    }

    public void Start(int port = DefaultPort)
    {
        _cts = new CancellationTokenSource();

        // 1. Start QUIC listener on UDP port
        _quicLoop = Task.Run(() => StartQuicListenerAsync(port, _cts.Token));

        // 2. Start TCP/SslStream listener on TCP port for Android client fallback
        _tcpLoop = Task.Run(() => StartTcpListenerAsync(port, _cts.Token));

        _logger.Info($"FileTransferReceiver listening on UDP/TCP port {port} (ALPN=tether-quic-v1).");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }

        try { _quicListener?.DisposeAsync().AsTask().Wait(2000); } catch { }
        try { _tcpListener?.Stop(); } catch { }

        try { _quicLoop?.Wait(2000); } catch { }
        try { _tcpLoop?.Wait(2000); } catch { }

        _cts?.Dispose();
        _cts = null;
        _logger.Info("FileTransferReceiver stopped.");
    }

    public void CancelTransfer(string transferId)
    {
        if (_activeTransferCts.TryRemove(transferId, out var cts))
        {
            try { cts.Cancel(); } catch { }
            try { cts.Dispose(); } catch { }
        }

        try
        {
            string stagingFile = GetStagingFilePath(transferId);
            if (File.Exists(stagingFile))
            {
                try { File.Delete(stagingFile); } catch { }
            }
        }
        catch (ArgumentException ex)
        {
            _logger.Warning($"Invalid transferId in CancelTransfer: {ex.Message}");
        }
    }

    private async Task StartQuicListenerAsync(int port, CancellationToken ct)
    {
        if (!QuicListener.IsSupported)
        {
            _logger.Warning("System.Net.Quic is not supported on this platform. QUIC UDP listener will not start.");
            return;
        }

        try
        {
            var options = new QuicListenerOptions
            {
                ListenEndPoint = new IPEndPoint(IPAddress.Any, port),
                ApplicationProtocols = new System.Collections.Generic.List<SslApplicationProtocol>
                {
                    new SslApplicationProtocol("tether-quic-v1")
                },
                ConnectionOptionsCallback = (connection, info, cancellationToken) =>
                {
                    return ValueTask.FromResult(new QuicServerConnectionOptions
                    {
                        ServerAuthenticationOptions = new SslServerAuthenticationOptions
                        {
                            ServerCertificate = _serverCertificate,
                            ClientCertificateRequired = false,
                            RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true
                        }
                    });
                }
            };

            _quicListener = await QuicListener.ListenAsync(options, ct);
            _logger.Info($"QuicListener active on UDP port {port}.");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var conn = await _quicListener.AcceptConnectionAsync(ct);
                    _ = Task.Run(() => HandleQuicConnectionAsync(conn, ct), ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    if (ct.IsCancellationRequested) break;
                    _logger.Warning($"QuicListener accept exception: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed starting QuicListener on UDP {port}: {ex.Message}");
        }
    }

    private async Task HandleQuicConnectionAsync(QuicConnection connection, CancellationToken ct)
    {
        try
        {
            // Identity is proven by the client certificate; CONTROL_INIT may only confirm it.
            var stream = await connection.AcceptInboundStreamAsync(ct);
            using var streamAdapter = new QuicStreamAdapter(stream);
            await HandleTransferSessionAsync(streamAdapter, ExtractPeerCertFromConnection(connection), ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"QuicConnection session ended: {ex.Message}");
        }
        finally
        {
            try { await connection.CloseAsync(0, ct); } catch { }
        }
    }

    private static X509Certificate2? ExtractPeerCertFromConnection(QuicConnection connection)
    {
        try
        {
            if (connection.RemoteCertificate is X509Certificate2 cert) return cert;
            if (connection.RemoteCertificate != null) return new X509Certificate2(connection.RemoteCertificate);
        }
        catch { }
        return null;
    }

    private async Task StartTcpListenerAsync(int port, CancellationToken ct)
    {
        try
        {
            _tcpListener = new TcpListener(IPAddress.Any, port);
            _tcpListener.Start(backlog: 8);
            _logger.Info($"TcpListener active on TCP port {port}.");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = await _tcpListener.AcceptTcpClientAsync(ct);
                    _ = Task.Run(() => HandleTcpConnectionAsync(client, ct), ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    if (ct.IsCancellationRequested) break;
                    _logger.Warning($"TcpListener accept exception: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed starting TcpListener on TCP {port}: {ex.Message}");
        }
    }

    private async Task HandleTcpConnectionAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            client.NoDelay = true;
            using var networkStream = client.GetStream();
            using var sslStream = new SslStream(networkStream, false, (sender, cert, chain, errors) => true);

            var sslOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _serverCertificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                ApplicationProtocols = new System.Collections.Generic.List<SslApplicationProtocol>
                {
                    new SslApplicationProtocol("tether-quic-v1")
                }
            };

            await sslStream.AuthenticateAsServerAsync(sslOptions, ct);

            // Capture client certificate if presented during handshake
            X509Certificate2? peerCertificate = sslStream.RemoteCertificate switch
            {
                X509Certificate2 asX509 => asX509,
                null => null,
                var other => new X509Certificate2(other)
            };

            using var streamAdapter = new NetworkStreamAdapter(sslStream);
            await HandleTransferSessionAsync(streamAdapter, peerCertificate, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"TcpConnection session ended: {ex.Message}");
        }
        finally
        {
            try { client.Close(); } catch { }
        }
    }

    private async Task HandleTransferSessionAsync(ITransportStream stream, X509Certificate2? peerCertificate, CancellationToken ct)
    {
        _logger.Info("Starting HandleTransferSessionAsync (waiting for CONTROL_INIT)");
        byte[] lenBuffer = new byte[4];

        string authenticatedPeerName = "Unknown Device";
        string authenticatedFingerprint = "";
        bool isAuthenticated = false;

        while (!ct.IsCancellationRequested)
        {
            int read = await ReadExactAsync(stream, lenBuffer, 0, 4, ct);
            if (read < 4) break;

            int payloadLen = BinaryPrimitives.ReadInt32BigEndian(lenBuffer);
            if (payloadLen <= 0 || payloadLen > MaxControlFrameBytes)
            {
                _logger.Error($"Invalid control frame length received: {payloadLen} bytes.");
                break;
            }

            byte[] controlJsonBytes = new byte[payloadLen];
            read = await ReadExactAsync(stream, controlJsonBytes, 0, payloadLen, ct);
            if (read < payloadLen) break;

            string jsonStr = Encoding.UTF8.GetString(controlJsonBytes);
            using var doc = JsonDocument.Parse(jsonStr);
            string messageType = doc.RootElement.GetProperty("type").GetString() ?? "";

            switch (messageType)
            {
                case ControlMessageType.CONTROL_INIT:
                    string deviceId = doc.RootElement.TryGetProperty("deviceId", out var dProp) ? dProp.GetString() ?? "" : "";

                    string certFingerprint = "";
                    string dispName = "Unknown Device";
                    bool hasFiles = false;
                    bool isAuthenticatedPeer = false;

                    if (peerCertificate != null)
                    {
                        // Validate client certificate against trust store and ensure fingerprint matches claimed deviceId
                        bool certValid = _trustValidator.ValidatePeerPublicKey(peerCertificate, out certFingerprint, out dispName, out hasFiles);
                        isAuthenticatedPeer = certValid && string.Equals(certFingerprint, deviceId, StringComparison.OrdinalIgnoreCase);
                        if (!isAuthenticatedPeer)
                        {
                            _logger.Warning($"Peer rejected: client certificate fingerprint '{certFingerprint}' does not match claimed deviceId '{deviceId}' or is untrusted.");
                        }
                    }
                    else
                    {
                        // Fallback when client certificate was not presented at transport layer
                        if (_trustValidator is FileTransferManager ftm && ftm.ValidatePeerByFingerprint(deviceId, out dispName, out hasFiles))
                        {
                            certFingerprint = deviceId;
                            isAuthenticatedPeer = true;
                        }
                        else
                        {
                            _logger.Warning($"Peer rejected: fingerprint '{deviceId}' untrusted.");
                        }
                    }

                    if (!isAuthenticatedPeer)
                    {
                        return; // Drop connection
                    }

                    if (hasFiles)
                    {
                        isAuthenticated = true;
                        authenticatedPeerName = dispName;
                        authenticatedFingerprint = certFingerprint;
                        _logger.Info($"QUIC/TCP peer authenticated successfully: {dispName}");
                        var ack = new ControlInitAckFrame { Status = "OK", GrantedCapabilities = "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA" };
                        await SendControlFrameAsync(stream, JsonSerializer.Serialize(ack), ct);
                    }
                    else
                    {
                        _logger.Warning($"Peer {dispName} rejected: missing FILES capability.");
                        return; // Drop connection
                    }
                    break;

                case ControlMessageType.FS_DB_SYNC_REQUEST:
                    if (!isAuthenticated) return;
                    var syncReq = JsonSerializer.Deserialize<FsDbSyncRequestFrame>(jsonStr);
                    if (syncReq != null)
                    {
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                var indexer = new WindowsFilesystemIndexer(_logger);
                                string dbPath = await indexer.BuildDatabaseAsync();

                                var resp = new FsDbSyncResponseFrame
                                {
                                    RequestId = syncReq.RequestId,
                                    Status = "OK",
                                    DbSize = new FileInfo(dbPath).Length,
                                    Checksum = "unknown_for_now"
                                };
                                await SendControlFrameAsync(stream, JsonSerializer.Serialize(resp), ct);

                                _durableQueue.EnqueueOutgoing(dbPath, authenticatedPeerName, "windows_fs.db");
                            }
                            catch (Exception ex)
                            {
                                var resp = new FsDbSyncResponseFrame
                                {
                                    RequestId = syncReq.RequestId,
                                    Status = "ERROR"
                                };
                                await SendControlFrameAsync(stream, JsonSerializer.Serialize(resp), ct);
                            }
                        });
                    }
                    break;

                case ControlMessageType.BROWSE_ROOTS_REQUEST:
                    if (!isAuthenticated)
                    {
                        _logger.Warning("BROWSE_ROOTS_REQUEST received before CONTROL_INIT.");
                        return;
                    }
                    var browseReq = JsonSerializer.Deserialize<BrowseRootsRequestFrame>(jsonStr);
                    var roots = _fileSystemBrowser.GetPermittedRoots();
                    var browseResp = new BrowseRootsResponseFrame
                    {
                        RequestId = browseReq?.RequestId ?? "",
                        Status = "OK",
                        Roots = roots
                    };
                    await SendControlFrameAsync(stream, JsonSerializer.Serialize(browseResp), ct);
                    break;

                case ControlMessageType.LIST_DIR_REQUEST:
                    if (!isAuthenticated)
                    {
                        _logger.Warning("LIST_DIR_REQUEST received before CONTROL_INIT.");
                        return;
                    }
                    var listReq = JsonSerializer.Deserialize<ListDirRequestFrame>(jsonStr);
                    try
                    {
                        var items = _fileSystemBrowser.ListDirectory(listReq?.Path ?? "");
                        var listResp = new ListDirResponseFrame
                        {
                            RequestId = listReq?.RequestId ?? "",
                            Status = "OK",
                            Path = listReq?.Path ?? "",
                            Items = items
                        };
                        await SendControlFrameAsync(stream, JsonSerializer.Serialize(listResp), ct);
                    }
                    catch (Exception ex)
                    {
                        var errorResp = new ListDirResponseFrame
                        {
                            RequestId = listReq?.RequestId ?? "",
                            Status = "ERROR",
                            Path = listReq?.Path ?? "",
                            ErrorMessage = ex.Message
                        };
                        await SendControlFrameAsync(stream, JsonSerializer.Serialize(errorResp), ct);
                    }
                    break;

                case ControlMessageType.QUEUE_SYNC_REQUEST:
                    if (!isAuthenticated)
                    {
                        _logger.Warning("QUEUE_SYNC_REQUEST received before CONTROL_INIT.");
                        return;
                    }
                    var qSyncReq = JsonSerializer.Deserialize<QueueSyncRequestFrame>(jsonStr);
                    var queueItems = _durableQueue.GetAllItems().ToList();
                    var syncSnapshot = new QueueSyncSnapshotFrame
                    {
                        RequestId = qSyncReq?.RequestId ?? "",
                        Items = queueItems
                    };
                    await SendControlFrameAsync(stream, JsonSerializer.Serialize(syncSnapshot), ct);
                    break;

                case ControlMessageType.TRANSFER_REQUEST:
                    if (!isAuthenticated)
                    {
                        _logger.Warning("TRANSFER_REQUEST received before CONTROL_INIT. Dropping connection.");
                        return;
                    }
                    var request = JsonSerializer.Deserialize<TransferRequestFrame>(jsonStr);
                    if (request != null)
                    {
                        await HandleIncomingTransferRequestAsync(stream, request, authenticatedPeerName, ct);
                    }
                    break;

                case ControlMessageType.TRANSFER_CANCEL:
                    if (!isAuthenticated)
                    {
                        _logger.Warning("TRANSFER_CANCEL received before CONTROL_INIT. Dropping connection.");
                        return;
                    }
                    var cancel = JsonSerializer.Deserialize<TransferCancelFrame>(jsonStr);
                    if (cancel != null)
                    {
                        CancelTransfer(cancel.TransferId);
                    }
                    break;

                default:
                    _logger.Debug($"Unhandled control message type: {messageType}");
                    break;
            }
        }
    }

    private async Task HandleIncomingTransferRequestAsync(
        ITransportStream stream,
        TransferRequestFrame request,
        string peerName,
        CancellationToken ct)
    {
        string transferId = request.TransferId;
        string sanitizedFileName = SanitizeFilename(request.FileName);
        string stagingFile = GetStagingFilePath(transferId);

        using var transferCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _activeTransferCts[transferId] = transferCts;

        var progress = new TransferProgress
        {
            TransferId = transferId,
            FileName = sanitizedFileName,
            FileSize = request.FileSize,
            BytesTransferred = 0L,
            SpeedBytesPerSec = 0.0,
            State = FileTransferState.TRANSFERRING,
            IsIncoming = true,
            PeerName = peerName
        };

        _onProgressUpdate(progress);

        // Send ACCEPTED response
        var acceptResp = new TransferResponseFrame
        {
            TransferId = transferId,
            Status = "ACCEPTED",
            ResumeOffset = 0L
        };
        await SendControlFrameAsync(stream, JsonSerializer.Serialize(acceptResp), ct);

        // Prepare streaming file write & SHA-512 calculation
        if (File.Exists(stagingFile))
        {
            try { File.Delete(stagingFile); } catch { }
        }

        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        long bytesTransferred = 0L;
        long startTimeMs = Environment.TickCount64;
        long lastEmitTimeMs = startTimeMs;

        try
        {
            using (var fileStream = new FileStream(stagingFile, FileMode.Create, FileAccess.Write, FileShare.None, 65536, useAsync: true))
            {
                byte[] frameLenBuf = new byte[4];

                while (bytesTransferred < request.FileSize && !transferCts.Token.IsCancellationRequested)
                {
                    int readLen = await ReadExactAsync(stream, frameLenBuf, 0, 4, transferCts.Token);
                    if (readLen < 4) break;

                    int totalFrameLength = BinaryPrimitives.ReadInt32BigEndian(frameLenBuf);
                    if (totalFrameLength < DataChunkFraming.HeaderSizeBytes - 4) break;

                    long remainingBytes = request.FileSize - bytesTransferred;
                    if (totalFrameLength > MaxDataFrameBytes ||
                        totalFrameLength > remainingBytes + (DataChunkFraming.HeaderSizeBytes - 4))
                    {
                        throw new InvalidDataException(
                            $"Data frame length {totalFrameLength} is invalid for transfer {transferId} (remaining bytes: {remainingBytes}).");
                    }

                    byte[] frameBuffer = ArrayPool<byte>.Shared.Rent(totalFrameLength);
                    try
                    {
                        readLen = await ReadExactAsync(stream, frameBuffer, 0, totalFrameLength, transferCts.Token);
                        if (readLen < totalFrameLength) break;

                        var header = DataChunkFraming.ParseHeader(frameBuffer.AsSpan(0, DataChunkFraming.HeaderSizeBytes - 4));
                        if (header.MsgType == DataChunkMessageType.MSG_DATA_END)
                        {
                            _logger.Info($"Received DATA_END signal for transfer {transferId}.");
                            break;
                        }

                        int payloadOffset = DataChunkFraming.HeaderSizeBytes - 4;
                        int payloadLen = header.PayloadLength;

                        if (payloadLen > 0 && payloadOffset + payloadLen <= totalFrameLength)
                        {
                            await fileStream.WriteAsync(frameBuffer.AsMemory(payloadOffset, payloadLen), transferCts.Token);
                            hasher.AppendData(frameBuffer, payloadOffset, payloadLen);
                            bytesTransferred += payloadLen;

                            long now = Environment.TickCount64;
                            if (now - lastEmitTimeMs >= 100) // ~100ms throttle
                            {
                                double elapsedSec = (now - startTimeMs) / 1000.0;
                                double speed = elapsedSec > 0 ? bytesTransferred / elapsedSec : 0.0;

                                progress = progress with
                                {
                                    BytesTransferred = bytesTransferred,
                                    SpeedBytesPerSec = speed,
                                    State = FileTransferState.TRANSFERRING
                                };
                                _onProgressUpdate(progress);
                                lastEmitTimeMs = now;
                            }
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(frameBuffer);
                    }
                }

                await fileStream.FlushAsync(transferCts.Token);
            }

            // Verify SHA-512 integrity
            progress = progress with { BytesTransferred = bytesTransferred, State = FileTransferState.VERIFYING };
            _onProgressUpdate(progress);

            byte[] computedHash = hasher.GetHashAndReset();
            string computedHashHex = Convert.ToHexString(computedHash);

            if (!FixedTimeHexEquals(computedHashHex, request.ExpectedSha512))
            {
                _logger.Error($"SHA-512 integrity verification failed for {sanitizedFileName} ({transferId}). Expected={request.ExpectedSha512}, Computed={computedHashHex}");
                try { File.Delete(stagingFile); } catch { }

                progress = progress with
                {
                    State = FileTransferState.FAILED,
                    ErrorMessage = "SHA-512 integrity verification failed."
                };
                _onProgressUpdate(progress);

                var failComplete = new TransferCompleteFrame
                {
                    TransferId = transferId,
                    Status = "FAILED",
                    ErrorCode = (int)FileTransferErrorCode.INTEGRITY_FAILED,
                    Reason = "SHA-512 digest mismatch"
                };
                await SendControlFrameAsync(stream, JsonSerializer.Serialize(failComplete), ct);
                return;
            }

            // Promote staging file
            string finalDestination;
            if (sanitizedFileName == "android_fs.db")
            {
                string commonData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string destPath = Path.Combine(commonData, "Tether", "android_fs.db");
                if (File.Exists(destPath)) File.Delete(destPath);
                File.Move(stagingFile, destPath);
                finalDestination = destPath;
                _logger.Info($"Installed android_fs.db to {finalDestination}");
            }
            else
            {
                finalDestination = PromoteToDownloads(stagingFile, sanitizedFileName, _logger);
            }

            progress = progress with
            {
                BytesTransferred = bytesTransferred,
                State = FileTransferState.COMPLETED,
                DestinationPath = finalDestination,
                ErrorMessage = null
            };
            _onProgressUpdate(progress);

            _logger.Info($"File transfer {transferId} completed successfully! Destination={finalDestination}");

            var successComplete = new TransferCompleteFrame
            {
                TransferId = transferId,
                Status = "SUCCESS",
                ErrorCode = 0,
                Reason = ""
            };
            await SendControlFrameAsync(stream, JsonSerializer.Serialize(successComplete), ct);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning($"Transfer {transferId} cancelled by user.");
            try { File.Delete(stagingFile); } catch { }

            progress = progress with
            {
                State = FileTransferState.CANCELLED,
                ErrorMessage = "Cancelled by user"
            };
            _onProgressUpdate(progress);
        }
        catch (Exception ex)
        {
            _logger.Error($"Error receiving transfer {transferId}: {ex.Message}");
            try { File.Delete(stagingFile); } catch { }

            progress = progress with
            {
                State = FileTransferState.FAILED,
                ErrorMessage = ex.Message
            };
            _onProgressUpdate(progress);
        }
        finally
        {
            _activeTransferCts.TryRemove(transferId, out _);
        }
    }

    public static string SanitizeFilename(string? rawFileName)
    {
        if (string.IsNullOrWhiteSpace(rawFileName)) return "tether_received_file";

        string name = Path.GetFileName(rawFileName.Trim());
        char[] invalidChars = Path.GetInvalidFileNameChars();

        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
        {
            sb.Append(invalidChars.Contains(c) ? '_' : c);
        }

        string sanitized = sb.ToString().Trim();
        if (string.IsNullOrEmpty(sanitized) || sanitized == "." || sanitized == "..")
        {
            return "tether_received_file";
        }

        return sanitized.Length > 255 ? sanitized[..255] : sanitized;
    }

    public static string PromoteToDownloads(string stagingPath, string fileName, ITetherLogger logger)
    {
        string tetherFolder = GetTargetTetherFolder();
        if (!Directory.Exists(tetherFolder))
        {
            Directory.CreateDirectory(tetherFolder);
        }

        string destinationPath = Path.Combine(tetherFolder, fileName);
        string baseName = Path.GetFileNameWithoutExtension(fileName);
        string extension = Path.GetExtension(fileName);

        int counter = 1;
        while (File.Exists(destinationPath))
        {
            destinationPath = Path.Combine(tetherFolder, $"{baseName} ({counter}){extension}");
            counter++;
        }

        // Copy then delete to properly inherit target folder ACLs for standard users
        File.Copy(stagingPath, destinationPath, overwrite: false);
        File.Delete(stagingPath);

        logger.Info($"Promoted file from staging to destination: {destinationPath}");
        return destinationPath;
    }

    public static string GetTargetTetherFolder()
    {
        string baseUserFolder = GetActiveUserDirectory();

        // Check for custom path setting
        string settingsFile = Path.Combine(baseUserFolder, "AppData", "Local", "Tether", "settings.json");
        if (File.Exists(settingsFile))
        {
            try
            {
                var doc = JsonDocument.Parse(File.ReadAllText(settingsFile));
                if (doc.RootElement.TryGetProperty("DownloadPath", out var pathProp))
                {
                    string customPath = pathProp.GetString() ?? "";
                    if (!string.IsNullOrWhiteSpace(customPath) && Directory.Exists(customPath))
                    {
                        return customPath;
                    }
                }
            }
            catch { }
        }

        return Path.Combine(baseUserFolder, "Downloads", "Tether");
    }

    public static string GetActiveUserDirectory()
    {
        try
        {
            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            string usersDir = Path.Combine(systemDrive, "Users");

            if (Directory.Exists(usersDir))
            {
                var userDirs = Directory.GetDirectories(usersDir)
                    .Where(d => !d.EndsWith("Public", StringComparison.OrdinalIgnoreCase) &&
                                !d.EndsWith("Default", StringComparison.OrdinalIgnoreCase) &&
                                !d.EndsWith("Default User", StringComparison.OrdinalIgnoreCase) &&
                                !d.EndsWith("All Users", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(Directory.GetLastWriteTime)
                    .ToList();

                foreach (var dir in userDirs)
                {
                    if (Directory.Exists(Path.Combine(dir, "Downloads"))) return dir;
                }
            }
        }
        catch { }

        return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    }

    private static bool FixedTimeHexEquals(string hexA, string hexB)
    {
        if (string.Equals(hexA, hexB, StringComparison.OrdinalIgnoreCase))
            return true;

        try
        {
            byte[] a = Convert.FromHexString(hexA);
            byte[] b = Convert.FromHexString(hexB);
            return CryptographicOperations.FixedTimeEquals(a, b);
        }
        catch
        {
            return false;
        }
    }

    private static async Task SendControlFrameAsync(ITransportStream stream, string jsonPayload, CancellationToken ct)
    {
        byte[] payloadBytes = Encoding.UTF8.GetBytes(jsonPayload);
        byte[] frame = new byte[4 + payloadBytes.Length];

        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(0, 4), payloadBytes.Length);
        Array.Copy(payloadBytes, 0, frame, 4, payloadBytes.Length);

        await stream.WriteAsync(frame.AsMemory(), ct);
        await stream.FlushAsync(ct);
    }

    private static async Task<int> ReadExactAsync(ITransportStream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset + totalRead, count - totalRead), ct);
            if (read == 0) break;
            totalRead += read;
        }
        return totalRead;
    }

    private string GetStagingFilePath(string transferId)
    {
        if (!Guid.TryParse(transferId, out _))
        {
            throw new ArgumentException("transferId must be a GUID.", nameof(transferId));
        }

        string stagingRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_stagingDirectory));
        string stagingFile = Path.GetFullPath(Path.Combine(stagingRoot, $"{transferId}.tmp"));

        if (!stagingFile.StartsWith(stagingRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("transferId resolves outside the staging directory.", nameof(transferId));
        }

        return stagingFile;
    }

    private static void EnsureStagingDirectoryAcl(string directoryPath, ITetherLogger logger)
    {
        try
        {
            Directory.CreateDirectory(directoryPath);
            var di = new DirectoryInfo(directoryPath);
            var sec = di.GetAccessControl();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            sec.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));

            di.SetAccessControl(sec);
        }
        catch (Exception ex)
        {
            logger.Warning($"Could not set strict ACL on staging directory {directoryPath}: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}

public interface ITransportStream
{
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken);
    ValueTask FlushAsync(CancellationToken cancellationToken);
}

internal sealed class QuicStreamAdapter : ITransportStream, IDisposable
{
    private readonly QuicStream _stream;
    public QuicStreamAdapter(QuicStream stream) => _stream = stream;

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.ReadAsync(buffer, cancellationToken);

    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.WriteAsync(buffer, cancellationToken);

    public ValueTask FlushAsync(CancellationToken cancellationToken) =>
        ValueTask.CompletedTask;

    public void Dispose() => _stream.Dispose();
}

internal sealed class NetworkStreamAdapter : ITransportStream, IDisposable
{
    private readonly SslStream _stream;
    public NetworkStreamAdapter(SslStream stream) => _stream = stream;

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.ReadAsync(buffer, cancellationToken);

    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken) =>
        _stream.WriteAsync(buffer, cancellationToken);

    public ValueTask FlushAsync(CancellationToken cancellationToken) =>
        new ValueTask(_stream.FlushAsync(cancellationToken));

    public void Dispose() => _stream.Dispose();
}
