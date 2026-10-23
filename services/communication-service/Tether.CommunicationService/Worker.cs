using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Discovery;
using Tether.CommunicationService.Ipc;
using Tether.CommunicationService.Power;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Transport;
using Tether.EnforcementEngine;
using Tether.EventBus;
using Tether.FileTransfer;
using Tether.FileTransfer.Protocol;
using Tether.FileTransfer.Receiver;
using Tether.PanicEngine;
using Tether.RecoveryEngine;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Tether.TrustEngine;

namespace Tether.CommunicationService;

public sealed class Worker : BackgroundService
{
    private const string AdvertisedCaps = "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED";

    private readonly ILogger<Worker> _logger;
    private readonly ITetherLogger _tetherLogger;
    private readonly PipeServer _pipeServer;
    private readonly TetherTcpServer _tcpServer;
    private readonly MdnsAdvertiser _mdns;
    private readonly UdpDiscovery _udpDiscovery;
    private readonly WindowsIdentity _identity;
    private readonly SessionManager _sessionManager;
    private readonly PowerEventWatcher _powerWatcher;
    private readonly PowerEventNotifier _powerNotifier;
    private readonly FileTransferManager _fileTransferManager;

    public Worker(
        ILogger<Worker> logger,
        ITetherLogger tetherLogger,
        PipeServer pipeServer,
        TetherTcpServer tcpServer,
        MdnsAdvertiser mdns,
        UdpDiscovery udpDiscovery,
        WindowsIdentity identity,
        SessionManager sessionManager,
        PowerEventWatcher powerWatcher,
        PowerEventNotifier powerNotifier,
        FileTransferManager fileTransferManager,
        TrustStateManager trustStateManager,
        EnforcementManager enforcementManager,
        PanicManager panicManager,
        RecoveryManager recoveryManager,
        IpcEventRelay ipcEventRelay,
        IEventBus eventBus)
    {
        _logger = logger;
        _tetherLogger = tetherLogger;
        _pipeServer = pipeServer;
        _tcpServer = tcpServer;
        _mdns = mdns;
        _udpDiscovery = udpDiscovery;
        _identity = identity;
        _sessionManager = sessionManager;
        _powerWatcher = powerWatcher;
        _powerNotifier = powerNotifier;
        _fileTransferManager = fileTransferManager;
        _ = trustStateManager; _ = enforcementManager; _ = panicManager; _ = recoveryManager; _ = ipcEventRelay;

        eventBus.Subscribe(evt =>
        {
            if (evt.EventType == TetherEventType.TELEMETRY_SYNC_REQUESTED)
            {
                if (_sessionManager.ActiveSessionCount > 0)
                {
                    var firstDevice = _sessionManager.GetActiveSessions().FirstOrDefault()?.Device;
                    if (firstDevice != null)
                    {
                        eventBus.Publish(new TetherEvent
                        {
                            EventType = TetherEventType.PHONE_CONNECTED,
                            Source = "WorkerSync",
                            PayloadJson = System.Text.Json.JsonSerializer.Serialize(new
                            {
                                deviceId = firstDevice.DeviceId,
                                displayName = firstDevice.DisplayName,
                                fingerprint = firstDevice.Fingerprint
                            })
                        });
                    }
                }
            }
            else if (evt.EventType == TetherEventType.FILE_TRANSFER_CANCEL_REQUESTED && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(evt.PayloadJson);
                    if (doc.RootElement.TryGetProperty("transferId", out var idElem))
                    {
                        string transferId = idElem.GetString() ?? "";
                        if (!string.IsNullOrEmpty(transferId))
                        {
                            _fileTransferManager.CancelTransfer(transferId);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _tetherLogger.Warning($"Failed handling FILE_TRANSFER_CANCEL_REQUESTED: {ex.Message}");
                }
            }
            else if (evt.EventType == TetherEventType.FILE_TRANSFER_ENQUEUE_REQUESTED && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(evt.PayloadJson);
                    string targetDeviceId = doc.RootElement.TryGetProperty("targetDeviceId", out var devElem) ? devElem.GetString() ?? "" : "";
                    if (string.IsNullOrEmpty(targetDeviceId))
                    {
                        targetDeviceId = _sessionManager.GetActiveSessions().FirstOrDefault()?.Device?.DeviceId ?? "TARGET_PHONE";
                    }

                    if (doc.RootElement.TryGetProperty("paths", out var pathsElem) && pathsElem.ValueKind == System.Text.Json.JsonValueKind.Array)
                    {
                        foreach (var pathNode in pathsElem.EnumerateArray())
                        {
                            string path = pathNode.GetString() ?? "";
                            if (!string.IsNullOrWhiteSpace(path))
                            {
                                if (path.StartsWith("/") || path.StartsWith("\\"))
                                {
                                    string? activeIp = _sessionManager.GetActiveSessions().FirstOrDefault()?.IpAddress ?? _udpDiscovery.LastDiscoveryIp;
                                    if (!string.IsNullOrEmpty(activeIp))
                                    {
                                        _ = Task.Run(async () =>
                                        {
                                            try
                                            {
                                                using var client = new System.Net.Sockets.TcpClient();
                                                await client.ConnectAsync(activeIp, FileTransferReceiver.DefaultPort);
                                                using var sslStream = new System.Net.Security.SslStream(client.GetStream(), false, (s, c, ch, err) => true);
                                                await sslStream.AuthenticateAsClientAsync(activeIp);

                                                var init = new ControlInitFrame { DeviceId = _identity.DeviceId };
                                                byte[] initBytes = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(init));
                                                byte[] lenBuf = new byte[4];
                                                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lenBuf, initBytes.Length);
                                                await sslStream.WriteAsync(lenBuf);
                                                await sslStream.WriteAsync(initBytes);
                                                await sslStream.FlushAsync();

                                                byte[] ackLenBuf = new byte[4];
                                                await sslStream.ReadExactlyAsync(ackLenBuf, 0, 4);
                                                int ackLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(ackLenBuf);
                                                byte[] ackBuf = new byte[ackLen];
                                                await sslStream.ReadExactlyAsync(ackBuf, 0, ackLen);

                                                var req = new FileDownloadRequestFrame { FilePath = path };
                                                byte[] reqBytes = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(req));
                                                System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(lenBuf, reqBytes.Length);
                                                await sslStream.WriteAsync(lenBuf);
                                                await sslStream.WriteAsync(reqBytes);
                                                await sslStream.FlushAsync();

                                                _tetherLogger.Info($"Sent FILE_DOWNLOAD_REQUEST for '{path}' to phone {activeIp}");
                                            }
                                            catch (Exception ex)
                                            {
                                                _tetherLogger.Warning($"Failed sending FILE_DOWNLOAD_REQUEST for '{path}': {ex.Message}");
                                            }
                                        });
                                    }
                                }
                                else
                                {
                                    _fileTransferManager.DurableQueue.EnqueueOutgoing(path, targetDeviceId);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _tetherLogger.Warning($"Failed handling FILE_TRANSFER_ENQUEUE_REQUESTED: {ex.Message}");
                }
            }
            else if (evt.EventType == TetherEventType.FS_DB_SYNC_REQUESTED)
            {
                try
                {
                    string? activeIp = _sessionManager.GetActiveSessions().FirstOrDefault()?.IpAddress ?? _udpDiscovery.LastDiscoveryIp;
                    if (!string.IsNullOrEmpty(activeIp))
                    {
                        _ = _fileTransferManager.RequestPhoneDbSyncAsync(activeIp);
                    }
                    else
                    {
                        _tetherLogger.Warning("FS_DB_SYNC_REQUESTED received but no phone IP address is known yet.");
                    }
                }
                catch (Exception ex)
                {
                    _tetherLogger.Warning($"Failed handling FS_DB_SYNC_REQUESTED: {ex.Message}");
                }
            }
            else if (evt.EventType == TetherEventType.HARDWARE_SYNC_REQUESTED && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(evt.PayloadJson);
                    var root = doc.RootElement;
                    int vol = root.TryGetProperty("vol", out var vProp) ? vProp.GetInt32() : -1;
                    int bri = root.TryGetProperty("bri", out var bProp) ? bProp.GetInt32() : -1;

                    if (vol >= 0)
                    {
                        HardwareExecutor.ExecuteCommand($"volume_set:{vol}", _tetherLogger, out _);
                        if (_sessionManager.ActiveSessionCount > 0)
                        {
                            _sessionManager.BroadcastRawFrame(System.Text.Json.JsonSerializer.Serialize(new
                            {
                                type = "COMMAND_EXECUTE",
                                command = $"volume_set:{vol}",
                                requestId = Guid.NewGuid().ToString()
                            }));
                        }
                    }
                    if (bri >= 0)
                    {
                        HardwareExecutor.ExecuteCommand($"brightness_set:{bri}", _tetherLogger, out _);
                        if (_sessionManager.ActiveSessionCount > 0)
                        {
                            _sessionManager.BroadcastRawFrame(System.Text.Json.JsonSerializer.Serialize(new
                            {
                                type = "COMMAND_EXECUTE",
                                command = $"brightness_set:{bri}",
                                requestId = Guid.NewGuid().ToString()
                            }));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _tetherLogger.Warning($"Failed handling HARDWARE_SYNC_REQUESTED: {ex.Message}");
                }
            }
        });
    }

    private bool _hasSyncedFsOnConnect = false;

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _tetherLogger.Info("Tether Communication Service starting (mDNS + UDP Broadcast + TLS 1.3 transport + QUIC File Transfer).");
        _logger.LogInformation("Tether Communication Service running at {Time}", DateTimeOffset.Now);

        PowerEventHub.Watcher = _powerWatcher;

        EnsureFirewallRulesExist();

        _pipeServer.Start();
        _tcpServer.Start();
        _udpDiscovery.Start();
        _fileTransferManager.Start();

        _mdns.Start(
            port: TetherTcpServer.ListenPort,
            id: _identity.DeviceId,
            name: _identity.DeviceName,
            caps: AdvertisedCaps,
            pqc: false);

        _tetherLogger.Info($"Transport up. DeviceId={_identity.DeviceId}");

        _powerWatcher.Start();
        _tetherLogger.Info("PowerEventWatcher: started (WMI + SystemEvents corroborators).");

        LaptopStateCollector.Initialize(_sessionManager, _tetherLogger);

        _ = Task.Run(async () =>
        {
            var lastIsCharging = false;
            var lastBattery = -1;
            var lastLock = "";

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(3000, stoppingToken);

                    string? activeIp = _sessionManager.GetActiveSessions().FirstOrDefault()?.IpAddress ?? _udpDiscovery.LastDiscoveryIp;
                    if (!string.IsNullOrEmpty(activeIp))
                    {
                        await _fileTransferManager.ProcessOutgoingQueueAsync(activeIp, stoppingToken);

                        if (!_hasSyncedFsOnConnect)
                        {
                            _ = Task.Run(async () =>
                            {
                                try
                                {
                                    _tetherLogger.Info($"Auto-triggering background filesystem database sync with phone ({activeIp})...");
                                    var indexer = new WindowsFilesystemIndexer(_tetherLogger);
                                    string localDb = await indexer.BuildDatabaseAsync();
                                    var activeDev = _sessionManager.GetActiveSessions().FirstOrDefault()?.Device?.DeviceId ?? "TARGET_PHONE";
                                    _fileTransferManager.DurableQueue.EnqueueOutgoing(localDb, activeDev, "windows_fs.db");
                                    await _fileTransferManager.RequestPhoneDbSyncAsync(activeIp, stoppingToken);
                                    _hasSyncedFsOnConnect = true;
                                }
                                catch (Exception ex)
                                {
                                    _tetherLogger.Warning($"Auto-sync filesystem DB failed: {ex.Message}");
                                }
                            }, stoppingToken);
                        }
                    }

                    if (_sessionManager.ActiveSessionCount > 0)
                    {
                        var snap = LaptopStateCollector.GetLaptopSnapshot(_tetherLogger);
                        if (snap.IsCharging != lastIsCharging || snap.BatteryLevel != lastBattery || snap.LockState != lastLock)
                        {
                        lastIsCharging = snap.IsCharging;
                        lastBattery = snap.BatteryLevel;
                        lastLock = snap.LockState;
                        _sessionManager.BroadcastLaptopState(snap);
                    }

                    if (_powerWatcher.HasPending)
                    {
                        try
                        {
                            _powerNotifier.FlushToSession(
                                json => _sessionManager.BroadcastRawFrame(json));
                        }
                        catch (Exception ex)
                        {
                            _tetherLogger.Warning($"Worker: power-event flush failed: {ex.Message}");
                        }
                    }
                }
                else
                {
                    _hasSyncedFsOnConnect = false;
                }
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
        }, stoppingToken);

        return Task.Delay(Timeout.Infinite, stoppingToken).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    private static void EnsureFirewallRulesExist()
    {
        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
            if (!string.IsNullOrEmpty(exePath))
            {
                var psiDeleteBlock = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall delete rule name=all program=\"{exePath}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var p0 = Process.Start(psiDeleteBlock);
                p0?.WaitForExit(2000);

                var psiAllowExe = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall add rule name=\"Tether Service Exe\" dir=in action=allow program=\"{exePath}\" enable=yes profile=any",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var pExe = Process.Start(psiAllowExe);
                pExe?.WaitForExit(2000);
            }

            var psiTcp = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall firewall add rule name=\"Tether TCP 37123\" dir=in action=allow protocol=TCP localport=37123 profile=any",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p1 = Process.Start(psiTcp);
            p1?.WaitForExit(2000);

            var psiUdp = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall firewall add rule name=\"Tether UDP 37124\" dir=in action=allow protocol=UDP localport=37124 profile=any",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p2 = Process.Start(psiUdp);
            p2?.WaitForExit(2000);

            var psiQuicUdp = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall firewall add rule name=\"Tether QUIC UDP 37125\" dir=in action=allow protocol=UDP localport=37125 profile=any",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p3 = Process.Start(psiQuicUdp);
            p3?.WaitForExit(2000);

            var psiQuicTcp = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall firewall add rule name=\"Tether QUIC TCP 37125\" dir=in action=allow protocol=TCP localport=37125 profile=any",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p4 = Process.Start(psiQuicTcp);
            p4?.WaitForExit(2000);
        }
        catch { }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _tetherLogger.Info("Tether Communication Service is stopping.");

        try { _powerWatcher.Dispose(); } catch { }
        PowerEventHub.Watcher = null;

        _mdns.Stop();
        _udpDiscovery.Stop();
        _fileTransferManager.Stop();
        _tcpServer.Stop();
        _pipeServer.Dispose();
        await base.StopAsync(cancellationToken);
    }
}
