using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
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
using Tether.PanicEngine;
using Tether.RecoveryEngine;
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
        TrustStateManager trustStateManager,
        EnforcementManager enforcementManager,
        PanicManager panicManager,
        RecoveryManager recoveryManager,
        IpcEventRelay ipcEventRelay)
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
        _ = trustStateManager; _ = enforcementManager; _ = panicManager; _ = recoveryManager; _ = ipcEventRelay;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _tetherLogger.Info("Tether Communication Service starting (mDNS + UDP Broadcast + TLS 1.3 transport).");
        _logger.LogInformation("Tether Communication Service running at {Time}", DateTimeOffset.Now);

        // Publish the watcher to the static hub before any long-running setup.
        // ServiceBase callbacks can fire at any time after host.Start() returns,
        // and HardwareExecutor reads PowerEventHub.Watcher on the hot path.
        PowerEventHub.Watcher = _powerWatcher;

        EnsureFirewallRulesExist();

        _pipeServer.Start();
        _tcpServer.Start();
        _udpDiscovery.Start();

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
        _tcpServer.Stop();
        _pipeServer.Dispose();
        await base.StopAsync(cancellationToken);
    }
}