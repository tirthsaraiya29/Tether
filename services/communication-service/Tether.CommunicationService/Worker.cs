using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Discovery;
using Tether.CommunicationService.Ipc;
using Tether.CommunicationService.Security;
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

    public Worker(
        ILogger<Worker> logger,
        ITetherLogger tetherLogger,
        PipeServer pipeServer,
        TetherTcpServer tcpServer,
        MdnsAdvertiser mdns,
        UdpDiscovery udpDiscovery,
        WindowsIdentity identity,
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
        _ = trustStateManager; _ = enforcementManager; _ = panicManager; _ = recoveryManager; _ = ipcEventRelay;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _tetherLogger.Info("Tether Communication Service starting (mDNS + UDP Broadcast + TLS 1.3 transport).");
        _logger.LogInformation("Tether Communication Service running at {Time}", DateTimeOffset.Now);

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
        _mdns.Stop();
        _udpDiscovery.Stop();
        _tcpServer.Stop();
        _pipeServer.Dispose();
        await base.StopAsync(cancellationToken);
    }
}
