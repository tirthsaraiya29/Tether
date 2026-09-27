// services/communication-service/Tether.CommunicationService/Worker.cs
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Discovery;
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
    private readonly WindowsIdentity _identity;

    public Worker(
        ILogger<Worker> logger,
        ITetherLogger tetherLogger,
        PipeServer pipeServer,
        TetherTcpServer tcpServer,
        MdnsAdvertiser mdns,
        WindowsIdentity identity,
        TrustStateManager trustStateManager,
        EnforcementManager enforcementManager,
        PanicManager panicManager,
        RecoveryManager recoveryManager)
    {
        _logger = logger;
        _tetherLogger = tetherLogger;
        _pipeServer = pipeServer;
        _tcpServer = tcpServer;
        _mdns = mdns;
        _identity = identity;
        // Engine singletons are resolved so they initialize; not otherwise referenced here.
        _ = trustStateManager; _ = enforcementManager; _ = panicManager; _ = recoveryManager;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _tetherLogger.Info("Tether Communication Service starting (mDNS + TLS 1.3 transport).");
        _logger.LogInformation("Tether Communication Service running at {Time}", DateTimeOffset.Now);

        _pipeServer.Start();
        _tcpServer.Start();

        _mdns.Start(
            port: TetherTcpServer.ListenPort,
            id: _identity.DeviceId,
            name: _identity.DeviceName,
            caps: AdvertisedCaps,
            pqc: false);

        _tetherLogger.Info($"Transport up. DeviceId={_identity.DeviceId}");

        return Task.Delay(Timeout.Infinite, stoppingToken).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _tetherLogger.Info("Tether Communication Service is stopping.");
        _mdns.Stop();
        _tcpServer.Stop();
        _pipeServer.Dispose();
        await base.StopAsync(cancellationToken);
    }
}