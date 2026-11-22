using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Tether.EventBus;
using Tether.LinuxDaemon.Capabilities;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Devices;
using Tether.LinuxDaemon.Discovery;
using Tether.LinuxDaemon.FileTransfer;
using Tether.LinuxDaemon.Input;
using Tether.LinuxDaemon.Pairing;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Security;
using Tether.LinuxDaemon.Sessions;
using Tether.LinuxDaemon.Terminal;
using Tether.LinuxDaemon.Transport;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Logging;
using Tether.Shared.Network;

namespace Tether.LinuxDaemon;

public sealed class DaemonWorker : BackgroundService
{
    private const string ServerCapabilities = "FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED,INPUT,WINDOWS_ADMIN,APP_MANAGEMENT";

    private readonly ITetherLogger _logger;
    private readonly IEventBus _eventBus;

    public DaemonWorker(ITetherLogger logger, IEventBus eventBus)
    {
        _logger = logger;
        _eventBus = eventBus;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.Info("DaemonWorker: Initializing Tether Linux Daemon core subsystems...");

        var config = LinuxDaemonConfig.Load();
        var sessionInfo = PlatformDetection.GetActiveSessionInfo();
        _logger.Info($"DaemonWorker: Running on {PlatformDetection.GetDistributionName()} ({sessionInfo.DisplayServer}).");

        using var identity = new LinuxIdentity(_logger, config);
        var trustStore = new LinuxTrustStore(_logger, config);
        var deviceManager = new LinuxDeviceManager(_logger, trustStore);
        var pairingManager = new LinuxPairingManager(_eventBus, _logger, identity, deviceManager, trustStore);
        var sessionManager = new LinuxSessionManager(_logger);
        var tokenStore = new LinuxTokenStore();

        using var inputInjector = new LinuxUinputInjector(_logger);
        using var terminalManager = new LinuxTerminalManager(_logger);
        var adminManager = new LinuxAdminManager(_logger);
        using var pamServer = new LinuxPamAuthServer(_logger, config);

        var router = new LinuxPacketRouter(
            sessionManager,
            tokenStore,
            inputInjector,
            terminalManager,
            adminManager,
            pamServer,
            _logger);

        using var tcpServer = new LinuxTcpServer(
            _eventBus,
            _logger,
            identity,
            config,
            deviceManager,
            sessionManager,
            pairingManager,
            trustStore,
            (rawFrame, sess, ct) => router.RouteFrameAsync(rawFrame, sess, ct));

        using var udpDiscovery = new LinuxUdpDiscovery(
            _logger,
            identity);

        using var mdns = new LinuxMdnsAdvertiser(_logger);

        var fileTransferServer = new LinuxFileTransferServer(
            _logger,
            identity,
            config,
            tokenStore);

        try
        {
            pamServer.Start();
            await fileTransferServer.StartAsync(stoppingToken);
            tcpServer.Start();
            udpDiscovery.Start();
            mdns.Start(config.ControlPort, identity.DeviceId, identity.DeviceName, ServerCapabilities, pqc: false, ftPort: config.FileTransferPort);

            _logger.Info("DaemonWorker: All network and IPC services started successfully.");

            int loopCount = 0;
            LaptopStateFrame? lastState = null;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(3000, stoppingToken);
                    loopCount++;

                    if (sessionManager.GetAllSessions().Count > 0)
                    {
                        var currentState = LinuxLaptopStateCollector.GetLaptopState(_logger);

                        bool shouldBroadcast = lastState == null ||
                                               loopCount % 5 == 0 ||
                                               lastState.BatteryPercent != currentState.BatteryPercent ||
                                               lastState.IsCharging != currentState.IsCharging ||
                                               lastState.LockState != currentState.LockState ||
                                               lastState.VolumeLevel != currentState.VolumeLevel ||
                                               lastState.IsMuted != currentState.IsMuted ||
                                               lastState.BrightnessLevel != currentState.BrightnessLevel;

                        if (shouldBroadcast)
                        {
                            lastState = currentState;
                            await sessionManager.BroadcastJsonAsync(currentState, stoppingToken);
                        }
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Warning($"DaemonWorker telemetry broadcast error: {ex.Message}");
                }
            }
        }
        finally
        {
            _logger.Info("DaemonWorker: Stopping all network services...");
            try { mdns.Stop(); } catch { }
            try { udpDiscovery.Stop(); } catch { }
            try { tcpServer.Stop(); } catch { }
            try { await fileTransferServer.StopAsync(CancellationToken.None); } catch { }
            try { pamServer.Stop(); } catch { }
            _logger.Info("DaemonWorker: Graceful shutdown complete.");
        }
    }
}
