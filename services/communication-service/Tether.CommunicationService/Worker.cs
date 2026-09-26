using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.EnforcementEngine;
using Tether.EventBus;
using Tether.PanicEngine;
using Tether.RecoveryEngine;
using Tether.Shared.DTO;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Tether.TrustEngine;

namespace Tether.CommunicationService
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly ITetherLogger _tetherLogger;
        private readonly IEventBus _eventBus;
        private readonly PipeServer _pipeServer;
        private readonly LanTransportServer _lanServer;   // ← was BleManager

        private readonly TrustStateManager _trustStateManager;
        private readonly EnforcementManager _enforcementManager;
        private readonly PanicManager _panicManager;
        private readonly RecoveryManager _recoveryManager;

        public Worker(
            ILogger<Worker> logger,
            ITetherLogger tetherLogger,
            IEventBus eventBus,
            PipeServer pipeServer,
            LanTransportServer lanServer,
            TrustStateManager trustStateManager,
            EnforcementManager enforcementManager,
            PanicManager panicManager,
            RecoveryManager recoveryManager)
        {
            _logger = logger;
            _tetherLogger = tetherLogger;
            _eventBus = eventBus;
            _pipeServer = pipeServer;
            _lanServer = lanServer;
            _trustStateManager = trustStateManager;
            _enforcementManager = enforcementManager;
            _panicManager = panicManager;
            _recoveryManager = recoveryManager;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _tetherLogger.Info("Worker starting: Initializing background engines (Wi-Fi LAN transport).");
            _logger.LogInformation("Tether Communication Service running at: {time}", DateTimeOffset.Now);

            _pipeServer.Start();
            _lanServer.Start();   // ← listens on TCP/UDP 37123

            // Provisioning from the local UI pipe
            _eventBus.Subscribe(evt =>
            {
                if (evt.EventType == TetherEventType.PROVISION_PHONE && !string.IsNullOrEmpty(evt.PayloadJson))
                {
                    try
                    {
                        var payload = JsonSerializer.Deserialize<ProvisionPayload>(evt.PayloadJson);
                        if (payload != null && !string.IsNullOrEmpty(payload.PublicKeyBase64))
                            _lanServer.ProvisionPhone(payload.PublicKeyBase64);
                    }
                    catch (Exception ex)
                    {
                        _tetherLogger.Error($"Provisioning failed: {ex.Message}");
                    }
                }
            });

            _tetherLogger.Info("LAN transport and named pipe server initialized successfully.");

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(30000, stoppingToken);
                _tetherLogger.Debug("Service heartbeat - alive and listening for LAN and IPC events");
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _tetherLogger.Info("Tether Communication Service is stopping");
            _pipeServer?.Dispose();
            _lanServer?.Stop();
            await base.StopAsync(cancellationToken);
        }
    }
}