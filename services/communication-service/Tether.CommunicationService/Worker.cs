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
        private readonly BleManager _bleManager;

        private readonly TrustStateManager _trustStateManager;
        private readonly EnforcementManager _enforcementManager;
        private readonly PanicManager _panicManager;
        private readonly RecoveryManager _recoveryManager;

        public Worker(
            ILogger<Worker> logger,
            ITetherLogger tetherLogger,
            IEventBus eventBus,
            PipeServer pipeServer,
            BleManager bleManager,
            TrustStateManager trustStateManager,
            EnforcementManager enforcementManager,
            PanicManager panicManager,
            RecoveryManager recoveryManager)
        {
            _logger = logger;
            _tetherLogger = tetherLogger;
            _eventBus = eventBus;
            _pipeServer = pipeServer;
            _bleManager = bleManager;

            _trustStateManager = trustStateManager;
            _enforcementManager = enforcementManager;
            _panicManager = panicManager;
            _recoveryManager = recoveryManager;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _tetherLogger.Info("Worker starting: Initializing background engines...");
            _logger.LogInformation("Tether Communication Service running at: {time}", DateTimeOffset.Now);

            _pipeServer.Start();

            _bleManager.InitializeIPCHandles();
            _bleManager.Start();

            _eventBus.Subscribe(evt => {
                if (evt.EventType == TetherEventType.PROVISION_PHONE && !string.IsNullOrEmpty(evt.PayloadJson))
                {
                    try
                    {
                        var payload = JsonSerializer.Deserialize<ProvisionPayload>(evt.PayloadJson);
                        if (payload != null && !string.IsNullOrEmpty(payload.PublicKeyBase64))
                        {
                            _bleManager.ProvisionPhone(payload.PublicKeyBase64);
                        }
                    }
                    catch (Exception ex)
                    {
                        _tetherLogger.Error($"Failed to process provisioning event in Worker: {ex.Message}");
                    }
                }
            });

            _tetherLogger.Info("All background engines, cross-session named pipes, and BLE stacks initialized successfully.");

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(30000, stoppingToken);
                _tetherLogger.Debug("Service heartbeat - alive and listening for BLE and IPC events");
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _tetherLogger.Info("Tether Communication Service is stopping");

            _pipeServer?.Dispose();
            _bleManager?.Stop();

            await base.StopAsync(cancellationToken);
        }
    }
}