using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Tether.EventBus;
using Tether.Shared.Logging;
using Tether.TrustEngine;
using Tether.EnforcementEngine;
using Tether.PanicEngine;
using Tether.RecoveryEngine;

namespace Tether.CommunicationService
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly ITetherLogger _tetherLogger;
        private readonly IEventBus _eventBus;
        private readonly PipeServer _pipeServer;
        private readonly BleManager _bleManager;

        // By injecting the state managers here, the DI container forces them to initialize
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

            // Start the IPC pipe server for UI communication
            _pipeServer.Start();

            // Initialize and start BLE manager
            _bleManager.InitializeIPCHandles();
            _bleManager.Start();

            _tetherLogger.Info("All background engines, cross-session named pipes, and BLE stacks initialized successfully.");

            while (!stoppingToken.IsCancellationRequested)
            {
                // Keep service alive - heartbeat every 30 seconds
                await Task.Delay(30000, stoppingToken);
                _tetherLogger.Debug("Service heartbeat - alive and listening for BLE and IPC events");
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _tetherLogger.Info("Tether Communication Service is stopping");

            // Clean up resources gracefully
            _pipeServer?.Dispose();
            _bleManager?.Stop();

            await base.StopAsync(cancellationToken);
        }
    }
}