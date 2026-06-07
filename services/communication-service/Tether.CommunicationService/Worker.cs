using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting; // FIXED: Added missing hosting extension definitions
using Microsoft.Extensions.Logging; // FIXED: Added missing tracking log subsystem components
using Tether.EventBus;
using Tether.Shared.Logging;

namespace Tether.CommunicationService
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly ITetherLogger _tetherLogger;
        private readonly IEventBus _eventBus;

        public Worker(ILogger<Worker> logger, ITetherLogger tetherLogger, IEventBus eventBus)
        {
            _logger = logger;
            _tetherLogger = tetherLogger;
            _eventBus = eventBus;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _tetherLogger.Info("Tether Communication Service started successfully");
            _logger.LogInformation("Tether Communication Service running at: {time}", DateTimeOffset.Now);

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
            await base.StopAsync(cancellationToken);
        }
    }
}