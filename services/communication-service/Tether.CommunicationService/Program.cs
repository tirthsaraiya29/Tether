using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tether.CommunicationService;
using Tether.EnforcementEngine;
using Tether.EventBus;
using Tether.PanicEngine;
using Tether.RecoveryEngine;
using Tether.Shared.Logging;
using Tether.TrustEngine;

namespace Tether.CommunicationService
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = Host.CreateApplicationBuilder(args);

            builder.Services.AddSingleton<ITetherLogger, SerilogTetherLogger>();
            builder.Services.AddSingleton<IEventBus>(sp =>
            {
                var logger = sp.GetRequiredService<ITetherLogger>();
                return new InMemoryEventBus(logger);
            });

            builder.Services.AddSingleton<TrustStateManager>();
            builder.Services.AddSingleton<EnforcementManager>();
            builder.Services.AddSingleton<PanicManager>();
            builder.Services.AddSingleton<RecoveryManager>();
            builder.Services.AddSingleton<BleManager>();
            builder.Services.AddSingleton<PipeServer>();

            builder.Services.AddHostedService<Worker>();

            var host = builder.Build();

            // Force initialization of background engines
            _ = host.Services.GetRequiredService<TrustStateManager>();
            _ = host.Services.GetRequiredService<EnforcementManager>();
            _ = host.Services.GetRequiredService<PanicManager>();
            _ = host.Services.GetRequiredService<RecoveryManager>();

            // Start the IPC pipe server for UI communication
            var pipeServer = host.Services.GetRequiredService<PipeServer>();
            pipeServer.Start();

            // Initialize and start BLE manager
            var bleManager = host.Services.GetRequiredService<BleManager>();
            bleManager.InitializeIPCHandles();
            bleManager.Start();

            var logger = host.Services.GetRequiredService<ITetherLogger>();
            logger.Info("All background engines, cross-session named pipes, and BLE stacks initialized. Launching host environment...");

            await host.RunAsync();
        }
    }
}