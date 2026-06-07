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

            // 1. Core Platform Shared Utilities Setup
            builder.Services.AddSingleton<ITetherLogger, SerilogTetherLogger>();
            builder.Services.AddSingleton<IEventBus>(sp =>
            {
                var logger = sp.GetRequiredService<ITetherLogger>();
                return new InMemoryEventBus(logger);
            });

            // 2. Core Engine Manager Architecture Registrations
            builder.Services.AddSingleton<TrustStateManager>();
            builder.Services.AddSingleton<EnforcementManager>();
            builder.Services.AddSingleton<PanicManager>();
            builder.Services.AddSingleton<RecoveryManager>();
            builder.Services.AddSingleton<BleManager>();
            builder.Services.AddSingleton<PipeServer>();
            builder.Services.AddHostedService<Worker>();

            // 3. Native Windows Service Lifecycle Configuration
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "Tether Communication Service";
            });

            var host = builder.Build();

            // 4. Force Instance Activation (Triggers Constructor Event Bus Subscriptions)
            _ = host.Services.GetRequiredService<TrustStateManager>();
            _ = host.Services.GetRequiredService<EnforcementManager>();
            _ = host.Services.GetRequiredService<PanicManager>();
            _ = host.Services.GetRequiredService<RecoveryManager>();

            // 5. Spin up Inter-Process Communication Pipe Layer
            var pipeServer = host.Services.GetRequiredService<PipeServer>();
            pipeServer.Start();

            // 6. Extract BleManager to run handle configuration AND boot up the BT stack
            var bleManager = host.Services.GetRequiredService<BleManager>();

            // Setup our low-integrity Session 0 global signaling handles 
            bleManager.InitializeIPCHandles();

            // FIXED: Restored your core Bluetooth discovery/OTA engine startup sequence!
            bleManager.Start();

            // 7. Fire Logging and Run Service Host Loop
            var logger = host.Services.GetRequiredService<ITetherLogger>();
            logger.Info("All background services, low-integrity handles, and BLE stacks initialized. Starting execution host...");

            await host.RunAsync();
        }
    }
}