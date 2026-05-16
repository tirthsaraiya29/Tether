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

            // Register engine managers (renamed classes)
            builder.Services.AddSingleton<TrustStateManager>();
            builder.Services.AddSingleton<EnforcementManager>();
            builder.Services.AddSingleton<PanicManager>();
            builder.Services.AddSingleton<RecoveryManager>();
            builder.Services.AddSingleton<BleManager>();
            builder.Services.AddSingleton<PipeServer>();
            builder.Services.AddHostedService<Worker>();

            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "Tether Communication Service";
            });

            var host = builder.Build();

            // Force initialization (they subscribe in constructor)
            _ = host.Services.GetRequiredService<TrustStateManager>();
            _ = host.Services.GetRequiredService<EnforcementManager>();
            _ = host.Services.GetRequiredService<PanicManager>();
            _ = host.Services.GetRequiredService<RecoveryManager>();

            // Start IPC server
            var pipeServer = host.Services.GetRequiredService<PipeServer>();
            pipeServer.Start();

            // Start BLE manager
            var bleManager = host.Services.GetRequiredService<BleManager>();
            bleManager.Start();

            var logger = host.Services.GetRequiredService<ITetherLogger>();
            logger.Info("All services initialized. Starting host...");

            await host.RunAsync();
        }
    }
}