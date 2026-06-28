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
            var host = Host.CreateDefaultBuilder(args)
                .UseWindowsService(options =>
                {
                    options.ServiceName = "TetherCommService";
                })
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddSingleton<ITetherLogger, SerilogTetherLogger>();
                    services.AddSingleton<IEventBus>(sp =>
                    {
                        var logger = sp.GetRequiredService<ITetherLogger>();
                        return new InMemoryEventBus(logger);
                    });

                    services.AddSingleton<TrustStateManager>();
                    services.AddSingleton<EnforcementManager>();
                    services.AddSingleton<PanicManager>();
                    services.AddSingleton<RecoveryManager>();
                    services.AddSingleton<BleManager>();
                    services.AddSingleton<PipeServer>();

                    services.AddHostedService<Worker>();
                })
                .Build();

            // DO NOT PUT CUSTOM INITIALIZATION HERE.
            // RunAsync() must be hit immediately to avoid Error 1053.
            await host.RunAsync();
        }
    }
}