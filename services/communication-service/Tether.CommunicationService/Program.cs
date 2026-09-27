// services/communication-service/Tether.CommunicationService/Program.cs
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tether.CommunicationService;
using Tether.CommunicationService.Discovery;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Transport;
using Tether.CommunicationService.Trust;
using Tether.EnforcementEngine;
using Tether.EventBus;
using Tether.PanicEngine;
using Tether.RecoveryEngine;
using Tether.Shared.Logging;
using Tether.TrustEngine;

var host = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options => { options.ServiceName = "TetherCommService"; })
    .ConfigureServices((ctx, services) =>
    {
        services.AddSingleton<ITetherLogger, SerilogTetherLogger>();
        services.AddSingleton<IEventBus>(sp =>
            new InMemoryEventBus(sp.GetRequiredService<ITetherLogger>()));

        // --- Windows connection stack ---
        services.AddSingleton<WindowsIdentity>();
        services.AddSingleton<TrustStore>();
        services.AddSingleton<PairingCoordinator>();
        services.AddSingleton<MdnsAdvertiser>();
        services.AddSingleton<TetherTcpServer>();

        // --- Engines (untouched) ---
        services.AddSingleton<TrustStateManager>();
        services.AddSingleton<EnforcementManager>();
        services.AddSingleton<PanicManager>();
        services.AddSingleton<RecoveryManager>();

        // --- IPC + worker ---
        services.AddSingleton<PipeServer>();
        services.AddHostedService<Worker>();
    })
    .Build();

await host.RunAsync();