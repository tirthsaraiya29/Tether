using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using System;
using System.ServiceProcess;
using Tether.CommunicationService;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Discovery;
using Tether.CommunicationService.Ipc;
using Tether.CommunicationService.Pairing;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Transport;
using Tether.CommunicationService.Trust;
using Tether.CommunicationService.Power;
using Tether.EnforcementEngine;
using Tether.EventBus;
using Tether.PanicEngine;
using Tether.RecoveryEngine;
using Tether.Shared.Logging;
using Tether.TrustEngine;

var builder = Host.CreateDefaultBuilder(args);

bool runningAsService = WindowsServiceHelpers.IsWindowsService();

if (runningAsService)
{
    builder.UseContentRoot(AppContext.BaseDirectory);

    builder.ConfigureLogging(logging =>
    {
        logging.AddEventLog(settings =>
        {
            settings.SourceName = "TetherCommService";
        });
    });
}

var host = builder
    .ConfigureServices((ctx, services) =>
    {
        services.AddSingleton<ITetherLogger, SerilogTetherLogger>();
        services.AddSingleton<IEventBus>(sp =>
            new InMemoryEventBus(sp.GetRequiredService<ITetherLogger>()));

        services.AddSingleton<WindowsIdentity>();
        services.AddSingleton<TrustStore>();
        services.AddSingleton<DeviceManager>();
        services.AddSingleton<SessionManager>();
        services.AddSingleton<PairingManager>();
        services.AddSingleton<CapabilityManager>();
        services.AddSingleton<PacketRouter>();
        services.AddSingleton<MdnsAdvertiser>();
        services.AddSingleton<UdpDiscovery>();
        services.AddSingleton<TetherTcpServer>();
        services.AddSingleton<PowerEventWatcher>();
        services.AddSingleton<PowerEventNotifier>();

        services.AddSingleton<InputForwarder>();
        services.AddHostedService(sp => sp.GetRequiredService<InputForwarder>());

        services.AddHostedService<SessionHelperDaemon>();

        services.AddSingleton<TrustStateManager>();
        services.AddSingleton<EnforcementManager>();
        services.AddSingleton<PanicManager>();
        services.AddSingleton<RecoveryManager>();

        services.AddSingleton<PipeServer>();
        services.AddSingleton<IpcEventRelay>();
        services.AddHostedService<Worker>();
    })
    .Build();

if (runningAsService)
{
    ServiceBase.Run(new TetherWindowsService(host));
}
else
{
    await host.RunAsync();
}