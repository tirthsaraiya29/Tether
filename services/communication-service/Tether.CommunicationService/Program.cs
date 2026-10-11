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
    // Windows services start with CWD = C:\Windows\System32. Fix the content root
    // so appsettings.json and any relative paths resolve next to the EXE.
    builder.UseContentRoot(AppContext.BaseDirectory);

    // Configure the Windows Event Log directly. We deliberately do NOT call
    // UseWindowsService() because it installs the WindowsServiceLifetime, whose
    // ServiceBase overrides for OnPowerEvent/OnSessionChange/OnShutdown are
    // no-ops and would shadow ours. TetherWindowsService drives the lifecycle.
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

        // Input relay to the interactive-session SessionHelper.
        services.AddSingleton<InputForwarder>();
        services.AddHostedService(sp => sp.GetRequiredService<InputForwarder>());

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
    // ServiceBase.Run blocks. It drives the SCM handshake and dispatches
    // SERVICE_CONTROL_* callbacks into TetherWindowsService.
    ServiceBase.Run(new TetherWindowsService(host));
}
else
{
    // Console / F5 debugging path — same host, unchanged behavior.
    await host.RunAsync();
}