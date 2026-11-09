using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Discovery;
using Tether.CommunicationService.Ipc;
using Tether.CommunicationService.Power;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Transport;
using Tether.CommunicationService.Trust;
using Tether.EnforcementEngine;
using Tether.EventBus;
using Tether.PanicEngine;
using Tether.RecoveryEngine;
using Tether.Shared.Events;
using Tether.Shared.Logging;
using Tether.TrustEngine;

namespace Tether.CommunicationService;

public sealed class Worker : BackgroundService
{
    private const string AdvertisedCaps = "CLIPBOARD,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED,WINDOWS_ADMIN,APP_MANAGEMENT,AUTOMATION";

    // Legacy rules to purge
    private const string RuleLegacyExe = "Tether Service Exe";
    private const string RuleLegacyTcp = "Tether TCP 37123";
    private const string RuleLegacyUdp = "Tether UDP 37124";
    private const string RuleLegacyQuicUdp = "Tether QUIC UDP 37125";
    private const string RuleLegacyQuicTcp = "Tether QUIC TCP 37125";

    // Active port rules
    private const string RuleControlTcp = "Tether Control (TCP-In 37123)";
    private const string RuleDiscoveryUdp = "Tether Discovery (UDP-In 37124)";
    private const string RuleMdnsUdp = "Tether mDNS (UDP-In 5353)";
    private const string RuleFileTransferTcp = "Tether File Transfer (TCP-In 37124)";

    private readonly ILogger<Worker> _logger;
    private readonly ITetherLogger _tetherLogger;
    private readonly PipeServer _pipeServer;
    private readonly TetherTcpServer _tcpServer;
    private readonly MdnsAdvertiser _mdns;
    private readonly UdpDiscovery _udpDiscovery;
    private readonly WindowsIdentity _identity;
    private readonly SessionManager _sessionManager;
    private readonly PowerEventWatcher _powerWatcher;
    private readonly PowerEventNotifier _powerNotifier;
    private readonly TrustStore _trustStore;

    public Worker(
        ILogger<Worker> logger,
        ITetherLogger tetherLogger,
        PipeServer pipeServer,
        TetherTcpServer tcpServer,
        MdnsAdvertiser mdns,
        UdpDiscovery udpDiscovery,
        WindowsIdentity identity,
        SessionManager sessionManager,
        PowerEventWatcher powerWatcher,
        PowerEventNotifier powerNotifier,
        TrustStateManager trustStateManager,
        EnforcementManager enforcementManager,
        PanicManager panicManager,
        RecoveryManager recoveryManager,
        IpcEventRelay ipcEventRelay,
        IEventBus eventBus,
        TrustStore trustStore)
    {
        _logger = logger;
        _tetherLogger = tetherLogger;
        _pipeServer = pipeServer;
        _tcpServer = tcpServer;
        _mdns = mdns;
        _udpDiscovery = udpDiscovery;
        _identity = identity;
        _sessionManager = sessionManager;
        _powerWatcher = powerWatcher;
        _powerNotifier = powerNotifier;
        _trustStore = trustStore;
        _ = trustStateManager; _ = enforcementManager; _ = panicManager; _ = recoveryManager; _ = ipcEventRelay;

        eventBus.Subscribe(evt =>
        {
            if (evt.EventType == TetherEventType.TELEMETRY_SYNC_REQUESTED)
            {
                PublishPairedDevicesList(eventBus);
                if (_sessionManager.ActiveSessionCount > 0)
                {
                    var firstDevice = _sessionManager.GetActiveSessions().FirstOrDefault()?.Device;
                    if (firstDevice != null)
                    {
                        eventBus.Publish(new TetherEvent
                        {
                            EventType = TetherEventType.PHONE_CONNECTED,
                            Source = "WorkerSync",
                            PayloadJson = System.Text.Json.JsonSerializer.Serialize(new
                            {
                                deviceId = firstDevice.DeviceId,
                                displayName = firstDevice.DisplayName,
                                fingerprint = firstDevice.Fingerprint
                            })
                        });
                    }
                }
            }
            else if (evt.EventType == TetherEventType.HARDWARE_SYNC_REQUESTED && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(evt.PayloadJson);
                    var root = doc.RootElement;
                    int vol = root.TryGetProperty("vol", out var vProp) ? vProp.GetInt32() : -1;
                    int bri = root.TryGetProperty("bri", out var bProp) ? bProp.GetInt32() : -1;

                    if (vol >= 0)
                    {
                        HardwareExecutor.ExecuteCommand($"volume_set:{vol}", _tetherLogger, out _);
                        if (_sessionManager.ActiveSessionCount > 0)
                        {
                            _sessionManager.BroadcastRawFrame(System.Text.Json.JsonSerializer.Serialize(new
                            {
                                type = "COMMAND_EXECUTE",
                                command = $"volume_set:{vol}",
                                requestId = Guid.NewGuid().ToString()
                            }));
                        }
                    }
                    if (bri >= 0)
                    {
                        HardwareExecutor.ExecuteCommand($"brightness_set:{bri}", _tetherLogger, out _);
                        if (_sessionManager.ActiveSessionCount > 0)
                        {
                            _sessionManager.BroadcastRawFrame(System.Text.Json.JsonSerializer.Serialize(new
                            {
                                type = "COMMAND_EXECUTE",
                                command = $"brightness_set:{bri}",
                                requestId = Guid.NewGuid().ToString()
                            }));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _tetherLogger.Warning($"Failed handling HARDWARE_SYNC_REQUESTED: {ex.Message}");
                }
            }
            else if (evt.EventType == TetherEventType.FORGET_PHONE && !string.IsNullOrEmpty(evt.PayloadJson))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(evt.PayloadJson);
                    var root = doc.RootElement;
                    string? fingerprint = root.TryGetProperty("fingerprint", out var fpProp) ? fpProp.GetString() : null;
                    if (!string.IsNullOrEmpty(fingerprint))
                    {
                        _trustStore.Remove(fingerprint);
                        _sessionManager.DisconnectDevice(fingerprint, "Unpaired by user");
                        _tetherLogger.Info($"Device with fingerprint {fingerprint} was removed from TrustStore and disconnected.");
                        PublishPairedDevicesList(eventBus);
                    }
                }
                catch (Exception ex)
                {
                    _tetherLogger.Warning($"Failed handling FORGET_PHONE: {ex.Message}");
                }
            }
        });
    }

    private void PublishPairedDevicesList(IEventBus eventBus)
    {
        try
        {
            var trusted = _trustStore.All().Select(p => new
            {
                deviceId = p.DeviceId,
                displayName = p.DisplayName,
                fingerprint = p.Fingerprint,
                lastSeen = p.LastSeenUtc
            }).ToList();

            eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PROVISION_PHONE,
                Source = "TrustStore",
                PayloadJson = System.Text.Json.JsonSerializer.Serialize(trusted)
            });
        }
        catch (Exception ex)
        {
            _tetherLogger.Warning($"Failed publishing paired devices list: {ex.Message}");
        }
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _tetherLogger.Info("Tether Communication Service starting (mDNS + UDP Broadcast + TLS 1.3 transport).");
        _logger.LogInformation("Tether Communication Service running at {Time}", DateTimeOffset.Now);

        PowerEventHub.Watcher = _powerWatcher;

        EnsureFirewallRulesExist();

        _pipeServer.Start();
        _tcpServer.Start();
        _udpDiscovery.Start();

        _mdns.Start(
            port: TetherTcpServer.ListenPort,
            id: _identity.DeviceId,
            name: _identity.DeviceName,
            caps: AdvertisedCaps,
            pqc: false,
            ftPort: 37124);

        _tetherLogger.Info($"Transport up. DeviceId={_identity.DeviceId}");

        _powerWatcher.Start();
        _powerWatcher.PowerEventOccurred += evt =>
        {
            try
            {
                if (_sessionManager.ActiveSessionCount > 0)
                {
                    _powerNotifier.FlushToSession(json => _sessionManager.BroadcastRawFrame(json));
                }
            }
            catch (Exception ex)
            {
                _tetherLogger.Warning($"Worker: immediate power-event flush failed: {ex.Message}");
            }
        };
        _tetherLogger.Info("PowerEventWatcher: started (WMI + SystemEvents corroborators).");

        LaptopStateCollector.Initialize(_sessionManager, _tetherLogger);

        InitializeUnlockEvents();

        _ = Task.Run(async () =>
        {
            var lastIsCharging = false;
            var lastBattery = -1;
            var lastLock = "";

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(3000, stoppingToken);

                    if (_sessionManager.ActiveSessionCount > 0)
                    {
                        var snap = LaptopStateCollector.GetLaptopSnapshot(_tetherLogger);
                        if (snap.IsCharging != lastIsCharging || snap.BatteryLevel != lastBattery || snap.LockState != lastLock)
                        {
                            lastIsCharging = snap.IsCharging;
                            lastBattery = snap.BatteryLevel;
                            lastLock = snap.LockState;
                            _sessionManager.BroadcastLaptopState(snap);
                        }

                        if (_powerWatcher.HasPending)
                        {
                            try
                            {
                                _powerNotifier.FlushToSession(
                                    json => _sessionManager.BroadcastRawFrame(json));
                            }
                            catch (Exception ex)
                            {
                                _tetherLogger.Warning($"Worker: power-event flush failed: {ex.Message}");
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }, stoppingToken);

        return Task.Delay(Timeout.Infinite, stoppingToken).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    private EventWaitHandle? _unlockPromptEvent;
    private RegisteredWaitHandle? _unlockPromptWait;
    private EventWaitHandle? _appUnlockedEvent;

    /// <summary>
    /// Relays unlock-prompt requests from the credential provider (LogonUI secure desktop)
    /// to the paired phone as UNLOCK_PROMPT frames over the TLS control channel.
    /// The CP signals Global\TetherUnlockPromptRequested; we broadcast once per signal.
    /// </summary>
    private void InitializeUnlockEvents()
    {
        try
        {
            var sec = new System.Security.AccessControl.EventWaitHandleSecurity();
            sec.SetSecurityDescriptorSddlForm("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
            _appUnlockedEvent = EventWaitHandleAcl.Create(
                false, EventResetMode.ManualReset, @"Global\TetherPhoneAppUnlocked", out bool createdNewUnlocked, sec);
            if (!createdNewUnlocked)
            {
                var ac = _appUnlockedEvent.GetAccessControl();
                var owner = ac.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)) as System.Security.Principal.SecurityIdentifier;
                if (owner == null || (!owner.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid) && !owner.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid)))
                {
                    _tetherLogger.Warning($"Worker: Untrusted owner '{owner?.Value}' on unlock event. Discarding.");
                    _appUnlockedEvent.Dispose();
                    _appUnlockedEvent = null;
                }
            }
        }
        catch (Exception ex)
        {
            _tetherLogger.Error($"Worker: could not create Global\\TetherPhoneAppUnlocked: {ex.Message}");
        }

        StartUnlockPromptRelay();
    }
    private void StartUnlockPromptRelay()
    {
        try
        {
            var sec = new System.Security.AccessControl.EventWaitHandleSecurity();
            sec.SetSecurityDescriptorSddlForm("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
            // ManualReset: the CP can't safely Set+Reset from the secure desktop
            // (lost-signal race), so we consume the signal here.
            _unlockPromptEvent = EventWaitHandleAcl.Create(
                false, EventResetMode.ManualReset, @"Global\TetherUnlockPromptRequested", out bool createdNewPrompt, sec);
            if (!createdNewPrompt)
            {
                var ac = _unlockPromptEvent.GetAccessControl();
                var owner = ac.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)) as System.Security.Principal.SecurityIdentifier;
                if (owner == null || (!owner.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid) && !owner.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid)))
                {
                    _tetherLogger.Warning($"UnlockPromptRelay: Untrusted owner '{owner?.Value}' on request event. Relay aborted.");
                    _unlockPromptEvent.Dispose();
                    _unlockPromptEvent = null;
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            _tetherLogger.Error($"UnlockPromptRelay: could not create request event: {ex.Message}");
            return;
        }

        _unlockPromptWait = ThreadPool.RegisterWaitForSingleObject(
            _unlockPromptEvent,
            (state, timedOut) =>
            {
                if (timedOut) return;
                try
                {
                    // Consume the signal first so a rapid re-request isn't lost
                    // behind this callback's own broadcast work.
                    _unlockPromptEvent?.Reset();

                    if (_sessionManager.ActiveSessionCount == 0)
                    {
                        _tetherLogger.Info("UnlockPromptRelay: phone not connected; prompt request dropped.");
                        return;
                    }
                    _sessionManager.BroadcastRawFrame(System.Text.Json.JsonSerializer.Serialize(new
                    {
                        type = "UNLOCK_PROMPT",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    }));
                    _tetherLogger.Info("UnlockPromptRelay: UNLOCK_PROMPT frame broadcast to phone.");
                }
                catch (Exception ex)
                {
                    _tetherLogger.Warning($"UnlockPromptRelay: broadcast failed: {ex.Message}");
                }
            },
            null,
            Timeout.Infinite,
            executeOnlyOnce: false);
    }

    private void EnsureFirewallRulesExist()
    {
        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
            if (string.IsNullOrEmpty(exePath))
            {
                _tetherLogger.Warning("Firewall: Service executable path could not be resolved. Skipping firewall rule configuration.");
                return;
            }

            // 1. Purge legacy wide-open rules
            DeleteFirewallRule(RuleLegacyExe);
            DeleteFirewallRule(RuleLegacyQuicUdp);
            DeleteFirewallRule(RuleLegacyQuicTcp);
            DeleteFirewallRule(RuleLegacyTcp);
            DeleteFirewallRule(RuleLegacyUdp);

            // 2. Add port-specific rules scoped to executable and Private/Domain profiles
            // Port 37123 TCP: Primary TLS Control Channel
            AddPortRule(RuleControlTcp, "TCP", 37123, exePath);

            // Port 37124 UDP: Local Broadcast Discovery
            AddPortRule(RuleDiscoveryUdp, "UDP", 37124, exePath);

            // Port 5353 UDP: Multicast DNS (mDNS for Android NsdManager)
            AddPortRule(RuleMdnsUdp, "UDP", 5353, exePath);

            // Port 37124 TCP: HTTPS File Transfer API
            AddPortRule(RuleFileTransferTcp, "TCP", 37124, exePath);

            _tetherLogger.Info("Firewall rules synchronized: Scoped strictly to TCP 37123, UDP 37124, UDP 5353, TCP 37124 on Private/Domain profiles.");
        }
        catch (Exception ex)
        {
            _tetherLogger.Error($"Firewall configuration error: {ex.Message}", ex);
        }
    }

    private void AddPortRule(string ruleName, string protocol, int port, string exePath)
    {
        DeleteFirewallRule(ruleName);
        string arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=allow protocol={protocol} localport={port} program=\"{exePath}\" profile=private,domain enable=yes";
        RunNetshCommand(arguments, isDelete: false);
    }

    private void DeleteFirewallRule(string ruleName)
    {
        string arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"";
        RunNetshCommand(arguments, isDelete: true);
    }

    private void RunNetshCommand(string arguments, bool isDelete)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi);
            if (process == null) return;

            process.WaitForExit(3000);

            if (process.ExitCode != 0 && !isDelete)
            {
                string error = process.StandardError.ReadToEnd().Trim();
                _tetherLogger.Warning($"netsh returned exit code ({process.ExitCode}) executing '{arguments}': {error}");
            }
        }
        catch (Exception ex)
        {
            _tetherLogger.Warning($"Failed executing netsh command '{arguments}': {ex.Message}");
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _tetherLogger.Info("Tether Communication Service is stopping.");

        try { _powerWatcher.Dispose(); } catch { }
        PowerEventHub.Watcher = null;

        try
        {
            _unlockPromptWait?.Unregister(null);
            _unlockPromptEvent?.Dispose();
            _appUnlockedEvent?.Dispose();
        }
        catch { }

        _mdns.Stop();
        _udpDiscovery.Stop();
        _tcpServer.Stop();
        _pipeServer.Dispose();
        await base.StopAsync(cancellationToken);
    }
}
