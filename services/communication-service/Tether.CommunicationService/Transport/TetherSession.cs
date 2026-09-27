// services/communication-service/Tether.CommunicationService/Transport/TetherSession.cs
using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Trust;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Transport;

public sealed class TetherSession : IDisposable
{
    private const string ProtocolVersion = "1.0";
    private const string ServerCaps = "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED";

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly TrustStore _trust;
    private readonly PairingCoordinator _pairing;
    private readonly int _handshakeTimeoutSeconds;

    private SslStream? _tls;
    private TrustedPhone? _trustedPhone;
    private bool _isAuthenticated;

    public TetherSession(IEventBus eventBus, ITetherLogger logger,
                         WindowsIdentity identity, TrustStore trust, PairingCoordinator pairing,
                         int handshakeTimeoutSeconds)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _trust = trust;
        _pairing = pairing;
        _handshakeTimeoutSeconds = handshakeTimeoutSeconds;
    }

    public async Task RunAsync(TcpClient client, CancellationToken serviceCt)
    {
        var remote = (client.Client.RemoteEndPoint as System.Net.IPEndPoint)?.Address?.ToString() ?? "unknown";
        _logger.Info($"TCP connection from {remote}.");

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(_handshakeTimeoutSeconds));

        try
        {
            // ---- TLS 1.3 (server side, no client cert) ----
            var networkStream = client.GetStream();
            _tls = new SslStream(networkStream, leaveInnerStreamOpen: false);

            var sslOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = _identity.Certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            };

            await _tls.AuthenticateAsServerAsync(sslOptions, handshakeCts.Token);
            _logger.Info($"TLS established with {remote} ({_tls.SslProtocol}, {_tls.NegotiatedCipherSuite}).");

            // ---- Tether handshake ----
            await HandleHandshakeAsync(handshakeCts.Token);

            if (!_isAuthenticated || _trustedPhone is null)
            {
                _logger.Warning($"Session with {remote} closed without authentication.");
                return;
            }

            // ---- Post-handshake command loop ----
            await CommandLoopAsync(serviceCt);
        }
        catch (OperationCanceledException) { _logger.Info($"Session with {remote} timed out."); }
        catch (AuthenticationException ex) { _logger.Warning($"TLS failure from {remote}: {ex.Message}"); }
        catch (Exception ex) { _logger.Warning($"Session failure from {remote}: {ex.Message}"); }
        finally
        {
            if (_isAuthenticated)
            {
                _eventBus.Publish(new TetherEvent
                {
                    EventType = TetherEventType.PHONE_DISCONNECTED,
                    Source = nameof(TetherSession)
                });
            }
        }
    }

    private async Task HandleHandshakeAsync(CancellationToken ct)
    {
        var stream = _tls!;

        using var initDoc = await FrameCodec.ReadJsonFrameAsync(stream, ct);
        if (initDoc is null)
        {
            _logger.Warning("No HANDSHAKE_INIT received.");
            return;
        }

        HandshakeInit? init;
        try
        {
            init = JsonSerializer.Deserialize<HandshakeInit>(initDoc.RootElement.GetRawText());
        }
        catch (JsonException ex)
        {
            _logger.Warning($"Malformed HANDSHAKE_INIT: {ex.Message}");
            return;
        }

        if (init is null ||
            !string.Equals(init.Type, "HANDSHAKE_INIT", StringComparison.Ordinal) ||
            string.IsNullOrEmpty(init.PublicKey))
        {
            _logger.Warning("Rejected HANDSHAKE_INIT (bad type or missing publicKey).");
            return;
        }

        if (!string.Equals(init.Version, ProtocolVersion, StringComparison.Ordinal))
        {
            _logger.Warning($"Rejected HANDSHAKE_INIT: unsupported protocol version '{init.Version}'.");
            return;
        }

        // Validate the phone SPKI before trusting it in any way.
        var phoneFingerprint = TrustStore.ComputeFingerprintOrNull(init.PublicKey);
        if (phoneFingerprint is null)
        {
            _logger.Warning("Rejected HANDSHAKE_INIT: phone publicKey is not valid base64.");
            return;
        }

        // ---- Decide trust status ----
        string status;

        var known = _trust.FindBySpkiBase64(init.PublicKey);
        if (known is not null)
        {
            _trustedPhone = known;
            _trust.Touch(known.Fingerprint);
            status = HandshakeStatus.Paired;
            _logger.Info($"Recognized paired phone {phoneFingerprint}; status=PAIRED.");
        }
        else if (init.IsPairingRequested)
        {
            // First-time (or re-pair) — route through DesktopUI.
            var allowed = await RequestPairingDecisionAsync(init, phoneFingerprint, ct);
            if (!allowed)
            {
                status = HandshakeStatus.PairingDenied;
                _logger.Warning($"Pairing denied for {phoneFingerprint}.");
            }
            else
            {
                var caps = SplitCaps(init.Capabilities);
                _trustedPhone = _trust.AddOrUpdate(
                    deviceId: phoneFingerprint,
                    displayName: init.DeviceName,
                    spkiBase64: init.PublicKey,
                    capabilities: caps,
                    protocolVersion: init.Version);
                status = HandshakeStatus.PairingAccepted;
                _logger.Info($"Pairing accepted; phone {phoneFingerprint} pinned.");
            }
        }
        else
        {
            // Unknown phone that did not ask to pair. Fail closed.
            status = HandshakeStatus.PairingDenied;
            _logger.Warning($"Unknown phone {phoneFingerprint} presented no pairing request. Denying.");
        }

        // ---- Send HANDSHAKE_RESPONSE ----
        var resp = new HandshakeResponse
        {
            DeviceId = _identity.DeviceId,
            DeviceName = _identity.DeviceName,
            PublicKey = _identity.GetPublicKeySpkiBase64(),
            Status = status,
            Capabilities = ServerCaps,
            Pqc = false, // see report: no PQC negotiated at TLS layer
        };
        await FrameCodec.WriteJsonFrameAsync(stream, resp, ct);

        if (status != HandshakeStatus.Paired && status != HandshakeStatus.PairingAccepted)
        {
            _logger.Info($"Handshake completed with status={status}; closing session.");
            return;
        }

        _isAuthenticated = true;
        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.PHONE_CONNECTED,
            Source = nameof(TetherSession)
        });

        // Re-establish trust signal: phone is authenticated.
        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.TRUST_RESTORED,
            Source = nameof(TetherSession)
        });
    }

    private async Task<bool> RequestPairingDecisionAsync(HandshakeInit init, string phoneFingerprint, CancellationToken ct)
    {
        // Note: the pairing decision is correlated by RequestId + phone SPKI.
        // DesktopUI cannot self-authorize: it only supplies an "Allowed" bit,
        // and PairingCoordinator verifies the presented key against the pending
        // registration via FixedTimeEquals.
        byte[] phoneSpki;
        try { phoneSpki = Convert.FromBase64String(init.PublicKey); }
        catch { return false; }

        var pending = _pairing.Register(phoneSpki);
        try
        {
            _eventBus.Publish(new TetherEvent
            {
                EventType = TetherEventType.PAIRING_REQUESTED,
                Source = nameof(TetherSession),
                PayloadJson = JsonSerializer.Serialize(new
                {
                    requestId = pending.RequestId,
                    phonePublicKeyBase64 = init.PublicKey,
                    fingerprint = pending.Fingerprint,
                    displayName = init.DeviceName,
                    timestampUtcTicks = DateTime.UtcNow.Ticks
                })
            });

            var delay = Task.Delay(TimeSpan.FromSeconds(30), ct);
            var done = await Task.WhenAny(pending.Decision.Task, delay);
            if (done != pending.Decision.Task)
            {
                _logger.Warning($"Pairing request {pending.RequestId} timed out. Failing closed.");
                pending.Decision.TrySetResult(false);
            }
            return await pending.Decision.Task;
        }
        finally
        {
            _pairing.Remove(pending.RequestId);
        }
    }

    private async Task CommandLoopAsync(CancellationToken ct)
    {
        var stream = _tls!;
        while (!ct.IsCancellationRequested)
        {
            using var doc = await FrameCodec.ReadJsonFrameAsync(stream, ct);
            if (doc is null) break;

            string type;
            try { type = doc.RootElement.GetProperty("type").GetString() ?? ""; }
            catch { continue; }

            switch (type)
            {
                case "COMMAND_EXECUTE":
                    await HandleCommandAsync(doc, ct);
                    break;
                default:
                    _logger.Debug($"Ignoring inbound frame type '{type}'.");
                    break;
            }
        }
    }

    private async Task HandleCommandAsync(JsonDocument doc, CancellationToken ct)
    {
        CommandExecute? cmd;
        try { cmd = JsonSerializer.Deserialize<CommandExecute>(doc.RootElement.GetRawText()); }
        catch { return; }
        if (cmd is null || string.IsNullOrEmpty(cmd.Command)) return;

        // Capability enforcement is authoritative on Windows.
        var requiredCap = MapCommandToCapability(cmd.Command);
        if (requiredCap is null)
        {
            _logger.Warning($"Rejected unknown command: {cmd.Command}");
            return;
        }

        if (!HasCapability(_trustedPhone!, requiredCap))
        {
            _logger.Warning($"Capability denied for command '{cmd.Command}' (requires {requiredCap}).");
            return;
        }

        _logger.Info($"Command accepted: {cmd.Command} (requestId={cmd.RequestId}).");

        // Send CONFIRM_COMMAND back to the phone (Android expects this).
        await FrameCodec.WriteJsonFrameAsync(_tls!, new ConfirmCommand { ConfirmedCommand = cmd.Command }, ct);

        // Phase 12 (this change) implements acknowledgement; command *execution*
        // is deliberately stubbed. Wiring execution to the EnforcementEngine must
        // remain gated on the same capability check performed above.
    }

    private static string? MapCommandToCapability(string command) => command switch
    {
        "shutdown" or "reboot" or "sleep" or "halt" => "POWER_ELEVATED",
        "lock_now" or "panic" or "unlock" or "auth_ok"
            or "reset_pending" or "screen_unlock" => "MEDIA", // control primitives
        "volume_up" or "volume_down"
            or "brightness_up" or "brightness_down" => "MEDIA",
        "PING" => "MEDIA",
        "cmd" or "powershell" or "powershell7"
            or "wsl" or "bash" => "TERMINAL",
        _ => null
    };

    private static bool HasCapability(TrustedPhone phone, string capability) =>
        phone.Capabilities.Contains(capability, StringComparer.OrdinalIgnoreCase);

    private static List<string> SplitCaps(string csv) =>
        string.IsNullOrWhiteSpace(csv)
            ? new List<string>()
            : new List<string>(csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    public void Dispose()
    {
        try { _tls?.Dispose(); } catch { }
        _tls = null;
    }
}