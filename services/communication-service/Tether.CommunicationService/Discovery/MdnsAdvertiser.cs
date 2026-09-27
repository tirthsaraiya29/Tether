// services/communication-service/Tether.CommunicationService/Discovery/MdnsAdvertiser.cs
using System;
using Makaretu.Dns;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Discovery;

/// <summary>
/// Advertises this Windows endpoint on _tether._tcp.local.
/// TXT records: v, id, name, caps, pqc. All values are non-secret.
/// </summary>
public sealed class MdnsAdvertiser : IDisposable
{
    public const string ServiceBaseName = "tether";       // → _tether._tcp.local
    public const string InstanceName = "TetherWindows";

    private readonly ITetherLogger _logger;
    private ServiceDiscovery? _discovery;
    private ServiceProfile? _profile;

    public MdnsAdvertiser(ITetherLogger logger) => _logger = logger;

    public void Start(int port, string id, string name, string caps, bool pqc)
    {
        try
        {
            Stop();

            _discovery = new ServiceDiscovery();
            _profile = new ServiceProfile(InstanceName, ServiceBaseName, (ushort)port);
            _profile.AddProperty("v", "1.0");
            _profile.AddProperty("id", id);
            _profile.AddProperty("name", name);
            _profile.AddProperty("caps", caps);
            _profile.AddProperty("pqc", pqc ? "true" : "false");

            _discovery.Advertise(_profile);
            _logger.Info($"mDNS advertised: {InstanceName}._tether._tcp.local on port {port} (id={id}, pqc={pqc}).");
        }
        catch (Exception ex)
        {
            _logger.Error($"mDNS advertisement failed: {ex.Message}");
        }
    }

    public void Stop()
    {
        try
        {
            if (_discovery != null)
            {
                if (_profile != null)
                {
                    try { _discovery.Unadvertise(_profile); } catch { /* best effort */ }
                }
                _discovery.Dispose();
            }
        }
        catch { /* best effort */ }
        finally
        {
            _discovery = null;
            _profile = null;
        }
    }

    public void Dispose() => Stop();
}