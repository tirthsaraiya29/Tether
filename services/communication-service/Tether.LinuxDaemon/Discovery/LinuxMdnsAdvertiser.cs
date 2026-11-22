using System;
using Makaretu.Dns;
using Tether.Shared.Logging;
using Tether.Shared.Network;

namespace Tether.LinuxDaemon.Discovery;

public sealed class LinuxMdnsAdvertiser : IDisposable
{
    public const string ServiceBaseName = "tether";
    public const string InstanceName = "TetherLinux";

    private readonly ITetherLogger _logger;
    private ServiceDiscovery? _discovery;
    private ServiceProfile? _profile;

    public LinuxMdnsAdvertiser(ITetherLogger logger) => _logger = logger;

    public void Start(int port, string id, string name, string caps, bool pqc, int? ftPort = null)
    {
        try
        {
            Stop();

            _discovery = new ServiceDiscovery();
            _profile = new ServiceProfile(InstanceName, ServiceBaseName, (ushort)port);
            _profile.AddProperty("v", "2.0");
            _profile.AddProperty("id", id);
            _profile.AddProperty("name", name);
            _profile.AddProperty("caps", caps);
            _profile.AddProperty("pqc", pqc ? "true" : "false");
            _profile.AddProperty("os", "linux");
            if (ftPort.HasValue)
            {
                _profile.AddProperty("ft_port", ftPort.Value.ToString());
            }

            _discovery.Advertise(_profile);
            _logger.Info($"Linux mDNS advertised: {InstanceName}._{ServiceBaseName}._tcp.local on port {port} (id={id}, os=linux).");
        }
        catch (Exception ex)
        {
            _logger.Error($"Linux mDNS advertisement failed: {ex.Message}");
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
                    try { _discovery.Unadvertise(_profile); } catch { }
                }
                _discovery.Dispose();
            }
        }
        catch { }
        finally
        {
            _discovery = null;
            _profile = null;
        }
    }

    public void Dispose() => Stop();
}
