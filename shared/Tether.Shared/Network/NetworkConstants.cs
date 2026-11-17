namespace Tether.Shared.Network;

public static class NetworkConstants
{
    public const int ControlPort = 37123;
    public const int FileTransferPort = 37124;
    public const int DiscoveryPort = 37124;
    public const int MdnsPort = 5353;
    public const string MdnsServiceType = "_tether._tcp.";
    public const string DefaultLocalhostAddress = "127.0.0.1";
}
