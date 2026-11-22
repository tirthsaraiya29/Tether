using System;
using System.Security.Cryptography.X509Certificates;

namespace Tether.Shared.Security;

public interface IHostIdentity
{
    X509Certificate2 Certificate { get; }
    string Fingerprint { get; }
    string DeviceId { get; }
    string DeviceName { get; }
    byte[] GetPublicKeySpkiDer();
    string GetPublicKeySpkiBase64();
}
