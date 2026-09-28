using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Security;

public sealed class WindowsIdentity : IDisposable
{
    private const string SubjectDn = "CN=Tether Windows Identity";
    private const string FriendlyName = "Tether Windows Identity";
    private const string StoreName = "My";
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    private readonly ITetherLogger _logger;
    private readonly X509Certificate2 _certificate;
    private readonly byte[] _spkiDer;
    private readonly string _fingerprint;

    public WindowsIdentity(ITetherLogger logger)
    {
        _logger = logger;
        _certificate = LoadOrCreate();
        _spkiDer = ExportSpki(_certificate);
        _fingerprint = ComputeFingerprint(_spkiDer);
        _logger.Info($"Tether Windows identity ready. Fingerprint={_fingerprint}");
    }

    public X509Certificate2 Certificate => _certificate;
    public string Fingerprint => _fingerprint;
    public string DeviceId => _fingerprint;
    public string DeviceName => Environment.MachineName;
    public byte[] GetPublicKeySpkiDer() => _spkiDer;
    public string GetPublicKeySpkiBase64() => Convert.ToBase64String(_spkiDer);

    private X509Certificate2 LoadOrCreate()
    {
        using var store = new X509Store(StoreName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);

        var existing = store.Certificates
            .Find(X509FindType.FindBySubjectDistinguishedName, SubjectDn, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault(c =>
                string.Equals(c.FriendlyName, FriendlyName, StringComparison.Ordinal));

        if (existing is { HasPrivateKey: true } && existing.NotAfter > DateTime.UtcNow.AddDays(30))
            return existing;

        if (existing != null)
        {
            try { store.Remove(existing); }
            catch (Exception ex) { _logger.Warning($"Could not remove stale identity cert: {ex.Message}"); }
        }

        _logger.Info("Generating new Tether identity certificate (ECDSA P-256, self-signed, 10y).");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(new X500DistinguishedName(SubjectDn), ecdsa, HashAlgorithmName.SHA256);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(ServerAuthOid) }, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(10);

        using var ephemeral = req.CreateSelfSigned(notBefore, notAfter);

        var pfx = ephemeral.Export(X509ContentType.Pfx);
#pragma warning disable SYSLIB0057
        var persisted = new X509Certificate2(
            pfx,
            (string?)null,
            X509KeyStorageFlags.MachineKeySet |
            X509KeyStorageFlags.PersistKeySet |
            X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057

        persisted.FriendlyName = FriendlyName;
        store.Add(persisted);
        return persisted;
    }

    private static byte[] ExportSpki(X509Certificate2 cert)
    {
        using var ec = cert.GetECDsaPublicKey();
        if (ec is not null) return ec.ExportSubjectPublicKeyInfo();

        using var rsa = cert.GetRSAPublicKey();
        if (rsa is not null) return rsa.ExportSubjectPublicKeyInfo();

        throw new InvalidOperationException("Unsupported identity key type in server certificate.");
    }

    private static string ComputeFingerprint(byte[] spkiDer)
    {
        var hash = SHA256.HashData(spkiDer);
        return string.Join(":", hash.Select(b => b.ToString("X2")));
    }

    public void Dispose() => _certificate.Dispose();
}
