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
    private const string PfxPassword = "tether-identity-pass";

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
        var locationsToTry = new[]
        {
            IsAdministrator() ? StoreLocation.LocalMachine : StoreLocation.CurrentUser,
            IsAdministrator() ? StoreLocation.CurrentUser : StoreLocation.LocalMachine
        }.Distinct();

        foreach (var storeLocation in locationsToTry)
        {
            X509KeyStorageFlags keyFlags = storeLocation == StoreLocation.LocalMachine
                ? X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable;

            try
            {
                using var store = new X509Store(StoreName, storeLocation);
                store.Open(OpenFlags.ReadWrite);

                var existing = store.Certificates
                    .Find(X509FindType.FindBySubjectDistinguishedName, SubjectDn, validOnly: false)
                    .OfType<X509Certificate2>()
                    .FirstOrDefault(c => string.Equals(c.FriendlyName, FriendlyName, StringComparison.Ordinal) ||
                                         string.Equals(c.Subject, SubjectDn, StringComparison.OrdinalIgnoreCase));

                if (existing is { HasPrivateKey: true } && existing.NotAfter > DateTime.UtcNow.AddDays(30))
                {
                    if (CanSignWithPrivateKey(existing))
                    {
                        return existing;
                    }

                    _logger.Warning("Existing cert private key signing test failed. Removing stale cert.");
                }

                if (existing != null)
                {
                    try { store.Remove(existing); }
                    catch (Exception ex) { _logger.Warning($"Could not remove stale identity cert: {ex.Message}"); }
                }

                _logger.Warning($"Generating new Tether identity certificate (ECDSA P-256, self-signed, 10y, Store={storeLocation}).");

                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var req = new CertificateRequest(new X500DistinguishedName(SubjectDn), ecdsa, HashAlgorithmName.SHA256);

                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature, false));
                req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid(ServerAuthOid) }, false));
                req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
                var notAfter = DateTimeOffset.UtcNow.AddYears(10);

                using var ephemeral = req.CreateSelfSigned(notBefore, notAfter);
                var pfx = ephemeral.Export(X509ContentType.Pfx, PfxPassword);

#pragma warning disable SYSLIB0057
                var persisted = new X509Certificate2(pfx, PfxPassword, keyFlags);
#pragma warning restore SYSLIB0057

                try { persisted.FriendlyName = FriendlyName; } catch { }
                try { store.Add(persisted); } catch { }

                if (CanSignWithPrivateKey(persisted))
                {
                    return persisted;
                }
            }
            catch (Exception ex)
            {
                _logger.Warning($"Could not load/create identity cert in store location {storeLocation}: {ex.Message}");
            }
        }

        _logger.Error("Failed loading/creating identity cert in certificate stores. Creating ephemeral identity cert.");

        using var fallbackRsa = RSA.Create(2048);
        var fallbackReq = new CertificateRequest(new X500DistinguishedName(SubjectDn), fallbackRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        fallbackReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        fallbackReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        fallbackReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ServerAuthOid) }, false));
        fallbackReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(fallbackReq.PublicKey, false));

        using var selfSigned = fallbackReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        byte[] ephemeralPfx = selfSigned.Export(X509ContentType.Pfx, PfxPassword);

#pragma warning disable SYSLIB0057
        return new X509Certificate2(ephemeralPfx, PfxPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
#pragma warning restore SYSLIB0057
    }

    private static bool CanSignWithPrivateKey(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPrivateKey();
            if (rsa != null)
            {
                byte[] testData = new byte[] { 1, 2, 3, 4, 5 };
                byte[] sig = rsa.SignData(testData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return sig != null && sig.Length > 0;
            }

            using var ec = cert.GetECDsaPrivateKey();
            if (ec != null)
            {
                byte[] testData = new byte[] { 1, 2, 3, 4, 5 };
                byte[] sig = ec.SignData(testData, HashAlgorithmName.SHA256);
                return sig != null && sig.Length > 0;
            }
        }
        catch { }

        return false;
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
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
