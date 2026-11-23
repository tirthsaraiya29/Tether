using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tether.LinuxDaemon.Config;
using Tether.Shared.Logging;
using Tether.Shared.Security;

namespace Tether.LinuxDaemon.Security;

public sealed class LinuxIdentity : IHostIdentity, IDisposable
{
    private const string SubjectDn = "CN=Tether Linux Identity";
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    private readonly ITetherLogger _logger;
    private readonly LinuxDaemonConfig _config;
    private readonly X509Certificate2 _certificate;
    private readonly byte[] _spkiDer;
    private readonly string _fingerprint;

    public LinuxIdentity(ITetherLogger logger, LinuxDaemonConfig config)
    {
        _logger = logger;
        _config = config;
        _certificate = LoadOrCreate();
        _spkiDer = ExportSpki(_certificate);
        _fingerprint = ComputeFingerprint(_spkiDer);
        _logger.Info($"Tether Linux identity ready. Fingerprint={_fingerprint}");
    }

    public X509Certificate2 Certificate => _certificate;
    public string Fingerprint => _fingerprint;
    public string DeviceId => _fingerprint;
    public string DeviceName => Environment.MachineName;
    public byte[] GetPublicKeySpkiDer() => _spkiDer;
    public string GetPublicKeySpkiBase64() => Convert.ToBase64String(_spkiDer);

    private X509Certificate2 LoadOrCreate()
    {
        _config.EnsureDirectories();
        string certPath = Path.Combine(_config.DataDir, "identity.pfx");
        string keyFile = Path.Combine(_config.DataDir, "identity.key");

        if (File.Exists(certPath))
        {
            try
            {
                string pwd = File.Exists(keyFile) ? File.ReadAllText(keyFile).Trim() : "";
                var cert = X509CertificateLoader.LoadPkcs12FromFile(certPath, pwd, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                if (cert.HasPrivateKey && cert.NotAfter > DateTime.UtcNow.AddDays(30) && CanSign(cert))
                {
                    _logger.Info($"Loaded existing identity certificate from {certPath}");
                    return cert;
                }
            }
            catch (Exception ex)
            {
                _logger.Error($"LinuxIdentity: Existing identity certificate at {certPath} failed to load: {ex.Message}. Refusing to silently overwrite pre-existing identity certificate.");
                throw new InvalidOperationException($"Identity certificate at {certPath} is unreadable or corrupted. Automatic regeneration disabled to prevent invalidating paired mobile devices.", ex);
            }
        }

        _logger.Info($"Generating new Tether Linux identity certificate (ECDSA P-256, self-signed, 10y) at {certPath}...");
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(new X500DistinguishedName(SubjectDn), ecdsa, HashAlgorithmName.SHA256);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(ServerAuthOid) }, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(Environment.MachineName);
        try { sanBuilder.AddDnsName($"{Environment.MachineName.ToLowerInvariant()}.local"); } catch { }
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                    {
                        if (!IPAddress.IsLoopback(ip.Address))
                        {
                            sanBuilder.AddIpAddress(ip.Address);
                        }
                    }
                }
            }
        }
        catch { }

        req.CertificateExtensions.Add(sanBuilder.Build());

        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddYears(10);

        var generatedCert = req.CreateSelfSigned(notBefore, notAfter);
        byte[] rawPassword = RandomNumberGenerator.GetBytes(32);
        string certPassword = Convert.ToBase64String(rawPassword);

        byte[] pfxBytes = generatedCert.Export(X509ContentType.Pfx, certPassword);

        string tmpCert = certPath + ".tmp";
        string tmpKey = keyFile + ".tmp";

        File.WriteAllBytes(tmpCert, pfxBytes);
        File.WriteAllText(tmpKey, certPassword);

        if (OperatingSystem.IsLinux())
        {
            try
            {
                File.SetUnixFileMode(tmpCert, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.SetUnixFileMode(tmpKey, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch { }
        }

        File.Move(tmpCert, certPath, overwrite: true);
        File.Move(tmpKey, keyFile, overwrite: true);

        return X509CertificateLoader.LoadPkcs12FromFile(certPath, certPassword, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
    }

    private static bool CanSign(X509Certificate2 cert)
    {
        try
        {
            using var ecdsa = cert.GetECDsaPrivateKey();
            if (ecdsa == null) return false;
            byte[] test = "tether-sign-check"u8.ToArray();
            byte[] sig = ecdsa.SignData(test, HashAlgorithmName.SHA256);
            using var pub = cert.GetECDsaPublicKey();
            return pub != null && pub.VerifyData(test, sig, HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }

    private static byte[] ExportSpki(X509Certificate2 cert)
    {
        using var ecdsa = cert.GetECDsaPublicKey()
            ?? throw new InvalidOperationException("Certificate does not possess an ECDSA public key.");
        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    private static string ComputeFingerprint(byte[] spkiDer)
    {
        byte[] hash = SHA256.HashData(spkiDer);
        return string.Join(":", hash.Select(b => b.ToString("X2")));
    }

    public void Dispose()
    {
        _certificate.Dispose();
    }
}
