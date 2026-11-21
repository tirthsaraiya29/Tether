using System;
using System.Security.Cryptography;
using System.Text;
using Tether.Shared.Security;
using Xunit;

namespace Tether.Tests;

public class AuthenticodeVerifierTests
{
    [Fact]
    public void CreatePinnedManifestPublicKey_DefaultPinnedKey_LoadsSuccessfully()
    {
        using var ecdsa = AuthenticodeVerifier.CreatePinnedManifestPublicKey();
        Assert.NotNull(ecdsa);

        // Verify key parameters
        var parameters = ecdsa.ExportParameters(false);
        Assert.NotNull(parameters.Q.X);
        Assert.NotNull(parameters.Q.Y);
        Assert.Equal(32, parameters.Q.X.Length);
        Assert.Equal(32, parameters.Q.Y.Length);
    }

    [Fact]
    public void VerifyManifestSignature_ValidDetachedSignature_ReturnsTrue()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"version\":\"1.2.1\",\"channel\":\"stable\"}");
        byte[] rawSig = ecdsa.SignData(manifestBytes, HashAlgorithmName.SHA256);

        // Raw bytes verification
        Assert.True(AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, rawSig, spki));

        // Base64 text-encoded verification
        byte[] b64Sig = Encoding.UTF8.GetBytes(Convert.ToBase64String(rawSig));
        Assert.True(AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, b64Sig, spki));

        // Hex text-encoded verification
        byte[] hexSig = Encoding.UTF8.GetBytes(Convert.ToHexString(rawSig));
        Assert.True(AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, hexSig, spki));
    }

    [Fact]
    public void VerifyManifestSignature_TamperedDataOrSignature_FailsClosed()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"version\":\"1.2.1\"}");
        byte[] rawSig = ecdsa.SignData(manifestBytes, HashAlgorithmName.SHA256);

        // Tampered payload
        byte[] tampered = Encoding.UTF8.GetBytes("{\"version\":\"1.2.2\"}");
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(tampered, rawSig, spki));

        // Tampered signature bytes
        byte[] corruptedSig = (byte[])rawSig.Clone();
        corruptedSig[0] ^= 0xFF;
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, corruptedSig, spki));

        // Empty/null inputs fail closed
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(Array.Empty<byte>(), rawSig, spki));
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, Array.Empty<byte>(), spki));
    }
}
