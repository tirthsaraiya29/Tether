using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Tether.CommunicationService;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Transport;
using Tether.Shared.Logging;
using Tether.Shared.Security;
using Xunit;

namespace Tether.Tests;

public class TETH_SEC_006_CryptoVaultAndGeneralHardeningTests
{
    private sealed class NoOpLogger : ITetherLogger
    {
        public void Debug(string message) { }
        public void Info(string message) { }
        public void Warning(string message) { }
        public void Error(string message, Exception? ex = null) { }
        public void Critical(string message, Exception? ex = null) { }
    }

    #region Requirement R3: Cryptographic Verification and Key Management Hardening

    [Fact]
    public void PinnedManifestPublicKey_Valid91ByteP256SpkiParameters()
    {
        // Assert that AuthenticodeVerifier.PinnedManifestPublicKey exists and is valid 91-byte DER SPKI
        string pinnedBase64 = AuthenticodeVerifier.PinnedManifestPublicKey;
        Assert.NotNull(pinnedBase64);
        Assert.NotEmpty(pinnedBase64);

        byte[] spkiDer = Convert.FromBase64String(pinnedBase64);
        Assert.Equal(91, spkiDer.Length);

        using var ecdsa = AuthenticodeVerifier.CreatePinnedManifestPublicKey();
        Assert.NotNull(ecdsa);
        Assert.Equal(256, ecdsa.KeySize);

        // P-256 SPKI header check: 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 (id-ecPublicKey) 06 08 2A 86 48 CE 3D 03 01 07 (secp256r1)
        byte[] expectedPrefix = new byte[] { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
        for (int i = 0; i < expectedPrefix.Length; i++)
        {
            Assert.Equal(expectedPrefix[i], spkiDer[i]);
        }
    }

    [Fact]
    public void VerifyManifestSignature_RejectsRawByteTampering()
    {
        // 1. Generate ephemeral P-256 key pair
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());

        // 2. Original valid manifest bytes
        string originalManifestJson = "{\"version\":\"2.0.0\",\"channel\":\"stable\",\"packages\":[{\"name\":\"Tether.Setup.exe\",\"sha512\":\"deadbeef\"}]}";
        byte[] manifestBytes = Encoding.UTF8.GetBytes(originalManifestJson);

        // 3. Detached signature of raw bytes
        byte[] signatureBytes = signer.SignData(manifestBytes, HashAlgorithmName.SHA256);

        // Verify valid manifest passes
        bool validResult = AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, signatureBytes, spkiBase64);
        Assert.True(validResult, "Valid manifest and signature must pass verification.");

        // 4. Adversarial tamper: flip 1 byte in manifest payload
        byte[] tamperedBytes = (byte[])manifestBytes.Clone();
        tamperedBytes[15] ^= 0xFF;

        bool tamperedResult = AuthenticodeVerifier.VerifyManifestSignature(tamperedBytes, signatureBytes, spkiBase64);
        Assert.False(tamperedResult, "Tampered manifest raw bytes must be rejected fail-closed.");
    }

    [Fact]
    public void VerifyManifestSignature_RejectsCorruptedDetachedSignature()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"version\":\"1.0.0\"}");
        byte[] signatureBytes = signer.SignData(manifestBytes, HashAlgorithmName.SHA256);

        // Corrupt signature bytes
        byte[] corruptedSig = (byte[])signatureBytes.Clone();
        corruptedSig[corruptedSig.Length - 1] ^= 0x55;
        corruptedSig[corruptedSig.Length / 2] ^= 0xAA;

        bool result = AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, corruptedSig, spkiBase64);
        Assert.False(result, "Corrupted detached signature must be rejected fail-closed.");
    }

    [Fact]
    public void VerifyManifestSignature_RejectsEmptySignatureOrManifest()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spkiBase64 = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());

        byte[] manifestBytes = Encoding.UTF8.GetBytes("{\"version\":\"1.0.0\"}");
        byte[] validSignature = signer.SignData(manifestBytes, HashAlgorithmName.SHA256);

        // Empty signature
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, Array.Empty<byte>(), spkiBase64), "Empty signature bytes must be rejected.");

        // Empty manifest
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(Array.Empty<byte>(), validSignature, spkiBase64), "Empty manifest bytes must be rejected.");

        // Null checks
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(null!, validSignature, spkiBase64), "Null manifest must be rejected.");
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(manifestBytes, null!, spkiBase64), "Null signature must be rejected.");
    }

    #endregion

    #region Requirement R4: Credential Vault Identity Binding and General Security Hardening

    [Fact]
    public void PipeServer_ValidateVaultSecretPayload_RejectsCrossUserSubstitution()
    {
        // ValidateVaultSecretPayload(byte[] protectedPayload, string clientSid, string? username)
        var method = typeof(PipeServer).GetMethod("ValidateVaultSecretPayload", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // Client SID for Alice (dummy well-known SID S-1-5-21-1111-2222-3333-1001)
        string clientSid = "S-1-5-21-1111-2222-3333-1001";

        // Bob's username: an existing local or well-known account like "Guest" or "Administrator"
        // which definitely translates to a different SID than Alice's
        string targetUser = "Administrator";

        byte[] dummyPayload = new byte[64];
        RandomNumberGenerator.Fill(dummyPayload);

        // Invoke with mismatched username whose SID cannot match clientSid
        var result = (bool)method.Invoke(null, new object[] { dummyPayload, clientSid, targetUser })!;
        Assert.False(result, "Cross-user credential substitution attempt must be rejected fail-closed.");
    }

    [Fact]
    public void PipeServer_ValidateVaultSecretPayload_RejectsCorruptOrEmptyPayload()
    {
        var method = typeof(PipeServer).GetMethod("ValidateVaultSecretPayload", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string clientSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "S-1-5-18";

        // Null payload
        var resultNull = (bool)method.Invoke(null, new object?[] { null, clientSid, null })!;
        Assert.False(resultNull, "Null protected payload must return false.");

        // Empty payload
        var resultEmpty = (bool)method.Invoke(null, new object[] { Array.Empty<byte>(), clientSid, null })!;
        Assert.False(resultEmpty, "Empty protected payload must return false.");

        // Random garbage bytes that fail DPAPI CryptUnprotectData
        byte[] garbage = new byte[32];
        RandomNumberGenerator.Fill(garbage);
        var resultGarbage = (bool)method.Invoke(null, new object[] { garbage, clientSid, null })!;
        Assert.False(resultGarbage, "Corrupt DPAPI payload must return false without unhandled exceptions.");
    }

    [Fact]
    public void CapabilityManager_LeastPrivilege_EmptyOrNullCapabilitiesStrictlyDenied()
    {
        var logger = new NoOpLogger();
        var capManager = new CapabilityManager(logger);

        var deviceEmpty = new TetherDevice
        {
            DeviceId = "dev-empty",
            DisplayName = "Unprivileged Device",
            Fingerprint = "fp-empty",
            PublicKeySpkiBase64 = "spki-empty",
            Capabilities = new List<string>() // Explicitly empty
        };

        var deviceNull = new TetherDevice
        {
            DeviceId = "dev-null",
            DisplayName = "Null Capabilities Device",
            Fingerprint = "fp-null",
            PublicKeySpkiBase64 = "spki-null",
            Capabilities = null!
        };

        // All capability checks must return false for empty or null capabilities
        string[] allKnownCaps = new[]
        {
            "FILES",
            "MEDIA",
            "POWER_ELEVATED",
            "WINDOWS_ADMIN",
            "APP_MANAGEMENT",
            "TERMINAL",
            "NOTIFICATIONS",
            "APP_LAUNCH",
            "CLIPBOARD"
        };

        foreach (var cap in allKnownCaps)
        {
            Assert.False(capManager.HasCapability(deviceEmpty, cap), $"Empty capabilities must deny '{cap}'.");
            Assert.False(capManager.HasCapability(deviceNull, cap), $"Null capabilities must deny '{cap}'.");
            Assert.False(CapabilityManager.HasCapability(new List<string>(), cap), $"Static HasCapability with empty list must deny '{cap}'.");
            Assert.False(CapabilityManager.HasCapability((IEnumerable<string>?)null, cap), $"Static HasCapability with null list must deny '{cap}'.");
        }
    }

    [Fact]
    public void FirewallRuleArguments_IncludeAllProfiles_WithLocalSubnetScope()
    {
        string ruleArgs = Worker.BuildFirewallRuleArguments(
            "Tether-Control-TCP",
            "TCP",
            37123,
            @"C:\Program Files\Tether\Tether.CommunicationService.exe"
        );

        Assert.Contains("profile=private,domain,public", ruleArgs);
        Assert.DoesNotContain("profile=any", ruleArgs);
        Assert.Contains("remoteip=localsubnet", ruleArgs);
    }

    [Fact]
    public void TetherSession_TryVerifyHandshakeProof_RejectsMismatchedSpkiProofOfPossession()
    {
        var session = (TetherSession)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(TetherSession));
        var identity = new Tether.CommunicationService.Security.WindowsIdentity(new NoOpLogger());
        typeof(TetherSession).GetField("_identity", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(session, identity);

        var verifyMethod = typeof(TetherSession).GetMethod("TryVerifyHandshakeProof", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(verifyMethod);

        using var clientKey1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var clientKey2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki1 = Convert.ToBase64String(clientKey1.ExportSubjectPublicKeyInfo());
        string spki2 = Convert.ToBase64String(clientKey2.ExportSubjectPublicKeyInfo());

        byte[] serverNonce = new byte[32];
        byte[] clientNonce = new byte[32];
        RandomNumberGenerator.Fill(serverNonce);
        RandomNumberGenerator.Fill(clientNonce);

        var proofObj = new
        {
            type = "HANDSHAKE_PROOF",
            signature = Convert.ToBase64String(new byte[64]),
            clientNonce = Convert.ToBase64String(clientNonce)
        };
        byte[] proofBytes = JsonSerializer.SerializeToUtf8Bytes(proofObj);

        // Attempt reconnect presenting SPKI1 when stored paired SPKI is SPKI2
        object[] args = new object[]
        {
            proofBytes,
            spki2, // storedPhoneSpkiBase64
            serverNonce,
            spki1, // presentedPhoneSpkiBase64 (mismatched!)
            "" // out failureReason
        };

        bool ok = (bool)verifyMethod.Invoke(session, args)!;
        string failureReason = (string)args[4];

        Assert.False(ok, "Mismatched presented SPKI vs stored SPKI must be rejected fail-closed.");
        Assert.Equal("Presented SPKI does not match stored SPKI", failureReason);
    }

    [Fact]
    public void TetherSession_TryVerifyHandshakeProof_RejectsMalformedProofJson()
    {
        var session = (TetherSession)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(TetherSession));
        var identity = new Tether.CommunicationService.Security.WindowsIdentity(new NoOpLogger());
        typeof(TetherSession).GetField("_identity", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(session, identity);

        var verifyMethod = typeof(TetherSession).GetMethod("TryVerifyHandshakeProof", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(verifyMethod);

        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(clientKey.ExportSubjectPublicKeyInfo());

        byte[] malformedBytes = Encoding.UTF8.GetBytes("{ not valid json at all");
        byte[] serverNonce = new byte[32];

        object[] args = new object[]
        {
            malformedBytes,
            spki,
            serverNonce,
            spki,
            ""
        };

        bool ok = (bool)verifyMethod.Invoke(session, args)!;
        string failureReason = (string)args[4];

        Assert.False(ok, "Malformed JSON must fail proof verification.");
        Assert.Contains("Malformed JSON", failureReason);
    }

    #endregion
}
