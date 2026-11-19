using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Tether.Shared.Security;

public enum FallbackAuthType : uint
{
    None = 0,
    Pin = 1,
    Password = 2
}

// Backward compatibility alias
public enum MasterAuthType : uint
{
    None = 0,
    Pin = 1,
    Password = 2
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public static class FallbackCredentialStore
{
    public const string SecretSubKey = @"SOFTWARE\Tether\CredentialProvider\Secrets";
    public const string RootSubKey = @"SOFTWARE\Tether\CredentialProvider";
    public static readonly byte[] SystemBoundEntropy = "Tether_System_Bound_Vault_v1"u8.ToArray();
    public static readonly byte[] Magic = "TMAP"u8.ToArray(); // Tether Mode Auth Payload

    public static byte[] CreatePayload(string credential, FallbackAuthType type)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        const int iterations = 100_000;
        byte[] credUtf8 = Encoding.UTF8.GetBytes(credential);

        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            credUtf8,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            32
        );
        CryptographicOperations.ZeroMemory(credUtf8);

        // Raw payload layout:
        // Offset 0..3:  Magic (4 bytes) "TMAP"
        // Offset 4:     Type (1 byte: 1=Pin, 2=Password)
        // Offset 5:     SaltLen (1 byte: 16)
        // Offset 6..21: Salt (16 bytes)
        // Offset 22..25: Iterations (4 bytes LE: 100,000)
        // Offset 26:    HashLen (1 byte: 32)
        // Offset 27..58: Hash (32 bytes)
        byte[] raw = new byte[4 + 1 + 1 + 16 + 4 + 1 + 32];
        Buffer.BlockCopy(Magic, 0, raw, 0, 4);
        raw[4] = (byte)type;
        raw[5] = 16;
        Buffer.BlockCopy(salt, 0, raw, 6, 16);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(22, 4), iterations);
        raw[26] = 32;
        Buffer.BlockCopy(hash, 0, raw, 27, 32);

        CryptographicOperations.ZeroMemory(hash);

        // Protect with DPAPI local machine scope using system bound entropy
        byte[] protectedBlob = ProtectedData.Protect(
            raw,
            SystemBoundEntropy,
            DataProtectionScope.LocalMachine
        );

        CryptographicOperations.ZeroMemory(raw);
        return protectedBlob;
    }

    public static bool VerifyPayload(string credential, byte[] protectedPayload, FallbackAuthType expectedType)
    {
        byte[]? raw = null;
        try
        {
            raw = ProtectedData.Unprotect(
                protectedPayload,
                SystemBoundEntropy,
                DataProtectionScope.LocalMachine
            );

            if (raw.Length < 59) return false;
            if (!raw.AsSpan(0, 4).SequenceEqual(Magic)) return false;

            byte type = raw[4];
            if (expectedType != FallbackAuthType.None && type != (byte)expectedType) return false;

            byte saltLen = raw[5];
            if (saltLen != 16) return false;
            byte[] salt = raw.AsSpan(6, 16).ToArray();

            int iterations = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(22, 4));
            if (iterations < 1000 || iterations > 2_000_000) return false;

            byte hashLen = raw[26];
            if (hashLen != 32) return false;
            byte[] storedHash = raw.AsSpan(27, 32).ToArray();

            byte[] credUtf8 = Encoding.UTF8.GetBytes(credential);
            byte[] computedHash = Rfc2898DeriveBytes.Pbkdf2(
                credUtf8,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                32
            );
            CryptographicOperations.ZeroMemory(credUtf8);

            bool matches = CryptographicOperations.FixedTimeEquals(computedHash, storedHash);

            CryptographicOperations.ZeroMemory(computedHash);
            CryptographicOperations.ZeroMemory(storedHash);
            return matches;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (raw != null) CryptographicOperations.ZeroMemory(raw);
        }
    }

    public static void SaveFallbackAuth(byte[] protectedPayload, FallbackAuthType type, RegistryKey? rootKey = null)
    {
        var hklm = rootKey ?? Registry.LocalMachine;
        using var secretsKey = hklm.CreateSubKey(SecretSubKey, true);
        if (secretsKey != null)
        {
            secretsKey.SetValue("FallbackAuthType", (int)type, RegistryValueKind.DWord);
            secretsKey.SetValue("FallbackAuthPayload", protectedPayload, RegistryValueKind.Binary);
            secretsKey.SetValue("FallbackAuthFailedAttempts", 0, RegistryValueKind.DWord);
            secretsKey.SetValue("FallbackAuthLockoutUntil", 0L, RegistryValueKind.QWord);

            // Maintain compatibility keys during migration
            secretsKey.SetValue("MasterAuthType", (int)type, RegistryValueKind.DWord);
            secretsKey.SetValue("MasterAuthPayload", protectedPayload, RegistryValueKind.Binary);
            secretsKey.SetValue("MasterAuthFailedAttempts", 0, RegistryValueKind.DWord);
            secretsKey.SetValue("MasterAuthLockoutUntil", 0L, RegistryValueKind.QWord);
        }
    }

    public static void DisableFallbackAuth(RegistryKey? rootKey = null)
    {
        var hklm = rootKey ?? Registry.LocalMachine;
        using var secretsKey = hklm.CreateSubKey(SecretSubKey, true);
        if (secretsKey != null)
        {
            secretsKey.SetValue("FallbackAuthType", 0, RegistryValueKind.DWord);
            try { secretsKey.DeleteValue("FallbackAuthPayload", false); } catch { }
            secretsKey.SetValue("FallbackAuthFailedAttempts", 0, RegistryValueKind.DWord);
            secretsKey.SetValue("FallbackAuthLockoutUntil", 0L, RegistryValueKind.QWord);

            secretsKey.SetValue("MasterAuthType", 0, RegistryValueKind.DWord);
            try { secretsKey.DeleteValue("MasterAuthPayload", false); } catch { }
            secretsKey.SetValue("MasterAuthFailedAttempts", 0, RegistryValueKind.DWord);
            secretsKey.SetValue("MasterAuthLockoutUntil", 0L, RegistryValueKind.QWord);
        }
    }

    public static (FallbackAuthType Type, byte[]? Payload) LoadFallbackAuth(RegistryKey? rootKey = null)
    {
        var hklm = rootKey ?? Registry.LocalMachine;
        using var secretsKey = hklm.OpenSubKey(SecretSubKey, false);
        if (secretsKey == null) return (FallbackAuthType.None, null);

        var typeObj = secretsKey.GetValue("FallbackAuthType") ?? secretsKey.GetValue("MasterAuthType");
        int typeVal = typeObj is int i ? i : 0;
        var payloadObj = (secretsKey.GetValue("FallbackAuthPayload") ?? secretsKey.GetValue("MasterAuthPayload")) as byte[];

        return ((FallbackAuthType)typeVal, payloadObj);
    }
}

// Forwarding helper for any legacy callers
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public static class MasterCredentialStore
{
    public static byte[] CreatePayload(string credential, MasterAuthType type) =>
        FallbackCredentialStore.CreatePayload(credential, (FallbackAuthType)type);

    public static bool VerifyPayload(string credential, byte[] protectedPayload, MasterAuthType expectedType) =>
        FallbackCredentialStore.VerifyPayload(credential, protectedPayload, (FallbackAuthType)expectedType);

    public static void SaveMasterAuth(byte[] protectedPayload, MasterAuthType type, RegistryKey? rootKey = null) =>
        FallbackCredentialStore.SaveFallbackAuth(protectedPayload, (FallbackAuthType)type, rootKey);

    public static void DisableMasterAuth(RegistryKey? rootKey = null) =>
        FallbackCredentialStore.DisableFallbackAuth(rootKey);

    public static (MasterAuthType Type, byte[]? Payload) LoadMasterAuth(RegistryKey? rootKey = null)
    {
        var (t, p) = FallbackCredentialStore.LoadFallbackAuth(rootKey);
        return ((MasterAuthType)t, p);
    }
}
