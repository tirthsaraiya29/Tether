using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32;
using Tether.PanicEngine;
using Tether.Shared.Logging;
using Tether.Shared.Security;
using Xunit;

namespace Tether.Tests;

[SupportedOSPlatform("windows")]
public class FallbackAuthenticationTests
{
    private readonly TestLogger _logger = new();

    #region PIN Validation Tests

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidatePin_RejectsEmpty(string? pin)
    {
        var result = FallbackCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.None, result.Strength);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("1234")]
    [InlineData("9842137")] // 7 digits (< 8)
    public void ValidatePin_RejectsTooShort(string pin)
    {
        var result = FallbackCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.VeryWeak, result.Strength);
    }

    [Theory]
    [InlineData("1234567a")]
    [InlineData("1234 5678")]
    [InlineData("9842-1376")]
    public void ValidatePin_RejectsNonDigits(string pin)
    {
        var result = FallbackCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.VeryWeak, result.Strength);
    }

    [Theory]
    [InlineData("11145678")] // 111 at start
    [InlineData("98444123")] // 444 in middle
    [InlineData("98421777")] // 777 at end
    public void ValidatePin_RejectsRepeatedDigits(string pin)
    {
        var result = FallbackCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.Weak, result.Strength);
    }

    [Theory]
    [InlineData("12345678")] // Ascending
    [InlineData("87654321")] // Descending
    [InlineData("98421234")] // 1234 at end
    [InlineData("98432176")] // 4321 in middle
    public void ValidatePin_RejectsSequentialDigits(string pin)
    {
        var result = FallbackCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.Weak, result.Strength);
    }

    [Theory]
    [InlineData("12121212")] // 2-char repeat
    [InlineData("12312312")] // 3-char repeat
    [InlineData("12341234")] // 4-char repeat
    [InlineData("98429842")] // 4-char repeat
    public void ValidatePin_RejectsRepeatingChunks(string pin)
    {
        var result = FallbackCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.Weak, result.Strength);
    }

    [Theory]
    [InlineData("98421376")]
    [InlineData("38194625")]
    [InlineData("729401835")]
    public void ValidatePin_AcceptsStrongNonPredictable(string pin)
    {
        var result = FallbackCredentialValidator.ValidatePin(pin);
        Assert.True(result.IsValid);
        Assert.True(result.Strength >= CredentialStrength.Good);
    }

    #endregion

    #region Password Validation Tests

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidatePassword_RejectsEmpty(string? password)
    {
        var result = FallbackCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.None, result.Strength);
    }

    [Theory]
    [InlineData("Pass1!")]
    [InlineData("Abc!2")]
    public void ValidatePassword_RejectsTooShort(string password)
    {
        var result = FallbackCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.VeryWeak, result.Strength);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("password123")]
    [InlineData("administrator")]
    [InlineData("qwertyui")]
    [InlineData("masterpass")]
    public void ValidatePassword_RejectsCommonWeak(string password)
    {
        var result = FallbackCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.True(result.Strength <= CredentialStrength.Weak);
    }

    [Theory]
    [InlineData("aaaabbbb1!")] // repeated chars
    [InlineData("abcdefgh1!")] // alphabet sequence
    [InlineData("98765432!Aa")] // digit sequence
    public void ValidatePassword_RejectsPredictablePatterns(string password)
    {
        var result = FallbackCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.True(result.Strength <= CredentialStrength.Weak);
    }

    [Theory]
    [InlineData("qwerty1234!A")]
    [InlineData("asdfgh123!Aa")]
    public void ValidatePassword_RejectsKeyboardSequences(string password)
    {
        var result = FallbackCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.True(result.Strength <= CredentialStrength.Weak);
    }

    [Theory]
    [InlineData("Xbv!9842wY#")]
    [InlineData("Tether*Sec#2026!")]
    [InlineData("K9#vL2$mQ8!pZ5")]
    public void ValidatePassword_AcceptsDiverseStrong(string password)
    {
        var result = FallbackCredentialValidator.ValidatePassword(password);
        Assert.True(result.IsValid);
        Assert.True(result.Strength >= CredentialStrength.Good);
    }

    #endregion

    #region Vault Storage & Cryptographic Verification Tests

    [Fact]
    public void FallbackCredentialStore_CreateAndVerify_Pin_Succeeds()
    {
        const string pin = "98421376";
        byte[] protectedPayload = FallbackCredentialStore.CreatePayload(pin, FallbackAuthType.Pin);
        Assert.NotNull(protectedPayload);
        Assert.True(protectedPayload.Length > 59);

        // Verification succeeds with matching pin
        bool verified = FallbackCredentialStore.VerifyPayload(pin, protectedPayload, FallbackAuthType.Pin);
        Assert.True(verified);

        // Verification fails with wrong pin
        bool failed = FallbackCredentialStore.VerifyPayload("98421377", protectedPayload, FallbackAuthType.Pin);
        Assert.False(failed);

        // Type mismatch fails
        bool typeMismatch = FallbackCredentialStore.VerifyPayload(pin, protectedPayload, FallbackAuthType.Password);
        Assert.False(typeMismatch);
    }

    [Fact]
    public void FallbackCredentialStore_CreateAndVerify_Password_Succeeds()
    {
        const string password = "P@ssw0rd!Secure2026";
        byte[] protectedPayload = FallbackCredentialStore.CreatePayload(password, FallbackAuthType.Password);
        Assert.NotNull(protectedPayload);

        bool verified = FallbackCredentialStore.VerifyPayload(password, protectedPayload, FallbackAuthType.Password);
        Assert.True(verified);

        bool wrongPwd = FallbackCredentialStore.VerifyPayload("P@ssw0rd!Secure2027", protectedPayload, FallbackAuthType.Password);
        Assert.False(wrongPwd);
    }

    [Fact]
    public void BackwardCompatibility_AliasesWork()
    {
        const string pin = "98421376";
        byte[] payload = MasterCredentialStore.CreatePayload(pin, MasterAuthType.Pin);
        Assert.True(MasterCredentialStore.VerifyPayload(pin, payload, MasterAuthType.Pin));
    }

    #endregion

    #region Credential Provider Filter Registration Tests

    [Fact]
    public void EnsureFilterRegistered_CreatesFilterKeyInRegistry()
    {
        const string testSubKey = @"Software\Tether\TestFilterRegistry";
        using var rootKey = Registry.CurrentUser.CreateSubKey(testSubKey, true);
        Assert.NotNull(rootKey);

        SafeCredentialFilterManager.EnsureFilterRegistered(rootKey, _logger);

        string expectedSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\" + SafeCredentialFilterManager.TetherProviderGuid.ToString("B");
        using var filterKey = rootKey.OpenSubKey(expectedSubKey);
        Assert.NotNull(filterKey);

        object? val = filterKey.GetValue("");
        Assert.Equal("TetherCredentialProvider", val);

        Registry.CurrentUser.DeleteSubKeyTree(testSubKey, false);
    }

    #endregion
}
