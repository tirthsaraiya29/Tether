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
public class MasterAuthenticationTests
{
    private readonly TestLogger _logger = new();

    #region PIN Validation Tests

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidatePin_RejectsEmpty(string? pin)
    {
        var result = MasterCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.None, result.Strength);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("1234")]
    [InlineData("9842137")] // 7 digits (< 8)
    public void ValidatePin_RejectsTooShort(string pin)
    {
        var result = MasterCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.VeryWeak, result.Strength);
    }

    [Theory]
    [InlineData("1234abcd")] // Letters in PIN
    [InlineData("1234-5678")] // Punctuation in PIN
    [InlineData("1234 5678")] // Space in PIN
    public void ValidatePin_RejectsNonDigits(string pin)
    {
        var result = MasterCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("01234567")] // Ascending
    [InlineData("12345678")] // Ascending
    [InlineData("23456789")] // Ascending
    [InlineData("76543210")] // Descending
    [InlineData("87654321")] // Descending
    [InlineData("98765432")] // Descending
    public void ValidatePin_RejectsSequentialDigits(string pin)
    {
        var result = MasterCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Contains("sequential", result.FeedbackMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("11111111")] // All same
    [InlineData("99999999")] // All same
    [InlineData("11145678")] // 3 consecutive same
    [InlineData("98755512")] // 3 consecutive same
    public void ValidatePin_RejectsRepeatedDigits(string pin)
    {
        var result = MasterCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Contains("repeated", result.FeedbackMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("48484848")] // 2-char non-sequential repetition
    [InlineData("95195195")] // 3-char non-sequential repetition
    [InlineData("84218421")] // 4-char non-sequential repetition
    public void ValidatePin_RejectsRepeatingPatterns(string pin)
    {
        var result = MasterCredentialValidator.ValidatePin(pin);
        Assert.False(result.IsValid);
        Assert.Contains("repeating", result.FeedbackMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("98421376")]
    [InlineData("71938204")]
    [InlineData("58204917")]
    [InlineData("39182746")]
    public void ValidatePin_AcceptsStrongUnpredictablePin(string pin)
    {
        var result = MasterCredentialValidator.ValidatePin(pin);
        Assert.True(result.IsValid);
        Assert.True(result.Strength >= CredentialStrength.Fair);
    }

    #endregion

    #region Password Validation Tests

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidatePassword_RejectsEmpty(string? password)
    {
        var result = MasterCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.None, result.Strength);
    }

    [Theory]
    [InlineData("P@ss1")]
    [InlineData("Short1!")] // 7 chars
    public void ValidatePassword_RejectsTooShort(string password)
    {
        var result = MasterCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.Equal(CredentialStrength.VeryWeak, result.Strength);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("password123")]
    [InlineData("qwertyuiop")]
    [InlineData("asdfghjkl")]
    [InlineData("admin12345")]
    public void ValidatePassword_RejectsCommonOrKeyboardPatterns(string password)
    {
        var result = MasterCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("abcdefgh")] // Lowercase sequential
    [InlineData("ZYXWVUTS")] // Uppercase sequential descending
    [InlineData("abcd12345")] // Sequential alpha + numeric
    public void ValidatePassword_RejectsAlphabeticalSequences(string password)
    {
        var result = MasterCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("onlylowercasehere")]
    [InlineData("ONLYUPPERCASEHERE")]
    [InlineData("9472018356194")]
    public void ValidatePassword_RejectsLackOfCharacterDiversity(string password)
    {
        var result = MasterCredentialValidator.ValidatePassword(password);
        Assert.False(result.IsValid);
        Assert.True(result.FeedbackMessage.Contains("uppercase", StringComparison.OrdinalIgnoreCase) ||
                    result.FeedbackMessage.Contains("lowercase", StringComparison.OrdinalIgnoreCase) ||
                    result.FeedbackMessage.Contains("number", StringComparison.OrdinalIgnoreCase) ||
                    result.FeedbackMessage.Contains("letter", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("P@ssw0rd!Secure2026")]
    [InlineData("Tr#7mK9$vL2!pQx")]
    [InlineData("Tether#Vault98!")]
    public void ValidatePassword_AcceptsStrongComplexPassword(string password)
    {
        var result = MasterCredentialValidator.ValidatePassword(password);
        Assert.True(result.IsValid);
        Assert.True(result.Strength >= CredentialStrength.Good);
    }

    #endregion

    #region Store DPAPI & Verification Tests

    [Fact]
    public void MasterCredentialStore_CreateAndVerify_Pin_Succeeds()
    {
        const string pin = "98421376";
        byte[] protectedPayload = MasterCredentialStore.CreatePayload(pin, MasterAuthType.Pin);
        Assert.NotNull(protectedPayload);
        Assert.True(protectedPayload.Length > 59); // DPAPI adds overhead

        // Matching PIN verifies
        bool verified = MasterCredentialStore.VerifyPayload(pin, protectedPayload, MasterAuthType.Pin);
        Assert.True(verified);

        // Incorrect PIN fails
        bool failed = MasterCredentialStore.VerifyPayload("98421377", protectedPayload, MasterAuthType.Pin);
        Assert.False(failed);

        // Type mismatch fails
        bool typeMismatch = MasterCredentialStore.VerifyPayload(pin, protectedPayload, MasterAuthType.Password);
        Assert.False(typeMismatch);
    }

    [Fact]
    public void MasterCredentialStore_CreateAndVerify_Password_Succeeds()
    {
        const string password = "P@ssw0rd!Secure2026";
        byte[] protectedPayload = MasterCredentialStore.CreatePayload(password, MasterAuthType.Password);
        Assert.NotNull(protectedPayload);

        bool verified = MasterCredentialStore.VerifyPayload(password, protectedPayload, MasterAuthType.Password);
        Assert.True(verified);

        bool wrongPwd = MasterCredentialStore.VerifyPayload("P@ssw0rd!Secure2027", protectedPayload, MasterAuthType.Password);
        Assert.False(wrongPwd);
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
