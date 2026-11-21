using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Tether.Shared.Security;

public enum CredentialStrength
{
    None = 0,
    VeryWeak = 1,
    Weak = 2,
    Fair = 3,
    Good = 4,
    Strong = 5
}

public sealed record ValidationResult(
    bool IsValid,
    CredentialStrength Strength,
    string FeedbackMessage
);

public static class FallbackCredentialValidator
{
    public const int MinimumLength = 8;

    private static readonly HashSet<string> CommonWeakPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password1", "password123", "12345678", "87654321",
        "administrator", "admin123", "qwertyui", "qwerty123", "asdfghjk",
        "welcome1", "letmein1", "iloveyou", "changeme", "pass1234",
        "trustno1", "masterpass", "masterpin", "tether123", "default1"
    };

    private static readonly string[] KeyboardRows =
    {
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
        "poiuytrewq",
        "lkjhgfdsa",
        "mnbvcxz",
        "0987654321"
    };

    public static ValidationResult ValidatePin(string? pin)
    {
        if (string.IsNullOrWhiteSpace(pin))
        {
            return new ValidationResult(false, CredentialStrength.None, "PIN cannot be empty.");
        }

        if (pin.Length < MinimumLength)
        {
            return new ValidationResult(false, CredentialStrength.VeryWeak, $"PIN must be at least {MinimumLength} digits.");
        }

        if (!pin.All(char.IsDigit))
        {
            return new ValidationResult(false, CredentialStrength.VeryWeak, "PIN must contain only numbers (0-9).");
        }

        // Check for 3 or more repeated identical consecutive digits (e.g. "111")
        for (int i = 0; i <= pin.Length - 3; i++)
        {
            if (pin[i] == pin[i + 1] && pin[i] == pin[i + 2])
            {
                return new ValidationResult(false, CredentialStrength.Weak, $"PIN contains repeated numbers ('{pin.Substring(i, 3)}').");
            }
        }

        // Check for sequential digits (ascending or descending runs of 3+ digits)
        for (int i = 0; i <= pin.Length - 3; i++)
        {
            int d0 = pin[i] - '0';
            int d1 = pin[i + 1] - '0';
            int d2 = pin[i + 2] - '0';

            if (d1 == d0 + 1 && d2 == d1 + 1)
            {
                return new ValidationResult(false, CredentialStrength.Weak, $"PIN contains sequential ascending numbers ('{pin.Substring(i, 3)}').");
            }
            if (d1 == d0 - 1 && d2 == d1 - 1)
            {
                return new ValidationResult(false, CredentialStrength.Weak, $"PIN contains sequential descending numbers ('{pin.Substring(i, 3)}').");
            }
        }

        // Check for repeating patterns / chunks of length 2, 3, 4 (e.g. 12121212, 12312312, 12341234)
        for (int chunkLen = 2; chunkLen <= 4; chunkLen++)
        {
            for (int i = 0; i <= pin.Length - (chunkLen * 2); i++)
            {
                string chunk1 = pin.Substring(i, chunkLen);
                string chunk2 = pin.Substring(i + chunkLen, chunkLen);
                if (chunk1 == chunk2)
                {
                    return new ValidationResult(false, CredentialStrength.Weak, $"PIN contains repeating pattern ('{chunk1}{chunk2}').");
                }
            }
        }

        // Must have at least 4 distinct digits
        int distinctDigits = pin.Distinct().Count();
        if (distinctDigits < 4)
        {
            return new ValidationResult(false, CredentialStrength.Weak, "PIN must contain at least 4 distinct numbers.");
        }

        // Check predictable alternating digits (e.g. 13131313, 24242424)
        bool alternating = true;
        for (int i = 2; i < pin.Length; i++)
        {
            if (pin[i] != pin[i % 2])
            {
                alternating = false;
                break;
            }
        }
        if (alternating)
        {
            return new ValidationResult(false, CredentialStrength.Weak, "PIN contains predictable alternating numbers.");
        }

        // Good or Strong
        var strength = pin.Length >= 10 && distinctDigits >= 6
            ? CredentialStrength.Strong
            : CredentialStrength.Good;

        return new ValidationResult(true, strength, strength == CredentialStrength.Strong ? "Strong PIN." : "Good PIN.");
    }

    public static ValidationResult ValidatePassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return new ValidationResult(false, CredentialStrength.None, "Password cannot be empty.");
        }

        if (password.Length < MinimumLength)
        {
            return new ValidationResult(false, CredentialStrength.VeryWeak, $"Password must be at least {MinimumLength} characters.");
        }

        if (CommonWeakPasswords.Contains(password))
        {
            return new ValidationResult(false, CredentialStrength.VeryWeak, "Password is too common or easily guessed.");
        }

        // Check for 3+ repeated identical consecutive characters (e.g. "aaa", "111")
        for (int i = 0; i <= password.Length - 3; i++)
        {
            if (password[i] == password[i + 1] && password[i] == password[i + 2])
            {
                return new ValidationResult(false, CredentialStrength.Weak, $"Password contains repeated characters ('{password.Substring(i, 3)}').");
            }
        }

        // Check for alphabetical sequences (3+ consecutive ascending/descending letters)
        string lower = password.ToLowerInvariant();
        for (int i = 0; i <= lower.Length - 3; i++)
        {
            char c0 = lower[i];
            char c1 = lower[i + 1];
            char c2 = lower[i + 2];

            if (char.IsLetter(c0) && char.IsLetter(c1) && char.IsLetter(c2))
            {
                if (c1 == c0 + 1 && c2 == c1 + 1)
                {
                    return new ValidationResult(false, CredentialStrength.Weak, $"Password contains alphabetical sequence ('{password.Substring(i, 3)}').");
                }
                if (c1 == c0 - 1 && c2 == c1 - 1)
                {
                    return new ValidationResult(false, CredentialStrength.Weak, $"Password contains reverse alphabetical sequence ('{password.Substring(i, 3)}').");
                }
            }
        }

        // Check for digit sequences (3+ consecutive ascending/descending numbers)
        for (int i = 0; i <= lower.Length - 3; i++)
        {
            char c0 = lower[i];
            char c1 = lower[i + 1];
            char c2 = lower[i + 2];

            if (char.IsDigit(c0) && char.IsDigit(c1) && char.IsDigit(c2))
            {
                if (c1 == c0 + 1 && c2 == c1 + 1)
                {
                    return new ValidationResult(false, CredentialStrength.Weak, $"Password contains sequential digits ('{password.Substring(i, 3)}').");
                }
                if (c1 == c0 - 1 && c2 == c1 - 1)
                {
                    return new ValidationResult(false, CredentialStrength.Weak, $"Password contains sequential digits ('{password.Substring(i, 3)}').");
                }
            }
        }

        // Check for keyboard patterns (e.g. "qwerty", "asdfgh")
        foreach (var row in KeyboardRows)
        {
            for (int k = 0; k <= row.Length - 4; k++)
            {
                string pattern = row.Substring(k, 4);
                if (lower.Contains(pattern))
                {
                    return new ValidationResult(false, CredentialStrength.Weak, $"Password contains keyboard pattern ('{pattern}').");
                }
            }
        }

        // Check for repeating patterns / substrings of length 2, 3, 4
        for (int chunkLen = 2; chunkLen <= 4; chunkLen++)
        {
            for (int i = 0; i <= lower.Length - (chunkLen * 2); i++)
            {
                string chunk1 = lower.Substring(i, chunkLen);
                string chunk2 = lower.Substring(i + chunkLen, chunkLen);
                if (chunk1 == chunk2)
                {
                    return new ValidationResult(false, CredentialStrength.Weak, $"Password contains repeating substring ('{password.Substring(i, chunkLen * 2)}').");
                }
            }
        }

        // Character diversity checks
        bool hasUpper = password.Any(char.IsUpper);
        bool hasLower = password.Any(char.IsLower);
        bool hasDigit = password.Any(char.IsDigit);
        bool hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

        int categoryCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

        if (categoryCount < 3)
        {
            return new ValidationResult(false, CredentialStrength.Weak, "Password must include at least 3 character types (uppercase, lowercase, numbers, or symbols).");
        }

        CredentialStrength strength;
        string feedback;

        if (categoryCount >= 4 && password.Length >= 12)
        {
            strength = CredentialStrength.Strong;
            feedback = "Strong password.";
        }
        else if (categoryCount >= 3 && password.Length >= 10)
        {
            strength = CredentialStrength.Good;
            feedback = "Good password.";
        }
        else
        {
            strength = CredentialStrength.Fair;
            feedback = "Fair password. Consider adding symbols or length for extra security.";
        }

        return new ValidationResult(true, strength, feedback);
    }
}

// Backward compatibility forwarder
public static class MasterCredentialValidator
{
    public const int MinimumLength = FallbackCredentialValidator.MinimumLength;
    public static ValidationResult ValidatePin(string? pin) => FallbackCredentialValidator.ValidatePin(pin);
    public static ValidationResult ValidatePassword(string? password) => FallbackCredentialValidator.ValidatePassword(password);
}
