using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace Tether.DesktopUI
{
    public enum WindowsAccountType
    {
        Local,
        MicrosoftAccount,
        Domain,
        Unknown
    }

    public sealed class WindowsAccountInfo
    {
        public WindowsAccountType AccountType { get; init; } = WindowsAccountType.Local;
        public bool IsMicrosoftAccount => AccountType == WindowsAccountType.MicrosoftAccount;
        public string SamAccountName { get; init; } = "";
        public string DomainName { get; init; } = "";
        public string LocalQualifiedName { get; init; } = "";
        public string? InternetProviderName { get; init; }
        public string? InternetPrincipalName { get; init; }

        public string DisplayIdentity =>
            IsMicrosoftAccount && !string.IsNullOrWhiteSpace(InternetPrincipalName)
                ? InternetPrincipalName
                : LocalQualifiedName;

        public string AccountTypeDisplayName => AccountType switch
        {
            WindowsAccountType.MicrosoftAccount => "Microsoft Account",
            WindowsAccountType.Domain => "Domain Account",
            WindowsAccountType.Local => "Local Account",
            _ => "Local Account"
        };

        public string AccountBadgeText => AccountType switch
        {
            WindowsAccountType.MicrosoftAccount => "MICROSOFT ACCOUNT",
            WindowsAccountType.Domain => "DOMAIN ACCOUNT",
            WindowsAccountType.Local => "LOCAL ACCOUNT",
            _ => "LOCAL ACCOUNT"
        };
    }

    public static class WindowsAccountDetector
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct USER_INFO_24
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool usri24_internet_identity;
            public uint usri24_flags;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? usri24_internet_provider_name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? usri24_internet_principal_name;
            public IntPtr usri24_user_sid;
        }

        [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int NetUserGetInfo(
            string? serverName,
            string userName,
            int level,
            out IntPtr bufPtr);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(
            string lpszUsername,
            string? lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_LOGON_NETWORK = 3;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        /// <summary>
        /// Automatically detects whether the active Windows session is linked to a Microsoft Account (MSA)
        /// or is a standalone local account, extracting the associated email address when present.
        /// </summary>
        public static WindowsAccountInfo DetectCurrentAccount()
        {
            string samUser = Environment.UserName;
            string userDomain = Environment.UserDomainName;
            string localQualified = $"{userDomain}\\{samUser}";

            // 1. Primary Win32 Method: NetUserGetInfo Level 24
            try
            {
                IntPtr pBuf = IntPtr.Zero;
                int nerr = NetUserGetInfo(null, samUser, 24, out pBuf);
                if (nerr == 0 && pBuf != IntPtr.Zero)
                {
                    try
                    {
                        var info24 = Marshal.PtrToStructure<USER_INFO_24>(pBuf);
                        bool isInternetIdentity = info24.usri24_internet_identity;
                        string? provider = info24.usri24_internet_provider_name;
                        string? principal = info24.usri24_internet_principal_name;

                        bool providerMatchesMsa = !string.IsNullOrEmpty(provider) &&
                            provider.IndexOf("MicrosoftAccount", StringComparison.OrdinalIgnoreCase) >= 0;

                        bool hasEmailPrincipal = !string.IsNullOrEmpty(principal) &&
                            principal.Contains('@');

                        if (isInternetIdentity || providerMatchesMsa || hasEmailPrincipal)
                        {
                            return new WindowsAccountInfo
                            {
                                AccountType = WindowsAccountType.MicrosoftAccount,
                                SamAccountName = samUser,
                                DomainName = userDomain,
                                LocalQualifiedName = localQualified,
                                InternetProviderName = !string.IsNullOrEmpty(provider) ? provider : "MicrosoftAccount",
                                InternetPrincipalName = !string.IsNullOrEmpty(principal) ? principal : null
                            };
                        }
                    }
                    finally
                    {
                        NetApiBufferFree(pBuf);
                    }
                }
            }
            catch
            {
                // Fall through to registry and identity checks
            }

            // 2. Secondary Method: Registry Check for IdentityCRL User Extended Properties
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\IdentityCRL\UserExtendedProperties");
                if (key != null)
                {
                    string[] subKeys = key.GetSubKeyNames();
                    string? msaEmail = subKeys.FirstOrDefault(k => k.Contains('@'));
                    if (!string.IsNullOrEmpty(msaEmail))
                    {
                        return new WindowsAccountInfo
                        {
                            AccountType = WindowsAccountType.MicrosoftAccount,
                            SamAccountName = samUser,
                            DomainName = userDomain,
                            LocalQualifiedName = localQualified,
                            InternetProviderName = "MicrosoftAccount",
                            InternetPrincipalName = msaEmail
                        };
                    }
                }
            }
            catch
            {
                // Fall through to identity checks
            }

            // 3. Tertiary Method: Check WindowsIdentity token groups for Microsoft Account SID (S-1-11-96-...)
            try
            {
                using var currentIdentity = WindowsIdentity.GetCurrent();
                if (currentIdentity.Groups != null)
                {
                    foreach (var group in currentIdentity.Groups)
                    {
                        if (group.Value.StartsWith("S-1-11-96-", StringComparison.OrdinalIgnoreCase))
                        {
                            return new WindowsAccountInfo
                            {
                                AccountType = WindowsAccountType.MicrosoftAccount,
                                SamAccountName = samUser,
                                DomainName = userDomain,
                                LocalQualifiedName = localQualified,
                                InternetProviderName = "MicrosoftAccount",
                                InternetPrincipalName = null
                            };
                        }
                    }
                }
            }
            catch
            {
                // Fall through to local
            }

            // Fallback: Standard Local / Domain Account
            bool isDomain = !string.Equals(userDomain, Environment.MachineName, StringComparison.OrdinalIgnoreCase);

            return new WindowsAccountInfo
            {
                AccountType = isDomain ? WindowsAccountType.Domain : WindowsAccountType.Local,
                SamAccountName = samUser,
                DomainName = userDomain,
                LocalQualifiedName = localQualified,
                InternetProviderName = null,
                InternetPrincipalName = null
            };
        }

        /// <summary>
        /// Validates entered credentials with pre-save checks and Win32 LogonUser,
        /// detecting common mistakes such as PINs vs passwords and returning clean, helpful guidance.
        /// </summary>
        public static bool ValidateCredentials(string password, WindowsAccountInfo accountInfo, out string errorMessage)
        {
            errorMessage = string.Empty;

            if (string.IsNullOrEmpty(password))
            {
                errorMessage = "Please enter your password.";
                return false;
            }

            // Check if the user entered what looks like a Windows Hello PIN (e.g., 4-8 numeric digits)
            if (password.Length >= 4 && password.Length <= 10 && password.All(char.IsDigit))
            {
                if (accountInfo.IsMicrosoftAccount)
                {
                    errorMessage = "Windows Hello PIN detected. Windows auto-unlock requires your full Microsoft Account password, not your PIN.";
                }
                else
                {
                    errorMessage = "Windows Hello PIN detected. Windows auto-unlock requires your local Windows account password, not your PIN.";
                }
                return false;
            }

            // Candidate pairs of (username, domain) to validate against Win32 LogonUser
            var candidates = new (string username, string? domain)[]
            {
                // If Microsoft Account, test MSA principal with "MicrosoftAccount" domain first
                (accountInfo.InternetPrincipalName ?? "", "MicrosoftAccount"),
                (accountInfo.InternetPrincipalName ?? "", null),
                (accountInfo.InternetPrincipalName ?? "", ""),
                // Test SAM account name with local domain
                (accountInfo.SamAccountName, accountInfo.DomainName),
                (accountInfo.SamAccountName, "."),
                (accountInfo.SamAccountName, null)
            };

            int lastError = 0;
            foreach (var (user, domain) in candidates)
            {
                if (string.IsNullOrWhiteSpace(user)) continue;

                // Try LOGON32_LOGON_INTERACTIVE (2) first
                if (LogonUser(user, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out IntPtr token))
                {
                    CloseHandle(token);
                    return true;
                }
                lastError = Marshal.GetLastWin32Error();

                // Try LOGON32_LOGON_NETWORK (3) as fallback (does not require SE_TCB privileges)
                if (LogonUser(user, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out token))
                {
                    CloseHandle(token);
                    return true;
                }
                lastError = Marshal.GetLastWin32Error();
            }

            // Format clear, helpful error messages based on account type and error code
            if (lastError == 1326 /* ERROR_LOGON_FAILURE */)
            {
                if (accountInfo.IsMicrosoftAccount)
                {
                    errorMessage = $"Incorrect Microsoft Account password for {accountInfo.DisplayIdentity}. Please enter your online account password (not your Windows Hello PIN).";
                }
                else
                {
                    errorMessage = $"Incorrect Windows password for {accountInfo.DisplayIdentity}. Please enter your valid local Windows account password.";
                }
            }
            else if (lastError == 1330 /* ERROR_PASSWORD_EXPIRED */)
            {
                errorMessage = "Your Windows account password has expired. Please update it in Windows Settings first.";
            }
            else if (lastError == 1331 /* ERROR_ACCOUNT_DISABLED */)
            {
                errorMessage = "This Windows account is currently disabled.";
            }
            else
            {
                if (accountInfo.IsMicrosoftAccount)
                {
                    errorMessage = $"Authentication failed (Error {lastError}). Please verify your Microsoft Account password.";
                }
                else
                {
                    errorMessage = $"Authentication failed (Error {lastError}). Please verify your Windows password.";
                }
            }

            return false;
        }
    }
}
