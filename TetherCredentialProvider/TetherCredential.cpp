// CSampleCredential.cpp
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <wincrypt.h>
#include <winreg.h>
#include <vector>
#include <cstring>
#include <cstdarg>
#include "TetherCredential.h"
#include "TetherProvider.h"
#include "guid.h"
#include "TetherCredentialGlobals.h"

#pragma comment(lib, "crypt32.lib")

#define WM_SIGNAL_CREDENTIALS_CHANGED (WM_USER + 101)

static bool g_isClassRegistered = false;
void WriteDebugLog(const wchar_t* format, ...);


// -------------------------------------------------------------------
// Constructor / Destructor
// -------------------------------------------------------------------
CSampleCredential::CSampleCredential() :
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0),
    _dwSelectedMethod(0),
    _fBypassEnabled(false),
    _pszStoredPasswordHash(nullptr),
    _cpus(CPUS_INVALID),
    _pProvider(nullptr),
    _hWndMessage(nullptr),
    _hAppEvent(nullptr),
    _hScreenEvent(nullptr),
    _hWaitApp(nullptr),
    _hWaitScreen(nullptr),
    _isValid(true)
{
    DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    _isValid.store(false);

    if (_hWaitApp) { UnregisterWait(_hWaitApp); _hWaitApp = nullptr; }
    if (_hWaitScreen) { UnregisterWait(_hWaitScreen); _hWaitScreen = nullptr; }
    Sleep(100);

    if (_hAppEvent) CloseHandle(_hAppEvent);
    if (_hScreenEvent) CloseHandle(_hScreenEvent);
    _DestroyMessageWindow();

    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t len = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], len * sizeof(WCHAR));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszStoredPasswordHash);
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}

// -------------------------------------------------------------------
// Window procedure
// -------------------------------------------------------------------
LRESULT CALLBACK CSampleCredential::WebAuthMsgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_SIGNAL_CREDENTIALS_CHANGED)
    {
        CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lParam);
        if (pThis && pThis->_pProvider)
            pThis->_pProvider->SignalCredentialsChanged();
        return 0;
    }
    return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

// -------------------------------------------------------------------
// Initialize – FIX #3: null check
// -------------------------------------------------------------------
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    const FIELD_STATE_PAIR* rgfsp,
    ICredentialProviderUser* pcpUser)
{
    if (!pcpUser) return E_INVALIDARG;

    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    _dwSelectedMethod = g_dwSelectedMethod.load();

    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    _rgFieldStatePairs[SFI_PASSWORD].cpfs = (_dwSelectedMethod == 2) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;

    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Tether Pro Gateway", &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Sign in using Tether", &_rgFieldStrings[SFI_LARGE_TEXT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Choose verification channel:", &_rgFieldStrings[SFI_METHOD_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(s_rgUnlockMethodStrings[_dwSelectedMethod], &_rgFieldStrings[SFI_METHOD_COMBOBOX]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Authenticate", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);

    const WCHAR* pszStatus = L"Awaiting phone app synchronization...";
    if (_dwSelectedMethod == 1) pszStatus = L"Unlock your connected mobile screen to proceed...";
    else if (_dwSelectedMethod == 2) pszStatus = L"Provide local TPM authorization credential.";
    else if (_dwSelectedMethod == 3) pszStatus = L"Development Bypass Active.";
    if (SUCCEEDED(hr)) hr = SHStrDupW(pszStatus, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);

    if (SUCCEEDED(hr)) hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    if (SUCCEEDED(hr)) hr = pcpUser->GetSid(&_pszUserSid);

    LoadStoredPasswordHashFromTpm();
    _CreateMessageWindow();
    _StartBackgroundIPCListeners();

    return hr;
}

// -------------------------------------------------------------------
// Load stored hash (kept for compatibility, but not used for verification)
// -------------------------------------------------------------------
HRESULT CSampleCredential::LoadStoredPasswordHashFromTpm()
{
    HRESULT hr = S_FALSE;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        WCHAR szHash[512];
        DWORD dwSize = sizeof(szHash);
        if (RegQueryValueExW(hKey, L"PasswordHash", nullptr, nullptr, (LPBYTE)szHash, &dwSize) == ERROR_SUCCESS)
            hr = SHStrDupW(szHash, &_pszStoredPasswordHash);
        RegCloseKey(hKey);
    }
    if (FAILED(hr))
        hr = SHStrDupW(L"", &_pszStoredPasswordHash);
    return hr;
}

// -------------------------------------------------------------------
// Standard COM methods (Advise, UnAdvise, SetSelected, SetDeselected...)
// -------------------------------------------------------------------
HRESULT CSampleCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

HRESULT CSampleCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t len = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], len * sizeof(WCHAR));
        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
    }
    return hr;
}

HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
        return SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (dwFieldID == SFI_TILEIMAGE)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp)
        {
            *phbmp = hbmp;
            return S_OK;
        }
        return HRESULT_FROM_WIN32(GetLastError());
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID == SFI_SUBMIT_BUTTON)
    {
        *pdwAdjacentTo = SFI_PASSWORD;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (_rgCredProvFieldDescriptors[dwFieldID].cpft == CPFT_EDIT_TEXT ||
            _rgCredProvFieldDescriptors[dwFieldID].cpft == CPFT_PASSWORD_TEXT))
    {
        CoTaskMemFree(_rgFieldStrings[dwFieldID]);
        return SHStrDupW(pwz, &_rgFieldStrings[dwFieldID]);
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_INVALIDARG; }
HRESULT CSampleCredential::SetCheckboxValue(DWORD, BOOL) { return E_INVALIDARG; }

HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX)
    {
        *pcItems = _countof(s_rgUnlockMethodStrings);
        *pdwSelectedItem = _dwSelectedMethod;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX && dwItem < _countof(s_rgUnlockMethodStrings))
        return SHStrDupW(s_rgUnlockMethodStrings[dwItem], ppwszItem);
    return E_INVALIDARG;
}

HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX && dwSelectedItem < _countof(s_rgUnlockMethodStrings))
    {
        _dwSelectedMethod = dwSelectedItem;
        g_dwSelectedMethod.store(dwSelectedItem);

        if (_pCredProvCredentialEvents)
        {
            // Removed Begin/EndFieldUpdates (not needed)
            CREDENTIAL_PROVIDER_FIELD_STATE cpfsPassword = (_dwSelectedMethod == 2) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            CREDENTIAL_PROVIDER_FIELD_STATE cpfsBypass = (_dwSelectedMethod == 3) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, cpfsPassword);

            PCWSTR status = L"Awaiting phone app authorization confirmation...";
            if (_dwSelectedMethod == 1) status = L"Unlock your connected mobile screen to proceed...";
            else if (_dwSelectedMethod == 2) status = L"Provide local TPM authorization credential.";
            _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, status);
        }
        return S_OK;
    }
    return E_INVALIDARG;
}

// -------------------------------------------------------------------
// Password packing helpers
// -------------------------------------------------------------------
HRESULT CSampleCredential::_PackActualPasswordCredential(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PCWSTR pszPassword)
{
    HRESULT hr = E_FAIL;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

    PWSTR pszDomain = nullptr;
    PWSTR pszUsername = nullptr;

    // Robust self-contained parsing engine to resolve explicit routing tokens for LSA
    if (_pszQualifiedUserName)
    {
        if (wcsstr(_pszQualifiedUserName, L"MicrosoftAccount\\") == _pszQualifiedUserName)
        {
            // 1) Microsoft Account format routing (Domain must be explicit, username is the raw email)
            hr = SHStrDupW(L"MicrosoftAccount", &pszDomain);
            if (SUCCEEDED(hr))
            {
                hr = SHStrDupW(_pszQualifiedUserName + 17, &pszUsername); // Skip "MicrosoftAccount\" (17 chars)
            }
        }
        else
        {
            const wchar_t* pchWhack = wcschr(_pszQualifiedUserName, L'\\');
            if (pchWhack)
            {
                // 2) Standard Local or Domain format (Domain\User)
                size_t lenDomain = pchWhack - _pszQualifiedUserName;
                pszDomain = (PWSTR)CoTaskMemAlloc((lenDomain + 1) * sizeof(WCHAR));
                if (pszDomain)
                {
                    wcsncpy_s(pszDomain, lenDomain + 1, _pszQualifiedUserName, lenDomain);
                    hr = SHStrDupW(pchWhack + 1, &pszUsername);
                }
                else hr = E_OUTOFMEMORY;
            }
            else
            {
                const wchar_t* pchAt = wcschr(_pszQualifiedUserName, L'@');
                if (pchAt)
                {
                    // 3) Pure UPN format (User@Domain)
                    size_t lenUser = pchAt - _pszQualifiedUserName;
                    pszUsername = (PWSTR)CoTaskMemAlloc((lenUser + 1) * sizeof(WCHAR));
                    if (pszUsername)
                    {
                        wcsncpy_s(pszUsername, lenUser + 1, _pszQualifiedUserName, lenUser);
                        hr = SHStrDupW(pchAt + 1, &pszDomain);
                    }
                    else hr = E_OUTOFMEMORY;
                }
                else
                {
                    // 4) Isolated Username Fallback - Fetch active machine profile context
                    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
                    DWORD size = ARRAYSIZE(computerName);
                    if (!GetComputerNameW(computerName, &size))
                        wcscpy_s(computerName, L".");

                    hr = SHStrDupW(computerName, &pszDomain);
                    if (SUCCEEDED(hr))
                    {
                        hr = SHStrDupW(_pszQualifiedUserName, &pszUsername);
                    }
                }
            }
        }
    }

    if (SUCCEEDED(hr) && pszUsername)
    {
        PWSTR pwzProtectedPassword = nullptr;
        hr = ProtectIfNecessaryAndCopyPassword(pszPassword, _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            KERB_INTERACTIVE_UNLOCK_LOGON kiul;
            ZeroMemory(&kiul, sizeof(kiul));
            hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
            if (SUCCEEDED(hr))
            {
                hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                if (SUCCEEDED(hr))
                {
                    ULONG ulAuthPackage = 0;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        hr = S_OK;
                    }
                }
            }
            CoTaskMemFree(pwzProtectedPassword);
        }
        CoTaskMemFree(pszDomain);
        CoTaskMemFree(pszUsername);
    }
    return hr;
}

HRESULT CSampleCredential::_GetStoredPasswordAndPack(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    HRESULT hr = E_FAIL;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        BYTE encryptedData[2048];
        DWORD dwSize = sizeof(encryptedData);
        DWORD dwType = 0;
        if (RegQueryValueExW(hKey, L"EncryptedPassword", nullptr, &dwType, encryptedData, &dwSize) == ERROR_SUCCESS)
        {
            DATA_BLOB dataIn = { dwSize, encryptedData };
            DATA_BLOB dataOut = { 0 };
            if (CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr,
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &dataOut))
            {
                // Calculate length strictly based on non-zero WCHARs to drop any padding artifacts
                size_t passwordLen = 0;
                const WCHAR* pChars = reinterpret_cast<const WCHAR*>(dataOut.pbData);
                size_t maxChars = dataOut.cbData / sizeof(WCHAR);

                while (passwordLen < maxChars && pChars[passwordLen] != L'\0')
                {
                    passwordLen++;
                }

                PWSTR pszDecryptedPassword = (PWSTR)CoTaskMemAlloc((passwordLen + 1) * sizeof(WCHAR));
                if (pszDecryptedPassword)
                {
                    CopyMemory(pszDecryptedPassword, dataOut.pbData, passwordLen * sizeof(WCHAR));
                    pszDecryptedPassword[passwordLen] = L'\0'; // Hard null-termination

                    // Pack the completely sanitized password string
                    hr = _PackActualPasswordCredential(pcpgsr, pcpcs, pszDecryptedPassword);

                    SecureZeroMemory(pszDecryptedPassword, (passwordLen + 1) * sizeof(WCHAR));
                    CoTaskMemFree(pszDecryptedPassword);
                }
                SecureZeroMemory(dataOut.pbData, dataOut.cbData);
                LocalFree(dataOut.pbData);
            }
        }
        RegCloseKey(hKey);
    }
    return hr;
}

bool CSampleCredential::_IsEncryptedPasswordBlobPresent()
{
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD dwType = 0;
    LONG res = RegQueryValueExW(hKey, L"EncryptedPassword", nullptr, &dwType, nullptr, nullptr);
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS && dwType == REG_BINARY);
}

// -------------------------------------------------------------------
// GetSerialization – FIX #1, #7
// -------------------------------------------------------------------
HRESULT CSampleCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    if (!pcpgsr || !pcpcs || !ppwszOptionalStatusText || !pcpsiOptionalStatusIcon)
        return E_INVALIDARG;

    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    if (!_IsEncryptedPasswordBlobPresent())
    {
        SHStrDupW(L"Tether not configured. Run Tether.Configuration.exe as Administrator.",
            ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    PWSTR pszCurrentTileSid = nullptr;
    if (FAILED(GetUserSid(&pszCurrentTileSid)) || !pszCurrentTileSid)
    {
        SHStrDupW(L"Security Error: Failed to resolve local identity scope context.",
            ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        CoTaskMemFree(pszCurrentTileSid);
        return S_FALSE;
    }
    CoTaskMemFree(pszCurrentTileSid);

    if (_dwSelectedMethod == 0)   // phone app
    {
        if (!g_fPhoneAppTriggered.load())
        {
            SHStrDupW(L"Tether App transmission signal undetected. Verify Bluetooth connectivity.",
                ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_FALSE;
        }
        HRESULT hr = _GetStoredPasswordAndPack(pcpgsr, pcpcs);
        g_fPhoneAppTriggered.store(false);
        g_fAutoLogonReady.store(false);
        if (SUCCEEDED(hr) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED)
            return S_OK;
        SHStrDupW(L"Tether App error: Local authentication credentials missing or corrupted.",
            ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }
    else if (_dwSelectedMethod == 1)   // phone screen
    {
        if (!g_fPhoneScreenTriggered.load())
        {
            SHStrDupW(L"Biometric mobile secure validation not yet established.",
                ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_FALSE;
        }
        HRESULT hr = _GetStoredPasswordAndPack(pcpgsr, pcpcs);
        g_fPhoneScreenTriggered.store(false);
        g_fAutoLogonReady.store(false);
        if (SUCCEEDED(hr) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED)
            return S_OK;
        SHStrDupW(L"Biometric link error: Local validation store is unreachable.",
            ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }
    else if (_dwSelectedMethod == 2)   // TPM password
    {
        if (!_rgFieldStrings[SFI_PASSWORD] || wcslen(_rgFieldStrings[SFI_PASSWORD]) == 0)
        {
            SHStrDupW(L"Please enter your local security validation credential.",
                ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_FALSE;
        }
        HRESULT hrVerify = _VerifySaltedPassword(_rgFieldStrings[SFI_PASSWORD]);
        if (FAILED(hrVerify))
        {
            if (_pCredProvCredentialEvents)
                _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
            size_t len = wcslen(_rgFieldStrings[SFI_PASSWORD]);
            SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], len * sizeof(WCHAR));
            SHStrDupW(L"Invalid security password or hash discrepancy.",
                ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_FALSE;
        }
        HRESULT hrPack = _PackActualPasswordCredential(pcpgsr, pcpcs, _rgFieldStrings[SFI_PASSWORD]);
        size_t len = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], len * sizeof(WCHAR));
        if (SUCCEEDED(hrPack) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED)
        {
            g_fAutoLogonReady.store(false);
            return S_OK;
        }
        SHStrDupW(L"System packaging fault encountered during interactive serialization.",
            ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    return E_UNEXPECTED;
}

// -------------------------------------------------------------------
// ReportResult
// -------------------------------------------------------------------
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (ntsStatus == STATUS_LOGON_FAILURE)
    {
        SHStrDupW(L"Tether login failed – check your password.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }
    else if (ntsStatus == STATUS_ACCOUNT_RESTRICTION && ntsSubstatus == STATUS_ACCOUNT_DISABLED)
    {
        SHStrDupW(L"Your Tether account is disabled. Contact support.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
    }

    if (FAILED(HRESULT_FROM_NT(ntsStatus)) && _pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
    return S_OK;
}

HRESULT CSampleCredential::GetUserSid(PWSTR* ppszSid)
{
    if (!_pszUserSid) return E_UNEXPECTED;
    return SHStrDupW(_pszUserSid, ppszSid);
}

// -------------------------------------------------------------------
// Password verification – FIX #11: salted hash using CryptHashData
// -------------------------------------------------------------------
HRESULT CSampleCredential::_VerifySaltedPassword(PCWSTR pwzEnteredPassword)
{
    // Read stored hash and salt from registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return E_FAIL;

    WCHAR szStoredHash[128];
    DWORD dwSize = sizeof(szStoredHash);
    DWORD dwType;
    if (RegQueryValueExW(hKey, L"PasswordHash", nullptr, &dwType, (LPBYTE)szStoredHash, &dwSize) != ERROR_SUCCESS || dwType != REG_SZ)
    {
        RegCloseKey(hKey);
        return E_FAIL;
    }

    BYTE salt[64];
    dwSize = sizeof(salt);
    if (RegQueryValueExW(hKey, L"PasswordSalt", nullptr, &dwType, salt, &dwSize) != ERROR_SUCCESS || dwType != REG_BINARY)
    {
        RegCloseKey(hKey);
        return E_FAIL;
    }
    RegCloseKey(hKey);

    // Convert password to UTF-8 bytes (Passing wcslen instead of -1 excludes the null terminator)
    int cchPassword = (int)wcslen(pwzEnteredPassword);
    int cbNeeded = WideCharToMultiByte(CP_UTF8, 0, pwzEnteredPassword, cchPassword, nullptr, 0, nullptr, nullptr);
    if (cbNeeded <= 0) return E_FAIL;

    std::vector<BYTE> passwordBytes(cbNeeded);
    if (WideCharToMultiByte(CP_UTF8, 0, pwzEnteredPassword, cchPassword, (LPSTR)passwordBytes.data(), (int)passwordBytes.size(), nullptr, nullptr) == 0)
        return E_FAIL;

    // Combine salt + password cleanly (No need to subtract 1 anymore!)
    std::vector<BYTE> combined;
    combined.reserve(dwSize + cbNeeded);
    combined.insert(combined.end(), salt, salt + dwSize);
    combined.insert(combined.end(), passwordBytes.begin(), passwordBytes.end());

    // Compute SHA-256 using CryptoAPI
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return E_FAIL;
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return E_FAIL;
    }
    if (!CryptHashData(hHash, combined.data(), (DWORD)combined.size(), 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return E_FAIL;
    }
    BYTE hash[32];
    DWORD cbHash = 32;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &cbHash, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return E_FAIL;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // Convert to hex string
    WCHAR computedHex[65];
    for (int i = 0; i < 32; i++)
        swprintf_s(&computedHex[i * 2], 3, L"%02x", hash[i]);
    computedHex[64] = 0;
    WriteDebugLog(L"Stored hash: %s", szStoredHash);
    WriteDebugLog(L"Computed hex: %s", computedHex);
    return (_wcsicmp(computedHex, szStoredHash) == 0) ? S_OK : E_FAIL;


    WriteDebugLog(L"Stored hash: %s", szStoredHash);
    WriteDebugLog(L"Computed hex: %s", computedHex);
}

// Old method kept for compatibility (not used)
HRESULT CSampleCredential::_VerifyTpmPassword(PCWSTR) { return E_NOTIMPL; }
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    // No command links are used in this credential provider.
    return E_INVALIDARG;
}
// -------------------------------------------------------------------
// Field options
// -------------------------------------------------------------------
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo)
{
    *pcpcfo = CPCFO_NONE;
    if (dwFieldID == SFI_PASSWORD)
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    else if (dwFieldID == SFI_TILEIMAGE)
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    return S_OK;
}

// -------------------------------------------------------------------
// Event callbacks – FIX #12
// -------------------------------------------------------------------
void CALLBACK CSampleCredential::_OnAppEventSignaled(PVOID lpParameter, BOOLEAN)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;

    if (pThis->_hWndMessage && !g_fPhoneAppTriggered.load())
    {
        g_fPhoneAppTriggered.store(true);
        g_fAutoLogonReady.store(true);
        if (pThis->_hAppEvent) ResetEvent(pThis->_hAppEvent);
        PostMessageW(pThis->_hWndMessage, WM_SIGNAL_CREDENTIALS_CHANGED, 0, reinterpret_cast<LPARAM>(pThis));
    }
}

void CALLBACK CSampleCredential::_OnScreenEventSignaled(PVOID lpParameter, BOOLEAN)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;

    if (pThis->_hWndMessage && !g_fPhoneScreenTriggered.load())
    {
        g_fPhoneScreenTriggered.store(true);
        g_fAutoLogonReady.store(true);
        if (pThis->_hScreenEvent) ResetEvent(pThis->_hScreenEvent);
        PostMessageW(pThis->_hWndMessage, WM_SIGNAL_CREDENTIALS_CHANGED, 0, reinterpret_cast<LPARAM>(pThis));
    }
}

void CSampleCredential::_StartBackgroundIPCListeners()
{
    if (g_fAutoLogonReady.load() || g_fPhoneAppTriggered.load() ||
        g_fPhoneScreenTriggered.load() || g_fBypassTriggered.load())
        return;

    _hAppEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, L"Global\\TetherPhoneAppUnlocked");
    if (_hAppEvent)
    {
        RegisterWaitForSingleObject(&_hWaitApp, _hAppEvent,
            CSampleCredential::_OnAppEventSignaled, this,
            INFINITE, WT_EXECUTEDEFAULT);
    }

    _hScreenEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, L"Global\\TetherPhoneScreenUnlocked");
    if (_hScreenEvent)
    {
        RegisterWaitForSingleObject(&_hWaitScreen, _hScreenEvent,
            CSampleCredential::_OnScreenEventSignaled, this,
            INFINITE, WT_EXECUTEONLYONCE);
    }
}

void CALLBACK CSampleCredential::_OnIPCEventSignaled(PVOID lpParameter, BOOLEAN)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (pThis && pThis->_pProvider && pThis->_isValid.load())
    {
        g_fAutoLogonReady.store(true);
        pThis->_pProvider->SignalCredentialsChanged();
    }
}

void CSampleCredential::_CreateMessageWindow()
{
    WNDCLASSEXW wcex = { sizeof(wcex) };
    wcex.lpfnWndProc = CSampleCredential::WebAuthMsgProc;
    wcex.hInstance = HINST_THISDLL;
    wcex.lpszClassName = L"TetherMessageWindowPool";
    RegisterClassExW(&wcex);
    _hWndMessage = CreateWindowExW(0, wcex.lpszClassName, nullptr, 0, 0, 0, 0, 0,
        HWND_MESSAGE, nullptr, HINST_THISDLL, this);
}

void WriteDebugLog(const wchar_t* format, ...)
{
    wchar_t buf[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(buf, sizeof(buf) / sizeof(wchar_t), format, args);
    va_end(args);
    OutputDebugStringW(buf);
    OutputDebugStringW(L"\n");
}

void CSampleCredential::_DestroyMessageWindow()
{
    if (_hWndMessage)
    {
        DestroyWindow(_hWndMessage);
        _hWndMessage = nullptr;
        UnregisterClassW(L"TetherMessageWindowPool", HINST_THISDLL);
    }
}