#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <winreg.h>
#include <vector>
#include <cstring>
#include <cstdarg>
#include "TetherCredential.h"
#include "TetherProvider.h"
#include "guid.h"
#include "TetherCredentialGlobals.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#define WM_SIGNAL_CREDENTIALS_CHANGED (WM_USER + 101)

void WriteDebugLog(const wchar_t* format, ...);

static HBITMAP CreateFallbackLogoBitmap(int cx, int cy)
{
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = cx;
    bmi.bmiHeader.biHeight = -cy;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP hbmp = CreateDIBSection(nullptr, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!hbmp) return nullptr;

    HDC dc = CreateCompatibleDC(nullptr);
    HGDIOBJ old = SelectObject(dc, hbmp);

    RECT rc = { 0, 0, cx, cy };
    HBRUSH bg = CreateSolidBrush(RGB(0x00, 0x78, 0xD4));
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    int pw = cx / 3;
    int ph = cy / 2;
    RECT prc = { (cx - pw) / 2, (cy - ph) / 2, (cx + pw) / 2, (cy + ph) / 2 };
    HBRUSH wb = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(dc, &prc, wb);
    DeleteObject(wb);

    HBRUSH bb = CreateSolidBrush(RGB(0x00, 0x78, 0xD4));
    RECT slot = { prc.left + pw / 3, prc.top + ph / 10, prc.right - pw / 3, prc.top + ph / 6 };
    FillRect(dc, &slot, bb);
    DeleteObject(bb);

    SelectObject(dc, old);
    DeleteDC(dc);
    return hbmp;
}

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

    if (_hWaitApp)
    {
        UnregisterWait(_hWaitApp);
        _hWaitApp = nullptr;
    }
    if (_hWaitScreen)
    {
        UnregisterWait(_hWaitScreen);
        _hWaitScreen = nullptr;
    }
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

    _dwSelectedMethod = 0;
    g_dwSelectedMethod.store(0);

    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    _rgFieldStatePairs[SFI_METHOD_COMBOBOX].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_METHOD_LABEL].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[SFI_SUBMIT_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[SFI_LOGONSTATUS_TEXT].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;

    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Tether Pro Gateway", &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Sign in using Tether", &_rgFieldStrings[SFI_LARGE_TEXT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Open the Tether app on your phone and tap 'Unlock PC'", &_rgFieldStrings[SFI_METHOD_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Unlock via Phone App", &_rgFieldStrings[SFI_METHOD_COMBOBOX]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Unlock", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Waiting for the Tether app on your phone...", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);

    if (SUCCEEDED(hr)) hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    if (SUCCEEDED(hr)) hr = pcpUser->GetSid(&_pszUserSid);

    _CreateMessageWindow();
    _StartBackgroundIPCListeners();

    return hr;
}

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
    return S_OK;
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
        return SHStrDupW(_rgFieldStrings[dwFieldID] ? _rgFieldStrings[dwFieldID] : L"", ppwsz);
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (dwFieldID != SFI_TILEIMAGE)
        return E_INVALIDARG;

    HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
    if (!hbmp)
        hbmp = CreateFallbackLogoBitmap(128, 128);

    if (!hbmp)
        return HRESULT_FROM_WIN32(GetLastError());

    *phbmp = hbmp;
    return S_OK;
}

HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID == SFI_SUBMIT_BUTTON)
    {
        *pdwAdjacentTo = SFI_METHOD_LABEL;
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
        *pcItems = 1;
        *pdwSelectedItem = 0;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX && dwItem == 0)
        return SHStrDupW(L"Unlock via Phone App", ppwszItem);
    return E_INVALIDARG;
}

HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX)
    {
        _dwSelectedMethod = 0;
        g_dwSelectedMethod.store(0);
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::_PackActualPasswordCredential(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PCWSTR pszPassword)
{
    HRESULT hr = E_FAIL;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

    PWSTR pszDomain = nullptr;
    PWSTR pszUsername = nullptr;

    if (_pszQualifiedUserName)
    {
        if (wcsstr(_pszQualifiedUserName, L"MicrosoftAccount\\") == _pszQualifiedUserName)
        {
            hr = SHStrDupW(L"MicrosoftAccount", &pszDomain);
            if (SUCCEEDED(hr))
            {
                hr = SHStrDupW(_pszQualifiedUserName + 17, &pszUsername);
            }
        }
        else
        {
            const wchar_t* pchWhack = wcschr(_pszQualifiedUserName, L'\\');
            if (pchWhack)
            {
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
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey);
    }

    if (hKey != nullptr)
    {
        BYTE encryptedData[2048];
        DWORD dwSize = sizeof(encryptedData);
        DWORD dwType = 0;
        if (RegQueryValueExW(hKey, L"EncryptedPassword", nullptr, &dwType, encryptedData, &dwSize) == ERROR_SUCCESS)
        {
            DATA_BLOB dataIn = { dwSize, encryptedData };
            DATA_BLOB dataOut = { 0 };

            BYTE entropyBytes[] = "Tether_System_Bound_Vault_v1";
            DATA_BLOB entropyBlob = { sizeof(entropyBytes) - 1, entropyBytes };

            if (CryptUnprotectData(&dataIn, nullptr, &entropyBlob, nullptr, nullptr,
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &dataOut))
            {
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
                    pszDecryptedPassword[passwordLen] = L'\0';

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

HRESULT CSampleCredential::_GetManualPasswordAndPack(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    if (!_rgFieldStrings[SFI_PASSWORD] || wcslen(_rgFieldStrings[SFI_PASSWORD]) == 0)
        return S_FALSE;

    HRESULT hrPack = _PackActualPasswordCredential(pcpgsr, pcpcs, _rgFieldStrings[SFI_PASSWORD]);
    size_t len = wcslen(_rgFieldStrings[SFI_PASSWORD]);
    SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], len * sizeof(WCHAR));
    if (SUCCEEDED(hrPack) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED)
    {
        g_fAutoLogonReady.store(false);
        return S_OK;
    }
    return E_FAIL;
}

bool CSampleCredential::_IsEncryptedPasswordBlobPresent()
{
    const wchar_t* subKeys[] =
    {
        L"SOFTWARE\\Tether\\CredentialProvider\\Secrets",
        L"SOFTWARE\\Tether\\CredentialProvider"
    };

    for (const wchar_t* subKey : subKeys)
    {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        DWORD dwType = 0;
        LONG res = RegQueryValueExW(hKey, L"EncryptedPassword", nullptr, &dwType, nullptr, nullptr);
        RegCloseKey(hKey);

        if (res == ERROR_SUCCESS && dwType == REG_BINARY)
            return true;
    }
    return false;
}

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

    PWSTR pszCurrentTileSid = nullptr;
    if (FAILED(GetUserSid(&pszCurrentTileSid)) || !pszCurrentTileSid)
    {
        SHStrDupW(L"Security Error: Failed to resolve local identity scope context.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        CoTaskMemFree(pszCurrentTileSid);
        return S_FALSE;
    }
    CoTaskMemFree(pszCurrentTileSid);

    if (!g_fPhoneAppTriggered.load())
    {
        SHStrDupW(L"Open the Tether app on your phone and tap 'Unlock PC'.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_FALSE;
    }

    HRESULT hr = _GetStoredPasswordAndPack(pcpgsr, pcpcs);
    g_fPhoneAppTriggered.store(false);
    g_fAutoLogonReady.store(false);
    if (SUCCEEDED(hr) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED)
        return S_OK;

    SHStrDupW(L"Tether App error: Local authentication credentials missing or corrupted.", ppwszOptionalStatusText);
    *pcpsiOptionalStatusIcon = CPSI_ERROR;
    return S_FALSE;
}

HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (ntsStatus == STATUS_LOGON_FAILURE)
    {
        SHStrDupW(L"Tether login failed.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }
    else if (ntsStatus == STATUS_ACCOUNT_RESTRICTION && ntsSubstatus == STATUS_ACCOUNT_DISABLED)
    {
        SHStrDupW(L"Your Tether account is disabled. Contact support.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
    }
    return S_OK;
}

HRESULT CSampleCredential::GetUserSid(PWSTR* ppszSid)
{
    if (!_pszUserSid) return E_UNEXPECTED;
    return SHStrDupW(_pszUserSid, ppszSid);
}

static bool ConstantTimeWcsEquals(PCWSTR a, PCWSTR b)
{
    if (!a || !b) return false;
    size_t lenA = wcslen(a);
    size_t lenB = wcslen(b);
    size_t maxLen = (lenA > lenB) ? lenA : lenB;

    int diff = (int)(lenA ^ lenB);
    for (size_t i = 0; i < maxLen; i++)
    {
        WCHAR ca = (i < lenA) ? a[i] : 0;
        WCHAR cb = (i < lenB) ? b[i] : 0;
        diff |= (ca ^ cb);
    }
    return diff == 0;
}

static bool DerivePbkdf2Key(LPCWSTR algId, const BYTE* password, DWORD cbPassword, const BYTE* salt, DWORD cbSalt, DWORD iterations, BYTE* derivedKey, DWORD cbDerivedKey)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, algId, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return false;

    NTSTATUS status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password, cbPassword, (PUCHAR)salt, cbSalt, iterations, derivedKey, cbDerivedKey, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return status == 0;
}

HRESULT CSampleCredential::_VerifySaltedPassword(PCWSTR pwzEnteredPassword)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return E_FAIL;
    }

    WCHAR szAlgorithm[64] = L"sha256-v1";
    DWORD dwSize = sizeof(szAlgorithm);
    DWORD dwType = 0;
    RegQueryValueExW(hKey, L"HashAlgorithm", nullptr, &dwType, (LPBYTE)szAlgorithm, &dwSize);

    WCHAR szStoredHash[256];
    dwSize = sizeof(szStoredHash);
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
    DWORD saltLen = dwSize;
    RegCloseKey(hKey);

    int cchPassword = (int)wcslen(pwzEnteredPassword);
    int cbNeeded = WideCharToMultiByte(CP_UTF8, 0, pwzEnteredPassword, cchPassword, nullptr, 0, nullptr, nullptr);
    if (cbNeeded <= 0) return E_FAIL;

    std::vector<BYTE> passwordBytes(cbNeeded);
    if (WideCharToMultiByte(CP_UTF8, 0, pwzEnteredPassword, cchPassword, (LPSTR)passwordBytes.data(), (int)passwordBytes.size(), nullptr, nullptr) == 0)
        return E_FAIL;

    if (wcscmp(szAlgorithm, L"pbkdf2-sha256-600k") == 0)
    {
        BYTE derived[32];
        if (!DerivePbkdf2Key(BCRYPT_SHA256_ALGORITHM, passwordBytes.data(), (DWORD)passwordBytes.size(), salt, saltLen, 600000, derived, sizeof(derived)))
            return E_FAIL;

        WCHAR computedHex[65];
        for (int i = 0; i < 32; i++)
            swprintf_s(&computedHex[i * 2], 3, L"%02x", derived[i]);
        computedHex[64] = 0;

        return ConstantTimeWcsEquals(computedHex, szStoredHash) ? S_OK : E_FAIL;
    }
    else if (wcscmp(szAlgorithm, L"pbkdf2-sha512-210k") == 0)
    {
        BYTE derived[64];
        if (!DerivePbkdf2Key(BCRYPT_SHA512_ALGORITHM, passwordBytes.data(), (DWORD)passwordBytes.size(), salt, saltLen, 210000, derived, sizeof(derived)))
            return E_FAIL;

        WCHAR computedHex[129];
        for (int i = 0; i < 64; i++)
            swprintf_s(&computedHex[i * 2], 3, L"%02x", derived[i]);
        computedHex[128] = 0;

        return ConstantTimeWcsEquals(computedHex, szStoredHash) ? S_OK : E_FAIL;
    }
    else
    {
        std::vector<BYTE> combined;
        combined.reserve(saltLen + cbNeeded);
        combined.insert(combined.end(), salt, salt + saltLen);
        combined.insert(combined.end(), passwordBytes.begin(), passwordBytes.end());

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

        WCHAR computedHex[65];
        for (int i = 0; i < 32; i++)
            swprintf_s(&computedHex[i * 2], 3, L"%02x", hash[i]);
        computedHex[64] = 0;

        bool isOk = ConstantTimeWcsEquals(computedHex, szStoredHash);
        if (isOk)
        {
            BYTE newDerived[32];
            if (DerivePbkdf2Key(BCRYPT_SHA256_ALGORITHM, passwordBytes.data(), (DWORD)passwordBytes.size(), salt, saltLen, 600000, newDerived, sizeof(newDerived)))
            {
                WCHAR newHex[65];
                for (int i = 0; i < 32; i++)
                    swprintf_s(&newHex[i * 2], 3, L"%02x", newDerived[i]);
                newHex[64] = 0;

                HKEY hWriteKey = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_SET_VALUE, &hWriteKey) == ERROR_SUCCESS ||
                    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_SET_VALUE, &hWriteKey) == ERROR_SUCCESS)
                {
                    RegSetValueExW(hWriteKey, L"PasswordHash", 0, REG_SZ, (LPBYTE)newHex, (DWORD)((wcslen(newHex) + 1) * sizeof(WCHAR)));
                    const WCHAR* newAlg = L"pbkdf2-sha256-600k";
                    RegSetValueExW(hWriteKey, L"HashAlgorithm", 0, REG_SZ, (LPBYTE)newAlg, (DWORD)((wcslen(newAlg) + 1) * sizeof(WCHAR)));
                    RegCloseKey(hWriteKey);
                }
            }
        }
        return isOk ? S_OK : E_FAIL;
    }
}

HRESULT CSampleCredential::_VerifyTpmPassword(PCWSTR) { return E_NOTIMPL; }

HRESULT CSampleCredential::CommandLinkClicked(DWORD)
{
    return E_INVALIDARG;
}

HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo)
{
    *pcpcfo = CPCFO_NONE;
    if (dwFieldID == SFI_TILEIMAGE)
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    return S_OK;
}

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
    if (g_fAutoLogonReady.load() || g_fPhoneAppTriggered.load())
        return;

    _hAppEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, L"Global\\TetherPhoneAppUnlocked");
    if (_hAppEvent == nullptr)
    {
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
        _hAppEvent = CreateEventW(&sa, TRUE, FALSE, L"Global\\TetherPhoneAppUnlocked");
        if (_hAppEvent)
            WriteDebugLog(L"Created missing global event: TetherPhoneAppUnlocked");
    }

    if (_hAppEvent)
    {
        RegisterWaitForSingleObject(&_hWaitApp, _hAppEvent,
            CSampleCredential::_OnAppEventSignaled, this,
            INFINITE, WT_EXECUTEDEFAULT);
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
        UnregisterClassW(L"TetherMessagePool", HINST_THISDLL);
    }
}