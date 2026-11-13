#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <winreg.h>
#include <sddl.h>
#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")
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
#define WM_PROMPT_COOLDOWN_TICK (WM_USER + 102)
#define WM_STATUS_UPDATE (WM_USER + 103)

// Named event consumed by the communication service, which relays an
// UNLOCK_PROMPT frame to the paired phone over the TLS control channel.
static const wchar_t c_wszUnlockPromptEventName[] = L"Global\\TetherUnlockPromptRequested";
static const int c_promptCooldownSeconds = 3;

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
    _cpus(CPUS_INVALID),
    _pProvider(nullptr),
    _hWndMessage(nullptr),
    _hAppEvent(nullptr),
    _hScreenEvent(nullptr),
    _hPhoneConnectedEvent(nullptr),
    _hWaitApp(nullptr),
    _hWaitScreen(nullptr),
    _hWaitPhoneConnected(nullptr),
    _pCooldownTimer(nullptr),
    _pStatusTimer(nullptr),
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

    if (_pStatusTimer)
    {
        SetThreadpoolTimer(_pStatusTimer, nullptr, 0, 0);
        WaitForThreadpoolTimerCallbacks(_pStatusTimer, TRUE);
        CloseThreadpoolTimer(_pStatusTimer);
        _pStatusTimer = nullptr;
    }
    if (_hWaitPhoneConnected)
    {
        UnregisterWaitEx(_hWaitPhoneConnected, INVALID_HANDLE_VALUE);
        _hWaitPhoneConnected = nullptr;
    }
    if (_hPhoneConnectedEvent)
    {
        CloseHandle(_hPhoneConnectedEvent);
        _hPhoneConnectedEvent = nullptr;
    }

    if (_hWaitApp)
    {
        UnregisterWaitEx(_hWaitApp, INVALID_HANDLE_VALUE);
        _hWaitApp = nullptr;
    }
    if (_hWaitScreen)
    {
        UnregisterWaitEx(_hWaitScreen, INVALID_HANDLE_VALUE);
        _hWaitScreen = nullptr;
    }

    if (_hAppEvent) CloseHandle(_hAppEvent);
    if (_hScreenEvent) CloseHandle(_hScreenEvent);
    if (_pCooldownTimer)
    {
        SetThreadpoolTimer(_pCooldownTimer, nullptr, 0, 0);
        WaitForThreadpoolTimerCallbacks(_pCooldownTimer, TRUE);
        CloseThreadpoolTimer(_pCooldownTimer);
        _pCooldownTimer = nullptr;
    }
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
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}

LRESULT CALLBACK CSampleCredential::WebAuthMsgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // WM_NCCREATE carries the lpParam passed to CreateWindowExW ('this'); stashed
    // here so messages that don't route it explicitly (WM_TIMER) can find the owner.
    if (uMsg == WM_NCCREATE)
    {
        CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(
            reinterpret_cast<LPCREATESTRUCTW>(lParam)->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        return DefWindowProcW(hWnd, uMsg, wParam, lParam);
    }

    auto pThis = reinterpret_cast<CSampleCredential*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));

    if (uMsg == WM_SIGNAL_CREDENTIALS_CHANGED)
    {
        if (pThis && pThis->_pProvider)
            pThis->_pProvider->SignalCredentialsChanged();
        return 0;
    }
    if (uMsg == WM_PROMPT_COOLDOWN_TICK)
    {
        if (pThis) pThis->_OnCooldownTick();
        return 0;
    }
    if (uMsg == WM_STATUS_UPDATE)
    {
        if (pThis) pThis->_CheckStatusAndRefreshUi();
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
    _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_SERVICE_ACTION_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;

    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Tether", &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Sign in using Tether", &_rgFieldStrings[SFI_LARGE_TEXT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Open the Tether app on your phone and tap 'Unlock PC'", &_rgFieldStrings[SFI_METHOD_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Unlock via Phone App", &_rgFieldStrings[SFI_METHOD_COMBOBOX]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Unlock", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Checking Tether service...", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Send unlock prompt to phone", &_rgFieldStrings[SFI_UNLOCK_PROMPT_BUTTON]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Restart Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);

    if (SUCCEEDED(hr)) hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    if (SUCCEEDED(hr)) hr = pcpUser->GetSid(&_pszUserSid);

    _CreateMessageWindow();
    _StartBackgroundIPCListeners();

    _pStatusTimer = CreateThreadpoolTimer(CSampleCredential::_OnStatusTimerFired, this, nullptr);
    if (_pStatusTimer)
    {
        LONG64 due100ns = -1000000LL; // 100ms
        FILETIME ftDue = *reinterpret_cast<FILETIME*>(&due100ns);
        SetThreadpoolTimer(_pStatusTimer, &ftDue, 1500, 0);
    }

    return hr;
}

HRESULT CSampleCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    try
    {
        if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
        return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::UnAdvise()
{
    try
    {
        if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = nullptr;
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::SetSelected(BOOL* pbAutoLogon)
{
    try
    {
        *pbAutoLogon = FALSE;
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::SetDeselected()
{
    return S_OK;
}

HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    try
    {
        if (dwFieldID < ARRAYSIZE(_rgFieldStatePairs))
        {
            *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
            *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
            return S_OK;
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    try
    {
        if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
            return SHStrDupW(_rgFieldStrings[dwFieldID] ? _rgFieldStrings[dwFieldID] : L"", ppwsz);
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    try
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
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    try
    {
        if (dwFieldID == SFI_SUBMIT_BUTTON)
        {
            *pdwAdjacentTo = SFI_METHOD_LABEL;
            return S_OK;
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    try
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
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_INVALIDARG; }
HRESULT CSampleCredential::SetCheckboxValue(DWORD, BOOL) { return E_INVALIDARG; }

HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem)
{
    try
    {
        if (dwFieldID == SFI_METHOD_COMBOBOX)
        {
            *pcItems = 1;
            *pdwSelectedItem = 0;
            return S_OK;
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem)
{
    try
    {
        if (dwFieldID == SFI_METHOD_COMBOBOX && dwItem == 0)
            return SHStrDupW(L"Unlock via Phone App", ppwszItem);
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD)
{
    try
    {
        if (dwFieldID == SFI_METHOD_COMBOBOX)
        {
            g_dwSelectedMethod.store(0);
            return S_OK;
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
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
    try
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

    // Check target user SID if configured in registry secrets to prevent cross-tile starvation
    HKEY hKeyVault = nullptr;
    WCHAR szTargetSid[128] = { 0 };
    DWORD dwTargetSidLen = sizeof(szTargetSid);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ, &hKeyVault) == ERROR_SUCCESS ||
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKeyVault) == ERROR_SUCCESS)
    {
        RegQueryValueExW(hKeyVault, L"TargetUserSid", nullptr, nullptr, (LPBYTE)szTargetSid, &dwTargetSidLen);
        RegCloseKey(hKeyVault);
    }

    if (szTargetSid[0] != L'\0' && _wcsicmp(szTargetSid, pszCurrentTileSid) != 0)
    {
        WriteDebugLog(L"GetSerialization: tile SID (%ls) does not match target SID (%ls). Skipping tile.", pszCurrentTileSid, szTargetSid);
        CoTaskMemFree(pszCurrentTileSid);
        return S_FALSE; // Not for this user; preserve trigger flag for targeted user tile
    }
    CoTaskMemFree(pszCurrentTileSid);

    bool isTriggered = _fInstancePhoneAppTriggered.exchange(false) || g_fPhoneAppTriggered.load();
    if (!isTriggered)
    {
        SHStrDupW(L"Open the Tether app on your phone and tap 'Unlock PC'.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_FALSE;
    }

    HRESULT hr = _GetStoredPasswordAndPack(pcpgsr, pcpcs);
    g_fPhoneAppTriggered.store(false);
    g_fAutoLogonReady.store(false);
    _fInstanceAutoLogonReady.store(false);

    if (SUCCEEDED(hr) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED)
    {
        WriteDebugLog(L"GetSerialization: Successfully packaged credentials for logon.");
        return S_OK;
    }

    WriteDebugLog(L"GetSerialization: _GetStoredPasswordAndPack failed (hr=0x%08X).", hr);
    SHStrDupW(L"Tether App error: Local authentication credentials missing or corrupted.", ppwszOptionalStatusText);
    *pcpsiOptionalStatusIcon = CPSI_ERROR;
    return S_FALSE;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    try
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
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleCredential::GetUserSid(PWSTR* ppszSid)
{
    if (_pszUserSid)
    {
        return SHStrDupW(_pszUserSid, ppszSid);
    }

    if (_pszQualifiedUserName && _pszQualifiedUserName[0] != L'\0')
    {
        DWORD cbSid = 0;
        DWORD cchDomain = 0;
        SID_NAME_USE sidType;
        LookupAccountNameW(nullptr, _pszQualifiedUserName, nullptr, &cbSid, nullptr, &cchDomain, &sidType);
        if (cbSid > 0)
        {
            BYTE* pSid = (BYTE*)LocalAlloc(LPTR, cbSid);
            WCHAR* pDomain = (WCHAR*)LocalAlloc(LPTR, (cchDomain > 0 ? cchDomain : 1) * sizeof(WCHAR));
            if (pSid && pDomain)
            {
                if (LookupAccountNameW(nullptr, _pszQualifiedUserName, pSid, &cbSid, pDomain, &cchDomain, &sidType))
                {
                    LPWSTR pStrSid = nullptr;
                    if (ConvertSidToStringSidW(pSid, &pStrSid) && pStrSid)
                    {
                        HRESULT hr = SHStrDupW(pStrSid, ppszSid);
                        LocalFree(pStrSid);
                        LocalFree(pSid);
                        LocalFree(pDomain);
                        return hr;
                    }
                }
            }
            if (pSid) LocalFree(pSid);
            if (pDomain) LocalFree(pDomain);
        }
    }

    return E_UNEXPECTED;
}

void CSampleCredential::_CheckStatusAndRefreshUi()
{
    if (!_isValid.load() || _fServiceActionInProgress.load()) return;

    bool isServiceRunning = false;
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        SC_HANDLE hSvc = OpenServiceW(hSCM, L"TetherCommService", SERVICE_QUERY_STATUS);
        if (hSvc)
        {
            SERVICE_STATUS_PROCESS ssp = {};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
            {
                isServiceRunning = (ssp.dwCurrentState == SERVICE_RUNNING);
            }
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }
    _fServiceRunning.store(isServiceRunning);

    bool isPhoneConnected = false;
    if (isServiceRunning)
    {
        HANDLE hPhone = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\TetherPhoneConnected");
        if (hPhone)
        {
            isPhoneConnected = (WaitForSingleObject(hPhone, 0) == WAIT_OBJECT_0);
            CloseHandle(hPhone);
        }
    }
    _fPhoneConnected.store(isPhoneConnected);

    if (_pCredProvCredentialEvents)
    {
        if (!isServiceRunning)
        {
            _SetStatusText(L"Tether service is not running");
            CoTaskMemFree(_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            SHStrDupW(L"Start Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            _pCredProvCredentialEvents->SetFieldString(this, SFI_SERVICE_ACTION_BUTTON, L"Start Tether Service");
            _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_SERVICE_ACTION_BUTTON, CPFIS_NONE);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);

            _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFS_HIDDEN);
        }
        else if (!isPhoneConnected)
        {
            _SetStatusText(L"Phone: Disconnected");
            CoTaskMemFree(_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            SHStrDupW(L"Restart Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            _pCredProvCredentialEvents->SetFieldString(this, SFI_SERVICE_ACTION_BUTTON, L"Restart Tether Service");
            _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_SERVICE_ACTION_BUTTON, CPFIS_NONE);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);

            _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFS_HIDDEN);
        }
        else
        {
            _SetStatusText(L"Phone: Connected");
            CoTaskMemFree(_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            SHStrDupW(L"Restart Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            _pCredProvCredentialEvents->SetFieldString(this, SFI_SERVICE_ACTION_BUTTON, L"Restart Tether Service");
            _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_SERVICE_ACTION_BUTTON, CPFIS_NONE);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);

            _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _pCredProvCredentialEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);

            long long nowMs = GetTickCount64();
            long long endMs = _promptCooldownEndMs.load(std::memory_order_acquire);
            if (nowMs >= endMs)
            {
                _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_NONE);
            }
            else
            {
                _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_DISABLED);
            }
        }
    }
}

void CSampleCredential::_PerformServiceActionAsync()
{
    struct ActionContext
    {
        CSampleCredential* pThis;
    };

    auto* ctx = new (std::nothrow) ActionContext{ this };
    if (!ctx) return;

    QueueUserWorkItem([](PVOID param) -> DWORD
    {
        auto* c = reinterpret_cast<ActionContext*>(param);
        if (c && c->pThis && c->pThis->_isValid.load())
        {
            SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (hSCM)
            {
                SC_HANDLE hSvc = OpenServiceW(hSCM, L"TetherCommService", SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
                if (hSvc)
                {
                    SERVICE_STATUS_PROCESS ssp = {};
                    DWORD bytesNeeded = 0;
                    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
                    {
                        if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING)
                        {
                            SERVICE_STATUS stopStatus = {};
                            ControlService(hSvc, SERVICE_CONTROL_STOP, &stopStatus);
                            for (int i = 0; i < 20; i++)
                            {
                                Sleep(250);
                                if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
                                {
                                    if (ssp.dwCurrentState == SERVICE_STOPPED) break;
                                }
                            }
                        }
                    }

                    StartServiceW(hSvc, 0, nullptr);
                    for (int i = 0; i < 20; i++)
                    {
                        Sleep(250);
                        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
                        {
                            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
                        }
                    }

                    CloseServiceHandle(hSvc);
                }
                CloseServiceHandle(hSCM);
            }

            c->pThis->_fServiceActionInProgress.store(false);
            if (c->pThis->_hWndMessage)
            {
                PostMessageW(c->pThis->_hWndMessage, WM_STATUS_UPDATE, 0, 0);
            }
        }
        delete c;
        return 0;
    }, ctx, WT_EXECUTEDEFAULT);
}

void CALLBACK CSampleCredential::_OnStatusTimerFired(PTP_CALLBACK_INSTANCE, PVOID lpParameter, PTP_TIMER)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;
    if (pThis->_hWndMessage)
        PostMessageW(pThis->_hWndMessage, WM_STATUS_UPDATE, 0, 0);
}

void CALLBACK CSampleCredential::_OnPhoneConnectedSignaled(PVOID lpParameter, BOOLEAN)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;
    if (pThis->_hWndMessage)
        PostMessageW(pThis->_hWndMessage, WM_STATUS_UPDATE, 0, 0);
}

HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    try
    {
        if (dwFieldID == SFI_SERVICE_ACTION_BUTTON)
        {
            if (_fServiceActionInProgress.exchange(true))
                return S_OK;

            bool isRestart = _fServiceRunning.load();
            _SetStatusText(isRestart ? L"Restarting Tether service..." : L"Starting Tether service...");
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_SERVICE_ACTION_BUTTON, CPFIS_DISABLED);
            }
            _PerformServiceActionAsync();
            return S_OK;
        }

        if (dwFieldID != SFI_UNLOCK_PROMPT_BUTTON)
            return E_INVALIDARG;

        if (!_fPhoneConnected.load())
            return S_OK;

    // 5s cooldown gate: a press inside the window is ignored, the countdown
    // just restarts the displayed seconds via the still-running timer.
    long long nowMs = GetTickCount64();
    long long endMs = _promptCooldownEndMs.load(std::memory_order_acquire);
    if (nowMs < endMs)
    {
        WriteDebugLog(L"CommandLinkClicked: prompt button pressed during %lld ms cooldown; ignored.", endMs - nowMs);
        return S_OK;
    }

    // Ask the service to relay an unlock prompt to the phone. Use OpenEvent
    // first so we never clobber the service-owned DACL with ours.
    HANDLE hEvt = OpenEventW(EVENT_MODIFY_STATE | READ_CONTROL, FALSE, c_wszUnlockPromptEventName);
    if (hEvt)
    {
        PSID pOwner = nullptr;
        PSECURITY_DESCRIPTOR pSecDesc = nullptr;
        DWORD dwRes = GetSecurityInfo(hEvt, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &pOwner, nullptr, nullptr, nullptr, &pSecDesc);
        if (dwRes != ERROR_SUCCESS || !pOwner || (!IsWellKnownSid(pOwner, WinLocalSystemSid) && !IsWellKnownSid(pOwner, WinBuiltinAdministratorsSid)))
        {
            WriteDebugLog(L"CommandLinkClicked: untrusted owner on prompt event (%u). Discarding.", dwRes);
            CloseHandle(hEvt);
            hEvt = nullptr;
        }
        if (pSecDesc) LocalFree(pSecDesc);
    }
    else
    {
        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &pSD, nullptr))
        {
            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), pSD, FALSE };
            hEvt = CreateEventW(&sa, TRUE, FALSE, c_wszUnlockPromptEventName);
            DWORD dwErr = GetLastError();
            if (hEvt && dwErr == ERROR_ALREADY_EXISTS)
            {
                PSID pOwner = nullptr;
                PSECURITY_DESCRIPTOR pSecDesc = nullptr;
                DWORD dwRes = GetSecurityInfo(hEvt, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &pOwner, nullptr, nullptr, nullptr, &pSecDesc);
                if (dwRes != ERROR_SUCCESS || !pOwner || (!IsWellKnownSid(pOwner, WinLocalSystemSid) && !IsWellKnownSid(pOwner, WinBuiltinAdministratorsSid)))
                {
                    WriteDebugLog(L"CommandLinkClicked: untrusted owner on existing prompt event. Discarding.");
                    CloseHandle(hEvt);
                    hEvt = nullptr;
                }
                if (pSecDesc) LocalFree(pSecDesc);
            }
            LocalFree(pSD);
        }
    }
    if (hEvt)
    {
        // Leave signaled; the service consumes (resets) it in its wait callback.
        SetEvent(hEvt);
        CloseHandle(hEvt);
        WriteDebugLog(L"CommandLinkClicked: signaled unlock prompt request event.");
    }
    else
    {
        WriteDebugLog(L"CommandLinkClicked: could not open/create prompt event (%u).", GetLastError());
    }

    _BeginUnlockPromptCooldown();
    return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

void CSampleCredential::_SetStatusText(PCWSTR pszStatus)
{
    CoTaskMemFree(_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    if (FAILED(SHStrDupW(pszStatus, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT])))
        _rgFieldStrings[SFI_LOGONSTATUS_TEXT] = nullptr;

    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, pszStatus);
}

void CSampleCredential::_BeginUnlockPromptCooldown()
{
    _promptCooldownEndMs.store(GetTickCount64() + c_promptCooldownSeconds * 1000LL, std::memory_order_release);

    if (_pCredProvCredentialEvents)
    {
        // Disable the button and announce the countdown; both field updates are
        // refreshed by the WM_PROMPT_COOLDOWN_TICK posts from the pool timer.
        _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_DISABLED);
        wchar_t statusText[64];
        swprintf_s(statusText, L"Unlock prompt sent - resend available in %d s", c_promptCooldownSeconds);
        _SetStatusText(statusText);
    }

    // SetTimer is unreliable here: ticks are only delivered if the thread that
    // created the window keeps pumping its queue, which LogonUI does not
    // guarantee for credential callbacks. Use a threadpool timer instead - it
    // fires on a pool thread and hops to the window thread via PostMessage,
    // the same pattern the unlock-refresh path uses.
    if (!_pCooldownTimer)
        _pCooldownTimer = CreateThreadpoolTimer(CSampleCredential::_OnCooldownTimerFired, this, nullptr);
    if (_pCooldownTimer)
    {
        // Negative FILETIME = due time relative to now, in 100ns units (-1s).
        LONG64 due100ns = -10000000LL;
        FILETIME ftDue = *reinterpret_cast<FILETIME*>(&due100ns);
        // msPeriod = 1000: re-fire every second until the countdown ends.
        SetThreadpoolTimer(_pCooldownTimer, &ftDue, 1000, 0);
    }
}

void CALLBACK CSampleCredential::_OnCooldownTimerFired(PTP_CALLBACK_INSTANCE, PVOID lpParameter, PTP_TIMER)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;

    if (pThis->_hWndMessage)
        PostMessageW(pThis->_hWndMessage, WM_PROMPT_COOLDOWN_TICK, 0, reinterpret_cast<LPARAM>(pThis));
}

void CSampleCredential::_OnCooldownTick()
{
    long long nowMs = GetTickCount64();
    long long endMs = _promptCooldownEndMs.load(std::memory_order_acquire);

    if (nowMs >= endMs)
    {
        if (_pCooldownTimer)
        {
            SetThreadpoolTimer(_pCooldownTimer, nullptr, 0, 0); // stop firing
            CloseThreadpoolTimer(_pCooldownTimer);
            _pCooldownTimer = nullptr;
        }
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_NONE);
            _SetStatusText(_fPhoneConnected.load() ? L"Phone: Connected" : L"Phone: Disconnected");
        }
        return;
    }

    wchar_t statusText[64];
    swprintf_s(statusText, L"Unlock prompt sent - resend available in %d s", (int)((endMs - nowMs + 999) / 1000));
    _SetStatusText(statusText);
}

HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo)
{
    try
    {
        *pcpcfo = CPCFO_NONE;
        if (dwFieldID == SFI_TILEIMAGE)
            *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

void CALLBACK CSampleCredential::_OnAppEventSignaled(PVOID lpParameter, BOOLEAN)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;

    WriteDebugLog(L"CSampleCredential::_OnAppEventSignaled for instance %p", pThis);
    pThis->_fInstancePhoneAppTriggered.store(true);
    pThis->_fInstanceAutoLogonReady.store(true);
    g_fPhoneAppTriggered.store(true);
    g_fAutoLogonReady.store(true);

    if (pThis->_hAppEvent) ResetEvent(pThis->_hAppEvent);
    if (pThis->_hWndMessage)
    {
        PostMessageW(pThis->_hWndMessage, WM_SIGNAL_CREDENTIALS_CHANGED, 0, reinterpret_cast<LPARAM>(pThis));
    }
    else if (pThis->_pProvider)
    {
        pThis->_pProvider->SignalCredentialsChanged();
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
    PSECURITY_DESCRIPTOR pSD = nullptr;
    // D:P(A;;GA;;;SY)(A;;GA;;;BA) -> Protected DACL, Grant Generic All to SYSTEM and Builtin Admins only
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1,
        &pSD,
        nullptr))
    {
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), pSD, FALSE };
        _hAppEvent = CreateEventW(&sa, TRUE, FALSE, L"Global\\TetherPhoneAppUnlocked");
        DWORD dwErr = GetLastError();

        if (_hAppEvent != nullptr)
        {
            if (dwErr == ERROR_ALREADY_EXISTS)
            {
                PSID pOwner = nullptr;
                PSECURITY_DESCRIPTOR pSecDesc = nullptr;
                DWORD dwRes = GetSecurityInfo(_hAppEvent, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &pOwner, nullptr, nullptr, nullptr, &pSecDesc);
                if (dwRes == ERROR_SUCCESS && pOwner != nullptr)
                {
                    if (IsWellKnownSid(pOwner, WinLocalSystemSid) || IsWellKnownSid(pOwner, WinBuiltinAdministratorsSid))
                    {
                        // Verified trusted owner (SYSTEM or Builtin Administrators); enforce secure DACL
                        if (!SetKernelObjectSecurity(_hAppEvent, DACL_SECURITY_INFORMATION, pSD))
                        {
                            WriteDebugLog(L"SECURITY WARNING: SetKernelObjectSecurity failed (%u) on TetherPhoneAppUnlocked. Discarding.", GetLastError());
                            CloseHandle(_hAppEvent);
                            _hAppEvent = nullptr;
                        }
                        else
                        {
                            WriteDebugLog(L"Opened existing global event with verified owner and secure attributes: TetherPhoneAppUnlocked");
                        }
                    }
                    else
                    {
                        WriteDebugLog(L"SECURITY WARNING: Existing TetherPhoneAppUnlocked event has untrusted owner! Discarding.");
                        CloseHandle(_hAppEvent);
                        _hAppEvent = nullptr;
                    }
                }
                else
                {
                    WriteDebugLog(L"SECURITY WARNING: Failed to query owner for existing TetherPhoneAppUnlocked event (dwRes=%u). Discarding.", dwRes);
                    CloseHandle(_hAppEvent);
                    _hAppEvent = nullptr;
                }
                if (pSecDesc != nullptr)
                {
                    LocalFree(pSecDesc);
                }
            }
            else
            {
                WriteDebugLog(L"Created secure global event: TetherPhoneAppUnlocked");
            }
        }
        else
        {
            WriteDebugLog(L"CreateEventW failed (%u)", dwErr);
        }
        LocalFree(pSD);
    }
    else
    {
        WriteDebugLog(L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed (%u)", GetLastError());
    }

    if (_hAppEvent)
    {
        RegisterWaitForSingleObject(&_hWaitApp, _hAppEvent,
            CSampleCredential::_OnAppEventSignaled, this,
            INFINITE, WT_EXECUTEDEFAULT);
    }

    _hPhoneConnectedEvent = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\TetherPhoneConnected");
    if (_hPhoneConnectedEvent)
    {
        RegisterWaitForSingleObject(&_hWaitPhoneConnected, _hPhoneConnectedEvent,
            CSampleCredential::_OnPhoneConnectedSignaled, this,
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

    // Persistent file logging to %ProgramData%\Tether\logs\credential-provider.log
    WCHAR szPath[MAX_PATH];
    DWORD dwEnvLen = GetEnvironmentVariableW(L"ProgramData", szPath, MAX_PATH);
    if (dwEnvLen > 0 && dwEnvLen < MAX_PATH)
    {
        PathAppendW(szPath, L"Tether");
        CreateDirectoryW(szPath, NULL);
        PathAppendW(szPath, L"logs");
        CreateDirectoryW(szPath, NULL);
        PathAppendW(szPath, L"credential-provider.log");

        HANDLE hFile = CreateFileW(szPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            // Limit log file size to ~5 MB
            LARGE_INTEGER fileSize;
            if (GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 5 * 1024 * 1024)
            {
                CloseHandle(hFile);
                hFile = CreateFileW(szPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            }

            if (hFile != INVALID_HANDLE_VALUE)
            {
                SYSTEMTIME st;
                GetLocalTime(&st);
                char line[2048];
                int n = sprintf_s(line, "[%04u-%02u-%02u %02u:%02u:%02u.%03u] %ls\r\n",
                                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
                if (n > 0)
                {
                    DWORD written = 0;
                    WriteFile(hFile, line, (DWORD)n, &written, NULL);
                }
                CloseHandle(hFile);
            }
        }
    }
}

void CSampleCredential::_DestroyMessageWindow()
{
    if (_hWndMessage)
    {
        DestroyWindow(_hWndMessage);
        _hWndMessage = nullptr;
    }
}