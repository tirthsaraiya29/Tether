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

// Named event consumed by the communication service, which relays an
// UNLOCK_PROMPT frame to the paired phone over the TLS control channel.
static const wchar_t c_wszUnlockPromptEventName[] = L"Global\\TetherUnlockPromptRequested";
static const int c_promptCooldownSeconds = 3;

void WriteDebugLog(const wchar_t* format, ...);

static bool IsTrustedKernelObjectOwner(HANDLE hObject)
{
    if (!hObject) return false;
    PSID pOwner = nullptr;
    PSECURITY_DESCRIPTOR pSecDesc = nullptr;
    DWORD dwRes = GetSecurityInfo(hObject, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &pOwner, nullptr, nullptr, nullptr, &pSecDesc);
    bool isTrusted = false;
    if (dwRes == ERROR_SUCCESS && pOwner != nullptr)
    {
        if (IsWellKnownSid(pOwner, WinLocalSystemSid) || IsWellKnownSid(pOwner, WinBuiltinAdministratorsSid))
        {
            isTrusted = true;
        }
    }
    if (pSecDesc != nullptr)
    {
        LocalFree(pSecDesc);
    }
    return isTrusted;
}

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

CTetherCredential::CTetherCredential() :
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _cpus(CPUS_INVALID),
    _pProvider(nullptr),
    _hAppEvent(nullptr),
    _hWaitApp(nullptr),
    _pCooldownTimer(nullptr),
    _pStatusTimer(nullptr),
    _isValid(true),
    _dwFallbackAuthType(TAM_PHONE_APP),
    _availableMethods({ TAM_PHONE_APP }),
    _dwSelectedMethodIndex(0)
{
    InitializeCriticalSection(&_csCredentialEvents);
    DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CTetherCredential::~CTetherCredential()
{
    _isValid.store(false);

    if (_pStatusTimer)
    {
        SetThreadpoolTimer(_pStatusTimer, nullptr, 0, 0);
        WaitForThreadpoolTimerCallbacks(_pStatusTimer, TRUE);
        CloseThreadpoolTimer(_pStatusTimer);
        _pStatusTimer = nullptr;
    }

    if (_pCooldownTimer)
    {
        SetThreadpoolTimer(_pCooldownTimer, nullptr, 0, 0);
        WaitForThreadpoolTimerCallbacks(_pCooldownTimer, TRUE);
        CloseThreadpoolTimer(_pCooldownTimer);
        _pCooldownTimer = nullptr;
    }

    if (_hWaitApp)
    {
        UnregisterWaitEx(_hWaitApp, NULL);
        _hWaitApp = nullptr;
    }

    if (_hAppEvent)
    {
        CloseHandle(_hAppEvent);
        _hAppEvent = nullptr;
    }

    EnterCriticalSection(&_csCredentialEvents);
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = nullptr;
    }
    LeaveCriticalSection(&_csCredentialEvents);
    DeleteCriticalSection(&_csCredentialEvents);

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

ICredentialProviderCredentialEvents* CTetherCredential::_GetCredentialEventsSafe()
{
    ICredentialProviderCredentialEvents* pEvents = nullptr;
    EnterCriticalSection(&_csCredentialEvents);
    if (_pCredProvCredentialEvents != nullptr)
    {
        pEvents = _pCredProvCredentialEvents;
        pEvents->AddRef();
    }
    LeaveCriticalSection(&_csCredentialEvents);
    return pEvents;
}

HRESULT CTetherCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    const FIELD_STATE_PAIR* rgfsp,
    ICredentialProviderUser* pcpUser)
{
    try
    {
        if (!pcpUser || !rgcpfd || !rgfsp) return E_INVALIDARG;

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

        _LoadFallbackAuthConfiguration();

    _rgFieldStatePairs[SFI_METHOD_LABEL].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[SFI_SUBMIT_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[SFI_LOGONSTATUS_TEXT].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_SERVICE_ACTION_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;

    // Determine initial service and phone connection status synchronously
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
    _prevServiceRunning.store(isServiceRunning);

    bool isPhoneConnected = false;
    if (isServiceRunning)
    {
        HANDLE hPhone = OpenEventW(SYNCHRONIZE | READ_CONTROL, FALSE, L"Global\\TetherPhoneConnected");
        if (hPhone)
        {
            if (IsTrustedKernelObjectOwner(hPhone))
            {
                isPhoneConnected = (WaitForSingleObject(hPhone, 0) == WAIT_OBJECT_0);
            }
            CloseHandle(hPhone);
        }
    }
    _fPhoneConnected.store(isPhoneConnected);
    _prevPhoneConnected.store(isPhoneConnected);

    PCWSTR pszInitialStatus = !isServiceRunning ? L"Tether service is not running" :
                              (isPhoneConnected ? L"Phone: Connected" : L"Phone: Disconnected");

    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Tether", &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Sign in using Tether", &_rgFieldStrings[SFI_LARGE_TEXT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Open the Tether app on your phone and tap 'Unlock PC'", &_rgFieldStrings[SFI_METHOD_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Unlock via Phone App", &_rgFieldStrings[SFI_METHOD_COMBOBOX]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Unlock", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(pszInitialStatus, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Send unlock prompt to phone", &_rgFieldStrings[SFI_UNLOCK_PROMPT_BUTTON]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(!isServiceRunning ? L"Start Tether Service" : L"Restart Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);

    if (isPhoneConnected)
    {
        _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    }

    // Retrieve user SID and qualified name robustly
    pcpUser->GetSid(&_pszUserSid);
    if (!_pszUserSid)
    {
        PWSTR pszPrimarySid = nullptr;
        if (SUCCEEDED(pcpUser->GetStringValue(PKEY_Identity_PrimarySid, &pszPrimarySid)) && pszPrimarySid)
        {
            _pszUserSid = pszPrimarySid;
        }
    }

    if (FAILED(pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName)) || !_pszQualifiedUserName)
    {
        pcpUser->GetStringValue(PKEY_Identity_UserName, &_pszQualifiedUserName);
    }

    _StartBackgroundIPCListeners();

    _pStatusTimer = CreateThreadpoolTimer(CTetherCredential::_OnStatusTimerFired, this, nullptr);
    if (_pStatusTimer)
    {
        LONG64 due100ns = -15000000LL; // 1500ms
        FILETIME ftDue = *reinterpret_cast<FILETIME*>(&due100ns);
        SetThreadpoolTimer(_pStatusTimer, &ftDue, 1500, 0);
    }

    return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    try
    {
        EnterCriticalSection(&_csCredentialEvents);
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->Release();
            _pCredProvCredentialEvents = nullptr;
        }
        HRESULT hr = E_INVALIDARG;
        if (pcpce)
        {
            hr = pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
        }
        LeaveCriticalSection(&_csCredentialEvents);
        return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::UnAdvise()
{
    try
    {
        EnterCriticalSection(&_csCredentialEvents);
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->Release();
            _pCredProvCredentialEvents = nullptr;
        }
        LeaveCriticalSection(&_csCredentialEvents);
        _pProvider = nullptr;
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::SetSelected(BOOL* pbAutoLogon)
{
    try
    {
        if (!pbAutoLogon) return E_POINTER;
        *pbAutoLogon = FALSE;
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::SetDeselected()
{
    return S_OK;
}

HRESULT CTetherCredential::GetFieldState(DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    try
    {
        if (!pcpfs || !pcpfis) return E_POINTER;
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

HRESULT CTetherCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    try
    {
        if (!ppwsz) return E_POINTER;
        *ppwsz = nullptr;
        if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
            return SHStrDupW(_rgFieldStrings[dwFieldID] ? _rgFieldStrings[dwFieldID] : L"", ppwsz);
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    try
    {
        if (!phbmp) return E_POINTER;
        *phbmp = nullptr;
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

HRESULT CTetherCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    try
    {
        if (!pdwAdjacentTo) return E_POINTER;
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

HRESULT CTetherCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    try
    {
        if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
            (_rgCredProvFieldDescriptors[dwFieldID].cpft == CPFT_EDIT_TEXT ||
                _rgCredProvFieldDescriptors[dwFieldID].cpft == CPFT_PASSWORD_TEXT))
        {
            if (_rgFieldStrings[dwFieldID])
            {
                if (dwFieldID == SFI_PASSWORD)
                {
                    SecureZeroMemory(_rgFieldStrings[dwFieldID], wcslen(_rgFieldStrings[dwFieldID]) * sizeof(WCHAR));
                }
                CoTaskMemFree(_rgFieldStrings[dwFieldID]);
                _rgFieldStrings[dwFieldID] = nullptr;
            }
            return SHStrDupW(pwz ? pwz : L"", &_rgFieldStrings[dwFieldID]);
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_INVALIDARG; }
HRESULT CTetherCredential::SetCheckboxValue(DWORD, BOOL) { return E_INVALIDARG; }

HRESULT CTetherCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem)
{
    try
    {
        if (dwFieldID == SFI_METHOD_COMBOBOX)
        {
            if (!pcItems || !pdwSelectedItem) return E_POINTER;
            *pcItems = static_cast<DWORD>(_availableMethods.size());
            *pdwSelectedItem = _dwSelectedMethodIndex;
            return S_OK;
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem)
{
    try
    {
        if (!ppwszItem) return E_POINTER;
        *ppwszItem = nullptr;
        if (dwFieldID == SFI_METHOD_COMBOBOX && dwItem < _availableMethods.size())
        {
            DWORD method = _availableMethods[dwItem];
            if (method < ARRAYSIZE(s_rgUnlockMethodStrings))
            {
                return SHStrDupW(s_rgUnlockMethodStrings[method], ppwszItem);
            }
            return E_FAIL;
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    try
    {
        if (dwFieldID == SFI_METHOD_COMBOBOX)
        {
            if (dwSelectedItem >= _availableMethods.size())
            {
                return E_INVALIDARG;
            }

            _dwSelectedMethodIndex = dwSelectedItem;
            DWORD method = _availableMethods[dwSelectedItem];
            g_dwSelectedMethod.store(method);

            ICredentialProviderCredentialEvents* pEvents = _GetCredentialEventsSafe();

            if (method == TAM_PHONE_APP)
            {
                _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = _fPhoneConnected.load() ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_SERVICE_ACTION_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;

                CoTaskMemFree(_rgFieldStrings[SFI_METHOD_LABEL]);
                _rgFieldStrings[SFI_METHOD_LABEL] = nullptr;
                SHStrDupW(L"Open the Tether app on your phone and tap 'Unlock PC'", &_rgFieldStrings[SFI_METHOD_LABEL]);

                if (pEvents)
                {
                    pEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);
                    pEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs);
                    pEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
                    pEvents->SetFieldString(this, SFI_METHOD_LABEL, _rgFieldStrings[SFI_METHOD_LABEL]);
                    pEvents->SetFieldComboBoxSelectedItem(this, SFI_METHOD_COMBOBOX, dwSelectedItem);
                }
            }
            else
            {
                _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
                _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_SERVICE_ACTION_BUTTON].cpfs = CPFS_HIDDEN;

                CoTaskMemFree(_rgFieldStrings[SFI_METHOD_LABEL]);
                _rgFieldStrings[SFI_METHOD_LABEL] = nullptr;
                if (method == TAM_FALLBACK_PIN)
                {
                    SHStrDupW(L"Enter Fallback PIN to unlock PC", &_rgFieldStrings[SFI_METHOD_LABEL]);
                }
                else
                {
                    SHStrDupW(L"Enter Fallback Password to unlock PC", &_rgFieldStrings[SFI_METHOD_LABEL]);
                }

                if (pEvents)
                {
                    pEvents->SetFieldState(this, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
                    pEvents->SetFieldInteractiveState(this, SFI_PASSWORD, CPFIS_FOCUSED);
                    pEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFS_HIDDEN);
                    pEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_HIDDEN);
                    pEvents->SetFieldString(this, SFI_METHOD_LABEL, _rgFieldStrings[SFI_METHOD_LABEL]);
                    pEvents->SetFieldComboBoxSelectedItem(this, SFI_METHOD_COMBOBOX, dwSelectedItem);
                }
            }

            if (pEvents)
            {
                pEvents->Release();
            }

            return S_OK;
        }
        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::_PackActualPasswordCredential(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PCWSTR pszPassword)
{
    try
    {
        if (!pcpgsr || !pcpcs) return E_POINTER;
        HRESULT hr = E_FAIL;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

        PWSTR pszDomain = nullptr;
        PWSTR pszUsername = nullptr;
        PWSTR pwzProtectedPassword = nullptr;
        KERB_INTERACTIVE_UNLOCK_LOGON kiul;
        ZeroMemory(&kiul, sizeof(kiul));

        try
        {
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
                hr = ProtectIfNecessaryAndCopyPassword(pszPassword, _cpus, &pwzProtectedPassword);
                if (SUCCEEDED(hr))
                {
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
                                pcpcs->clsidCredentialProvider = CLSID_TetherProvider;
                                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                                hr = S_OK;
                            }
                        }
                    }
                }
            }
        }
        catch (...)
        {
            hr = E_UNEXPECTED;
        }

        if (pwzProtectedPassword)
        {
            SecureZeroMemory(pwzProtectedPassword, wcslen(pwzProtectedPassword) * sizeof(WCHAR));
            CoTaskMemFree(pwzProtectedPassword);
            pwzProtectedPassword = nullptr;
        }
        SecureZeroMemory(&kiul, sizeof(kiul));
        if (pszDomain) { CoTaskMemFree(pszDomain); pszDomain = nullptr; }
        if (pszUsername) { CoTaskMemFree(pszUsername); pszUsername = nullptr; }

        if (FAILED(hr))
        {
            if (pcpcs->rgbSerialization)
            {
                SecureZeroMemory(pcpcs->rgbSerialization, pcpcs->cbSerialization);
                CoTaskMemFree(pcpcs->rgbSerialization);
                pcpcs->rgbSerialization = nullptr;
                pcpcs->cbSerialization = 0;
            }
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        }

        return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherCredential::_GetStoredPasswordAndPack(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    try
    {
        if (!pcpgsr || !pcpcs) return E_POINTER;
        HRESULT hr = E_FAIL;

        // Verify VaultDaclVersion == 2 before accessing Secrets
        HKEY hRoot = nullptr;
        DWORD dwVaultDaclVer = 0;
        DWORD dwVerSize = sizeof(dwVaultDaclVer);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ | KEY_WOW64_64KEY, &hRoot) == ERROR_SUCCESS ||
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether", 0, KEY_READ | KEY_WOW64_64KEY, &hRoot) == ERROR_SUCCESS)
        {
            RegQueryValueExW(hRoot, L"VaultDaclVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwVaultDaclVer), &dwVerSize);
            RegCloseKey(hRoot);
        }
        if (dwVaultDaclVer < 2)
        {
            WriteDebugLog(L"CTetherCredential::_GetStoredPasswordAndPack: Rejected insecure or legacy vault (VaultDaclVersion < 2).");
            return E_ACCESSDENIED;
        }

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        {
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\Secrets", 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
        }

        if (hKey != nullptr)
        {
            BYTE encryptedData[2048];
            ZeroMemory(encryptedData, sizeof(encryptedData));
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
            SecureZeroMemory(encryptedData, sizeof(encryptedData));
            RegCloseKey(hKey);
        }
        return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

bool CTetherCredential::_IsEncryptedPasswordBlobPresent()
{
    HKEY hRoot = nullptr;
    DWORD dwVaultDaclVer = 0;
    DWORD dwVerSize = sizeof(dwVaultDaclVer);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ | KEY_WOW64_64KEY, &hRoot) == ERROR_SUCCESS ||
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether", 0, KEY_READ | KEY_WOW64_64KEY, &hRoot) == ERROR_SUCCESS)
    {
        RegQueryValueExW(hRoot, L"VaultDaclVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwVaultDaclVer), &dwVerSize);
        RegCloseKey(hRoot);
    }
    if (dwVaultDaclVer < 2)
    {
        return false;
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS &&
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\Secrets", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD dwType = 0;
    LONG res = RegQueryValueExW(hKey, L"EncryptedPassword", nullptr, &dwType, nullptr, nullptr);
    RegCloseKey(hKey);

    return (res == ERROR_SUCCESS && dwType == REG_BINARY);
}

void CTetherCredential::_LoadFallbackAuthConfiguration()
{
    _availableMethods.clear();
    _availableMethods.push_back(TAM_PHONE_APP);
    _dwSelectedMethodIndex = 0;
    _dwFallbackAuthType = TAM_PHONE_APP;

    HKEY hRoot = nullptr;
    DWORD dwVaultDaclVer = 0;
    DWORD dwVerSize = sizeof(dwVaultDaclVer);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ | KEY_WOW64_64KEY, &hRoot) == ERROR_SUCCESS)
    {
        RegQueryValueExW(hRoot, L"VaultDaclVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwVaultDaclVer), &dwVerSize);
        RegCloseKey(hRoot);
    }
    if (dwVaultDaclVer < 2)
    {
        WriteDebugLog(L"_LoadFallbackAuthConfiguration: Insecure vault DACL version (%u), skipping fallback auth.", dwVaultDaclVer);
        return;
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        DWORD dwType = 0;
        DWORD dwTypeSize = sizeof(dwType);
        // Check FallbackAuthType first, fallback to MasterAuthType
        if (RegQueryValueExW(hKey, L"FallbackAuthType", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwType), &dwTypeSize) != ERROR_SUCCESS ||
            (dwType != TAM_FALLBACK_PIN && dwType != TAM_FALLBACK_PASSWORD))
        {
            dwTypeSize = sizeof(dwType);
            RegQueryValueExW(hKey, L"MasterAuthType", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwType), &dwTypeSize);
        }

        if (dwType == TAM_FALLBACK_PIN || dwType == TAM_FALLBACK_PASSWORD)
        {
            DWORD dwPayloadSize = 0;
            // Check FallbackAuthPayload first, fallback to MasterAuthPayload
            if (RegQueryValueExW(hKey, L"FallbackAuthPayload", nullptr, nullptr, nullptr, &dwPayloadSize) != ERROR_SUCCESS || dwPayloadSize < 59)
            {
                RegQueryValueExW(hKey, L"MasterAuthPayload", nullptr, nullptr, nullptr, &dwPayloadSize);
            }

            if (dwPayloadSize >= 59)
            {
                _dwFallbackAuthType = dwType;
                _availableMethods.push_back(dwType);
                WriteDebugLog(L"_LoadFallbackAuthConfiguration: Registered fallback auth method %u. Total methods=%u", dwType, (DWORD)_availableMethods.size());
            }
        }
        RegCloseKey(hKey);
    }
}

HRESULT CTetherCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
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
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ | KEY_WOW64_64KEY, &hKeyVault) == ERROR_SUCCESS ||
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ | KEY_WOW64_64KEY, &hKeyVault) == ERROR_SUCCESS)
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

    DWORD selectedMethod = g_dwSelectedMethod.load();
    if (selectedMethod == TAM_FALLBACK_PIN || selectedMethod == TAM_FALLBACK_PASSWORD)
    {
        // 1. Rate limiting check
        HKEY hKeyParams = nullptr;
        DWORD failedAttempts = 0;
        ULONGLONG lockoutUntil = 0;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, nullptr, 0,
            KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hKeyParams, nullptr) == ERROR_SUCCESS)
        {
            DWORD dwSize = sizeof(failedAttempts);
            if (RegQueryValueExW(hKeyParams, L"FallbackAuthFailedAttempts", nullptr, nullptr, reinterpret_cast<LPBYTE>(&failedAttempts), &dwSize) != ERROR_SUCCESS)
            {
                dwSize = sizeof(failedAttempts);
                RegQueryValueExW(hKeyParams, L"MasterAuthFailedAttempts", nullptr, nullptr, reinterpret_cast<LPBYTE>(&failedAttempts), &dwSize);
            }
            dwSize = sizeof(lockoutUntil);
            if (RegQueryValueExW(hKeyParams, L"FallbackAuthLockoutUntil", nullptr, nullptr, reinterpret_cast<LPBYTE>(&lockoutUntil), &dwSize) != ERROR_SUCCESS)
            {
                dwSize = sizeof(lockoutUntil);
                RegQueryValueExW(hKeyParams, L"MasterAuthLockoutUntil", nullptr, nullptr, reinterpret_cast<LPBYTE>(&lockoutUntil), &dwSize);
            }
        }

        FILETIME ftNow;
        GetSystemTimeAsFileTime(&ftNow);
        ULONGLONG now = (((ULONGLONG)ftNow.dwHighDateTime) << 32) | ftNow.dwLowDateTime;

        if (now < lockoutUntil)
        {
            DWORD secRemaining = static_cast<DWORD>((lockoutUntil - now + 9999999ULL) / 10000000ULL);
            WCHAR szRateLimitMsg[128];
            swprintf_s(szRateLimitMsg, L"Too many incorrect attempts. Please wait %u seconds.", secRemaining);
            SHStrDupW(szRateLimitMsg, ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            if (hKeyParams) RegCloseKey(hKeyParams);
            return S_FALSE;
        }

        // 2. Validate user input
        PCWSTR pszEntered = _rgFieldStrings[SFI_PASSWORD];
        if (!pszEntered || pszEntered[0] == L'\0')
        {
            SHStrDupW(selectedMethod == TAM_FALLBACK_PIN ? L"Please enter your Fallback PIN." : L"Please enter your Fallback Password.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            if (hKeyParams) RegCloseKey(hKeyParams);
            return S_FALSE;
        }

        // 3. Read and unprotect FallbackAuthPayload from Secrets
        bool verified = false;
        HKEY hKeySecrets = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ | KEY_WOW64_64KEY, &hKeySecrets) == ERROR_SUCCESS)
        {
            BYTE encryptedPayload[4096];
            DWORD dwEncSize = sizeof(encryptedPayload);
            DWORD dwType = 0;
            // Try FallbackAuthPayload first, then MasterAuthPayload
            if (RegQueryValueExW(hKeySecrets, L"FallbackAuthPayload", nullptr, &dwType, encryptedPayload, &dwEncSize) != ERROR_SUCCESS)
            {
                dwEncSize = sizeof(encryptedPayload);
                RegQueryValueExW(hKeySecrets, L"MasterAuthPayload", nullptr, &dwType, encryptedPayload, &dwEncSize);
            }

            if (dwEncSize > 0)
            {
                DATA_BLOB dataIn = { dwEncSize, encryptedPayload };
                DATA_BLOB dataOut = { 0 };
                BYTE entropyBytes[] = "Tether_System_Bound_Vault_v1";
                DATA_BLOB entropyBlob = { sizeof(entropyBytes) - 1, entropyBytes };

                if (CryptUnprotectData(&dataIn, nullptr, &entropyBlob, nullptr, nullptr,
                    CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &dataOut))
                {
                    verified = VerifyFallbackCredentialPBKDF2(pszEntered, dataOut.pbData, dataOut.cbData, selectedMethod);
                    SecureZeroMemory(dataOut.pbData, dataOut.cbData);
                    LocalFree(dataOut.pbData);
                }
                SecureZeroMemory(encryptedPayload, sizeof(encryptedPayload));
            }
            RegCloseKey(hKeySecrets);
        }

        // Wipe entered credential string in-place
        if (_rgFieldStrings[SFI_PASSWORD])
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
            CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
            _rgFieldStrings[SFI_PASSWORD] = nullptr;
            SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        }

        if (!verified)
        {
            failedAttempts++;
            DWORD delaySeconds = (failedAttempts >= 5) ? 30 : ((failedAttempts == 4) ? 15 : ((failedAttempts == 3) ? 5 : ((failedAttempts == 2) ? 3 : 1)));
            lockoutUntil = now + (static_cast<ULONGLONG>(delaySeconds) * 10000000ULL);

            if (hKeyParams)
            {
                RegSetValueExW(hKeyParams, L"FallbackAuthFailedAttempts", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&failedAttempts), sizeof(failedAttempts));
                RegSetValueExW(hKeyParams, L"FallbackAuthLockoutUntil", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&lockoutUntil), sizeof(lockoutUntil));
                RegSetValueExW(hKeyParams, L"MasterAuthFailedAttempts", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&failedAttempts), sizeof(failedAttempts));
                RegSetValueExW(hKeyParams, L"MasterAuthLockoutUntil", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&lockoutUntil), sizeof(lockoutUntil));
                RegCloseKey(hKeyParams);
            }

            WriteDebugLog(L"GetSerialization: Fallback credential verification failed (attempt #%u, lockout %u s).", failedAttempts, delaySeconds);
            SHStrDupW(selectedMethod == TAM_FALLBACK_PIN ? L"Incorrect Fallback PIN." : L"Incorrect Fallback Password.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_FALSE;
        }

        // Reset rate-limiting state on success
        failedAttempts = 0;
        lockoutUntil = 0;
        if (hKeyParams)
        {
            RegSetValueExW(hKeyParams, L"FallbackAuthFailedAttempts", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&failedAttempts), sizeof(failedAttempts));
            RegSetValueExW(hKeyParams, L"FallbackAuthLockoutUntil", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&lockoutUntil), sizeof(lockoutUntil));
            RegSetValueExW(hKeyParams, L"MasterAuthFailedAttempts", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&failedAttempts), sizeof(failedAttempts));
            RegSetValueExW(hKeyParams, L"MasterAuthLockoutUntil", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&lockoutUntil), sizeof(lockoutUntil));
            RegCloseKey(hKeyParams);
        }

        WriteDebugLog(L"GetSerialization: Fallback credential successfully verified. Unlocking session...");
        HRESULT hr = _GetStoredPasswordAndPack(pcpgsr, pcpcs);
        if (SUCCEEDED(hr) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED)
        {
            WriteDebugLog(L"GetSerialization: Successfully packaged stored credentials via fallback auth.");
            return S_OK;
        }

        WriteDebugLog(L"GetSerialization: Failed to unpack stored credentials (hr=0x%08X).", hr);
        SHStrDupW(L"Failed to unlock: Stored Windows logon credentials missing or corrupted.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }

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

HRESULT CTetherCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    try
    {
        if (!ppwszOptionalStatusText || !pcpsiOptionalStatusIcon)
            return E_POINTER;

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

HRESULT CTetherCredential::GetUserSid(PWSTR* ppszSid)
{
    if (!ppszSid) return E_POINTER;
    *ppszSid = nullptr;

    if (_pszUserSid && _pszUserSid[0] != L'\0')
    {
        return SHStrDupW(_pszUserSid, ppszSid);
    }

    return E_FAIL;
}

void CTetherCredential::_CheckStatusAndRefreshUi()
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
        HANDLE hPhone = OpenEventW(SYNCHRONIZE | READ_CONTROL, FALSE, L"Global\\TetherPhoneConnected");
        if (hPhone)
        {
            if (IsTrustedKernelObjectOwner(hPhone))
            {
                isPhoneConnected = (WaitForSingleObject(hPhone, 0) == WAIT_OBJECT_0);
            }
            else
            {
                WriteDebugLog(L"SECURITY WARNING: Global\\TetherPhoneConnected has untrusted owner! Discarding.");
            }
            CloseHandle(hPhone);
        }
    }
    _fPhoneConnected.store(isPhoneConnected);

    bool prevRunning = _prevServiceRunning.exchange(isServiceRunning);
    bool prevConnected = _prevPhoneConnected.exchange(isPhoneConnected);
    bool statusChanged = (prevRunning != isServiceRunning) || (prevConnected != isPhoneConnected);

    ICredentialProviderCredentialEvents* pEvents = _GetCredentialEventsSafe();
    if (!pEvents) return;

    DWORD currentMethod = g_dwSelectedMethod.load();

    if (statusChanged)
    {
        if (!isServiceRunning)
        {
            _SetStatusText(L"Tether service is not running");
            CoTaskMemFree(_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            SHStrDupW(L"Start Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            pEvents->SetFieldString(this, SFI_SERVICE_ACTION_BUTTON, L"Start Tether Service");
            pEvents->SetFieldInteractiveState(this, SFI_SERVICE_ACTION_BUTTON, CPFIS_NONE);
            if (currentMethod == TAM_PHONE_APP)
            {
                pEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
            }

            _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_HIDDEN;
            pEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFS_HIDDEN);
        }
        else if (!isPhoneConnected)
        {
            _SetStatusText(L"Phone: Disconnected");
            CoTaskMemFree(_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            SHStrDupW(L"Restart Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            pEvents->SetFieldString(this, SFI_SERVICE_ACTION_BUTTON, L"Restart Tether Service");
            pEvents->SetFieldInteractiveState(this, SFI_SERVICE_ACTION_BUTTON, CPFIS_NONE);
            if (currentMethod == TAM_PHONE_APP)
            {
                pEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
            }

            _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_HIDDEN;
            pEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFS_HIDDEN);
        }
        else
        {
            _SetStatusText(L"Phone: Connected");
            CoTaskMemFree(_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            SHStrDupW(L"Restart Tether Service", &_rgFieldStrings[SFI_SERVICE_ACTION_BUTTON]);
            pEvents->SetFieldString(this, SFI_SERVICE_ACTION_BUTTON, L"Restart Tether Service");
            pEvents->SetFieldInteractiveState(this, SFI_SERVICE_ACTION_BUTTON, CPFIS_NONE);
            if (currentMethod == TAM_PHONE_APP)
            {
                pEvents->SetFieldState(this, SFI_SERVICE_ACTION_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
                _rgFieldStatePairs[SFI_UNLOCK_PROMPT_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
                pEvents->SetFieldState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
            }
        }
    }

    if (currentMethod == TAM_PHONE_APP && isServiceRunning && isPhoneConnected)
    {
        long long nowMs = GetTickCount64();
        long long endMs = _promptCooldownEndMs.load(std::memory_order_acquire);
        if (nowMs >= endMs)
        {
            pEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_NONE);
        }
        else
        {
            pEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_DISABLED);
        }
    }

    pEvents->Release();
}

void CTetherCredential::_PerformServiceActionAsync()
{
    struct ActionContext
    {
        CTetherCredential* pThis;
    };

    auto* ctx = new (std::nothrow) ActionContext{ this };
    if (!ctx) return;

    this->AddRef();

    BOOL queued = QueueUserWorkItem([](PVOID param) -> DWORD
    {
        auto* c = reinterpret_cast<ActionContext*>(param);
        if (c)
        {
            CTetherCredential* pThis = c->pThis;
            try
            {
                if (pThis && pThis->_isValid.load())
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
                                        if (!pThis->_isValid.load()) break;
                                        Sleep(250);
                                        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
                                        {
                                            if (ssp.dwCurrentState == SERVICE_STOPPED) break;
                                        }
                                    }
                                }
                            }

                            if (pThis->_isValid.load())
                            {
                                StartServiceW(hSvc, 0, nullptr);
                                for (int i = 0; i < 20; i++)
                                {
                                    if (!pThis->_isValid.load()) break;
                                    Sleep(250);
                                    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
                                    {
                                        if (ssp.dwCurrentState == SERVICE_RUNNING) break;
                                    }
                                }
                            }

                            CloseServiceHandle(hSvc);
                        }
                        CloseServiceHandle(hSCM);
                    }

                    if (pThis->_isValid.load())
                    {
                        pThis->_fServiceActionInProgress.store(false);
                        pThis->_CheckStatusAndRefreshUi();
                    }
                }
            }
            catch (...)
            {
            }

            if (pThis)
            {
                pThis->Release();
            }
            delete c;
        }
        return 0;
    }, ctx, WT_EXECUTEDEFAULT);

    if (!queued)
    {
        this->Release();
        delete ctx;
    }
}

void CALLBACK CTetherCredential::_OnStatusTimerFired(PTP_CALLBACK_INSTANCE, PVOID lpParameter, PTP_TIMER)
{
    CTetherCredential* pThis = reinterpret_cast<CTetherCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;
    pThis->_CheckStatusAndRefreshUi();
}

HRESULT CTetherCredential::CommandLinkClicked(DWORD dwFieldID)
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

    // Ask the service to relay an unlock prompt to the phone.
    HANDLE hEvt = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)", SDDL_REVISION_1, &pSD, nullptr))
    {
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), pSD, FALSE };
        hEvt = CreateEventW(&sa, TRUE, FALSE, c_wszUnlockPromptEventName);
        DWORD dwErr = GetLastError();
        if (hEvt && dwErr == ERROR_ALREADY_EXISTS)
        {
            if (!IsTrustedKernelObjectOwner(hEvt))
            {
                WriteDebugLog(L"CommandLinkClicked: untrusted owner on existing prompt event. Discarding.");
                CloseHandle(hEvt);
                hEvt = nullptr;
            }
            else
            {
                SetKernelObjectSecurity(hEvt, DACL_SECURITY_INFORMATION, pSD);
            }
        }
        LocalFree(pSD);
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

void CTetherCredential::_SetStatusText(PCWSTR pszStatus)
{
    if (!pszStatus) return;

    if (_rgFieldStrings[SFI_LOGONSTATUS_TEXT] && wcscmp(_rgFieldStrings[SFI_LOGONSTATUS_TEXT], pszStatus) == 0)
    {
        return; // Text hasn't changed; avoid redundant redraw
    }

    CoTaskMemFree(_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    _rgFieldStrings[SFI_LOGONSTATUS_TEXT] = nullptr;
    SHStrDupW(pszStatus, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);

    ICredentialProviderCredentialEvents* pEvents = _GetCredentialEventsSafe();
    if (pEvents)
    {
        pEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, pszStatus);
        pEvents->Release();
    }
}

void CTetherCredential::_BeginUnlockPromptCooldown()
{
    _promptCooldownEndMs.store(GetTickCount64() + c_promptCooldownSeconds * 1000LL, std::memory_order_release);

    ICredentialProviderCredentialEvents* pEvents = _GetCredentialEventsSafe();
    if (pEvents)
    {
        pEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_DISABLED);
        pEvents->Release();
    }
    wchar_t statusText[64];
    swprintf_s(statusText, L"Unlock prompt sent - resend available in %d s", c_promptCooldownSeconds);
    _SetStatusText(statusText);

    if (!_pCooldownTimer)
        _pCooldownTimer = CreateThreadpoolTimer(CTetherCredential::_OnCooldownTimerFired, this, nullptr);
    if (_pCooldownTimer)
    {
        LONG64 due100ns = -10000000LL;
        FILETIME ftDue = *reinterpret_cast<FILETIME*>(&due100ns);
        SetThreadpoolTimer(_pCooldownTimer, &ftDue, 1000, 0);
    }
}

void CALLBACK CTetherCredential::_OnCooldownTimerFired(PTP_CALLBACK_INSTANCE, PVOID lpParameter, PTP_TIMER)
{
    CTetherCredential* pThis = reinterpret_cast<CTetherCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;
    pThis->_OnCooldownTick();
}

void CTetherCredential::_OnCooldownTick()
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
        ICredentialProviderCredentialEvents* pEvents = _GetCredentialEventsSafe();
        if (pEvents)
        {
            pEvents->SetFieldInteractiveState(this, SFI_UNLOCK_PROMPT_BUTTON, CPFIS_NONE);
            pEvents->Release();
        }
        _SetStatusText(_fPhoneConnected.load() ? L"Phone: Connected" : L"Phone: Disconnected");
        return;
    }

    wchar_t statusText[64];
    swprintf_s(statusText, L"Unlock prompt sent - resend available in %d s", (int)((endMs - nowMs + 999) / 1000));
    _SetStatusText(statusText);
}

HRESULT CTetherCredential::GetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo)
{
    try
    {
        if (!pcpcfo) return E_POINTER;
        *pcpcfo = CPCFO_NONE;
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

void CALLBACK CTetherCredential::_OnAppEventSignaled(PVOID lpParameter, BOOLEAN)
{
    CTetherCredential* pThis = reinterpret_cast<CTetherCredential*>(lpParameter);
    if (!pThis || !pThis->_isValid.load()) return;

    WriteDebugLog(L"CTetherCredential::_OnAppEventSignaled for instance %p", pThis);
    pThis->_fInstancePhoneAppTriggered.store(true);
    pThis->_fInstanceAutoLogonReady.store(true);
    g_fPhoneAppTriggered.store(true);
    g_fAutoLogonReady.store(true);

    if (pThis->_hAppEvent) ResetEvent(pThis->_hAppEvent);
    if (pThis->_pProvider)
    {
        pThis->_pProvider->SignalCredentialsChanged();
    }
}

void CTetherCredential::_StartBackgroundIPCListeners()
{
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)",
        SDDL_REVISION_1,
        &pSD,
        nullptr))
    {
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), pSD, FALSE };
        _hAppEvent = CreateEventW(&sa, TRUE, FALSE, L"Global\\TetherPhoneAppUnlocked");
        DWORD dwErr = GetLastError();
        if (_hAppEvent)
        {
            if (dwErr == ERROR_ALREADY_EXISTS)
            {
                if (!IsTrustedKernelObjectOwner(_hAppEvent))
                {
                    WriteDebugLog(L"SECURITY WARNING: Existing TetherPhoneAppUnlocked event has untrusted owner! Discarding.");
                    CloseHandle(_hAppEvent);
                    _hAppEvent = nullptr;
                }
                else
                {
                    SetKernelObjectSecurity(_hAppEvent, DACL_SECURITY_INFORMATION, pSD);
                    WriteDebugLog(L"Opened existing global event with verified owner: TetherPhoneAppUnlocked");
                }
            }
            else
            {
                WriteDebugLog(L"Created secure global event: TetherPhoneAppUnlocked");
            }
        }
        LocalFree(pSD);
    }

    if (_hAppEvent)
    {
        RegisterWaitForSingleObject(&_hWaitApp, _hAppEvent,
            CTetherCredential::_OnAppEventSignaled, this,
            INFINITE, WT_EXECUTEDEFAULT);
    }
}
