#include <initguid.h>
#include <cguid.h>
#include <string>
#include <vector>
#include <new>
#include <combaseapi.h>
#include "TetherProvider.h"
#include "TetherCredential.h"
#include "TetherCredentialGlobals.h"
#include "guid.h"

CTetherProvider::CTetherProvider() :
    _cRef(1),
    _pCredProviderUserArray(nullptr),
    _fRecreateEnumeratedCredentials(false),
    _cpus(CPUS_INVALID),
    _pCredProviderEvents(nullptr),
    _upAdviseContext(0),
    _dwUpToDateCredentialsCount(0)
{
    InitializeCriticalSection(&_csEvents);
    DllAddRef();
}

CTetherProvider::~CTetherProvider()
{
    _ReleaseEnumeratedCredentials();
    EnterCriticalSection(&_csEvents);
    if (_pCredProviderEvents != nullptr)
    {
        _pCredProviderEvents->Release();
        _pCredProviderEvents = nullptr;
    }
    LeaveCriticalSection(&_csEvents);
    DeleteCriticalSection(&_csEvents);
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
    DllRelease();
}

HRESULT CTetherProvider::SetUsageScenario(
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _In_ DWORD dwFlags)
{
    try
    {
        HRESULT hr = S_OK;

        switch (cpus)
        {
        case CPUS_LOGON:
        case CPUS_UNLOCK_WORKSTATION: // Supports locked workstation transitions natively
        case CPUS_CREDUI:
            _cpus = cpus;
            g_fPhoneAppTriggered.store(false);
            g_fAutoLogonReady.store(false);
            hr = S_OK;
            break;

        case CPUS_CHANGE_PASSWORD:
        case CPUS_PLAP:
        case CPUS_INVALID:
            _cpus = cpus;
            hr = E_NOTIMPL;
            break;

        default:
            hr = E_INVALIDARG;
            break;
        }

        return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::GetFieldDescriptorCount(_Out_ DWORD* pdwCount)
{
    try
    {
        if (pdwCount == nullptr)
        {
            return E_POINTER;
        }
        *pdwCount = SFI_NUM_FIELDS;
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::GetFieldDescriptorAt(
    _In_ DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    try
    {
        HRESULT hr = E_INVALIDARG;
        if (ppcpfd == nullptr)
        {
            return E_POINTER;
        }
        *ppcpfd = nullptr;

        if (dwIndex < SFI_NUM_FIELDS)
        {
            hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
        }

        return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::GetCredentialCount(_Out_ DWORD* pdwCount,
    _Out_ DWORD* pdwDefault,
    _Out_ BOOL* pbAutoLogonWithDefault)
{
    try
    {
        if (pdwCount == nullptr || pdwDefault == nullptr || pbAutoLogonWithDefault == nullptr)
            return E_POINTER;

        *pdwCount = 0;
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE;

        if (_credentials.empty())
        {
            _EnumerateCredentials();
        }

        *pdwCount = static_cast<DWORD>(_credentials.size());

        if (*pdwCount > 0)
        {
            if (g_fAutoLogonReady.load())
            {
                DWORD defaultIdx = 0;
                // Check if a target user SID is configured in registry secrets
                HKEY hKeyVault = nullptr;
                WCHAR szTargetSid[128] = { 0 };
                DWORD dwTargetSidLen = sizeof(szTargetSid);
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider\\Secrets", 0, KEY_READ, &hKeyVault) == ERROR_SUCCESS ||
                    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKeyVault) == ERROR_SUCCESS)
                {
                    RegQueryValueExW(hKeyVault, L"TargetUserSid", nullptr, nullptr, (LPBYTE)szTargetSid, &dwTargetSidLen);
                    RegCloseKey(hKeyVault);
                }

                if (szTargetSid[0] != L'\0')
                {
                    for (DWORD i = 0; i < *pdwCount; i++)
                    {
                        PWSTR pszTileSid = nullptr;
                        if (SUCCEEDED(_credentials[i]->GetUserSid(&pszTileSid)) && pszTileSid)
                        {
                            if (_wcsicmp(szTargetSid, pszTileSid) == 0)
                            {
                                defaultIdx = i;
                                CoTaskMemFree(pszTileSid);
                                break;
                            }
                            CoTaskMemFree(pszTileSid);
                        }
                    }
                }

                *pdwDefault = defaultIdx;
                *pbAutoLogonWithDefault = TRUE;
            }
            else
            {
                *pdwDefault = 0;
                *pbAutoLogonWithDefault = FALSE;
            }
        }
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::GetCredentialAt(
    _In_ DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential** ppcpc)
{
    try
    {
        if (ppcpc == nullptr)
        {
            return E_POINTER;
        }
        *ppcpc = nullptr;

        if (dwIndex < _credentials.size() && _credentials[dwIndex] != nullptr)
        {
            return _credentials[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
        }

        return E_INVALIDARG;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::SetUserArray(_In_ ICredentialProviderUserArray* users)
{
    try
    {
        if (_pCredProviderUserArray != nullptr)
        {
            _pCredProviderUserArray->Release();
            _pCredProviderUserArray = nullptr;
        }

        _pCredProviderUserArray = users;
        if (_pCredProviderUserArray != nullptr)
        {
            _pCredProviderUserArray->AddRef();
        }

        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::Advise(_In_ ICredentialProviderEvents* pcpe, _In_ UINT_PTR upAdviseContext)
{
    try
    {
        EnterCriticalSection(&_csEvents);
        if (_pCredProviderEvents != nullptr)
        {
            _pCredProviderEvents->Release();
            _pCredProviderEvents = nullptr;
        }

        _pCredProviderEvents = pcpe;
        _upAdviseContext = upAdviseContext;

        if (_pCredProviderEvents != nullptr)
        {
            _pCredProviderEvents->AddRef();
        }
        LeaveCriticalSection(&_csEvents);

        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::UnAdvise()
{
    try
    {
        EnterCriticalSection(&_csEvents);
        if (_pCredProviderEvents != nullptr)
        {
            _pCredProviderEvents->Release();
            _pCredProviderEvents = nullptr;
        }
        _upAdviseContext = 0;
        LeaveCriticalSection(&_csEvents);
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::SetSerialization(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    try
    {
        UNREFERENCED_PARAMETER(pcpcs);
        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

#ifdef TETHER_TEST_HARNESS
static HKEY g_hPanicRegistryRoot = HKEY_CURRENT_USER;
static std::wstring g_wszPanicRegistryPath = L"Software\\Tether\\TestPanicLock";

void CTetherProvider_SetTestRegistryRoot(HKEY hRoot, const wchar_t* subKey)
{
    g_hPanicRegistryRoot = hRoot;
    g_wszPanicRegistryPath = (subKey != nullptr && *subKey != L'\0') ? subKey : L"Software\\Tether\\TestPanicLock";
}

static const wchar_t* _GetPanicRegistryPath()
{
    return g_wszPanicRegistryPath.c_str();
}
#else
static const HKEY g_hPanicRegistryRoot = HKEY_LOCAL_MACHINE;
static const wchar_t* _GetPanicRegistryPath()
{
    return L"SOFTWARE\\Tether\\PanicLock";
}
#endif

static HRESULT _ReadPanicFilterState(
    _Out_ bool* pbPanicActive,
    _Out_ std::wstring* pSessionId,
    _Out_ std::vector<GUID>* pHiddenProviders)
{
    if (pbPanicActive == nullptr || pSessionId == nullptr || pHiddenProviders == nullptr)
    {
        return E_POINTER;
    }

    *pbPanicActive = false;
    pSessionId->clear();
    pHiddenProviders->clear();

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(g_hPanicRegistryRoot, _GetPanicRegistryPath(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return S_OK;
    }

    DWORD dwDaclVer = 0;
    DWORD dwSize = sizeof(dwDaclVer);
    if (RegQueryValueExW(hKey, L"VaultDaclVersion", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwDaclVer), &dwSize) != ERROR_SUCCESS || dwDaclVer < 2)
    {
        RegCloseKey(hKey);
        return E_ACCESSDENIED;
    }

    DWORD dwPanicActive = 0;
    dwSize = sizeof(dwPanicActive);
    if (RegQueryValueExW(hKey, L"IsPanicActive", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwPanicActive), &dwSize) == ERROR_SUCCESS)
    {
        *pbPanicActive = (dwPanicActive != 0);
    }

    wchar_t szSessionId[128] = { 0 };
    dwSize = sizeof(szSessionId);
    if (RegQueryValueExW(hKey, L"PanicSessionId", nullptr, nullptr, reinterpret_cast<LPBYTE>(szSessionId), &dwSize) == ERROR_SUCCESS)
    {
        *pSessionId = szSessionId;
    }

    DWORD dwType = 0;
    dwSize = 0;
    if (RegQueryValueExW(hKey, L"HiddenProviders", nullptr, &dwType, nullptr, &dwSize) == ERROR_SUCCESS && dwSize > 0 && dwType == REG_MULTI_SZ)
    {
        std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t) + 2, 0);
        if (RegQueryValueExW(hKey, L"HiddenProviders", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer.data()), &dwSize) == ERROR_SUCCESS)
        {
            const wchar_t* p = buffer.data();
            while (*p != L'\0')
            {
                GUID guid = GUID_NULL;
                if (SUCCEEDED(IIDFromString(p, &guid)) && !IsEqualGUID(guid, GUID_NULL))
                {
                    pHiddenProviders->push_back(guid);
                }
                p += wcslen(p) + 1;
            }
        }
    }

    RegCloseKey(hKey);
    return S_OK;
}

static HRESULT _WriteHiddenProviders(const std::vector<GUID>& hiddenProviders)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(g_hPanicRegistryRoot, _GetPanicRegistryPath(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
    {
        return E_FAIL;
    }

    if (hiddenProviders.empty())
    {
        RegDeleteValueW(hKey, L"HiddenProviders");
        RegCloseKey(hKey);
        return S_OK;
    }

    std::vector<wchar_t> multiSz;
    for (const auto& g : hiddenProviders)
    {
        wchar_t szGuid[64] = { 0 };
        if (StringFromGUID2(g, szGuid, ARRAYSIZE(szGuid)) > 0)
        {
            size_t len = wcslen(szGuid);
            multiSz.insert(multiSz.end(), szGuid, szGuid + len + 1);
        }
    }
    multiSz.push_back(L'\0');

    DWORD cbData = static_cast<DWORD>(multiSz.size() * sizeof(wchar_t));
    RegSetValueExW(hKey, L"HiddenProviders", 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(multiSz.data()), cbData);
    RegCloseKey(hKey);
    return S_OK;
}

static HRESULT _ClearHiddenProviders()
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(g_hPanicRegistryRoot, _GetPanicRegistryPath(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        RegDeleteValueW(hKey, L"HiddenProviders");
        RegCloseKey(hKey);
    }
    return S_OK;
}

HRESULT CTetherProvider::Filter(
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _In_ DWORD dwFlags,
    _In_reads_(cProviders) GUID* rgclsidProviders,
    _Inout_updates_(cProviders) BOOL* rgbAllow,
    _In_ DWORD cProviders)
{
    try
    {
        UNREFERENCED_PARAMETER(cpus);
        UNREFERENCED_PARAMETER(dwFlags);

        if (rgclsidProviders == nullptr || rgbAllow == nullptr || cProviders == 0)
        {
            return S_OK;
        }

        bool bPanicActive = false;
        std::wstring sessionId;
        std::vector<GUID> previouslyHidden;

        HRESULT hr = _ReadPanicFilterState(&bPanicActive, &sessionId, &previouslyHidden);
        if (FAILED(hr))
        {
            // Fail safely: if state or DACL cannot be validated, preserve incoming allow states
            return S_OK;
        }

        if (bPanicActive)
        {
            // Panic Lock is ACTIVE:
            // 1. Preserve any incoming FALSE decision: if a provider (including Tether's own)
            //    was already denied (FALSE), it must remain FALSE (never override another filter).
            // 2. Hide alternative providers that are currently allowed (TRUE) and track them.
            // 3. For providers already FALSE, keep them FALSE and do not track as hidden by Tether.
            std::vector<GUID> newlyHidden = previouslyHidden;
            bool trackingChanged = false;

            for (DWORD i = 0; i < cProviders; ++i)
            {
                if (IsEqualGUID(rgclsidProviders[i], CLSID_TetherProvider))
                {
                    // Preserve incoming rgbAllow[i] decision. If already FALSE, leave FALSE.
                    // Do not force rgbAllow[i] = TRUE over another filter's denial.
                }
                else
                {
                    if (rgbAllow[i] == FALSE)
                    {
                        // Already denied before Tether touched it. Keep FALSE and do not claim ownership.
                    }
                    else
                    {
                        // Provider was currently allowed. Tether explicitly hides it.
                        rgbAllow[i] = FALSE;

                        bool alreadyTracked = false;
                        for (const auto& g : newlyHidden)
                        {
                            if (IsEqualGUID(g, rgclsidProviders[i]))
                            {
                                alreadyTracked = true;
                                break;
                            }
                        }
                        if (!alreadyTracked)
                        {
                            newlyHidden.push_back(rgclsidProviders[i]);
                            trackingChanged = true;
                        }
                    }
                }
            }

            if (trackingChanged)
            {
                _WriteHiddenProviders(newlyHidden);
            }
        }
        else
        {
            // Panic Lock is INACTIVE:
            // Restore ONLY providers that Tether explicitly hid.
            // Never unhide providers that were already hidden before Panic Lock or hidden by others.
            if (!previouslyHidden.empty())
            {
                for (DWORD i = 0; i < cProviders; ++i)
                {
                    if (IsEqualGUID(rgclsidProviders[i], CLSID_TetherProvider))
                    {
                        // Preserve incoming decision
                    }
                    else
                    {
                        bool wasHiddenByTether = false;
                        for (const auto& g : previouslyHidden)
                        {
                            if (IsEqualGUID(g, rgclsidProviders[i]))
                            {
                                wasHiddenByTether = true;
                                break;
                            }
                        }

                        if (wasHiddenByTether)
                        {
                            // Tether explicitly hid this provider; safely restore it
                            rgbAllow[i] = TRUE;
                        }
                        // If not hidden by Tether, leave rgbAllow[i] completely untouched!
                    }
                }

                // Restoration applied; clear tracked providers to guarantee idempotency
                _ClearHiddenProviders();
            }
        }

        return S_OK;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::UpdateRemoteCredential(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const* pcpcsIn,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
    try
    {
        UNREFERENCED_PARAMETER(pcpcsIn);
        if (pcpcsOut == nullptr)
        {
            return E_POINTER;
        }
        *pcpcsOut = {};
        return E_NOTIMPL;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CTetherProvider::SignalCredentialsChanged()
{
    ICredentialProviderEvents* pEvents = nullptr;
    UINT_PTR upContext = 0;

    EnterCriticalSection(&_csEvents);
    if (_pCredProviderEvents != nullptr)
    {
        pEvents = _pCredProviderEvents;
        pEvents->AddRef();
        upContext = _upAdviseContext;
    }
    LeaveCriticalSection(&_csEvents);

    if (pEvents != nullptr)
    {
        HRESULT hr = pEvents->CredentialsChanged(upContext);
        pEvents->Release();
        return hr;
    }
    return S_FALSE;
}

void CTetherProvider::_ReleaseEnumeratedCredentials()
{
    for (auto* pCred : _credentials)
    {
        if (pCred != nullptr)
        {
            pCred->Release();
        }
    }
    _credentials.clear();
}

HRESULT CTetherProvider::_EnumerateCredentials()
{
    _ReleaseEnumeratedCredentials();

    if (_pCredProviderUserArray != nullptr)
    {
        DWORD dwUserCount = 0;
        HRESULT hr = _pCredProviderUserArray->GetCount(&dwUserCount);
        if (SUCCEEDED(hr) && dwUserCount > 0)
        {
            for (DWORD i = 0; i < dwUserCount; i++)
            {
                ICredentialProviderUser* pCredUser = nullptr;
                if (SUCCEEDED(_pCredProviderUserArray->GetAt(i, &pCredUser)) && pCredUser != nullptr)
                {
                    CTetherCredential* pCredential = new(std::nothrow) CTetherCredential();
                    if (pCredential != nullptr)
                    {
                        pCredential->SetProvider(this);
                        if (SUCCEEDED(pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors,
                            s_rgFieldStatePairs, pCredUser)))
                        {
                            _credentials.push_back(pCredential);
                        }
                        else
                        {
                            pCredential->Release();
                        }
                    }
                    pCredUser->Release();
                }
            }
        }
    }
    return S_OK;
}

HRESULT CTetherProvider_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv)
{
    if (ppv == nullptr)
    {
        return E_POINTER;
    }
    *ppv = nullptr;

    HRESULT hr = E_OUTOFMEMORY;
    CTetherProvider* pProvider = new(std::nothrow) CTetherProvider();

    if (pProvider != nullptr)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }

    return hr;
}

HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv)
{
    return CTetherProvider_CreateInstance(riid, ppv);
}