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
static bool g_bSimulateInvalidAcl = false;
static bool g_bSimulateUnexpectedAce = false;
static bool g_bSimulateUnauthorizedAllow = false;
static bool g_bSimulateWriteFailure = false;
static bool g_bEnforceAclInTest = false;

void CTetherProvider_SetTestRegistryRoot(HKEY hRoot, const wchar_t* subKey)
{
    g_hPanicRegistryRoot = hRoot;
    g_wszPanicRegistryPath = (subKey != nullptr && *subKey != L'\0') ? subKey : L"Software\\Tether\\TestPanicLock";
}

void CTetherProvider_SetSimulateInvalidAcl(bool simulate)
{
    g_bSimulateInvalidAcl = simulate;
}

void CTetherProvider_SetSimulateUnexpectedAce(bool simulate)
{
    g_bSimulateUnexpectedAce = simulate;
}

void CTetherProvider_SetSimulateUnauthorizedAllow(bool simulate)
{
    g_bSimulateUnauthorizedAllow = simulate;
}

void CTetherProvider_SetSimulateWriteFailure(bool simulate)
{
    g_bSimulateWriteFailure = simulate;
}

void CTetherProvider_SetEnforceAclInTest(bool enforce)
{
    g_bEnforceAclInTest = enforce;
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

static bool _VerifyRegistrySecurity(HKEY hKey)
{
#ifdef TETHER_TEST_HARNESS
    if (g_bSimulateInvalidAcl)
    {
        return false;
    }
    if (g_bSimulateUnexpectedAce)
    {
        return false;
    }
    if (g_bSimulateUnauthorizedAllow)
    {
        return false;
    }
    if (g_hPanicRegistryRoot != HKEY_LOCAL_MACHINE && !g_bEnforceAclInTest)
    {
        return true;
    }
#endif

    DWORD cbSD = 0;
    LONG lRes = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, nullptr, &cbSD);
    if (lRes != ERROR_SUCCESS && lRes != ERROR_INSUFFICIENT_BUFFER)
    {
        return false;
    }

    if (cbSD == 0)
    {
        return false;
    }

    std::vector<BYTE> sdBuffer(cbSD);
    PSECURITY_DESCRIPTOR pSD = reinterpret_cast<PSECURITY_DESCRIPTOR>(sdBuffer.data());
    lRes = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pSD, &cbSD);
    if (lRes != ERROR_SUCCESS)
    {
        return false;
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD dwRevision = 0;
    if (!GetSecurityDescriptorControl(pSD, &control, &dwRevision))
    {
        return false;
    }

    // Strictly require protected ACL (explicit inheritance protection)
    if ((control & SE_DACL_PROTECTED) == 0)
    {
        return false;
    }

    BOOL bDaclPresent = FALSE;
    PACL pAcl = nullptr;
    BOOL bDaclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pAcl, &bDaclDefaulted) || !bDaclPresent || pAcl == nullptr)
    {
        return false;
    }

    BYTE sidSystemBuffer[SECURITY_MAX_SID_SIZE] = { 0 };
    DWORD cbSidSystem = sizeof(sidSystemBuffer);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sidSystemBuffer, &cbSidSystem))
    {
        return false;
    }
    PSID pSidSystem = reinterpret_cast<PSID>(sidSystemBuffer);

    BYTE sidAdminsBuffer[SECURITY_MAX_SID_SIZE] = { 0 };
    DWORD cbSidAdmins = sizeof(sidAdminsBuffer);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sidAdminsBuffer, &cbSidAdmins))
    {
        return false;
    }
    PSID pSidAdmins = reinterpret_cast<PSID>(sidAdminsBuffer);

    bool bHasSystem = false;
    bool bHasAdmins = false;

    for (WORD i = 0; i < pAcl->AceCount; ++i)
    {
        LPVOID pAce = nullptr;
        if (!GetAce(pAcl, i, &pAce) || pAce == nullptr)
        {
            return false;
        }

        PACE_HEADER pHeader = reinterpret_cast<PACE_HEADER>(pAce);
        if (pHeader->AceType == ACCESS_DENIED_ACE_TYPE)
        {
            PACCESS_DENIED_ACE pDenied = reinterpret_cast<PACCESS_DENIED_ACE>(pAce);
            PSID pAceSid = reinterpret_cast<PSID>(&pDenied->SidStart);
            if (EqualSid(pAceSid, pSidSystem) || EqualSid(pAceSid, pSidAdmins))
            {
                return false;
            }
        }
        else if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
        {
            PACCESS_ALLOWED_ACE pAllowed = reinterpret_cast<PACCESS_ALLOWED_ACE>(pAce);
            PSID pAceSid = reinterpret_cast<PSID>(&pAllowed->SidStart);

            DWORD reqRights = (KEY_READ | KEY_WRITE);
            if ((pAllowed->Mask & reqRights) != reqRights && (pAllowed->Mask & KEY_ALL_ACCESS) != KEY_ALL_ACCESS)
            {
                return false;
            }

            if (EqualSid(pAceSid, pSidSystem))
            {
                bHasSystem = true;
            }
            else if (EqualSid(pAceSid, pSidAdmins))
            {
                bHasAdmins = true;
            }
            else
            {
                // Disallow unauthorized SIDs
                return false;
            }
        }
        else
        {
            // Reject unexpected ACE types
            return false;
        }
    }

    if (!bHasSystem || !bHasAdmins)
    {
        return false;
    }

    return true;
}

static HRESULT _ReadPanicFilterState(
    _Out_ bool* pbPanicActive,
    _Out_ std::wstring* pSessionId,
    _Out_ std::vector<GUID>* pHiddenProviders,
    _Out_opt_ std::vector<GUID>* pIndependentlyDeniedProviders = nullptr)
{
    if (pbPanicActive == nullptr || pSessionId == nullptr || pHiddenProviders == nullptr)
    {
        return E_POINTER;
    }

    *pbPanicActive = false;
    pSessionId->clear();
    pHiddenProviders->clear();
    if (pIndependentlyDeniedProviders != nullptr)
    {
        pIndependentlyDeniedProviders->clear();
    }

    HKEY hKey = nullptr;
    LONG lRes = RegOpenKeyExW(g_hPanicRegistryRoot, _GetPanicRegistryPath(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (lRes == ERROR_FILE_NOT_FOUND)
    {
        WriteDebugLog(L"CTetherProvider::_ReadPanicFilterState: PanicLock key not found (normal non-panic state).");
        return S_OK;
    }
    if (lRes != ERROR_SUCCESS)
    {
        WriteDebugLog(L"CTetherProvider::_ReadPanicFilterState: RegOpenKeyExW failed with %ld", lRes);
        return HRESULT_FROM_WIN32(lRes);
    }

    if (!_VerifyRegistrySecurity(hKey))
    {
        WriteDebugLog(L"CTetherProvider::_ReadPanicFilterState: _VerifyRegistrySecurity rejected key ACL (E_ACCESSDENIED)");
        RegCloseKey(hKey);
        return E_ACCESSDENIED;
    }

    DWORD dwType = 0;
    DWORD dwDaclVer = 0;
    DWORD dwSize = sizeof(dwDaclVer);
    lRes = RegQueryValueExW(hKey, L"VaultDaclVersion", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwDaclVer), &dwSize);
    if (lRes != ERROR_SUCCESS || dwType != REG_DWORD || dwSize != sizeof(DWORD) || dwDaclVer < 2)
    {
        WriteDebugLog(L"CTetherProvider::_ReadPanicFilterState: Missing or invalid VaultDaclVersion (lRes=%ld, type=%u, ver=%u)", lRes, dwType, dwDaclVer);
        RegCloseKey(hKey);
        return E_FAIL;
    }

    DWORD dwPanicActive = 0;
    dwSize = sizeof(dwPanicActive);
    lRes = RegQueryValueExW(hKey, L"IsPanicActive", nullptr, &dwType, reinterpret_cast<LPBYTE>(&dwPanicActive), &dwSize);
    if (lRes != ERROR_SUCCESS || dwType != REG_DWORD || dwSize != sizeof(DWORD))
    {
        WriteDebugLog(L"CTetherProvider::_ReadPanicFilterState: Missing or invalid IsPanicActive (lRes=%ld, type=%u)", lRes, dwType);
        RegCloseKey(hKey);
        return E_FAIL;
    }
    *pbPanicActive = (dwPanicActive != 0);

    wchar_t szSessionId[128] = { 0 };
    dwSize = sizeof(szSessionId);
    lRes = RegQueryValueExW(hKey, L"PanicSessionId", nullptr, &dwType, reinterpret_cast<LPBYTE>(szSessionId), &dwSize);
    if (lRes != ERROR_SUCCESS || dwType != REG_SZ || dwSize <= sizeof(wchar_t) || szSessionId[0] == L'\0')
    {
        WriteDebugLog(L"CTetherProvider::_ReadPanicFilterState: Missing or invalid PanicSessionId (lRes=%ld, type=%u)", lRes, dwType);
        RegCloseKey(hKey);
        return E_FAIL;
    }
    *pSessionId = szSessionId;

    // Read HiddenProviders (optional, but if present must be REG_MULTI_SZ)
    dwType = 0;
    dwSize = 0;
    lRes = RegQueryValueExW(hKey, L"HiddenProviders", nullptr, &dwType, nullptr, &dwSize);
    if (lRes == ERROR_SUCCESS)
    {
        if (dwType != REG_MULTI_SZ)
        {
            RegCloseKey(hKey);
            return E_FAIL;
        }
        if (dwSize > 0)
        {
            std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t) + 2, 0);
            lRes = RegQueryValueExW(hKey, L"HiddenProviders", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer.data()), &dwSize);
            if (lRes == ERROR_SUCCESS)
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
            else
            {
                RegCloseKey(hKey);
                return HRESULT_FROM_WIN32(lRes);
            }
        }
    }
    else if (lRes != ERROR_FILE_NOT_FOUND)
    {
        RegCloseKey(hKey);
        return HRESULT_FROM_WIN32(lRes);
    }

    // Read IndependentlyDeniedProviders (optional, if present must be REG_MULTI_SZ)
    if (pIndependentlyDeniedProviders != nullptr)
    {
        dwType = 0;
        dwSize = 0;
        lRes = RegQueryValueExW(hKey, L"IndependentlyDeniedProviders", nullptr, &dwType, nullptr, &dwSize);
        if (lRes == ERROR_SUCCESS)
        {
            if (dwType != REG_MULTI_SZ)
            {
                RegCloseKey(hKey);
                return E_FAIL;
            }
            if (dwSize > 0)
            {
                std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t) + 2, 0);
                lRes = RegQueryValueExW(hKey, L"IndependentlyDeniedProviders", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer.data()), &dwSize);
                if (lRes == ERROR_SUCCESS)
                {
                    const wchar_t* p = buffer.data();
                    while (*p != L'\0')
                    {
                        GUID guid = GUID_NULL;
                        if (SUCCEEDED(IIDFromString(p, &guid)) && !IsEqualGUID(guid, GUID_NULL))
                        {
                            pIndependentlyDeniedProviders->push_back(guid);
                        }
                        p += wcslen(p) + 1;
                    }
                }
                else
                {
                    RegCloseKey(hKey);
                    return HRESULT_FROM_WIN32(lRes);
                }
            }
        }
        else if (lRes != ERROR_FILE_NOT_FOUND)
        {
            RegCloseKey(hKey);
            return HRESULT_FROM_WIN32(lRes);
        }
    }

    RegCloseKey(hKey);
    return S_OK;
}

static HRESULT _WriteHiddenProviders(const std::vector<GUID>& hiddenProviders)
{
#ifdef TETHER_TEST_HARNESS
    if (g_bSimulateWriteFailure)
    {
        return E_FAIL;
    }
#endif

    HKEY hKey = nullptr;
    LONG lRes = RegOpenKeyExW(g_hPanicRegistryRoot, _GetPanicRegistryPath(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
    if (lRes != ERROR_SUCCESS)
    {
        WriteDebugLog(L"CTetherProvider::_WriteHiddenProviders: RegOpenKeyExW failed with %ld", lRes);
        return HRESULT_FROM_WIN32(lRes);
    }

    if (hiddenProviders.empty())
    {
        LONG lDel = RegDeleteValueW(hKey, L"HiddenProviders");
        RegCloseKey(hKey);
        if (lDel != ERROR_SUCCESS && lDel != ERROR_FILE_NOT_FOUND)
        {
            return HRESULT_FROM_WIN32(lDel);
        }
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
    LONG lSet = RegSetValueExW(hKey, L"HiddenProviders", 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(multiSz.data()), cbData);
    RegCloseKey(hKey);

    if (lSet != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(lSet);
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
            WriteDebugLog(L"CTetherProvider::Filter: Null arguments or 0 providers (scenario=%u, cProviders=%u)", cpus, cProviders);
            return S_OK;
        }

        WriteDebugLog(L"CTetherProvider::Filter: Invoked (scenario=%u, flags=0x%08X, cProviders=%u)", cpus, dwFlags, cProviders);

        bool bPanicActive = false;
        std::wstring sessionId;
        std::vector<GUID> previouslyHidden;
        std::vector<GUID> independentlyDenied;

        HRESULT hr = _ReadPanicFilterState(&bPanicActive, &sessionId, &previouslyHidden, &independentlyDenied);
        if (FAILED(hr))
        {
            WriteDebugLog(L"CTetherProvider::Filter: Failed to read PanicLock state (hr=0x%08X). Failing closed, preserving allow states.", hr);
            // Fail closed: missing, malformed, inaccessible or inconsistent panic state
            // must NEVER trigger provider restoration!
            // Preserve incoming allow states without modification.
            return hr;
        }

        WriteDebugLog(L"CTetherProvider::Filter: State read ok. bPanicActive=%d, session='%ls', prevHidden=%zu, indepDenied=%zu",
            bPanicActive ? 1 : 0, sessionId.c_str(), previouslyHidden.size(), independentlyDenied.size());

        if (bPanicActive)
        {
            // Panic Lock is ACTIVE:
            // 1. Preserve any incoming FALSE decision: if a provider (including Tether's own)
            //    was already denied (FALSE), it must remain FALSE (never override another filter).
            // 2. Hide alternative providers that are currently allowed (TRUE) and track them.
            // 3. For providers already FALSE, keep them FALSE and do not track as hidden by Tether.
            std::vector<GUID> newlyHidden = previouslyHidden;
            std::vector<DWORD> newlyHiddenIndices;

            for (DWORD i = 0; i < cProviders; ++i)
            {
                wchar_t szGuid[64] = { 0 };
                StringFromGUID2(rgclsidProviders[i], szGuid, ARRAYSIZE(szGuid));

                if (IsEqualGUID(rgclsidProviders[i], CLSID_TetherProvider))
                {
                    // Preserve incoming rgbAllow[i] decision. If already FALSE, leave FALSE.
                    // Do not force rgbAllow[i] = TRUE over another filter's denial.
                    WriteDebugLog(L"CTetherProvider::Filter [PANIC ACTIVE]: Preserving Tether provider [%u] %ls allow=%d", i, szGuid, rgbAllow[i]);
                }
                else
                {
                    if (rgbAllow[i] == FALSE)
                    {
                        // Already denied before Tether touched it. Keep FALSE and do not claim ownership.
                        WriteDebugLog(L"CTetherProvider::Filter [PANIC ACTIVE]: Provider [%u] %ls already denied (allow=0), preserving denial", i, szGuid);
                    }
                    else
                    {
                        // Provider was currently allowed. Tether explicitly hides it.
                        rgbAllow[i] = FALSE;
                        newlyHiddenIndices.push_back(i);
                        WriteDebugLog(L"CTetherProvider::Filter [PANIC ACTIVE]: Hiding alternative provider [%u] %ls (allow=1 -> allow=0)", i, szGuid);

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
                        }
                    }
                }
            }

            if (newlyHidden.size() > previouslyHidden.size())
            {
                HRESULT hrWrite = _WriteHiddenProviders(newlyHidden);
                if (FAILED(hrWrite))
                {
                    WriteDebugLog(L"CTetherProvider::Filter [PANIC ACTIVE]: Failed to persist hidden providers (hr=0x%08X), reverting allow states", hrWrite);
                    // Persistence failed: never silently report successful ownership persistence!
                    // Revert the allow states modified during this pass so we don't hide providers
                    // without persistent backing.
                    for (DWORD idx : newlyHiddenIndices)
                    {
                        rgbAllow[idx] = TRUE;
                    }
                    return hrWrite;
                }
            }
        }
        else
        {
            // Panic Lock is INACTIVE:
            // 1. Restore only providers explicitly hidden by Tether.
            // 2. Never set a provider's allow state to TRUE merely because it appears in HiddenProviders.
            // 3. If incoming rgbAllow[i] == FALSE or the provider is in independentlyDenied,
            //    preserve the denial (leave FALSE), and do NOT mark as restored!
            // 4. Retain records for providers absent from the current enumeration.
            // 5. Remove an ownership record only after its restoration has been successfully completed.
            if (!previouslyHidden.empty())
            {
                std::vector<GUID> successfullyRestored;

                for (DWORD i = 0; i < cProviders; ++i)
                {
                    wchar_t szGuid[64] = { 0 };
                    StringFromGUID2(rgclsidProviders[i], szGuid, ARRAYSIZE(szGuid));

                    if (IsEqualGUID(rgclsidProviders[i], CLSID_TetherProvider))
                    {
                        // Preserve incoming decision
                        WriteDebugLog(L"CTetherProvider::Filter [RESTORE]: Tether provider [%u] %ls preserved allow=%d", i, szGuid, rgbAllow[i]);
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

                        bool isIndependentlyDenied = false;
                        for (const auto& g : independentlyDenied)
                        {
                            if (IsEqualGUID(g, rgclsidProviders[i]))
                            {
                                isIndependentlyDenied = true;
                                break;
                            }
                        }

                        if (wasHiddenByTether)
                        {
                            // If independently denied OR incoming rgbAllow[i] is already FALSE (imposed by preceding filter),
                            // preserve the denial rather than guessing!
                            if (isIndependentlyDenied || rgbAllow[i] == FALSE)
                            {
                                rgbAllow[i] = FALSE;
                                WriteDebugLog(L"CTetherProvider::Filter [RESTORE]: Provider [%u] %ls has independent denial (isIndep=%d, incoming=%d), keeping allow=0",
                                    i, szGuid, isIndependentlyDenied ? 1 : 0, rgbAllow[i]);
                                // NOT added to successfullyRestored: retain ownership record until demonstrably restored
                            }
                            else
                            {
                                // Clean restoration: Tether hid it and no independent denial exists
                                rgbAllow[i] = TRUE;
                                successfullyRestored.push_back(rgclsidProviders[i]);
                                WriteDebugLog(L"CTetherProvider::Filter [RESTORE]: Clean restoration of provider [%u] %ls (allow=0 -> allow=1)", i, szGuid);
                            }
                        }
                        else
                        {
                            WriteDebugLog(L"CTetherProvider::Filter [RESTORE]: Provider [%u] %ls not hidden by Tether, leaving untouched (allow=%d)", i, szGuid, rgbAllow[i]);
                        }
                    }
                }

                if (!successfullyRestored.empty())
                {
                    std::vector<GUID> remainingHidden;
                    for (const auto& g : previouslyHidden)
                    {
                        bool restored = false;
                        for (const auto& r : successfullyRestored)
                        {
                            if (IsEqualGUID(g, r))
                            {
                                restored = true;
                                break;
                            }
                        }
                        if (!restored)
                        {
                            // Retain record for providers absent from the current enumeration
                            remainingHidden.push_back(g);
                        }
                    }

                    // Remove ownership records only after successful restoration!
                    HRESULT hrWrite = _WriteHiddenProviders(remainingHidden);
                    if (FAILED(hrWrite))
                    {
                        WriteDebugLog(L"CTetherProvider::Filter [RESTORE]: Failed to update remaining hidden providers in registry (hr=0x%08X)", hrWrite);
                        // Failed to update registry: preserve recovery information!
                        return hrWrite;
                    }
                }
            }
        }

        WriteDebugLog(L"CTetherProvider::Filter: Completed successfully.");
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