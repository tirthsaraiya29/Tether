#ifndef TETHER_TEST_HARNESS
#define TETHER_TEST_HARNESS
#endif
#include <windows.h>
#include <credentialprovider.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

#include "../../TetherCredentialProvider/guid.h"
#include "../../TetherCredentialProvider/TetherProvider.h"

HINSTANCE g_hinst = nullptr;
void DllAddRef() {}
void DllRelease() {}

// Custom assertion macro that remains active in BOTH Debug and Release mode builds (NDEBUG proof)
#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        std::cerr << "Assertion failed: " #cond << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
        std::exit(1); \
    } \
} while (0)

// Exported test helpers from TetherProvider.cpp
void CTetherProvider_SetTestRegistryRoot(HKEY hRoot, const wchar_t* subKey);
void CTetherProvider_SetSimulateInvalidAcl(bool simulate);
void CTetherProvider_SetSimulateWriteFailure(bool simulate);

static const wchar_t* TEST_KEY_PATH = L"Software\\Tether\\TestPanicLock";

static void CleanTestRegistry()
{
    CTetherProvider_SetSimulateInvalidAcl(false);
    CTetherProvider_SetSimulateWriteFailure(false);
    RegDeleteKeyW(HKEY_CURRENT_USER, TEST_KEY_PATH);
}

static void SetTestRegistryPanicState(bool active, const wchar_t* sessionId, DWORD daclVer = 2)
{
    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, TEST_KEY_PATH, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        DWORD dwDacl = daclVer;
        RegSetValueExW(hKey, L"VaultDaclVersion", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwDacl), sizeof(dwDacl));

        DWORD dwActive = active ? 1 : 0;
        RegSetValueExW(hKey, L"IsPanicActive", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwActive), sizeof(dwActive));

        if (sessionId != nullptr)
        {
            RegSetValueExW(hKey, L"PanicSessionId", 0, REG_SZ, reinterpret_cast<const BYTE*>(sessionId), static_cast<DWORD>((wcslen(sessionId) + 1) * sizeof(wchar_t)));
        }

        RegCloseKey(hKey);
    }
}

static std::vector<GUID> GetTestRegistryHiddenProviders()
{
    std::vector<GUID> result;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, TEST_KEY_PATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        DWORD dwType = 0;
        DWORD dwSize = 0;
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
                        result.push_back(guid);
                    }
                    p += wcslen(p) + 1;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return result;
}

static const GUID ProvA = { 0x11111111, 0x1111, 0x1111, { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } };
static const GUID ProvB = { 0x22222222, 0x2222, 0x2222, { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 } };
static const GUID ProvC = { 0x33333333, 0x3333, 0x3333, { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 } };

static void RunTest(const char* name, void (*testFunc)())
{
    std::cout << "[RUNNING] " << name << "..." << std::endl;
    CleanTestRegistry();
    testFunc();
    CleanTestRegistry();
    std::cout << "[PASSED]  " << name << std::endl;
}

static void Test_ReleaseModeNativeTestAssertions()
{
    // Verify TEST_ASSERT is operational in Release mode
    bool reached = false;
    int x = 42;
    TEST_ASSERT(x == 42);
    reached = true;
    TEST_ASSERT(reached);
}

static void Test_NormalOperation_OutsidePanic()
{
    CleanTestRegistry();
    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, FALSE, TRUE };

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == TRUE);
    TEST_ASSERT(allow[1] == FALSE);
    TEST_ASSERT(allow[2] == TRUE);

    pFilter->Release();
}

static void Test_PanicActive_HidesAlternatives_PreservesTether_AndRestoresCleanly()
{
    SetTestRegistryPanicState(true, L"native-sess-1");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE, TRUE };

    // 1. Filter during active panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == FALSE); // Hidden by Tether
    TEST_ASSERT(allow[1] == FALSE); // Hidden by Tether
    TEST_ASSERT(allow[2] == TRUE);  // Tether remains visible

    // Verify registry captured hidden providers
    auto hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.size() == 2);

    // 2. Clear panic
    SetTestRegistryPanicState(false, L"native-sess-1");

    // 3. Filter during restore
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == TRUE); // Restored
    TEST_ASSERT(allow[1] == TRUE); // Restored
    TEST_ASSERT(allow[2] == TRUE); // Tether remains visible

    // Verify registry is cleaned after full restoration
    hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.empty());

    pFilter->Release();
}

static void Test_PreserveIncomingDenial_OnAlternativeProvider()
{
    SetTestRegistryPanicState(true, L"native-sess-prehidden");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    // ProvB was ALREADY FALSE before Tether filter executed!
    BOOL allow[] = { TRUE, FALSE, TRUE };

    // 1. Filter during active panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == FALSE); // ProvA hidden by Tether
    TEST_ASSERT(allow[1] == FALSE); // ProvB remains hidden
    TEST_ASSERT(allow[2] == TRUE);  // Tether remains visible

    // ProvB must NOT be recorded as hidden by Tether!
    auto hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.size() == 1);
    TEST_ASSERT(IsEqualGUID(hidden[0], ProvA));

    // 2. Clear panic
    SetTestRegistryPanicState(false, L"native-sess-prehidden");

    // 3. Filter outside panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == TRUE);  // ProvA restored (Tether hid it)
    TEST_ASSERT(allow[1] == FALSE); // ProvB MUST REMAIN FALSE! Never unhide pre-hidden tiles!
    TEST_ASSERT(allow[2] == TRUE);

    pFilter->Release();
}

static void Test_PreserveIncomingDenial_OnTetherProvider()
{
    SetTestRegistryPanicState(true, L"native-sess-tether-denied");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, CLSID_TetherProvider };
    // Another filter already denied Tether!
    BOOL allow[] = { TRUE, FALSE };

    // 1. Filter during active panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == FALSE); // ProvA hidden
    TEST_ASSERT(allow[1] == FALSE); // Tether denial MUST BE PRESERVED!

    // 2. Clear panic
    SetTestRegistryPanicState(false, L"native-sess-tether-denied");

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == TRUE);
    TEST_ASSERT(allow[1] == FALSE); // Tether denial preserved after restore

    pFilter->Release();
}

static void Test_MultipleCooperatingFilters()
{
    SetTestRegistryPanicState(true, L"native-sess-cooperating");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, ProvC, CLSID_TetherProvider };
    // Filter 1 (Security Policy Filter) denied ProvB and CLSID_TetherProvider
    BOOL allow[] = { TRUE, FALSE, TRUE, FALSE };

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 4);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == FALSE); // ProvA hidden by Tether
    TEST_ASSERT(allow[1] == FALSE); // ProvB kept denied
    TEST_ASSERT(allow[2] == FALSE); // ProvC hidden by Tether
    TEST_ASSERT(allow[3] == FALSE); // Tether kept denied

    SetTestRegistryPanicState(false, L"native-sess-cooperating");

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 4);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == TRUE);  // ProvA restored
    TEST_ASSERT(allow[1] == FALSE); // ProvB preserved FALSE
    TEST_ASSERT(allow[2] == TRUE);  // ProvC restored
    TEST_ASSERT(allow[3] == FALSE); // Tether preserved FALSE

    pFilter->Release();
}

static void Test_LogonUIReenumeration_DuringPanic()
{
    SetTestRegistryPanicState(true, L"native-sess-reenum");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE };

    // Pass 1: initial panic filtering
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == FALSE);
    TEST_ASSERT(allow[1] == TRUE);

    // Pass 2: LogonUI re-enumeration while panic is still active
    BOOL reenumAllow[] = { FALSE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, reenumAllow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(reenumAllow[0] == FALSE);
    TEST_ASSERT(reenumAllow[1] == TRUE);

    // Unlock
    SetTestRegistryPanicState(false, L"native-sess-reenum");

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, reenumAllow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(reenumAllow[0] == TRUE);
    TEST_ASSERT(reenumAllow[1] == TRUE);

    pFilter->Release();
}

static void Test_RestorationIdempotency()
{
    SetTestRegistryPanicState(true, L"native-sess-idempotent");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, FALSE, TRUE };

    // 1. Hide
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(allow[0] == FALSE);
    TEST_ASSERT(allow[1] == FALSE);
    TEST_ASSERT(allow[2] == TRUE);

    // 2. Clear panic & restore
    SetTestRegistryPanicState(false, L"native-sess-idempotent");
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(allow[0] == TRUE);
    TEST_ASSERT(allow[1] == FALSE);
    TEST_ASSERT(allow[2] == TRUE);

    // 3. Repeated call after restore must be strictly idempotent
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(allow[0] == TRUE);
    TEST_ASSERT(allow[1] == FALSE);
    TEST_ASSERT(allow[2] == TRUE);

    pFilter->Release();
}

static void Test_FailSafe_WhenDaclVersionInvalid()
{
    SetTestRegistryPanicState(true, L"native-sess-tamper", 1);

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE };

    // Must fail safe: refuse to interpret untrusted registry, leave allow states untouched!
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == TRUE);
    TEST_ASSERT(allow[1] == TRUE);

    pFilter->Release();
}

static void Test_FailSafe_WhenSecurityAclInvalid()
{
    SetTestRegistryPanicState(true, L"native-sess-invalid-acl");
    CTetherProvider_SetSimulateInvalidAcl(true);

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE };

    // When security descriptor validation fails, fail safe and leave allow states untouched
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == TRUE);
    TEST_ASSERT(allow[1] == TRUE);

    CTetherProvider_SetSimulateInvalidAcl(false);
    pFilter->Release();
}

static void Test_FailedRegistryWrite_PreservesState()
{
    SetTestRegistryPanicState(true, L"native-sess-write-fail");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    // Initial normal hide of ProvA
    GUID p1[] = { ProvA, CLSID_TetherProvider };
    BOOL a1[] = { TRUE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, p1, a1, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(a1[0] == FALSE);

    auto hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.size() == 1);
    TEST_ASSERT(IsEqualGUID(hidden[0], ProvA));

    // Now simulate registry write failure when new provider ProvB appears
    CTetherProvider_SetSimulateWriteFailure(true);

    GUID p2[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL a2[] = { FALSE, TRUE, TRUE };

    hr = pFilter->Filter(CPUS_LOGON, 0, p2, a2, 3);
    // Write failed: Filter must NOT silently report success, and must revert ProvB allow state
    TEST_ASSERT(FAILED(hr));
    TEST_ASSERT(a2[1] == TRUE); // ProvB not hidden because persistence failed

    // Prior recorded provider ProvA is NOT lost
    CTetherProvider_SetSimulateWriteFailure(false);
    hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.size() == 1);
    TEST_ASSERT(IsEqualGUID(hidden[0], ProvA));

    pFilter->Release();
}

static void Test_ProvidersAbsentDuringFirstRestorationEnumeration()
{
    SetTestRegistryPanicState(true, L"native-sess-partial-restore");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    // 1. Active panic: both ProvA and ProvB are hidden
    GUID allProviders[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allAllow[] = { TRUE, TRUE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, allProviders, allAllow, 3);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allAllow[0] == FALSE);
    TEST_ASSERT(allAllow[1] == FALSE);

    auto hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.size() == 2);

    // 2. Panic Lock cleared
    SetTestRegistryPanicState(false, L"native-sess-partial-restore");

    // 3. First restoration pass only enumerates ProvA (ProvB is absent)
    GUID pass1Providers[] = { ProvA, CLSID_TetherProvider };
    BOOL pass1Allow[] = { TRUE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, pass1Providers, pass1Allow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(pass1Allow[0] == TRUE); // ProvA restored

    // ProvB was absent: ownership record for ProvB MUST BE RETAINED!
    hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.size() == 1);
    TEST_ASSERT(IsEqualGUID(hidden[0], ProvB));

    // 4. Second restoration pass enumerates ProvB
    GUID pass2Providers[] = { ProvB, CLSID_TetherProvider };
    BOOL pass2Allow[] = { TRUE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, pass2Providers, pass2Allow, 2);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(pass2Allow[0] == TRUE); // ProvB restored

    // All restored: registry records cleared
    hidden = GetTestRegistryHiddenProviders();
    TEST_ASSERT(hidden.empty());

    pFilter->Release();
}

static void Test_ThirdPartyDenialIntroducedAfterTetherHidesProvider()
{
    SetTestRegistryPanicState(true, L"native-sess-3rdparty");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    TEST_ASSERT(SUCCEEDED(hr) && pFilter != nullptr);

    // 1. Active panic: ProvA and ProvB hidden
    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    TEST_ASSERT(SUCCEEDED(hr));
    TEST_ASSERT(allow[0] == FALSE);
    TEST_ASSERT(allow[1] == FALSE);

    // 2. Clear panic
    SetTestRegistryPanicState(false, L"native-sess-3rdparty");

    // 3. An independent component/policy introduced a denial for ProvB after Tether hid it!
    // This updates the persistent registry state so ProvB is no longer eligible for Tether restoration.
    // (Simulating managed RecordIndependentDenial having synchronized to registry)
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, TEST_KEY_PATH, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        wchar_t szGuid[64] = { 0 };
        StringFromGUID2(ProvA, szGuid, ARRAYSIZE(szGuid));
        size_t len = wcslen(szGuid);
        std::vector<wchar_t> multiSz(szGuid, szGuid + len + 1);
        multiSz.push_back(L'\0');
        RegSetValueExW(hKey, L"HiddenProviders", 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(multiSz.data()), static_cast<DWORD>(multiSz.size() * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }

    // 4. Restore enumeration executes:
    BOOL restoreAllow[] = { FALSE, FALSE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, restoreAllow, 3);
    TEST_ASSERT(SUCCEEDED(hr));

    // ProvA was in HiddenProviders -> restored to TRUE
    TEST_ASSERT(restoreAllow[0] == TRUE);
    // ProvB was denied by third party -> MUST REMAIN FALSE! Never unhide!
    TEST_ASSERT(restoreAllow[1] == FALSE);

    pFilter->Release();
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << " Tether Native Credential Filter Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    CTetherProvider_SetTestRegistryRoot(HKEY_CURRENT_USER, TEST_KEY_PATH);

    RunTest("ReleaseModeNativeTestAssertions", Test_ReleaseModeNativeTestAssertions);
    RunTest("NormalOperation_OutsidePanic", Test_NormalOperation_OutsidePanic);
    RunTest("PanicActive_HidesAlternatives_PreservesTether_AndRestoresCleanly", Test_PanicActive_HidesAlternatives_PreservesTether_AndRestoresCleanly);
    RunTest("PreserveIncomingDenial_OnAlternativeProvider", Test_PreserveIncomingDenial_OnAlternativeProvider);
    RunTest("PreserveIncomingDenial_OnTetherProvider", Test_PreserveIncomingDenial_OnTetherProvider);
    RunTest("MultipleCooperatingFilters", Test_MultipleCooperatingFilters);
    RunTest("LogonUIReenumeration_DuringPanic", Test_LogonUIReenumeration_DuringPanic);
    RunTest("RestorationIdempotency", Test_RestorationIdempotency);
    RunTest("FailSafe_WhenDaclVersionInvalid", Test_FailSafe_WhenDaclVersionInvalid);
    RunTest("FailSafe_WhenSecurityAclInvalid", Test_FailSafe_WhenSecurityAclInvalid);
    RunTest("FailedRegistryWrite_PreservesState", Test_FailedRegistryWrite_PreservesState);
    RunTest("ProvidersAbsentDuringFirstRestorationEnumeration", Test_ProvidersAbsentDuringFirstRestorationEnumeration);
    RunTest("ThirdPartyDenialIntroducedAfterTetherHidesProvider", Test_ThirdPartyDenialIntroducedAfterTetherHidesProvider);

    std::cout << "========================================" << std::endl;
    std::cout << " All Native Tests Passed Successfully!" << std::endl;
    std::cout << "========================================" << std::endl;
    return 0;
}
