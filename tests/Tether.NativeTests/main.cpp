#ifndef TETHER_TEST_HARNESS
#define TETHER_TEST_HARNESS
#endif
#include <windows.h>
#include <credentialprovider.h>
#include <iostream>
#include <vector>
#include <cassert>
#include <string>

#include "../../TetherCredentialProvider/guid.h"
#include "../../TetherCredentialProvider/TetherProvider.h"

HINSTANCE g_hinst = nullptr;
void DllAddRef() {}
void DllRelease() {}

// Defined in TetherProvider.cpp when TETHER_TEST_HARNESS is active
void CTetherProvider_SetTestRegistryRoot(HKEY hRoot, const wchar_t* subKey);

static const wchar_t* TEST_KEY_PATH = L"Software\\Tether\\TestPanicLock";

static void CleanTestRegistry()
{
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

static void Test_NormalOperation_OutsidePanic()
{
    CleanTestRegistry();
    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, FALSE, TRUE };

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(SUCCEEDED(hr));
    assert(allow[0] == TRUE);
    assert(allow[1] == FALSE);
    assert(allow[2] == TRUE);

    pFilter->Release();
}

static void Test_PanicActive_HidesAlternatives_PreservesTether_AndRestoresCleanly()
{
    SetTestRegistryPanicState(true, L"native-sess-1");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE, TRUE };

    // 1. Filter during active panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(SUCCEEDED(hr));
    assert(allow[0] == FALSE); // Hidden by Tether
    assert(allow[1] == FALSE); // Hidden by Tether
    assert(allow[2] == TRUE);  // Tether remains visible

    // 2. Clear panic
    SetTestRegistryPanicState(false, L"native-sess-1");

    // 3. Filter during restore
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(SUCCEEDED(hr));
    assert(allow[0] == TRUE); // Restored
    assert(allow[1] == TRUE); // Restored
    assert(allow[2] == TRUE); // Tether remains visible

    pFilter->Release();
}

static void Test_PreserveIncomingDenial_OnAlternativeProvider()
{
    SetTestRegistryPanicState(true, L"native-sess-prehidden");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    // ProvB was ALREADY FALSE before Tether filter executed!
    BOOL allow[] = { TRUE, FALSE, TRUE };

    // 1. Filter during active panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(SUCCEEDED(hr));
    assert(allow[0] == FALSE); // ProvA hidden by Tether
    assert(allow[1] == FALSE); // ProvB remains hidden
    assert(allow[2] == TRUE);  // Tether remains visible

    // 2. Clear panic
    SetTestRegistryPanicState(false, L"native-sess-prehidden");

    // 3. Filter outside panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(SUCCEEDED(hr));
    assert(allow[0] == TRUE);  // ProvA restored (Tether hid it)
    assert(allow[1] == FALSE); // ProvB MUST REMAIN FALSE! Never unhide pre-hidden tiles!
    assert(allow[2] == TRUE);

    pFilter->Release();
}

static void Test_PreserveIncomingDenial_OnTetherProvider()
{
    SetTestRegistryPanicState(true, L"native-sess-tether-denied");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, CLSID_TetherProvider };
    // Another filter already denied Tether!
    BOOL allow[] = { TRUE, FALSE };

    // 1. Filter during active panic
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    assert(SUCCEEDED(hr));
    assert(allow[0] == FALSE); // ProvA hidden
    assert(allow[1] == FALSE); // Tether denial MUST BE PRESERVED! Never reverse another filter's denial!

    // 2. Clear panic
    SetTestRegistryPanicState(false, L"native-sess-tether-denied");

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    assert(SUCCEEDED(hr));
    assert(allow[0] == TRUE);
    assert(allow[1] == FALSE); // Tether denial preserved after restore

    pFilter->Release();
}

static void Test_MultipleCooperatingFilters()
{
    SetTestRegistryPanicState(true, L"native-sess-cooperating");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, ProvC, CLSID_TetherProvider };
    // Filter 1 (Security Policy Filter) denied ProvB and CLSID_TetherProvider
    BOOL allow[] = { TRUE, FALSE, TRUE, FALSE };

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 4);
    assert(SUCCEEDED(hr));
    assert(allow[0] == FALSE); // ProvA hidden by Tether
    assert(allow[1] == FALSE); // ProvB kept denied
    assert(allow[2] == FALSE); // ProvC hidden by Tether
    assert(allow[3] == FALSE); // Tether kept denied

    SetTestRegistryPanicState(false, L"native-sess-cooperating");

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 4);
    assert(SUCCEEDED(hr));
    assert(allow[0] == TRUE);  // ProvA restored
    assert(allow[1] == FALSE); // ProvB preserved FALSE
    assert(allow[2] == TRUE);  // ProvC restored
    assert(allow[3] == FALSE); // Tether preserved FALSE

    pFilter->Release();
}

static void Test_LogonUIReenumeration_DuringPanic()
{
    SetTestRegistryPanicState(true, L"native-sess-reenum");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE };

    // Pass 1: initial panic filtering
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    assert(SUCCEEDED(hr));
    assert(allow[0] == FALSE);
    assert(allow[1] == TRUE);

    // Pass 2: LogonUI re-enumeration while panic is still active
    BOOL reenumAllow[] = { FALSE, TRUE };
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, reenumAllow, 2);
    assert(SUCCEEDED(hr));
    assert(reenumAllow[0] == FALSE);
    assert(reenumAllow[1] == TRUE);

    // Unlock
    SetTestRegistryPanicState(false, L"native-sess-reenum");

    hr = pFilter->Filter(CPUS_LOGON, 0, providers, reenumAllow, 2);
    assert(SUCCEEDED(hr));
    assert(reenumAllow[0] == TRUE);
    assert(reenumAllow[1] == TRUE);

    pFilter->Release();
}

static void Test_RestorationIdempotency()
{
    SetTestRegistryPanicState(true, L"native-sess-idempotent");

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, ProvB, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, FALSE, TRUE };

    // 1. Hide
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(allow[0] == FALSE);
    assert(allow[1] == FALSE);
    assert(allow[2] == TRUE);

    // 2. Clear panic & restore
    SetTestRegistryPanicState(false, L"native-sess-idempotent");
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(allow[0] == TRUE);
    assert(allow[1] == FALSE);
    assert(allow[2] == TRUE);

    // 3. Repeated call after restore must be strictly idempotent
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 3);
    assert(allow[0] == TRUE);
    assert(allow[1] == FALSE);
    assert(allow[2] == TRUE);

    pFilter->Release();
}

static void Test_FailSafe_WhenDaclVersionInvalid()
{
    // Simulate untrusted or tampered registry: VaultDaclVersion is 1 (outdated/untrusted)
    SetTestRegistryPanicState(true, L"native-sess-tamper", 1);

    ICredentialProviderFilter* pFilter = nullptr;
    HRESULT hr = CTetherProvider_CreateInstance(IID_ICredentialProviderFilter, reinterpret_cast<void**>(&pFilter));
    assert(SUCCEEDED(hr) && pFilter != nullptr);

    GUID providers[] = { ProvA, CLSID_TetherProvider };
    BOOL allow[] = { TRUE, TRUE };

    // Must fail safe: refuse to interpret untrusted registry, leave allow states untouched!
    hr = pFilter->Filter(CPUS_LOGON, 0, providers, allow, 2);
    assert(SUCCEEDED(hr));
    assert(allow[0] == TRUE);
    assert(allow[1] == TRUE);

    pFilter->Release();
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << " Tether Native Credential Filter Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    CTetherProvider_SetTestRegistryRoot(HKEY_CURRENT_USER, TEST_KEY_PATH);

    RunTest("NormalOperation_OutsidePanic", Test_NormalOperation_OutsidePanic);
    RunTest("PanicActive_HidesAlternatives_PreservesTether_AndRestoresCleanly", Test_PanicActive_HidesAlternatives_PreservesTether_AndRestoresCleanly);
    RunTest("PreserveIncomingDenial_OnAlternativeProvider", Test_PreserveIncomingDenial_OnAlternativeProvider);
    RunTest("PreserveIncomingDenial_OnTetherProvider", Test_PreserveIncomingDenial_OnTetherProvider);
    RunTest("MultipleCooperatingFilters", Test_MultipleCooperatingFilters);
    RunTest("LogonUIReenumeration_DuringPanic", Test_LogonUIReenumeration_DuringPanic);
    RunTest("RestorationIdempotency", Test_RestorationIdempotency);
    RunTest("FailSafe_WhenDaclVersionInvalid", Test_FailSafe_WhenDaclVersionInvalid);

    std::cout << "========================================" << std::endl;
    std::cout << " All Native Tests Passed Successfully!" << std::endl;
    std::cout << "========================================" << std::endl;
    return 0;
}
