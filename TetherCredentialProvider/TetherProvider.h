#pragma once

#include "helpers.h"
#include <windows.h>
#include <strsafe.h>
#include <atomic>
#include <new>

#include <vector>

#include "TetherCredential.h"

HRESULT CTetherProvider_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv);
HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv);

class CTetherProvider : public ICredentialProvider,
    public ICredentialProviderSetUserArray,
    public ICredentialProviderFilter
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CTetherProvider, ICredentialProvider),
            QITABENT(CTetherProvider, ICredentialProviderSetUserArray),
            QITABENT(CTetherProvider, ICredentialProviderFilter),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

    // Declaration only - the body resides exclusively in TetherProvider.cpp
    HRESULT SignalCredentialsChanged();

public:
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(_In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const* pcpcs);

    IFACEMETHODIMP Advise(_In_ ICredentialProviderEvents* pcpe, _In_ UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(_Out_ DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    IFACEMETHODIMP GetCredentialCount(_Out_ DWORD* pdwCount,
        _Out_ DWORD* pdwDefault,
        _Out_ BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
        _Outptr_result_nullonfailure_ ICredentialProviderCredential** ppcpc);

    IFACEMETHODIMP SetUserArray(_In_ ICredentialProviderUserArray* users);

    // ICredentialProviderFilter
    IFACEMETHODIMP Filter(
        _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        _In_ DWORD dwFlags,
        _In_reads_(cProviders) GUID* rgclsidProviders,
        _Inout_updates_(cProviders) BOOL* rgbAllow,
        _In_ DWORD cProviders);

    IFACEMETHODIMP UpdateRemoteCredential(
        _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const* pcpcsIn,
        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut);

    friend HRESULT CTetherProvider_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv);
    friend HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv);

#ifdef TETHER_TEST_HARNESS
    friend void CTetherProvider_SetTestRegistryRoot(HKEY hRoot, const wchar_t* subKey);
#endif

protected:
    CTetherProvider();
    virtual ~CTetherProvider();

private:
    void _ReleaseEnumeratedCredentials();
    void _CreateEnumeratedCredentials();
    HRESULT _EnumerateEmpty();
    HRESULT _EnumerateCredentials();
    HRESULT _EnumerateEmptyTileCredential();

private:
    std::atomic<long>                       _cRef;
    std::vector<CTetherCredential*>         _credentials;
    bool                                    _fRecreateEnumeratedCredentials;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
    ICredentialProviderUserArray*           _pCredProviderUserArray;

    // Unified naming alignment matching the implementation file
    CRITICAL_SECTION                        _csEvents;
    ICredentialProviderEvents*              _pCredProviderEvents;
    UINT_PTR                                _upAdviseContext;
    DWORD                                   _dwUpToDateCredentialsCount;
};

typedef CTetherProvider CSampleProvider;