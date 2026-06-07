//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.

#include <initguid.h>
#include <new>
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"

CSampleProvider::CSampleProvider() :
    _cRef(1),
    _pCredential(nullptr),
    _pCredProviderUserArray(nullptr),
    _fRecreateEnumeratedCredentials(false),
    _cpus(CPUS_INVALID),
    _pCredProviderEvents(nullptr),
    _upAdviseContext(0),
    _dwUpToDateCredentialsCount(0) // Fixed initialization
{
    DllAddRef();
}

CSampleProvider::~CSampleProvider()
{
    _ReleaseEnumeratedCredentials();
    if (_pCredProviderEvents != nullptr)
    {
        _pCredProviderEvents->Release();
        _pCredProviderEvents = nullptr;
    }
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
    DllRelease();
}

HRESULT CSampleProvider::SetUsageScenario(
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _In_ DWORD dwFlags)
{
    HRESULT hr = S_OK;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION: // Supports locked workstation transitions natively
    case CPUS_CREDUI:
        _cpus = cpus;
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

HRESULT CSampleProvider::GetFieldDescriptorCount(_Out_ DWORD* pdwCount)
{
    if (pdwCount == nullptr)
    {
        return E_POINTER;
    }
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

HRESULT CSampleProvider::GetFieldDescriptorAt(
    _In_ DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
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

HRESULT CSampleProvider::GetCredentialCount(
    _Out_ DWORD* pdwCount,
    _Out_ DWORD* pdwDefault,
    _Out_ BOOL* pbAutoLogonWithDefault)
{
    if (pdwCount == nullptr || pdwDefault == nullptr || pbAutoLogonWithDefault == nullptr)
    {
        return E_POINTER;
    }

    *pdwCount = 0;
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    HRESULT hr = S_OK;

    if (_pCredential == nullptr)
    {
        hr = _EnumerateCredentials();
    }

    if (SUCCEEDED(hr) && _pCredential != nullptr)
    {
        *pdwCount = 1;
        *pdwDefault = 0;

        extern bool g_fAutoLogonReady;
        if (g_fAutoLogonReady)
        {
            *pbAutoLogonWithDefault = TRUE;
            // g_fAutoLogonReady = false;
        }
        else
        {
            *pbAutoLogonWithDefault = FALSE;
        }
    }

    return hr;
}

HRESULT CSampleProvider::GetCredentialAt(
    _In_ DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential** ppcpc)
{
    if (ppcpc == nullptr)
    {
        return E_POINTER;
    }
    *ppcpc = nullptr;

    HRESULT hr = E_INVALIDARG;

    if (dwIndex == 0 && _pCredential != nullptr)
    {
        hr = _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
    }

    return hr;
}

HRESULT CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray* users)
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

HRESULT CSampleProvider::Advise(_In_ ICredentialProviderEvents* pcpe, _In_ UINT_PTR upAdviseContext)
{
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

    return S_OK;
}

HRESULT CSampleProvider::UnAdvise()
{
    if (_pCredProviderEvents != nullptr)
    {
        _pCredProviderEvents->Release();
        _pCredProviderEvents = nullptr;
    }
    _upAdviseContext = 0;
    return S_OK;
}

HRESULT CSampleProvider::SetSerialization(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    UNREFERENCED_PARAMETER(pcpcs);
    return S_OK;
}

// Fixed: Unified body signature returning HRESULT matching the header file declaration
HRESULT CSampleProvider::SignalCredentialsChanged()
{
    if (_pCredProviderEvents != nullptr)
    {
        return _pCredProviderEvents->CredentialsChanged(_upAdviseContext);
    }
    return S_FALSE;
}

void CSampleProvider::_ReleaseEnumeratedCredentials()
{
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
}

HRESULT CSampleProvider::_EnumerateCredentials()
{
    HRESULT hr = E_UNEXPECTED;

    _ReleaseEnumeratedCredentials();

    if (_pCredProviderUserArray != nullptr)
    {
        DWORD dwUserCount = 0;
        _pCredProviderUserArray->GetCount(&dwUserCount);

        if (dwUserCount > 0)
        {
            ICredentialProviderUser* pCredUser = nullptr;
            hr = _pCredProviderUserArray->GetAt(0, &pCredUser);

            if (SUCCEEDED(hr) && pCredUser != nullptr)
            {
                _pCredential = new(std::nothrow) CSampleCredential();
                if (_pCredential != nullptr)
                {
                    _pCredential->SetProvider(this);
                    hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
                    if (FAILED(hr))
                    {
                        _pCredential->Release();
                        _pCredential = nullptr;
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
                pCredUser->Release();
            }
        }
        else
        {
            _pCredential = new(std::nothrow) CSampleCredential();
            if (_pCredential != nullptr)
            {
                _pCredential->SetProvider(this);
                hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
                if (FAILED(hr))
                {
                    _pCredential->Release();
                    _pCredential = nullptr;
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }
    return hr;
}

HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv)
{
    if (ppv == nullptr)
    {
        return E_POINTER;
    }
    *ppv = nullptr;

    HRESULT hr = E_OUTOFMEMORY;
    CSampleProvider* pProvider = new(std::nothrow) CSampleProvider();

    if (pProvider != nullptr)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }

    return hr;
}