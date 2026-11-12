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
#include "TetherProvider.h"
#include "TetherCredential.h"
#include "TetherCredentialGlobals.h"
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
    InitializeCriticalSection(&_csEvents);
    DllAddRef();
}

CSampleProvider::~CSampleProvider()
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

HRESULT CSampleProvider::SetUsageScenario(
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

HRESULT CSampleProvider::GetFieldDescriptorCount(_Out_ DWORD* pdwCount)
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

HRESULT CSampleProvider::GetFieldDescriptorAt(
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

HRESULT CSampleProvider::GetCredentialCount(_Out_ DWORD* pdwCount,
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

        HRESULT hr = S_OK;
        if (_pCredential == nullptr)
            hr = _EnumerateCredentials();

        if (SUCCEEDED(hr) && _pCredential != nullptr)
        {
            *pdwCount = 1;
            *pdwDefault = 0;
            if (g_fAutoLogonReady.load())
                *pbAutoLogonWithDefault = TRUE;
            else
                *pbAutoLogonWithDefault = FALSE;
        }
        return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleProvider::GetCredentialAt(
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

        HRESULT hr = E_INVALIDARG;

        if (dwIndex == 0 && _pCredential != nullptr)
        {
            hr = _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
        }

        return hr;
    }
    catch (...)
    {
        return E_UNEXPECTED;
    }
}

HRESULT CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray* users)
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

HRESULT CSampleProvider::Advise(_In_ ICredentialProviderEvents* pcpe, _In_ UINT_PTR upAdviseContext)
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

HRESULT CSampleProvider::UnAdvise()
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

HRESULT CSampleProvider::SetSerialization(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
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

// Fixed: Unified body signature returning HRESULT matching the header file declaration
HRESULT CSampleProvider::SignalCredentialsChanged()
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
                if (_pCredential)
                {
                    _pCredential->SetProvider(this);
                    hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors,
                        s_rgFieldStatePairs, pCredUser);
                    if (FAILED(hr))
                    {
                        _pCredential->Release();
                        _pCredential = nullptr;
                    }
                }
                else hr = E_OUTOFMEMORY;
                pCredUser->Release();
            }
        }
        else
        {
            // No users – do not create a credential (FIX #3)
            _pCredential = nullptr;
            hr = S_OK;
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