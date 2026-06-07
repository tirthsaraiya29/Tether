//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleCredential is our implementation of ICredentialProviderCredential.

#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <propkey.h>
#include "common.h"
#include "dll.h"
#include "resource.h"

class CSampleProvider;
class CSampleCredential : public ICredentialProviderCredential2, public ICredentialProviderCredentialWithFieldOptions
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
            QITABENT(CSampleCredential, ICredentialProviderCredential),
            QITABENT(CSampleCredential, ICredentialProviderCredential2),
            QITABENT(CSampleCredential, ICredentialProviderCredentialWithFieldOptions),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

    void SetProvider(CSampleProvider* pProvider) { _pProvider = pProvider; }

public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(_In_ ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(_Out_ BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
        _Out_ CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL* pbChecked, _Outptr_result_nullonfailure_ PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD* pcItems, _Deref_out_range_(< , *pcItems) _Out_ DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD* pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(_Outptr_result_nullonfailure_ PWSTR* ppszSid);

    // ICredentialProviderCredentialWithFieldOptions
    IFACEMETHODIMP GetFieldOptions(DWORD dwFieldID, _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo);

public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const* rgcpfd,
        _In_ FIELD_STATE_PAIR const* rgfsp,
        _In_ ICredentialProviderUser* pcpUser);
    HRESULT LoadStoredPasswordHashFromTpm();
    CSampleCredential();

private:
    virtual ~CSampleCredential();

    // Background IPC Signaled Handlers & Registration Listeners
    void _StartBackgroundIPCListeners();
    void _ShutdownBackgroundIPCListeners();
    static void CALLBACK _OnIPCEventSignaled(PVOID lpParameter, BOOLEAN TimerOrWaitFired);

    // Helper functions for packing credentials
    HRESULT _PackActualPasswordCredential(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, PCWSTR pszPassword);
    HRESULT _GetStoredPasswordAndPack(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

private:
    long                                    _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];
    FIELD_STATE_PAIR                        _rgFieldStatePairs[SFI_NUM_FIELDS];
    PWSTR                                   _rgFieldStrings[SFI_NUM_FIELDS];
    PWSTR                                   _pszUserSid;
    PWSTR                                   _pszQualifiedUserName;
    ICredentialProviderCredentialEvents2* _pCredProvCredentialEvents;

    BOOL                                    _fChecked;
    DWORD                                   _dwComboIndex;
    bool                                    _fShowControls;
    bool                                    _fIsLocalUser;

    DWORD                                   _dwSelectedMethod;      // 0=Phone app, 1=Phone screen, 2=TPM password, 3=Bypass
    bool                                    _fBypassEnabled;        // True if bypass button was clicked
    PWSTR                                   _pszStoredPasswordHash; // TPM/DPAPI stored hash (hex string)

    HRESULT                                 _VerifyTpmPassword(_In_ PCWSTR pwzEnteredPassword);
    CSampleProvider* _pProvider;

    // Asynchronous synchronization listener variables
    HANDLE                                  _hAppEvent;
    HANDLE                                  _hScreenEvent;
    HANDLE                                  _hWaitApp;
    HANDLE                                  _hWaitScreen;
};