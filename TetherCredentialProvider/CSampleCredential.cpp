//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <wincrypt.h>
#include <winreg.h>
#include "CSampleCredential.h"
#include "CSampleProvider.h"
#include "guid.h"

#pragma comment(lib, "crypt32.lib")

CSampleCredential::CSampleCredential() :
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0),
    _dwSelectedMethod(0),
    _fBypassEnabled(false),
    _pszStoredPasswordHash(nullptr)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszStoredPasswordHash);
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const* rgcpfd,
    _In_ FIELD_STATE_PAIR const* rgfsp,
    _In_ ICredentialProviderUser* pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Tether Pro Gateway", &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Sign in using Tether", &_rgFieldStrings[SFI_LARGE_TEXT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Choose verification channel:", &_rgFieldStrings[SFI_METHOD_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(s_rgUnlockMethodStrings[0], &_rgFieldStrings[SFI_METHOD_COMBOBOX]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Execute Unsafe Dev Bypass", &_rgFieldStrings[SFI_BYPASS_BUTTON]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Authenticate", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"Awaiting phone app synchronization...", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);

    if (SUCCEEDED(hr)) hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    if (SUCCEEDED(hr)) hr = pcpUser->GetSid(&_pszUserSid);

    // Seed internal variables and establish background event handles
    LoadStoredPasswordHashFromTpm();
    _StartBackgroundIPCListeners();

    return hr;
}

HRESULT CSampleCredential::LoadStoredPasswordHashFromTpm()
{
    HRESULT hr = S_FALSE;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        WCHAR szHash[512];
        DWORD dwSize = sizeof(szHash);
        if (RegQueryValueExW(hKey, L"PasswordHash", nullptr, nullptr, (LPBYTE)szHash, &dwSize) == ERROR_SUCCESS)
        {
            hr = SHStrDupW(szHash, &_pszStoredPasswordHash);
        }
        RegCloseKey(hKey);
    }
    // If not present, default to empty (no password set)
    if (FAILED(hr))
    {
        hr = SHStrDupW(L"", &_pszStoredPasswordHash);
    }
    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR* ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP* phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD* pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = SFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
            CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL* pbChecked, _Outptr_result_nullonfailure_ PWSTR* ppwszLabel)
{
    *pbChecked = FALSE;
    *ppwszLabel = nullptr;
    return E_INVALIDARG;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    return E_INVALIDARG;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD* pcItems, _Out_ DWORD* pdwSelectedItem)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX)
    {
        *pcItems = _countof(s_rgUnlockMethodStrings);
        *pdwSelectedItem = _dwSelectedMethod;
        return S_OK;
    }
    return E_INVALIDARG;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR* ppwszItem)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX && dwItem < _countof(s_rgUnlockMethodStrings))
    {
        return SHStrDupW(s_rgUnlockMethodStrings[dwItem], ppwszItem);
    }
    return E_INVALIDARG;
}

// Replace this complete function in CSampleCredential.cpp
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    if (dwFieldID == SFI_METHOD_COMBOBOX && dwSelectedItem < _countof(s_rgUnlockMethodStrings))
    {
        _dwSelectedMethod = dwSelectedItem;

        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->BeginFieldUpdates();

            // Set contextual visibility
            CREDENTIAL_PROVIDER_FIELD_STATE cpfsPassword = (_dwSelectedMethod == 2) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            CREDENTIAL_PROVIDER_FIELD_STATE cpfsBypass = (_dwSelectedMethod == 3) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;

            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, cpfsPassword);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_BYPASS_BUTTON, cpfsBypass);

            // Update status text dynamically based on selection
            if (_dwSelectedMethod == 0)
                _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, L"Awaiting phone app authorization confirmation...");
            else if (_dwSelectedMethod == 1)
                _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, L"Unlock your connected mobile screen to proceed...");
            else if (_dwSelectedMethod == 2)
                _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, L"Provide local TPM authorization credential.");
            else if (_dwSelectedMethod == 3)
                _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, L"Development Bypass Active.");

            _pCredProvCredentialEvents->EndFieldUpdates();
        }
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    if (dwFieldID == SFI_BYPASS_BUTTON)
    {
        HKEY hKey;
        DWORD dwEnabled = 0;
        DWORD dwSize = sizeof(dwEnabled);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            RegQueryValueExW(hKey, L"EnableBypass", nullptr, nullptr, (LPBYTE)&dwEnabled, &dwSize);
            RegCloseKey(hKey);
        }

        if (dwEnabled == 1)
        {
            _fBypassEnabled = true;
            if (_pProvider)
            {
                _pProvider->SignalCredentialsChanged();
            }
        }
        else
        {
            MessageBoxW(nullptr, L"Access Denied: Set HKLM\\SOFTWARE\\Tether\\CredentialProvider\\EnableBypass=1", L"Security Guardrail", MB_OK | MB_ICONERROR);
        }
        return S_OK;
    }
    return E_INVALIDARG;
}
// Private helper inside CSampleCredential.cpp to pack standard interactive logon fields
HRESULT CSampleCredential::_PackActualPasswordCredential(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PCWSTR pszPassword)
{
    HRESULT hr = E_FAIL;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

    if (_fIsLocalUser)
    {
        PWSTR pwzProtectedPassword = nullptr;
        hr = ProtectIfNecessaryAndCopyPassword(pszPassword, _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain = nullptr, pszUsername = nullptr;
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                    if (SUCCEEDED(hr))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_CSample;
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                }
                CoTaskMemFree(pszDomain);
                CoTaskMemFree(pszUsername);
            }
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;
        if (!CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(pszPassword), nullptr, &pcpcs->cbSerialization) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            pcpcs->rgbSerialization = static_cast<byte*>(CoTaskMemAlloc(pcpcs->cbSerialization));
            if (pcpcs->rgbSerialization)
            {
                if (CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(pszPassword), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
                else hr = HRESULT_FROM_WIN32(GetLastError());
            }
            else hr = E_OUTOFMEMORY;
        }
    }
    return hr;
}

// Private helper to securely read DPAPI Local System key storage secrets
HRESULT CSampleCredential::_GetStoredPasswordAndPack(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    HRESULT hr = E_FAIL;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Tether\\CredentialProvider", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        BYTE encryptedData[2048];
        DWORD dwSize = sizeof(encryptedData);
        DWORD dwType = 0;
        if (RegQueryValueExW(hKey, L"EncryptedPassword", nullptr, &dwType, encryptedData, &dwSize) == ERROR_SUCCESS)
        {
            DATA_BLOB dataIn = { dwSize, encryptedData };
            DATA_BLOB dataOut = { 0 };

            if (CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &dataOut))
            {
                size_t passwordLen = dataOut.cbData / sizeof(WCHAR);
                PWSTR pszDecryptedPassword = (PWSTR)CoTaskMemAlloc(dataOut.cbData + sizeof(WCHAR));
                if (pszDecryptedPassword)
                {
                    CopyMemory(pszDecryptedPassword, dataOut.pbData, dataOut.cbData);
                    pszDecryptedPassword[passwordLen] = L'\0';

                    hr = _PackActualPasswordCredential(pcpgsr, pcpcs, pszDecryptedPassword);

                    SecureZeroMemory(pszDecryptedPassword, dataOut.cbData);
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

HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // Method 4: Dev Bypass Routing Execution
    if (_dwSelectedMethod == 3)
    {
        if (_fBypassEnabled)
        {
            _fBypassEnabled = false;
            return _GetStoredPasswordAndPack(pcpgsr, pcpcs);
        }
        SHStrDupW(L"Click 'Bypass (Development Use Only)' link to activate authorization.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_FALSE;
    }

    // Method 1: Phone App Signaling Interrogation
    if (_dwSelectedMethod == 0)
    {
        HANDLE hEvent = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\TetherPhoneAppUnlocked");
        if (hEvent)
        {
            if (WaitForSingleObject(hEvent, 0) == WAIT_OBJECT_0)
            {
                CloseHandle(hEvent);
                return _GetStoredPasswordAndPack(pcpgsr, pcpcs);
            }
            CloseHandle(hEvent);
        }
        SHStrDupW(L"Tether App transmission signal undetected.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_FALSE;
    }

    // Method 2: Phone Screen Lock Signal Interrogation
    if (_dwSelectedMethod == 1)
    {
        HANDLE hEvent = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\TetherPhoneScreenUnlocked");
        if (hEvent)
        {
            if (WaitForSingleObject(hEvent, 0) == WAIT_OBJECT_0)
            {
                CloseHandle(hEvent);
                return _GetStoredPasswordAndPack(pcpgsr, pcpcs);
            }
            CloseHandle(hEvent);
        }
        SHStrDupW(L"Biometric mobile secure validation not yet established.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_FALSE;
    }

    // Method 3: Password Text / Local Verification Logic
    if (_dwSelectedMethod == 2)
    {
        if (SUCCEEDED(_VerifyTpmPassword(_rgFieldStrings[SFI_PASSWORD])))
        {
            return _PackActualPasswordCredential(pcpgsr, pcpcs, _rgFieldStrings[SFI_PASSWORD]);
        }
        else
        {
            if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
            SHStrDupW(L"Invalid security password or hash discrepancy.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_FALSE;
        }
    }

    return E_UNEXPECTED;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, const_cast <PWSTR>(L"Incorrect password or username."), CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, const_cast <PWSTR>(L"The account is disabled."), CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    // Custom error messages
    if (ntsStatus == STATUS_LOGON_FAILURE)
    {
        SHStrDupW(const_cast <PWSTR>(L"Tether login failed – check your password."), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }
    else if (ntsStatus == STATUS_ACCOUNT_RESTRICTION && ntsSubstatus == STATUS_ACCOUNT_DISABLED)
    {
        SHStrDupW(const_cast <PWSTR>(L"Your Tether account is disabled. Contact support."), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
    }
    // For all other failures, leave default (no message)

    // Clear password field on failure
    if (FAILED(HRESULT_FROM_NT(ntsStatus)) && _pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
    }
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR* ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    return hr;
}

HRESULT CSampleCredential::_VerifyTpmPassword(_In_ PCWSTR pwzEnteredPassword)
{
    if (!_pszStoredPasswordHash || wcslen(_pszStoredPasswordHash) == 0)
        return E_FAIL;

    BYTE hash[32];
    DWORD cbHash = 32;

    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return E_FAIL;

    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return E_FAIL;
    }

    BYTE* pwdBytes = (BYTE*)pwzEnteredPassword;
    DWORD pwdLen = (DWORD)(wcslen(pwzEnteredPassword) * sizeof(WCHAR));
    if (!CryptHashData(hHash, pwdBytes, pwdLen, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return E_FAIL;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &cbHash, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return E_FAIL;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    WCHAR computedHex[65];
    for (int i = 0; i < 32; i++)
        swprintf_s(&computedHex[i * 2], 3, L"%02x", hash[i]);
    computedHex[64] = 0;

    return (_wcsicmp(computedHex, _pszStoredPasswordHash) == 0) ? S_OK : E_FAIL;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}

void CSampleCredential::_StartBackgroundIPCListeners()
{
    _hAppEvent = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\TetherPhoneAppUnlocked");
    if (_hAppEvent)
    {
        RegisterWaitForSingleObject(&_hWaitApp, _hAppEvent, _OnIPCEventSignaled, this, INFINITE, WT_EXECUTEDEFAULT);
    }

    _hScreenEvent = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\TetherPhoneScreenUnlocked");
    if (_hScreenEvent)
    {
        RegisterWaitForSingleObject(&_hWaitScreen, _hScreenEvent, _OnIPCEventSignaled, this, INFINITE, WT_EXECUTEDEFAULT);
    }
}

void CALLBACK CSampleCredential::_OnIPCEventSignaled(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
    CSampleCredential* pThis = reinterpret_cast<CSampleCredential*>(lpParameter);
    if (pThis && pThis->_pProvider)
    {
        pThis->_pProvider->SignalCredentialsChanged();
    }
}