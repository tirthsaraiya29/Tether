#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <propkey.h>
#include <atomic>
#include "common.h"
#include "dll.h"
#include "resource.h"
#include "TetherCredentialGlobals.h"

class CSampleProvider;

class CSampleCredential : public ICredentialProviderCredential2,
    public ICredentialProviderCredentialWithFieldOptions
{
public:
    IFACEMETHODIMP_(ULONG) AddRef() { return ++_cRef; }
    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef) delete this;
        return cRef;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        static const QITAB qit[] = {
            QITABENT(CSampleCredential, ICredentialProviderCredential),
            QITABENT(CSampleCredential, ICredentialProviderCredential2),
            QITABENT(CSampleCredential, ICredentialProviderCredentialWithFieldOptions),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

    void SetProvider(CSampleProvider* pProvider) { _pProvider = pProvider; }

    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    IFACEMETHODIMP GetUserSid(PWSTR* ppszSid);

    IFACEMETHODIMP GetFieldOptions(DWORD dwFieldID, CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS* pcpcfo);

public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
        const FIELD_STATE_PAIR* rgfsp,
        ICredentialProviderUser* pcpUser);
    CSampleCredential();

private:
    virtual ~CSampleCredential();

    void _StartBackgroundIPCListeners();
    static void CALLBACK _OnIPCEventSignaled(PVOID lpParameter, BOOLEAN TimerOrWaitFired);
    static void CALLBACK _OnAppEventSignaled(PVOID lpParameter, BOOLEAN TimerOrWaitFired);
    static void CALLBACK _OnScreenEventSignaled(PVOID lpParameter, BOOLEAN TimerOrWaitFired);
    static void CALLBACK _OnPhoneConnectedSignaled(PVOID lpParameter, BOOLEAN TimerOrWaitFired);
    static LRESULT CALLBACK WebAuthMsgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void _CreateMessageWindow();
    void _DestroyMessageWindow();
    void _BeginUnlockPromptCooldown();
    static void CALLBACK _OnCooldownTimerFired(PTP_CALLBACK_INSTANCE Instance, PVOID lpParameter, PTP_TIMER Timer);
    static void CALLBACK _OnStatusTimerFired(PTP_CALLBACK_INSTANCE Instance, PVOID lpParameter, PTP_TIMER Timer);
    void _OnCooldownTick();
    void _SetStatusText(PCWSTR pszStatus);
    void _CheckStatusAndRefreshUi();
    void _PerformServiceActionAsync();

    HRESULT _PackActualPasswordCredential(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PCWSTR pszPassword);
    HRESULT _GetStoredPasswordAndPack(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    bool _IsEncryptedPasswordBlobPresent();

private:
    std::atomic<long>                       _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];
    FIELD_STATE_PAIR                        _rgFieldStatePairs[SFI_NUM_FIELDS];
    PWSTR                                   _rgFieldStrings[SFI_NUM_FIELDS];
    PWSTR                                   _pszUserSid;
    PWSTR                                   _pszQualifiedUserName;
    ICredentialProviderCredentialEvents*    _pCredProvCredentialEvents;

    bool                                    _fIsLocalUser;
    CSampleProvider*                        _pProvider;

    HANDLE                                  _hAppEvent{ nullptr };
    HANDLE                                  _hScreenEvent{ nullptr };
    HANDLE                                  _hPhoneConnectedEvent{ nullptr };
    HANDLE                                  _hWaitApp{ nullptr };
    HANDLE                                  _hWaitScreen{ nullptr };
    HANDLE                                  _hWaitPhoneConnected{ nullptr };
    HWND                                    _hWndMessage{ nullptr };

    PTP_TIMER                               _pCooldownTimer{ nullptr };
    PTP_TIMER                               _pStatusTimer{ nullptr };

    std::atomic<bool>                       _isValid{ true };
    std::atomic<bool>                       _fInstancePhoneAppTriggered{ false };
    std::atomic<bool>                       _fInstanceAutoLogonReady{ false };
    std::atomic<long long>                  _promptCooldownEndMs{ 0 };
    std::atomic<bool>                       _fPhoneConnected{ false };
    std::atomic<bool>                       _fServiceRunning{ false };
    std::atomic<bool>                       _fServiceActionInProgress{ false };
};