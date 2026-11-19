// common.h
#pragma once
#include "helpers.h"

enum TETHER_FIELD_ID
{
    SFI_TILEIMAGE = 0,
    SFI_LABEL = 1,
    SFI_LARGE_TEXT = 2,
    SFI_METHOD_LABEL = 3,
    SFI_METHOD_COMBOBOX = 4,
    SFI_PASSWORD = 5,
    SFI_SUBMIT_BUTTON = 6,
    SFI_LOGONSTATUS_TEXT = 7,
    SFI_UNLOCK_PROMPT_BUTTON = 8,
    SFI_SERVICE_ACTION_BUTTON = 9,
    SFI_NUM_FIELDS = 10
};
typedef TETHER_FIELD_ID SAMPLE_FIELD_ID;

enum TETHER_AUTH_METHOD
{
    TAM_PHONE_APP = 0,
    TAM_MASTER_PIN = 1,
    TAM_MASTER_PASSWORD = 2
};

struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE }, // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE }, // SFI_LABEL
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE }, // SFI_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE }, // SFI_METHOD_LABEL
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE }, // SFI_METHOD_COMBOBOX
    { CPFS_HIDDEN,                   CPFIS_NONE }, // SFI_PASSWORD (shown when PIN or Password method chosen)
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE }, // SFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE }, // SFI_LOGONSTATUS_TEXT
    { CPFS_HIDDEN,                   CPFIS_NONE }, // SFI_UNLOCK_PROMPT_BUTTON (shown only when phone connected)
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE }, // SFI_SERVICE_ACTION_BUTTON
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,        CPFT_TILE_IMAGE,    const_cast<PWSTR>(L"Logo") },
    { SFI_LABEL,            CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Tether") },
    { SFI_LARGE_TEXT,       CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"Tether Link") },
    { SFI_METHOD_LABEL,     CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Open the Tether app on your phone and tap 'Unlock PC'") },
    { SFI_METHOD_COMBOBOX,  CPFT_COMBOBOX,      const_cast<PWSTR>(L"Authentication Method") },
    { SFI_PASSWORD,         CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Enter Master PIN or Password") },
    { SFI_SUBMIT_BUTTON,    CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Unlock") },
    { SFI_LOGONSTATUS_TEXT, CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Status Context") },
    { SFI_UNLOCK_PROMPT_BUTTON, CPFT_COMMAND_LINK, const_cast<PWSTR>(L"Send unlock prompt to phone") },
    { SFI_SERVICE_ACTION_BUTTON, CPFT_COMMAND_LINK, const_cast<PWSTR>(L"Restart Tether Service") },
};

static const PWSTR s_rgUnlockMethodStrings[] =
{
    const_cast<PWSTR>(L"Unlock via Phone App"),
    const_cast<PWSTR>(L"Master PIN"),
    const_cast<PWSTR>(L"Master Password"),
};