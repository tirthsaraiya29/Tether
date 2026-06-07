// common.h
#pragma once
#include "helpers.h"

enum SAMPLE_FIELD_ID
{
    SFI_TILEIMAGE = 0,
    SFI_LABEL = 1,
    SFI_LARGE_TEXT = 2,
    SFI_METHOD_LABEL = 3, // Small prompt text
    SFI_METHOD_COMBOBOX = 4, // Method choice dropdown
    SFI_PASSWORD = 5, // PIN/Password input field (Shown only for Method 3)
    SFI_BYPASS_BUTTON = 6, // Command Link for development (Shown only for Method 4)
    SFI_SUBMIT_BUTTON = 7, // Submit arrow button
    SFI_LOGONSTATUS_TEXT = 8, // Informational status text field
    SFI_NUM_FIELDS = 9  // Absolute field footprint count
};

struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    }, // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    }, // SFI_LABEL
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    }, // SFI_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_METHOD_LABEL
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_METHOD_COMBOBOX
    { CPFS_HIDDEN,                     CPFIS_NONE    }, // SFI_PASSWORD (Hidden by default)
    { CPFS_HIDDEN,                     CPFIS_NONE    }, // SFI_BYPASS_BUTTON (Hidden by default)
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_LOGONSTATUS_TEXT
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,        CPFT_TILE_IMAGE,    const_cast<PWSTR>(L"Logo") },
    { SFI_LABEL,            CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Tether Authentication Security") },
    { SFI_LARGE_TEXT,       CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"Tether Link") },
    { SFI_METHOD_LABEL,     CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Select authentication option:") },
    { SFI_METHOD_COMBOBOX,  CPFT_COMBOBOX,      const_cast<PWSTR>(L"Authentication Options") },
    { SFI_PASSWORD,         CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Enter Security Password") },
    { SFI_BYPASS_BUTTON,    CPFT_COMMAND_LINK,  const_cast<PWSTR>(L"Bypass (Development Use Only)") },
    { SFI_SUBMIT_BUTTON,    CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Submit Auth") },
    { SFI_LOGONSTATUS_TEXT, CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Status Context") },
};

static const PWSTR s_rgUnlockMethodStrings[] =
{
    const_cast<PWSTR>(L"1. Unlock via Phone App"),
    const_cast<PWSTR>(L"2. Unlock via Phone Screen Unlock"),
    const_cast<PWSTR>(L"3. Use TPM-Stored Password"),
    const_cast<PWSTR>(L"4. Development Bypass (temporary)"),
};