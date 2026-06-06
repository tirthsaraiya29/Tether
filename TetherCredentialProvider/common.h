//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// This file contains some global variables that describe what our
// sample tile looks like.  For example, it defines what fields a tile has
// and which fields show in which states of LogonUI. This sample illustrates
// the use of each UI field type.

#pragma once
#include "helpers.h"

// The indexes of each of the fields in our credential provider's tiles. Note that we're
// using each of the nine available field types here.
enum SAMPLE_FIELD_ID
{
    SFI_TILEIMAGE = 0,
    SFI_LABEL = 1,
    SFI_LARGE_TEXT = 2,
    SFI_PASSWORD = 3,
    SFI_SUBMIT_BUTTON = 4,
    SFI_LAUNCHWINDOW_LINK = 5,
    SFI_HIDECONTROLS_LINK = 6,
    SFI_FULLNAME_TEXT = 7,
    SFI_DISPLAYNAME_TEXT = 8,
    SFI_LOGONSTATUS_TEXT = 9,
    SFI_CHECKBOX = 10,
    SFI_EDIT_TEXT = 11,
    SFI_COMBOBOX = 12,
    // New fields for unlock methods
    SFI_METHOD_LABEL = 13,       // small text label
    SFI_METHOD_COMBOBOX = 14,       // combobox to choose method
    SFI_BYPASS_BUTTON = 15,       // command link for dev bypass
    SFI_NUM_FIELDS = 16,       // updated count
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when
// common.h – replace the FIELD_STATE_PAIR array
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    }, // SFI_TILEIMAGE
    { CPFS_HIDDEN,                     CPFIS_NONE    }, // SFI_LABEL
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    }, // SFI_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED }, // SFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_LAUNCHWINDOW_LINK
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_HIDECONTROLS_LINK
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_FULLNAME_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_DISPLAYNAME_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_LOGONSTATUS_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_CHECKBOX
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_EDIT_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_COMBOBOX
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_METHOD_LABEL
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_METHOD_COMBOBOX
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    }, // SFI_BYPASS_BUTTON
};

// common.h – replace the field descriptors array
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE, CPFT_TILE_IMAGE, const_cast<PWSTR>(L"Image"), CPFG_CREDENTIAL_PROVIDER_LOGO },
    { SFI_LABEL,             CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Tether Secure Login"),                    CPFG_CREDENTIAL_PROVIDER_LABEL },
    { SFI_LARGE_TEXT,        CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"Tether")                                 },
    { SFI_PASSWORD,          CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Password")                               },
    { SFI_SUBMIT_BUTTON,     CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Submit")                                 },
    { SFI_LAUNCHWINDOW_LINK, CPFT_COMMAND_LINK,  const_cast<PWSTR>(L"Launch helper window")                   },
    { SFI_HIDECONTROLS_LINK, CPFT_COMMAND_LINK,  const_cast<PWSTR>(L"Hide additional controls")               },
    { SFI_FULLNAME_TEXT,     CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Full name: ")                            },
    { SFI_DISPLAYNAME_TEXT,  CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Display name: ")                        },
    { SFI_LOGONSTATUS_TEXT,  CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Logon status: ")                        },
    { SFI_CHECKBOX,          CPFT_CHECKBOX,      const_cast<PWSTR>(L"Remember me")                           },
    { SFI_EDIT_TEXT,         CPFT_EDIT_TEXT,     const_cast<PWSTR>(L"Tether ID")                             },
    { SFI_COMBOBOX,          CPFT_COMBOBOX,      const_cast<PWSTR>(L"Tether Option")                         },
    { SFI_METHOD_LABEL,      CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Unlock method:")                        },
    { SFI_METHOD_COMBOBOX,   CPFT_COMBOBOX,      const_cast<PWSTR>(L"Method")                                },
    { SFI_BYPASS_BUTTON,     CPFT_COMMAND_LINK,  const_cast<PWSTR>(L"Development Bypass (temporary)")       },
};

// common.h – add this combobox string array for the unlock methods
static const PWSTR s_rgUnlockMethodStrings[] =
{
    const_cast<PWSTR>(L"1. Unlock via Phone App"),
    const_cast<PWSTR>(L"2. Unlock via Phone Screen Unlock"),
    const_cast<PWSTR>(L"3. Use TPM-Stored Password"),
};

static const PWSTR s_rgComboBoxStrings[] =
{
    const_cast<PWSTR>(L"First"),
    const_cast<PWSTR>(L"Second"),
    const_cast<PWSTR>(L"Third"),
};
