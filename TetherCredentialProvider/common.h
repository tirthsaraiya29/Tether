#pragma once
#include "helpers.h"
enum SAMPLE_FIELD_ID
{
    SFI_TILEIMAGE = 0,
    SFI_LABEL = 1,
    SFI_LARGE_TEXT = 2,
    SFI_METHOD_LABEL = 3,
    SFI_METHOD_COMBOBOX = 4,
    SFI_PASSWORD = 5,
    SFI_SUBMIT_BUTTON = 6,
    SFI_LOGONSTATUS_TEXT = 7,
    SFI_NUM_FIELDS = 8
};
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE },
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE },
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE },
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
    { CPFS_HIDDEN,                   CPFIS_NONE },
    { CPFS_HIDDEN,                   CPFIS_NONE },
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
};
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,        CPFT_TILE_IMAGE,    const_cast<PWSTR>(L"Logo") },
    { SFI_LABEL,            CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Tether Authentication Security") },
    { SFI_LARGE_TEXT,       CPFT_LARGE_TEXT,    const_cast<PWSTR>(L"Tether Link") },
    { SFI_METHOD_LABEL,     CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Open the Tether app on your phone and tap 'Unlock PC'") },
    { SFI_METHOD_COMBOBOX,  CPFT_COMBOBOX,      const_cast<PWSTR>(L"Authentication Options") },
    { SFI_PASSWORD,         CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Enter Security Password") },
    { SFI_SUBMIT_BUTTON,    CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Unlock") },
    { SFI_LOGONSTATUS_TEXT, CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"Status Context") },
};
static const PWSTR s_rgUnlockMethodStrings[] =
{
    const_cast<PWSTR>(L"Unlock via Phone App"),
};