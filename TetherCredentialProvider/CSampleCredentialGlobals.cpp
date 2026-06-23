// CSampleCredentialGlobals.cpp
#include "CSampleCredentialGlobals.h"

std::atomic<DWORD> g_dwSelectedMethod{ 0 };
std::atomic<bool> g_fBypassTriggered{ false };
std::atomic<bool> g_fPhoneAppTriggered{ false };
std::atomic<bool> g_fPhoneScreenTriggered{ false };
std::atomic<bool> g_fAutoLogonReady{ false };