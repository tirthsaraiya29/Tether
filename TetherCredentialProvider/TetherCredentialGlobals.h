#pragma once
#include <atomic>
#include <windows.h>

extern std::atomic<DWORD> g_dwSelectedMethod;
extern std::atomic<bool> g_fBypassTriggered;
extern std::atomic<bool> g_fPhoneAppTriggered;
extern std::atomic<bool> g_fPhoneScreenTriggered;
extern std::atomic<bool> g_fAutoLogonReady;