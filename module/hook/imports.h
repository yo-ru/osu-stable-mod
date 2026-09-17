#pragma once
// resolves Win32 APIs at runtime without a static import table

#include <Windows.h>
#include <cstdint>
#include "pe.h"

namespace imports {

  namespace detail {
    static constexpr auto h_kernel32 = pe::hash("kernel32.dll");
    static constexpr auto h_user32 = pe::hash("user32.dll");

    static constexpr auto h_VirtualProtect = pe::hash("VirtualProtect");
    static constexpr auto h_VirtualQuery = pe::hash("VirtualQuery");
    static constexpr auto h_Sleep = pe::hash("Sleep");
    static constexpr auto h_CreateThread = pe::hash("CreateThread");
    static constexpr auto h_CloseHandle = pe::hash("CloseHandle");
    static constexpr auto h_DisableThreadLibraryCalls = pe::hash("DisableThreadLibraryCalls");
    static constexpr auto h_QueryPerformanceCounter = pe::hash("QueryPerformanceCounter");
    static constexpr auto h_QueryPerformanceFrequency = pe::hash("QueryPerformanceFrequency");
    static constexpr auto h_GetCurrentProcessId = pe::hash("GetCurrentProcessId");
    static constexpr auto h_HeapAlloc = pe::hash("HeapAlloc");
    static constexpr auto h_HeapFree = pe::hash("HeapFree");
    static constexpr auto h_GetProcessHeap = pe::hash("GetProcessHeap");
    static constexpr auto h_GetModuleFileNameA = pe::hash("GetModuleFileNameA");
    static constexpr auto h_CreateFileA = pe::hash("CreateFileA");
    static constexpr auto h_ReadFile = pe::hash("ReadFile");
    static constexpr auto h_GetFileSize = pe::hash("GetFileSize");
    static constexpr auto h_FindFirstFileA = pe::hash("FindFirstFileA");
    static constexpr auto h_FindNextFileA = pe::hash("FindNextFileA");
    static constexpr auto h_FindClose = pe::hash("FindClose");
    static constexpr auto h_EnumWindows = pe::hash("EnumWindows");
    static constexpr auto h_GetWindowThreadProcessId = pe::hash("GetWindowThreadProcessId");
    static constexpr auto h_IsWindowVisible = pe::hash("IsWindowVisible");
    static constexpr auto h_GetClientRect = pe::hash("GetClientRect");
    static constexpr auto h_AllocConsole = pe::hash("AllocConsole");
    static constexpr auto h_keybd_event = pe::hash("keybd_event");
  }  // namespace detail

  using VirtualProtect_t = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
  using VirtualQuery_t = SIZE_T(WINAPI*)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
  using Sleep_t = void(WINAPI*)(DWORD);
  using CreateThread_t = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                                         LPVOID, DWORD, LPDWORD);
  using CloseHandle_t = BOOL(WINAPI*)(HANDLE);
  using DisableThreadLibraryCalls_t = BOOL(WINAPI*)(HMODULE);
  using QueryPerformanceCounter_t = BOOL(WINAPI*)(LARGE_INTEGER*);
  using QueryPerformanceFrequency_t = BOOL(WINAPI*)(LARGE_INTEGER*);
  using GetCurrentProcessId_t = DWORD(WINAPI*)();
  using HeapAlloc_t = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);
  using HeapFree_t = BOOL(WINAPI*)(HANDLE, DWORD, LPVOID);
  using GetProcessHeap_t = HANDLE(WINAPI*)();
  using GetModuleFileNameA_t = DWORD(WINAPI*)(HMODULE, LPSTR, DWORD);
  using CreateFileA_t = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                        HANDLE);
  using ReadFile_t = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
  using GetFileSize_t = DWORD(WINAPI*)(HANDLE, LPDWORD);
  using FindFirstFileA_t = HANDLE(WINAPI*)(LPCSTR, LPWIN32_FIND_DATAA);
  using FindNextFileA_t = BOOL(WINAPI*)(HANDLE, LPWIN32_FIND_DATAA);
  using FindClose_t = BOOL(WINAPI*)(HANDLE);
  using EnumWindows_t = BOOL(WINAPI*)(WNDENUMPROC, LPARAM);
  using GetWindowThreadProcessId_t = DWORD(WINAPI*)(HWND, LPDWORD);
  using IsWindowVisible_t = BOOL(WINAPI*)(HWND);
  using GetClientRect_t = BOOL(WINAPI*)(HWND, LPRECT);
  using AllocConsole_t = BOOL(WINAPI*)();
  using KeybdEvent_t = void(WINAPI*)(BYTE, BYTE, DWORD, ULONG_PTR);

  inline VirtualProtect_t pVirtualProtect;
  inline VirtualQuery_t pVirtualQuery;
  inline Sleep_t pSleep;
  inline CreateThread_t pCreateThread;
  inline CloseHandle_t pCloseHandle;
  inline DisableThreadLibraryCalls_t pDisableThreadLibraryCalls;
  inline QueryPerformanceCounter_t pQueryPerformanceCounter;
  inline QueryPerformanceFrequency_t pQueryPerformanceFrequency;
  inline GetCurrentProcessId_t pGetCurrentProcessId;
  inline HeapAlloc_t pHeapAlloc;
  inline HeapFree_t pHeapFree;
  inline GetProcessHeap_t pGetProcessHeap;
  inline GetModuleFileNameA_t pGetModuleFileNameA;
  inline CreateFileA_t pCreateFileA;
  inline ReadFile_t pReadFile;
  inline GetFileSize_t pGetFileSize;
  inline FindFirstFileA_t pFindFirstFileA;
  inline FindNextFileA_t pFindNextFileA;
  inline FindClose_t pFindClose;
  inline EnumWindows_t pEnumWindows;
  inline GetWindowThreadProcessId_t pGetWindowThreadProcessId;
  inline IsWindowVisible_t pIsWindowVisible;
  inline GetClientRect_t pGetClientRect;
  inline AllocConsole_t pAllocConsole;
  inline KeybdEvent_t pKeybdEvent;

  __forceinline bool init() {
    using namespace detail;
    auto* k32 = pe::mod(h_kernel32);
    auto* u32 = pe::mod(h_user32);

    pVirtualProtect = (VirtualProtect_t)pe::exp(k32, h_VirtualProtect);
    pVirtualQuery = (VirtualQuery_t)pe::exp(k32, h_VirtualQuery);
    pSleep = (Sleep_t)pe::exp(k32, h_Sleep);
    pCreateThread = (CreateThread_t)pe::exp(k32, h_CreateThread);
    pCloseHandle = (CloseHandle_t)pe::exp(k32, h_CloseHandle);
    pDisableThreadLibraryCalls =
        (DisableThreadLibraryCalls_t)pe::exp(k32, h_DisableThreadLibraryCalls);
    pQueryPerformanceCounter = (QueryPerformanceCounter_t)pe::exp(k32, h_QueryPerformanceCounter);
    pQueryPerformanceFrequency =
        (QueryPerformanceFrequency_t)pe::exp(k32, h_QueryPerformanceFrequency);
    pGetCurrentProcessId = (GetCurrentProcessId_t)pe::exp(k32, h_GetCurrentProcessId);
    pHeapAlloc = (HeapAlloc_t)pe::exp(k32, h_HeapAlloc);
    pHeapFree = (HeapFree_t)pe::exp(k32, h_HeapFree);
    pGetProcessHeap = (GetProcessHeap_t)pe::exp(k32, h_GetProcessHeap);
    pGetModuleFileNameA = (GetModuleFileNameA_t)pe::exp(k32, h_GetModuleFileNameA);
    pCreateFileA = (CreateFileA_t)pe::exp(k32, h_CreateFileA);
    pReadFile = (ReadFile_t)pe::exp(k32, h_ReadFile);
    pGetFileSize = (GetFileSize_t)pe::exp(k32, h_GetFileSize);
    pFindFirstFileA = (FindFirstFileA_t)pe::exp(k32, h_FindFirstFileA);
    pFindNextFileA = (FindNextFileA_t)pe::exp(k32, h_FindNextFileA);
    pFindClose = (FindClose_t)pe::exp(k32, h_FindClose);
    pAllocConsole = (AllocConsole_t)pe::exp(k32, h_AllocConsole);

    if (u32) {
      pEnumWindows = (EnumWindows_t)pe::exp(u32, h_EnumWindows);
      pGetWindowThreadProcessId =
          (GetWindowThreadProcessId_t)pe::exp(u32, h_GetWindowThreadProcessId);
      pIsWindowVisible = (IsWindowVisible_t)pe::exp(u32, h_IsWindowVisible);
      pGetClientRect = (GetClientRect_t)pe::exp(u32, h_GetClientRect);
      pKeybdEvent = (KeybdEvent_t)pe::exp(u32, h_keybd_event);
    }

    bool ready = pVirtualProtect && pVirtualQuery && pSleep && pCreateThread && pCloseHandle &&
                 pDisableThreadLibraryCalls && pQueryPerformanceCounter &&
                 pQueryPerformanceFrequency && pGetCurrentProcessId && pHeapAlloc && pHeapFree &&
                 pGetProcessHeap && pGetModuleFileNameA && pCreateFileA && pReadFile &&
                 pGetFileSize && pFindFirstFileA && pFindNextFileA && pFindClose && pEnumWindows &&
                 pGetWindowThreadProcessId && pIsWindowVisible && pGetClientRect && pKeybdEvent;

#ifdef ENABLE_LOGGING
    ready = ready && pAllocConsole;
#endif

    return ready;
  }

}  // namespace imports
