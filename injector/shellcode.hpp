#pragma once

#include <Windows.h>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <intrin.h>

typedef HINSTANCE(WINAPI* f_LoadLibraryA)(const char*);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE, const char*);
typedef BOOL(WINAPI* f_DllMain)(HINSTANCE, DWORD, LPVOID);

struct manual_mapping_data {
  f_LoadLibraryA load_library;
  f_GetProcAddress get_proc_address;
  BYTE* pbase;
  HINSTANCE hMod;
  DWORD reason;
  LPVOID reserved;
  BOOL seh_support;
  volatile LONG executed;
};

void __stdcall shellcode(manual_mapping_data* data);
