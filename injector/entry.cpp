// APC-based manual map injector for 32-bit .NET Framework processes
// queues APC + forces delivery via NtTestAlert redirect

#include "shellcode.hpp"
#include <vector>

#ifdef DISABLE_OUTPUT
#define LOG(fmt, ...)
#define LOG_STATUS(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define LOG_STATUS(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID Arg1,
                                            PVOID Arg2, PVOID Arg3);
typedef NTSTATUS(NTAPI* NtSuspendThread_t)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* NtResumeThread_t)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static constexpr ULONG ThreadQuerySetWin32StartAddress = 9;

static NtQueueApcThread_t g_NtQueueApcThread;
static NtSuspendThread_t g_NtSuspendThread;
static NtResumeThread_t g_NtResumeThread;
static NtQueryInformationThread_t g_NtQueryInformationThread;
static void* g_pNtTestAlert;

struct module_info {
  BYTE* base;
  SIZE_T size;
};

DWORD get_process_id(const char* name) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32 pe{};
  pe.dwSize = sizeof(pe);

  DWORD pid = 0;

  if (Process32First(snap, &pe)) {
    do {
      if (_stricmp(pe.szExeFile, name) == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (Process32Next(snap, &pe));
  }

  CloseHandle(snap);
  return pid;
}

module_info find_module(DWORD pid, const char* name) {
  module_info info{};

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE)
    return info;

  MODULEENTRY32 me{};
  me.dwSize = sizeof(me);

  if (Module32First(snap, &me)) {
    do {
      if (_stricmp(me.szModule, name) == 0) {
        info.base = me.modBaseAddr;
        info.size = me.modBaseSize;
        break;
      }
    } while (Module32Next(snap, &me));
  }

  CloseHandle(snap);
  return info;
}

std::vector<DWORD> get_native_threads(DWORD pid) {
  std::vector<DWORD> result;

  module_info clr = find_module(pid, "clr.dll");
  module_info clrjit = find_module(pid, "clrjit.dll");

  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return result;

  THREADENTRY32 te{};
  te.dwSize = sizeof(te);

  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid)
        continue;

      HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
      if (!hThread)
        continue;

      PVOID start_addr = nullptr;
      NTSTATUS status = g_NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress,
                                                   &start_addr, sizeof(start_addr), nullptr);
      CloseHandle(hThread);

      if (status != 0 || !start_addr)
        continue;

      auto addr = reinterpret_cast<BYTE*>(start_addr);

      bool is_clr = false;
      if (clr.base)
        is_clr = (addr >= clr.base && addr < clr.base + clr.size);
      if (!is_clr && clrjit.base)
        is_clr = (addr >= clrjit.base && addr < clrjit.base + clrjit.size);

      if (!is_clr)
        result.push_back(te.th32ThreadID);
    } while (Thread32Next(snap, &te));
  }

  CloseHandle(snap);
  return result;
}

std::vector<BYTE> read_file(const char* path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file.is_open())
    return {};

  size_t size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<BYTE> buf(size);
  file.read(reinterpret_cast<char*>(buf.data()), size);
  return buf;
}

struct injection_context {
  BYTE* pTargetBase;
  BYTE* pMappingData;
  void* pShellcode;
  void* pTrampoline;
  bool execution_started;
  bool valid;
};

void release_injection_context(HANDLE process, injection_context& ctx, bool release_image) {
  if (ctx.pTrampoline)
    VirtualFreeEx(process, ctx.pTrampoline, 0, MEM_RELEASE);
  if (ctx.pShellcode)
    VirtualFreeEx(process, ctx.pShellcode, 0, MEM_RELEASE);
  if (ctx.pMappingData)
    VirtualFreeEx(process, ctx.pMappingData, 0, MEM_RELEASE);
  if (release_image && ctx.pTargetBase)
    VirtualFreeEx(process, ctx.pTargetBase, 0, MEM_RELEASE);

  ctx.pTrampoline = nullptr;
  ctx.pShellcode = nullptr;
  ctx.pMappingData = nullptr;
  if (release_image)
    ctx.pTargetBase = nullptr;
  ctx.valid = false;
}

// copies the image into the target and prepares the relocation/import shellcode
// this bypasses the normal windows loader, so the image is absent from its module list
injection_context map_dll(HANDLE hProc, BYTE* src_data, SIZE_T file_size) {
  injection_context ctx{};

  if (reinterpret_cast<IMAGE_DOS_HEADER*>(src_data)->e_magic != 0x5A4D) {
    LOG_STATUS("[!] invalid file\n");
    return ctx;
  }

  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
      src_data + reinterpret_cast<IMAGE_DOS_HEADER*>(src_data)->e_lfanew);
  auto* opt = &nt->OptionalHeader;
  auto* file_hdr = &nt->FileHeader;

  if (file_hdr->Machine != IMAGE_FILE_MACHINE_I386) {
    LOG_STATUS("[!] invalid platform\n");
    return ctx;
  }

  ctx.pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(
      hProc, nullptr, opt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  if (!ctx.pTargetBase) {
    LOG_STATUS("[!] image alloc failed\n");
    return ctx;
  }

  LOG("[+] image at %p (0x%X bytes)\n", ctx.pTargetBase, opt->SizeOfImage);

  if (!WriteProcessMemory(hProc, ctx.pTargetBase, src_data, 0x1000, nullptr)) {
    VirtualFreeEx(hProc, ctx.pTargetBase, 0, MEM_RELEASE);
    return ctx;
  }

  auto* sec = IMAGE_FIRST_SECTION(nt);
  for (UINT i = 0; i < file_hdr->NumberOfSections; ++i, ++sec) {
    if (!sec->SizeOfRawData)
      continue;

    if (!WriteProcessMemory(hProc, ctx.pTargetBase + sec->VirtualAddress,
                            src_data + sec->PointerToRawData, sec->SizeOfRawData, nullptr)) {
      LOG("[!] section %s write failed\n", sec->Name);
      VirtualFreeEx(hProc, ctx.pTargetBase, 0, MEM_RELEASE);
      return ctx;
    }
  }

  manual_mapping_data data{};
  data.load_library = LoadLibraryA;
  data.get_proc_address = GetProcAddress;
  data.pbase = ctx.pTargetBase;
  data.reason = DLL_PROCESS_ATTACH;
  data.reserved = nullptr;
  data.seh_support = FALSE;
  data.executed = 0;
  data.hMod = nullptr;

  ctx.pMappingData = reinterpret_cast<BYTE*>(VirtualAllocEx(
      hProc, nullptr, sizeof(manual_mapping_data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!ctx.pMappingData) {
    VirtualFreeEx(hProc, ctx.pTargetBase, 0, MEM_RELEASE);
    return ctx;
  }

  if (!WriteProcessMemory(hProc, ctx.pMappingData, &data, sizeof(data), nullptr)) {
    VirtualFreeEx(hProc, ctx.pTargetBase, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, ctx.pMappingData, 0, MEM_RELEASE);
    return ctx;
  }

  ctx.pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!ctx.pShellcode) {
    VirtualFreeEx(hProc, ctx.pTargetBase, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, ctx.pMappingData, 0, MEM_RELEASE);
    return ctx;
  }

  if (!WriteProcessMemory(hProc, ctx.pShellcode, shellcode, 0x1000, nullptr)) {
    VirtualFreeEx(hProc, ctx.pTargetBase, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, ctx.pMappingData, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, ctx.pShellcode, 0, MEM_RELEASE);
    return ctx;
  }

  DWORD old;
  VirtualProtectEx(hProc, ctx.pShellcode, 0x1000, PAGE_EXECUTE_READ, &old);

  LOG("[+] shellcode at %p (RX)\n", ctx.pShellcode);
  LOG("[+] mapping data at %p\n", ctx.pMappingData);

  ctx.valid = true;
  return ctx;
}

// x86 trampoline: saves volatile regs, calls NtTestAlert, restores, returns
// NtTestAlert address patched at offset 5
static constexpr BYTE k_trampoline[] = {
    0x9C,                    // pushfd
    0x50,                    // push eax
    0x51,                    // push ecx
    0x52,                    // push edx
    0xB8,                    // mov eax, <NtTestAlert>
    0x00, 0x00, 0x00, 0x00,  // (patched at runtime)
    0xFF, 0xD0,              // call eax
    0x5A,                    // pop edx
    0x59,                    // pop ecx
    0x58,                    // pop eax
    0x9D,                    // popfd
    0xC3,                    // ret
};

static constexpr SIZE_T k_trampoline_nta_offset = 5;

void* alloc_trampoline(HANDLE hProc) {
  BYTE buf[sizeof(k_trampoline)];
  memcpy(buf, k_trampoline, sizeof(buf));
  memcpy(buf + k_trampoline_nta_offset, &g_pNtTestAlert, sizeof(g_pNtTestAlert));

  void* mem = VirtualAllocEx(hProc, nullptr, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!mem)
    return nullptr;

  if (!WriteProcessMemory(hProc, mem, buf, sizeof(buf), nullptr)) {
    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
    return nullptr;
  }

  DWORD old;
  VirtualProtectEx(hProc, mem, sizeof(buf), PAGE_EXECUTE_READ, &old);
  return mem;
}

bool is_in_module(DWORD eip, const module_info& mod) {
  return mod.base && eip >= reinterpret_cast<DWORD>(mod.base) &&
         eip < reinterpret_cast<DWORD>(mod.base + mod.size);
}

// NtTestAlert drains the queued APC immediately, even if the selected thread
// never enters an alertable wait on its own
bool try_apc_nttestalert(HANDLE hProc, injection_context& ctx, DWORD tid) {
  HANDLE hThread =
      OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
  if (!hThread)
    return false;

  ULONG prev = 0;

  if (g_NtSuspendThread(hThread, &prev) != 0 || prev > 0) {
    if (prev > 0)
      g_NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  CONTEXT c{};
  c.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(hThread, &c)) {
    g_NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  CONTEXT original = c;
  DWORD orig_eip = original.Eip;

  c.Esp -= 4;

  if (!WriteProcessMemory(hProc, reinterpret_cast<void*>(c.Esp), &orig_eip, 4, nullptr)) {
    g_NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  c.Eip = reinterpret_cast<DWORD>(ctx.pTrampoline);

  if (!SetThreadContext(hThread, &c)) {
    g_NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  if (g_NtQueueApcThread(hThread, ctx.pShellcode, ctx.pMappingData, nullptr, nullptr) != 0) {
    SetThreadContext(hThread, &original);
    g_NtResumeThread(hThread, nullptr);
    CloseHandle(hThread);
    return false;
  }

  ctx.execution_started = true;

  g_NtResumeThread(hThread, nullptr);
  CloseHandle(hThread);

  LOG("[+] trampoline on thread %lu (EIP was %p)\n", tid, (void*)orig_eip);

  for (int i = 0; i < 5; ++i) {
    Sleep(100);
    manual_mapping_data data{};
    ReadProcessMemory(hProc, ctx.pMappingData, &data, sizeof(data), nullptr);
    if (data.executed)
      return true;
  }

  return false;
}

bool inject_via_apc(HANDLE hProc, injection_context& ctx, DWORD pid) {
  ctx.pTrampoline = alloc_trampoline(hProc);
  if (!ctx.pTrampoline) {
    LOG_STATUS("[!] trampoline alloc failed\n");
    return false;
  }

  LOG("[+] trampoline at %p\n", ctx.pTrampoline);

  module_info ntdll_mod = find_module(pid, "ntdll.dll");

  for (int attempt = 0; attempt < 100; ++attempt) {
    DWORD exitcode = 0;
    GetExitCodeProcess(hProc, &exitcode);
    if (exitcode != STILL_ACTIVE)
      return false;

    auto tids = get_native_threads(pid);
    if (tids.empty()) {
      Sleep(100);
      continue;
    }

    if (attempt == 0)
      LOG("[+] found %zu native threads\n", tids.size());

    for (DWORD tid : tids) {
      HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
      if (!h)
        continue;

      ULONG prev = 0;
      if (g_NtSuspendThread(h, &prev) != 0 || prev > 0) {
        if (prev > 0)
          g_NtResumeThread(h, nullptr);
        CloseHandle(h);
        continue;
      }

      CONTEXT c{};
      c.ContextFlags = CONTEXT_CONTROL;
      bool ok = GetThreadContext(h, &c);
      g_NtResumeThread(h, nullptr);
      CloseHandle(h);

      if (!ok || is_in_module(c.Eip, ntdll_mod))
        continue;

      if (try_apc_nttestalert(hProc, ctx, tid))
        return true;
      if (ctx.execution_started)
        return true;
    }

    Sleep(100);
  }

  LOG_STATUS("[!] no active thread found after 10s\n");
  return false;
}

bool wait_for_injection(HANDLE hProc, injection_context& ctx) {
  LOG("[*] waiting for execution...\n");

  HINSTANCE hCheck = NULL;

  for (int i = 0; i < 100 && !hCheck; ++i) {
    DWORD exitcode = 0;
    GetExitCodeProcess(hProc, &exitcode);
    if (exitcode != STILL_ACTIVE) {
      LOG_STATUS("[!] process exited\n");
      return false;
    }

    manual_mapping_data data{};
    ReadProcessMemory(hProc, ctx.pMappingData, &data, sizeof(data), nullptr);
    hCheck = data.hMod;

    if (hCheck == reinterpret_cast<HINSTANCE>(0x404040)) {
      LOG_STATUS("[!] shellcode error\n");
      return false;
    }

    if (hCheck == reinterpret_cast<HINSTANCE>(0x505050)) {
      LOG("[!] SEH support failed (non-fatal)\n");
      hCheck = reinterpret_cast<HINSTANCE>(ctx.pTargetBase);
    }

    if (!hCheck) {
      Sleep(100);

      if ((i + 1) % 10 == 0)
        LOG("[*] waiting... (%ds)\n", (i + 1) / 10);
    }
  }

  if (!hCheck) {
    manual_mapping_data data{};
    ReadProcessMemory(hProc, ctx.pMappingData, &data, sizeof(data), nullptr);
    LOG_STATUS("[!] timeout (%s)\n", data.executed ? "init failed" : "never executed");
    return false;
  }

  LOG("[+] DLL loaded at %p\n", hCheck);

  release_injection_context(hProc, ctx, false);

  return true;
}

bool kill_auth_threads(HANDLE hProc, DWORD pid) {
  LOG_STATUS("[*] waiting for osu!auth.dll...\n");

  module_info auth{};
  for (int i = 0; i < 100 && !auth.base; ++i) {
    DWORD exitcode = 0;
    GetExitCodeProcess(hProc, &exitcode);
    if (exitcode != STILL_ACTIVE)
      return false;

    auth = find_module(pid, "osu!auth.dll");
    if (!auth.base)
      Sleep(200);
  }

  if (!auth.base) {
    LOG_STATUS("[!] osu!auth.dll not found\n");
    return false;
  }

  LOG("[+] osu!auth.dll at %p (0x%zX bytes)\n", auth.base, auth.size);

  int killed = 0;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

  if (snap == INVALID_HANDLE_VALUE)
    return false;

  THREADENTRY32 te{};
  te.dwSize = sizeof(te);

  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != pid)
        continue;

      HANDLE hThread =
          OpenThread(THREAD_QUERY_INFORMATION | THREAD_TERMINATE, FALSE, te.th32ThreadID);
      if (!hThread)
        continue;

      PVOID start_addr = nullptr;
      NTSTATUS status = g_NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress,
                                                   &start_addr, sizeof(start_addr), nullptr);

      if (status == 0 && start_addr) {
        auto addr = reinterpret_cast<BYTE*>(start_addr);
        if (addr >= auth.base && addr < auth.base + auth.size) {
          TerminateThread(hThread, 0);
          killed++;
          LOG("[+] killed auth thread %lu (start %p)\n", te.th32ThreadID, start_addr);
        }
      }

      CloseHandle(hThread);
    } while (Thread32Next(snap, &te));
  }

  CloseHandle(snap);

  LOG_STATUS("[+] killed %d auth thread(s)\n", killed);
  return killed > 0;
}

int main(int argc, char* argv[]) {
  const char* dll_path = "DiscordHook.dll";
  bool disable_auth = false;

  for (int i = 1; i < argc; ++i) {
    if (_stricmp(argv[i], "--disable-auth") == 0)
      disable_auth = true;
    else
      dll_path = argv[i];
  }

  LOG_STATUS("[*] starting...\n");

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  g_NtQueueApcThread =
      reinterpret_cast<NtQueueApcThread_t>(GetProcAddress(ntdll, "NtQueueApcThread"));
  g_NtSuspendThread = reinterpret_cast<NtSuspendThread_t>(GetProcAddress(ntdll, "NtSuspendThread"));
  g_NtResumeThread = reinterpret_cast<NtResumeThread_t>(GetProcAddress(ntdll, "NtResumeThread"));
  g_NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
      GetProcAddress(ntdll, "NtQueryInformationThread"));
  g_pNtTestAlert = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtTestAlert"));

  if (!g_NtQueueApcThread || !g_NtSuspendThread || !g_NtResumeThread ||
      !g_NtQueryInformationThread || !g_pNtTestAlert) {
    LOG_STATUS("[!] ntdll init failed\n");
    return 1;
  }

  auto dll_bytes = read_file(dll_path);

  if (dll_bytes.empty()) {
    LOG_STATUS("[!] failed to read payload\n");
    return 1;
  }

  LOG_STATUS("[*] waiting for target...\n");

  DWORD pid = 0;

  while (!pid) {
    pid = get_process_id("osu!.exe");
    if (!pid)
      Sleep(100);
  }

  LOG_STATUS("[+] found target (pid %lu)\n", pid);

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

  if (!hProcess) {
    LOG_STATUS("[!] failed to open target\n");
    return 1;
  }

  LOG_STATUS("[*] waiting for CLR...\n");

  while (!find_module(pid, "clr.dll").base) {
    DWORD exitcode = 0;
    GetExitCodeProcess(hProcess, &exitcode);
    if (exitcode != STILL_ACTIVE) {
      LOG_STATUS("[!] target exited\n");
      CloseHandle(hProcess);
      return 1;
    }
    Sleep(100);
  }

  while (!find_module(pid, "clrjit.dll").base) {
    DWORD exitcode = 0;
    GetExitCodeProcess(hProcess, &exitcode);
    if (exitcode != STILL_ACTIVE) {
      LOG_STATUS("[!] target exited\n");
      CloseHandle(hProcess);
      return 1;
    }
    Sleep(100);
  }

  LOG_STATUS("[+] CLR ready\n");
  Sleep(1000);

  injection_context ctx = map_dll(hProcess, dll_bytes.data(), dll_bytes.size());

  if (!ctx.valid) {
    LOG_STATUS("[!] mapping failed\n");
    CloseHandle(hProcess);
    return 1;
  }

  if (!inject_via_apc(hProcess, ctx, pid)) {
    LOG_STATUS("[!] injection failed\n");
    if (!ctx.execution_started)
      release_injection_context(hProcess, ctx, true);
    CloseHandle(hProcess);
    return 1;
  }

  bool success = wait_for_injection(hProcess, ctx);

  if (success && disable_auth)
    kill_auth_threads(hProcess, pid);

  CloseHandle(hProcess);

  LOG_STATUS(success ? "[+] done\n" : "[!] timed out\n");
  return success ? 0 : 1;
}
