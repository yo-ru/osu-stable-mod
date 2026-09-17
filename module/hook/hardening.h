#pragma once
// cleans up artifacts left by manual mapping

#include <Windows.h>
#include "imports.h"

namespace hardening {

  // restore each section's expected memory protection
  inline void fix_section_protections(HMODULE module) {
    __try {
      auto* dos = (IMAGE_DOS_HEADER*)module;
      if (dos->e_magic != 0x5A4D)
        return;
      auto* nt = (IMAGE_NT_HEADERS32*)((char*)module + dos->e_lfanew);
      auto* sec = IMAGE_FIRST_SECTION(nt);

      for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->Misc.VirtualSize)
          continue;

        bool exec = (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool write = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        DWORD prot = PAGE_READONLY;
        if (exec && write)
          prot = PAGE_EXECUTE_READWRITE;
        else if (exec)
          prot = PAGE_EXECUTE_READ;
        else if (write)
          prot = PAGE_READWRITE;

        DWORD old = 0;
        imports::pVirtualProtect((LPVOID)((char*)module + sec->VirtualAddress),
                                 sec->Misc.VirtualSize, prot, &old);
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
  }

  // clear the mapped image headers after initialization
  inline void scrub_pe_headers(HMODULE module) {
    __try {
      auto* dos = (IMAGE_DOS_HEADER*)module;
      if (dos->e_magic != 0x5A4D)
        return;
      auto* nt = (IMAGE_NT_HEADERS32*)((char*)module + dos->e_lfanew);
      DWORD header_size = nt->OptionalHeader.SizeOfHeaders;

      DWORD old = 0;
      if (imports::pVirtualProtect((LPVOID)module, header_size, PAGE_READWRITE, &old)) {
        volatile uint8_t* p = (volatile uint8_t*)module;
        for (uint32_t i = 0; i < header_size; ++i)
          p[i] = 0;
        imports::pVirtualProtect((LPVOID)module, header_size, PAGE_READONLY, &old);
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
  }

}  // namespace hardening
