#include "shellcode.hpp"
#include <intrin.h>

#define RELOC_FLAG(info) (((info) >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)

#pragma runtime_checks("", off)
#pragma optimize("", off)
void __stdcall shellcode(manual_mapping_data* data) {
  if (!data)
    return;

  // only the first queued APC may run the mapper
  if (_InterlockedCompareExchange(&data->executed, 1, 0) != 0)
    return;

  BYTE* base = data->pbase;
  auto* opt = &reinterpret_cast<IMAGE_NT_HEADERS32*>(
                   base + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)base)->e_lfanew)
                   ->OptionalHeader;

  auto load_library = data->load_library;
  auto get_proc_address = data->get_proc_address;
  auto dll_main = reinterpret_cast<f_DllMain>(base + opt->AddressOfEntryPoint);

  BYTE* location_delta = base - opt->ImageBase;

  // apply base relocations because manual mapping rarely receives ImageBase
  if (location_delta) {
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
      auto* reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
          base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
      const auto* reloc_end = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
          reinterpret_cast<uintptr_t>(reloc_data) +
          opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

      while (reloc_data < reloc_end && reloc_data->SizeOfBlock) {
        UINT entry_count = (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relative_info = reinterpret_cast<WORD*>(reloc_data + 1);

        for (UINT i = 0; i != entry_count; ++i, ++relative_info) {
          if (RELOC_FLAG(*relative_info)) {
            UINT_PTR* patch = reinterpret_cast<UINT_PTR*>(base + reloc_data->VirtualAddress +
                                                          ((*relative_info) & 0xFFF));
            *patch += reinterpret_cast<UINT_PTR>(location_delta);
          }
        }

        reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(reloc_data) +
                                                              reloc_data->SizeOfBlock);
      }
    }
  }

  // resolve the copied image's import table inside the target process
  if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
    auto* import_descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (import_descr->Name) {
      char* mod_name = reinterpret_cast<char*>(base + import_descr->Name);
      HINSTANCE hDll = load_library(mod_name);

      ULONG_PTR* thunk_ref = reinterpret_cast<ULONG_PTR*>(base + import_descr->OriginalFirstThunk);
      ULONG_PTR* func_ref = reinterpret_cast<ULONG_PTR*>(base + import_descr->FirstThunk);

      if (!import_descr->OriginalFirstThunk)
        thunk_ref = func_ref;

      for (; *thunk_ref; ++thunk_ref, ++func_ref) {
        if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref)) {
          *func_ref =
              (ULONG_PTR)get_proc_address(hDll, reinterpret_cast<char*>(*thunk_ref & 0xFFFF));
        } else {
          auto* import_entry = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + (*thunk_ref));
          *func_ref = (ULONG_PTR)get_proc_address(hDll, import_entry->Name);
        }
      }

      ++import_descr;
    }
  }

  // run TLS callbacks before DllMain, matching the Windows loader order
  if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY32*>(
        base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    auto* callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);

    for (; callback && *callback; ++callback)
      (*callback)(base, DLL_PROCESS_ATTACH, nullptr);
  }

  if (!dll_main(reinterpret_cast<HINSTANCE>(base), data->reason, data->reserved)) {
    data->hMod = reinterpret_cast<HINSTANCE>(0x404040);
    return;
  }

  data->hMod = reinterpret_cast<HINSTANCE>(base);
}
