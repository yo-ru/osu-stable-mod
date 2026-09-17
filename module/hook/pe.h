#pragma once
// finds loaded modules and exports by hash through the PEB

#include <Windows.h>
#include <cstdint>
#include <intrin.h>

namespace pe {

  struct unicode_str {
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
  };

  struct peb_ldr {
    uint8_t reserved[0x14];
    LIST_ENTRY InMemoryOrderModuleList;
  };

  struct peb_t {
    uint8_t reserved[0x0C];
    peb_ldr* Ldr;
  };

  struct ldr_entry {
    LIST_ENTRY in_load_order;
    LIST_ENTRY in_memory_order;
    LIST_ENTRY in_init_order;
    void* dll_base;
    void* entry_point;
    uint32_t size_of_image;
    unicode_str full_dll_name;
    unicode_str base_dll_name;
  };

  static constexpr uint32_t fnv_basis = 0x811c9dc5;
  static constexpr uint32_t fnv_prime = 0x01000193;

  // case-insensitive compile-time FNV-1a hash
  static consteval uint32_t hash(const char* s) {
    uint32_t h = fnv_basis;
    for (; *s; ++s) {
      char c = *s;
      if (c >= 'A' && c <= 'Z')
        c += 32;
      h ^= static_cast<uint32_t>(c);
      h *= fnv_prime;
    }
    return h;
  }

  // case-insensitive runtime FNV-1a hash for narrow strings
  static __forceinline uint32_t hash_rt(const char* s) {
    uint32_t h = fnv_basis;
    for (; *s; ++s) {
      char c = *s;
      if (c >= 'A' && c <= 'Z')
        c += 32;
      h ^= static_cast<uint32_t>(c);
      h *= fnv_prime;
    }
    return h;
  }

  // case-insensitive runtime FNV-1a hash for wide strings
  static __forceinline uint32_t hash_rt(const wchar_t* s, uint16_t len) {
    uint32_t h = fnv_basis;
    for (uint16_t i = 0; i < len; ++i) {
      char c = static_cast<char>(s[i]);
      if (c >= 'A' && c <= 'Z')
        c += 32;
      h ^= static_cast<uint32_t>(c);
      h *= fnv_prime;
    }
    return h;
  }

  // find a loaded module by its name hash
  static __forceinline void* mod(uint32_t name_hash) {
    auto* peb = reinterpret_cast<peb_t*>(__readfsdword(0x30));
    auto* head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto* cur = head->Flink; cur != head; cur = cur->Flink) {
      auto* entry = CONTAINING_RECORD(cur, ldr_entry, in_memory_order);
      auto& name = entry->base_dll_name;
      if (!name.Buffer || !name.Length)
        continue;
      if (hash_rt(name.Buffer, name.Length / sizeof(wchar_t)) == name_hash)
        return entry->dll_base;
    }
    return nullptr;
  }

  // resolve an export by its name hash
  static __forceinline void* exp(void* base, uint32_t name_hash) {
    if (!base)
      return nullptr;
    auto b = reinterpret_cast<uintptr_t>(base);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(b + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress)
      return nullptr;

    uint32_t exp_start = dir.VirtualAddress;
    uint32_t exp_end = exp_start + dir.Size;

    auto* eat = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(b + exp_start);
    auto* names = reinterpret_cast<uint32_t*>(b + eat->AddressOfNames);
    auto* ordinals = reinterpret_cast<uint16_t*>(b + eat->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<uint32_t*>(b + eat->AddressOfFunctions);

    for (uint32_t i = 0; i < eat->NumberOfNames; ++i) {
      auto* name = reinterpret_cast<const char*>(b + names[i]);
      if (hash_rt(name) != name_hash)
        continue;

      uint32_t rva = funcs[ordinals[i]];

      // a forwarded export points back into the export directory
      if (rva >= exp_start && rva < exp_end) {
        const char* fwd = reinterpret_cast<const char*>(b + rva);
        const char* dot = fwd;
        while (*dot && *dot != '.')
          dot++;
        if (!*dot)
          return nullptr;

        wchar_t fwd_mod[64];
        int mi = 0;
        for (const char* p = fwd; p < dot && mi < 60; p++)
          fwd_mod[mi++] = static_cast<wchar_t>(*p);
        fwd_mod[mi++] = L'.';
        fwd_mod[mi++] = L'd';
        fwd_mod[mi++] = L'l';
        fwd_mod[mi++] = L'l';
        fwd_mod[mi] = 0;

        void* fwd_base = mod(hash_rt(fwd_mod, static_cast<uint16_t>(mi)));
        if (fwd_base)
          return exp(fwd_base, hash_rt(dot + 1));
        return nullptr;
      }

      return reinterpret_cast<void*>(b + rva);
    }
    return nullptr;
  }

}  // namespace pe
