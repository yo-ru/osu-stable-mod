#pragma once
// hooks native method pointers stored in CLR vtable slots
// swapping the slot leaves the compiled method body and IAT unchanged
// this avoids standard inline hook checks because no executable bytes are patched
// detection requires validating the slot destination instead of scanning for a code patch

#include <Windows.h>
#include "nocrt.h"
#include "pe.h"
#include "imports.h"
#include "../util/scan.h"

struct method_desc;

struct method_table {
  unsigned int flags;
  unsigned int base_size;
  unsigned short flags2;
  unsigned short token;
  unsigned short num_virtuals;
  unsigned short num_interfaces;
  unsigned int parent;
  unsigned int loader_module;
  unsigned int writable_data;
  unsigned int ee_class;
  unsigned int per_inst_info;
  unsigned int interface_map;

  // vtable slots follow the method table header
  unsigned int* get_slot(unsigned int slot) {
    auto** indirections = (unsigned int**)(this + 1);
    return &indirections[slot >> 3][slot & 7];
  }
};

struct ec_hash {
  ec_hash* next;
  const void* impl;
  const method_desc* md;
};

using do_prestub_fn = unsigned int(__thiscall*)(method_desc*, unsigned int);
using get_md_for_slot_fn = method_desc*(__thiscall*)(method_table*, unsigned int);

namespace clr {
  inline ec_hash** g_fcall_list = nullptr;
  inline do_prestub_fn g_do_prestub = nullptr;
  inline get_md_for_slot_fn g_get_md_for_slot = nullptr;
  inline bool g_range_armed = false;

  // forces the CLR to finish startup
  static constexpr auto k_sig_init =
      compile_pattern("55 8B EC 83 E4 F8 33 C9 E8 ?? ?? ?? ?? 8B E5 5D C3");

  // locates the CLR native-to-managed call table
  static constexpr auto k_sig_ecash = compile_pattern("85 C9 74 35 3B 0D ?? ?? ?? ?? 72 2D 3B 0D");

  // resolves a vtable slot to its MethodDesc
  static constexpr auto k_sig_getmd =
      compile_pattern("55 8B EC 51 56 57 FF 75 08 8B F1 E8 ?? ?? ?? ?? 8B F8 8B 16 81 E2");

  // compiles a method whose slot still points to the prestub
  static constexpr auto k_sig_prestub = compile_pattern("53 8B 4D 08 E8 ?? ?? ?? ?? 88");

  inline bool init() {
    static constexpr auto h_clr = pe::hash("clr.dll");
    void* clr_base = pe::mod(h_clr);
    if (!clr_base)
      return false;

    // finish CLR startup before resolving internal state
    auto* init_hit = scan_module_hashed(clr_base, &k_sig_init);
    if (!init_hit)
      return false;
    __try {
      ((void(__stdcall*)())init_hit)();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    // delay changing the range until the first hook is installed
    auto* echash_hit = scan_module_hashed(clr_base, &k_sig_ecash);
    if (!echash_hit)
      return false;
    g_fcall_list = *(ec_hash***)(echash_hit + 0x24);

    auto* getmd_hit = scan_module_hashed(clr_base, &k_sig_getmd);
    if (!getmd_hit)
      return false;
    g_get_md_for_slot = (get_md_for_slot_fn)getmd_hit;

    auto* prestub_hit = scan_module_hashed(clr_base, &k_sig_prestub);
    if (!prestub_hit)
      return false;
    auto call_base = (unsigned char*)prestub_hit + 4;
    int rel = *(int*)(call_base + 1);
    g_do_prestub = (do_prestub_fn)(call_base + 5 + rel);

    return g_fcall_list && g_get_md_for_slot && g_do_prestub;
  }

  // expand the accepted address range before installing the first hook
  inline void arm_fcall_range() {
    if (g_range_armed)
      return;
    g_range_armed = true;

    static constexpr auto h_clr = pe::hash("clr.dll");
    void* clr_base = pe::mod(h_clr);
    if (!clr_base)
      return;

    auto* echash_hit = scan_module_hashed(clr_base, &k_sig_ecash);
    if (!echash_hit)
      return;

    unsigned int* min_ptr = *(unsigned int**)(echash_hit + 0x6);
    unsigned int* max_ptr = *(unsigned int**)(echash_hit + 0xE);

    DWORD old = 0;
    if (imports::pVirtualProtect(min_ptr, 4, PAGE_READWRITE, &old)) {
      *min_ptr = 0;
      imports::pVirtualProtect(min_ptr, 4, old, &old);
    }
    if (imports::pVirtualProtect(max_ptr, 4, PAGE_READWRITE, &old)) {
      *max_ptr = 0x7FFFFFFF;
      imports::pVirtualProtect(max_ptr, 4, old, &old);
    }
  }

  inline void register_fcall(const void* impl, const method_desc* desc) {
    if (!g_fcall_list)
      return;

    unsigned int idx = (unsigned int)impl % 257;
    ec_hash** head = &g_fcall_list[idx];
    while (*head)
      head = &(*head)->next;

    HANDLE heap = imports::pGetProcessHeap();
    if (!heap)
      return;

    auto* node = (ec_hash*)imports::pHeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(ec_hash));
    if (node) {
      node->next = nullptr;
      node->impl = impl;
      node->md = desc;
      *head = node;
    }
  }

  inline unsigned int prepare_method(method_desc* md, unsigned int* slot) {
    // a 0xB0 prefix means the method still uses its prestub
    if (*(unsigned char*)*slot == 0xB0)
      return g_do_prestub(md, 0);
    return *slot;
  }

  // swap the slot in one atomic write so no thread can read a partial pointer
  // InterlockedExchange returns the original target for continued execution
  // the compiled method body is never patched
  template <typename F>
  inline F hook_virtual(method_table* mt, unsigned int slot, F detour) {
    arm_fcall_range();
    method_desc* md = g_get_md_for_slot(mt, slot);
    unsigned int* addr = mt->get_slot(slot);
    register_fcall((const void*)detour, md);
    prepare_method(md, addr);
    LONG original = InterlockedExchange((volatile LONG*)addr, (LONG)detour);
    return (F)original;
  }
}  // namespace clr
