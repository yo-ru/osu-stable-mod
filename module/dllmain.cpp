#include "pch.h"
#include "log.h"
#include "hook/clr.h"
#include "hook/imports.h"
#include "hook/pe.h"
#include "hook/hardening.h"
#include "game/offsets.h"
#include "game/scaler.h"
#include "game/math.hpp"
#include "aim/aim_assist.hpp"
#include "relax/relax.hpp"
#include "util/scan.h"

// signatures found in JIT code and the CLR runtime

// player method table marker in the CLR heap
static constexpr auto k_sig_player = compile_pattern("00 02 10 01 ?? 01 00 00 8A 05");
// SetMousePos call site in the JIT input handler
static constexpr auto k_sig_mouse = compile_pattern("FF 15 ?? ?? ?? ?? D9 45 E4 D9 45 E8");
// audio time pointer access
static constexpr auto k_sig_audio = compile_pattern("DE E9 83 EC 04 D9 1C 24 E8 ?? ?? ?? ?? 8B 85");

// runtime state

static HMODULE g_module = nullptr;
static method_table* g_player_mt = nullptr;
static int* g_audio_time = nullptr;
static int g_last_audio_time = 0;
static LARGE_INTEGER g_audio_freeze_start = {};
static bool g_audio_frozen = false;
static int64_t g_qpf_cached = 0;
static uint32_t g_fc = 0;
static int g_last_relax_audio_time = -1;
static vec2 g_cursor_pos = {};

// safe field reads for managed object pointers

static void* rptr(void* o, int off) {
  return o ? *(void**)((char*)o + off) : nullptr;
}
static int rint(void* o, int off) {
  return o ? *(int*)((char*)o + off) : 0;
}
static float rflt(void* o, int off) {
  return o ? *(float*)((char*)o + off) : 0;
}
static bool rbool(void* o, int off) {
  return o ? *(bool*)((char*)o + off) : false;
}
static vec2 rvec2(void* o, int off) {
  return o ? *(vec2*)((char*)o + off) : vec2{0, 0};
}

// original hook targets

typedef void(__fastcall* player_fn_t)(void*);
typedef void(__stdcall* set_mouse_pos_t)(vec2);

static player_fn_t g_orig_update = nullptr;
static player_fn_t g_orig_dispose = nullptr;
static player_fn_t g_orig_load_complete = nullptr;
static set_mouse_pos_t g_orig_set_mouse_pos = nullptr;

static void update_aim(void* player, int audio_time) {
  __try {
    void* hom = rptr(player, OFF_PLAYER_HIT_OBJECT_MANAGER);
    if (!hom)
      return;
    int preempt = rint(hom, OFF_HOM_PREEMPT);
    float sc = g_scaler.get_scale();

    void* list = rptr(hom, OFF_HOM_HIT_OBJECTS);
    if (!list)
      return;
    void* arr = rptr(list, OFF_LIST_ITEMS);
    int count = rint(list, OFF_LIST_SIZE);
    if (!arr || count <= 0)
      return;
    void** items = (void**)((char*)arr + OFF_ARRAY_DATA);

    int hw = rint(hom, OFF_HOM_HIT_WINDOW_300);
    int ep = preempt > 0 ? preempt : 800;
    void* target = nullptr;

    for (int i = 0; i < count; i++) {
      void* obj = items[i];
      if (!obj)
        continue;
      if (rint(obj, OFF_HO_TYPE) & HIT_SPINNER)
        continue;
      int st = rint(obj, OFF_HO_START_TIME);
      if (audio_time > st - hw)
        continue;
      if (audio_time >= st - ep)
        target = obj;
      break;
    }

    if (!target) {
      aa::g.should_assist = false;
      return;
    }

    vec2 screen_pos = g_scaler.to_screen(rvec2(target, OFF_HO_POSITION));
    float raw_radius = rflt(hom, OFF_HOM_HIT_OBJECT_RADIUS);
    aa::set_target(screen_pos, raw_radius, (double)rint(target, OFF_HO_START_TIME), sc);
    aa::g.should_assist = aa::check_range(aa::g.prev_mouse_pos);
  } __except (1) {
    aa::g.should_assist = false;
  }
}

// runs once per Player.Update frame

static void __fastcall update_impl(void* ecx) {
  g_fc++;
  if (!g_audio_time)
    return;

  __try {
    if (rbool(ecx, OFF_PLAYER_IS_REPLAY)) {
      aa::g.should_assist = false;
      if (aa::g.in_gameplay)
        aa::reset();
      relax::reset();
      return;
    }
    if (!rbool(ecx, OFF_PLAYER_ASYNC_LOAD_COMPLETE))
      return;
  } __except (1) {
    aa::g.should_assist = false;
    relax::reset();
    return;
  }

  int current_time = *g_audio_time;
  if (current_time != g_last_audio_time) {
    g_audio_freeze_start.QuadPart = 0;
    g_audio_frozen = false;
  } else if (!g_audio_freeze_start.QuadPart) {
    imports::pQueryPerformanceCounter(&g_audio_freeze_start);
  } else {
    LARGE_INTEGER now;
    imports::pQueryPerformanceCounter(&now);
    if (!g_qpf_cached) {
      LARGE_INTEGER frequency;
      imports::pQueryPerformanceFrequency(&frequency);
      g_qpf_cached = frequency.QuadPart;
    }
    double elapsed =
        (double)(now.QuadPart - g_audio_freeze_start.QuadPart) / (double)g_qpf_cached;
    g_audio_frozen = elapsed > 0.5;
  }
  g_last_audio_time = current_time;

  if (g_audio_frozen) {
    aa::g.should_assist = false;
    if (aa::g.in_gameplay)
      aa::reset();
    return;
  }

  if (g_last_relax_audio_time >= 0 && current_time < g_last_relax_audio_time - 500)
    relax::reset();
  g_last_relax_audio_time = current_time;

  aa::begin_gameplay(g_cursor_pos);
  if (g_fc % 500 == 0)
    g_scaler.update();

  update_aim(ecx, current_time);
  relax::update(ecx, current_time, g_cursor_pos);
}

static void __fastcall dispose_impl(void*) {
  aa::reset();
  relax::reset();
  g_last_relax_audio_time = -1;
}

static void __fastcall loadcomplete_impl(void*) {
  g_scaler.update();
}

// applies the aim offset to cursor updates

static void __stdcall mouse_process(vec2* pos) {
  g_cursor_pos = *pos;
  if (aa::g.in_gameplay || aa::needs_resync())
    *pos = aa::process(*pos);
}

// preserve the caller's registers around each detour

static __declspec(naked) void update_hook() {
  __asm {
    pushad
    pushfd
    mov ecx, [esp+0x1C]
    call update_impl
    popfd
    popad
    jmp [g_orig_update]
  }
}

static __declspec(naked) void dispose_hook() {
  __asm {
    pushad
    pushfd
    mov ecx, [esp+0x1C]
    call dispose_impl
    popfd
    popad
    jmp [g_orig_dispose]
  }
}

static __declspec(naked) void loadcomplete_hook() {
  __asm {
    pushad
    pushfd
    mov ecx, [esp+0x1C]
    call loadcomplete_impl
    popfd
    popad
    jmp [g_orig_load_complete]
  }
}

static __declspec(naked) void mouse_hook() {
  __asm {
    lea eax, [esp+4]
    push eax
    call mouse_process
    jmp [g_orig_set_mouse_pos]
  }
}

// initializes hooks after the CLR is ready

static DWORD WINAPI bootstrap_thread(LPVOID) {
  log_init();

  static constexpr auto h_clrjit = pe::hash("clrjit.dll");
  while (!pe::mod(h_clrjit))
    imports::pSleep(10);

  imports::pSleep(3000);

  if (!clr::init()) {
    LOG("clr init failed");
    return 1;
  }

  imports::pSleep(5000);

  // find the Player method table in the CLR heap
  method_table* player_mt = nullptr;
  refresh_scan_cache();

  for (int attempt = 0; attempt < 60; attempt++) {
    if (attempt == 30)
      refresh_scan_cache();

    auto* hit = (method_table*)scan_rw(&k_sig_player);
    if (hit) {
      bool valid = false;
      __try {
        valid = hit->num_virtuals >= 5 && hit->num_virtuals <= 300 && hit->num_interfaces <= 50 &&
                hit->base_size >= 0x100 && hit->base_size <= 0x2000;
      } __except (1) {
        valid = false;
      }
      if (valid) {
        player_mt = hit;
        g_player_mt = hit;
        break;
      }
    }
    imports::pSleep(1000);
  }

  if (!player_mt) {
    LOG("player mt not found");
    return 1;
  }
  LOG("player mt at %p", (void*)player_mt);

  // player slots 6, 7, and 11 handle update, dispose, and load completion
  g_orig_update = clr::hook_virtual(player_mt, 6, (player_fn_t)update_hook);
  g_orig_dispose = clr::hook_virtual(player_mt, 7, (player_fn_t)dispose_hook);
  g_orig_load_complete = clr::hook_virtual(player_mt, 11, (player_fn_t)loadcomplete_hook);

  LOG("player hooks: update=%p dispose=%p loadcomplete=%p", (void*)g_orig_update,
      (void*)g_orig_dispose, (void*)g_orig_load_complete);

  // atomically replace the indirect SetMousePos target used by the JIT input handler
  // keep the original delegate returned by InterlockedExchange for normal execution
  for (int attempt = 0; attempt < 120; attempt++) {
    if (attempt == 60)
      refresh_scan_cache();

    auto* hit = scan_rwx(&k_sig_mouse);
    if (hit) {
      __try {
        auto** slot = *(uint32_t***)(hit + 0x2);
        MEMORY_BASIC_INFORMATION mbi;
        if (slot && imports::pVirtualQuery((void*)*slot, &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT) {
          g_orig_set_mouse_pos =
              (set_mouse_pos_t)InterlockedExchange((volatile LONG*)slot, (LONG)mouse_hook);
          LOG("mouse hook at %p", (void*)g_orig_set_mouse_pos);
          break;
        }
      } __except (1) {
        continue;
      }
    }
    imports::pSleep(500);
  }

  // find the current song time
  __try {
    auto* at = scan_rwx(&k_sig_audio);
    if (at) {
      int* candidate = *(int**)(at + 0x1E);
      MEMORY_BASIC_INFORMATION mbi;
      if (candidate && imports::pVirtualQuery(candidate, &mbi, sizeof(mbi)) &&
          mbi.State == MEM_COMMIT) {
        g_audio_time = candidate;
        LOG("audio time at %p", (void*)g_audio_time);
      }
    }
  } __except (1) {
  }

  relax::initialize();

  // clean up the mapped image after hooks are ready
  hardening::fix_section_protections(g_module);
  hardening::scrub_pe_headers(g_module);

  LOG("hardening complete");

  return 0;
}

// resolves imports and starts initialization after manual mapping

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_module = module;
    if (!imports::init())
      return FALSE;
    imports::pDisableThreadLibraryCalls(module);

    HANDLE thread = imports::pCreateThread(nullptr, 0, bootstrap_thread, nullptr, 0, nullptr);
    if (thread)
      imports::pCloseHandle(thread);
  }

  return TRUE;
}
