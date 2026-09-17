#include "relax.hpp"

#include "../game/offsets.h"
#include "../hook/imports.h"
#include "../hook/nocrt.h"

namespace relax {

  struct profile {
    float base_offset_ms;
    float offset_sigma_ms;
    float offset_skew;
    float k1_hold_mean_ms;
    float k1_hold_sigma_ms;
    float k2_hold_mean_ms;
    float k2_hold_sigma_ms;
    float min_hold_ms;
    float k1_bias;
    float fatigue_rate;
    float fatigue_cap;
    float warmup_notes;
    float stream_drift_rate;
    float stream_drift_dir;
    float stream_reset_chance;
    float post_break_sigma;
    float first_note_bias;
    float bpm_offset_scale;
    float bpm_sigma_scale;
    float timing_noise_tau;
    float hold_noise_tau;
    float key_asymmetry;
  };

  struct state {
    bool initialized;
    profile prof;
    bool k1_down;
    bool k2_down;
    int k1_release_time;
    int k2_release_time;
    bool last_key_was_k1;
    int press_target_time;
    int current_ho_index;
    float timing_ou;
    float hold_ou;
    float fatigue_acc;
    int notes_hit;
    int last_hit_time;
    float late_debt;
    float last_interval;
    uint32_t rng;
    vec2 last_cursor_pos;
    int last_cursor_move_time;
  };

  static state g_state = {};
  static BYTE g_vk_k1 = 0x5A;
  static BYTE g_vk_k2 = 0x58;

  static void* read_pointer(void* object, int offset) {
    return object ? *(void**)((char*)object + offset) : nullptr;
  }

  static int read_int(void* object, int offset) {
    return object ? *(int*)((char*)object + offset) : 0;
  }

  static uint32_t seed_rng(const uint8_t* seed) {
    uint32_t hash = 0x811C9DC5u;

    for (int i = 0; i < 32; i++) {
      hash ^= seed[i];
      hash *= 0x01000193u;
    }

    return hash ? hash : 0x9E3779B9u;
  }

  static uint32_t xorshift(uint32_t& state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;

    return state;
  }

  static float uniform_01(uint32_t& state) {
    return (float)(xorshift(state) & 0x7FFFFFFF) / 2147483647.0f;
  }

  static float gaussian(float u1, float u2) {
    float safe_u1 = u1 < 0.0001f ? 0.0001f : u1;

    return nc_sqrtf(-2.0f * nc_logf(safe_u1)) * nc_cosf(6.2831853f * u2);
  }

  static float clamp(float value, float low, float high) {
    return value < low ? low : value > high ? high : value;
  }

  static void initialize_profile() {
    // the seed keeps one install's timing and playstyle stable between runs
    uint32_t seed = seed_rng(config::seed);
    g_state.rng = seed;

    auto normal = [&](float mean, float sigma) {
      float u1 = uniform_01(seed);
      float u2 = uniform_01(seed);

      return mean + sigma * gaussian(u1, u2);
    };

    g_state.prof.base_offset_ms = clamp(normal(-4.0f, 0.5f), -6.0f, -2.5f);
    g_state.prof.offset_sigma_ms = clamp(normal(0.36f, 0.03f), 0.30f, 0.42f);
    g_state.prof.offset_skew = clamp(normal(-0.03f, 0.05f), -0.10f, 0.08f);
    g_state.prof.k1_hold_mean_ms = clamp(normal(38.0f, 5.0f), 28.0f, 50.0f);
    g_state.prof.k1_hold_sigma_ms = clamp(normal(6.0f, 1.0f), 4.0f, 9.0f);
    g_state.prof.k2_hold_mean_ms = clamp(normal(40.0f, 5.0f), 30.0f, 52.0f);
    g_state.prof.k2_hold_sigma_ms = clamp(normal(6.0f, 1.0f), 4.0f, 9.0f);
    g_state.prof.min_hold_ms = clamp(normal(18.0f, 3.0f), 12.0f, 25.0f);
    g_state.prof.k1_bias = clamp(normal(0.5f, 0.02f), 0.47f, 0.53f);
    g_state.prof.fatigue_rate = clamp(uniform_01(seed) * 0.06f, 0.0f, 0.08f);
    g_state.prof.fatigue_cap = clamp(normal(1.5f, 0.3f), 0.8f, 2.5f);
    g_state.prof.warmup_notes = clamp(normal(3.0f, 1.0f), 2.0f, 5.0f);
    g_state.prof.stream_drift_rate = clamp(normal(0.0f, 0.08f), -0.2f, 0.2f);
    g_state.prof.stream_drift_dir = uniform_01(seed) > 0.5f ? 1.0f : -1.0f;
    g_state.prof.stream_reset_chance = clamp(uniform_01(seed) * 0.06f, 0.02f, 0.06f);
    g_state.prof.post_break_sigma = clamp(normal(1.5f, 0.4f), 0.8f, 2.5f);
    g_state.prof.first_note_bias = clamp(normal(-0.5f, 0.8f), -2.0f, 1.0f);
    g_state.prof.bpm_offset_scale = clamp(normal(0.0f, 0.003f), -0.008f, 0.008f);
    g_state.prof.bpm_sigma_scale = clamp(normal(0.0f, 0.002f), -0.005f, 0.005f);
    g_state.prof.timing_noise_tau = clamp(normal(0.50f, 0.08f), 0.35f, 0.70f);
    g_state.prof.hold_noise_tau = clamp(normal(0.35f, 0.05f), 0.25f, 0.50f);
    g_state.prof.key_asymmetry = clamp(normal(3.0f, 1.5f), 1.0f, 6.0f);
    g_state.initialized = true;
  }

  static BYTE key_name_to_vk(const char* name, int length) {
    if (length == 1 && name[0] >= 'A' && name[0] <= 'Z')
      return (BYTE)name[0];
    if (length == 1 && name[0] >= 'a' && name[0] <= 'z')
      return (BYTE)(name[0] - 32);
    if (length == 1 && name[0] >= '0' && name[0] <= '9')
      return (BYTE)name[0];

    uint32_t hash = 0x811C9DC5u;
    for (int i = 0; i < length; i++) {
      char value = name[i];
      if (value >= 'A' && value <= 'Z')
        value += 32;
      hash ^= (uint8_t)value;
      hash *= 0x01000193u;
    }

    switch (hash) {
      case 0x3553E285u:
        return 0x20;
      case 0x98F72E4Cu:
        return 0x09;
      case 0x65A211B0u:
        return 0xA0;
      case 0x1E1F20EEu:
        return 0xA1;
      case 0xA237DC4Bu:
        return 0xA2;
      case 0x62BE7577u:
        return 0xBC;
      case 0x3F7E9FFDu:
        return 0xBE;
      case 0xFF24E0B0u:
        return 0xDB;
      case 0x0124E3D6u:
        return 0xDD;
      case 0x7DE4A469u:
        return 0xBA;
      case 0x92720329u:
        return 0xDE;
      case 0xA0E51618u:
        return 0xBF;
      case 0x8138F272u:
        return 0xC0;
      case 0x3229AA58u:
        return 0xDC;
      case 0x26C62BC4u:
        return 0xBB;
      case 0x4150482Cu:
        return 0xBD;
    }

    return 0;
  }

  static bool read_keys() {
    if (!imports::pGetModuleFileNameA || !imports::pCreateFileA || !imports::pReadFile ||
        !imports::pCloseHandle || !imports::pGetFileSize || !imports::pFindFirstFileA ||
        !imports::pFindNextFileA || !imports::pFindClose || !imports::pHeapAlloc ||
        !imports::pHeapFree || !imports::pGetProcessHeap)
      return false;

    char executable_path[MAX_PATH];
    DWORD path_length = imports::pGetModuleFileNameA(nullptr, executable_path, MAX_PATH);
    if (!path_length || path_length >= MAX_PATH)
      return false;

    int directory_length = (int)path_length;
    while (directory_length > 0 && executable_path[directory_length - 1] != '\\')
      directory_length--;

    // read the player's real binds so relax never assumes Z/X unnecessarily
    static constexpr char k_glob[] = "osu!.*.cfg";
    if (directory_length + (int)sizeof(k_glob) > MAX_PATH)
      return false;

    char search_path[MAX_PATH];
    for (int i = 0; i < directory_length; i++)
      search_path[i] = executable_path[i];
    for (int i = 0; k_glob[i]; i++)
      search_path[directory_length + i] = k_glob[i];
    search_path[directory_length + sizeof(k_glob) - 1] = 0;

    WIN32_FIND_DATAA find_data;
    HANDLE find = imports::pFindFirstFileA(search_path, &find_data);
    if (find == INVALID_HANDLE_VALUE)
      return false;

    bool found_k1 = false;
    bool found_k2 = false;

    do {
      char file_path[MAX_PATH];
      for (int i = 0; i < directory_length; i++)
        file_path[i] = executable_path[i];

      int name_length = 0;
      while (find_data.cFileName[name_length]) {
        if (directory_length + name_length + 1 >= MAX_PATH)
          break;
        file_path[directory_length + name_length] = find_data.cFileName[name_length];
        name_length++;
      }
      file_path[directory_length + name_length] = 0;

      HANDLE file = imports::pCreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                           OPEN_EXISTING, 0, nullptr);
      if (file == INVALID_HANDLE_VALUE)
        continue;

      DWORD file_size = imports::pGetFileSize(file, nullptr);
      if (!file_size || file_size > 512 * 1024) {
        imports::pCloseHandle(file);
        continue;
      }

      HANDLE heap = imports::pGetProcessHeap();
      auto* buffer = (char*)imports::pHeapAlloc(heap, 0, file_size + 1);
      if (!buffer) {
        imports::pCloseHandle(file);
        continue;
      }

      DWORD bytes_read = 0;
      BOOL read = imports::pReadFile(file, buffer, file_size, &bytes_read, nullptr);
      imports::pCloseHandle(file);

      if (!read) {
        imports::pHeapFree(heap, 0, buffer);
        continue;
      }

      buffer[bytes_read] = 0;
      int position = 0;

      while (position < (int)bytes_read) {
        int line_start = position;
        while (position < (int)bytes_read && buffer[position] != '\n' &&
               buffer[position] != '\r')
          position++;
        int line_end = position;
        while (position < (int)bytes_read &&
               (buffer[position] == '\n' || buffer[position] == '\r'))
          position++;

        int line_length = line_end - line_start;
        char* line = buffer + line_start;
        static constexpr char k_left[] = "keyOsuLeft";
        static constexpr char k_right[] = "keyOsuRight";
        bool is_left = line_length > 13;
        bool is_right = line_length > 14;

        for (int i = 0; is_left && i < 10; i++)
          is_left = line[i] == k_left[i];
        for (int i = 0; is_right && i < 11; i++)
          is_right = line[i] == k_right[i];

        if (!is_left && !is_right)
          continue;

        int value_start = is_left ? 10 : 11;
        while (value_start < line_length &&
               (line[value_start] == ' ' || line[value_start] == '='))
          value_start++;

        int value_end = line_length;
        while (value_end > value_start &&
               (line[value_end - 1] == ' ' || line[value_end - 1] == '\t'))
          value_end--;

        BYTE key = key_name_to_vk(line + value_start, value_end - value_start);
        if (!key)
          continue;

        if (is_left) {
          g_vk_k1 = key;
          found_k1 = true;
        } else {
          g_vk_k2 = key;
          found_k2 = true;
        }
      }

      imports::pHeapFree(heap, 0, buffer);
    } while (!(found_k1 && found_k2) && imports::pFindNextFileA(find, &find_data));

    imports::pFindClose(find);

    return found_k1 && found_k2;
  }

  static void send_key(BYTE key, bool down) {
    if (imports::pKeybdEvent)
      imports::pKeybdEvent(key, 0, down ? 0 : KEYEVENTF_KEYUP, 0);
  }

  static void release_all() {
    if (g_state.k1_down) {
      send_key(g_vk_k1, false);
      g_state.k1_down = false;
    }
    if (g_state.k2_down) {
      send_key(g_vk_k2, false);
      g_state.k2_down = false;
    }
  }

  static void step_ou(float& state, float tau, float delta_ms) {
    if (tau < 0.001f)
      tau = 0.001f;

    float delta = delta_ms / 1000.0f;
    float decay = nc_expf(-delta / tau);
    float u1 = uniform_01(g_state.rng);
    float u2 = uniform_01(g_state.rng);
    float variance = nc_fmaxf(0, 1.0f - decay * decay);
    state = state * decay + gaussian(u1, u2) * nc_sqrtf(variance);
  }

  static float sample_timing(float delta_from_previous, int hit_window_300) {
    float sigma = g_state.prof.offset_sigma_ms * (float)hit_window_300;

    if (delta_from_previous < 100.0f) {
      int bpm_limit = config::bpm_limit;
      float limit_interval = bpm_limit > 0 ? 30000.0f / (float)bpm_limit : 50.0f;
      if (delta_from_previous >= limit_interval) {
        sigma *= 0.55f;
      } else {
        float excess = (limit_interval - delta_from_previous) / limit_interval;
        sigma *= 0.55f + excess * 0.35f;
      }
    } else if (delta_from_previous > 200.0f) {
      sigma *= 0.5f;
    } else if (delta_from_previous > 150.0f) {
      sigma *= 0.7f;
    }

    sigma += nc_fminf(g_state.fatigue_acc, g_state.prof.fatigue_cap) * 0.15f;

    if (g_state.notes_hit < (int)g_state.prof.warmup_notes)
      sigma *= 1.0f + 0.15f *
                           (1.0f - (float)g_state.notes_hit / g_state.prof.warmup_notes);
    if (delta_from_previous > 1000.0f)
      sigma += g_state.prof.post_break_sigma;

    step_ou(g_state.timing_ou, g_state.prof.timing_noise_tau, delta_from_previous);

    float ou_weight = 0.15f;
    if (delta_from_previous < 100.0f)
      ou_weight = 0.95f;
    else if (delta_from_previous < 200.0f)
      ou_weight = 0.40f;

    float u1 = uniform_01(g_state.rng);
    float u2 = uniform_01(g_state.rng);
    float independent = gaussian(u1, u2);
    float offset = g_state.prof.base_offset_ms +
                   (independent * (1.0f - ou_weight) + g_state.timing_ou * ou_weight) * sigma;
    float asymmetry = g_state.prof.key_asymmetry;

    if (delta_from_previous < 100.0f)
      asymmetry *= 0.4f;
    offset += g_state.last_key_was_k1 ? asymmetry : -asymmetry;

    if (!g_state.notes_hit)
      offset += g_state.prof.first_note_bias;

    if (g_state.late_debt > 2.0f) {
      float recovery = delta_from_previous < 100.0f ? 0.25f : 0.6f;
      offset -= g_state.late_debt * recovery;
      g_state.late_debt *= 1.0f - recovery * 0.8f;
    } else {
      g_state.late_debt *= 0.6f;
    }

    float bpm_loss = 0.0f;
    int bpm_limit = config::bpm_limit;
    if (bpm_limit > 0 && delta_from_previous > 20.0f) {
      float threshold = 30000.0f / (float)bpm_limit;
      if (delta_from_previous < threshold) {
        bpm_loss = (threshold - delta_from_previous) / threshold;
        if (bpm_loss > 1.0f)
          bpm_loss = 1.0f;
        sigma *= 1.0f + bpm_loss * 1.5f;
      }
    }

    float max_early = (float)hit_window_300 * 0.6f;
    float max_late = (float)hit_window_300 * 0.35f;
    if (delta_from_previous > 150.0f)
      max_late = (float)hit_window_300 * 0.15f;
    else if (delta_from_previous > 100.0f)
      max_late = (float)hit_window_300 * 0.25f;

    if (bpm_loss > 0.0f) {
      max_late += (float)hit_window_300 * bpm_loss * 0.8f;
      max_early += (float)hit_window_300 * bpm_loss * 0.4f;
    }

    return clamp(offset, -max_early, max_late);
  }

  static float sample_hold(float interval) {
    float base_hold;
    if (interval < 100.0f)
      base_hold = interval * 1.1f + 10.0f;
    else if (interval < 200.0f)
      base_hold = interval * 0.5f + 30.0f;
    else
      base_hold = 50.0f;

    float u1 = uniform_01(g_state.rng);
    float u2 = uniform_01(g_state.rng);
    step_ou(g_state.hold_ou, g_state.prof.hold_noise_tau, interval);
    float hold = base_hold + (gaussian(u1, u2) * 0.3f + g_state.hold_ou * 0.7f) * 6.0f;

    return hold < 30.0f ? 30.0f : hold;
  }

  static bool choose_k1() {
    if (!g_state.notes_hit)
      return g_state.prof.k1_bias > 0.5f;
    if (g_state.last_interval < 130.0f)
      return !g_state.last_key_was_k1;

    float bias = g_state.prof.k1_bias;
    if (bias < 0.495f)
      return !g_state.last_key_was_k1;
    if (bias > 0.525f)
      return bias > 0.5f;

    float singletap_chance = 0.18f;
    if (g_state.last_interval < 200.0f)
      singletap_chance = 0.20f;
    else if (g_state.last_interval < 300.0f)
      singletap_chance = 0.35f;

    if (uniform_01(g_state.rng) < singletap_chance)
      return bias > 0.5f;

    return !g_state.last_key_was_k1;
  }

  void initialize() {
    read_keys();
    initialize_profile();
    reset();
  }

  void update(void* player, int audio_time, vec2 cursor_pos) {
    if (!config::enabled || !g_state.initialized)
      return;

    __try {
      if (g_state.k1_down && g_state.k1_release_time > 0 &&
          audio_time >= g_state.k1_release_time) {
        send_key(g_vk_k1, false);
        g_state.k1_down = false;
      }
      if (g_state.k2_down && g_state.k2_release_time > 0 &&
          audio_time >= g_state.k2_release_time) {
        send_key(g_vk_k2, false);
        g_state.k2_down = false;
      }

      void* manager = read_pointer(player, OFF_PLAYER_HIT_OBJECT_MANAGER);
      if (!manager)
        return;
      void* list = read_pointer(manager, OFF_HOM_HIT_OBJECTS);
      if (!list)
        return;
      void* array = read_pointer(list, OFF_LIST_ITEMS);
      int count = read_int(list, OFF_LIST_SIZE);
      if (!array || count <= 0)
        return;

      auto** items = (void**)((char*)array + OFF_ARRAY_DATA);
      if (g_state.current_ho_index >= count) {
        reset();
        return;
      }

      int hit_window_300 = read_int(manager, OFF_HOM_HIT_WINDOW_300);
      int hit_window_50 = read_int(manager, OFF_HOM_HIT_WINDOW_50);
      if (hit_window_300 <= 0)
        hit_window_300 = 50;
      if (hit_window_50 <= 0)
        hit_window_50 = 150;

      // cursor activity prevents taps when the player is not actively aiming
      float cursor_delta = (cursor_pos - g_state.last_cursor_pos).length();
      if (cursor_delta > 2.0f)
        g_state.last_cursor_move_time = audio_time;
      g_state.last_cursor_pos = cursor_pos;
      bool cursor_active = audio_time - g_state.last_cursor_move_time < 2000;

      for (int i = g_state.current_ho_index; i < count; i++) {
        void* object = items[i];
        if (!object)
          continue;

        int type = read_int(object, OFF_HO_TYPE);
        if (!(type & (HIT_CIRCLE | HIT_SLIDER | HIT_SPINNER))) {
          g_state.current_ho_index = i + 1;
          continue;
        }

        int start_time = read_int(object, OFF_HO_START_TIME);
        if (type & HIT_SPINNER) {
          int end_time = read_int(object, OFF_HO_END_TIME);
          if (end_time <= start_time)
            end_time = start_time + 1000;

          if (!g_state.k1_down && !g_state.k2_down && !g_state.press_target_time) {
            float u1 = uniform_01(g_state.rng);
            float u2 = uniform_01(g_state.rng);
            int early = 30 + (int)(gaussian(u1, u2) * 15.0f);
            early = (int)clamp((float)early, 10.0f, 80.0f);
            g_state.press_target_time = start_time - early;

            u1 = uniform_01(g_state.rng);
            u2 = uniform_01(g_state.rng);
            int late = 20 + (int)(gaussian(u1, u2) * 12.0f);
            late = (int)clamp((float)late, 5.0f, 60.0f);
            g_state.k1_release_time = end_time + late;
          }

          if (!g_state.k1_down && !g_state.k2_down && g_state.press_target_time &&
              audio_time >= g_state.press_target_time) {
            int release_time = g_state.k1_release_time;
            bool use_k1 = !g_state.last_key_was_k1;
            send_key(use_k1 ? g_vk_k1 : g_vk_k2, true);
            if (use_k1) {
              g_state.k1_down = true;
              g_state.k1_release_time = release_time;
            } else {
              g_state.k2_down = true;
              g_state.k2_release_time = release_time;
            }
            g_state.last_key_was_k1 = use_k1;
          }

          if (audio_time >= end_time + 50) {
            g_state.press_target_time = 0;
            g_state.current_ho_index = i + 1;
            continue;
          }
          break;
        }

        if (audio_time > start_time + hit_window_50 && !g_state.press_target_time) {
          g_state.current_ho_index = i + 1;
          continue;
        }

        if (!g_state.press_target_time) {
          float map_delta = g_state.last_interval;
          if (i > 0) {
            void* previous = items[i - 1];
            if (previous) {
              int previous_start = read_int(previous, OFF_HO_START_TIME);
              if (start_time > previous_start)
                map_delta = (float)(start_time - previous_start);
            }
          }

          if (map_delta > 0)
            g_state.last_interval = map_delta;
          float timing_delta = (float)(start_time - g_state.last_hit_time);
          float sample_delta = timing_delta > 0 ? timing_delta : map_delta;
          g_state.press_target_time =
              start_time + (int)sample_timing(sample_delta, hit_window_300);
          g_state.last_key_was_k1 = choose_k1();
        }

        if (audio_time >= g_state.press_target_time && cursor_active) {
          bool use_k1 = g_state.last_key_was_k1;
          if ((use_k1 && g_state.k1_down) || (!use_k1 && g_state.k2_down))
            use_k1 = !use_k1;

          send_key(use_k1 ? g_vk_k1 : g_vk_k2, true);
          if (use_k1)
            g_state.k1_down = true;
          else
            g_state.k2_down = true;

          int release_time;
          if (type & HIT_SLIDER) {
            int end_time = read_int(object, OFF_HO_END_TIME);
            if (end_time <= start_time)
              end_time = start_time + 100;
            float u1 = uniform_01(g_state.rng);
            float u2 = uniform_01(g_state.rng);
            float extra = 25.0f + gaussian(u1, u2) * 12.0f;
            if (extra < 10.0f)
              extra = 10.0f;
            release_time = end_time + (int)extra;
          } else {
            release_time = audio_time + (int)sample_hold(g_state.last_interval);
          }

          if (use_k1)
            g_state.k1_release_time = release_time;
          else
            g_state.k2_release_time = release_time;

          float lateness = (float)(audio_time - start_time);
          if (lateness > 2.0f)
            g_state.late_debt += lateness * 0.8f;
          g_state.notes_hit++;
          g_state.fatigue_acc += g_state.prof.fatigue_rate;
          g_state.last_hit_time = start_time;
          g_state.press_target_time = 0;
          g_state.current_ho_index = i + 1;
          break;
        }

        if (!cursor_active && audio_time > start_time + hit_window_50) {
          g_state.press_target_time = 0;
          g_state.current_ho_index = i + 1;
          continue;
        }
        break;
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      reset();
    }
  }

  void reset() {
    release_all();
    g_state.k1_down = false;
    g_state.k2_down = false;
    g_state.k1_release_time = 0;
    g_state.k2_release_time = 0;
    g_state.press_target_time = 0;
    g_state.current_ho_index = 0;
    g_state.timing_ou = 0;
    g_state.hold_ou = 0;
    g_state.fatigue_acc = 0;
    g_state.notes_hit = 0;
    g_state.last_hit_time = 0;
    g_state.late_debt = 0;
    g_state.last_interval = 170.0f;
    g_state.last_cursor_move_time = 0;
  }

}  // namespace relax
