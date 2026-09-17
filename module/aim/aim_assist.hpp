#pragma once
// adjusts cursor input through the game's SetMousePos delegate

#include "../game/math.hpp"
#include "../hook/nocrt.h"

namespace aa {

  // recompile after changing these values
  namespace config {
    inline float max_offset = 8.0f;
    inline float assist_strength = 0.25f;
    inline float power = 0.40f;
    inline float resync_speed = 0.25f;
    inline float deadzone_decay = 0.40f;
    inline float deadzone_radius = 0.90f;
    inline bool enable_anti_tug = false;
    inline float stream_time_threshold = 125.0f;
    inline float stream_distance_mult = 5.0f;
    inline float stream_velocity_cap = 0.3f;
  }  // namespace config

  struct state {
    vec2 target_pos, mouse_offset, prev_mouse_pos;
    vec2 prev_offset_delta;
    vec2 prev_output_vel;
    bool should_assist, in_gameplay;
    float object_radius, assist_radius, max_offset, current_decay;
    double current_target_time;
    float tap_engagement, stream_factor;
    float angle_noise_assist, angle_noise_resync;
    float speed_noise;
    float hesitation;
    float resync_blend;
    int64_t last_step_ticks, qpc_freq_ticks;
  };

  extern state g;

  void begin_gameplay(vec2 cursor);
  void reset();
  bool needs_resync();
  void set_target(vec2 sp, float rad, double st, float scale);
  bool check_range(vec2 c);
  vec2 process(vec2 raw);

}  // namespace aa
