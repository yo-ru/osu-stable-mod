#include "aim_assist.hpp"
#include "../hook/imports.h"
#include "../util/rng.hpp"

namespace aa {

  state g = {};

  static xorshift32 g_rng;

  static constexpr float K_NOISE_TAU = 0.080f, K_NOISE_SIGMA = 0.075f;
  static constexpr float K_SPEED_TAU = 0.060f, K_SPEED_SIGMA = 0.12f;
  static constexpr float K_HESIT_TAU = 0.200f, K_HESIT_SIGMA = 0.08f;
  static constexpr float K_DZ_INNER = 0.70f, K_DZ_OUTER = 1.00f, K_SAT = 1.5f;
  static constexpr float K_EXIT_DECAY = 12.0f;

  static vec2 rotate(vec2 v, float a) {
    float c = nc_cosf(a), s = nc_sinf(a);
    return {v.x * c - v.y * s, v.x * s + v.y * c};
  }

  static float smoothstep(float x) {
    x = nc_fminf(nc_fmaxf(x, 0), 1);
    return x * x * (3 - 2 * x);
  }

  static float saturate(float m, float mo) {
    float k = mo * K_SAT;
    return k < 0.0001f ? m : k * nc_tanhf(m / k);
  }

  // adds smooth noise instead of sharp random jitter
  static void step_ou(float& s, float base_tau, float base_sigma, float sf, float dt) {
    float t = base_tau, sig = base_sigma;
    if (sf > 0) {
      t *= 1 - 0.5f * sf;
      sig *= 1 - 0.35f * sf;
    }
    if (t < 0.0005f)
      t = 0.0005f;
    float d = nc_expf(-dt / t);
    float amp = sig * nc_sqrtf(nc_fmaxf(0, 1 - d * d));
    s = s * d + g_rng.gauss() * amp;
  }

  static void step_noise(float& s, float sf, float dt) {
    step_ou(s, K_NOISE_TAU, K_NOISE_SIGMA, sf, dt);
  }

  void begin_gameplay(vec2 cursor) {
    if (g.in_gameplay)
      return;

    g.in_gameplay = true;
    g.prev_mouse_pos = cursor;
    g.prev_offset_delta = g.mouse_offset;
    g.prev_output_vel = {};
    g.last_step_ticks = 0;
  }

  void reset() {
    g.should_assist = g.in_gameplay = false;
    g.object_radius = g.assist_radius = g.max_offset = 0;
    g.current_target_time = 0;
    g.tap_engagement = g.stream_factor = 0;
    g.resync_blend = 0;
  }

  bool needs_resync() {
    return g.mouse_offset.length_sq() > 0.0001f;
  }

  void set_target(vec2 sp, float rad, double st, float scale) {
    if (st != g.current_target_time) {
      float td = (float)(st - g.current_target_time);
      float sd = (sp - g.target_pos).length();
      float msd = g.object_radius * config::stream_distance_mult;
      if (td > 0 && td < config::stream_time_threshold && sd < msd)
        g.stream_factor = nc_fminf(1 - td / config::stream_time_threshold, 1 - sd / msd);
      else
        g.stream_factor = 0;
      g.current_target_time = st;
      g.tap_engagement = 0;
    }
    g.target_pos = sp;
    g.object_radius = rad * scale;
    g.max_offset = config::max_offset * scale;
    g.assist_radius = g.object_radius + g.max_offset;
  }

  bool check_range(vec2 c) {
    vec2 tt = g.target_pos - (c + g.mouse_offset);
    float d = tt.length();
    bool in = d < g.assist_radius;
    if (!config::enable_anti_tug) {
      g.tap_engagement = 0;
      return in;
    }
    if (d < g.object_radius)
      g.tap_engagement = nc_fminf(1, g.tap_engagement + 0.30f);
    return in;
  }

  vec2 process(vec2 raw) {
    if (!imports::pQueryPerformanceCounter)
      return raw;

    LARGE_INTEGER now;
    imports::pQueryPerformanceCounter(&now);

    if (!g.qpc_freq_ticks) {
      LARGE_INTEGER f;
      imports::pQueryPerformanceFrequency(&f);
      g.qpc_freq_ticks = f.QuadPart;
    }

    float dt = 0.001f;
    if (g.last_step_ticks && g.qpc_freq_ticks > 0)
      dt = (float)((double)(now.QuadPart - g.last_step_ticks) / (double)g.qpc_freq_ticks);
    g.last_step_ticks = now.QuadPart;
    if (dt < 0.0001f)
      dt = 0.0001f;
    if (dt > 0.050f)
      dt = 0.050f;

    if (g.should_assist) {
      g.resync_blend = 0;
      vec2 tt = g.target_pos - (raw + g.mouse_offset);
      float dist = tt.length();

      // fade the pull near the center of the circle
      float t = (K_DZ_OUTER > K_DZ_INNER)
                    ? smoothstep((dist - g.object_radius * K_DZ_INNER) /
                                 (g.object_radius * (K_DZ_OUTER - K_DZ_INNER)))
                    : 1.0f;
      g.current_decay = config::deadzone_decay + t * (1 - config::deadzone_decay);

      vec2 disp = raw - g.prev_mouse_pos;
      tt = g.target_pos - raw - g.mouse_offset;
      dist = tt.length();

      if (dist > 0.0001f) {
        float spd =
            saturate(disp.length(), g.max_offset) * g.current_decay * config::assist_strength;

        if (config::enable_anti_tug && g.tap_engagement > 0)
          spd *= 1 - 0.85f * g.tap_engagement;

        if (g.stream_factor > 0) {
          float c = spd * config::stream_velocity_cap;
          spd = c + (spd - c) * (1 - g.stream_factor);
        }

        step_noise(g.angle_noise_assist, g.stream_factor, dt);
        step_ou(g.speed_noise, K_SPEED_TAU, K_SPEED_SIGMA, g.stream_factor, dt);
        step_ou(g.hesitation, K_HESIT_TAU, K_HESIT_SIGMA, g.stream_factor, dt);
        spd *= (1.0f + g.speed_noise) * (1.0f - nc_fabsf(g.hesitation));
        if (spd < 0)
          spd = 0;

        g.mouse_offset = g.mouse_offset + rotate(tt.normalized(), g.angle_noise_assist) * spd;
        float len = g.mouse_offset.length();
        if (len > g.max_offset)
          g.mouse_offset = g.mouse_offset.normalized() * g.max_offset;
      }
    } else if (!g.in_gameplay) {
      // ease out the remaining offset after gameplay ends
      float decay = nc_expf(-K_EXIT_DECAY * dt);
      g.mouse_offset = g.mouse_offset * decay;

      if (!needs_resync())
        g.mouse_offset = {};
    } else {
      // ease the offset back to zero outside the assist range
      float blend_rate = 8.0f + g_rng.gauss() * 1.2f;
      if (blend_rate < 4.0f)
        blend_rate = 4.0f;
      g.resync_blend = nc_fminf(1.0f, g.resync_blend + blend_rate * dt);
      float len = g.mouse_offset.length();

      if (len > 0.0001f) {
        vec2 disp = raw - g.prev_mouse_pos;
        float spd = nc_fminf(len, saturate(disp.length(), g.max_offset) * config::resync_speed);
        if (disp.dot(g.mouse_offset) >= 0)
          spd *= config::power;

        step_noise(g.angle_noise_resync, g.stream_factor, dt);
        step_ou(g.speed_noise, K_SPEED_TAU, K_SPEED_SIGMA, g.stream_factor, dt);
        spd *= (1.0f + g.speed_noise) * smoothstep(g.resync_blend);
        if (spd < 0)
          spd = 0;

        g.mouse_offset =
            g.mouse_offset - rotate(g.mouse_offset.normalized(), g.angle_noise_resync) * spd;
      }
    }

    // dampen sudden direction changes in the final cursor movement
    if (g.in_gameplay) {
      vec2 cur_output = raw + g.mouse_offset;
      vec2 prev_output = g.prev_mouse_pos + g.prev_offset_delta;
      vec2 cur_vel = cur_output - prev_output;
      vec2 prev_vel = g.prev_output_vel;
      float cv_len = cur_vel.length();
      float pv_len = prev_vel.length();

      if (cv_len > 1.0f && pv_len > 1.0f) {
        float cos_a = cur_vel.dot(prev_vel) / (cv_len * pv_len);
        if (cos_a < -0.342f) {
          float scale = 1.0f - 0.9f * smoothstep((-0.342f - cos_a) / 0.658f);
          vec2 offset_change = g.mouse_offset - g.prev_offset_delta;
          g.mouse_offset = g.prev_offset_delta + offset_change * scale;
        }
      }

      g.prev_output_vel = (raw + g.mouse_offset) - prev_output;
      g.prev_offset_delta = g.mouse_offset;
    } else {
      g.prev_output_vel = {};
      g.prev_offset_delta = g.mouse_offset;
    }

    g.prev_mouse_pos = raw;
    g.should_assist = false;
    return raw + g.mouse_offset;
  }

}  // namespace aa
