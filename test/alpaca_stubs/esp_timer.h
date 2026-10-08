// Host stand-in for ESP-IDF's esp_timer.h, for the native tests only.
#pragma once

#include <stdint.h>

extern int64_t fake_now_us;

inline int64_t esp_timer_get_time()
{
  return fake_now_us;
}
