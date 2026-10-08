// Host stand-in for ESP-IDF's esp_log.h, for the native tests only. Log
// macros do nothing; the log level is a variable the tests can change.
#pragma once

typedef enum
{
  ESP_LOG_NONE,
  ESP_LOG_ERROR,
  ESP_LOG_WARN,
  ESP_LOG_INFO,
  ESP_LOG_DEBUG,
  ESP_LOG_VERBOSE,
} esp_log_level_t;

extern esp_log_level_t fake_log_level;

inline esp_log_level_t esp_log_level_get(const char *tag)
{
  (void)tag;
  return fake_log_level;
}

#define ESP_LOGE(tag, format, ...) ((void)0)
#define ESP_LOGW(tag, format, ...) ((void)0)
#define ESP_LOGI(tag, format, ...) ((void)0)
#define ESP_LOGD(tag, format, ...) ((void)0)
