// Host stand-in for ESP-IDF's esp_err.h, for the native tests only.
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int esp_err_t;

#define ESP_OK               0
#define ESP_FAIL             -1
#define ESP_ERR_INVALID_ARG  0x102
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_NOT_FOUND    0x105

// newlib (ESP-IDF's libc) declares itoa() in stdlib.h; the host libc does not.
inline char *itoa(int value, char *str, int base)
{
  (void)base;
  sprintf(str, "%d", value);
  return str;
}

#define ESP_ERROR_CHECK(x)                                                                                             \
  do                                                                                                                   \
  {                                                                                                                    \
    esp_err_t err_rc_ = (x);                                                                                           \
    if (err_rc_ != ESP_OK)                                                                                             \
    {                                                                                                                  \
      fprintf(stderr, "ESP_ERROR_CHECK failed: 0x%x at %s:%d\n", err_rc_, __FILE__, __LINE__);                         \
      abort();                                                                                                         \
    }                                                                                                                  \
  } while (0)
