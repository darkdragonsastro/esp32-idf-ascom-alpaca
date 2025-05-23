#pragma once
#ifndef __ALPACA_CLIENT_DISCOVERY_H__
#define __ALPACA_CLIENT_DISCOVERY_H__

#include <stdio.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

#include <lwip/sockets.h>
#include <lwip/netdb.h>

#include <cJSON.h>
#include <esp_log.h>
#include <esp_err.h>

typedef struct discovered_device_t discovered_device_t;

esp_err_t alpaca_discover();
esp_err_t alpaca_discovery_init();
esp_err_t alpaca_get_discovered_devices(discovered_device_t **devices, size_t *count);
void alpaca_free_discovered_devices(discovered_device_t *devices);
void alpaca_discovery_cleanup();

#endif // __ALPACA_CLIENT_DISCOVERY_H__
