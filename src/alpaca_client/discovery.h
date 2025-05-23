#pragma once
#ifndef __ALPACA_CLIENT_DISCOVERY_H__
#define __ALPACA_CLIENT_DISCOVERY_H__

#include <stdio.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <lwip/sockets.h>
#include <lwip/netdb.h>

#include "alpaca_client/discovery.h"

#include <stdio.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <lwip/sockets.h>
#include <lwip/netdb.h>

#include <cJSON.h>
#include <esp_log.h>

static const char *TAG = "alpaca_client_discovery";

typedef struct discovered_device_t {
    char ip_address[16]; // e.g., "192.168.1.100"
    int port;
    struct discovered_device_t *next;
} discovered_device_t;

static discovered_device_t *discovered_devices_head = NULL;
static SemaphoreHandle_t discovered_devices_mutex;

static void add_discovered_device(const char *ip_address, int port) {
    discovered_device_t *new_device = (discovered_device_t *)malloc(sizeof(discovered_device_t));
    if (new_device == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for discovered device");
        return;
    }
    strncpy(new_device->ip_address, ip_address, sizeof(new_device->ip_address) - 1);
    new_device->ip_address[sizeof(new_device->ip_address) - 1] = '\0'; // Ensure null termination
    new_device->port = port;
    new_device->next = NULL;

    // Protect access to the linked list
    if (xSemaphoreTake(discovered_devices_mutex, portMAX_DELAY) == pdTRUE) {
        if (discovered_devices_head == NULL) {
            discovered_devices_head = new_device;
        } else {
            discovered_device_t *current = discovered_devices_head;
            while (current->next != NULL) {
                current = current->next;
            }
            current->next = new_device;
        }
        xSemaphoreGive(discovered_devices_mutex);
    } else {
        ESP_LOGE(TAG, "Failed to acquire mutex");
        free(new_device); // Free the allocated memory if mutex acquisition fails
    }
}


esp_err_t alpaca_discover()
{
  int sock = 0;
  struct sockaddr_in dest_addr;
  struct sockaddr_in source_addr;
  socklen_t socklen = sizeof(source_addr);
  char rx_buffer[128];
  int addr_family = AF_INET;
  int ip_protocol = IPPROTO_UDP;

  dest_addr.sin_addr.s_addr = inet_addr("255.255.255.255"); // Broadcast address
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(32227);

  sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
  if (sock < 0)
  {
    ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
    return ESP_FAIL;
  }
  ESP_LOGI(TAG, "Socket created, sending to %s:%d", inet_ntoa(dest_addr.sin_addr), 32227);

  // Set socket options for broadcast
  int broadcastEnable = 1;
  int ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
  if (ret == -1)
  {
    ESP_LOGE(TAG, "Unable to set socket options SO_BROADCAST: errno %d", errno);
    close(sock);
    return ESP_FAIL;
  }

  const char *message = "alpacadiscovery1";
  int err = sendto(sock, message, strlen(message), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (err < 0)
  {
    ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
    close(sock);
    return ESP_FAIL;
  }
  ESP_LOGI(TAG, "Message sent");

  // Set timeout for receiving data
  struct timeval tv;
  tv.tv_sec = 5; // Set a 5-second timeout
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  while (true)
  {
    ESP_LOGI(TAG, "Waiting for data");
    int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);

    // Error occurred during receiving
    if (len < 0)
    {
      ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
      break;
    }
    // Data received
    else
    {
      rx_buffer[len] = 0; // Null-terminate whatever we received and treat like a string
      ESP_LOGI(TAG, "Received %d bytes from %s:%d", len, inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port));
      ESP_LOGI(TAG, "Data: %s", rx_buffer);

      // Parse JSON
      cJSON *json = cJSON_Parse(rx_buffer);
      if (json == NULL)
      {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
          ESP_LOGE(TAG, "Error before: %s", error_ptr);
        }
        cJSON_Delete(json);
        continue; // Continue to the next received packet
      }

      cJSON *alpaca_port = cJSON_GetObjectItem(json, "AlpacaPort");
      if (cJSON_IsNumber(alpaca_port))
      {
        int port = alpaca_port->valueint;
        const char *ip_address = inet_ntoa(source_addr.sin_addr);
        ESP_LOGI(TAG, "Alpaca Port: %d, IP Address: %s", port, ip_address);
        add_discovered_device(ip_address, port);
      }
      else
      {
        ESP_LOGW(TAG, "AlpacaPort not found or not a number");
      }
      cJSON_Delete(json);
    }
  }

  close(sock);
  return ESP_OK;
}

esp_err_t alpaca_discovery_init() {
    discovered_devices_mutex = xSemaphoreCreateMutex();
    if (discovered_devices_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t alpaca_get_discovered_devices(discovered_device_t **devices, size_t *count) {
    if (devices == NULL || count == NULL) {
        ESP_LOGE(TAG, "Invalid arguments");
        return ESP_ERR_INVALID_ARG;
    }

    *devices = NULL;
    *count = 0;

    if (xSemaphoreTake(discovered_devices_mutex, portMAX_DELAY) == pdTRUE) {
        // Count the number of discovered devices
        discovered_device_t *current = discovered_devices_head;
        while (current != NULL) {
            (*count)++;
            current = current->next;
        }

        if (*count > 0) {
            // Allocate memory for the array of devices
            *devices = (discovered_device_t *)malloc(sizeof(discovered_device_t) * (*count));
            if (*devices == NULL) {
                ESP_LOGE(TAG, "Failed to allocate memory for discovered devices array");
                xSemaphoreGive(discovered_devices_mutex);
                return ESP_FAIL;
            }

            // Copy the discovered devices to the array
            current = discovered_devices_head;
            for (size_t i = 0; i < *count; i++) {
                memcpy(&(*devices)[i], current, sizeof(discovered_device_t));
                current = current->next;
                (*devices)[i].next = NULL; // Ensure next pointer is NULL in the array
            }
        }
        xSemaphoreGive(discovered_devices_mutex);
        return ESP_OK;
    } else {
        ESP_LOGE(TAG, "Failed to acquire mutex");
        return ESP_FAIL;
    }
}

void alpaca_free_discovered_devices(discovered_device_t *devices) {
    if (devices != NULL) {
        free(devices);
    }
}

void alpaca_discovery_cleanup() {
    // Protect access to the linked list
    if (xSemaphoreTake(discovered_devices_mutex, portMAX_DELAY) == pdTRUE) {
        // Free all the devices in the linked list
        discovered_device_t *current = discovered_devices_head;
        while (current != NULL) {
            discovered_device_t *next = current->next;
            free(current);
            current = next;
        }
        discovered_devices_head = NULL; // Reset the head of the list
        xSemaphoreGive(discovered_devices_mutex);
    } else {
        ESP_LOGE(TAG, "Failed to acquire mutex during cleanup");
    }
    vSemaphoreDelete(discovered_devices_mutex);
}
