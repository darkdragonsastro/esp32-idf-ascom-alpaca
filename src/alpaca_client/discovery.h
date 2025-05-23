#pragma once
#ifndef __ALPACA_CLIENT_DISCOVERY_H__
#define __ALPACA_CLIENT_DISCOVERY_H__

#include <stdio.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <lwip/sockets.h>
#include <lwip/netdb.h>

#include <cJSON.h>
#include <esp_log.h>

#include "alpaca_client/discovery.h"

static const char *TAG = "alpaca_client_discovery";

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
        ESP_LOGI(TAG, "Alpaca Port: %d", port);
        // TODO: Store the discovered port and IP address for later use.  A linked list or other data structure would be appropriate.
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

#endif // __ALPACA_CLIENT_DISCOVERY_H__
