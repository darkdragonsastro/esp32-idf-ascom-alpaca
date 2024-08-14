#include "alpaca_server/discovery.h"

#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

#include <alpaca_server/udp_server.h>

static const char *TAG = "alpaca_server_discovery";

typedef struct
{
  udp_server_handle_t udp_server_handle;
  uint16_t http_server_port;
} discovery_task_args_t;

void discovery_task(void *pvParameters)
{
  discovery_task_args_t *config = (discovery_task_args_t *)pvParameters;
  udp_message_t message;

  char response[128];
  sprintf(response, "{\"AlpacaPort\":%d}", config->http_server_port);

  size_t response_len = strlen(response);

  while (true)
  {
    esp_err_t err = udp_server_recv(config->udp_server_handle, &message);

    if (err == ESP_OK)
    {
      char addr_str[128];
      inet_ntoa_r(((struct sockaddr_in *)&message.source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);

      // If the data received == alpacadiscovery1 then send the response back
      if (strncmp((char *)message.data, "alpacadiscovery1", message.length) == 0)
      {
        ESP_LOGI(TAG, "Sending response back to %s", addr_str);
        memset(&message.data, 0, sizeof(message.data));

        strcpy((char *)message.data, response);
        message.length = response_len;

        udp_server_send(config->udp_server_handle, &message);
      }
    }
  }

  vTaskDelete(NULL);
  free(config);
}

esp_err_t alpaca_server_discovery_start(uint16_t http_server_port)
{
  udp_server_handle_t udp_server_handle;

  udp_server_init(32227, &udp_server_handle);

  udp_server_start(udp_server_handle);

  discovery_task_args_t *config = malloc(sizeof(discovery_task_args_t));
  config->udp_server_handle = udp_server_handle;
  config->http_server_port = http_server_port;

  xTaskCreatePinnedToCore(discovery_task, "discovery_task", 8192, config, 5, NULL, 1);

  return ESP_OK;
}
