#include "alpaca_server/udp_server.h"

#include <string.h>

#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <sys/param.h>

#include <lwip/err.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>

static const char *TAG = "udp_server";

static void udp_server_task(void *pvParameters)
{
  udp_server_handle_t udp_server_handle = (udp_server_handle_t)pvParameters;

  char rx_buffer[1024];
  char addr_str[128];
  int addr_family = AF_INET;
  int ip_protocol = 0;
#ifdef CONFIG_LWIP_IPV6
  struct sockaddr_in6 dest_addr;
#else
  struct sockaddr_in dest_addr;
#endif
  while (true)
  {
    struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *)&dest_addr;
    dest_addr_ip4->sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr_ip4->sin_family = AF_INET;
    dest_addr_ip4->sin_port = htons(udp_server_handle->port);
    ip_protocol = IPPROTO_IP;

    int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
    if (sock < 0)
    {
      ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
      break;
    }
    ESP_LOGD(TAG, "Socket created");

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000; // 10ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

    int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0)
    {
      ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
    }
    ESP_LOGD(TAG, "Socket bound, port %d", udp_server_handle->port);

    struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
    socklen_t socklen = sizeof(source_addr);

    while (true)
    {
      ESP_LOGD(TAG, "Waiting for data");

      int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);

      // Error occurred during receiving
      if (len < 0)
      {
        ESP_LOGD(TAG, "recvfrom failed: errno %d", errno);
        break;
      }
      // Data received
      else
      {
        // Get the sender's ip address as string
        if (source_addr.ss_family == PF_INET)
        {
          inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
        }
#ifdef CONFIG_LWIP_IPV6
        else if (source_addr.ss_family == PF_INET6)
        {
          inet6_ntoa_r(((struct sockaddr_in6 *)&source_addr)->sin6_addr, addr_str, sizeof(addr_str) - 1);
        }
#endif
        // create a udp message and add it to the server's queue

        udp_message_t message;

        memset(message.data, 0, sizeof(message.data));

        memcpy(message.data, rx_buffer, len);
        message.length = len;
        memcpy(&message.source_addr, &source_addr, sizeof(source_addr));
        message._sock = sock;

        BaseType_t res = xQueueSend(udp_server_handle->udp_server_queue, &message, pdMS_TO_TICKS(10));

        if (res != pdTRUE)
        {
          ESP_LOGE(TAG, "Failed to send message to queue");
        }
      }

      vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (sock != -1)
    {
      ESP_LOGD(TAG, "Shutting down socket and restarting...");
      shutdown(sock, 0);
      close(sock);
    }
  }
  vTaskDelete(NULL);
}

esp_err_t udp_server_init(uint16_t port, udp_server_handle_t *udp_server_handle)
{
  *udp_server_handle = (udp_server_handle_t)malloc(sizeof(udp_server_t));
  if (*udp_server_handle == NULL)
  {
    ESP_LOGE(TAG, "Failed to allocate memory for udp_server_handle");
    return ESP_ERR_NO_MEM;
  }

  (*udp_server_handle)->port = port;
  (*udp_server_handle)->udp_server_queue = xQueueCreate(10, sizeof(udp_message_t));
  if ((*udp_server_handle)->udp_server_queue == NULL)
  {
    ESP_LOGE(TAG, "Failed to create queue for udp_server_handle");
    free(*udp_server_handle);
    return ESP_ERR_NO_MEM;
  }

  return ESP_OK;
}

esp_err_t udp_server_start(udp_server_handle_t udp_server_handle)
{
  xTaskCreatePinnedToCore(udp_server_task, "udp_server_task", 8192, udp_server_handle, 5, NULL, 1);
  return ESP_OK;
}

esp_err_t udp_server_recv(udp_server_handle_t udp_server_handle, udp_message_t *message)
{
  BaseType_t res = xQueueReceive(udp_server_handle->udp_server_queue, message, portMAX_DELAY);
  if (res != pdTRUE)
  {
    ESP_LOGD(TAG, "Failed to receive message from queue");
    return ESP_ERR_TIMEOUT;
  }

  return ESP_OK;
}

esp_err_t udp_server_send(udp_server_handle_t udp_server_handle, udp_message_t *message)
{
  int err = sendto(
      message->_sock,
      message->data,
      message->length,
      0,
      (struct sockaddr *)&message->source_addr,
      sizeof(message->source_addr)
  );
  if (err < 0)
  {
    ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
    return ESP_FAIL;
  }

  return ESP_OK;
}
