#pragma once
#ifndef __UDP_SERVER_H__
#define __UDP_SERVER_H__

#include <esp_err.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <lwip/sockets.h>

#ifdef __cplusplus
extern "C"
{
#endif

  typedef struct
  {
    uint8_t data[1024];
    size_t length;

    struct sockaddr_storage source_addr;
    int _sock;
  } udp_message_t;

  struct udp_server_t
  {
    uint16_t port;
    QueueHandle_t udp_server_queue;
  };

  typedef struct udp_server_t udp_server_t;

  typedef struct udp_server_t *udp_server_handle_t;

  esp_err_t udp_server_init(uint16_t port, udp_server_handle_t *udp_server_handle);
  esp_err_t udp_server_start(udp_server_handle_t udp_server_handle);
  esp_err_t udp_server_recv(udp_server_handle_t udp_server_handle, udp_message_t *message);
  esp_err_t udp_server_send(udp_server_handle_t udp_server_handle, udp_message_t *message);

#ifdef __cplusplus
}
#endif

#endif // __UDP_SERVER_H__
