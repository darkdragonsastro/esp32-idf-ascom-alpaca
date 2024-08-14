#pragma once
#ifndef __ALPACA_SERVER_DISCOVERY_H__
#define __ALPACA_SERVER_DISCOVERY_H__

#include <esp_err.h>

#ifdef __cplusplus
extern "C"
{
#endif

  esp_err_t alpaca_server_discovery_start(uint16_t http_server_port);

#ifdef __cplusplus
}
#endif

#endif // __ALPACA_SERVER_DISCOVERY_H__
