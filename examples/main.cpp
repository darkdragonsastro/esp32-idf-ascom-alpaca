#include "sdkconfig.h"

#include <alpaca_server/api.h>
#include <alpaca_server/device.h>
#include <alpaca_server/discovery.h>

#include <esp_app_desc.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_ota_ops.h>

#include "roll_off_roof.h"

static const char *TAG = "main";

extern "C" void app_main(void)
{
  esp_log_level_set("alpaca_server_api", ESP_LOG_INFO);

  esp_app_desc_t desc;
  ESP_ERROR_CHECK(esp_ota_get_partition_description(esp_ota_get_running_partition(), &desc));

  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  httpd_handle_t esp_http_server;
  ESP_ERROR_CHECK(httpd_start(&esp_http_server, &config));

  std::vector<AlpacaServer::Device *> devices = {
    new RollOffRoof(),
  };

  AlpacaServer::Api api(
      devices,
      "MY_DEVICE_SERIAL_NUMBER",
      "Dark Dragons Alpaca Server",
      "Dark Dragons Astronomy LLC",
      desc.version,
      "Home"
  );
  api.register_routes(esp_http_server);

  ESP_LOGI(TAG, "Starting Discovery server");
  alpaca_server_discovery_start(80);

  while (true)
  {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
