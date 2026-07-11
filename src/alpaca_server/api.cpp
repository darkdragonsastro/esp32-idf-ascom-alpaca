#include "alpaca_server/api.h"

#include <math.h>

#include <esp_log.h>
#include <esp_timer.h>
#include <mbedtls/md5.h>

static const char *TAG = "alpaca_server_api";
static AlpacaServer::custom_error_message_handler_t s_err_msg_func = &AlpacaServer::error_message;

#define REGISTER_DEVICE_ROUTE(device_type, endpoint, device_number, http_method, name)                                 \
  {                                                                                                                    \
    sprintf(uri, "/api/v1/%s/%d/%s", device_type, device_number, endpoint);                                            \
    httpd_uri_t uri_##name = {                                                                                         \
      .uri = uri,                                                                                                      \
      .method = http_method,                                                                                           \
      .handler = handle_##name,                                                                                        \
      .user_ctx = this,                                                                                                \
    };                                                                                                                 \
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_##name));                                                  \
  }

namespace AlpacaServer
{
esp_err_t error_message(uint16_t error_code, char *buf, size_t len)
{
  switch (error_code)
  {
  case ALPACA_ERR_NOT_IMPLEMENTED:
    strncpy(buf, ALPACA_ERR_MESSAGE_NOT_IMPLEMENTED, len);
    break;
  case ALPACA_ERR_INVALID_VALUE:
    strncpy(buf, ALPACA_ERR_MESSAGE_INVALID_VALUE, len);
    break;
  case ALPACA_ERR_VALUE_NOT_SET:
    strncpy(buf, ALPACA_ERR_MESSAGE_VALUE_NOT_SET, len);
    break;
  case ALPACA_ERR_NOT_CONNECTED:
    strncpy(buf, ALPACA_ERR_MESSAGE_NOT_CONNECTED, len);
    break;
  case ALPACA_ERR_INVALID_WHILE_PARKED:
    strncpy(buf, ALPACA_ERR_MESSAGE_INVALID_WHILE_PARKED, len);
    break;
  case ALPACA_ERR_INVALID_WHILE_SLAVED:
    strncpy(buf, ALPACA_ERR_MESSAGE_INVALID_WHILE_SLAVED, len);
    break;
  case ALPACA_ERR_INVALID_OPERATION:
    strncpy(buf, ALPACA_ERR_MESSAGE_INVALID_OPERATION, len);
    break;
  case ALPACA_ERR_ACTION_NOT_IMPLEMENTED:
    strncpy(buf, ALPACA_ERR_MESSAGE_ACTION_NOT_IMPLEMENTED, len);
    break;
  default:
    return ESP_ERR_NOT_FOUND;
  }

  return ESP_OK;
}

custom_error_message_handler_t set_custom_error_message_handler(
    custom_error_message_handler_t custom_error_message_handler
)
{
  AlpacaServer::custom_error_message_handler_t old = s_err_msg_func;
  s_err_msg_func = custom_error_message_handler;
  return old;
}

Api::Api(
    std::vector<Device *> &devices,
    const char *server_id,
    const char *server_name,
    const char *manufacturer,
    const char *manufacturer_version,
    const char *location
)
{
  _server_transaction_id = 0;

  for (auto device : devices)
  {
    _devices[device->device_type()].push_back(device);
  }

  _server_id = strdup(server_id);
  _server_name = strdup(server_name);
  _manufacturer = strdup(manufacturer);
  _manufacturer_version = strdup(manufacturer_version);
  _location = strdup(location);
}

Api::~Api()
{
  free(_server_id);
  free(_server_name);
  free(_manufacturer);
  free(_manufacturer_version);
  free(_location);
}

void Api::set_server_name(const char *server_name)
{
  free(_server_name);
  _server_name = strdup(server_name);
}

void Api::set_location(const char *location)
{
  free(_location);
  _location = strdup(location);
}

void Api::initialize()
{
  for (auto it : _devices)
  {
    for (auto device : it.second)
    {
      char name[33];
      device->get_name(name, sizeof(name));

      esp_err_t err = generate_unique_id(
          _server_id,
          name,
          device->device_type(),
          device->_number,
          device->_unique_id,
          sizeof(device->_unique_id)
      );
      ESP_ERROR_CHECK(err);
    }
  }
}

esp_err_t Api::generate_unique_id(
    const char *server_id,
    const char *device_name,
    DeviceType device_type,
    uint8_t device_number,
    char *unique_id,
    size_t len
)
{
  mbedtls_md5_context ctx;

  char device_type_str[16];
  sprintf(device_type_str, "%d", (int)device_type);

  char device_number_str[16];
  sprintf(device_number_str, "%d", device_number);

  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts(&ctx);
  mbedtls_md5_update(&ctx, (const unsigned char *)server_id, strlen(server_id));
  mbedtls_md5_update(&ctx, (const unsigned char *)device_name, strlen(device_name));
  mbedtls_md5_update(&ctx, (const unsigned char *)device_type_str, strlen(device_type_str));
  mbedtls_md5_update(&ctx, (const unsigned char *)device_number_str, strlen(device_number_str));

  unsigned char hash[16];
  mbedtls_md5_finish(&ctx, hash);
  mbedtls_md5_free(&ctx);

  memset(unique_id, 0, 33);
  for (int i = 0; i < 16; i++)
  {
    sprintf(&unique_id[i * 2], "%02x", (unsigned int)hash[i]);
  }

  return ESP_OK;
}

void Api::register_routes(httpd_handle_t server)
{
  initialize();

  httpd_uri_t uri_get_supported_api_versions = {
    .uri = "/management/apiversions",
    .method = HTTP_GET,
    .handler = handle_get_supported_api_versions,
    .user_ctx = this,
  };
  ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_get_supported_api_versions));

  httpd_uri_t uri_get_server_description = {
    .uri = "/management/v1/description",
    .method = HTTP_GET,
    .handler = handle_get_server_description,
    .user_ctx = this,
  };
  ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_get_server_description));

  httpd_uri_t uri_get_configured_devices = {
    .uri = "/management/v1/configureddevices",
    .method = HTTP_GET,
    .handler = handle_get_configured_devices,
    .user_ctx = this,
  };
  ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_get_configured_devices));

  for (auto it : _devices)
  {
    for (size_t i = 0; i < it.second.size(); i++)
    {
      register_device_routes(server, i, it.second[i]);
    }
  }
}

void Api::register_device_routes(httpd_handle_t server, size_t device_number, Device *device)
{
  char uri[128];
  char device_type_str[32];
  memset(device_type_str, 0, sizeof(device_type_str));

  uri_device_type(device->device_type(), device_type_str, sizeof(device_type_str));

  REGISTER_DEVICE_ROUTE(device_type_str, "action", device_number, HTTP_PUT, put_action);
  REGISTER_DEVICE_ROUTE(device_type_str, "commandblind", device_number, HTTP_PUT, put_commandblind);
  REGISTER_DEVICE_ROUTE(device_type_str, "commandbool", device_number, HTTP_PUT, put_commandbool);
  REGISTER_DEVICE_ROUTE(device_type_str, "commandstring", device_number, HTTP_PUT, put_commandstring);
  REGISTER_DEVICE_ROUTE(device_type_str, "connected", device_number, HTTP_GET, get_connected);
  REGISTER_DEVICE_ROUTE(device_type_str, "connected", device_number, HTTP_PUT, put_connected);
  REGISTER_DEVICE_ROUTE(device_type_str, "description", device_number, HTTP_GET, get_description);
  REGISTER_DEVICE_ROUTE(device_type_str, "driverinfo", device_number, HTTP_GET, get_driverinfo);
  REGISTER_DEVICE_ROUTE(device_type_str, "driverversion", device_number, HTTP_GET, get_driverversion);
  REGISTER_DEVICE_ROUTE(device_type_str, "interfaceversion", device_number, HTTP_GET, get_interfaceversion);
  REGISTER_DEVICE_ROUTE(device_type_str, "name", device_number, HTTP_GET, get_name);
  REGISTER_DEVICE_ROUTE(device_type_str, "supportedactions", device_number, HTTP_GET, get_supportedactions);

  switch (device->device_type())
  {
  case DeviceType::Camera:
    register_camera_routes(server, device_number, (Camera *)device);
    break;
  case DeviceType::CoverCalibrator:
    register_covercalibrator_routes(server, device_number, (CoverCalibrator *)device);
    break;
  case DeviceType::Dome:
    register_dome_routes(server, device_number, (Dome *)device);
    break;
  case DeviceType::FilterWheel:
    register_filterwheel_routes(server, device_number, (FilterWheel *)device);
    break;
  case DeviceType::Focuser:
    register_focuser_routes(server, device_number, (Focuser *)device);
    break;
  case DeviceType::ObservingConditions:
    register_observingconditions_routes(server, device_number, (ObservingConditions *)device);
    break;
  case DeviceType::Rotator:
    register_rotator_routes(server, device_number, (Rotator *)device);
    break;
  case DeviceType::SafetyMonitor:
    register_safetymonitor_routes(server, device_number, (SafetyMonitor *)device);
    break;
  case DeviceType::Switch:
    register_switch_routes(server, device_number, (Switch *)device);
    break;
  case DeviceType::Telescope:
    register_telescope_routes(server, device_number, (Telescope *)device);
    break;
  default:
    break;
  }
}

void Api::register_camera_routes(httpd_handle_t server, size_t device_number, Camera *device)
{
  // TODO: Implement camera routes
}

void Api::register_covercalibrator_routes(httpd_handle_t server, size_t device_number, CoverCalibrator *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("covercalibrator", "brightness", device_number, HTTP_GET, get_covercalibrator_brightness);
  REGISTER_DEVICE_ROUTE(
      "covercalibrator",
      "calibratorstate",
      device_number,
      HTTP_GET,
      get_covercalibrator_calibratorstate
  );
  REGISTER_DEVICE_ROUTE("covercalibrator", "coverstate", device_number, HTTP_GET, get_covercalibrator_coverstate);
  REGISTER_DEVICE_ROUTE("covercalibrator", "maxbrightness", device_number, HTTP_GET, get_covercalibrator_maxbrightness);
  REGISTER_DEVICE_ROUTE("covercalibrator", "calibratoroff", device_number, HTTP_PUT, put_covercalibrator_calibratoroff);
  REGISTER_DEVICE_ROUTE("covercalibrator", "calibratoron", device_number, HTTP_PUT, put_covercalibrator_calibratoron);
  REGISTER_DEVICE_ROUTE("covercalibrator", "closecover", device_number, HTTP_PUT, put_covercalibrator_closecover);
  REGISTER_DEVICE_ROUTE("covercalibrator", "haltcover", device_number, HTTP_PUT, put_covercalibrator_haltcover);
  REGISTER_DEVICE_ROUTE("covercalibrator", "opencover", device_number, HTTP_PUT, put_covercalibrator_opencover);
}

void Api::register_dome_routes(httpd_handle_t server, size_t device_number, Dome *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("dome", "altitude", device_number, HTTP_GET, get_dome_altitude);
  REGISTER_DEVICE_ROUTE("dome", "athome", device_number, HTTP_GET, get_dome_athome);
  REGISTER_DEVICE_ROUTE("dome", "atpark", device_number, HTTP_GET, get_dome_atpark);
  REGISTER_DEVICE_ROUTE("dome", "azimuth", device_number, HTTP_GET, get_dome_azimuth);
  REGISTER_DEVICE_ROUTE("dome", "canfindhome", device_number, HTTP_GET, get_dome_canfindhome);
  REGISTER_DEVICE_ROUTE("dome", "canpark", device_number, HTTP_GET, get_dome_canpark);
  REGISTER_DEVICE_ROUTE("dome", "cansetaltitude", device_number, HTTP_GET, get_dome_cansetaltitude);
  REGISTER_DEVICE_ROUTE("dome", "cansetazimuth", device_number, HTTP_GET, get_dome_cansetazimuth);
  REGISTER_DEVICE_ROUTE("dome", "cansetpark", device_number, HTTP_GET, get_dome_cansetpark);
  REGISTER_DEVICE_ROUTE("dome", "cansetshutter", device_number, HTTP_GET, get_dome_cansetshutter);
  REGISTER_DEVICE_ROUTE("dome", "canslave", device_number, HTTP_GET, get_dome_canslave);
  REGISTER_DEVICE_ROUTE("dome", "cansyncazimuth", device_number, HTTP_GET, get_dome_cansyncazimuth);
  REGISTER_DEVICE_ROUTE("dome", "shutterstatus", device_number, HTTP_GET, get_dome_shutterstatus);
  REGISTER_DEVICE_ROUTE("dome", "slaved", device_number, HTTP_GET, get_dome_slaved);
  REGISTER_DEVICE_ROUTE("dome", "slaved", device_number, HTTP_PUT, put_dome_slaved);
  REGISTER_DEVICE_ROUTE("dome", "slewing", device_number, HTTP_GET, get_dome_slewing);
  REGISTER_DEVICE_ROUTE("dome", "abortslew", device_number, HTTP_PUT, put_dome_abortslew);
  REGISTER_DEVICE_ROUTE("dome", "closeshutter", device_number, HTTP_PUT, put_dome_closeshutter);
  REGISTER_DEVICE_ROUTE("dome", "findhome", device_number, HTTP_PUT, put_dome_findhome);
  REGISTER_DEVICE_ROUTE("dome", "openshutter", device_number, HTTP_PUT, put_dome_openshutter);
  REGISTER_DEVICE_ROUTE("dome", "park", device_number, HTTP_PUT, put_dome_park);
  REGISTER_DEVICE_ROUTE("dome", "setpark", device_number, HTTP_PUT, put_dome_setpark);
  REGISTER_DEVICE_ROUTE("dome", "slewtoaltitude", device_number, HTTP_PUT, put_dome_slewtoaltitude);
  REGISTER_DEVICE_ROUTE("dome", "slewtoazimuth", device_number, HTTP_PUT, put_dome_slewtoazimuth);
  REGISTER_DEVICE_ROUTE("dome", "synctoazimuth", device_number, HTTP_PUT, put_dome_synctoazimuth);
}

void Api::register_filterwheel_routes(httpd_handle_t server, size_t device_number, FilterWheel *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("filterwheel", "focusoffsets", device_number, HTTP_GET, get_filterwheel_focusoffsets);
  REGISTER_DEVICE_ROUTE("filterwheel", "names", device_number, HTTP_GET, get_filterwheel_names);
  REGISTER_DEVICE_ROUTE("filterwheel", "position", device_number, HTTP_GET, get_filterwheel_position);
  REGISTER_DEVICE_ROUTE("filterwheel", "position", device_number, HTTP_PUT, put_filterwheel_position);
}

void Api::register_focuser_routes(httpd_handle_t server, size_t device_number, Focuser *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("focuser", "absolute", device_number, HTTP_GET, get_focuser_absolute);
  REGISTER_DEVICE_ROUTE("focuser", "ismoving", device_number, HTTP_GET, get_focuser_ismoving);
  REGISTER_DEVICE_ROUTE("focuser", "maxincrement", device_number, HTTP_GET, get_focuser_maxincrement);
  REGISTER_DEVICE_ROUTE("focuser", "maxstep", device_number, HTTP_GET, get_focuser_maxstep);
  REGISTER_DEVICE_ROUTE("focuser", "position", device_number, HTTP_GET, get_focuser_position);
  REGISTER_DEVICE_ROUTE("focuser", "stepsize", device_number, HTTP_GET, get_focuser_stepsize);
  REGISTER_DEVICE_ROUTE("focuser", "tempcomp", device_number, HTTP_GET, get_focuser_tempcomp);
  REGISTER_DEVICE_ROUTE("focuser", "tempcomp", device_number, HTTP_PUT, put_focuser_tempcomp);
  REGISTER_DEVICE_ROUTE("focuser", "tempcompavailable", device_number, HTTP_GET, get_focuser_tempcompavailable);
  REGISTER_DEVICE_ROUTE("focuser", "temperature", device_number, HTTP_GET, get_focuser_temperature);
  REGISTER_DEVICE_ROUTE("focuser", "halt", device_number, HTTP_PUT, put_focuser_halt);
  REGISTER_DEVICE_ROUTE("focuser", "move", device_number, HTTP_PUT, put_focuser_move);
}

void Api::register_observingconditions_routes(httpd_handle_t server, size_t device_number, ObservingConditions *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "averageperiod",
      device_number,
      HTTP_GET,
      get_observingconditions_averageperiod
  );
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "averageperiod",
      device_number,
      HTTP_PUT,
      put_observingconditions_averageperiod
  );
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "cloudcover",
      device_number,
      HTTP_GET,
      get_observingconditions_cloudcover
  );
  REGISTER_DEVICE_ROUTE("observingconditions", "dewpoint", device_number, HTTP_GET, get_observingconditions_dewpoint);
  REGISTER_DEVICE_ROUTE("observingconditions", "humidity", device_number, HTTP_GET, get_observingconditions_humidity);
  REGISTER_DEVICE_ROUTE("observingconditions", "pressure", device_number, HTTP_GET, get_observingconditions_pressure);
  REGISTER_DEVICE_ROUTE("observingconditions", "rainrate", device_number, HTTP_GET, get_observingconditions_rainrate);
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "skybrightness",
      device_number,
      HTTP_GET,
      get_observingconditions_skybrightness
  );
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "skyquality",
      device_number,
      HTTP_GET,
      get_observingconditions_skyquality
  );
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "skytemperature",
      device_number,
      HTTP_GET,
      get_observingconditions_skytemperature
  );
  REGISTER_DEVICE_ROUTE("observingconditions", "starfwhm", device_number, HTTP_GET, get_observingconditions_starfwhm);
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "temperature",
      device_number,
      HTTP_GET,
      get_observingconditions_temperature
  );
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "winddirection",
      device_number,
      HTTP_GET,
      get_observingconditions_winddirection
  );
  REGISTER_DEVICE_ROUTE("observingconditions", "windgust", device_number, HTTP_GET, get_observingconditions_windgust);
  REGISTER_DEVICE_ROUTE("observingconditions", "windspeed", device_number, HTTP_GET, get_observingconditions_windspeed);
  REGISTER_DEVICE_ROUTE("observingconditions", "refresh", device_number, HTTP_PUT, put_observingconditions_refresh);
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "sensordescription",
      device_number,
      HTTP_GET,
      get_observingconditions_sensordescription
  );
  REGISTER_DEVICE_ROUTE(
      "observingconditions",
      "timesincelastupdate",
      device_number,
      HTTP_GET,
      get_observingconditions_timesincelastupdate
  );
}

void Api::register_rotator_routes(httpd_handle_t server, size_t device_number, Rotator *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("rotator", "canreverse", device_number, HTTP_GET, get_rotator_canreverse);
  REGISTER_DEVICE_ROUTE("rotator", "ismoving", device_number, HTTP_GET, get_rotator_ismoving);
  REGISTER_DEVICE_ROUTE("rotator", "mechanicalposition", device_number, HTTP_GET, get_rotator_mechanicalposition);
  REGISTER_DEVICE_ROUTE("rotator", "position", device_number, HTTP_GET, get_rotator_position);
  REGISTER_DEVICE_ROUTE("rotator", "reverse", device_number, HTTP_GET, get_rotator_reverse);
  REGISTER_DEVICE_ROUTE("rotator", "reverse", device_number, HTTP_PUT, put_rotator_reverse);
  REGISTER_DEVICE_ROUTE("rotator", "stepsize", device_number, HTTP_GET, get_rotator_stepsize);
  REGISTER_DEVICE_ROUTE("rotator", "targetposition", device_number, HTTP_GET, get_rotator_targetposition);
  REGISTER_DEVICE_ROUTE("rotator", "halt", device_number, HTTP_PUT, put_rotator_halt);
  REGISTER_DEVICE_ROUTE("rotator", "move", device_number, HTTP_PUT, put_rotator_move);
  REGISTER_DEVICE_ROUTE("rotator", "moveabsolute", device_number, HTTP_PUT, put_rotator_moveabsolute);
  REGISTER_DEVICE_ROUTE("rotator", "movemechanical", device_number, HTTP_PUT, put_rotator_movemechanical);
  REGISTER_DEVICE_ROUTE("rotator", "sync", device_number, HTTP_PUT, put_rotator_sync);
}

void Api::register_safetymonitor_routes(httpd_handle_t server, size_t device_number, SafetyMonitor *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("safetymonitor", "issafe", device_number, HTTP_GET, get_safetymonitor_issafe);
}

void Api::register_switch_routes(httpd_handle_t server, size_t device_number, Switch *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("switch", "maxswitch", device_number, HTTP_GET, get_switch_maxswitch);
  REGISTER_DEVICE_ROUTE("switch", "canwrite", device_number, HTTP_GET, get_switch_canwrite);
  REGISTER_DEVICE_ROUTE("switch", "getswitch", device_number, HTTP_GET, get_switch_getswitch);
  REGISTER_DEVICE_ROUTE("switch", "getswitchdescription", device_number, HTTP_GET, get_switch_getswitchdescription);
  REGISTER_DEVICE_ROUTE("switch", "getswitchname", device_number, HTTP_GET, get_switch_getswitchname);
  REGISTER_DEVICE_ROUTE("switch", "getswitchvalue", device_number, HTTP_GET, get_switch_getswitchvalue);
  REGISTER_DEVICE_ROUTE("switch", "minswitchvalue", device_number, HTTP_GET, get_switch_minswitchvalue);
  REGISTER_DEVICE_ROUTE("switch", "maxswitchvalue", device_number, HTTP_GET, get_switch_maxswitchvalue);
  REGISTER_DEVICE_ROUTE("switch", "setswitch", device_number, HTTP_PUT, put_switch_setswitch);
  REGISTER_DEVICE_ROUTE("switch", "setswitchname", device_number, HTTP_PUT, put_switch_setswitchname);
  REGISTER_DEVICE_ROUTE("switch", "setswitchvalue", device_number, HTTP_PUT, put_switch_setswitchvalue);
  REGISTER_DEVICE_ROUTE("switch", "switchstep", device_number, HTTP_GET, get_switch_switchstep);
}

void Api::register_telescope_routes(httpd_handle_t server, size_t device_number, Telescope *device)
{
  char uri[128];

  REGISTER_DEVICE_ROUTE("telescope", "alignmentmode", device_number, HTTP_GET, get_telescope_alignmentmode);
  REGISTER_DEVICE_ROUTE("telescope", "altitude", device_number, HTTP_GET, get_telescope_altitude);
  REGISTER_DEVICE_ROUTE("telescope", "aperturearea", device_number, HTTP_GET, get_telescope_aperturearea);
  REGISTER_DEVICE_ROUTE("telescope", "aperturediameter", device_number, HTTP_GET, get_telescope_aperturediameter);
  REGISTER_DEVICE_ROUTE("telescope", "athome", device_number, HTTP_GET, get_telescope_athome);
  REGISTER_DEVICE_ROUTE("telescope", "atpark", device_number, HTTP_GET, get_telescope_atpark);
  REGISTER_DEVICE_ROUTE("telescope", "axisrates", device_number, HTTP_GET, get_telescope_axisrates);
  REGISTER_DEVICE_ROUTE("telescope", "azimuth", device_number, HTTP_GET, get_telescope_azimuth);
  REGISTER_DEVICE_ROUTE("telescope", "canfindhome", device_number, HTTP_GET, get_telescope_canfindhome);
  REGISTER_DEVICE_ROUTE("telescope", "canmoveaxis", device_number, HTTP_GET, get_telescope_canmoveaxis);
  REGISTER_DEVICE_ROUTE("telescope", "canpark", device_number, HTTP_GET, get_telescope_canpark);
  REGISTER_DEVICE_ROUTE("telescope", "canpulseguide", device_number, HTTP_GET, get_telescope_canpulseguide);
  REGISTER_DEVICE_ROUTE("telescope", "cansetdeclinationrate", device_number, HTTP_GET, get_telescope_cansetdeclinationrate);
  REGISTER_DEVICE_ROUTE("telescope", "cansetguiderates", device_number, HTTP_GET, get_telescope_cansetguiderates);
  REGISTER_DEVICE_ROUTE("telescope", "cansetpark", device_number, HTTP_GET, get_telescope_cansetpark);
  REGISTER_DEVICE_ROUTE("telescope", "cansetpierside", device_number, HTTP_GET, get_telescope_cansetpierside);
  REGISTER_DEVICE_ROUTE("telescope", "cansetrightascensionrate", device_number, HTTP_GET, get_telescope_cansetrightascensionrate);
  REGISTER_DEVICE_ROUTE("telescope", "cansettracking", device_number, HTTP_GET, get_telescope_cansettracking);
  REGISTER_DEVICE_ROUTE("telescope", "canslew", device_number, HTTP_GET, get_telescope_canslew);
  REGISTER_DEVICE_ROUTE("telescope", "canslewaltaz", device_number, HTTP_GET, get_telescope_canslewaltaz);
  REGISTER_DEVICE_ROUTE("telescope", "canslewaltazasync", device_number, HTTP_GET, get_telescope_canslewaltazasync);
  REGISTER_DEVICE_ROUTE("telescope", "canslewasync", device_number, HTTP_GET, get_telescope_canslewasync);
  REGISTER_DEVICE_ROUTE("telescope", "cansync", device_number, HTTP_GET, get_telescope_cansync);
  REGISTER_DEVICE_ROUTE("telescope", "cansyncaltaz", device_number, HTTP_GET, get_telescope_cansyncaltaz);
  REGISTER_DEVICE_ROUTE("telescope", "canunpark", device_number, HTTP_GET, get_telescope_canunpark);
  REGISTER_DEVICE_ROUTE("telescope", "declination", device_number, HTTP_GET, get_telescope_declination);
  REGISTER_DEVICE_ROUTE("telescope", "declinationrate", device_number, HTTP_GET, get_telescope_declinationrate);
  REGISTER_DEVICE_ROUTE("telescope", "destinationsideofpier", device_number, HTTP_GET, get_telescope_destinationsideofpier);
  REGISTER_DEVICE_ROUTE("telescope", "doesrefraction", device_number, HTTP_GET, get_telescope_doesrefraction);
  REGISTER_DEVICE_ROUTE("telescope", "equatorialsystem", device_number, HTTP_GET, get_telescope_equatorialsystem);
  REGISTER_DEVICE_ROUTE("telescope", "focallength", device_number, HTTP_GET, get_telescope_focallength);
  REGISTER_DEVICE_ROUTE("telescope", "guideratedeclination", device_number, HTTP_GET, get_telescope_guideratedeclination);
  REGISTER_DEVICE_ROUTE("telescope", "guideraterightascension", device_number, HTTP_GET, get_telescope_guideraterightascension);
  REGISTER_DEVICE_ROUTE("telescope", "ispulseguiding", device_number, HTTP_GET, get_telescope_ispulseguiding);
  REGISTER_DEVICE_ROUTE("telescope", "rightascension", device_number, HTTP_GET, get_telescope_rightascension);
  REGISTER_DEVICE_ROUTE("telescope", "rightascensionrate", device_number, HTTP_GET, get_telescope_rightascensionrate);
  REGISTER_DEVICE_ROUTE("telescope", "sideofpier", device_number, HTTP_GET, get_telescope_sideofpier);
  REGISTER_DEVICE_ROUTE("telescope", "siderealtime", device_number, HTTP_GET, get_telescope_siderealtime);
  REGISTER_DEVICE_ROUTE("telescope", "siteelevation", device_number, HTTP_GET, get_telescope_siteelevation);
  REGISTER_DEVICE_ROUTE("telescope", "sitelatitude", device_number, HTTP_GET, get_telescope_sitelatitude);
  REGISTER_DEVICE_ROUTE("telescope", "sitelongitude", device_number, HTTP_GET, get_telescope_sitelongitude);
  REGISTER_DEVICE_ROUTE("telescope", "slewing", device_number, HTTP_GET, get_telescope_slewing);
  REGISTER_DEVICE_ROUTE("telescope", "slewsettletime", device_number, HTTP_GET, get_telescope_slewsettletime);
  REGISTER_DEVICE_ROUTE("telescope", "targetdeclination", device_number, HTTP_GET, get_telescope_targetdeclination);
  REGISTER_DEVICE_ROUTE("telescope", "targetrightascension", device_number, HTTP_GET, get_telescope_targetrightascension);
  REGISTER_DEVICE_ROUTE("telescope", "tracking", device_number, HTTP_GET, get_telescope_tracking);
  REGISTER_DEVICE_ROUTE("telescope", "trackingrate", device_number, HTTP_GET, get_telescope_trackingrate);
  REGISTER_DEVICE_ROUTE("telescope", "trackingrates", device_number, HTTP_GET, get_telescope_trackingrates);
  REGISTER_DEVICE_ROUTE("telescope", "utcdate", device_number, HTTP_GET, get_telescope_utcdate);
  REGISTER_DEVICE_ROUTE("telescope", "abortslew", device_number, HTTP_PUT, put_telescope_abortslew);
  REGISTER_DEVICE_ROUTE("telescope", "declinationrate", device_number, HTTP_PUT, put_telescope_declinationrate);
  REGISTER_DEVICE_ROUTE("telescope", "doesrefraction", device_number, HTTP_PUT, put_telescope_doesrefraction);
  REGISTER_DEVICE_ROUTE("telescope", "findhome", device_number, HTTP_PUT, put_telescope_findhome);
  REGISTER_DEVICE_ROUTE("telescope", "guideratedeclination", device_number, HTTP_PUT, put_telescope_guideratedeclination);
  REGISTER_DEVICE_ROUTE("telescope", "guideraterightascension", device_number, HTTP_PUT, put_telescope_guideraterightascension);
  REGISTER_DEVICE_ROUTE("telescope", "moveaxis", device_number, HTTP_PUT, put_telescope_moveaxis);
  REGISTER_DEVICE_ROUTE("telescope", "park", device_number, HTTP_PUT, put_telescope_park);
  REGISTER_DEVICE_ROUTE("telescope", "pulseguide", device_number, HTTP_PUT, put_telescope_pulseguide);
  REGISTER_DEVICE_ROUTE("telescope", "rightascensionrate", device_number, HTTP_PUT, put_telescope_rightascensionrate);
  REGISTER_DEVICE_ROUTE("telescope", "setpark", device_number, HTTP_PUT, put_telescope_setpark);
  REGISTER_DEVICE_ROUTE("telescope", "sideofpier", device_number, HTTP_PUT, put_telescope_sideofpier);
  REGISTER_DEVICE_ROUTE("telescope", "siteelevation", device_number, HTTP_PUT, put_telescope_siteelevation);
  REGISTER_DEVICE_ROUTE("telescope", "sitelatitude", device_number, HTTP_PUT, put_telescope_sitelatitude);
  REGISTER_DEVICE_ROUTE("telescope", "sitelongitude", device_number, HTTP_PUT, put_telescope_sitelongitude);
  REGISTER_DEVICE_ROUTE("telescope", "slewsettletime", device_number, HTTP_PUT, put_telescope_slewsettletime);
  REGISTER_DEVICE_ROUTE("telescope", "slewtoaltazasync", device_number, HTTP_PUT, put_telescope_slewtoaltazasync);
  REGISTER_DEVICE_ROUTE("telescope", "slewtocoordinatesasync", device_number, HTTP_PUT, put_telescope_slewtocoordinatesasync);
  REGISTER_DEVICE_ROUTE("telescope", "slewtotargetasync", device_number, HTTP_PUT, put_telescope_slewtotargetasync);
  // Alias: INDI's alpaca bridge (indi_alpaca_telescope) slews via the synchronous
  // endpoint name then polls /slewing — i.e. async semantics under the sync name.
  // Blocking a httpd worker for a full slew is not viable on-device, so serve the
  // async handler here. NOTE: nonconformant when CanSlew=false; revisit at ConformU gate.
  REGISTER_DEVICE_ROUTE("telescope", "slewtotarget", device_number, HTTP_PUT, put_telescope_slewtotargetasync);
  REGISTER_DEVICE_ROUTE("telescope", "synctoaltaz", device_number, HTTP_PUT, put_telescope_synctoaltaz);
  REGISTER_DEVICE_ROUTE("telescope", "synctocoordinates", device_number, HTTP_PUT, put_telescope_synctocoordinates);
  REGISTER_DEVICE_ROUTE("telescope", "synctotarget", device_number, HTTP_PUT, put_telescope_synctotarget);
  REGISTER_DEVICE_ROUTE("telescope", "targetdeclination", device_number, HTTP_PUT, put_telescope_targetdeclination);
  REGISTER_DEVICE_ROUTE("telescope", "targetrightascension", device_number, HTTP_PUT, put_telescope_targetrightascension);
  REGISTER_DEVICE_ROUTE("telescope", "tracking", device_number, HTTP_PUT, put_telescope_tracking);
  REGISTER_DEVICE_ROUTE("telescope", "trackingrate", device_number, HTTP_PUT, put_telescope_trackingrate);
  REGISTER_DEVICE_ROUTE("telescope", "unpark", device_number, HTTP_PUT, put_telescope_unpark);
  REGISTER_DEVICE_ROUTE("telescope", "utcdate", device_number, HTTP_PUT, put_telescope_utcdate);
}

void parse_string(alpaca_request_t *req, char *query, bool case_sensitive = true)
{
  while (query)
  {
    char *key = query;
    char *value = strstr(query, "=");

    if (!value)
    {
      break;
    }

    *value = '\0';
    value += 1;

    char *next = strstr(value, "&");

    if (next)
    {
      *next = '\0';
      next += 1;
    }

    if (case_sensitive)
    {
      if (strcmp(key, "ClientTransactionID") == 0)
      {
        req->client_transaction_id = atoi(value);
      }
      else if (strcmp(key, "ClientID") == 0)
      {
        req->client_id = atoi(value);
      }
      else
      {
        cJSON_AddStringToObject(req->body, key, value);
      }
    }
    else
    {
      if (strcasecmp(key, "ClientTransactionID") == 0)
      {
        ESP_LOGD(TAG, "ClientTransactionID: '%s'", value);

        req->client_transaction_id = atoi(value);
      }
      else if (strcasecmp(key, "ClientID") == 0)
      {
        ESP_LOGD(TAG, "ClientID: '%s'", value);

        req->client_id = atoi(value);
      }
      else
      {
        cJSON_AddStringToObject(req->body, key, value);
      }
    }

    query = next;
  }
}


// Alpaca PUT parameters arrive form-urlencoded; parse_string() stores them as
// JSON *strings*, so cJSON_GetNumberValue() on them yields NAN. Parse one as a
// double the same way the dome/focuser handlers do, returning NAN when the
// parameter is absent or malformed. Tolerates a genuine JSON number too.
static double get_number_param(cJSON *body, const char *key)
{
  cJSON *item = cJSON_GetObjectItemCaseSensitive(body, key);
  if (cJSON_IsNumber(item))
  {
    return cJSON_GetNumberValue(item);
  }
  char *str = cJSON_GetStringValue(item);
  if (!str || *str == '\0')
  {
    return NAN;
  }
  char *endptr;
  double value = strtod(str, &endptr);
  return (*endptr == '\0') ? value : NAN;
}

esp_err_t Api::parse_request(httpd_req_t *req, alpaca_request_t *parsed_request)
{
  parsed_request->body = cJSON_CreateObject();
  parsed_request->client_id = 0;
  parsed_request->client_transaction_id = 0;
  parsed_request->server_transaction_id = 0;
  parsed_request->start_time = esp_timer_get_time();
  parsed_request->device_number = 0;
  parsed_request->device_type = DeviceType::Unknown;

  char device_type_str[32];
  memset(device_type_str, 0, sizeof(device_type_str));
  sscanf(req->uri, "/api/v1/%32[^/]/%hhd/", device_type_str, &parsed_request->device_number);

  if (strcmp(device_type_str, "camera") == 0)
  {
    parsed_request->device_type = DeviceType::Camera;
  }
  else if (strcmp(device_type_str, "covercalibrator") == 0)
  {
    parsed_request->device_type = DeviceType::CoverCalibrator;
  }
  else if (strcmp(device_type_str, "dome") == 0)
  {
    parsed_request->device_type = DeviceType::Dome;
  }
  else if (strcmp(device_type_str, "filterwheel") == 0)
  {
    parsed_request->device_type = DeviceType::FilterWheel;
  }
  else if (strcmp(device_type_str, "focuser") == 0)
  {
    parsed_request->device_type = DeviceType::Focuser;
  }
  else if (strcmp(device_type_str, "observingconditions") == 0)
  {
    parsed_request->device_type = DeviceType::ObservingConditions;
  }
  else if (strcmp(device_type_str, "rotator") == 0)
  {
    parsed_request->device_type = DeviceType::Rotator;
  }
  else if (strcmp(device_type_str, "safetymonitor") == 0)
  {
    parsed_request->device_type = DeviceType::SafetyMonitor;
  }
  else if (strcmp(device_type_str, "switch") == 0)
  {
    parsed_request->device_type = DeviceType::Switch;
  }
  else if (strcmp(device_type_str, "telescope") == 0)
  {
    parsed_request->device_type = DeviceType::Telescope;
  }

  _mutex.lock();
  parsed_request->server_transaction_id = ++_server_transaction_id;
  _mutex.unlock();

  size_t query_len = httpd_req_get_url_query_len(req);

  if (query_len > 512)
  {
    return ESP_ERR_INVALID_SIZE;
  }

  if (query_len > 0)
  {
    char query[513];
    memset(query, 0, sizeof(query));
    httpd_req_get_url_query_str(req, query, sizeof(query));

    if (query[0] != '\0')
    {
      ESP_LOGD(TAG, "Parsing query: %s", query);
      parse_string(parsed_request, query, false);
    }
  }

  int len = req->content_len;

  ESP_LOGD(TAG, "Content-Length: %d", len);

  if (len > 0 && len < 4096)
  {
    char buf[4096];
    int recv_len = httpd_req_recv(req, buf, req->content_len);

    ESP_LOGD(TAG, "Received %d bytes", recv_len);

    if (recv_len > 0)
    {
      buf[recv_len] = '\0';

      size_t hdr_len = httpd_req_get_hdr_value_len(req, "Content-Type");
      char hdr[hdr_len + 1];
      httpd_req_get_hdr_value_str(req, "Content-Type", hdr, hdr_len + 1);
      hdr[hdr_len] = '\0';

      ESP_LOGD(TAG, "Content-Type: %s", hdr);

      if (strncasecmp(hdr, "application/x-www-form-urlencoded", 33) == 0)
      {
        ESP_LOGD(TAG, "Parsing form data: %s", buf);
        parse_string(parsed_request, buf, true);
      }
    }
  }

  if (esp_log_level_get(TAG) >= ESP_LOG_DEBUG)
  {
    char debugstr[512] = {0};
    cJSON_bool ret = cJSON_PrintPreallocated(parsed_request->body, debugstr, sizeof(debugstr), false);
    if (!ret)
    {
      ESP_LOGW(TAG, "error allocating json");
    }
    ESP_LOGD(TAG, "%s", debugstr);

    ESP_LOGD(TAG, "ClientTransactionID: %ld", parsed_request->client_transaction_id);
    ESP_LOGD(TAG, "ClientID: %ld", parsed_request->client_id);
  }

  if (parsed_request->device_type == DeviceType::Unknown)
  {
    return ESP_ERR_NOT_FOUND;
  }

  if (parsed_request->device_number >= _devices[parsed_request->device_type].size())
  {
    return ESP_ERR_NOT_FOUND;
  }

  if (parsed_request->client_transaction_id <= 0)
  {
    // TODO: Add optional strict check here
    return ESP_OK;
  }

  if (parsed_request->client_id <= 0)
  {
    // TODO: Add optional strict check here
    return ESP_OK;
  }

  return ESP_OK;
}

esp_err_t Api::send_json_response(httpd_req_t *req, alpaca_request_t *parsed_request, cJSON *root, uint16_t status_code)
{
  cJSON_AddNumberToObject(root, "ClientTransactionID", parsed_request->client_transaction_id);
  cJSON_AddNumberToObject(root, "ServerTransactionID", parsed_request->server_transaction_id);

  char json[512] = {0};
  cJSON_bool ret = cJSON_PrintPreallocated(root, json, sizeof(json), false);
  if (!ret)
  {
    ESP_LOGW(TAG, "error allocating json");
  }
  cJSON_Delete(root);

  int json_len = strlen(json);

  switch (status_code)
  {
  case 200:
    httpd_resp_set_status(req, HTTPD_200);
    break;
  case 204:
    httpd_resp_set_status(req, HTTPD_204);
    break;
  case 207:
    httpd_resp_set_status(req, HTTPD_207);
    break;
  case 400:
    httpd_resp_set_status(req, HTTPD_400);
    break;
  case 401:
    httpd_resp_set_status(req, "401 Not Authorized");
    break;
  case 404:
    httpd_resp_set_status(req, HTTPD_404);
    break;
  case 408:
    httpd_resp_set_status(req, HTTPD_408);
    break;
  case 500:
    httpd_resp_set_status(req, HTTPD_500);
    break;
  }

  httpd_resp_set_type(req, HTTPD_TYPE_JSON);
  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_hdr(req, "Connection", "Keep-Alive");
  httpd_resp_set_hdr(req, "Keep-Alive", "timeout=2, max=100");
  httpd_resp_send(req, json, json_len);

  if (esp_log_level_get(TAG) >= ESP_LOG_DEBUG)
  {
    char method[16];
    switch (req->method)
    {
    case HTTP_GET:
      strcpy(method, "GET");
      break;
    case HTTP_POST:
      strcpy(method, "POST");
      break;
    case HTTP_PUT:
      strcpy(method, "PUT");
      break;
    case HTTP_DELETE:
      strcpy(method, "DELETE");
      break;
    case HTTP_OPTIONS:
      strcpy(method, "OPTIONS");
      break;
    default:
      strcpy(method, "-");
      break;
    }

    int64_t end_time = esp_timer_get_time();

    int64_t duration = end_time - parsed_request->start_time;

    ESP_LOGD(TAG, "%s %s %lldus %ld", method, req->uri, duration, parsed_request->server_transaction_id);
  }

  cJSON_Delete(parsed_request->body);

  return ESP_OK;
}

esp_err_t Api::send_error_response(httpd_req_t *req, uint16_t status_code)
{
  switch (status_code)
  {
  case 200:
    httpd_resp_set_status(req, HTTPD_200);
    break;
  case 204:
    httpd_resp_set_status(req, HTTPD_204);
    break;
  case 207:
    httpd_resp_set_status(req, HTTPD_207);
    break;
  case 400:
    httpd_resp_set_status(req, HTTPD_400);
    break;
  case 404:
    httpd_resp_set_status(req, HTTPD_404);
    break;
  case 408:
    httpd_resp_set_status(req, HTTPD_408);
    break;
  case 500:
    httpd_resp_set_status(req, HTTPD_500);
    break;
  }

  httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
  httpd_resp_set_hdr(req, "Connection", "Keep-Alive");
  httpd_resp_set_hdr(req, "Keep-Alive", "timeout=2, max=100");
  return httpd_resp_send(req, NULL, 0);
}

// Management API

esp_err_t Api::handle_get_supported_api_versions(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  api->parse_request(req, &parsed_request);
  cJSON *root = cJSON_CreateObject();

  int supported_versions[] = {1};

  cJSON_AddItemToObject(root, "Value", cJSON_CreateIntArray(supported_versions, 1));

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_server_description(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  api->parse_request(req, &parsed_request);
  cJSON *root = cJSON_CreateObject();

  cJSON *value = cJSON_CreateObject();

  cJSON_AddStringToObject(value, "ServerName", api->_server_name);
  cJSON_AddStringToObject(value, "Manufacturer", api->_manufacturer);
  cJSON_AddStringToObject(value, "ManufacturerVersion", api->_manufacturer_version);
  cJSON_AddStringToObject(value, "Location", api->_location);

  cJSON_AddItemToObject(root, "Value", value);

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_configured_devices(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  api->parse_request(req, &parsed_request);
  cJSON *root = cJSON_CreateObject();

  cJSON *devices = cJSON_CreateArray();

  for (auto it : api->_devices)
  {
    for (size_t i = 0; i < it.second.size(); i++)
    {
      Device *device = it.second[i];

      cJSON *device_json = cJSON_CreateObject();

      char buf[33];

      device->get_name(buf, sizeof(buf));
      cJSON_AddStringToObject(device_json, "DeviceName", buf);

      friendly_device_type(device->device_type(), buf, sizeof(buf));
      cJSON_AddStringToObject(device_json, "DeviceType", buf);

      cJSON_AddNumberToObject(device_json, "DeviceNumber", i);
      cJSON_AddStringToObject(device_json, "UniqueID", device->_unique_id);

      cJSON_AddItemToArray(devices, device_json);
    }
  }

  cJSON_AddItemToObject(root, "Value", devices);

  return api->send_json_response(req, &parsed_request, root);
}

void set_error(esp_err_t err, cJSON *root)
{
  char buf[128];
  esp_err_t msgErr = s_err_msg_func(err, buf, sizeof(buf));

  cJSON_AddNumberToObject(root, "ErrorNumber", err);

  if (msgErr == ESP_OK)
  {
    cJSON_AddStringToObject(root, "ErrorMessage", buf);
  }
  else
  {
    cJSON_AddStringToObject(root, "ErrorMessage", "Unknown error");
  }
}

bool check_return(esp_err_t err, cJSON *root)
{
  if (err == ALPACA_OK)
  {
    return true;
  }
  else
  {
    set_error(err, root);
    return false;
  }
}

// Common Device API

esp_err_t Api::handle_put_action(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char *action = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Action"));
  char *parameters = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Parameters"));

  if (action && parameters)
  {
    char buf[512];
    if (check_return(device->action(action, parameters, buf, sizeof(buf)), root))
    {
      cJSON_AddStringToObject(root, "Value", buf);
    }
  }
  else
  {
    cJSON_Delete(root);
    return api->send_error_response(req, 400);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_commandblind(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char *command = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Command"));
  char *raw = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Raw"));

  if (command)
  {
    if (raw && (strcasecmp(raw, "true") == 0 || strcasecmp(raw, "false") == 0))
    {
      bool raw_value = strcasecmp(raw, "true") == 0;
      check_return(device->commandblind(command, raw_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    cJSON_Delete(root);
    return api->send_error_response(req, 400);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_commandbool(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char *command = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Command"));
  char *raw = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Raw"));

  if (command)
  {
    if (raw && (strcasecmp(raw, "true") == 0 || strcasecmp(raw, "false") == 0))
    {
      bool raw_value = strcasecmp(raw, "true") == 0;
      bool resp = false;
      if (check_return(device->commandbool(command, raw_value, &resp), root))
      {
        cJSON_AddBoolToObject(root, "Value", resp);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    cJSON_Delete(root);
    return api->send_error_response(req, 400);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_commandstring(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char *command = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Command"));
  char *raw = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Raw"));

  if (command)
  {
    if (raw && (strcasecmp(raw, "true") == 0 || strcasecmp(raw, "false") == 0))
    {
      bool raw_value = strcasecmp(raw, "true") == 0;

      char resp[512];

      if (check_return(device->commandstring(command, raw_value, resp, sizeof(resp)), root))
      {
        cJSON_AddStringToObject(root, "Value", resp);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    cJSON_Delete(root);
    return api->send_error_response(req, 400);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_connected(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  bool connected = false;
  if (check_return(device->get_connected(&connected), root))
  {
    cJSON_AddBoolToObject(root, "Value", connected);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_connected(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char *connected = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Connected"));
  if (connected && (strcasecmp(connected, "true") == 0 || strcasecmp(connected, "false") == 0))
  {
    bool connected_value = strcasecmp(connected, "true") == 0;
    check_return(device->set_connected(connected_value), root);
  }
  else
  {
    cJSON_Delete(root);
    return api->send_error_response(req, 400);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_description(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char buf[128];
  if (check_return(device->get_description(buf, sizeof(buf)), root))
  {
    cJSON_AddStringToObject(root, "Value", buf);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_driverinfo(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char buf[128];
  if (check_return(device->get_driverinfo(buf, sizeof(buf)), root))
  {
    cJSON_AddStringToObject(root, "Value", buf);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_driverversion(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char buf[128];
  if (check_return(device->get_driverversion(buf, sizeof(buf)), root))
  {
    cJSON_AddStringToObject(root, "Value", buf);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_interfaceversion(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  uint32_t version = 0;
  if (check_return(device->get_interfaceversion(&version), root))
  {
    cJSON_AddNumberToObject(root, "Value", version);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_name(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  char buf[128];
  if (check_return(device->get_name(buf, sizeof(buf)), root))
  {
    cJSON_AddStringToObject(root, "Value", buf);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_supportedactions(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  std::vector<std::string> actions;
  if (check_return(device->get_supportedactions(actions), root))
  {
    cJSON *value = cJSON_CreateArray();

    for (auto action : actions)
    {
      cJSON_AddItemToArray(value, cJSON_CreateString(action.c_str()));
    }

    cJSON_AddItemToObject(root, "Value", value);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// Camera API

// CoverCalibrator API

esp_err_t Api::handle_get_covercalibrator_brightness(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    uint32_t brightness = 0;
    if (check_return(cover_calibrator->get_brightness(&brightness), root))
    {
      cJSON_AddNumberToObject(root, "Value", brightness);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_covercalibrator_calibratorstate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    CoverCalibrator::CalibratorState state = CoverCalibrator::CalibratorState::Unknown;
    if (check_return(cover_calibrator->get_calibratorstate(&state), root))
    {
      cJSON_AddNumberToObject(root, "Value", (int)state);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_covercalibrator_coverstate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    CoverCalibrator::CoverState state = CoverCalibrator::CoverState::Unknown;
    if (check_return(cover_calibrator->get_coverstate(&state), root))
    {
      cJSON_AddNumberToObject(root, "Value", (int)state);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_covercalibrator_maxbrightness(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    uint32_t maxbrightness = 0;
    if (check_return(cover_calibrator->get_maxbrightness(&maxbrightness), root))
    {
      cJSON_AddNumberToObject(root, "Value", maxbrightness);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_covercalibrator_calibratoroff(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    check_return(cover_calibrator->turn_calibratoroff(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_covercalibrator_calibratoron(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    char *brightness = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Brightness"));
    if (brightness)
    {
      int brightness_value = atoi(brightness);

      char buf[128];
      itoa(brightness_value, buf, 10);

      if (strcmp(brightness, buf) != 0)
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(cover_calibrator->turn_calibratoron(brightness_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    cJSON_Delete(root);
    return api->send_error_response(req, 404);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_covercalibrator_closecover(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    check_return(cover_calibrator->closecover(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_covercalibrator_haltcover(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    check_return(cover_calibrator->haltcover(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_covercalibrator_opencover(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::CoverCalibrator)
  {
    CoverCalibrator *cover_calibrator = (CoverCalibrator *)device;

    check_return(cover_calibrator->opencover(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// Dome API

esp_err_t Api::handle_get_dome_altitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    double altitude = 0;
    if (check_return(dome->get_altitude(&altitude), root))
    {
      cJSON_AddNumberToObject(root, "Value", altitude);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_athome(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool athome = 0;
    if (check_return(dome->get_athome(&athome), root))
    {
      cJSON_AddBoolToObject(root, "Value", athome);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_atpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool atpark = 0;
    if (check_return(dome->get_atpark(&atpark), root))
    {
      cJSON_AddBoolToObject(root, "Value", atpark);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_azimuth(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    double azimuth = 0;
    if (check_return(dome->get_azimuth(&azimuth), root))
    {
      cJSON_AddNumberToObject(root, "Value", azimuth);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_canfindhome(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool canfindhome = 0;
    if (check_return(dome->get_canfindhome(&canfindhome), root))
    {
      cJSON_AddBoolToObject(root, "Value", canfindhome);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_canpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool canpark = 0;
    if (check_return(dome->get_canpark(&canpark), root))
    {
      cJSON_AddBoolToObject(root, "Value", canpark);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_cansetaltitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool cansetaltitude = 0;
    if (check_return(dome->get_cansetaltitude(&cansetaltitude), root))
    {
      cJSON_AddBoolToObject(root, "Value", cansetaltitude);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_cansetazimuth(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool cansetazimuth = 0;
    if (check_return(dome->get_cansetazimuth(&cansetazimuth), root))
    {
      cJSON_AddBoolToObject(root, "Value", cansetazimuth);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_cansetpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool cansetpark = 0;
    if (check_return(dome->get_cansetpark(&cansetpark), root))
    {
      cJSON_AddBoolToObject(root, "Value", cansetpark);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_cansetshutter(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool cansetshutter = 0;
    if (check_return(dome->get_cansetshutter(&cansetshutter), root))
    {
      cJSON_AddBoolToObject(root, "Value", cansetshutter);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_canslave(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool canslave = 0;
    if (check_return(dome->get_canslave(&canslave), root))
    {
      cJSON_AddBoolToObject(root, "Value", canslave);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_cansyncazimuth(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool cansyncazimuth = 0;
    if (check_return(dome->get_cansyncazimuth(&cansyncazimuth), root))
    {
      cJSON_AddBoolToObject(root, "Value", cansyncazimuth);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_shutterstatus(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    Dome::ShutterState shutterstatus;
    if (check_return(dome->get_shutterstatus(&shutterstatus), root))
    {
      cJSON_AddNumberToObject(root, "Value", (int)shutterstatus);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_slaved(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool slaved = 0;
    if (check_return(dome->get_slaved(&slaved), root))
    {
      cJSON_AddBoolToObject(root, "Value", slaved);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_slaved(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    char *slaved = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Slaved"));
    if (slaved && (strcasecmp(slaved, "true") == 0 || strcasecmp(slaved, "false") == 0))
    {
      bool slaved_value = strcasecmp(slaved, "true") == 0;
      check_return(dome->put_slaved(slaved_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_dome_slewing(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    bool slewing = 0;
    if (check_return(dome->get_slewing(&slewing), root))
    {
      cJSON_AddBoolToObject(root, "Value", slewing);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_abortslew(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    check_return(dome->put_abortslew(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_closeshutter(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    check_return(dome->put_closeshutter(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_findhome(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    check_return(dome->put_findhome(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_openshutter(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    check_return(dome->put_openshutter(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_park(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    check_return(dome->put_park(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_setpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    check_return(dome->put_setpark(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_slewtoaltitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    char *altitude = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Altitude"));
    if (altitude)
    {
      char *endptr;
      double altitude_value = strtof(altitude, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(dome->put_slewtoaltitude(altitude_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_slewtoazimuth(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    char *azimuth = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Azimuth"));
    if (azimuth)
    {
      char *endptr;
      double azimuth_value = strtof(azimuth, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(dome->put_slewtoazimuth(azimuth_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_dome_synctoazimuth(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Dome)
  {
    Dome *dome = (Dome *)device;

    char *azimuth = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Azimuth"));
    if (azimuth)
    {
      char *endptr;
      double azimuth_value = strtof(azimuth, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(dome->put_synctoazimuth(azimuth_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// FilterWheel API

esp_err_t Api::handle_get_filterwheel_focusoffsets(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::FilterWheel)
  {
    FilterWheel *filterwheel = (FilterWheel *)device;

    std::vector<int32_t> focusoffsets;
    if (check_return(filterwheel->get_focusoffsets(focusoffsets), root))
    {
      cJSON *focusoffsets_array = cJSON_CreateArray();
      for (int focus_offset : focusoffsets)
      {
        cJSON *focus_offset_item = cJSON_CreateNumber(focus_offset);
        cJSON_AddItemToArray(focusoffsets_array, focus_offset_item);
      }
      cJSON_AddItemToObject(root, "Value", focusoffsets_array);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_filterwheel_names(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::FilterWheel)
  {
    FilterWheel *filterwheel = (FilterWheel *)device;

    std::vector<std::string> names;
    if (check_return(filterwheel->get_names(names), root))
    {
      cJSON *names_array = cJSON_CreateArray();
      for (const std::string &name : names)
      {
        cJSON *name_item = cJSON_CreateString(name.c_str());
        cJSON_AddItemToArray(names_array, name_item);
      }
      cJSON_AddItemToObject(root, "Value", names_array);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_filterwheel_position(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::FilterWheel)
  {
    FilterWheel *filterwheel = (FilterWheel *)device;

    int32_t position = 0;
    if (check_return(filterwheel->get_position(&position), root))
    {
      cJSON_AddNumberToObject(root, "Value", position);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_filterwheel_position(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::FilterWheel)
  {
    FilterWheel *filterwheel = (FilterWheel *)device;

    char *position = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Position"));
    if (position)
    {
      char *endptr;
      int32_t position_value = strtol(position, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(filterwheel->put_position(position_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// Focuser API

esp_err_t Api::handle_get_focuser_absolute(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    bool absolute = 0;
    if (check_return(focuser->get_absolute(&absolute), root))
    {
      cJSON_AddBoolToObject(root, "Value", absolute);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_ismoving(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    bool ismoving = 0;
    if (check_return(focuser->get_ismoving(&ismoving), root))
    {
      cJSON_AddBoolToObject(root, "Value", ismoving);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_maxincrement(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    int32_t maxincrement = 0;
    if (check_return(focuser->get_maxincrement(&maxincrement), root))
    {
      cJSON_AddNumberToObject(root, "Value", maxincrement);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_maxstep(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    int32_t maxstep = 0;
    if (check_return(focuser->get_maxstep(&maxstep), root))
    {
      cJSON_AddNumberToObject(root, "Value", maxstep);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_position(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    int32_t position = 0;
    if (check_return(focuser->get_position(&position), root))
    {
      cJSON_AddNumberToObject(root, "Value", position);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_stepsize(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    int32_t stepsize = 0;
    if (check_return(focuser->get_stepsize(&stepsize), root))
    {
      cJSON_AddNumberToObject(root, "Value", stepsize);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_tempcomp(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    bool tempcomp = false;
    if (check_return(focuser->get_tempcomp(&tempcomp), root))
    {
      cJSON_AddBoolToObject(root, "Value", tempcomp);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_focuser_tempcomp(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    char *tempcomp = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "TempComp"));
    if (tempcomp && (strcasecmp(tempcomp, "true") == 0 || strcasecmp(tempcomp, "false") == 0))
    {
      bool tempcomp_value = strcasecmp(tempcomp, "true") == 0;
      check_return(focuser->put_tempcomp(tempcomp_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_tempcompavailable(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    bool tempcompavailable = false;
    if (check_return(focuser->get_tempcompavailable(&tempcompavailable), root))
    {
      cJSON_AddBoolToObject(root, "Value", tempcompavailable);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_focuser_temperature(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    double temperature = 0;
    if (check_return(focuser->get_temperature(&temperature), root))
    {
      cJSON_AddNumberToObject(root, "Value", temperature);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_focuser_halt(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    check_return(focuser->put_halt(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_focuser_move(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Focuser)
  {
    Focuser *focuser = (Focuser *)device;

    char *position = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Position"));
    if (position)
    {
      char *endptr;
      int32_t position_value = strtol(position, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(focuser->put_move(position_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// ObservingConditions API

esp_err_t Api::handle_get_observingconditions_averageperiod(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double averageperiod = 0;
    if (check_return(observingconditions->get_averageperiod(&averageperiod), root))
    {
      cJSON_AddNumberToObject(root, "Value", averageperiod);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_observingconditions_averageperiod(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    char *averageperiod = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "AveragePeriod"));
    if (averageperiod)
    {
      char *endptr;
      double averageperiod_value = strtof(averageperiod, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(observingconditions->put_averageperiod(averageperiod_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_cloudcover(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double cloudcover = 0;
    if (check_return(observingconditions->get_cloudcover(&cloudcover), root))
    {
      cJSON_AddNumberToObject(root, "Value", cloudcover);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_dewpoint(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double dewpoint = 0;
    if (check_return(observingconditions->get_dewpoint(&dewpoint), root))
    {
      cJSON_AddNumberToObject(root, "Value", dewpoint);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_humidity(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double humidity = 0;
    if (check_return(observingconditions->get_humidity(&humidity), root))
    {
      cJSON_AddNumberToObject(root, "Value", humidity);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_pressure(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double pressure = 0;
    if (check_return(observingconditions->get_pressure(&pressure), root))
    {
      cJSON_AddNumberToObject(root, "Value", pressure);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_rainrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double rainrate = 0;
    if (check_return(observingconditions->get_rainrate(&rainrate), root))
    {
      cJSON_AddNumberToObject(root, "Value", rainrate);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_skybrightness(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double skybrightness = 0;
    if (check_return(observingconditions->get_skybrightness(&skybrightness), root))
    {
      cJSON_AddNumberToObject(root, "Value", skybrightness);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_skyquality(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double skyquality = 0;
    if (check_return(observingconditions->get_skyquality(&skyquality), root))
    {
      cJSON_AddNumberToObject(root, "Value", skyquality);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_skytemperature(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double skytemperature = 0;
    if (check_return(observingconditions->get_skytemperature(&skytemperature), root))
    {
      cJSON_AddNumberToObject(root, "Value", skytemperature);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_starfwhm(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double starfwhm = 0;
    if (check_return(observingconditions->get_starfwhm(&starfwhm), root))
    {
      cJSON_AddNumberToObject(root, "Value", starfwhm);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_temperature(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double temperature = 0;
    if (check_return(observingconditions->get_temperature(&temperature), root))
    {
      cJSON_AddNumberToObject(root, "Value", temperature);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_winddirection(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double winddirection = 0;
    if (check_return(observingconditions->get_winddirection(&winddirection), root))
    {
      cJSON_AddNumberToObject(root, "Value", winddirection);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_windgust(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double windgust = 0;
    if (check_return(observingconditions->get_windgust(&windgust), root))
    {
      cJSON_AddNumberToObject(root, "Value", windgust);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_windspeed(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double windspeed = 0;
    if (check_return(observingconditions->get_windspeed(&windspeed), root))
    {
      cJSON_AddNumberToObject(root, "Value", windspeed);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_observingconditions_refresh(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    check_return(observingconditions->put_refresh(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_sensordescription(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    cJSON *sensor_name = cJSON_GetObjectItemCaseSensitive(parsed_request.body, "SensorName");
    if (!cJSON_IsString(sensor_name))
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }

    char sensordescription[512];

    if (check_return(
            observingconditions->get_sensordescription(sensor_name->valuestring, sensordescription, 512),
            root
        ))
    {
      cJSON_AddStringToObject(root, "Value", sensordescription);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_observingconditions_timesincelastupdate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::ObservingConditions)
  {
    ObservingConditions *observingconditions = (ObservingConditions *)device;

    double timesincelastupdate = 0;
    if (check_return(observingconditions->get_timesincelastupdate(&timesincelastupdate), root))
    {
      cJSON_AddNumberToObject(root, "Value", timesincelastupdate);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// Rotator API

esp_err_t Api::handle_get_rotator_canreverse(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    bool canreverse = false;
    if (check_return(rotator->get_canreverse(&canreverse), root))
    {
      cJSON_AddBoolToObject(root, "Value", canreverse);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_rotator_ismoving(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    bool ismoving = false;
    if (check_return(rotator->get_ismoving(&ismoving), root))
    {
      cJSON_AddBoolToObject(root, "Value", ismoving);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_rotator_mechanicalposition(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    double mechanicalposition = 0;
    if (check_return(rotator->get_mechanicalposition(&mechanicalposition), root))
    {
      cJSON_AddNumberToObject(root, "Value", mechanicalposition);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_rotator_position(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    double position = 0;
    if (check_return(rotator->get_position(&position), root))
    {
      cJSON_AddNumberToObject(root, "Value", position);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_rotator_reverse(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    bool reverse = false;
    if (check_return(rotator->get_reverse(&reverse), root))
    {
      cJSON_AddBoolToObject(root, "Value", reverse);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_rotator_reverse(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    char *reverse = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Reverse"));
    if (reverse && (strcasecmp(reverse, "true") == 0 || strcasecmp(reverse, "false") == 0))
    {
      bool reverse_value = strcasecmp(reverse, "true") == 0;
      check_return(rotator->put_reverse(reverse_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_rotator_stepsize(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    double stepsize = 0;
    if (check_return(rotator->get_stepsize(&stepsize), root))
    {
      cJSON_AddNumberToObject(root, "Value", stepsize);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_rotator_targetposition(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    double targetposition = 0;
    if (check_return(rotator->get_targetposition(&targetposition), root))
    {
      cJSON_AddNumberToObject(root, "Value", targetposition);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_rotator_halt(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    check_return(rotator->put_halt(), root);
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_rotator_move(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    char *position = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Position"));
    if (position)
    {
      char *endptr;
      double position_value = strtof(position, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(rotator->put_move(position_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_rotator_moveabsolute(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    char *position = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Position"));
    if (position)
    {
      char *endptr;
      double position_value = strtof(position, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(rotator->put_moveabsolute(position_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_rotator_movemechanical(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    char *position = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Position"));
    if (position)
    {
      char *endptr;
      double position_value = strtof(position, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(rotator->put_movemechanical(position_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_rotator_sync(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Rotator)
  {
    Rotator *rotator = (Rotator *)device;

    char *position = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Position"));
    if (position)
    {
      char *endptr;
      double position_value = strtof(position, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(rotator->put_sync(position_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// SafetyMonitor API

esp_err_t Api::handle_get_safetymonitor_issafe(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::SafetyMonitor)
  {
    SafetyMonitor *safetymonitor = (SafetyMonitor *)device;

    bool issafe = 0;
    if (check_return(safetymonitor->get_issafe(&issafe), root))
    {
      cJSON_AddBoolToObject(root, "Value", issafe);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// Switch API

esp_err_t Api::handle_get_switch_maxswitch(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    int32_t maxswitch = 0;
    if (check_return(switch_device->get_maxswitch(&maxswitch), root))
    {
      cJSON_AddNumberToObject(root, "Value", maxswitch);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_canwrite(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      bool canwrite = false;
      if (check_return(switch_device->get_canwrite(id_value, &canwrite), root))
      {
        cJSON_AddBoolToObject(root, "Value", canwrite);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_getswitch(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      bool switch_value = false;
      if (check_return(switch_device->get_getswitch(id_value, &switch_value), root))
      {
        cJSON_AddBoolToObject(root, "Value", switch_value);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_getswitchdescription(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      char switchdescription[512];
      if (check_return(switch_device->get_getswitchdescription(id_value, switchdescription, 512), root))
      {
        cJSON_AddStringToObject(root, "Value", switchdescription);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_getswitchname(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      char switchname[512];
      if (check_return(switch_device->get_getswitchname(id_value, switchname, 512), root))
      {
        cJSON_AddStringToObject(root, "Value", switchname);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_getswitchvalue(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      double switch_value = 0.0;
      if (check_return(switch_device->get_getswitchvalue(id_value, &switch_value), root))
      {
        cJSON_AddNumberToObject(root, "Value", switch_value);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_minswitchvalue(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      double switch_value = 0.0;
      if (check_return(switch_device->get_minswitchvalue(id_value, &switch_value), root))
      {
        cJSON_AddNumberToObject(root, "Value", switch_value);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_maxswitchvalue(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      double switch_value = 0.0;
      if (check_return(switch_device->get_maxswitchvalue(id_value, &switch_value), root))
      {
        cJSON_AddNumberToObject(root, "Value", switch_value);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_switch_setswitch(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Id"));
    char *state = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "State"));
    if (id && state && (strcasecmp(state, "true") == 0 || strcasecmp(state, "false") == 0))
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      bool state_value = strcasecmp(state, "true") == 0;
      check_return(switch_device->put_setswitch(id_value, state_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_switch_setswitchname(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Id"));
    char *name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Name"));
    if (id && name)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(switch_device->put_setswitchname(id_value, name), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_switch_setswitchvalue(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Id"));
    char *value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(parsed_request.body, "Value"));
    if (id && value)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      double value_value = strtod(value, &endptr);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      check_return(switch_device->put_setswitchvalue(id_value, value_value), root);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_switch_switchstep(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Switch)
  {
    Switch *switch_device = (Switch *)device;

    char *id = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Id"));
    if (id)
    {
      char *endptr;
      int32_t id_value = strtol(id, &endptr, 10);
      if (*endptr != '\0')
      {
        cJSON_Delete(root);
        return api->send_error_response(req, 400);
      }

      double switchstep = 0.0;
      if (check_return(switch_device->get_switchstep(id_value, &switchstep), root))
      {
        cJSON_AddNumberToObject(root, "Value", switchstep);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

// Telescope API

esp_err_t Api::handle_get_telescope_alignmentmode(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    Telescope::AlignmentMode value = Telescope::AlignmentMode::AltAz;
    if (check_return(telescope_device->get_alignmentmode(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", (int)value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_altitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_altitude(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_aperturearea(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_aperturearea(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_aperturediameter(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_aperturediameter(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_athome(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_athome(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_atpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_atpark(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_azimuth(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_azimuth(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canfindhome(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canfindhome(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canpark(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canpulseguide(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canpulseguide(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansetdeclinationrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansetdeclinationrate(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansetguiderates(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansetguiderates(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansetpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansetpark(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansetpierside(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansetpierside(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansetrightascensionrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansetrightascensionrate(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansettracking(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansettracking(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canslew(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canslew(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canslewaltaz(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canslewaltaz(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canslewaltazasync(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canslewaltazasync(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canslewasync(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canslewasync(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansync(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansync(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_cansyncaltaz(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_cansyncaltaz(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canunpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_canunpark(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_declination(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_declination(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_declinationrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_declinationrate(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_declinationrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double DeclinationRate = get_number_param(parsed_request.body, "DeclinationRate");
    if (!isnan(DeclinationRate))
    {
      if (check_return(telescope_device->put_declinationrate(DeclinationRate), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_doesrefraction(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_doesrefraction(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_doesrefraction(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    cJSON *DoesRefraction = cJSON_GetObjectItem(parsed_request.body, "DoesRefraction");
    if (cJSON_IsBool(DoesRefraction))
    {
      if (check_return(telescope_device->put_doesrefraction(cJSON_IsTrue(DoesRefraction)), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_equatorialsystem(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    Telescope::EquatorialSystem value = Telescope::EquatorialSystem::Other;
    if (check_return(telescope_device->get_equatorialsystem(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", (int)value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_focallength(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_focallength(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_guideratedeclination(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_guideratedeclination(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_guideratedeclination(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double GuideRateDeclination =
        get_number_param(parsed_request.body, "GuideRateDeclination");
    if (!isnan(GuideRateDeclination))
    {
      if (check_return(telescope_device->put_guideratedeclination(GuideRateDeclination), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_guideraterightascension(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_guideraterightascension(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_guideraterightascension(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double GuideRateRightAscension =
        get_number_param(parsed_request.body, "GuideRateRightAscension");
    if (!isnan(GuideRateRightAscension))
    {
      if (check_return(telescope_device->put_guideraterightascension(GuideRateRightAscension), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_ispulseguiding(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_ispulseguiding(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_rightascension(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_rightascension(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_rightascensionrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_rightascensionrate(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_rightascensionrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double RightAscensionRate = get_number_param(parsed_request.body, "RightAscensionRate");
    if (!isnan(RightAscensionRate))
    {
      if (check_return(telescope_device->put_rightascensionrate(RightAscensionRate), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_sideofpier(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    Telescope::SideOfPier value = Telescope::SideOfPier::Unknown;
    if (check_return(telescope_device->get_sideofpier(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", (int)value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_sideofpier(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double sideofpier_value = get_number_param(parsed_request.body, "SideOfPier");
    Telescope::SideOfPier sideofpier =
        isnan(sideofpier_value) ? Telescope::SideOfPier::Unknown : (Telescope::SideOfPier)sideofpier_value;
    if (sideofpier != Telescope::SideOfPier::Unknown)
    {
      if (check_return(telescope_device->put_sideofpier(sideofpier), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_siderealtime(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_siderealtime(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_siteelevation(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_siteelevation(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_siteelevation(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double SiteElevation = get_number_param(parsed_request.body, "SiteElevation");
    if (!isnan(SiteElevation))
    {
      if (check_return(telescope_device->put_siteelevation(SiteElevation), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_sitelatitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_sitelatitude(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_sitelatitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = get_number_param(parsed_request.body, "SiteLatitude");
    if (!isnan(value))
    {
      if (check_return(telescope_device->put_sitelatitude(value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_sitelongitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_sitelongitude(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_sitelongitude(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = get_number_param(parsed_request.body, "SiteLongitude");
    if (!isnan(value))
    {
      if (check_return(telescope_device->put_sitelongitude(value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_slewing(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_slewing(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_slewsettletime(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    int32_t value = 0;
    if (check_return(telescope_device->get_slewsettletime(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_slewsettletime(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = get_number_param(parsed_request.body, "SlewSettleTime");
    if (!isnan(value))
    {
      if (check_return(telescope_device->put_slewsettletime(value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_targetdeclination(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_targetdeclination(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_targetdeclination(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = get_number_param(parsed_request.body, "TargetDeclination");
    if (!isnan(value))
    {
      if (check_return(telescope_device->put_targetdeclination(value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_targetrightascension(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = 0.0;
    if (check_return(telescope_device->get_targetrightascension(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_targetrightascension(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = get_number_param(parsed_request.body, "TargetRightAscension");
    if (!isnan(value))
    {
      if (check_return(telescope_device->put_targetrightascension(value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_tracking(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    bool value = false;
    if (check_return(telescope_device->get_tracking(&value), root))
    {
      cJSON_AddBoolToObject(root, "Value", value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_tracking(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    cJSON *Tracking = (cJSON_GetObjectItem(parsed_request.body, "Tracking"));
    if (cJSON_IsBool(Tracking))
    {
      if (check_return(telescope_device->put_tracking(cJSON_IsTrue(Tracking)), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_trackingrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    Telescope::TrackingRate value = Telescope::TrackingRate::Sidereal;
    if (check_return(telescope_device->get_trackingrate(&value), root))
    {
      cJSON_AddNumberToObject(root, "Value", (int)value);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_trackingrate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double value = get_number_param(parsed_request.body, "TrackingRate");
    if (!isnan(value) && value >= 0 && value <= 3)
    {
      if (check_return(telescope_device->put_trackingrate((Telescope::TrackingRate)value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_trackingrates(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    std::vector<Telescope::TrackingRate> value;
    if (check_return(telescope_device->get_trackingrates(value), root))
    {
      cJSON *array = cJSON_CreateArray();
      for (auto &v : value)
      {
        cJSON_AddItemToArray(array, cJSON_CreateNumber((int)v));
      }
      cJSON_AddItemToObject(root, "Value", array);
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_utcdate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    std::string value;
    if (check_return(telescope_device->get_utcdate(value), root))
    {
      cJSON_AddStringToObject(root, "Value", value.c_str());
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_utcdate(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    std::string value = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "UTCDate"));
    if (!value.empty())
    {
      if (check_return(telescope_device->put_utcdate(value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_abortslew(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    if (check_return(telescope_device->put_abortslew(), root))
    {
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_axisrates(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    char *axisStr = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Axis"));
    if (axisStr != NULL)
    {
      Telescope::TelescopeAxis axis = (Telescope::TelescopeAxis)atoi(axisStr);
      std::vector<Telescope::AxisRate> value;

      if (check_return(telescope_device->get_axisrates(axis, value), root))
      {
        cJSON *array = cJSON_CreateArray();
        for (auto &v : value)
        {
          cJSON *rate = cJSON_CreateObject();
          cJSON_AddNumberToObject(rate, "Minimum", v.min);
          cJSON_AddNumberToObject(rate, "Maximum", v.max);
          cJSON_AddItemToArray(array, rate);
        }
        cJSON_AddItemToObject(root, "Value", array);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_canmoveaxis(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    char *axisStr = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Axis"));
    if (axisStr != NULL)
    {
      Telescope::TelescopeAxis axis = (Telescope::TelescopeAxis)atoi(axisStr);
      bool value = false;

      if (check_return(telescope_device->get_canmoveaxis(axis, &value), root))
      {
        cJSON_AddBoolToObject(root, "Value", value);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_get_telescope_destinationsideofpier(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    char *RightAscensionStr = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "RightAscension"));
    char *DeclinationStr = cJSON_GetStringValue(cJSON_GetObjectItem(parsed_request.body, "Declination"));
    if (RightAscensionStr != NULL && DeclinationStr != NULL)
    {
      double RightAscension = atof(RightAscensionStr);
      double Declination = atof(DeclinationStr);

      Telescope::SideOfPier value = Telescope::SideOfPier::Unknown;

      if (check_return(telescope_device->get_destinationsideofpier(RightAscension, Declination, &value), root))
      {
        cJSON_AddNumberToObject(root, "Value", (int)value);
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_findhome(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    if (check_return(telescope_device->put_findhome(), root))
    {
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_moveaxis(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double Axis_value = get_number_param(parsed_request.body, "Axis");
    double Rate = get_number_param(parsed_request.body, "Rate");
    int32_t Axis = isnan(Axis_value) ? -1 : (int32_t)Axis_value;
    if (!isnan(Rate) && Axis >= 0)
    {
      if (check_return(telescope_device->put_moveaxis((Telescope::TelescopeAxis)Axis, Rate), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_park(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    if (check_return(telescope_device->put_park(), root))
    {
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_pulseguide(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double Direction_value = get_number_param(parsed_request.body, "Direction");
    double Duration_value = get_number_param(parsed_request.body, "Duration");
    if (!isnan(Direction_value) && !isnan(Duration_value))
    {
      if (check_return(telescope_device->put_pulseguide((Telescope::GuideDirection)(int32_t)Direction_value, (int32_t)Duration_value), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_setpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    if (check_return(telescope_device->put_setpark(), root))
    {
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_slewtoaltazasync(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double Azimuth = get_number_param(parsed_request.body, "Azimuth");
    double Altitude = get_number_param(parsed_request.body, "Altitude");
    if (!isnan(Altitude) && !isnan(Azimuth))
    {
      if (check_return(telescope_device->put_slewtoaltazasync(Altitude, Azimuth), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_slewtocoordinatesasync(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double RightAscension = get_number_param(parsed_request.body, "RightAscension");
    double Declination = get_number_param(parsed_request.body, "Declination");
    if (!isnan(RightAscension) && !isnan(Declination))
    {
      if (check_return(telescope_device->put_slewtocoordinatesasync(RightAscension, Declination), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_slewtotargetasync(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    if (check_return(telescope_device->put_slewtotargetasync(), root))
    {
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_synctoaltaz(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double Azimuth = get_number_param(parsed_request.body, "Azimuth");
    double Altitude = get_number_param(parsed_request.body, "Altitude");
    if (!isnan(Altitude) && !isnan(Azimuth))
    {
      if (check_return(telescope_device->put_synctoaltaz(Altitude, Azimuth), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_synctocoordinates(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    double RightAscension = get_number_param(parsed_request.body, "RightAscension");
    double Declination = get_number_param(parsed_request.body, "Declination");
    if (!isnan(RightAscension) && !isnan(Declination))
    {
      if (check_return(telescope_device->put_synctocoordinates(RightAscension, Declination), root))
      {
      }
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_synctotarget(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    if (check_return(telescope_device->put_synctotarget(), root))
    {
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

esp_err_t Api::handle_put_telescope_unpark(httpd_req_t *req)
{
  Api *api = (Api *)req->user_ctx;
  alpaca_request_t parsed_request;
  esp_err_t err = api->parse_request(req, &parsed_request);
  if (err != ESP_OK)
  {
    api->send_error_response(req, err == ESP_ERR_NOT_FOUND ? 404 : 400);
    return err;
  }
  cJSON *root = cJSON_CreateObject();
  Device *device = api->_devices[parsed_request.device_type][parsed_request.device_number];

  if (parsed_request.device_type == DeviceType::Telescope)
  {
    Telescope *telescope_device = (Telescope *)device;
    if (check_return(telescope_device->put_unpark(), root))
    {
    }
    else
    {
      cJSON_Delete(root);
      return api->send_error_response(req, 400);
    }
  }
  else
  {
    set_error(ALPACA_ERR_NOT_IMPLEMENTED, root);
  }

  return api->send_json_response(req, &parsed_request, root);
}

} // namespace AlpacaServer
