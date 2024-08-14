#pragma once
#ifndef __ALPACA_SERVER_API_H__
#define __ALPACA_SERVER_API_H__

#include <alpaca_server/device.h>
#include <cJSON.h>
#include <esp_http_server.h>
#include <map>
#include <mutex>
#include <vector>

#define ALPACA_OK                                 0x000
#define ALPACA_ERR_NOT_IMPLEMENTED                0x400
#define ALPACA_ERR_INVALID_VALUE                  0x401
#define ALPACA_ERR_VALUE_NOT_SET                  0x402
#define ALPACA_ERR_NOT_CONNECTED                  0x407
#define ALPACA_ERR_INVALID_WHILE_PARKED           0x408
#define ALPACA_ERR_INVALID_WHILE_SLAVED           0x409
#define ALPACA_ERR_INVALID_OPERATION              0x40B
#define ALPACA_ERR_ACTION_NOT_IMPLEMENTED         0x40C

#define ALPACA_ERR_MESSAGE_NOT_IMPLEMENTED        "Not implemented"
#define ALPACA_ERR_MESSAGE_INVALID_VALUE          "Invalid value"
#define ALPACA_ERR_MESSAGE_VALUE_NOT_SET          "Value not set"
#define ALPACA_ERR_MESSAGE_NOT_CONNECTED          "Not connected"
#define ALPACA_ERR_MESSAGE_INVALID_WHILE_PARKED   "Invalid while parked"
#define ALPACA_ERR_MESSAGE_INVALID_WHILE_SLAVED   "Invalid while slaved"
#define ALPACA_ERR_MESSAGE_INVALID_OPERATION      "Invalid operation"
#define ALPACA_ERR_MESSAGE_ACTION_NOT_IMPLEMENTED "Action not implemented"

namespace AlpacaServer
{
esp_err_t error_message(uint16_t error_code, char *buf, size_t len);

typedef struct
{
  cJSON *body;
  int32_t client_id;
  int32_t client_transaction_id;
  int32_t server_transaction_id;
  int64_t start_time;

  uint8_t device_number;
  DeviceType device_type;
} alpaca_request_t;

class Api
{
public:
  /*
   * Constructor
   *
   * @param devices A vector of pointers to the devices that are managed by this API
   * @param server_id The unique identifier for this server. Used to create the unique id's for each device
   * @param server_name The name of this server
   * @param manufacturer The manufacturer of this server
   * @param manufacturer_version The version of the manufacturer's server
   * @param location The location of this server
   */
  Api(std::vector<Device *> &devices,
      const char *server_id,
      const char *server_name,
      const char *manufacturer,
      const char *manufacturer_version,
      const char *location);
  ~Api();

  /*
   * Register the routes for the API
   *
   * @param server The handle to the HTTP server
   */
  void register_routes(httpd_handle_t server);

  void set_server_name(const char *server_name);
  void set_location(const char *location);

private:
  void initialize();

  void register_device_routes(httpd_handle_t server, size_t device_number, Device *device);
  void register_camera_routes(httpd_handle_t server, size_t device_number, Camera *device);
  void register_covercalibrator_routes(httpd_handle_t server, size_t device_number, CoverCalibrator *device);
  void register_dome_routes(httpd_handle_t server, size_t device_number, Dome *device);
  void register_filterwheel_routes(httpd_handle_t server, size_t device_number, FilterWheel *device);
  void register_focuser_routes(httpd_handle_t server, size_t device_number, Focuser *device);
  void register_observingconditions_routes(httpd_handle_t server, size_t device_number, ObservingConditions *device);
  void register_rotator_routes(httpd_handle_t server, size_t device_number, Rotator *device);
  void register_safetymonitor_routes(httpd_handle_t server, size_t device_number, SafetyMonitor *device);
  void register_switch_routes(httpd_handle_t server, size_t device_number, Switch *device);
  void register_telescope_routes(httpd_handle_t server, size_t device_number, Telescope *device);

  // Management API
  static esp_err_t handle_get_supported_api_versions(httpd_req_t *req);
  static esp_err_t handle_get_server_description(httpd_req_t *req);
  static esp_err_t handle_get_configured_devices(httpd_req_t *req);

  // Common Device API
  static esp_err_t handle_put_action(httpd_req_t *req);
  static esp_err_t handle_put_commandblind(httpd_req_t *req);
  static esp_err_t handle_put_commandbool(httpd_req_t *req);
  static esp_err_t handle_put_commandstring(httpd_req_t *req);
  static esp_err_t handle_get_connected(httpd_req_t *req);
  static esp_err_t handle_put_connected(httpd_req_t *req);
  static esp_err_t handle_get_description(httpd_req_t *req);
  static esp_err_t handle_get_driverinfo(httpd_req_t *req);
  static esp_err_t handle_get_driverversion(httpd_req_t *req);
  static esp_err_t handle_get_interfaceversion(httpd_req_t *req);
  static esp_err_t handle_get_name(httpd_req_t *req);
  static esp_err_t handle_get_supportedactions(httpd_req_t *req);

  // Camera API

  // TODO: Implement the Camera API

  // CoverCalibrator API
  static esp_err_t handle_get_covercalibrator_brightness(httpd_req_t *req);
  static esp_err_t handle_get_covercalibrator_calibratorstate(httpd_req_t *req);
  static esp_err_t handle_get_covercalibrator_coverstate(httpd_req_t *req);
  static esp_err_t handle_get_covercalibrator_maxbrightness(httpd_req_t *req);
  static esp_err_t handle_put_covercalibrator_calibratoroff(httpd_req_t *req);
  static esp_err_t handle_put_covercalibrator_calibratoron(httpd_req_t *req);
  static esp_err_t handle_put_covercalibrator_closecover(httpd_req_t *req);
  static esp_err_t handle_put_covercalibrator_haltcover(httpd_req_t *req);
  static esp_err_t handle_put_covercalibrator_opencover(httpd_req_t *req);

  // Dome API

  static esp_err_t handle_get_dome_altitude(httpd_req_t *req);
  static esp_err_t handle_get_dome_athome(httpd_req_t *req);
  static esp_err_t handle_get_dome_atpark(httpd_req_t *req);
  static esp_err_t handle_get_dome_azimuth(httpd_req_t *req);
  static esp_err_t handle_get_dome_canfindhome(httpd_req_t *req);
  static esp_err_t handle_get_dome_canpark(httpd_req_t *req);
  static esp_err_t handle_get_dome_cansetaltitude(httpd_req_t *req);
  static esp_err_t handle_get_dome_cansetazimuth(httpd_req_t *req);
  static esp_err_t handle_get_dome_cansetpark(httpd_req_t *req);
  static esp_err_t handle_get_dome_cansetshutter(httpd_req_t *req);
  static esp_err_t handle_get_dome_canslave(httpd_req_t *req);
  static esp_err_t handle_get_dome_cansyncazimuth(httpd_req_t *req);
  static esp_err_t handle_get_dome_shutterstatus(httpd_req_t *req);
  static esp_err_t handle_get_dome_slaved(httpd_req_t *req);
  static esp_err_t handle_put_dome_slaved(httpd_req_t *req);
  static esp_err_t handle_get_dome_slewing(httpd_req_t *req);
  static esp_err_t handle_put_dome_abortslew(httpd_req_t *req);
  static esp_err_t handle_put_dome_closeshutter(httpd_req_t *req);
  static esp_err_t handle_put_dome_findhome(httpd_req_t *req);
  static esp_err_t handle_put_dome_openshutter(httpd_req_t *req);
  static esp_err_t handle_put_dome_park(httpd_req_t *req);
  static esp_err_t handle_put_dome_setpark(httpd_req_t *req);
  static esp_err_t handle_put_dome_slewtoaltitude(httpd_req_t *req);
  static esp_err_t handle_put_dome_slewtoazimuth(httpd_req_t *req);
  static esp_err_t handle_put_dome_synctoazimuth(httpd_req_t *req);

  // FilterWheel API

  static esp_err_t handle_get_filterwheel_focusoffsets(httpd_req_t *req);
  static esp_err_t handle_get_filterwheel_names(httpd_req_t *req);
  static esp_err_t handle_get_filterwheel_position(httpd_req_t *req);
  static esp_err_t handle_put_filterwheel_position(httpd_req_t *req);

  // Focuser API

  static esp_err_t handle_get_focuser_absolute(httpd_req_t *req);
  static esp_err_t handle_get_focuser_ismoving(httpd_req_t *req);
  static esp_err_t handle_get_focuser_maxincrement(httpd_req_t *req);
  static esp_err_t handle_get_focuser_maxstep(httpd_req_t *req);
  static esp_err_t handle_get_focuser_position(httpd_req_t *req);
  static esp_err_t handle_get_focuser_stepsize(httpd_req_t *req);
  static esp_err_t handle_get_focuser_tempcomp(httpd_req_t *req);
  static esp_err_t handle_put_focuser_tempcomp(httpd_req_t *req);
  static esp_err_t handle_get_focuser_tempcompavailable(httpd_req_t *req);
  static esp_err_t handle_get_focuser_temperature(httpd_req_t *req);
  static esp_err_t handle_put_focuser_halt(httpd_req_t *req);
  static esp_err_t handle_put_focuser_move(httpd_req_t *req);

  // ObservingConditions API

  static esp_err_t handle_get_observingconditions_averageperiod(httpd_req_t *req);
  static esp_err_t handle_put_observingconditions_averageperiod(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_cloudcover(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_dewpoint(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_humidity(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_pressure(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_rainrate(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_skybrightness(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_skyquality(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_skytemperature(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_starfwhm(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_temperature(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_winddirection(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_windgust(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_windspeed(httpd_req_t *req);
  static esp_err_t handle_put_observingconditions_refresh(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_sensordescription(httpd_req_t *req);
  static esp_err_t handle_get_observingconditions_timesincelastupdate(httpd_req_t *req);

  // Rotator API

  static esp_err_t handle_get_rotator_canreverse(httpd_req_t *req);
  static esp_err_t handle_get_rotator_ismoving(httpd_req_t *req);
  static esp_err_t handle_get_rotator_mechanicalposition(httpd_req_t *req);
  static esp_err_t handle_get_rotator_position(httpd_req_t *req);
  static esp_err_t handle_get_rotator_reverse(httpd_req_t *req);
  static esp_err_t handle_put_rotator_reverse(httpd_req_t *req);
  static esp_err_t handle_get_rotator_stepsize(httpd_req_t *req);
  static esp_err_t handle_get_rotator_targetposition(httpd_req_t *req);
  static esp_err_t handle_put_rotator_halt(httpd_req_t *req);
  static esp_err_t handle_put_rotator_move(httpd_req_t *req);
  static esp_err_t handle_put_rotator_moveabsolute(httpd_req_t *req);
  static esp_err_t handle_put_rotator_movemechanical(httpd_req_t *req);
  static esp_err_t handle_put_rotator_sync(httpd_req_t *req);

  // SafetyMonitor API

  static esp_err_t handle_get_safetymonitor_issafe(httpd_req_t *req);

  // Switch API

  static esp_err_t handle_get_switch_maxswitch(httpd_req_t *req);
  static esp_err_t handle_get_switch_canwrite(httpd_req_t *req);
  static esp_err_t handle_get_switch_getswitch(httpd_req_t *req);
  static esp_err_t handle_get_switch_getswitchdescription(httpd_req_t *req);
  static esp_err_t handle_get_switch_getswitchname(httpd_req_t *req);
  static esp_err_t handle_get_switch_getswitchvalue(httpd_req_t *req);
  static esp_err_t handle_get_switch_minswitchvalue(httpd_req_t *req);
  static esp_err_t handle_get_switch_maxswitchvalue(httpd_req_t *req);
  static esp_err_t handle_put_switch_setswitch(httpd_req_t *req);
  static esp_err_t handle_put_switch_setswitchname(httpd_req_t *req);
  static esp_err_t handle_put_switch_setswitchvalue(httpd_req_t *req);
  static esp_err_t handle_get_switch_switchstep(httpd_req_t *req);

  // Telescope API

  // TODO: Implement the Telescope API

  esp_err_t parse_request(httpd_req_t *req, alpaca_request_t *parsed_request);

  esp_err_t send_json_response(
      httpd_req_t *req,
      alpaca_request_t *parsed_request,
      cJSON *root,
      uint16_t status_code = 200
  );

  esp_err_t send_error_response(httpd_req_t *req, uint16_t status_code);

  esp_err_t generate_unique_id(
      const char *server_id,
      const char *device_name,
      DeviceType device_type,
      uint8_t device_number,
      char *unique_id,
      size_t len
  );

private:
  char *_server_id;

  char *_server_name;
  char *_manufacturer;
  char *_manufacturer_version;
  char *_location;

  uint32_t _server_transaction_id;

  std::map<DeviceType, std::vector<Device *>> _devices;

  std::mutex _mutex;
};

} // namespace AlpacaServer

#endif // __ALPACA_SERVER_API_H__
