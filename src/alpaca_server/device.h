#pragma once
#ifndef __ALPACA_SERVER_DEVICE_H__
#define __ALPACA_SERVER_DEVICE_H__

#include <cJSON.h>
#include <string>
#include <vector>

#include <esp_err.h>

namespace AlpacaServer
{
class Api;

enum class DeviceType
{
  Unknown = 0,
  Camera,
  CoverCalibrator,
  Dome,
  FilterWheel,
  Focuser,
  ObservingConditions,
  Rotator,
  SafetyMonitor,
  Switch,
  Telescope,
};

esp_err_t friendly_device_type(DeviceType t, char *buf, size_t len);
esp_err_t uri_device_type(DeviceType t, char *buf, size_t len);

class Device
{
public:
  Device();
  ~Device();

  virtual DeviceType device_type() = 0;

  virtual esp_err_t action(const char *action, const char *parameters, char *buf, size_t len) = 0;
  virtual esp_err_t commandblind(const char *command, bool raw) = 0;
  virtual esp_err_t commandbool(const char *command, bool raw, bool *resp) = 0;
  virtual esp_err_t commandstring(const char *action, bool raw, char *buf, size_t len) = 0;

  virtual esp_err_t get_connected(bool *connected) = 0;
  virtual esp_err_t set_connected(bool connected) = 0;

  virtual esp_err_t get_description(char *buf, size_t len) = 0;
  virtual esp_err_t get_driverinfo(char *buf, size_t len) = 0;
  virtual esp_err_t get_driverversion(char *buf, size_t len) = 0;
  virtual esp_err_t get_interfaceversion(uint32_t *version) = 0;
  virtual esp_err_t get_name(char *buf, size_t len) = 0;
  virtual esp_err_t get_supportedactions(std::vector<std::string> &actions) = 0;

private:
  friend class Api;
  uint8_t _number;

  char _unique_id[33];
};

class Camera : public Device
{
public:
  Camera();
  ~Camera();

  DeviceType device_type() override;
};

class CoverCalibrator : public Device
{
public:
  enum class CoverState
  {
    NotPresent,
    Closed,
    Moving,
    Open,
    Unknown,
    Error,
  };

  enum class CalibratorState
  {
    NotPresent,
    Off,
    NotReady,
    Ready,
    Unknown,
    Error,
  };

public:
  CoverCalibrator();
  ~CoverCalibrator();

  DeviceType device_type() override;

  virtual esp_err_t get_brightness(uint32_t *brightness) = 0;
  virtual esp_err_t get_calibratorstate(CalibratorState *state) = 0;
  virtual esp_err_t get_coverstate(CoverState *state) = 0;
  virtual esp_err_t get_maxbrightness(uint32_t *max) = 0;

  virtual esp_err_t turn_calibratoroff() = 0;
  virtual esp_err_t turn_calibratoron(int32_t brightness) = 0;
  virtual esp_err_t closecover() = 0;
  virtual esp_err_t opencover() = 0;
  virtual esp_err_t haltcover() = 0;
};

class Dome : public Device
{
public:
  enum class ShutterState
  {
    Open,
    Closed,
    Opening,
    Closing,
    Error,
  };

public:
  Dome();
  ~Dome();

  DeviceType device_type() override;

  virtual esp_err_t get_altitude(float *altitude) = 0;
  virtual esp_err_t get_athome(bool *athome) = 0;
  virtual esp_err_t get_atpark(bool *atpark) = 0;
  virtual esp_err_t get_azimuth(float *azimuth) = 0;
  virtual esp_err_t get_canfindhome(bool *canfindhome) = 0;
  virtual esp_err_t get_canpark(bool *canpark) = 0;
  virtual esp_err_t get_cansetaltitude(bool *cansetaltitude) = 0;
  virtual esp_err_t get_cansetazimuth(bool *cansetazimuth) = 0;
  virtual esp_err_t get_cansetpark(bool *cansetpark) = 0;
  virtual esp_err_t get_cansetshutter(bool *cansetshutter) = 0;
  virtual esp_err_t get_canslave(bool *canslave) = 0;
  virtual esp_err_t get_cansyncazimuth(bool *cansyncazimuth) = 0;
  virtual esp_err_t get_shutterstatus(ShutterState *shutterstatus) = 0;
  virtual esp_err_t get_slaved(bool *slaved) = 0;
  virtual esp_err_t put_slaved(bool slaved) = 0;
  virtual esp_err_t get_slewing(bool *slewing) = 0;
  virtual esp_err_t put_abortslew() = 0;
  virtual esp_err_t put_closeshutter() = 0;
  virtual esp_err_t put_findhome() = 0;
  virtual esp_err_t put_openshutter() = 0;
  virtual esp_err_t put_park() = 0;
  virtual esp_err_t put_setpark() = 0;
  virtual esp_err_t put_slewtoaltitude(float altitude) = 0;
  virtual esp_err_t put_slewtoazimuth(float azimuth) = 0;
  virtual esp_err_t put_synctoazimuth(float azimuth) = 0;
};

class FilterWheel : public Device
{
public:
  FilterWheel();
  ~FilterWheel();

  DeviceType device_type() override;

  virtual esp_err_t get_focusoffsets(std::vector<int32_t> &offsets) = 0;
  virtual esp_err_t get_names(std::vector<std::string> &names) = 0;
  virtual esp_err_t get_position(int32_t *position) = 0;
  virtual esp_err_t put_position(int32_t position) = 0;
};

class Focuser : public Device
{
public:
  Focuser();
  ~Focuser();

  DeviceType device_type() override;

  virtual esp_err_t get_absolute(bool *absolute) = 0;
  virtual esp_err_t get_ismoving(bool *ismoving) = 0;
  virtual esp_err_t get_maxincrement(int32_t *maxincrement) = 0;
  virtual esp_err_t get_maxstep(int32_t *maxstep) = 0;
  virtual esp_err_t get_position(int32_t *position) = 0;
  virtual esp_err_t get_stepsize(int32_t *stepsize) = 0;
  virtual esp_err_t get_tempcomp(bool *tempcomp) = 0;
  virtual esp_err_t put_tempcomp(bool tempcomp) = 0;
  virtual esp_err_t get_tempcompavailable(bool *tempcompavailable) = 0;
  virtual esp_err_t get_temperature(double *temperature) = 0;
  virtual esp_err_t put_halt() = 0;
  virtual esp_err_t put_move(int32_t position) = 0;
};

class ObservingConditions : public Device
{
public:
  ObservingConditions();
  ~ObservingConditions();

  DeviceType device_type() override;

  virtual esp_err_t get_averageperiod(double *averageperiod) = 0;
  virtual esp_err_t put_averageperiod(double averageperiod) = 0;
  virtual esp_err_t get_cloudcover(double *cloudcover) = 0;
  virtual esp_err_t get_dewpoint(double *dewpoint) = 0;
  virtual esp_err_t get_humidity(double *humidity) = 0;
  virtual esp_err_t get_pressure(double *pressure) = 0;
  virtual esp_err_t get_rainrate(double *rainrate) = 0;
  virtual esp_err_t get_skybrightness(double *skybrightness) = 0;
  virtual esp_err_t get_skyquality(double *skyquality) = 0;
  virtual esp_err_t get_skytemperature(double *skytemperature) = 0;
  virtual esp_err_t get_starfwhm(double *starfwhm) = 0;
  virtual esp_err_t get_temperature(double *temperature) = 0;
  virtual esp_err_t get_winddirection(double *winddirection) = 0;
  virtual esp_err_t get_windgust(double *windgust) = 0;
  virtual esp_err_t get_windspeed(double *windspeed) = 0;
  virtual esp_err_t put_refresh() = 0;
  virtual esp_err_t get_sensordescription(const char *sensorname, char *buf, size_t len) = 0;
  virtual esp_err_t get_timesincelastupdate(double *timesincelastupdate) = 0;
};

class Rotator : public Device
{
public:
  Rotator();
  ~Rotator();

  DeviceType device_type() override;

  virtual esp_err_t get_canreverse(bool *canreverse) = 0;
  virtual esp_err_t get_ismoving(bool *ismoving) = 0;
  virtual esp_err_t get_mechanicalposition(double *mechanicalposition) = 0;
  virtual esp_err_t get_position(double *position) = 0;
  virtual esp_err_t get_reverse(bool *reverse) = 0;
  virtual esp_err_t put_reverse(bool reverse) = 0;
  virtual esp_err_t get_stepsize(double *stepsize) = 0;
  virtual esp_err_t get_targetposition(double *targetposition) = 0;
  virtual esp_err_t put_halt() = 0;
  virtual esp_err_t put_move(double position) = 0;
  virtual esp_err_t put_moveabsolute(double position) = 0;
  virtual esp_err_t put_movemechanical(double position) = 0;
  virtual esp_err_t put_sync(double position) = 0;
};

class SafetyMonitor : public Device
{
public:
  SafetyMonitor();
  ~SafetyMonitor();

  DeviceType device_type() override;

  virtual esp_err_t get_issafe(bool *issafe) = 0;
};

class Switch : public Device
{
public:
  Switch();
  ~Switch();

  DeviceType device_type() override;

  virtual esp_err_t get_maxswitch(int32_t *maxswitch) = 0;
  virtual esp_err_t get_canwrite(int32_t id, bool *canwrite) = 0;
  virtual esp_err_t get_getswitch(int32_t id, bool *getswitch) = 0;
  virtual esp_err_t get_getswitchdescription(int32_t id, char *buf, size_t len) = 0;
  virtual esp_err_t get_getswitchname(int32_t id, char *buf, size_t len) = 0;
  virtual esp_err_t get_getswitchvalue(int32_t id, double *value) = 0;
  virtual esp_err_t get_minswitchvalue(int32_t id, double *value) = 0;
  virtual esp_err_t get_maxswitchvalue(int32_t id, double *value) = 0;
  virtual esp_err_t put_setswitch(int32_t id, bool value) = 0;
  virtual esp_err_t put_setswitchname(int32_t id, const char *name) = 0;
  virtual esp_err_t put_setswitchvalue(int32_t id, double value) = 0;
  virtual esp_err_t get_switchstep(int32_t id, double *switchstep) = 0;
};

class Telescope : public Device
{
public:
  Telescope();
  ~Telescope();

  DeviceType device_type() override;
};

} // namespace AlpacaServer

#endif // __ALPACA_SERVER_DEVICE_H__
