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

// Internal — used by the response path in api.cpp. Copies the pending
// per-call error detail (see Device::set_error_detail) into buf and clears
// it; returns the number of characters copied, 0 when no detail is pending.
size_t take_error_detail(char *buf, size_t len);

// Internal — drops any pending per-call error detail.
void clear_error_detail();

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

protected:
  // Explain the error you are about to return: call immediately before
  // returning a non-OK Alpaca error code from a device method, and the
  // response for that call reports ErrorMessage as
  // "<standard message>: <detail>". The detail is consumed (cleared) when
  // that response is built, so it never outlives the call that set it; when
  // no detail is set, responses are unchanged. A single pending slot is
  // safe because esp_http_server dispatches every URI handler on its one
  // server task and this library never defers handler work, so a device
  // method and the response built from its return value always run
  // back-to-back on that task.
  static void set_error_detail(const char *detail);

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

  virtual esp_err_t get_altitude(double *altitude) = 0;
  virtual esp_err_t get_athome(bool *athome) = 0;
  virtual esp_err_t get_atpark(bool *atpark) = 0;
  virtual esp_err_t get_azimuth(double *azimuth) = 0;
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
  virtual esp_err_t put_slewtoaltitude(double altitude) = 0;
  virtual esp_err_t put_slewtoazimuth(double azimuth) = 0;
  virtual esp_err_t put_synctoazimuth(double azimuth) = 0;
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
  enum class AlignmentMode
  {
    AltAz = 0,
    Polar = 1,
    GermanPolar = 2,
  };

  struct AxisRate
  {
    double min;
    double max;
  };

  enum SideOfPier
  {
    East = 0,
    West = 1,
    Unknown = -1,
  };

  enum EquatorialSystem
  {
    Other = 0,
    Topocentric = 1,
    J2000 = 2,
    J2050 = 3,
    B1950 = 4,
  };

  enum TrackingRate
  {
    Sidereal = 0,
    Lunar = 1,
    Solar = 2,
    King = 3,
  };

  enum TelescopeAxis
  {
    Primary = 0,
    Secondary = 1,
    Tertiary = 2,
  };

  enum GuideDirection
  {
    GuideNorth = 0,
    GuideSouth = 1,
    GuideEast = 2,
    GuideWest = 3,
  };

public:
  Telescope();
  ~Telescope();

  DeviceType device_type() override;

  virtual esp_err_t get_alignmentmode(AlignmentMode *alignmentmode) = 0;
  virtual esp_err_t get_altitude(double *altitude) = 0;
  virtual esp_err_t get_aperturearea(double *aperture) = 0;
  virtual esp_err_t get_aperturediameter(double *aperture) = 0;
  virtual esp_err_t get_athome(bool *athome) = 0;
  virtual esp_err_t get_atpark(bool *atpark) = 0;
  virtual esp_err_t get_azimuth(double *azimuth) = 0;
  virtual esp_err_t get_canfindhome(bool *canfindhome) = 0;
  virtual esp_err_t get_canpark(bool *canpark) = 0;
  virtual esp_err_t get_canpulseguide(bool *canpulseguide) = 0;
  virtual esp_err_t get_cansetdeclinationrate(bool *cansetdeclinationrate) = 0;
  virtual esp_err_t get_cansetguiderates(bool *cansetguiderates) = 0;
  virtual esp_err_t get_cansetpark(bool *cansetpark) = 0;
  virtual esp_err_t get_cansetpierside(bool *cansetpierside) = 0;
  virtual esp_err_t get_cansetrightascensionrate(bool *cansetrightascensionrate) = 0;
  virtual esp_err_t get_cansettracking(bool *cansettracking) = 0;
  virtual esp_err_t get_canslew(bool *canslew) = 0;
  virtual esp_err_t get_canslewaltaz(bool *canslewaltaz) = 0;
  virtual esp_err_t get_canslewaltazasync(bool *canslewaltazasync) = 0;
  virtual esp_err_t get_canslewasync(bool *canslewasync) = 0;
  virtual esp_err_t get_cansync(bool *cansync) = 0;
  virtual esp_err_t get_cansyncaltaz(bool *cansyncaltaz) = 0;
  virtual esp_err_t get_canunpark(bool *canunpark) = 0;
  virtual esp_err_t get_declination(double *declination) = 0;
  virtual esp_err_t get_declinationrate(double *declinationrate) = 0;
  virtual esp_err_t put_declinationrate(double declinationrate) = 0;
  virtual esp_err_t get_doesrefraction(bool *doesrefraction) = 0;
  virtual esp_err_t put_doesrefraction(bool doesrefraction) = 0;
  virtual esp_err_t get_equatorialsystem(EquatorialSystem *equatorialsystem) = 0;
  virtual esp_err_t get_focallength(double *focallength) = 0;
  virtual esp_err_t get_guideratedeclination(double *guideratedeclination) = 0;
  virtual esp_err_t put_guideratedeclination(double guideratedeclination) = 0;
  virtual esp_err_t get_guideraterightascension(double *guideraterightascension) = 0;
  virtual esp_err_t put_guideraterightascension(double guideraterightascension) = 0;
  virtual esp_err_t get_ispulseguiding(bool *ispulseguiding) = 0;
  virtual esp_err_t get_rightascension(double *rightascension) = 0;
  virtual esp_err_t get_rightascensionrate(double *rightascensionrate) = 0;
  virtual esp_err_t put_rightascensionrate(double rightascensionrate) = 0;
  virtual esp_err_t get_sideofpier(SideOfPier *sideofpier) = 0;
  virtual esp_err_t put_sideofpier(SideOfPier sideofpier) = 0;
  virtual esp_err_t get_siderealtime(double *siderealtime) = 0;
  virtual esp_err_t get_siteelevation(double *siteelevation) = 0;
  virtual esp_err_t put_siteelevation(double siteelevation) = 0;
  virtual esp_err_t get_sitelatitude(double *siteslatitude) = 0;
  virtual esp_err_t put_sitelatitude(double siteslatitude) = 0;
  virtual esp_err_t get_sitelongitude(double *sitelongitude) = 0;
  virtual esp_err_t put_sitelongitude(double sitelongitude) = 0;
  virtual esp_err_t get_slewing(bool *slewing) = 0;
  virtual esp_err_t get_slewsettletime(int32_t *slewsettletime) = 0;
  virtual esp_err_t put_slewsettletime(int32_t slewsettletime) = 0;
  virtual esp_err_t get_targetdeclination(double *targetdeclination) = 0;
  virtual esp_err_t put_targetdeclination(double targetdeclination) = 0;
  virtual esp_err_t get_targetrightascension(double *targetrightascension) = 0;
  virtual esp_err_t put_targetrightascension(double targetrightascension) = 0;
  virtual esp_err_t get_tracking(bool *tracking) = 0;
  virtual esp_err_t put_tracking(bool tracking) = 0;
  virtual esp_err_t get_trackingrate(TrackingRate *trackingrate) = 0;
  virtual esp_err_t put_trackingrate(TrackingRate trackingrate) = 0;
  virtual esp_err_t get_trackingrates(std::vector<TrackingRate> &trackingrates) = 0;
  virtual esp_err_t get_utcdate(std::string &utcdate) = 0;       // ISO 8601
  virtual esp_err_t put_utcdate(const std::string &utcdate) = 0; // ISO 8601
  virtual esp_err_t put_abortslew() = 0;
  virtual esp_err_t get_axisrates(TelescopeAxis axis, std::vector<AxisRate> &rates) = 0;
  virtual esp_err_t get_canmoveaxis(TelescopeAxis axis, bool *canmoveaxis) = 0;
  virtual esp_err_t get_destinationsideofpier(double rightascension, double declination, SideOfPier *sideofpier) = 0;
  virtual esp_err_t put_findhome() = 0;
  virtual esp_err_t put_moveaxis(TelescopeAxis axis, double rate) = 0;
  virtual esp_err_t put_park() = 0;
  virtual esp_err_t put_pulseguide(GuideDirection direction, int32_t duration) = 0;
  virtual esp_err_t put_setpark() = 0;
  virtual esp_err_t put_slewtoaltazasync(double altitude, double azimuth) = 0;
  virtual esp_err_t put_slewtocoordinatesasync(double rightascension, double declination) = 0;
  virtual esp_err_t put_slewtotargetasync() = 0;
  virtual esp_err_t put_synctoaltaz(double altitude, double azimuth) = 0;
  virtual esp_err_t put_synctocoordinates(double rightascension, double declination) = 0;
  virtual esp_err_t put_synctotarget() = 0;
  virtual esp_err_t put_unpark() = 0;
};

} // namespace AlpacaServer

#endif // __ALPACA_SERVER_DEVICE_H__
