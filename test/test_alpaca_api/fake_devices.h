// Fake devices for the native tests: one per Alpaca device type. Every
// type-specific method records its name in last_call and returns ret, so a
// test can check which device method a request reached and choose the
// result. The common Device members return real values.
#pragma once

#include <alpaca_server/api.h>
#include <stdio.h>
#include <string>
#include <vector>

using namespace AlpacaServer;

template <class Base> class FakeDevice : public Base
{
public:
  esp_err_t ret = ALPACA_OK;
  std::string last_call;
  std::string name = "Fake device";
  bool is_connected = true;
  uint32_t interface_version = 1;
  std::vector<std::string> supported_actions;

  esp_err_t action(const char *action, const char *parameters, char *buf, size_t len) override
  {
    return record("action");
  }

  esp_err_t commandblind(const char *command, bool raw) override
  {
    return record("commandblind");
  }

  esp_err_t commandbool(const char *command, bool raw, bool *resp) override
  {
    return record("commandbool");
  }

  esp_err_t commandstring(const char *action, bool raw, char *buf, size_t len) override
  {
    return record("commandstring");
  }

  esp_err_t get_connected(bool *connected) override
  {
    *connected = is_connected;
    return ALPACA_OK;
  }

  esp_err_t set_connected(bool connected) override
  {
    is_connected = connected;
    return ALPACA_OK;
  }

  esp_err_t get_description(char *buf, size_t len) override
  {
    snprintf(buf, len, "Fake description");
    return ALPACA_OK;
  }

  esp_err_t get_driverinfo(char *buf, size_t len) override
  {
    snprintf(buf, len, "Fake driver info");
    return ALPACA_OK;
  }

  esp_err_t get_driverversion(char *buf, size_t len) override
  {
    snprintf(buf, len, "1.0");
    return ALPACA_OK;
  }

  esp_err_t get_interfaceversion(uint32_t *version) override
  {
    *version = interface_version;
    return ALPACA_OK;
  }

  esp_err_t get_name(char *buf, size_t len) override
  {
    snprintf(buf, len, "%s", name.c_str());
    return ALPACA_OK;
  }

  esp_err_t get_supportedactions(std::vector<std::string> &actions) override
  {
    actions = supported_actions;
    return ALPACA_OK;
  }

protected:
  esp_err_t record(const char *method)
  {
    last_call = method;
    return ret;
  }
};

class FakeCamera : public FakeDevice<Camera>
{
public:
};

class FakeCoverCalibrator : public FakeDevice<CoverCalibrator>
{
public:
  esp_err_t get_brightness(uint32_t *brightness) override
  {
    return record("get_brightness");
  }

  esp_err_t get_calibratorstate(CalibratorState *state) override
  {
    return record("get_calibratorstate");
  }

  esp_err_t get_coverstate(CoverState *state) override
  {
    return record("get_coverstate");
  }

  esp_err_t get_maxbrightness(uint32_t *max) override
  {
    return record("get_maxbrightness");
  }

  esp_err_t turn_calibratoroff() override
  {
    return record("turn_calibratoroff");
  }

  esp_err_t turn_calibratoron(int32_t brightness) override
  {
    return record("turn_calibratoron");
  }

  esp_err_t closecover() override
  {
    return record("closecover");
  }

  esp_err_t opencover() override
  {
    return record("opencover");
  }

  esp_err_t haltcover() override
  {
    return record("haltcover");
  }
};

class FakeDome : public FakeDevice<Dome>
{
public:
  esp_err_t get_altitude(double *altitude) override
  {
    return record("get_altitude");
  }

  esp_err_t get_athome(bool *athome) override
  {
    return record("get_athome");
  }

  esp_err_t get_atpark(bool *atpark) override
  {
    return record("get_atpark");
  }

  esp_err_t get_azimuth(double *azimuth) override
  {
    return record("get_azimuth");
  }

  esp_err_t get_canfindhome(bool *canfindhome) override
  {
    return record("get_canfindhome");
  }

  esp_err_t get_canpark(bool *canpark) override
  {
    return record("get_canpark");
  }

  esp_err_t get_cansetaltitude(bool *cansetaltitude) override
  {
    return record("get_cansetaltitude");
  }

  esp_err_t get_cansetazimuth(bool *cansetazimuth) override
  {
    return record("get_cansetazimuth");
  }

  esp_err_t get_cansetpark(bool *cansetpark) override
  {
    return record("get_cansetpark");
  }

  esp_err_t get_cansetshutter(bool *cansetshutter) override
  {
    return record("get_cansetshutter");
  }

  esp_err_t get_canslave(bool *canslave) override
  {
    return record("get_canslave");
  }

  esp_err_t get_cansyncazimuth(bool *cansyncazimuth) override
  {
    return record("get_cansyncazimuth");
  }

  esp_err_t get_shutterstatus(ShutterState *shutterstatus) override
  {
    return record("get_shutterstatus");
  }

  esp_err_t get_slaved(bool *slaved) override
  {
    return record("get_slaved");
  }

  esp_err_t put_slaved(bool slaved) override
  {
    return record("put_slaved");
  }

  esp_err_t get_slewing(bool *slewing) override
  {
    return record("get_slewing");
  }

  esp_err_t put_abortslew() override
  {
    return record("put_abortslew");
  }

  esp_err_t put_closeshutter() override
  {
    return record("put_closeshutter");
  }

  esp_err_t put_findhome() override
  {
    return record("put_findhome");
  }

  esp_err_t put_openshutter() override
  {
    return record("put_openshutter");
  }

  esp_err_t put_park() override
  {
    return record("put_park");
  }

  esp_err_t put_setpark() override
  {
    return record("put_setpark");
  }

  esp_err_t put_slewtoaltitude(double altitude) override
  {
    return record("put_slewtoaltitude");
  }

  esp_err_t put_slewtoazimuth(double azimuth) override
  {
    return record("put_slewtoazimuth");
  }

  esp_err_t put_synctoazimuth(double azimuth) override
  {
    return record("put_synctoazimuth");
  }
};

class FakeFilterWheel : public FakeDevice<FilterWheel>
{
public:
  esp_err_t get_focusoffsets(std::vector<int32_t> &offsets) override
  {
    return record("get_focusoffsets");
  }

  esp_err_t get_names(std::vector<std::string> &names) override
  {
    return record("get_names");
  }

  esp_err_t get_position(int32_t *position) override
  {
    return record("get_position");
  }

  esp_err_t put_position(int32_t position) override
  {
    return record("put_position");
  }
};

class FakeFocuser : public FakeDevice<Focuser>
{
public:
  esp_err_t get_absolute(bool *absolute) override
  {
    return record("get_absolute");
  }

  esp_err_t get_ismoving(bool *ismoving) override
  {
    return record("get_ismoving");
  }

  esp_err_t get_maxincrement(int32_t *maxincrement) override
  {
    return record("get_maxincrement");
  }

  esp_err_t get_maxstep(int32_t *maxstep) override
  {
    return record("get_maxstep");
  }

  esp_err_t get_position(int32_t *position) override
  {
    return record("get_position");
  }

  esp_err_t get_stepsize(int32_t *stepsize) override
  {
    return record("get_stepsize");
  }

  esp_err_t get_tempcomp(bool *tempcomp) override
  {
    return record("get_tempcomp");
  }

  esp_err_t put_tempcomp(bool tempcomp) override
  {
    return record("put_tempcomp");
  }

  esp_err_t get_tempcompavailable(bool *tempcompavailable) override
  {
    return record("get_tempcompavailable");
  }

  esp_err_t get_temperature(double *temperature) override
  {
    return record("get_temperature");
  }

  esp_err_t put_halt() override
  {
    return record("put_halt");
  }

  esp_err_t put_move(int32_t position) override
  {
    return record("put_move");
  }
};

class FakeObservingConditions : public FakeDevice<ObservingConditions>
{
public:
  esp_err_t get_averageperiod(double *averageperiod) override
  {
    return record("get_averageperiod");
  }

  esp_err_t put_averageperiod(double averageperiod) override
  {
    return record("put_averageperiod");
  }

  esp_err_t get_cloudcover(double *cloudcover) override
  {
    return record("get_cloudcover");
  }

  esp_err_t get_dewpoint(double *dewpoint) override
  {
    return record("get_dewpoint");
  }

  esp_err_t get_humidity(double *humidity) override
  {
    return record("get_humidity");
  }

  esp_err_t get_pressure(double *pressure) override
  {
    return record("get_pressure");
  }

  esp_err_t get_rainrate(double *rainrate) override
  {
    return record("get_rainrate");
  }

  esp_err_t get_skybrightness(double *skybrightness) override
  {
    return record("get_skybrightness");
  }

  esp_err_t get_skyquality(double *skyquality) override
  {
    return record("get_skyquality");
  }

  esp_err_t get_skytemperature(double *skytemperature) override
  {
    return record("get_skytemperature");
  }

  esp_err_t get_starfwhm(double *starfwhm) override
  {
    return record("get_starfwhm");
  }

  esp_err_t get_temperature(double *temperature) override
  {
    return record("get_temperature");
  }

  esp_err_t get_winddirection(double *winddirection) override
  {
    return record("get_winddirection");
  }

  esp_err_t get_windgust(double *windgust) override
  {
    return record("get_windgust");
  }

  esp_err_t get_windspeed(double *windspeed) override
  {
    return record("get_windspeed");
  }

  esp_err_t put_refresh() override
  {
    return record("put_refresh");
  }

  esp_err_t get_sensordescription(const char *sensorname, char *buf, size_t len) override
  {
    return record("get_sensordescription");
  }

  esp_err_t get_timesincelastupdate(const char *sensorname, double *timesincelastupdate) override
  {
    return record("get_timesincelastupdate");
  }
};

class FakeRotator : public FakeDevice<Rotator>
{
public:
  esp_err_t get_canreverse(bool *canreverse) override
  {
    return record("get_canreverse");
  }

  esp_err_t get_ismoving(bool *ismoving) override
  {
    return record("get_ismoving");
  }

  esp_err_t get_mechanicalposition(double *mechanicalposition) override
  {
    return record("get_mechanicalposition");
  }

  esp_err_t get_position(double *position) override
  {
    return record("get_position");
  }

  esp_err_t get_reverse(bool *reverse) override
  {
    return record("get_reverse");
  }

  esp_err_t put_reverse(bool reverse) override
  {
    return record("put_reverse");
  }

  esp_err_t get_stepsize(double *stepsize) override
  {
    return record("get_stepsize");
  }

  esp_err_t get_targetposition(double *targetposition) override
  {
    return record("get_targetposition");
  }

  esp_err_t put_halt() override
  {
    return record("put_halt");
  }

  esp_err_t put_move(double position) override
  {
    return record("put_move");
  }

  esp_err_t put_moveabsolute(double position) override
  {
    return record("put_moveabsolute");
  }

  esp_err_t put_movemechanical(double position) override
  {
    return record("put_movemechanical");
  }

  esp_err_t put_sync(double position) override
  {
    return record("put_sync");
  }
};

class FakeSafetyMonitor : public FakeDevice<SafetyMonitor>
{
public:
  esp_err_t get_issafe(bool *issafe) override
  {
    return record("get_issafe");
  }
};

class FakeSwitch : public FakeDevice<Switch>
{
public:
  int32_t last_id = -1;
  double last_value = 0;

  esp_err_t get_maxswitch(int32_t *maxswitch) override
  {
    return record("get_maxswitch");
  }

  esp_err_t get_canwrite(int32_t id, bool *canwrite) override
  {
    return record("get_canwrite");
  }

  esp_err_t get_getswitch(int32_t id, bool *getswitch) override
  {
    last_id = id;
    return record("get_getswitch");
  }

  esp_err_t get_getswitchdescription(int32_t id, char *buf, size_t len) override
  {
    return record("get_getswitchdescription");
  }

  esp_err_t get_getswitchname(int32_t id, char *buf, size_t len) override
  {
    return record("get_getswitchname");
  }

  esp_err_t get_getswitchvalue(int32_t id, double *value) override
  {
    return record("get_getswitchvalue");
  }

  esp_err_t get_minswitchvalue(int32_t id, double *value) override
  {
    return record("get_minswitchvalue");
  }

  esp_err_t get_maxswitchvalue(int32_t id, double *value) override
  {
    return record("get_maxswitchvalue");
  }

  esp_err_t put_setswitch(int32_t id, bool value) override
  {
    last_id = id;
    return record("put_setswitch");
  }

  esp_err_t put_setswitchname(int32_t id, const char *name) override
  {
    return record("put_setswitchname");
  }

  esp_err_t put_setswitchvalue(int32_t id, double value) override
  {
    last_id = id;
    last_value = value;
    return record("put_setswitchvalue");
  }

  esp_err_t get_switchstep(int32_t id, double *switchstep) override
  {
    return record("get_switchstep");
  }
};

class FakeTelescope : public FakeDevice<Telescope>
{
public:
  std::string utcdate;

  esp_err_t get_alignmentmode(AlignmentMode *alignmentmode) override
  {
    return record("get_alignmentmode");
  }

  esp_err_t get_altitude(double *altitude) override
  {
    return record("get_altitude");
  }

  esp_err_t get_aperturearea(double *aperture) override
  {
    return record("get_aperturearea");
  }

  esp_err_t get_aperturediameter(double *aperture) override
  {
    return record("get_aperturediameter");
  }

  esp_err_t get_athome(bool *athome) override
  {
    return record("get_athome");
  }

  esp_err_t get_atpark(bool *atpark) override
  {
    return record("get_atpark");
  }

  esp_err_t get_azimuth(double *azimuth) override
  {
    return record("get_azimuth");
  }

  esp_err_t get_canfindhome(bool *canfindhome) override
  {
    return record("get_canfindhome");
  }

  esp_err_t get_canpark(bool *canpark) override
  {
    return record("get_canpark");
  }

  esp_err_t get_canpulseguide(bool *canpulseguide) override
  {
    return record("get_canpulseguide");
  }

  esp_err_t get_cansetdeclinationrate(bool *cansetdeclinationrate) override
  {
    return record("get_cansetdeclinationrate");
  }

  esp_err_t get_cansetguiderates(bool *cansetguiderates) override
  {
    return record("get_cansetguiderates");
  }

  esp_err_t get_cansetpark(bool *cansetpark) override
  {
    return record("get_cansetpark");
  }

  esp_err_t get_cansetpierside(bool *cansetpierside) override
  {
    return record("get_cansetpierside");
  }

  esp_err_t get_cansetrightascensionrate(bool *cansetrightascensionrate) override
  {
    return record("get_cansetrightascensionrate");
  }

  esp_err_t get_cansettracking(bool *cansettracking) override
  {
    return record("get_cansettracking");
  }

  esp_err_t get_canslew(bool *canslew) override
  {
    return record("get_canslew");
  }

  esp_err_t get_canslewaltaz(bool *canslewaltaz) override
  {
    return record("get_canslewaltaz");
  }

  esp_err_t get_canslewaltazasync(bool *canslewaltazasync) override
  {
    return record("get_canslewaltazasync");
  }

  esp_err_t get_canslewasync(bool *canslewasync) override
  {
    return record("get_canslewasync");
  }

  esp_err_t get_cansync(bool *cansync) override
  {
    return record("get_cansync");
  }

  esp_err_t get_cansyncaltaz(bool *cansyncaltaz) override
  {
    return record("get_cansyncaltaz");
  }

  esp_err_t get_canunpark(bool *canunpark) override
  {
    return record("get_canunpark");
  }

  esp_err_t get_declination(double *declination) override
  {
    return record("get_declination");
  }

  esp_err_t get_declinationrate(double *declinationrate) override
  {
    return record("get_declinationrate");
  }

  esp_err_t put_declinationrate(double declinationrate) override
  {
    return record("put_declinationrate");
  }

  esp_err_t get_doesrefraction(bool *doesrefraction) override
  {
    return record("get_doesrefraction");
  }

  esp_err_t put_doesrefraction(bool doesrefraction) override
  {
    return record("put_doesrefraction");
  }

  esp_err_t get_equatorialsystem(EquatorialSystem *equatorialsystem) override
  {
    return record("get_equatorialsystem");
  }

  esp_err_t get_focallength(double *focallength) override
  {
    return record("get_focallength");
  }

  esp_err_t get_guideratedeclination(double *guideratedeclination) override
  {
    return record("get_guideratedeclination");
  }

  esp_err_t put_guideratedeclination(double guideratedeclination) override
  {
    return record("put_guideratedeclination");
  }

  esp_err_t get_guideraterightascension(double *guideraterightascension) override
  {
    return record("get_guideraterightascension");
  }

  esp_err_t put_guideraterightascension(double guideraterightascension) override
  {
    return record("put_guideraterightascension");
  }

  esp_err_t get_ispulseguiding(bool *ispulseguiding) override
  {
    return record("get_ispulseguiding");
  }

  esp_err_t get_rightascension(double *rightascension) override
  {
    return record("get_rightascension");
  }

  esp_err_t get_rightascensionrate(double *rightascensionrate) override
  {
    return record("get_rightascensionrate");
  }

  esp_err_t put_rightascensionrate(double rightascensionrate) override
  {
    return record("put_rightascensionrate");
  }

  esp_err_t get_sideofpier(SideOfPier *sideofpier) override
  {
    return record("get_sideofpier");
  }

  esp_err_t put_sideofpier(SideOfPier sideofpier) override
  {
    return record("put_sideofpier");
  }

  esp_err_t get_siderealtime(double *siderealtime) override
  {
    return record("get_siderealtime");
  }

  esp_err_t get_siteelevation(double *siteelevation) override
  {
    return record("get_siteelevation");
  }

  esp_err_t put_siteelevation(double siteelevation) override
  {
    return record("put_siteelevation");
  }

  esp_err_t get_sitelatitude(double *siteslatitude) override
  {
    return record("get_sitelatitude");
  }

  esp_err_t put_sitelatitude(double siteslatitude) override
  {
    return record("put_sitelatitude");
  }

  esp_err_t get_sitelongitude(double *sitelongitude) override
  {
    return record("get_sitelongitude");
  }

  esp_err_t put_sitelongitude(double sitelongitude) override
  {
    return record("put_sitelongitude");
  }

  esp_err_t get_slewing(bool *slewing) override
  {
    return record("get_slewing");
  }

  esp_err_t get_slewsettletime(int32_t *slewsettletime) override
  {
    return record("get_slewsettletime");
  }

  esp_err_t put_slewsettletime(int32_t slewsettletime) override
  {
    return record("put_slewsettletime");
  }

  esp_err_t get_targetdeclination(double *targetdeclination) override
  {
    return record("get_targetdeclination");
  }

  esp_err_t put_targetdeclination(double targetdeclination) override
  {
    return record("put_targetdeclination");
  }

  esp_err_t get_targetrightascension(double *targetrightascension) override
  {
    return record("get_targetrightascension");
  }

  esp_err_t put_targetrightascension(double targetrightascension) override
  {
    return record("put_targetrightascension");
  }

  esp_err_t get_tracking(bool *tracking) override
  {
    return record("get_tracking");
  }

  esp_err_t put_tracking(bool tracking) override
  {
    return record("put_tracking");
  }

  esp_err_t get_trackingrate(TrackingRate *trackingrate) override
  {
    return record("get_trackingrate");
  }

  esp_err_t put_trackingrate(TrackingRate trackingrate) override
  {
    return record("put_trackingrate");
  }

  esp_err_t get_trackingrates(std::vector<TrackingRate> &trackingrates) override
  {
    return record("get_trackingrates");
  }

  esp_err_t get_utcdate(std::string &utcdate) override
  {
    return record("get_utcdate");
  }

  esp_err_t put_utcdate(const std::string &value) override
  {
    utcdate = value;
    return record("put_utcdate");
  }

  esp_err_t put_abortslew() override
  {
    return record("put_abortslew");
  }

  esp_err_t get_axisrates(TelescopeAxis axis, std::vector<AxisRate> &rates) override
  {
    return record("get_axisrates");
  }

  esp_err_t get_canmoveaxis(TelescopeAxis axis, bool *canmoveaxis) override
  {
    return record("get_canmoveaxis");
  }

  esp_err_t get_destinationsideofpier(double rightascension, double declination, SideOfPier *sideofpier) override
  {
    return record("get_destinationsideofpier");
  }

  esp_err_t put_findhome() override
  {
    return record("put_findhome");
  }

  esp_err_t put_moveaxis(TelescopeAxis axis, double rate) override
  {
    return record("put_moveaxis");
  }

  esp_err_t put_park() override
  {
    return record("put_park");
  }

  esp_err_t put_pulseguide(GuideDirection direction, int32_t duration) override
  {
    return record("put_pulseguide");
  }

  esp_err_t put_setpark() override
  {
    return record("put_setpark");
  }

  esp_err_t put_slewtoaltazasync(double altitude, double azimuth) override
  {
    return record("put_slewtoaltazasync");
  }

  esp_err_t put_slewtocoordinatesasync(double rightascension, double declination) override
  {
    return record("put_slewtocoordinatesasync");
  }

  esp_err_t put_slewtotargetasync() override
  {
    return record("put_slewtotargetasync");
  }

  esp_err_t put_synctoaltaz(double altitude, double azimuth) override
  {
    return record("put_synctoaltaz");
  }

  esp_err_t put_synctocoordinates(double rightascension, double declination) override
  {
    return record("put_synctocoordinates");
  }

  esp_err_t put_synctotarget() override
  {
    return record("put_synctotarget");
  }

  esp_err_t put_unpark() override
  {
    return record("put_unpark");
  }
};
