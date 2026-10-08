// ConformU's protocol checks for every endpoint it calls, device type by
// device type. Each helper below sends the same requests as the ConformU
// helper of the same name (GetNoParameters, GetOneParameter, ...) in
// AlpacaProtocolTestManager.cs, and expects the strict-mode results. A test
// collects every failing request for its device type before it fails, so
// one run lists them all.

#include "test_helpers.h"

#include <ctype.h>

namespace
{
const char *BAD_VALUE = "asduio6fghZZ";
const char *CLIENT_IDS_LOWER_ID = "clientid=12345&ClientTransactionID=67890";
const char *CLIENT_IDS_LOWER_TRANSACTION = "ClientID=12345&clienttransactionid=67890";

struct Param
{
  const char *name;
  const char *value;
};

// "ClientID" -> "cLIENTid": what ConformU's InvertCasing() does.
std::string invert_casing(const std::string &s)
{
  std::string out = s;
  for (char &c : out)
  {
    c = isupper((unsigned char)c) ? (char)tolower((unsigned char)c) : (char)toupper((unsigned char)c);
  }
  return out;
}

std::string join(const std::vector<Param> &params, const char *client_ids)
{
  std::string out = client_ids;
  for (const Param &p : params)
  {
    out += std::string("&") + p.name + "=" + p.value;
  }
  return out;
}

std::string describe(const FakeResponse &r)
{
  std::string out = "status " + std::to_string(r.status);
  cJSON *error_number = field(r, "ErrorNumber");
  if (error_number)
  {
    out += ", ErrorNumber " + std::to_string((int)cJSON_GetNumberValue(error_number));
  }
  if (r.handler_ret != ESP_OK)
  {
    out += ", handler returned " + std::to_string(r.handler_ret);
  }
  return out;
}

int transaction_id(const FakeResponse &r)
{
  cJSON *id = field(r, "ClientTransactionID");
  return cJSON_IsNumber(id) ? (int)cJSON_GetNumberValue(id) : -1;
}

class Checks
{
public:
  explicit Checks(const char *type) : _type(type)
  {
  }

  std::string path(const char *method) const
  {
    return std::string("/api/v1/") + _type + "/0/" + method;
  }

  void expect(bool ok, const char *method, const std::string &request, const FakeResponse &r)
  {
    if (!ok)
    {
      _failures.push_back(std::string(method) + " (" + request + "): " + describe(r));
    }
  }

  void expect_ok(const char *method, const std::string &request, const FakeResponse &r, bool want_value)
  {
    cJSON *error_number = field(r, "ErrorNumber");
    bool ok = r.status == 200 && r.json && (!error_number || cJSON_GetNumberValue(error_number) == 0) &&
              r.handler_ret == ESP_OK && (!want_value || field(r, "Value"));
    expect(ok, method, request, r);
  }

  void expect_bad_value(const char *method, const std::string &request, const FakeResponse &r)
  {
    bool ok = r.status == 400 ||
              (r.status == 200 && cJSON_GetNumberValue(field(r, "ErrorNumber")) == ALPACA_ERR_INVALID_VALUE);
    expect(ok, method, request, r);
  }

  void finish()
  {
    if (_failures.empty())
    {
      return;
    }
    std::string message = std::to_string(_failures.size()) + " failing request(s):";
    for (const std::string &f : _failures)
    {
      message += "\n  " + f;
    }
    TEST_FAIL_MESSAGE(message.c_str());
  }

private:
  const char *_type;
  std::vector<std::string> _failures;
};

void get_no_parameters(Checks &c, const char *method)
{
  std::string p = c.path(method);
  c.expect_ok(method, "good", get(p), true);
  c.expect_ok(method, "extra parameter", get(p, std::string(CLIENT_IDS) + "&ExtraParameter=Extra"), true);
  c.expect_ok(method, "lower-case clientid", get(p, CLIENT_IDS_LOWER_ID), true);
  FakeResponse r = get(p, CLIENT_IDS_LOWER_TRANSACTION);
  c.expect_ok(method, "lower-case clienttransactionid", r, true);
  c.expect(transaction_id(r) == 67890, method, "lower-case clienttransactionid is echoed", r);
}

void get_parameters(Checks &c, const char *method, std::vector<Param> params, bool test_bad_values = true)
{
  std::string p = c.path(method);
  c.expect_ok(method, "good", get(p, join(params, CLIENT_IDS)), true);
  c.expect_ok(method, "extra parameter", get(p, join(params, CLIENT_IDS) + "&ExtraParameter=Extra"), true);
  for (size_t i = 0; i < params.size(); i++)
  {
    std::vector<Param> changed = params;
    if (test_bad_values)
    {
      changed[i].value = BAD_VALUE;
      c.expect_bad_value(method, std::string("bad ") + params[i].name, get(p, join(changed, CLIENT_IDS)));
    }
    std::string inverted = invert_casing(params[i].name);
    changed = params;
    changed[i].name = inverted.c_str();
    c.expect_ok(method, "inverted casing " + inverted, get(p, join(changed, CLIENT_IDS)), true);
  }
  c.expect_ok(method, "lower-case clientid", get(p, join(params, CLIENT_IDS_LOWER_ID)), true);
  FakeResponse r = get(p, join(params, CLIENT_IDS_LOWER_TRANSACTION));
  c.expect_ok(method, "lower-case clienttransactionid", r, true);
  c.expect(transaction_id(r) == 67890, method, "lower-case clienttransactionid is echoed", r);
}

void put_parameters(Checks &c, const char *method, std::vector<Param> params = {}, bool test_bad_values = true)
{
  std::string p = c.path(method);
  c.expect_ok(method, "good", put(p, join(params, CLIENT_IDS)), false);
  c.expect_ok(method, "extra parameter", put(p, join(params, CLIENT_IDS) + "&ExtraParameter=Extra"), false);
  for (size_t i = 0; i < params.size(); i++)
  {
    std::vector<Param> changed = params;
    if (test_bad_values)
    {
      changed[i].value = BAD_VALUE;
      c.expect_bad_value(method, std::string("bad ") + params[i].name, put(p, join(changed, CLIENT_IDS)));
    }
    std::string inverted = invert_casing(params[i].name);
    changed = params;
    changed[i].name = inverted.c_str();
    FakeResponse r = put(p, join(changed, CLIENT_IDS));
    c.expect(r.status == 400, method, "inverted casing " + inverted, r);
  }
  c.expect_ok(method, "lower-case clientid", put(p, join(params, CLIENT_IDS_LOWER_ID)), false);
  FakeResponse r = put(p, join(params, CLIENT_IDS_LOWER_TRANSACTION));
  c.expect_ok(method, "lower-case clienttransactionid", r, false);
  c.expect(transaction_id(r) == 0, method, "lower-case clienttransactionid is ignored", r);
}

// The members every device type has (ConformU's TestCommon, plus the
// Platform 7 members it calls when the interface version allows them).
void common_members(Checks &c)
{
  const char *gets[] = {
    "connected",
    "description",
    "driverinfo",
    "driverversion",
    "interfaceversion",
    "name",
    "supportedactions",
    "devicestate",
    "connecting",
  };
  for (const char *method : gets)
  {
    get_no_parameters(c, method);
  }
  put_parameters(c, "connect");
  put_parameters(c, "disconnect");
}

template <class FakeType> void run_device(const char *type, void (*members)(Checks &))
{
  FakeType device;
  Server server({&device});
  Checks c(type);
  common_members(c);
  if (members)
  {
    members(c);
  }
  c.finish();
}

void camera_members(Checks &c)
{
  // Camera registers only the common routes so far; ConformU's camera calls
  // would all get 404. Nothing camera-specific to check yet.
  (void)c;
}

void covercalibrator_members(Checks &c)
{
  for (const char *m : {"brightness", "calibratorstate", "coverstate", "maxbrightness"})
  {
    get_no_parameters(c, m);
  }
  for (const char *m : {"calibratoroff", "opencover", "haltcover", "closecover"})
  {
    put_parameters(c, m);
  }
  put_parameters(c, "calibratoron", {{"Brightness", "50"}});
}

void dome_members(Checks &c)
{
  for (const char *m :
       {"altitude",
        "athome",
        "atpark",
        "azimuth",
        "canfindhome",
        "canpark",
        "cansetaltitude",
        "cansetazimuth",
        "cansetpark",
        "cansetshutter",
        "canslave",
        "cansyncazimuth",
        "shutterstatus",
        "slaved",
        "slewing"})
  {
    get_no_parameters(c, m);
  }
  put_parameters(c, "slaved", {{"Slaved", "False"}});
  put_parameters(c, "slewtoazimuth", {{"Azimuth", "180"}});
  put_parameters(c, "synctoazimuth", {{"Azimuth", "180"}});
  put_parameters(c, "slewtoaltitude", {{"Altitude", "45"}});
  for (const char *m : {"abortslew", "findhome", "openshutter", "closeshutter", "park", "setpark"})
  {
    put_parameters(c, m);
  }
}

void filterwheel_members(Checks &c)
{
  for (const char *m : {"focusoffsets", "names", "position"})
  {
    get_no_parameters(c, m);
  }
  put_parameters(c, "position", {{"Position", "0"}});
}

void focuser_members(Checks &c)
{
  for (const char *m :
       {"absolute",
        "ismoving",
        "maxincrement",
        "maxstep",
        "position",
        "stepsize",
        "tempcomp",
        "tempcompavailable",
        "temperature"})
  {
    get_no_parameters(c, m);
  }
  put_parameters(c, "tempcomp", {{"TempComp", "False"}});
  put_parameters(c, "move", {{"Position", "100"}});
  put_parameters(c, "halt");
}

void observingconditions_members(Checks &c)
{
  for (const char *m :
       {"averageperiod",
        "cloudcover",
        "dewpoint",
        "humidity",
        "pressure",
        "rainrate",
        "skybrightness",
        "skyquality",
        "skytemperature",
        "starfwhm",
        "temperature",
        "winddirection",
        "windgust",
        "windspeed"})
  {
    get_no_parameters(c, m);
  }
  put_parameters(c, "averageperiod", {{"AveragePeriod", "0"}});
  put_parameters(c, "refresh");
  // The library passes SensorName to the device, which decides whether a
  // name is valid, so the bad-value request is a device check, not a
  // library one.
  get_parameters(c, "sensordescription", {{"SensorName", "Pressure"}}, false);
  get_parameters(c, "timesincelastupdate", {{"SensorName", "Pressure"}}, false);
  get_parameters(c, "timesincelastupdate", {{"SensorName", ""}}, false);
}

void rotator_members(Checks &c)
{
  for (const char *m :
       {"canreverse", "ismoving", "mechanicalposition", "position", "reverse", "stepsize", "targetposition"})
  {
    get_no_parameters(c, m);
  }
  put_parameters(c, "reverse", {{"Reverse", "False"}});
  for (const char *m : {"move", "moveabsolute", "movemechanical", "sync"})
  {
    put_parameters(c, m, {{"Position", "10"}});
  }
  put_parameters(c, "halt");
}

void safetymonitor_members(Checks &c)
{
  get_no_parameters(c, "issafe");
}

void switch_members(Checks &c)
{
  get_no_parameters(c, "maxswitch");
  for (const char *m :
       {"canwrite",
        "getswitch",
        "getswitchdescription",
        "getswitchname",
        "getswitchvalue",
        "minswitchvalue",
        "maxswitchvalue",
        "switchstep"})
  {
    get_parameters(c, m, {{"Id", "0"}});
  }
  put_parameters(c, "setswitch", {{"Id", "0"}, {"State", "True"}});
  put_parameters(c, "setswitchvalue", {{"Id", "0"}, {"Value", "0"}});
  // ConformU sends no bad value for Name: any string is a valid name.
  c.expect_bad_value(
      "setswitchname",
      "bad Id",
      put(c.path("setswitchname"), std::string(CLIENT_IDS) + "&Id=" + BAD_VALUE + "&Name=x")
  );
  put_parameters(c, "setswitchname", {{"Id", "0"}, {"Name", "x"}}, false);
}

void telescope_members(Checks &c)
{
  for (const char *m :
       {"alignmentmode",
        "altitude",
        "aperturearea",
        "aperturediameter",
        "athome",
        "atpark",
        "azimuth",
        "canpark",
        "canpulseguide",
        "cansetdeclinationrate",
        "cansetguiderates",
        "cansetpark",
        "cansetpierside",
        "cansettracking",
        "canslew",
        "canslewaltaz",
        "canslewaltazasync",
        "cansync",
        "cansyncaltaz",
        "canunpark",
        "declination",
        "declinationrate",
        "doesrefraction",
        "equatorialsystem",
        "focallength",
        "guideratedeclination",
        "guideraterightascension",
        "ispulseguiding",
        "rightascension",
        "rightascensionrate",
        "sideofpier",
        "siderealtime",
        "siteelevation",
        "sitelatitude",
        "sitelongitude",
        "slewing",
        "slewsettletime",
        "targetdeclination",
        "targetrightascension",
        "tracking",
        "trackingrate",
        "trackingrates",
        "utcdate"})
  {
    get_no_parameters(c, m);
  }
  put_parameters(c, "declinationrate", {{"DeclinationRate", "0"}});
  put_parameters(c, "doesrefraction", {{"DoesRefraction", "False"}});
  put_parameters(c, "guideratedeclination", {{"GuideRateDeclination", "0.004"}});
  put_parameters(c, "guideraterightascension", {{"GuideRateRightAscension", "0.004"}});
  put_parameters(c, "rightascensionrate", {{"RightAscensionRate", "0"}});
  put_parameters(c, "sideofpier", {{"SideOfPier", "0"}});
  put_parameters(c, "siteelevation", {{"SiteElevation", "100"}});
  put_parameters(c, "sitelatitude", {{"SiteLatitude", "40"}});
  put_parameters(c, "sitelongitude", {{"SiteLongitude", "-105"}});
  put_parameters(c, "slewsettletime", {{"SlewSettleTime", "0"}});
  put_parameters(c, "targetdeclination", {{"TargetDeclination", "10"}});
  put_parameters(c, "targetrightascension", {{"TargetRightAscension", "10"}});
  put_parameters(c, "tracking", {{"Tracking", "True"}});
  put_parameters(c, "trackingrate", {{"TrackingRate", "0"}});
  // Form-encoded, as a client sends it: the colons arrive as %3A.
  put_parameters(c, "utcdate", {{"UTCDate", "2026-10-04T12%3A00%3A00.0000000Z"}});
  get_parameters(c, "axisrates", {{"Axis", "0"}}, false);
  get_parameters(c, "canmoveaxis", {{"Axis", "0"}}, false);
  get_parameters(c, "destinationsideofpier", {{"RightAscension", "10"}, {"Declination", "10"}}, false);
  for (const char *m :
       {"park", "setpark", "unpark", "findhome", "abortslew", "slewtotargetasync", "slewtotarget", "synctotarget"})
  {
    put_parameters(c, m);
  }
  put_parameters(c, "moveaxis", {{"Axis", "0"}, {"Rate", "0.0"}});
  put_parameters(c, "pulseguide", {{"Direction", "0"}, {"Duration", "0"}});
  for (const char *m : {"slewtocoordinatesasync", "synctocoordinates"})
  {
    put_parameters(c, m, {{"RightAscension", "10"}, {"Declination", "10"}});
  }
  for (const char *m : {"slewtoaltazasync", "synctoaltaz"})
  {
    put_parameters(c, m, {{"Azimuth", "180"}, {"Altitude", "45"}});
  }
}

void test_camera_protocol()
{
  run_device<FakeCamera>("camera", camera_members);
}

void test_covercalibrator_protocol()
{
  run_device<FakeCoverCalibrator>("covercalibrator", covercalibrator_members);
}

void test_dome_protocol()
{
  run_device<FakeDome>("dome", dome_members);
}

void test_filterwheel_protocol()
{
  run_device<FakeFilterWheel>("filterwheel", filterwheel_members);
}

void test_focuser_protocol()
{
  run_device<FakeFocuser>("focuser", focuser_members);
}

void test_observingconditions_protocol()
{
  run_device<FakeObservingConditions>("observingconditions", observingconditions_members);
}

void test_rotator_protocol()
{
  run_device<FakeRotator>("rotator", rotator_members);
}

void test_safetymonitor_protocol()
{
  run_device<FakeSafetyMonitor>("safetymonitor", safetymonitor_members);
}

void test_switch_protocol()
{
  run_device<FakeSwitch>("switch", switch_members);
}

void test_telescope_protocol()
{
  run_device<FakeTelescope>("telescope", telescope_members);
}
} // namespace

void run_device_protocol_tests()
{
  RUN_TEST(test_camera_protocol);
  RUN_TEST(test_covercalibrator_protocol);
  RUN_TEST(test_dome_protocol);
  RUN_TEST(test_filterwheel_protocol);
  RUN_TEST(test_focuser_protocol);
  RUN_TEST(test_observingconditions_protocol);
  RUN_TEST(test_rotator_protocol);
  RUN_TEST(test_safetymonitor_protocol);
  RUN_TEST(test_switch_protocol);
  RUN_TEST(test_telescope_protocol);
}
