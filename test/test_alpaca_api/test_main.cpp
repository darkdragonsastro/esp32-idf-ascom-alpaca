// Alpaca protocol tests for api.cpp, run natively against fake devices. The
// expected results follow ASCOM ConformU's protocol checks in strict mode.

#include "test_helpers.h"

void run_device_protocol_tests();

void setUp()
{
}

void tearDown()
{
}

// Management API

void test_apiversions_value_is_1()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  FakeResponse r = get("/management/apiversions");

  assert_ok(r);
  cJSON *value = field(r, "Value");
  TEST_ASSERT_TRUE(cJSON_IsArray(value));
  TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(value));
  TEST_ASSERT_EQUAL_INT(1, (int)cJSON_GetNumberValue(cJSON_GetArrayItem(value, 0)));
}

void test_description_reports_server_fields()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  FakeResponse r = get("/management/v1/description");

  assert_ok(r);
  cJSON *value = field(r, "Value");
  TEST_ASSERT_EQUAL_STRING("Test Server", cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(value, "ServerName")));
  TEST_ASSERT_EQUAL_STRING("Test Maker", cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(value, "Manufacturer")));
  TEST_ASSERT_EQUAL_STRING(
      "1.2.3",
      cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(value, "ManufacturerVersion"))
  );
  TEST_ASSERT_EQUAL_STRING("Test Site", cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(value, "Location")));
}

void test_configureddevices_numbers_devices_within_type_and_hashes_unique_ids()
{
  FakeTelescope scope0;
  scope0.name = "Scope 0";
  FakeTelescope scope1;
  scope1.name = "Scope 1";
  Server server({&scope0, &scope1});

  FakeResponse r = get("/management/v1/configureddevices");

  assert_ok(r);
  cJSON *value = field(r, "Value");
  TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(value));
  // UniqueID is MD5(server id + device name + device type number + device
  // number), worked out separately with Python's hashlib.
  const char *expected_ids[] = {"ad2c5f8d44ef9ad86f2137aaecac06f7", "a89da60a64e4cef612934309e5388b76"};
  for (int i = 0; i < 2; i++)
  {
    cJSON *device = cJSON_GetArrayItem(value, i);
    TEST_ASSERT_EQUAL_STRING("Telescope", cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(device, "DeviceType")));
    TEST_ASSERT_EQUAL_INT(i, (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(device, "DeviceNumber")));
    TEST_ASSERT_EQUAL_STRING(
        expected_ids[i],
        cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(device, "UniqueID"))
    );
  }
}

// Transaction IDs and response shape

void test_get_echoes_client_transaction_id_and_counts_server_transaction_id()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  FakeResponse first = get("/api/v1/safetymonitor/0/description");
  FakeResponse second = get("/api/v1/safetymonitor/0/description");

  assert_ok(first);
  assert_ok(second);
  TEST_ASSERT_EQUAL_INT(67890, (int)number(first, "ClientTransactionID"));
  TEST_ASSERT_TRUE(number(first, "ServerTransactionID") >= 1);
  TEST_ASSERT_TRUE(number(second, "ServerTransactionID") > number(first, "ServerTransactionID"));
}

void test_get_response_has_value()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  FakeResponse r = get("/api/v1/safetymonitor/0/description");

  assert_ok(r);
  TEST_ASSERT_EQUAL_STRING("Fake description", cJSON_GetStringValue(field(r, "Value")));
}

void test_get_accepts_client_id_names_in_any_casing()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  FakeResponse r = get("/api/v1/safetymonitor/0/description", "clientid=12345&clienttransactionid=67890");

  assert_ok(r);
  TEST_ASSERT_EQUAL_INT(67890, (int)number(r, "ClientTransactionID"));
}

void test_get_ignores_an_extra_parameter()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  FakeResponse r = get("/api/v1/safetymonitor/0/description", std::string(CLIENT_IDS) + "&ExtraParameter=Extra");

  assert_ok(r);
}

void test_put_ignores_a_badly_cased_client_transaction_id()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  FakeResponse r = put("/api/v1/safetymonitor/0/connected", "Connected=True&ClientID=12345&clienttransactionid=67890");

  assert_ok(r);
  TEST_ASSERT_EQUAL_INT(0, (int)number(r, "ClientTransactionID"));
}

// Connected, the call ConformU starts every run with

void test_put_connected_sets_the_device()
{
  FakeSafetyMonitor monitor;
  monitor.is_connected = false;
  Server server({&monitor});

  assert_ok(put("/api/v1/safetymonitor/0/connected", std::string("Connected=True&") + CLIENT_IDS));
  TEST_ASSERT_TRUE(monitor.is_connected);

  assert_ok(put("/api/v1/safetymonitor/0/connected", std::string("Connected=False&") + CLIENT_IDS));
  TEST_ASSERT_FALSE(monitor.is_connected);

  assert_ok(put("/api/v1/safetymonitor/0/connected", std::string(CLIENT_IDS) + "&Connected=True"));
  TEST_ASSERT_TRUE(monitor.is_connected);
}

void test_put_connected_refuses_bad_values()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  const char *bad_values[] = {"", "123456", "asdqwe"};
  for (const char *bad : bad_values)
  {
    assert_bad_value(put("/api/v1/safetymonitor/0/connected", std::string("Connected=") + bad + "&" + CLIENT_IDS));
  }
}

void test_put_parameter_names_are_case_sensitive()
{
  FakeSafetyMonitor monitor;
  monitor.is_connected = false;
  Server server({&monitor});

  FakeResponse r = put("/api/v1/safetymonitor/0/connected", std::string("cONNECTED=True&") + CLIENT_IDS);

  TEST_ASSERT_EQUAL_INT(400, r.status);
  TEST_ASSERT_FALSE(monitor.is_connected);
}

void test_a_response_over_512_bytes_is_sent_whole()
{
  FakeSafetyMonitor monitor;
  for (int i = 0; i < 100; i++)
  {
    monitor.supported_actions.push_back("action" + std::to_string(i));
  }
  Server server({&monitor});

  FakeResponse r = get("/api/v1/safetymonitor/0/supportedactions");

  assert_ok(r);
  TEST_ASSERT_TRUE(r.body.size() > 512);
  cJSON *value = field(r, "Value");
  TEST_ASSERT_EQUAL_INT(100, cJSON_GetArraySize(value));
  TEST_ASSERT_EQUAL_STRING("action99", cJSON_GetStringValue(cJSON_GetArrayItem(value, 99)));
}

// Telescope UTCDate

void test_put_utcdate_decodes_the_form_value()
{
  FakeTelescope scope;
  Server server({&scope});

  assert_ok(put("/api/v1/telescope/0/utcdate", std::string("UTCDate=2026-10-04T12%3A00%3A00.5Z&") + CLIENT_IDS));

  TEST_ASSERT_EQUAL_STRING("2026-10-04T12:00:00.5Z", scope.utcdate.c_str());
}

void test_put_utcdate_accepts_seconds_with_and_without_a_fraction()
{
  FakeTelescope scope;
  Server server({&scope});

  const char *good[] = {"2026-10-04T12:00:00Z", "2026-10-04T12:00:00.1Z", "2026-10-04T23:59:59.1234567Z", "2026-10-04T12:00:00.123456789Z"};
  for (const char *date : good)
  {
    scope.utcdate.clear();
    assert_ok(put("/api/v1/telescope/0/utcdate", std::string("UTCDate=") + date + "&" + CLIENT_IDS));
    TEST_ASSERT_EQUAL_STRING(date, scope.utcdate.c_str());
  }
}

void test_put_utcdate_refuses_a_missing_or_badly_formatted_date()
{
  FakeTelescope scope;
  Server server({&scope});

  assert_bad_value(put("/api/v1/telescope/0/utcdate", CLIENT_IDS));
  const char *bad[] = {
    "",
    "asduio6fghZZ",
    "2026-10-04",
    "2026-10-04T12:00:00",
    "2026-10-04 12:00:00Z",
    "2026-10-04T12:00:00.Z",
    "2026-13-04T12:00:00Z",
    "2026-10-32T12:00:00Z",
    "2026-10-04T24:00:00Z",
    "2026-10-04T12:60:00Z",
    "2026-10-04T12:00:00Zjunk",
  };
  for (const char *date : bad)
  {
    assert_bad_value(put("/api/v1/telescope/0/utcdate", std::string("UTCDate=") + date + "&" + CLIENT_IDS));
  }
  TEST_ASSERT_EQUAL_STRING("", scope.utcdate.c_str());
}

// Number parameters

// A number parameter that is empty, only spaces, or has a space before the
// number gets a 400 and never reaches the device. "%20" is a space and "%09"
// a tab, as a client encodes them.
void test_an_empty_or_blank_number_gets_a_400()
{
  FakeSwitch sw;
  FakeFocuser focuser;
  FakeDome dome;
  FakeTelescope scope;
  Server server({&sw, &focuser, &dome, &scope});

  const char *blanks[] = {"", "%20", "%20%20%20", "%09", "%203"};
  for (const char *blank : blanks)
  {
    std::string b = blank;
    FakeResponse responses[] = {
      get("/api/v1/switch/0/getswitch", std::string(CLIENT_IDS) + "&Id=" + b),
      put("/api/v1/switch/0/setswitch", "Id=" + b + "&State=True&" + CLIENT_IDS),
      put("/api/v1/switch/0/setswitchvalue", "Id=" + b + "&Value=1&" + CLIENT_IDS),
      put("/api/v1/switch/0/setswitchvalue", "Id=0&Value=" + b + "&" + CLIENT_IDS),
      put("/api/v1/focuser/0/move", "Position=" + b + "&" + CLIENT_IDS),
      put("/api/v1/dome/0/slewtoazimuth", "Azimuth=" + b + "&" + CLIENT_IDS),
      put("/api/v1/telescope/0/sitelatitude", "SiteLatitude=" + b + "&" + CLIENT_IDS),
    };
    for (const FakeResponse &r : responses)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(400, r.status, blank);
    }
  }
  TEST_ASSERT_EQUAL_STRING("", sw.last_call.c_str());
  TEST_ASSERT_EQUAL_STRING("", focuser.last_call.c_str());
  TEST_ASSERT_EQUAL_STRING("", dome.last_call.c_str());
  TEST_ASSERT_EQUAL_STRING("", scope.last_call.c_str());
}

// strtod() reads all of these, but none is a usable Alpaca number.
void test_a_double_that_is_not_finite_or_is_hex_gets_a_400()
{
  FakeSwitch sw;
  FakeTelescope scope;
  Server server({&sw, &scope});

  const char *bad[] = {"nan", "NAN", "inf", "-inf", "infinity", "1e400", "-1e400", "1e-9999", "0x1p3", "0X10"};
  for (const char *b : bad)
  {
    FakeResponse switch_r = put("/api/v1/switch/0/setswitchvalue", std::string("Id=0&Value=") + b + "&" + CLIENT_IDS);
    TEST_ASSERT_EQUAL_INT_MESSAGE(400, switch_r.status, b);
    FakeResponse scope_r = put("/api/v1/telescope/0/sitelatitude", std::string("SiteLatitude=") + b + "&" + CLIENT_IDS);
    TEST_ASSERT_EQUAL_INT_MESSAGE(400, scope_r.status, b);
  }
  TEST_ASSERT_EQUAL_STRING("", sw.last_call.c_str());
  TEST_ASSERT_EQUAL_STRING("", scope.last_call.c_str());
}

void test_an_id_outside_int32_gets_a_400()
{
  FakeSwitch sw;
  Server server({&sw});

  const char *bad[] = {"2147483648", "4294967296", "-2147483649", "99999999999999999999"};
  for (const char *b : bad)
  {
    FakeResponse get_r = get("/api/v1/switch/0/getswitch", std::string(CLIENT_IDS) + "&Id=" + b);
    TEST_ASSERT_EQUAL_INT_MESSAGE(400, get_r.status, b);
    FakeResponse put_r = put("/api/v1/switch/0/setswitch", std::string("Id=") + b + "&State=True&" + CLIENT_IDS);
    TEST_ASSERT_EQUAL_INT_MESSAGE(400, put_r.status, b);
  }
  TEST_ASSERT_EQUAL_STRING("", sw.last_call.c_str());
}

// INT32_MAX and INT32_MIN parse, so the device's own range check answers.
void test_an_id_at_the_int32_limits_reaches_the_device()
{
  FakeSwitch sw;
  sw.override_async = false;
  Server server({&sw});

  for (const char *id : {"2147483647", "-2147483648"})
  {
    FakeResponse r = get("/api/v1/switch/0/canasync", std::string(CLIENT_IDS) + "&Id=" + id);
    TEST_ASSERT_EQUAL_INT(200, r.status);
    TEST_ASSERT_EQUAL_INT(ALPACA_ERR_INVALID_VALUE, (int)number(r, "ErrorNumber"));
  }
  assert_ok(get("/api/v1/switch/0/getswitch", std::string(CLIENT_IDS) + "&Id=2147483647"));
  TEST_ASSERT_EQUAL_INT(INT32_MAX, sw.last_id);
}

void test_a_valid_number_still_reaches_the_device()
{
  FakeSwitch sw;
  FakeFocuser focuser;
  Server server({&sw, &focuser});

  assert_ok(get("/api/v1/switch/0/getswitch", std::string(CLIENT_IDS) + "&Id=1"));
  TEST_ASSERT_EQUAL_INT(1, sw.last_id);

  assert_ok(put("/api/v1/switch/0/setswitchvalue", std::string("Id=1&Value=-0.5&") + CLIENT_IDS));
  TEST_ASSERT_EQUAL_INT(1, sw.last_id);
  TEST_ASSERT_EQUAL_FLOAT(-0.5, sw.last_value);

  assert_ok(put("/api/v1/focuser/0/move", std::string("Position=100&") + CLIENT_IDS));
  TEST_ASSERT_EQUAL_STRING("put_move", focuser.last_call.c_str());
}

// Switch interface version 3

void assert_alpaca_error(const FakeResponse &r, int error_number)
{
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_EQUAL_INT(error_number, (int)number(r, "ErrorNumber"));
}

void test_switch_v3_defaults_model_a_switch_with_no_async()
{
  FakeSwitch sw;
  sw.override_async = false;
  Server server({&sw});

  FakeResponse r = get("/api/v1/switch/0/canasync", std::string(CLIENT_IDS) + "&Id=1");
  assert_ok(r);
  TEST_ASSERT_TRUE(cJSON_IsFalse(field(r, "Value")));

  assert_alpaca_error(
      put("/api/v1/switch/0/setasync", std::string("Id=1&State=True&") + CLIENT_IDS),
      ALPACA_ERR_NOT_IMPLEMENTED
  );
  assert_alpaca_error(
      put("/api/v1/switch/0/setasyncvalue", std::string("Id=1&Value=1&") + CLIENT_IDS),
      ALPACA_ERR_NOT_IMPLEMENTED
  );
  assert_alpaca_error(
      get("/api/v1/switch/0/statechangecomplete", std::string(CLIENT_IDS) + "&Id=1"),
      ALPACA_ERR_NOT_IMPLEMENTED
  );
  assert_ok(put("/api/v1/switch/0/cancelasync", std::string("Id=1&") + CLIENT_IDS));
}

void test_switch_v3_defaults_refuse_an_id_out_of_range()
{
  FakeSwitch sw;
  sw.override_async = false;
  Server server({&sw});

  for (const char *id : {"-1", "2"})
  {
    std::string query = std::string(CLIENT_IDS) + "&Id=" + id;
    std::string body = std::string("Id=") + id + "&" + CLIENT_IDS;
    assert_alpaca_error(get("/api/v1/switch/0/canasync", query), ALPACA_ERR_INVALID_VALUE);
    assert_alpaca_error(put("/api/v1/switch/0/setasync", body + "&State=True"), ALPACA_ERR_INVALID_VALUE);
    assert_alpaca_error(put("/api/v1/switch/0/setasyncvalue", body + "&Value=1"), ALPACA_ERR_INVALID_VALUE);
    assert_alpaca_error(get("/api/v1/switch/0/statechangecomplete", query), ALPACA_ERR_INVALID_VALUE);
    assert_alpaca_error(put("/api/v1/switch/0/cancelasync", body), ALPACA_ERR_INVALID_VALUE);
  }
}

void test_switch_v3_routes_reach_a_device_that_overrides_them()
{
  FakeSwitch sw;
  Server server({&sw});

  FakeResponse r = get("/api/v1/switch/0/canasync", std::string(CLIENT_IDS) + "&Id=0");
  assert_ok(r);
  TEST_ASSERT_EQUAL_STRING("get_canasync", sw.last_call.c_str());
  TEST_ASSERT_TRUE(cJSON_IsTrue(field(r, "Value")));

  assert_ok(put("/api/v1/switch/0/setasync", std::string("Id=0&State=True&") + CLIENT_IDS));
  TEST_ASSERT_EQUAL_STRING("put_setasync", sw.last_call.c_str());

  assert_ok(put("/api/v1/switch/0/setasyncvalue", std::string("Id=0&Value=1&") + CLIENT_IDS));
  TEST_ASSERT_EQUAL_STRING("put_setasyncvalue", sw.last_call.c_str());

  r = get("/api/v1/switch/0/statechangecomplete", std::string(CLIENT_IDS) + "&Id=0");
  assert_ok(r);
  TEST_ASSERT_EQUAL_STRING("get_statechangecomplete", sw.last_call.c_str());
  TEST_ASSERT_TRUE(cJSON_IsTrue(field(r, "Value")));

  assert_ok(put("/api/v1/switch/0/cancelasync", std::string("Id=0&") + CLIENT_IDS));
  TEST_ASSERT_EQUAL_STRING("put_cancelasync", sw.last_call.c_str());
}

// The DeviceState entry with this name, or NULL.
cJSON *state_entry(const FakeResponse &r, const char *name)
{
  cJSON *entry;
  cJSON_ArrayForEach(entry, field(r, "Value"))
  {
    if (strcmp(cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(entry, "Name")), name) == 0)
    {
      return cJSON_GetObjectItemCaseSensitive(entry, "Value");
    }
  }
  return NULL;
}

void test_switch_devicestate_lists_each_switch_and_skips_a_failed_read()
{
  FakeSwitch sw;
  sw.max_switch = 3;
  sw.failing_id = 1;
  sw.override_async = false;
  Server server({&sw});

  FakeResponse r = get("/api/v1/switch/0/devicestate");

  assert_ok(r);
  TEST_ASSERT_TRUE(cJSON_IsTrue(state_entry(r, "GetSwitch0")));
  TEST_ASSERT_NULL(state_entry(r, "GetSwitch1"));
  TEST_ASSERT_TRUE(cJSON_IsFalse(state_entry(r, "GetSwitch2")));
  TEST_ASSERT_EQUAL_FLOAT(0.5, cJSON_GetNumberValue(state_entry(r, "GetSwitchValue0")));
  TEST_ASSERT_NULL(state_entry(r, "GetSwitchValue1"));
  TEST_ASSERT_EQUAL_FLOAT(2.5, cJSON_GetNumberValue(state_entry(r, "GetSwitchValue2")));
  TEST_ASSERT_NULL(state_entry(r, "GetSwitch3"));
  // StateChangeComplete returns NotImplemented by default, so it is left out.
  TEST_ASSERT_NULL(state_entry(r, "StateChangeComplete0"));
}

void test_switch_devicestate_lists_statechangecomplete_when_the_device_has_it()
{
  FakeSwitch sw;
  Server server({&sw});

  FakeResponse r = get("/api/v1/switch/0/devicestate");

  assert_ok(r);
  TEST_ASSERT_TRUE(cJSON_IsTrue(state_entry(r, "StateChangeComplete0")));
  TEST_ASSERT_TRUE(cJSON_IsTrue(state_entry(r, "StateChangeComplete1")));
}

void test_switch_devicestate_has_no_switches_when_maxswitch_fails()
{
  FakeSwitch sw;
  sw.ret = ALPACA_ERR_NOT_CONNECTED;
  Server server({&sw});

  FakeResponse r = get("/api/v1/switch/0/devicestate");

  assert_ok(r);
  TEST_ASSERT_NULL(state_entry(r, "GetSwitch0"));
  TEST_ASSERT_NULL(state_entry(r, "GetSwitchValue0"));
}

// Bad URLs

void test_bad_urls_get_a_4xx_status()
{
  FakeSafetyMonitor monitor;
  Server server({&monitor});

  assert_4xx(get("/api/v1/SAFETYMONITOR/0/description"));
  assert_4xx(get("/api/v1/baddevicetype/0/description"));
  assert_4xx(get("/api/v1/safetymonitor/-1/description"));
  assert_4xx(get("/api/v1/safetymonitor/99999/description"));
  assert_4xx(get("/api/v1/safetymonitor/A/description"));
  assert_4xx(get("/api/v1/safetymonitor/1/description"));
  assert_4xx(get("/api/v1/safetymonitor/0/descrip"));
}

// Device results

void test_device_error_is_reported_in_the_body()
{
  FakeSafetyMonitor monitor;
  monitor.ret = ALPACA_ERR_NOT_CONNECTED;
  Server server({&monitor});

  FakeResponse r = get("/api/v1/safetymonitor/0/issafe");

  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_EQUAL_INT(ALPACA_ERR_NOT_CONNECTED, (int)number(r, "ErrorNumber"));
  TEST_ASSERT_EQUAL_STRING(ALPACA_ERR_MESSAGE_NOT_CONNECTED, cJSON_GetStringValue(field(r, "ErrorMessage")));
  TEST_ASSERT_NULL(field(r, "Value"));
}

void test_every_device_type_routes_to_its_device()
{
  FakeCamera camera;
  FakeCoverCalibrator cover;
  FakeDome dome;
  FakeFilterWheel wheel;
  FakeFocuser focuser;
  FakeObservingConditions conditions;
  FakeRotator rotator;
  FakeSafetyMonitor monitor;
  FakeSwitch sw;
  FakeTelescope scope;
  Server server({&camera, &cover, &dome, &wheel, &focuser, &conditions, &rotator, &monitor, &sw, &scope});

  const char *types[] = {
    "camera",
    "covercalibrator",
    "dome",
    "filterwheel",
    "focuser",
    "observingconditions",
    "rotator",
    "safetymonitor",
    "switch",
    "telescope",
  };
  for (const char *type : types)
  {
    FakeResponse r = get(std::string("/api/v1/") + type + "/0/interfaceversion");
    TEST_ASSERT_TRUE_MESSAGE(r.routed, type);
    assert_ok(r);
    TEST_ASSERT_EQUAL_INT(1, (int)number(r, "Value"));
  }

  struct
  {
    const char *path;
    std::string *last_call;
    const char *method;
  } calls[] = {
    {"/api/v1/covercalibrator/0/coverstate", &cover.last_call, "get_coverstate"},
    {"/api/v1/dome/0/altitude", &dome.last_call, "get_altitude"},
    {"/api/v1/filterwheel/0/position", &wheel.last_call, "get_position"},
    {"/api/v1/focuser/0/position", &focuser.last_call, "get_position"},
    {"/api/v1/observingconditions/0/humidity", &conditions.last_call, "get_humidity"},
    {"/api/v1/rotator/0/position", &rotator.last_call, "get_position"},
    {"/api/v1/safetymonitor/0/issafe", &monitor.last_call, "get_issafe"},
    {"/api/v1/switch/0/maxswitch", &sw.last_call, "get_maxswitch"},
    {"/api/v1/telescope/0/altitude", &scope.last_call, "get_altitude"},
  };

  for (auto &call : calls)
  {
    assert_ok(get(call.path));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(call.method, call.last_call->c_str(), call.path);
  }
}

int main(int argc, char **argv)
{
  UNITY_BEGIN();
  RUN_TEST(test_apiversions_value_is_1);
  RUN_TEST(test_description_reports_server_fields);
  RUN_TEST(test_configureddevices_numbers_devices_within_type_and_hashes_unique_ids);
  RUN_TEST(test_get_echoes_client_transaction_id_and_counts_server_transaction_id);
  RUN_TEST(test_get_response_has_value);
  RUN_TEST(test_get_accepts_client_id_names_in_any_casing);
  RUN_TEST(test_get_ignores_an_extra_parameter);
  RUN_TEST(test_put_ignores_a_badly_cased_client_transaction_id);
  RUN_TEST(test_put_connected_sets_the_device);
  RUN_TEST(test_put_connected_refuses_bad_values);
  RUN_TEST(test_put_parameter_names_are_case_sensitive);
  RUN_TEST(test_a_response_over_512_bytes_is_sent_whole);
  RUN_TEST(test_put_utcdate_decodes_the_form_value);
  RUN_TEST(test_put_utcdate_accepts_seconds_with_and_without_a_fraction);
  RUN_TEST(test_put_utcdate_refuses_a_missing_or_badly_formatted_date);
  RUN_TEST(test_an_empty_or_blank_number_gets_a_400);
  RUN_TEST(test_a_double_that_is_not_finite_or_is_hex_gets_a_400);
  RUN_TEST(test_an_id_outside_int32_gets_a_400);
  RUN_TEST(test_an_id_at_the_int32_limits_reaches_the_device);
  RUN_TEST(test_a_valid_number_still_reaches_the_device);
  RUN_TEST(test_switch_v3_defaults_model_a_switch_with_no_async);
  RUN_TEST(test_switch_v3_defaults_refuse_an_id_out_of_range);
  RUN_TEST(test_switch_v3_routes_reach_a_device_that_overrides_them);
  RUN_TEST(test_switch_devicestate_lists_each_switch_and_skips_a_failed_read);
  RUN_TEST(test_switch_devicestate_lists_statechangecomplete_when_the_device_has_it);
  RUN_TEST(test_switch_devicestate_has_no_switches_when_maxswitch_fails);
  RUN_TEST(test_bad_urls_get_a_4xx_status);
  RUN_TEST(test_device_error_is_reported_in_the_body);
  RUN_TEST(test_every_device_type_routes_to_its_device);
  run_device_protocol_tests();
  return UNITY_END();
}
