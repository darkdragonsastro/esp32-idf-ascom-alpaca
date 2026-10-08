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
  RUN_TEST(test_bad_urls_get_a_4xx_status);
  RUN_TEST(test_device_error_is_reported_in_the_body);
  RUN_TEST(test_every_device_type_routes_to_its_device);
  run_device_protocol_tests();
  return UNITY_END();
}
