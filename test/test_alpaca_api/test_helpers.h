// Shared helpers for the Alpaca protocol tests.
#pragma once

#include "fake_devices.h"
#include "fake_httpd.h"

#include <string>
#include <unity.h>
#include <vector>

inline const char *CLIENT_IDS = "ClientID=12345&ClientTransactionID=67890";

// One Api with the given devices, registered on the fake server.
struct Server
{
  std::vector<Device *> devices;
  Api api;

  explicit Server(std::vector<Device *> list)
      : devices(list), api(devices, "test-server", "Test Server", "Test Maker", "1.2.3", "Test Site")
  {
    fake_httpd_reset();
    api.register_routes(nullptr);
  }
};

inline FakeResponse get(const std::string &path, const std::string &query = CLIENT_IDS)
{
  return fake_request(HTTP_GET, query.empty() ? path : path + "?" + query);
}

inline FakeResponse put(const std::string &path, const std::string &body)
{
  return fake_request(HTTP_PUT, path, body);
}

inline cJSON *field(const FakeResponse &r, const char *key)
{
  return cJSON_GetObjectItemCaseSensitive(r.json.get(), key);
}

inline double number(const FakeResponse &r, const char *key)
{
  cJSON *item = field(r, key);
  TEST_ASSERT_TRUE_MESSAGE(cJSON_IsNumber(item), key);
  return cJSON_GetNumberValue(item);
}

// HTTP 200 with no Alpaca error.
inline void assert_ok(const FakeResponse &r)
{
  TEST_ASSERT_TRUE(r.routed);
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_NOT_NULL(r.json.get());
  cJSON *error_number = field(r, "ErrorNumber");
  if (error_number)
  {
    TEST_ASSERT_EQUAL_INT(0, (int)cJSON_GetNumberValue(error_number));
  }
  TEST_ASSERT_EQUAL_INT(ESP_OK, r.handler_ret);
}

// HTTP 400, or HTTP 200 with InvalidValue: ConformU accepts either for a bad
// parameter value.
inline void assert_bad_value(const FakeResponse &r)
{
  if (r.status == 200)
  {
    TEST_ASSERT_EQUAL_INT(ALPACA_ERR_INVALID_VALUE, (int)number(r, "ErrorNumber"));
  }
  else
  {
    TEST_ASSERT_EQUAL_INT(400, r.status);
  }
}

inline void assert_4xx(const FakeResponse &r)
{
  TEST_ASSERT_TRUE_MESSAGE(r.status >= 400 && r.status < 500, "expected a 4xx status");
}
