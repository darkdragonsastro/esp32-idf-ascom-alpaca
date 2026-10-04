// A fake esp_http_server for the native tests. Api::register_routes() fills
// its route table; fake_request() sends one request through it the way
// esp_http_server would and returns what the handler sent back.
#pragma once

#include <cJSON.h>
#include <esp_http_server.h>
#include <map>
#include <memory>
#include <string>

struct FakeResponse
{
  // False when no route matched; status is then 404 (unknown path) or 405
  // (known path, wrong method), as esp_http_server answers.
  bool routed = false;
  esp_err_t handler_ret = ESP_OK;
  int status = 200;
  std::string content_type;
  std::map<std::string, std::string> headers;
  std::string body;
  // The body parsed as JSON, or null when it is empty or not JSON.
  std::shared_ptr<cJSON> json;
};

void fake_httpd_reset();

FakeResponse fake_request(
    int method,
    const std::string &uri,
    const std::string &body = "",
    const std::string &content_type = "application/x-www-form-urlencoded"
);
