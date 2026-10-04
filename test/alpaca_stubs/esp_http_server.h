// Host stand-in for ESP-IDF's esp_http_server.h, for the native tests only.
// The functions are defined in test/test_alpaca_api/fake_httpd.cpp.
#pragma once

#include <stddef.h>
#include <sys/types.h>

#include "esp_err.h"

enum http_method
{
  HTTP_DELETE = 0,
  HTTP_GET = 1,
  HTTP_HEAD = 2,
  HTTP_POST = 3,
  HTTP_PUT = 4,
  HTTP_CONNECT = 5,
  HTTP_OPTIONS = 6,
};

typedef enum http_method httpd_method_t;

typedef void *httpd_handle_t;

typedef struct httpd_req
{
  httpd_handle_t handle;
  int method;
  char uri[513];
  size_t content_len;
  void *aux;
  void *user_ctx;
} httpd_req_t;

typedef struct httpd_uri
{
  const char *uri;
  httpd_method_t method;
  esp_err_t (*handler)(httpd_req_t *r);
  void *user_ctx;
} httpd_uri_t;

#define HTTPD_200       "200 OK"
#define HTTPD_204       "204 No Content"
#define HTTPD_207       "207 Multi-Status"
#define HTTPD_400       "400 Bad Request"
#define HTTPD_404       "404 Not Found"
#define HTTPD_408       "408 Request Timeout"
#define HTTPD_500       "500 Internal Server Error"

#define HTTPD_TYPE_JSON "application/json"

esp_err_t httpd_register_uri_handler(httpd_handle_t handle, const httpd_uri_t *uri_handler);
size_t httpd_req_get_url_query_len(httpd_req_t *r);
esp_err_t httpd_req_get_url_query_str(httpd_req_t *r, char *buf, size_t buf_len);
int httpd_req_recv(httpd_req_t *r, char *buf, size_t buf_len);
size_t httpd_req_get_hdr_value_len(httpd_req_t *r, const char *field);
esp_err_t httpd_req_get_hdr_value_str(httpd_req_t *r, const char *field, char *val, size_t val_size);
esp_err_t httpd_resp_set_status(httpd_req_t *r, const char *status);
esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *type);
esp_err_t httpd_resp_set_hdr(httpd_req_t *r, const char *field, const char *value);
esp_err_t httpd_resp_send(httpd_req_t *r, const char *buf, ssize_t buf_len);
