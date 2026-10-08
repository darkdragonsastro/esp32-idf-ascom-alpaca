#include "fake_httpd.h"

#include <esp_log.h>
#include <esp_timer.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <vector>

esp_log_level_t fake_log_level = ESP_LOG_INFO;
int64_t fake_now_us = 0;

namespace
{
struct Route
{
  std::string uri;
  int method;
  esp_err_t (*handler)(httpd_req_t *r);
  void *user_ctx;
};

struct Exchange
{
  std::string body_in;
  std::string content_type_in;
  size_t recv_offset = 0;
  FakeResponse response;
  std::string status_line = HTTPD_200;
};

std::vector<Route> routes;

Exchange *exchange_of(httpd_req_t *r)
{
  return static_cast<Exchange *>(r->aux);
}

const char *query_of(httpd_req_t *r)
{
  const char *q = strchr(r->uri, '?');
  return q ? q + 1 : nullptr;
}
} // namespace

void fake_httpd_reset()
{
  routes.clear();
}

esp_err_t httpd_register_uri_handler(httpd_handle_t handle, const httpd_uri_t *uri_handler)
{
  (void)handle;
  // esp_http_server copies the URI; api.cpp passes a stack buffer.
  routes.push_back({uri_handler->uri, uri_handler->method, uri_handler->handler, uri_handler->user_ctx});
  return ESP_OK;
}

size_t httpd_req_get_url_query_len(httpd_req_t *r)
{
  const char *q = query_of(r);
  return q ? strlen(q) : 0;
}

esp_err_t httpd_req_get_url_query_str(httpd_req_t *r, char *buf, size_t buf_len)
{
  const char *q = query_of(r);
  if (!q)
  {
    return ESP_ERR_NOT_FOUND;
  }
  strncpy(buf, q, buf_len - 1);
  buf[buf_len - 1] = '\0';
  return ESP_OK;
}

int httpd_req_recv(httpd_req_t *r, char *buf, size_t buf_len)
{
  Exchange *ex = exchange_of(r);
  size_t n = ex->body_in.size() - ex->recv_offset;
  if (n > buf_len)
  {
    n = buf_len;
  }
  memcpy(buf, ex->body_in.data() + ex->recv_offset, n);
  ex->recv_offset += n;
  return (int)n;
}

size_t httpd_req_get_hdr_value_len(httpd_req_t *r, const char *field)
{
  if (strcasecmp(field, "Content-Type") != 0)
  {
    return 0;
  }
  return exchange_of(r)->content_type_in.size();
}

esp_err_t httpd_req_get_hdr_value_str(httpd_req_t *r, const char *field, char *val, size_t val_size)
{
  if (strcasecmp(field, "Content-Type") != 0)
  {
    return ESP_ERR_NOT_FOUND;
  }
  strncpy(val, exchange_of(r)->content_type_in.c_str(), val_size - 1);
  val[val_size - 1] = '\0';
  return ESP_OK;
}

esp_err_t httpd_resp_set_status(httpd_req_t *r, const char *status)
{
  exchange_of(r)->status_line = status;
  return ESP_OK;
}

esp_err_t httpd_resp_set_type(httpd_req_t *r, const char *type)
{
  exchange_of(r)->response.content_type = type;
  return ESP_OK;
}

esp_err_t httpd_resp_set_hdr(httpd_req_t *r, const char *field, const char *value)
{
  exchange_of(r)->response.headers[field] = value;
  return ESP_OK;
}

esp_err_t httpd_resp_send(httpd_req_t *r, const char *buf, ssize_t buf_len)
{
  Exchange *ex = exchange_of(r);
  ex->response.body.assign(buf ? buf : "", buf ? (size_t)buf_len : 0);
  return ESP_OK;
}

FakeResponse fake_request(int method, const std::string &uri, const std::string &body, const std::string &content_type)
{
  std::string path = uri.substr(0, uri.find('?'));

  const Route *match = nullptr;
  bool path_known = false;
  for (const Route &route : routes)
  {
    if (route.uri == path)
    {
      path_known = true;
      if (route.method == method)
      {
        match = &route;
        break;
      }
    }
  }

  if (!match)
  {
    FakeResponse response;
    response.status = path_known ? 405 : 404;
    return response;
  }

  Exchange ex;
  ex.body_in = body;
  ex.content_type_in = body.empty() ? "" : content_type;

  httpd_req_t req = {};
  req.method = method;
  strncpy(req.uri, uri.c_str(), sizeof(req.uri) - 1);
  req.content_len = body.size();
  req.aux = &ex;
  req.user_ctx = match->user_ctx;

  ex.response.routed = true;
  ex.response.handler_ret = match->handler(&req);
  ex.response.status = atoi(ex.status_line.c_str());
  ex.response.json = std::shared_ptr<cJSON>(cJSON_Parse(ex.response.body.c_str()), cJSON_Delete);
  return ex.response;
}
