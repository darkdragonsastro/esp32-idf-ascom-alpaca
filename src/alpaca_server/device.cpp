#include "alpaca_server/device.h"

#include "alpaca_server/api.h"

#include <string.h>

using namespace AlpacaServer;

esp_err_t AlpacaServer::friendly_device_type(DeviceType t, char *buf, size_t len)
{
  switch (t)
  {
  case DeviceType::Camera:
    strncpy((char *)buf, "Camera", len);
    break;
  case DeviceType::CoverCalibrator:
    strncpy((char *)buf, "CoverCalibrator", len);
    break;
  case DeviceType::Dome:
    strncpy((char *)buf, "Dome", len);
    break;
  case DeviceType::FilterWheel:
    strncpy((char *)buf, "FilterWheel", len);
    break;
  case DeviceType::Focuser:
    strncpy((char *)buf, "Focuser", len);
    break;
  case DeviceType::ObservingConditions:
    strncpy((char *)buf, "ObservingConditions", len);
    break;
  case DeviceType::Rotator:
    strncpy((char *)buf, "Rotator", len);
    break;
  case DeviceType::SafetyMonitor:
    strncpy((char *)buf, "SafetyMonitor", len);
    break;
  case DeviceType::Switch:
    strncpy((char *)buf, "Switch", len);
    break;
  case DeviceType::Telescope:
    strncpy((char *)buf, "Telescope", len);
    break;
  default:
    strncpy((char *)buf, "Unknown", len);
    break;
  }

  buf[len - 1] = '\0';

  return ESP_OK;
}

esp_err_t AlpacaServer::uri_device_type(DeviceType t, char *buf, size_t len)
{
  switch (t)
  {
  case DeviceType::Camera:
    strncpy((char *)buf, "camera", len);
    break;
  case DeviceType::CoverCalibrator:
    strncpy((char *)buf, "covercalibrator", len);
    break;
  case DeviceType::Dome:
    strncpy((char *)buf, "dome", len);
    break;
  case DeviceType::FilterWheel:
    strncpy((char *)buf, "filterwheel", len);
    break;
  case DeviceType::Focuser:
    strncpy((char *)buf, "focuser", len);
    break;
  case DeviceType::ObservingConditions:
    strncpy((char *)buf, "observingconditions", len);
    break;
  case DeviceType::Rotator:
    strncpy((char *)buf, "rotator", len);
    break;
  case DeviceType::SafetyMonitor:
    strncpy((char *)buf, "safetymonitor", len);
    break;
  case DeviceType::Switch:
    strncpy((char *)buf, "switch", len);
    break;
  case DeviceType::Telescope:
    strncpy((char *)buf, "telescope", len);
    break;
  default:
    strncpy((char *)buf, "unknown", len);
    break;
  }

  return ESP_OK;
}

// Pending per-call error detail. One slot suffices: esp_http_server runs
// every URI handler on its single server task and this library never defers
// handler work (no httpd_queue_work / async request handlers), so a device
// method and the response built from its return value always execute
// back-to-back on that task.
static char s_error_detail[128] = {0};

void Device::set_error_detail(const char *detail)
{
  if (detail == NULL)
  {
    s_error_detail[0] = '\0';
    return;
  }

  strncpy(s_error_detail, detail, sizeof(s_error_detail) - 1);
  s_error_detail[sizeof(s_error_detail) - 1] = '\0';
}

size_t AlpacaServer::take_error_detail(char *buf, size_t len)
{
  if (len == 0 || s_error_detail[0] == '\0')
  {
    s_error_detail[0] = '\0';
    return 0;
  }

  strncpy(buf, s_error_detail, len - 1);
  buf[len - 1] = '\0';
  s_error_detail[0] = '\0';

  return strlen(buf);
}

void AlpacaServer::clear_error_detail()
{
  s_error_detail[0] = '\0';
}

Device::Device()
{
}

Device::~Device()
{
}

esp_err_t Device::connect()
{
  return set_connected(true);
}

esp_err_t Device::disconnect()
{
  return set_connected(false);
}

esp_err_t Device::get_connecting(bool *connecting)
{
  *connecting = false;
  return ALPACA_OK;
}

AlpacaServer::DeviceType Camera::device_type()
{
  return AlpacaServer::DeviceType::Camera;
}

Camera::Camera() : Device()
{
}

Camera::~Camera()
{
}

DeviceType CoverCalibrator::device_type()
{
  return DeviceType::CoverCalibrator;
}

CoverCalibrator::CoverCalibrator() : Device()
{
}

CoverCalibrator::~CoverCalibrator()
{
}

AlpacaServer::DeviceType Dome::device_type()
{
  return AlpacaServer::DeviceType::Dome;
}

Dome::Dome() : Device()
{
}

Dome::~Dome()
{
}

AlpacaServer::DeviceType FilterWheel::device_type()
{
  return AlpacaServer::DeviceType::FilterWheel;
}

FilterWheel::FilterWheel() : Device()
{
}

FilterWheel::~FilterWheel()
{
}

AlpacaServer::DeviceType Focuser::device_type()
{
  return AlpacaServer::DeviceType::Focuser;
}

Focuser::Focuser() : Device()
{
}

Focuser::~Focuser()
{
}

AlpacaServer::DeviceType ObservingConditions::device_type()
{
  return AlpacaServer::DeviceType::ObservingConditions;
}

ObservingConditions::ObservingConditions() : Device()
{
}

ObservingConditions::~ObservingConditions()
{
}

AlpacaServer::DeviceType Rotator::device_type()
{
  return AlpacaServer::DeviceType::Rotator;
}

Rotator::Rotator() : Device()
{
}

Rotator::~Rotator()
{
}

SafetyMonitor::SafetyMonitor()
{
}

SafetyMonitor::~SafetyMonitor()
{
}

DeviceType SafetyMonitor::device_type()
{
  return DeviceType::SafetyMonitor;
}

AlpacaServer::DeviceType Switch::device_type()
{
  return AlpacaServer::DeviceType::Switch;
}

Switch::Switch() : Device()
{
}

Switch::~Switch()
{
}

// Returns InvalidValue when id is not 0 to MaxSwitch - 1, or the error from
// get_maxswitch when that read fails.
static esp_err_t check_switch_id(Switch *device, int32_t id)
{
  int32_t maxswitch = 0;
  esp_err_t err = device->get_maxswitch(&maxswitch);
  if (err != ALPACA_OK)
  {
    return err;
  }
  if (id < 0 || id >= maxswitch)
  {
    return ALPACA_ERR_INVALID_VALUE;
  }
  return ALPACA_OK;
}

esp_err_t Switch::get_canasync(int32_t id, bool *canasync)
{
  esp_err_t err = check_switch_id(this, id);
  if (err == ALPACA_OK)
  {
    *canasync = false;
  }
  return err;
}

esp_err_t Switch::put_setasync(int32_t id, bool state)
{
  esp_err_t err = check_switch_id(this, id);
  return err == ALPACA_OK ? ALPACA_ERR_NOT_IMPLEMENTED : err;
}

esp_err_t Switch::put_setasyncvalue(int32_t id, double value)
{
  esp_err_t err = check_switch_id(this, id);
  return err == ALPACA_OK ? ALPACA_ERR_NOT_IMPLEMENTED : err;
}

esp_err_t Switch::get_statechangecomplete(int32_t id, bool *complete)
{
  esp_err_t err = check_switch_id(this, id);
  return err == ALPACA_OK ? ALPACA_ERR_NOT_IMPLEMENTED : err;
}

esp_err_t Switch::put_cancelasync(int32_t id)
{
  return check_switch_id(this, id);
}

AlpacaServer::DeviceType Telescope::device_type()
{
  return AlpacaServer::DeviceType::Telescope;
}

Telescope::Telescope() : Device()
{
}

Telescope::~Telescope()
{
}
