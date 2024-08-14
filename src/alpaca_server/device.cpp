#include "alpaca_server/device.h"

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

Device::Device()
{
}

Device::~Device()
{
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
