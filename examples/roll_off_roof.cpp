#include "roll_off_roof.h"

RollOffRoof::RollOffRoof() : Dome()
{
  _connected = false;
}

RollOffRoof::~RollOffRoof()
{
}

esp_err_t RollOffRoof::action(const char *action, const char *parameters, char *buf, size_t len)
{
  return ALPACA_ERR_ACTION_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::commandblind(const char *command, bool raw)
{
  return ALPACA_ERR_ACTION_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::commandbool(const char *command, bool raw, bool *resp)
{
  return ALPACA_ERR_ACTION_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::commandstring(const char *action, bool raw, char *buf, size_t len)
{
  return ALPACA_ERR_ACTION_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::get_connected(bool *connected)
{
  *connected = _connected;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::set_connected(bool connected)
{
  _connected = connected;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_description(char *buf, size_t len)
{
  strncpy(buf, "RollOffRoof Dome Controller", len);
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_driverinfo(char *buf, size_t len)
{
  strncpy(buf, "Dark Dragons Astronomy LLC", len);
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_driverversion(char *buf, size_t len)
{
  strncpy(buf, "1.0.0", len);
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_interfaceversion(uint32_t *version)
{
  *version = 2;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_name(char *buf, size_t len)
{
  strncpy(buf, "My Roof", len);
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_supportedactions(std::vector<std::string> &actions)
{
  actions.clear();
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_altitude(float *altitude)
{
  return ALPACA_ERR_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::get_athome(bool *athome)
{
  *athome = _azimuth_centi_degrees == 0;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_atpark(bool *atpark)
{
  return ALPACA_ERR_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::get_azimuth(float *azimuth)
{
  *azimuth = _azimuth_centi_degrees / 100.0;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_canfindhome(bool *canfindhome)
{
  *canfindhome = true;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_canpark(bool *canpark)
{
  *canpark = false;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_cansetaltitude(bool *cansetaltitude)
{
  *cansetaltitude = false;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_cansetazimuth(bool *cansetazimuth)
{
  *cansetazimuth = true;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_cansetpark(bool *cansetpark)
{
  *cansetpark = false;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_cansetshutter(bool *cansetshutter)
{
  *cansetshutter = true;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_canslave(bool *canslave)
{
  *canslave = false;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_cansyncazimuth(bool *cansyncazimuth)
{
  *cansyncazimuth = true;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_shutterstatus(ShutterState *shutterstatus)
{
  *shutterstatus = _shutterstatus;

  return ALPACA_OK;
}

esp_err_t RollOffRoof::get_slaved(bool *slaved)
{
  return ALPACA_ERR_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::put_slaved(bool slaved)
{
  return ALPACA_ERR_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::get_slewing(bool *slewing)
{
  *slewing = false;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::put_abortslew()
{
  // TODO: Stop all movement.
  return ALPACA_OK;
}

esp_err_t RollOffRoof::put_closeshutter()
{
  // TODO: Close the shutter.
  _shutterstatus = ShutterState::Closed;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::put_findhome()
{
  _azimuth_centi_degrees = 0;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::put_openshutter()
{
  _shutterstatus = ShutterState::Open;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::put_park()
{
  return ALPACA_ERR_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::put_setpark()
{
  return ALPACA_ERR_ACTION_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::put_slewtoaltitude(float altitude)
{
  return ALPACA_ERR_ACTION_NOT_IMPLEMENTED;
}

esp_err_t RollOffRoof::put_slewtoazimuth(float azimuth)
{
  _azimuth_centi_degrees = azimuth * 100;
  return ALPACA_OK;
}

esp_err_t RollOffRoof::put_synctoazimuth(float azimuth)
{
  _azimuth_centi_degrees = azimuth * 100;
  return ALPACA_OK;
}
