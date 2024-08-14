#pragma once
#ifndef ROLL_OFF_ROOF_H
#define ROLL_OFF_ROOF_H

#include <alpaca_server/api.h>

class RollOffRoof : public AlpacaServer::Dome
{
public:
  RollOffRoof();
  ~RollOffRoof();

public:
  virtual esp_err_t action(const char *action, const char *parameters, char *buf, size_t len) override;
  virtual esp_err_t commandblind(const char *command, bool raw) override;
  virtual esp_err_t commandbool(const char *command, bool raw, bool *resp) override;
  virtual esp_err_t commandstring(const char *action, bool raw, char *buf, size_t len) override;
  virtual esp_err_t get_connected(bool *connected) override;
  virtual esp_err_t set_connected(bool connected) override;
  virtual esp_err_t get_description(char *buf, size_t len) override;
  virtual esp_err_t get_driverinfo(char *buf, size_t len) override;
  virtual esp_err_t get_driverversion(char *buf, size_t len) override;
  virtual esp_err_t get_interfaceversion(uint32_t *version) override;
  virtual esp_err_t get_name(char *buf, size_t len) override;
  virtual esp_err_t get_supportedactions(std::vector<std::string> &actions) override;
  virtual esp_err_t get_altitude(float *altitude) override;
  virtual esp_err_t get_athome(bool *athome) override;
  virtual esp_err_t get_atpark(bool *atpark) override;
  virtual esp_err_t get_azimuth(float *azimuth) override;
  virtual esp_err_t get_canfindhome(bool *canfindhome) override;
  virtual esp_err_t get_canpark(bool *canpark) override;
  virtual esp_err_t get_cansetaltitude(bool *cansetaltitude) override;
  virtual esp_err_t get_cansetazimuth(bool *cansetazimuth) override;
  virtual esp_err_t get_cansetpark(bool *cansetpark) override;
  virtual esp_err_t get_cansetshutter(bool *cansetshutter) override;
  virtual esp_err_t get_canslave(bool *canslave) override;
  virtual esp_err_t get_cansyncazimuth(bool *cansyncazimuth) override;
  virtual esp_err_t get_shutterstatus(ShutterState *shutterstatus) override;
  virtual esp_err_t get_slaved(bool *slaved) override;
  virtual esp_err_t put_slaved(bool slaved) override;
  virtual esp_err_t get_slewing(bool *slewing) override;
  virtual esp_err_t put_abortslew() override;
  virtual esp_err_t put_closeshutter() override;
  virtual esp_err_t put_findhome() override;
  virtual esp_err_t put_openshutter() override;
  virtual esp_err_t put_park() override;
  virtual esp_err_t put_setpark() override;
  virtual esp_err_t put_slewtoaltitude(float altitude) override;
  virtual esp_err_t put_slewtoazimuth(float azimuth) override;
  virtual esp_err_t put_synctoazimuth(float azimuth) override;

private:
  bool _connected;

  uint32_t _azimuth_centi_degrees;
  ShutterState _shutterstatus;
};

#endif // ROLL_OFF_ROOF_H
