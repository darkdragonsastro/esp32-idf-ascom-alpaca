# esp32-idf-ascom-alpaca

This is a native ESP32 implementation of the ASCOM Alpaca http interface. It has implementations for all ASCOM device types except Telescope and Camera. Pull requests are welcome!

This is part of the code that powers [Dark Dragons Astronomy's](https://darkdragonsastro.com) Alpaca native devices. We decided to give back to the community and open source a part of our stack.

Please see the `examples` folder for a demonstration that shows an example Roll Off Room implementation of the ASCOM Dome device type.

## Working

- HTTP Management API
- HTTP Device API
  - CoverCalibrator
  - Dome
  - FilterWheel
  - Focuser
  - ObservingConditions
  - Rotator
  - SafetyMonitor
  - Switch
- UDP Discovery

## TODO

- HTTP Device API
  - Camera
  - Telescope

## License

Apache License Version 2.0 (Apache-2.0)
