## 1.4.0-b1 (2026-09-06)

### Fix

- **discovery**: keep the UDP socket across receive timeouts

## 1.4.0-b0 (2026-09-06)

### Feat

- **api**: Platform 7 members and unsigned transaction IDs

## 1.3.7 (2026-08-02)

### Feat

- per-call error detail: Device::set_error_detail() lets a device explain the specific refusal right before returning an error code; that one response's ErrorMessage becomes "<standard message>: <detail>", then the detail is cleared

## 1.3.6 (2026-08-01)

### Fix

- telescope boolean PUT params (Tracking, DoesRefraction) parsed as JSON bools — form-urlencoded "True"/"False" arrive as strings, so both handlers returned bare 400 on every request

## 1.3.5 (2026-07-11)

### Fix

- telescope handlers sent bare HTTP 400 on driver errors instead of Alpaca JSON error

## 1.3.4 (2026-07-10)

### Fix

- telescope PUT handlers parsed form params as JSON numbers (always NaN)
- register telescope routes — register_telescope_routes() was an empty stub since initial commit

## 1.3.3 (2025-11-26)

### Fix

- use strncasecmp for Content-Type header comparison

## 1.3.2 (2025-03-04)

### Fix

- use the new custom error message handler

## 1.3.1 (2025-03-04)

### Fix

- small refactor for error messages

## 1.3.0 (2025-03-04)

### Feat

- add custom error message handler for driver exceptions

## 1.2.4 (2025-03-03)

### Fix

- **telescope**: add api for telescope

## 1.2.3 (2025-03-03)

### Fix

- **telescope**: fix guide direction enum

## 1.2.2 (2025-03-03)

### Fix

- **telescope**: use enums for values where possible

## 1.2.1 (2025-02-26)

### Fix

- **api**: update type from float to double

## 1.2.0 (2025-02-26)

### Feat

- **device**: add telescope driver abstract class

## 1.1.4 (2024-09-13)

### Fix

- don't free mem from the stack :facepalm:

## 1.1.3 (2024-09-13)

### Fix

- memory leak

## 1.1.2 (2024-09-13)

### Fix

- return value for getswitchvalue

## 1.1.1 (2024-09-09)

### Fix

- return type for switches

## 1.1.0 (2024-08-14)

### Feat

- initial creation of the esp32-idf-ascom-alpaca library
