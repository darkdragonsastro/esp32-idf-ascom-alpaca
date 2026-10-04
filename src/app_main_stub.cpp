// Weak app_main stub for library builds.
// Applications that use this library will override this with their own app_main.

extern "C" __attribute__((weak)) void app_main(void)
{
  // This stub allows the library to compile standalone.
  // It will be overridden by the application's app_main.
}
