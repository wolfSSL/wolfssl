# wolfSSL STM32CubeMX2 (MX2) codegen assets

STM32CubeMX2 replaces the classic CubeMX pack mechanism: the configuration
GUI is defined by a JSON-Forms schema and the configuration header is
rendered by a Handlebars template through `cube codegen`, producing
`mx_wolfSSL_conf.h` in the generated project (the MX2 analog of
`wolfSSL.I-CUBE-wolfSSL_conf.h`, using the same `WOLF_CONF_*` scheme).

- `mx_wolfSSL_parameters.json` - the wolfSSL configuration panel shown in
  STM32CubeMX2 (JSON-Forms). Includes the `STM32 Hardware Crypto` toggle:
  on devices where wolfSSL has register-level STM32 support (independent
  of the HAL1 to HAL2 API change), the generated configuration enables the
  RNG, HASH, AES and PKA peripherals.
- `mx_wolfSSL_conf_template.h.hbs` - the Handlebars template that renders
  `mx_wolfSSL_conf.h`.

`wolfssl/wolfcrypt/settings.h` picks the generated header up automatically
via `__has_include("mx_wolfSSL_conf.h")` (HAL2 projects have no global
define like HAL1's `USE_HAL_DRIVER`).

These files are packaged into the `wolfSSL.wolfSSL_middlewares` pack for
STM32CubeMX2 by the wolfSSL pack tooling; the pack build prefers the copies
in this directory so the configuration stays versioned with the library.

## Project checklist (validated on NUCLEO-C5A3ZG, full wolfcrypt_test pass)

- Enable the console UART (Async) matching the wolfSSL panel's
  `Console UART instance` (default `usart2`, the Nucleo VCP) and enable the
  `RNG` peripheral so the generated clock init arms the RNG kernel clock.
- Raise `HEAP_SIZE`/`STACK_SIZE` in the project's `user_modifiable` linker
  script (128 KB / 16 KB recommended); the defaults are too small for
  wolfSSL and fail wolfcrypt_test's MEMORY test.
- Call `wolfCryptDemo(NULL)` (from `wolfssl_example.c`, the wolfCrypt Test
  component) in `main()` to get the interactive test/benchmark menu on the
  console UART; printf is retargeted through the syscalls utility's
  `__io_putchar` hook automatically.
- For benchmark throughput output add `-u _printf_float` to the linker
  options (newlib-nano) and build the Release profile.
