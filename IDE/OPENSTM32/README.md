# wolfSSL STM32 Example for System Workbench for STM32 (Open STM32 Tools)

This example includes:

* wolfCrypt test
* wolfCrypt benchmark
* wolfSSL TLS client/server test using in-memory transfers

These examples use the CubeMX Hal for STM32. If you'd like to use the older Standard Peripheral library undefine `WOLFSSL_STM32_CUBEMX` in `user_settings.h`.

## Requirements

* STM32CubeMX: STM32 CubeMX HAL code generation tool - [http://www.st.com/en/development-tools/stm32cubemx.html](http://www.st.com/en/development-tools/stm32cubemx.html)
* SystemWorkbench for STM32 - [http://www.st.com/en/development-tools/sw4stm32.html](http://www.st.com/en/development-tools/sw4stm32.html)

## Setup

1. Using the STM32CubeMX tool, load the `<wolfssl-root>/IDE/OPENSTM32/wolfSTM32.ioc` file.
2. Adjust the HAL options based on your specific micro-controller.
3. Generate source code.
4. Run `SystemWorkbench` and choose a new workspace location for this project.
5. Import `wolfSTM32` project from `<wolfssl-root>/IDE/OPENSTM32/`.
6. Adjust the micro-controller define in `Project Settings -> C/C++ General -> Paths and Symbols -> Symbols -> GNU C`. Example uses `STM32F437xx`, but should be changed to reflect your micro-controller type.
7. Build and Run

If you hardware support crypto acceleration then:
1. Manually copy over the CubeMX HAL files for `stm32f4xx_hal_cryp.c`, `stm32f4xx_hal_cryp_ex.c`, `stm32f4xx_hal_cryp.h`, `stm32f4xx_hal_cryp_ex.h`.
2. Uncomment the `#define HAL_CRYP_MODULE_ENABLED` line in `stm32f4xx_hal_conf.h`.

## Configuration

The settings for the wolfSTM32 project are located in `<wolfssl-root>/IDE/OPENSTM32/Inc/user_settings.h`.

* To enable STM32F2 support define `WOLFSSL_STM32F2`.
* To enable STM32F4 support define `WOLFSSL_STM32F4`.
* To enable STM32F7 support define `WOLFSSL_STM32F7`.
* To enable STM32L4 support define `WOLFSSL_STM32L4`.

If you are using FreeRTOS make sure your `FreeRTOSConfig.h` has its `configTOTAL_HEAP_SIZE` increased.

The TLS client/server benchmark example requires about 76 KB for allocated tasks (with stack) and peak heap.

## Example Output

```
....MENU

.t. WolfCrypt Test
.b. WolfCrypt Benchmark
.l. WolfSSL TLS Bench
.e. Show Cipher List

Please select one of the above options:
```

## Support

For questions please email [support@wolfssl.com](mailto:support@wolfssl.com)
