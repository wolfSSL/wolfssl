# wolfSSL STM32 Example for STM32 Cube IDE

This example includes:

* wolfCrypt test
* wolfCrypt benchmark
* wolfSSL TLS client/server test using in-memory transfers

These examples use the CubeMX Hal for STM32. If you'd like to use the older Standard Peripheral library undefine `WOLFSSL_STM32_CUBEMX` in `user_settings.h`.

## Requirements

* STM32CubeIDE: Integrated Development Environment for STM32 [https://www.st.com/en/development-tools/stm32cubeide.html](https://www.st.com/en/development-tools/stm32cubeide.html)

## Setup

1. Using the STM32CubeMX tool, load the `<wolfssl-root>/IDE/STM32Cube/Boards/*.ioc` file for your target.
2. Adjust the HAL options based on your specific micro-controller.
3. Enable the security RNG/HASH/CRYPT if available.
4. Enable the RTC and UART if available.
5. Add wolfSSL via Additional Software and check/configure wolfSSL.
6. Generate source code.

## Configuration

The settings for the wolfSTM32 project are located in `<wolfssl-root>/IDE/STM32Cube/wolfSSL.wolfSSL_conf.h`. The section for hardware platform may need to be adjusted depending on your processor and board:

* To enable STM32F2 support define `WOLFSSL_STM32F2`.
* To enable STM32F4 support define `WOLFSSL_STM32F4`.
* To enable STM32F7 support define `WOLFSSL_STM32F7`.
* To enable STM32L4 support define `WOLFSSL_STM32L4`.
* To enable STM32L5 support define `WOLFSSL_STM32L5`.
* To enable STM32WB support define `WOLFSSL_STM32WB`.

The L5 and WB55 support ECC PKA acceleration, which is enabled with `WOLFSSL_STM32_PKA`.

To disable hardware crypto acceleration you can define:

* `#define NO_STM32_HASH`
* `#define NO_STM32_CRYPTO`

To enable the latest CubeMX HAL support please use: `#define STM32_HAL_V2`

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
