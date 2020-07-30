# wolfSSL STM32 Example for STM32 Cube IDE

This example includes:

* wolfCrypt test
* wolfCrypt benchmark
* wolfSSL TLS client/server test using in-memory transfers

These examples use the Cube HAL for STM32.

## Requirements

* STM32CubeIDE: Integrated Development Environment for STM32 [https://www.st.com/en/development-tools/stm32cubeide.html](https://www.st.com/en/development-tools/stm32cubeide.html)

## Configuration

The settings for the wolfSTM32 project are located in `<wolfssl-root>/IDE/STM32Cube/wolfSSL.wolfSSL_conf.h`. The section for "Hardware platform" may need to be adjusted depending on your processor and board:

* To enable STM32F2 support define `WOLFSSL_STM32F2`.
* To enable STM32F4 support define `WOLFSSL_STM32F4`.
* To enable STM32F7 support define `WOLFSSL_STM32F7`.
* To enable STM32L4 support define `WOLFSSL_STM32L4`.
* To enable STM32L5 support define `WOLFSSL_STM32L5`.
* To enable STM32H7 support define `WOLFSSL_STM32H7`.
* To enable STM32WB support define `WOLFSSL_STM32WB`.

To use the STM32 Cube HAL support make sure `WOLFSSL_STM32_CUBEMX` is defined.

The L5 and WB55 support ECC PKA acceleration, which is enabled with `WOLFSSL_STM32_PKA`.

To disable hardware crypto acceleration you can define:

* `NO_STM32_HASH`
* `NO_STM32_CRYPTO`

To enable the latest Cube HAL support please define `STM32_HAL_V2`.

If you'd like to use the older Standard Peripheral library undefine `WOLFSSL_STM32_CUBEMX`.

If you are using FreeRTOS make sure your `FreeRTOSConfig.h` has its `configTOTAL_HEAP_SIZE` increased.

The TLS client/server benchmark example requires about 76 KB for allocated tasks (with stack) and peak heap.

## STM32 Cube Pack

### STM32 Cube Pack Installation

1. Download [wolfSSL Cube Pack](https://www.wolfssl.com/files/ide/I-CUBE-WOLFSSL-WOLFSSL.pack)
2. Run the “STM32CubeMX” tool.
3. Under “Manage software installations” click “INSTALL/REMOVE” button.
4. From Local and choose “I-CUBE-WOLFSSL-WOLFSSL.pack”.

### STM32 Cube Pack Usage

1. Create or open a Cube Project based on your hardware.
2. Under “Software Packs” choose “Select Components”.
3. Find and check all components for the wolfSSL.wolfSSL packs (wolfSSL / Core, wolfCrypt / Core and wolfCrypt / Test). Close
4. Under the “Software Packs” section click on “wolfSSL.wolfSSL” and configure the parameters.
5. For Cortex-M recommend “Math Configuration” -> “Single Precision Cortex-M Math”
6. Generate Code
7. The Benchmark example uses float. To enable go to "Project Properties" -> "C/C++ Build" -> "Settings" -> "Tool Settings" -> "MCU Settings" -> Check "Use float with printf".

### STM32 Cube Pack Examples

In the `I-CUBE-WOLFSSL-WOLFSSL.pack` pack there are pre-assembled example projects available.
After installing the pack you can find these example projects in `STM32Cube/Repository/Packs/wolfSSL/wolfSSL/[Version]/Projects`.
To use an example:

1. Open STM32CubeIDE
2. Choose "Import" -> "Import an Existing STM32CubeMX Configuration File (.ioc)".
3. Browse to find the .ioc in `STM32Cube/Repository/Packs/wolfSSL/wolfSSL/[Version]/Projects` and click finish.

## Example `IDE/STM32Cube/wolfssl_example.c` Output

```
....MENU

.t. WolfCrypt Test
.b. WolfCrypt Benchmark
.l. WolfSSL TLS Bench
.e. Show Cipher List

Please select one of the above options:
```

## Benchmarks

See [STM32_Benchmarks.md](STM32_Benchmarks.md).

## Support

For questions please email [support@wolfssl.com](mailto:support@wolfssl.com)
