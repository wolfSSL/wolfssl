# wolfSSL STM32 Example for STM32 Cube IDE

This example includes:

* wolfCrypt test
* wolfCrypt benchmark
* wolfSSL TLS client/server test using in-memory transfers

These examples use the Cube HAL for STM32.

## Requirements

* STM32CubeIDE: Integrated Development Environment for STM32 [https://www.st.com/en/development-tools/stm32cubeide.html](https://www.st.com/en/development-tools/stm32cubeide.html)

## Configuration

The settings for the wolfSSL CubeMX pack are in the generated `wolfSSL.wolfSSL_conf.h` file. An example of this is located in `IDE/STM32Cube/wolfSSL_conf.h` (renamed to avoid possible conflicts with generated file).

The template used for generation is `IDE/STM32Cube/default_conf.ftl` which can be updated at `STM32Cube/Repository/Packs/wolfSSL/wolfSSL/[Version]/CubeMX/templates/default_conf.ftl`.

The section for "Hardware platform" may need to be adjusted depending on your processor and board:

* To enable STM32F1 support define `WOLFSSL_STM32F1`.
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

The TLS client/server benchmark example requires about 76 KB for allocated tasks (with stack) and peak heap. This uses both a TLS client and server to test a TLS connection locally for each enabled TLS cipher suite.

## STM32 Cube Pack

### STM32 Cube Pack Installation

1. Download [wolfSSL Cube Pack](https://www.wolfssl.com/files/ide/I-CUBE-wolfSSL.pack)
2. Run the “STM32CubeMX” tool.
3. Under “Manage software installations” click “INSTALL/REMOVE” button.
4. From Local and choose “I-CUBE-wolfSSL.pack”.
5. Accept the GPLv2 license. Contact wolfSSL at sales@wolfssl.com for a commercial license and support/maintenance.

### STM32 Cube Pack Usage

1. Create or open a Cube Project based on your hardware.
2. Under “Software Packs” choose “Select Components”.
3. Find and check all components for the wolfSSL.wolfSSL packs (wolfSSL / Core, wolfCrypt / Core and wolfCrypt / Test). Close
4. Under the “Software Packs” section click on “wolfSSL.wolfSSL” and configure the parameters.
5. For Cortex-M recommend “Math Configuration” -> “Single Precision Cortex-M Math” for the fastest option.
6. Generate Code
7. The Benchmark example uses float. To enable go to "Project Properties" -> "C/C++ Build" -> "Settings" -> "Tool Settings" -> "MCU Settings" -> Check "Use float with printf".
8. To enable printf make the `main.c` changes below in the [STM32 Printf](#stm32-printf) section.

### STM32 Cube Pack Examples

In the `I-CUBE-wolfSSL.pack` pack there are pre-assembled example projects available.
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

Note: The Benchmark example uses float. To enable go to "Project Properties" -> "C/C++ Build" -> "Settings" -> "Tool Settings" -> "MCU Settings" -> Check "Use float with printf".

## STM32 Printf

In main.c make the following changes:

```
/* Retargets the C library printf function to the USART. */
#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#ifdef __GNUC__
int __io_putchar(int ch)
#else
int fputc(int ch, FILE *f)
#endif
{
    HAL_UART_Transmit(&HAL_CONSOLE_UART, (uint8_t *)&ch, 1, 0xFFFF);

    return ch;
}
#ifdef __GNUC__
int _write(int file,char *ptr, int len)
{
    int DataIdx;
    for (DataIdx= 0; DataIdx< len; DataIdx++) {
        __io_putchar(*ptr++);
    }
    return len;
}
#endif

int main(void)
{
    /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
    HAL_Init();

    /* Turn off buffers, so I/O occurs immediately */
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

```

## Support

For questions please email [support@wolfssl.com](mailto:support@wolfssl.com)
