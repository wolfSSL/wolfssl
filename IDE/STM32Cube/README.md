# wolfSSL STM32 Example for STM32 Cube IDE

This example includes:

* wolfCrypt test
* wolfCrypt benchmark
* wolfSSL TLS client/server test using in-memory transfers

These examples use the Cube HAL for STM32.

## Requirements

You need both the STM32 IDE and the STM32 initialization code generator (STM32CubeMX) tools. The STM32CubeMX tool is used to setup a project which is used by the IDE to make any required code level changes and program / debug the STM32.

* STM32CubeIDE: Integrated Development Environment for STM32 [https://www.st.com/en/development-tools/stm32cubeide.html](https://www.st.com/en/development-tools/stm32cubeide.html)
* STM32CubeMX: STM32Cube initialization code generator [https://www.st.com/en/development-tools/stm32cubemx.html](https://www.st.com/en/development-tools/stm32cubemx.html)

## STM32 Cube Pack

### STM32 Cube Pack Installation

1. Download [wolfSSL Cube Pack](https://www.wolfssl.com/files/ide/I-CUBE-wolfSSL.pack)
2. Run the “STM32CubeMX” tool.
3. Under “Manage software installations” pane on the right, click “INSTALL/REMOVE” button. This can be also found by clicking "Help" -> "Managed embedded software packages"
4. From Local and choose “I-CUBE-wolfSSL.pack”.
5. Accept the GPLv2 license. Contact wolfSSL at sales@wolfssl.com for a commercial license and support/maintenance.

### STM32 Cube Pack Usage

1. Create or open a Cube Project based on your hardware. See the sections below for creating a project and finding the example projects.
2. Under “Software Packs” choose “Select Components”.
3. Find and check all components for the wolfSSL.wolfSSL packs (wolfSSL / Core, wolfCrypt / Core and wolfCrypt / Test). Close
4. Under the “Software Packs” section click on “wolfSSL.wolfSSL” and configure the parameters.
5. For Cortex-M recommend “Math Configuration” -> “Single Precision Cortex-M Math” for the fastest option.
6. Hit the "Generate Code" button
7. Open the project in STM32CubeIDE
8. The Benchmark example uses float. To enable go to "Project Properties" -> "C/C++ Build" -> "Settings" -> "Tool Settings" -> "MCU Settings" -> Check "Use float with printf".
9. To enable printf make the `main.c` changes below in the [STM32 Printf](#stm32-printf) section.

### STM32 Cube Pack Examples

In the `I-CUBE-wolfSSL.pack` pack there are pre-assembled example projects available.
After installing the pack you can find these example projects in `STM32Cube/Repository/Packs/wolfSSL/wolfSSL/[Version]/Projects`.
To use an example:

1. Open STM32CubeIDE
2. Choose "Import" -> "Import an Existing STM32CubeMX Configuration File (.ioc)".
3. Browse to find the .ioc in `STM32Cube/Repository/Packs/wolfSSL/wolfSSL/[Version]/Projects` and click finish.

### Creating your own STM32CubeMX configuration

If none of the examples fit your STM32 type then you can create your own in STM32CubeMX by doing the following:

1. Create a project with the correct STM32 model.
2. Click on the "Software Packs" drop down near the top and choose "Select Components".
3. Expand the "wolfSSL" pack twice and check all the components. Then exit this menu.
4. Under "System Core" select "SYS" and changed the "Timebase Source" to TIM1.
5. Under "Timers" select "RTC" and make sure this is enabled.
6. Under "Connectivity" enable whichever UART/USART you have a serial I/O connected to.
7. Under "Middleware" select "FREERTOS" and change the interface to "CMSIS_V2".
    1. Increase the "TOTAL_HEAP_SIZE", preferably to 120000 but on smaller chips such as the F107 you may only be able to increase this to 40000.
    2. Enable "USE_MALLOC_FAILED_HOOK".
    3. Change "CHECK_FOR_STACK_OVERFLOW" to "Option2".
    4. Under "Tasks and Queues" select Add for a new task.
    5. Set the "Task Name" to "wolfCrypt".
    6. Set the "Stack Size" to 8960 or as high as you can close to that. The "Heap Usage" will show an error if this is too high.
    7. Set the "Entry Function" to "wolfCryptDemo".
    8. Set the "Code Generation Option" to "As external".
8. In "Software Packs" select "wolfSSL" and change any options as required.
9. Go to "Clock Configuration" and set the "HCLK" as high as the tool will let you.
10. In "Project Manager" select the "STM32CubeIDE" toolchain.

When you get to the IDE make sure you edit `wolfSSL.I-CUBE-wolfSSL_conf.h` to set the `HAL_CONSOLE_UART` to the correct one for your configuration.

## Configuration

The settings for the wolfSSL CubeMX pack are in the generated `wolfSSL.I-CUBE-wolfSSL_conf.h` file. An example of a generated file can be found at `examples/configs/user_settings_stm32.h`.

The template used for generation is `IDE/STM32Cube/default_conf.ftl`, which is stored in the pack here: `STM32Cube/Repository/Packs/wolfSSL/wolfSSL/[Version]/CubeMX/templates/default_conf.ftl`.

If the default settings for the Cube GUI are insufficient you can customize the build using one of these methods to prevent the changes from being overwritten when generating the code:

* Copy the `wolfSSL.I-CUBE-wolfSSL_conf.h` to `Core/Inc` and rename to `user_settings.h`. Then add the preprocessor macro `WOLFSSL_USER_SETTINGS` to your project. This will use the `user_settings.h` instead of the generated configuration.

OR

* Edit the source template file used for Cube pack generation here: `STM32Cube/Repository/Packs/wolfSSL/wolfSSL/[Version]/CubeMX/templates/default_conf.ftl`.


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

With STM32 Cube HAL v2 some AES GCM hardware has a limitation for the AAD header, which must be a multiple of 4 bytes.

If using `STM32_AESGCM_PARTIAL` with the following patch it will enable use for all AAD header sizes. The `STM32Cube_FW_F7_V1.16.0` patch is:

```diff
diff --git a/Drivers/STM32F7xx_HAL_Driver/Inc/stm32f7xx_hal_cryp.h b/Drivers/STM32F7xx_HAL_Driver/Inc/stm32f7xx_hal_cryp.h
--- a/Drivers/STM32F7xx_HAL_Driver/Inc/stm32f7xx_hal_cryp.h
+++ b/Drivers/STM32F7xx_HAL_Driver/Inc/stm32f7xx_hal_cryp.h
@@ -63,6 +63,7 @@ typedef struct
                                         GCM : also known as Additional Authentication Data
                                         CCM : named B1 composed of the associated data length and Associated Data. */
   uint32_t HeaderSize;                /*!< The size of header buffer in word  */
+  uint32_t HeaderPadSize;             /*!< <PATCH> The size of padding in bytes added to actual header data to pad it to a multiple of 32 bits </PATCH>  */
   uint32_t *B0;                       /*!< B0 is first authentication block used only  in AES CCM mode */
   uint32_t DataWidthUnit;              /*!< Data With Unit, this parameter can be value of @ref CRYP_Data_Width_Unit*/
   uint32_t KeyIVConfigSkip;            /*!< CRYP peripheral Key and IV configuration skip, to config Key and Initialization

diff --git a/Drivers/STM32F7xx_HAL_Driver/Src/stm32f7xx_hal_cryp_ex.c b/Drivers/STM32F7xx_HAL_Driver/Src/stm32f7xx_hal_cryp_ex.c
--- a/Drivers/STM32F7xx_HAL_Driver/Src/stm32f7xx_hal_cryp_ex.c
+++ b/Drivers/STM32F7xx_HAL_Driver/Src/stm32f7xx_hal_cryp_ex.c
@@ -132,6 +132,8 @@ HAL_StatusTypeDef HAL_CRYPEx_AESGCM_GenerateAuthTAG(CRYP_HandleTypeDef *hcryp, u
   uint64_t inputlength = (uint64_t)hcryp->SizesSum * 8U; /* input length in bits */
   uint32_t tagaddr = (uint32_t)AuthTag;
 
+  headerlength -= ((uint64_t)(hcryp->Init.HeaderPadSize) * 8U); /* <PATCH> Decrement the header size removing the pad size </PATCH> */  
+
   if (hcryp->State == HAL_CRYP_STATE_READY)
   {
     /* Process locked */
```

If you are using FreeRTOS make sure your `FreeRTOSConfig.h` has its `configTOTAL_HEAP_SIZE` increased.

The TLS client/server benchmark example requires about 76 KB for allocated tasks (with stack) and peak heap. This uses both a TLS client and server to test a TLS connection locally for each enabled TLS cipher suite.

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

This section needs to go below the `UART_HandleTypeDef` line, otherwise `wolfssl/wolfcrypt/settings.h` will error.

```c
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
```

In the `main()` function make the follow `setvbuf()` additions after `HAL_Init()`.

```c
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
