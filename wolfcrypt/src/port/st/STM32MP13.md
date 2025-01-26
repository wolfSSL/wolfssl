# STM32MP13 Port

The STM32MP13 is unique in that it is an MPU instead of an MCU. The HAL also
behaves a little differently. This document outlines how to use it in bare
metal mode. For Linux, this should be used as a normal ARM Linux device.

## Linux

To cross-compile from a Linux host to the STM32MP13 OpenSTLinux, you need to
install the [SDK](https://www.st.com/en/embedded-software/stm32mp1dev.html#get-software).
In this example, I have extracted it to `/opt/st`.

Your build environment is configured by running:

```sh
source /opt/st/stm32mp1/4.2.4-openstlinux-6.1-yocto-mickledore-mpu-v24.06.26/environment-setup-cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi
```

If you wish to compile with support for `/dev/crypto` then you will also need to
do the following so that the headers are found by the compiler:

```sh
export CFLAGS="$CFLAGS -I /opt/st/stm32mp1/4.2.4-openstlinux-6.1-yocto-mickledore-mpu-v24.06.26/sysroots/cortexa7t2hf-neon-vfpv4-ostl-linux-gnueabi/usr/src/debug/cryptodev-module/1.12-r0/"
```

When running `./configure`, make sure you add `--host=arm-linux-gnueabi` to the
configure options.

## Bare metal

To develop in bare metal, the board needs to be started in "engineering mode".
In this mode, there is 128KB of SRAM and 512MB of DDR RAM, but the DDR RAM is
not initialized. On the STM32MP135-DK board, there is no flash storage.

There is a catch-22 here, a wolfSSL project will likely need more than 128KB of
storage and RAM. But it cannot be loaded into the DDR RAM until the DDR has been
initialized. To work around this, before running the wolfSSL project, an
example project called `DDR_Init` needs to be run first. This sets up the clocks
and initializes the DDR RAM. The wolfSSL project can then be loaded into the DDR
RAM, where it is executed.

The DDR RAM section below shows how to obtain the `DDR_Init` project.

### Setting up

The board itself has dip switches to set the boot mode. These should be set to
off-off-on-off to set the board into "engineering mode". The MPU's SRAM can
then be flashed via the ST-Link.

#### Device Configuration Tool

In the configuration tool, enable and activate the following:

```
CRYP1
HASH1
PKA
RNG1
RTC
```

#### DDR RAM

As mentioned above, the DDR RAM needs to be initialized before the wolfSSL
project can be executed.

You need to obtain the [STM32MP13 MPU Firmware Package](https://github.com/STMicroelectronics/STM32CubeMP13),
which contains many examples of how to use the board in bare metal mode. One
of the examples is the [DDR Init](https://github.com/STMicroelectronics/STM32CubeMP13/tree/main/Projects/STM32MP135C-DK/Examples/DDR/DDR_Init),
which you will need to use all the features of wolfSSL. This is because the SRAM
is only 128KB, but the DDR RAM is 512MB. This example initializes the DDR RAM,
it also sets the MPU to 650MHz.

#### MMU & Cache

The MMU and cache will increase performance around 50x, so it is highly
recommended. It may, however, make debugging more difficult.

To enable them, in the preprocessor settings, change:

```
NO_MMU_USE
NO_CACHE_USE
```

to:

```
MMU_USE
CACHE_USE
```

Note that the Cube IDE may break this if you make any changes to the Device
Configuration Tool.

#### printf()

If you are using an STM32MP135F-DK board and want to use the ST-Link UART for
`printf()`, then you need to set PD6 and PD8 as the UART 4 RX/TX pins. You can
then enable UART4 and set it to "Asynchronous" mode.

In the code 0 section of `main.c` add:

```c
#ifdef __GNUC__
int __io_putchar(int ch)
#else
int fputc(int ch, FILE *f)
#endif
{
    HAL_UART_Transmit(&huart4, (uint8_t *)&ch, 1, 0xFFFF);

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

UART4 will now be used for `printf()`.



### wolfSSL in your project

There are a few things you need to do to get wolfSSL to run in your project. The
first is setting compile option, these additional ones are needed. The first
allows ARM ASM optimizations to compile, the second stops alignment issues from
crashing the board:

```
-fomit-frame-pointer
-mno-unaligned-access
```

The first of these should also be a flag for the assembler as well.

Then the code needs to be set to use the DDR RAM instead of SRAM. To do this,
edit `STM32MP135FAFX_RAM.ld` and change:

```c
REGION_ALIAS("RAM", SYSRAM_BASE);
```

To this:

```c
REGION_ALIAS("RAM", DDR_BASE);
```

In the Run Configuration menu, make sure that the debugger's startup has the
"monitor reset" command removed. Otherwise the DDR initialization will be reset.

In the `main.c` make sure that `SystemClock_Config();` is not executed. The DDR
Init code will do this, and changing it will likely crash the board. It can
be done like this:

```c
  /* USER CODE BEGIN Init */
#if 0
  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */
#endif
  /* USER CODE END SysInit */
```

### Benchmark

To use the wolfCrypt benchmark, add this to your `main.c`:

```c
double current_time(void)
{
    RTC_TimeTypeDef time;
    RTC_DateTypeDef date;
    uint32_t subsec = 0;

    /* must get time and date here due to STM32 HW bug */
    HAL_RTC_GetTime(&hrtc, &time, RTC_FORMAT_BIN);
    HAL_RTC_GetDate(&hrtc, &date, RTC_FORMAT_BIN);
    /* Not all STM32 RTCs have subseconds in the struct */
#ifdef RTC_ALARMSUBSECONDMASK_ALL
    subsec = (255 - time.SubSeconds) * 1000 / 255;
#endif

    (void) date;

    /* return seconds.milliseconds */
    return ((double) time.Hours * 24) + ((double) time.Minutes * 60)
            + (double) time.Seconds + ((double) subsec / 1000);
}
```

Then in the user code 2 block, you can add:

```c
  uint32_t mpuss_clock = HAL_RCC_GetMPUSSFreq() / 1000000;

  printf("System clock: %ld MHz, rng clock: %ld MHz\n\n", mpuss_clock);

  int ret;
  ret = benchmark_test(NULL);
  printf("End: %d\n", ret);
```

### Testing

To use the wolfCrypt test suite,

### Compiling wolfSSL

In your `user_settings.h` you should include:

```c
#define WOLFSSL_STM32MP13
#define WOLFSSL_STM32_CUBEMX
#define WOLFSSL_USER_CURRTIME
```

If you want ECDSA acceleration, you should also add:

```c
#define WOLFSSL_STM32_PKA
#define WOLFSSL_STM32_PKA_V2
```

### Running

Once you have compiled everything, to run your project, you will first need to
run the DDR Init project. This will initialize the DDR RAM and the blue LED on
the board will flash.

You can then run the wolfSSL based project. If the board loses power, the
DDR Init project will need to be run again before you are able to run the
wolfSSL project.
