

# wolfSSL Espressif IDE

This directory contains documentation and examples for the Espressif SoC devices.

Although wolfSSL _should_ work on any Espressif device, there's explicit support for these:

- esp32
- esp32c2
- esp32c3
- esp32c6
- esp32s2
- esp32s3
- esp32h2


## Getting Started

If you are new to wolfSSL on the Espressif ESP32, [this video](https://www.youtube.com/watch?v=CzwA3ZBZBZ8)
can help to get started:

[![Video Preview](https://img.youtube.com/vi/CzwA3ZBZBZ8/0.jpg)](https://www.youtube.com/watch?v=CzwA3ZBZBZ8)

Additional ESP-IDF specifics can be found in [Espressif/ESP-IDF](./ESP-IDF/README.md). The [wolfSSL Manual](https://www.wolfssl.com/documentation/manuals/wolfssl/index.html) is also a useful
resource.

## Requirements

The wolfSSL Espressif code requires the ESP-IDF to be installed for
[Windows](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/windows-setup.html)
or [Linux / MacOS](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/linux-macos-setup.html).

See the [Espressif Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/).

Any editor can be used. See also the [Espressif Third-Party Tools](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/resources.html)
for a list of feature-rich Integrated Development Environments.
The [wolfSSL examples](./ESP-IDF/examples/README.md) all include a `./VisualGDB` directory with SoC-specific configurations
to help get started quickly.

Although not required, a [JTAG Adapter](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/jtag-debugging/index.html)
can be helpful for development. When not using a built-in JTAG from Espressif, the examples typically
use the open source [Tigard board](https://github.com/tigard-tools/tigard#readme).

## Examples:

There are a variety of examples to help get started:

* [ESP-IDF Examples](./ESP-IDF/README.md)

## Managed Component

The wolfSSL library can be installed as a managed component:

* [Espressif Managed Component Registry](https://components.espressif.com/components/wolfssl/wolfssl)

## Notes:

WSL environment:

Contents of `/etc/wsl.conf`:
```text
[automount]
options = "metadata"
```

To ignore changes in file attributes, see https://github.com/microsoft/WSL/issues/936#issuecomment-1751469229

```
git config core.filemode false
```


Quick start
```

WORKSPACE=/mnt/c/workspace
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.1
WRK_WOLFSSL_PATH=${WORKSPACE}/wolfssl-$USER
WRK_PROJECT_DIR=${WRK_WOLFSSL_PATH}/IDE/Espressif/ESP-IDF/examples/wolfssl_test

echo "Run export.sh from ${WRK_IDF_PATH}"
. ${WRK_IDF_PATH}/export.sh

echo "Build and flash project in ${WRK_PROJECT_DIR}"
cd ${WRK_PROJECT_DIR}
idf.py build flash -p /dev/ttyS9 -b 115200 monitor
```

Bad chip version:

```
ESP-ROM:esp32c3-20200918
Build:Sep 18 2020
rst:0x3 (RTC_SW_SYS_RST),boot:0xc (SPI_FAST_FLASH_BOOT)
Saved PC:0x403d151e
SPIWP:0xee
mode:DIO, clock div:2
load:0x3fcd6100,len:0x16c8
load:0x403ce000,len:0x930
load:0x403d0000,len:0x2d28
entry 0x403ce000
I (34) boot: ESP-IDF v4.4.2-1-g0aba20e63d-dirty 2nd stage bootloader
I (35) boot: compile time 08:29:06
I (35) boot: chip revision: 2
E (38) boot_comm: This chip is revision 2 but the application is configured for minimum revision 3. Can't run.
```

If you've encountered a chip version earlier than that confirmed to be working
at wolfSSL, try adjusting the settings in `menuconfig`.

#### A fatal error occurred: This chip is esp[X] not esp[Y]

```
A fatal error occurred: This chip is ESP32-S3 not ESP32-C3. Wrong --chip argument?
CMake Error at run_serial_tool.cmake:56 (message):
  /home/gojimmypi/.espressif/python_env/idf4.4_py3.8_env/bin/python
  /mnt/c/SysGCC/esp32/esp-idf/v4.4.2/components/esptool_py/esptool/esptool.py
  --chip esp32c3 failed
```

Delete the `./build` and rename/delete your `sdkconfig` file, then run
`idf.py set-target`, in this example setting to `esp32c3`:

```bash
idf.py set-target esp32c3
```

#### Cmake Cache Warning

```
Executing action: clean
Project sdkconfig was generated for target 'esp32s3', but CMakeCache.txt contains 'esp32c3'. To keep the setting in sdkconfig (esp32s3) and re-generate CMakeCache.txt, run 'idf.py fullclean'. To re-generate sdkconfig for 'esp32c3' target, run 'idf.py set-target esp32c3'.
```

As indicated, run `idf.py set-target` and/or delete the `./build` directory.

#### Connecting, but fails to connect.

Some devices, particularly 3rd party, non-Espressif dev boards may not have implemented
the reset-program hardware properly, causing devices to not be programmed with the
`idf.py flash` command:

```
Connecting......................................

A fatal error occurred: Failed to connect to ESP32: Wrong boot mode detected (0x13)! The chip needs to be in download mode.
For troubleshooting steps visit: https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html
CMake Error at run_serial_tool.cmake:56 (message):
  /home/gojimmypi/.espressif/python_env/idf4.4_py3.8_env/bin/python
  /mnt/c/SysGCC/esp32/esp-idf/v4.4.2/components/esptool_py/esptool/esptool.py
  --chip esp32 failed
```

Solution:

Press and hold`EN` button, press and release `IO0` button, then release `EN` button.

#### Other Solutions

See also [this ESP-FAQ Handbook](https://docs.espressif.com/projects/esp-faq/en/latest/esp-faq-en-master.pdf)
