# wolfSSL Template Project

This is an example of a minimally viable wolfSSL template to get started with your own project.

For general information on [wolfSSL examples for Espressif](../README.md), see the
[README](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md) file.

### Prerequisites

It is assumed the [ESP-IDF environment](Espressifget-started/) has been installed.

### Files Included

- [main.c](./main/main.c) with a simple call to an Espressif library (`ESP_LOGI`) and a call to a wolfSSL library (`esp_ShowExtendedSystemInfo`) .

- See [components/wolfssl/include](./components/wolfssl/include/user_settings.h) directory to edit the wolfSSL `user_settings.h`.

- Edit [main/CMakeLists.txt](./main/CMakeLists.txt) to add/remove source files.

- The [components/wolfssl/CMakeLists.txt](./components/wolfssl/CMakeLists.txt) typically does not need to be changed.

- Optional [VisualGDB Project](./VisualGDB/README.md) for Visual Studio using ESP32 and ESP-IDF v5.2. See also [template](../template/VisualGDB/README.md) for other devices.

- Edit the project [CMakeLists.txt](./CMakeLists.txt) to optionally point this project's wolfSSL component source code at a different directory:

```
set(WOLFSSL_ROOT "~/workspace/wolfssl-other-source")
```


## Getting Started:

Here's an example using the command-line [idf.py](Espressifapi-guides/tools/idf-py.html).

Edit your `WRK_IDF_PATH`to point to your ESP-IDF install directory.

```
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

echo "Run export.sh from ${WRK_IDF_PATH}"
. ${WRK_IDF_PATH}/export.sh

# build the example:
idf.py build

# optionally erase the flash
idf.py erase-flash -p /dev/ttyS19 -b 115200

# flash the code onto the serial device at /dev/ttyS19
idf.py flash -p /dev/ttyS19 -b 115200

# build, flash, and view UART output with one command:
idf.py flash -p /dev/ttyS19 -b 115200 monitor
```

Press `Ctrl+]` to exit `idf.py monitor`. See [additional monitor keyboard commands](Espressifapi-guides/tools/idf-monitor.html).

## Other Examples:

For examples, see:

- [TLS Client](../wolfssl_client/README.md)
- [TLS Server](../wolfssl_server/README.md)
- [Benchmark](../wolfssl_benchmark/README.md)
- [Test](../wolfssl_test/README.md)
- [wolfssl-examples](https://github.com/wolfSSL/wolfssl-examples/tree/master/ESP32)
- [wolfssh-examples](https://github.com/wolfSSL/wolfssh-examples/tree/main/Espressif)


See the README.md file in the upper level 'examples' directory for [more information about examples](../README.md).


