# wolfSSL TLS Client Example

This is the wolfSSL TLS Client demo, typically used with the [Espressif TLS Server](../wolfssl_server/README.md)
or the CLI [Server](https://github.com/wolfSSL/wolfssl/tree/master/examples/server).

When using the CLI, see the [example parameters](/IDE/Espressif/ESP-IDF/examples#interaction-with-wolfssl-cli).

For general information on [wolfSSL examples for Espressif](../README.md), see the
[README](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md) file.

## Quick Start

Use the `ESP-IDF` for ESP32 or `RTOS SDK` for the ESP8266.

Run `menuconfig` utility (`idf.py menuconfig` for ESP32 or `make menuconfig` for the ESP8266)
and set the various parameters for the target device, along with local WiFi settings:

* Target Host: `CONFIG_WOLFSSL_TARGET_HOST` (The IP address of a listening server)
* Target Port: `CONFIG_WOLFSSL_TARGET_PORT` (Typically `11111`)
* Example WiFi SSID: `CONFIG_EXAMPLE_WIFI_SSID` (The WiFi that you want to connect to)
* Example WiFi Password: `CONFIG_EXAMPLE_WIFI_PASSWORD` (The WiFi password)

The latest examples use makefiles that do not require local file copy installation of wolfSSL.

Build and flash the software to see the example in action.

##  Quick Start with VisualGDB

There are optional [VisualGDB](https://visualgdb.com/tutorials/esp8266/) project files in the
[VisualGDB](./VisualGDB) project subdirectory, and an ESP8266 project file in the project directory,
called `wolfssl_client_ESP8266.vgdbproj`.

Open the VisualGDB Visual Studio Project file in the VisualGDB directory and click the "Start" button.
No wolfSSL setup is needed. You may need to adjust your specific COM port. The default is `COM19`.

## Troubleshooting

Weird results, odd messages, unexpected compiler errors? Manually delete the build directory and
any locally generated files (`sdkconfig`, `sdkconfig-debug`, etc.) and start over.

The `build` directory is typically located in the root of the project directory:  `[project]/build`.


Difficulty flashing:

* Ensure the target device has a robust, stable, clean power supply.
* Check that quality USB cables are being used.
* Try lowering the flash baud rate in the `menuconfig`. The 115200 is typically reliable.
* Review board specifications: some require manual boot mode via on-board buttons.
* See Espressif ESP Frequently Asked Questions `esp-faq-en-master.pdf`.

## ESP-IDF Commandline v5.x


1. `idf.py menuconfig` to config the project

      1-1. Example Configuration ->

          Target host ip address : the host that you want to connect to.(default is 127.0.0.1)

     1-2. Example Connection Configuration ->

          WIFI SSID: your own WIFI, which is connected to the Internet.(default is "myssid")
          WIFI Password: WIFI password, and default is "mypassword"


    Note: the example program uses 11111 port. If you want to use different port
        , you need to modify DEFAULT_PORT definition in the code.

When you want to test the wolfSSL client

1. `idf.py -p <PORT> flash` and then `idf.py monitor` to load the firmware and see the context
2. You can use <wolfssl>/examples/server/server program for test.

         e.g. Launch ./examples/server/server -v 4 -b -i -d


## VisualGDB for ESP8266

Reminder that we build with `make` and not `cmake` in VisualGDB.

Build files will be created in `[project directory]\build`

See notes below if building a project in a directory other than the examples.

Problems?

- Try deleting any existing `sdkconfig` file and/or `./build` directory to start fresh.
- Be sure the RTOS SDK is installed and properly configured.

## ESP-IDF `make` Commandline (version 3.5 or earlier for the ESP8266)

In-place example build:

```bash
export IDF_PATH=~/esp/ESP8266_RTOS_SDK
export PATH="$PATH:$HOME/esp/xtensa-lx106-elf/bin"
cd /mnt/c/workspace/wolfssl-master/IDE/Espressif/ESP-IDF/examples/wolfssl_client
make clean
make
```

When building a in a *different directory*, for example assuming the `wolfssl_client` in the wolfssl examples
directory is copied to the `C:\test\demo` directory in Windows. (aka ` /mnt/c/test/demo` in WSL),
with a clone of wolfSSL `master` branch in `C:\workspace\wolfssl-master`:

```bash
cp -r /mnt/c/workspace/wolfssl-master/IDE/Espressif/ESP-IDF/examples/wolfssl_client/* /mnt/c/test/demo
```

Modify the project `./components/wolfssl/component.mk` file. Adjust `WOLFSSL_ROOT` setting, in this case to a value of:

`WOLFSSL_ROOT := ../../../../workspace/wolfssl-master`

Ensure the path is *relative* to the project `component.mk` file location and *not* absolute.

Note the location of the component makefile in this case is `c:\test\demo\components\wolfssl\component.mk`.
Thus we need to navigate up 4 parents to the root of `C:\` to find `/mnt/c` in WSL.

Proceed to run `make` from the project directory as usual:

```bash
# setup environment as needed
export IDF_PATH=~/esp/ESP8266_RTOS_SDK
export PATH="$PATH:$HOME/esp/xtensa-lx106-elf/bin"

# copy and navigate to project directory
mkdir -p /mnt/c/test/demo
cp -r /mnt/c/workspace/wolfssl-master/IDE/Espressif/ESP-IDF/examples/wolfssl_client/* /mnt/c/test/demo
cd /mnt/c/test/demo

# Clean
rm -rf ./build
rm sdkconfig
make clean

# Edit ./components/wolfssl/component.mk and set WOLFSSL_ROOT value
# WOLFSSL_ROOT := ../../../../workspace/wolfssl-master

# build the example project
make
```

When using `make` there should be details in the build log to indicate
the assigned path, and the equivalent, fully-qualified path of `WOLFSSL_ROOT`.

```
*************  wolfssl_client *************
***********  wolfssl component ************
WOLFSSL_ROOT defined: ../../../../workspace/wolfssl-master
WOLFSSL_ROOT actual:  /mnt/c/workspace/wolfssl-master
********** end wolfssl component **********
```


## ESP-IDF CMake Commandline (version 3.5 or earlier for the ESP8266)

Build files will be created in `[project directory]\build\debug`

```
# Set your path to RTOS SDK, shown here for default from WSL with VisualGDB
WRK_IDF_PATH=/mnt/c/SysGCC/esp8266/rtos-sdk/v3.4
#  or
WRK_IDF_PATH=~/esp/ESP8266_RTOS_SDK

# Setup the environment
. $WRK_IDF_PATH/export.sh

# install as needed / prompted
/mnt/c/SysGCC/esp8266/rtos-sdk/v3.4/install.sh

# Fetch wolfssl from GitHub if needed:
cd /workspace
git clone https://github.com/wolfSSL/wolfssl.git

# change directory to wolfssl client example.
cd wolfssl/IDE/Espressif/ESP-IDF/examples/wolfssl_client

# or for example, WSL with C:\workspace as home for git clones:
# cd /mnt/c/workspace/wolfssl-$USER/IDE/Espressif/ESP-IDF/examples/wolfssl_client

# adjust settings as desired
idf.py menuconfig


idf.py build flash -p /dev/ttyS70 -b 115200
idf.py monitor -p /dev/ttyS70 -b 74880
```

## SM Ciphers

(TODO coming soon)
See https://github.com/wolfSSL/wolfsm

#### Working Linux Client to ESP32 Server Example:

```
./examples/client/client -h 192.168.1.37 -p 11111 -v 3
```

```text
-c <file>   Certificate file,           default ./certs/client-cert.pem
-k <file>   Key file,                   default ./certs/client-key.pem
-A <file>   Certificate Authority file, default ./certs/ca-cert.pem
```

Example client, with default certs explicitly given:

```bash
./examples/client/client -h 192.168.1.37 -p 11111 -v 3 -c ./certs/client-cert.pem -k      ./certs/client-key.pem -A     ./certs/ca-cert.pem
```

Example client, with RSA 1024 certs explicitly given:

```
./examples/client/client -h 192.168.1.37 -p 11111 -v 3 -c ./certs/1024/client-cert.pem -k ./certs/1024/client-key.pem -A ./certs/1024/ca-cert.pem
```

Command:

```
cd /mnt/c/workspace/wolfssl-$USER/IDE/Espressif/ESP-IDF/examples/wolfssl_server
. /mnt/c/SysGCC/esp32/esp-idf/v5.2/export.sh
idf.py flash -p /dev/ttyS19 -b 115200 monitor
```

```
cd /mnt/c/workspace/wolfssl-$USER

./examples/client/client  -h 192.168.1.108 -v 4 -l TLS_SM4_GCM_SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem     -A ./certs/sm2/root-sm2.pem -C
```

Output:

```text
SSL version is TLSv1.3
SSL cipher suite is TLS_SM4_GCM_SM3
SSL curve name is SM2P256V1
I hear you fa shizzle!
```

#### Linux client to Linux server:

```
./examples/client/client  -h 127.0.0.1 -v 4 -l ECDHE-ECDSA-SM4-CBC-SM3     -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem     -A ./certs/sm2/root-sm2.pem -C

./examples/server/server                   -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3     -c ./certs/sm2/server-sm2.pem -k ./certs/sm2/server-sm2-priv.pem     -A ./certs/sm2/client-sm2.pem -V
```


#### Linux Client using Kyber to ESP32 Server

```
# Ensure build with Kyber enabled:
# ./configure --enable-kyber=all --enable-experimental && make

./examples/client/client  -h 192.168.1.38 -v 4 -l  TLS_AES_128_GCM_SHA256 --pqc KYBER_LEVEL5
```

#### ESP32 Client to WSL Linux Server

In Windows Powershell, (elevated permissions) forward the port _after_ starting the listening server:

```bash
netsh interface portproxy add v4tov4 listenport=11111 listenaddress=0.0.0.0 connectport=11111 connectaddress=127.0.0.1
```

After the server exits, remove the port proxy forward:

```bash
netsh interface portproxy delete v4tov4 listenport=11111 listenaddress=0.0.0.0
```

For additional information, see [Accessing network applications with WSL](https://learn.microsoft.com/en-us/windows/wsl/networking).


## Additional Information

See the README.md file in the upper level 'examples' directory for [more information about examples](../README.md).
