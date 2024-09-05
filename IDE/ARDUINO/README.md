# wolfSSL with Arduino

See the [example sketches](./sketches/README.md):

- [sketches/wolfssl_server](./sketches/wolfssl_server/README.md)
- [sketches/wolfssl_client](./sketches/wolfssl_client/README.md)

When publishing a new version to the Arduino Registry, be sure to edit `WOLFSSL_VERSION_ARUINO_SUFFIX` in the `wolfssl-arduino.sh` script.

## Boards

Many of the supported boards are natively built-in to the [Arduino IDE Board Manager](https://docs.arduino.cc/software/ide-v2/tutorials/ide-v2-board-manager/)
and by adding [additional cores](https://docs.arduino.cc/learn/starting-guide/cores/) as needed.

STM32 Support can be added by including this link in the "Additional Boards Managers URLs" field
from [stm32duino/Arduino_Core_STM32](https://github.com/stm32duino/Arduino_Core_STM32?tab=readme-ov-file#getting-started)   .

```
https://github.com/stm32duino/BoardManagerFiles/raw/main/package_stmicroelectronics_index.json
```

## Using wolfSSL from the Arduino IDE

The Official wolfSSL: https://github.com/wolfSSL/arduino-wolfSSL See [PR #1](https://github.com/wolfSSL/Arduino-wolfSSL/pull/1).

This option will allow wolfSSL to be installed directly using the native Arduino tools.

## Manually Reformatting wolfSSL as a Compatible Arduino Library

Use [this](./wolfssl-arduino.sh) shell script that will re-organize the wolfSSL library to be
compatible with [Arduino Library Specification](https://arduino.github.io/arduino-cli/0.35/library-specification/)
for projects that use Arduino IDE 1.5.0 or newer.

The Arduino IDE requires a library's source files to be in the library's root directory with a
header file in the name of the library. This script moves all `src/` files to the `IDE/ARDUINO/wolfSSL/src`
directory and creates a stub header file called `wolfssl.h` inside that directory.

### Step 1:

To configure wolfSSL with Arduino, enter ONE of the following 4 commands
from within the `wolfssl/IDE/ARDUINO` directory:

1. `./wolfssl-arduino.sh`
    - Creates an Arduino Library directory structure in the local `wolfSSL` directory of `IDE/ARDUINO`.
    - You can add your own `user_settings.h`, or copy/rename the [default](../../examples/configs/user_settings_arduino.h).

2. `./wolfssl-arduino.sh INSTALL` (The most common option)
    - Creates an Arduino Library in the local `wolfSSL` directory
    - Moves that directory to the Arduino library directory:
        - `$HOME/Arduino/libraries` for most bash environments
        - `/mnt/c/Users/$USER/Documents/Arduino/libraries` (for WSL)
    - Adds the [default](../../examples/configs/user_settings_arduino.h) as `user_settings.h`.
    - The wolfSSL library is now available from the Arduino IDE.

3. `./wolfssl-arduino.sh INSTALL /path/to/repository` (Used to update [arduino-wolfSSL](https://github.com/wolfSSL/arduino-wolfSSL))
    - Creates an Arduino Library in `wolfSSL` directory
    - Copies that directory contents to the specified `/path/to/repository`
    - Adds the [default](../../examples/configs/user_settings_arduino.h) as `user_settings.h`.

4. `./wolfssl-arduino.sh INSTALL /path/to/any/other/directory`
    - Creates an Arduino Library in `wolfSSL` directory
    - Copies that directory contents to the specified `/path/to/any/other/directory`

### Step 2:

Edit `<arduino-libraries>/wolfSSL/src/user_settings.h`
If building for Intel Galileo platform add: `#define INTEL_GALILEO`.
Add any other custom settings. For a good start see the examples in wolfssl root
"[/examples/configs/user_settings_*.h](https://github.com/wolfssl/wolfssl/tree/master/examples/configs)"

### Step 3:

If you experience any issues with custom `user_settings.h` see the wolfssl
porting guide here for more assistance: https://www.wolfssl.com/docs/porting-guide/

If you have any issues contact support@wolfssl.com for help.

# Including wolfSSL in Arduino Libraries (for Arduino version 2.0 or greater)

1. In the Arduino IDE:

The wolfSSL library should automatically be detected when found in the `libraries`
directory.

  - In `Sketch -> Include Library` choose wolfSSL for new sketches.


##### Including wolfSSL in Arduino Libraries (for Arduino version 1.6.6)

1. In the Arduino IDE:
    - In `Sketch -> Include Library -> Add .ZIP Library...` and choose the
        `IDE/ARDUNIO/wolfSSL` folder.
    - In `Sketch -> Include Library` choose wolfSSL.

##### wolfSSL Examples

Open an example Arduino sketch for wolfSSL:

  - wolfSSL [Client INO sketch](./sketches/wolfssl_client/README.md): `sketches/wolfssl_client/wolfssl_client.ino`

  - wolfSSL [Server INO sketch](./sketches/wolfssl_server/README.md): `sketches/wolfssl_server/wolfssl_server.ino`

#### Script Examples

Refresh the local Windows Arduino wolfSSL library from GitHub repository directory using WSL:

Don't forget to edit `WOLFSSL_VERSION_ARUINO_SUFFIX`!

```bash
# Change to the wolfSSL Arduino IDE directory
cd /mnt/c/workspace/wolfssl-$USER/IDE/ARDUINO

# remove current Arduino wolfSSL library
rm -rf /mnt/c/Users/$USER/Documents/Arduino/libraries/wolfssl

# Install wolfSSL as an Arduino library
./wolfssl-arduino.sh INSTALL
```

Publish wolfSSL from WSL to a `Arduino-wolfSSL-$USER` repository.

```bash
cd /mnt/c/workspace/wolfssl-$USER/IDE/ARDUINO
rm -rf /mnt/c/Users/$USER/Documents/Arduino/libraries/wolfSSL
rm -rf /mnt/c/workspace/wolfssl-$USER/IDE/ARDUINO/wolfSSL
./wolfssl-arduino.sh INSTALL /mnt/c/workspace/Arduino-wolfSSL-$USER/
```

Publish wolfSSL from WSL to default Windows local library.

```bash
cd /mnt/c/workspace/wolfssl-$USER/IDE/ARDUINO
rm -rf /mnt/c/Users/$USER/Documents/Arduino/libraries/wolfSSL
rm -rf /mnt/c/workspace/wolfssl-arduino/IDE/ARDUINO/wolfSSL
./wolfssl-arduino.sh INSTALL
```

Test the TLS server by running a local command-line client.

```bash
cd /mnt/c/workspace/wolfssl-$USER
./examples/client/client -h 192.168.1.43 -p 11111 -v 3
```

Build wolfSSL to include wolfSSH support to an alternate development directory.

```bash
cd /mnt/c/workspace/wolfssl-$USER
./configure --prefix=/mnt/c/workspace/wolfssh-$USER/wolfssl_install --enable-ssh
make
make install

```

Build wolfSSH with wolfSSL not installed to default directory.

```bash
cd /mnt/c/workspace/wolfssh-$USER
./configure --with-wolfssl=/mnt/c/workspace/wolfssh-$USER/wolfssl_install
make
./examples/client/client -u jill -h 192.168.1.34 -p 22222 -P upthehill
```

Test the current wolfSSL.

```bash
cd /mnt/c/workspace/wolfssl-arduino
git status
./autogen.sh
./configure --enable-all
make clean
make && make test
```

Build and run `testwolfcrypt`.

```bash
./autogen.sh
./configure --enable-all
make clean && make && ./wolfcrypt/test/testwolfcrypt
```
