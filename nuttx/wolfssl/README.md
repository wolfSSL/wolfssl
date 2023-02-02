# NuttX + wolfSSL - Proof-of-Concept / Preview

## Instructions

1) Create working directory (e.g. ~/nuttxspace):
    ```
    $ cd ~
    $ mkdir nuttxspace
    ```
2) Install dependencies:
    ```
    $ cd ~/nuttxspace
    $ sudo su
    $ apt install -y bison flex gettext texinfo libncurses5-dev libncursesw5-dev gperf automake libtool pkg-config build-essential gperf genromfs libgmp-dev libmpc-dev libmpfr-dev libisl-dev binutils-dev libelf-dev libexpat-dev gcc-multilib g++-multilib picocom u-boot-tools util-linux
    $ apt install -y kconfig-frontends
    $ apt install -y gcc-arm-none-eabi binutils-arm-none-eabi
    $ exit # exit sudo
    ```
3) Clone nuttx and nuttx-apps into working directory:
    ```
    $ git clone https://github.com/apache/nuttx.git nuttx
    $ git clone https://github.com/apache/nuttx-apps apps
    ```
4) Copy this directory reanamed to "wolfssl" into the working directory applications:
    ```
    $ cd <path to where this archive was extracted>
    $ cp -r wolfSSL-nuttX-app ~/nuttxspace/apps/crypto/wolfssl
    ```
5) Setup wolfSSL in preparation for the build:
    ```
    $ cd ~/nuttxspace/apps/crypto/wolfssl
    $ ./setup-wolfssl.sh
    ```
> **NOTE:** There is a conflict with the function `mutex_test()` in `wolfcrypt/test/test.c`
> and NuttX itself so a patch has been provided and will be applied by the aforementioned
> script to address this.

6) Setup baseline NuttX configuration (board + NuttX Shell):
    ```
    $ cd ~/nuttxspace/nuttx
    $ ./tools/configure.sh -l <board>:nsh
    ```
> **EXAMPLES:**
>   - For NuttX Simulator: `$ ./tools/configure.sh sim:nsh`
>   - For BL602 (RISC-V): `$ ./tools/configure.sh -l bl602evb:nsh`
>   - For NUCLEO-L552ZE-Q (Cortex-M33): `$ ./tools/configure.sh -l nucleo-l552ze:nsh`

7) Start custom configuration system:
    ```
    $ make menuconfig
    ```
8) Configure NuttX to enable the wolfSSL crypto library test applications:
    - From main menu select: **Application Configuration > Cryptography Library Support**
    - Enable and then select **wolfSSL SSL/TLS Cryptography Library**
    - Enable and then select **wolfSSL applications**
    - Enable applications:
        - **wolfCrypt Benchmark application**
        - **wolfCrypt Test application**
    - Select Save from bottom menu, saving to `.config` file
    - Exit configuration tool

9) Build NuttX and wolfSSL:
    ```
    $ make
    ```
10) Open a serial terminal to the target, then load and run the NuttX image.  The
    NuttX Shell prompt (`nsh>`) should be displayed in the terminal.

11) Run the wolfcrypt benchmark and/or test in the NuttX Shell:
    ```
    nsh> wolfcrypt_test
    nsh> wolfcrypt_benchmark
    ```
## Notes
- Developed using the following targets:
    - STM NUCLEO-L552ZE-Q (Cortex-M33)
    - DT-BL10 / BL602 (RISC-V)
    - NuttX simulator
