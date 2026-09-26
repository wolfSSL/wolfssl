wolfSSL for Renesas RA Evaluation Kit (EK-RA6M4)
=================================================

## Description

This directory contains e2studio projects targeted at the Renesas RA 32-bit MCUs.
The example projects include a wolfSSL TLS client.
They also include benchmark and cryptography tests for the wolfCrypt library.


The wolfssl project contains both the wolfSSL and wolfCrypt libraries.
It is built as a `Renesas RA C Library Project` and contains the Renesas RA
configuration. The wolfssl project uses `Secure Cryptography Engine on RA6 Protected Mode`
as hardware acceleration for cypto and TLS operation.


The other projects (benchmark, client, and test) are built as a
`Renesas RA C Project Using RA Library`, where the RA library is the wolfssl project.
The wolfssl Project Summary is listed below and is relevant for every project.

### Project Summary
|Item|Name/Version|
|:--|:--|
|Board|EK-RA6M4|
|Device|R7FA6M4AF3CFB|
|Toolchain|GCC ARM Embedded|
|FSP Version|6.1.0|

#### Selected software components

|Components|Version|
|:--|:--|
|Board Support Package Common Files|v6.1.0|
|Secure Cryptography Engine on RA6 Protected Mode|v6.1.0|
|I/O Port|v6.1.0|
|Arm CMSIS Version 5 - Core (M)|v6.1.0+fsp.6.1.0|
|RA6M4-EK Board Support Files|v6.1.0|
|Board support package for R7FA6M4AF3CFB|v6.1.0|
|Board support package for RA6M4 - Events|v6.1.0|
|Board support package for RA6M4|v6.1.0|
|Board support package for RA6M4 - FSP Data|v6.1.0|
|FreeRTOS|v11.1.0+fsp.6.1.0|
|FreeRTOS - Memory Management - Heap 4|v11.1.0+fsp.6.1.0|
|r_ether to FreeRTOS+TCP Wrapper|v6.1.0|
|Ethernet|v6.1.0|
|Ethernet PHY|v6.1.0|
|FreeRTOS+TCP|v4.3.3+fsp.6.1.0|
|FreeRTOS - Buffer Allocation 2|v4.3.3+fsp.6.1.0|
|FreeRTOS Port|v6.1.0|

## Setup Steps and Build wolfSSL Library

1.) Import  projects from [File]->[Open projects from File System]

+ Select folder at /path/to/wolfssl/IDE/Renesas/e2studio/RA6M4
+ Deselect the Non-Eclipse project, RA6M4, by clicking the checkbox\
   Only the folders with 'Eclipse project' under 'Import as' need to be selected.

2.) Create a `dummy_library` Static Library.

+ Click File->New->`RA C/C++ Project`. Select `EK-RA6M4` from Drop-down list.
+ Select `Flat(Non-TrustZone) Project`. Click Next.
+ Select `None`. Click Next.
+ Check `Static Library`. Click Next.
+ Select `FreeRTOS` from RTOS selection. Click Next.
+ Check `FreeRTOS minimal - Static Allocation`. Click Finish.
+ Open Smart Configurator by clicking configuration.xml in the project
+ Go to `BSP` tab and increase Heap Size under `RA Common` on Properties page, e.g. 0x1000
+ Go to `Stacks` tab
+ Add `SCE Protected Mode` stack from `New Stack` -> `Security`
+ Add New thead and set properties

|Property|Value|
|:--|:--|
|Thread Symbol|sce_tst_thread|
|Thread Name|sce_tst_thread|
|Thread Stack size|increase depending on your environment<br> e.g. 0xA000|
|Thread MemoryAllocation|Dynamic|
|Common General Use Mutexes|Enabled|
|Common General Enable Backward Compatibility|Enabled|
|Common Memory Allocation Support Dynamic Allocation|Enabled|
|Common Memory Allocation Total Heap Size|increase depending on your environment<br> e.g. 0x20000, <br>  e.g. 0x30000 when using multi thread example|

+ Add `Heap 4` stack to sce_tst_thread from `New Stack` -> `RTOS` -> `FreeRTOS Heap 4`
+ Add `FreeRTOS + TCP` stack to sce_tst_thread from `New Stack` -> `Networking` -> `FreeRTOS+TCP` and set properties
+ Add Ethernet Driver by clicking `Add Ethernet Driver` element and select `New` -> `Ethernet(r_ether)`
+ Increase Heap size of `RA Common`. Go to `BSP` tab and inclease `RA Common` -> `Heap size (bytes)` to 0x2000


|Property|Value|
|:--|:--|
|Network Events call vApplicationIPNetworkEventHook|Disable|
|Use DHCP|Disable|

+ Save `dummy_library` FSP configuration
+ Copy <u>configuration.xml</u> and pincfg under `dummy_library` to `wolfSSL_RA6M4`
+ Open Smart Configurator by clicking copied configuration.xml
+ Click `Generate Project Content` on Smart Configurator

3.) Build the wolfSSL project

4.) Create a 'dummy_application' Renesas RA C Project Using RA Library.

+ Click File->New->`RA C/C++ Project`. Select `EK-RA6M4` from Drop-down list. Click Next.
+ Select `Flat(Non-TrustZone) Project`. Click Next
+ Select `None`. Click Next
+ Check `Executable Using an RA Static Library`. Select FreeRTOS from RTOS selection. Click Finish.
+ Enter `dummy_application` as the project name. Click Next.
+ Under `RA library project`, select `wolfSSL_RA6M4`. Click Finish.
+ Copy the following folder and file at `dummy_application` to `test_RA6M4`\
  script/\
  Debug/\
  src/sce_tst_thread_entry.c

+ Add `sce_test()` call under /* TODO: add your own code here */ line at sce_tst_thread_entry.c
```
...
  /* TODO: add your own code here */
   sce_test();
...
```

5.) Prepare SEGGER_RTT to logging

+ Download J-Link software from [Segger](https://www.segger.com/downloads/jlink)
+ Choose `J-Link Software and Documentation Pack`
+ Copy sample program files below from `Installed SEGGER` folder, `e.g C:\Program Files\SEGGER\JLink\Samples\RTT`, to /path/to/wolfssl/IDE/Reenesas/e2studio/RA6M4/test/src/SEGGER_RTT\

    SEGGER_RTT.c\
    SEGGER_RTT.h\
    SEGGER_RTT_Conf.h\
    SEGGER_RTT_printf.c

+ To connect RTT block, you can configure RTT viewer configuration based on where RTT block is in a map file.
+ To place the RTT control block at a fixed, predictable address, add the following to
  `script/fsp.ld` (not the auto-generated `fsp_gen.ld`, which gets overwritten every time the
  FSP Configurator regenerates project content):

```
SECTIONS
{
    .txt.rtt_block (READONLY) :
    {
        KEEP(*(.txt.rtt_block))
    } > RAM
} INSERT AFTER .data
```
  Also, adding the following line to `SEGGER_RTT.c`:

```
SEGGER_RTT_CB _SEGGER_RTT __attribute__((section(".txt.rtt_block")));
```

  As the result, you can find the following similar line in the map file.
  e.g.
    [test_RA6M4.map]
   ```
   *(.txt.rtt_block)
   .txt.rtt_block
               0x20000000       0xa8 ./src/SEGGER_RTT/SEGGER_RTT.o
               0x20000000                _SEGGER_RTT
   ````
    you can specify "RTT control block" to 0x20000000 by Address
    OR
    you can specify "RTT control block" to 0x20000000 0x1000 by Search Range

  `build.bat` does this lookup for you: after building `all`, it greps `test_RA6M4.map` for
  `_SEGGER_RTT` and prints the address to enter directly into the RTT Viewer's Address field,
  so you don't need to open the map file by hand.

## Run Client
1.) Enable TLS_CLIENT definition in wolfssl_demo.h of test_RA6M4 project

2.) Client IP address and Server IP address

+ Client IP address can be changed by the following line in wolf_client.c.
```
static const byte ucIPAddress[4]          = { 192, 168, 11, 241 };
```
+ Server IP address can be changed by the following line in wolfssl_demo.h.
```
#define SERVER_IP    "192.168.11.40"
```

3.) Build test_RA6M4 project

4.) Prepare peer wolfssl server

+ On Linux
```
$ autogen.sh
$ ./configure --enable-extended-master=no CFLAGS="-DWOLFSSL_STATIC_RSA -DHAVE_AES_CBC"
```

Run peer wolfSSL server

RSA sign and verify use, launch server with the following option
```
$./examples/server/server -b -d -i
```

ECDSA sign and verify use, launch server with the following option
```
$./examples/server/server -b -d -i -c ./certs/server-ecc.pem -k ./certs/ecc-key.pem
```

5.) Run the example Client

You will see the following message on J-LinK RTT Viewer when using RSA sign and verify.
```
 Start Client Example,
 Connecting to 192.168.11.xx

[wolfSSL_TLS_client_do(00)][00]  Start to connect to the server.
[wolfSSL_TLS_client_do(00)][00]   Cipher : NULL
[wolfSSL_TLS_client_do(00)][00]  Received: I hear you fa shizzle!

[wolfSSL_TLS_client_do(01)][01]  Start to connect to the server.
[wolfSSL_TLS_client_do(01)][01]   Cipher : ECDHE-RSA-AES128-GCM-SHA256
[wolfSSL_TLS_client_do(01)][01]  Received: I hear you fa shizzle!

[wolfSSL_TLS_client_do(02)][02]  Start to connect to the server.
[wolfSSL_TLS_client_do(02)][02]   Cipher : ECDHE-RSA-AES256-SHA
[wolfSSL_TLS_client_do(02)][02]  Received: I hear you fa shizzle!

[wolfSSL_TLS_client_do(03)][03]  Start to connect to the server.
[wolfSSL_TLS_client_do(03)][03]   Cipher : ECDHE-RSA-AES128-SHA256
[wolfSSL_TLS_client_do(03)][03]  Received: I hear you fa shizzle!

[wolfSSL_TLS_client_do(04)][04]  Start to connect to the server.
[wolfSSL_TLS_client_do(04)][04]   Cipher : AES128-SHA256
[wolfSSL_TLS_client_do(04)][04]  Received: I hear you fa shizzle!


 End of Client Example
```

You will see the following message on J-LinK RTT Viewer when using ECDSA sign and verify.
```
 Start Client Example,
 Connecting to 192.168.11.xx

[wolfSSL_TLS_client_do(00)][00]  Start to connect to the server.
[wolfSSL_TLS_client_do(00)][00]   Cipher : NULL
[wolfSSL_TLS_client_do(00)][00]  Received: I hear you fa shizzle!

[wolfSSL_TLS_client_do(01)][01]  Start to connect to the server.
[wolfSSL_TLS_client_do(01)][01]   Cipher : ECDHE-ECDSA-AES128-GCM-SHA256
[wolfSSL_TLS_client_do(01)][01]  Received: I hear you fa shizzle!

[wolfSSL_TLS_client_do(02)][02]  Start to connect to the server.
[wolfSSL_TLS_client_do(02)][02]   Cipher : ECDHE-ECDSA-AES256-SHA
[wolfSSL_TLS_client_do(02)][02]  Received: I hear you fa shizzle!

[wolfSSL_TLS_client_do(03)][03]  Start to connect to the server.
[wolfSSL_TLS_client_do(03)][03]   Cipher : ECDHE-ECDSA-AES128-SHA256
[wolfSSL_TLS_client_do(03)][03]  Received: I hear you fa shizzle!


 End of Client Exampl
```

 **Note**\
   To run "RSA verify" client, enable "#define USE_CERT_BUFFERS_2048" in wolfssl_demo.h\
   To run "ECDSA verify" client, enable "#define USE_CERT_BUFFERS_256" in wolfssl_demo.h


### Run Multi Client Session example
1.) Enable TLS_CLIENT and TLS_MULTITHREAD_TEST definition in wolfssl_demo.h of test_RA6M4 project

2.) Follow [Run Client](#run-client) instruction

3.) Prepare peer wolfssl server

RSA sign and verify use, launch server with the following option
```
$./examples/server/server -b -d -i -p 11111

Open another terminal and launch another server example
$./examples/server/server -b -d -i -p 11112
```

ECDSA sign and verify use, launch server with the following option
```
$./examples/server/server -b -d -c -i ./certs/server-ecc.pem -k ./certs/ecc-key.pem -p 11111

Open another terminal and launch another server example
$./examples/server/server -b -d -c -i ./certs/server-ecc.pem -k ./certs/ecc-key.pem -p 11112
```

4.) Run Multi Client Session Example
You will see similar following message on J-LinK RTT Viewer when using ECDSA sign and verify.
```
 Start Client Example,
 Connecting to 192.168.11.xx

 clt_thd_taskA connecting to 11111 port
 clt_thd_taskB connecting to 11112 port
[clt_thd_taskA][00]  Ready to connect.
[clt_thd_taskA][00]  Start to connect to the server.
[clt_thd_taskA][00]   Cipher : ECDHE-RSA-AES128-GCM-SHA256
[clt_thd_taskB][00]  Ready to connect.
[clt_thd_taskB][00]  Start to connect to the server.
[clt_thd_taskB][00]   Cipher : ECDHE-RSA-AES128-SHA256
[clt_thd_taskB][00]  Received: I hear you fa shizzle!

[clt_thd_taskA][00]  Received: I hear you fa shizzle!

 clt_thd_taskA connecting to 11111 port
 clt_thd_taskB connecting to 11112 port
[clt_thd_taskA][00]  Ready to connect.
[clt_thd_taskA][00]  Start to connect to the server.
[clt_thd_taskA][00]   Cipher : AES128-SHA256
[clt_thd_taskB][00]  Ready to connect.
[clt_thd_taskB][00]  Start to connect to the server.
[clt_thd_taskB][00]   Cipher : AES256-SHA256
[clt_thd_taskA][00]  Received: I hear you fa shizzle!

[clt_thd_taskB][00]  Received: I hear you fa shizzle!


 End of Client Example
```

You will see similar following message on J-LinK RTT Viewer when using ECDSA sign and verify.
```
 Start Client Example,
 Connecting to 192.168.11.xx

 clt_thd_taskA connecting to 11111 port
 clt_thd_taskB connecting to 11112 port
[clt_thd_taskA][00]  Ready to connect.
[clt_thd_taskA][00]  Start to connect to the server.
[clt_thd_taskA][00]   Cipher : ECDHE-ECDSA-AES128-GCM-SHA256
[clt_thd_taskB][00]  Ready to connect.
[clt_thd_taskB][00]  Start to connect to the server.
[clt_thd_taskB][00]   Cipher : ECDHE-ECDSA-AES128-SHA256
[clt_thd_taskB][00]  Received: I hear you fa shizzle!

[clt_thd_taskA][00]  Received: I hear you fa shizzle!


 End of Client Example
```

**Note**\
Multi Client session use case is only able to run threads that all use either SCE cipher suite or SW cipher suite.
The example program runs two threads that use SCE cipher suite.

## Run Crypt test and Benchmark

1.) Enable CRYPT_TEST and/or BENCHMARK definition in wolfssl_demo.h

2.) Enable SCEKEY_INSTALLED definition in user_settings.h if you have installed key for AES

In the example code for benchmark, it assumes that AES key is installed at DIRECT_KEY_ADDRESS which is 0x08000000U as follows:
```
#if defined(SCEKEY_INSTALLED)
    /* aes 256 */
    memcpy(guser_PKCbInfo.sce_wrapped_key_aes256.value,
           (uint32_t *)DIRECT_KEY_ADDRESS, HW_SCE_AES256_KEY_INDEX_WORD_SIZE*4);
    guser_PKCbInfo.sce_wrapped_key_aes256.type = SCE_KEY_INDEX_TYPE_AES256;
    guser_PKCbInfo.aes256_installedkey_set = 1;
    /* aes 128 */
    guser_PKCbInfo.aes128_installedkey_set = 0;
#endif
```

To install key, please refer [Installing and Updating Secure Keys](https://www.renesas.com/us/en/document/apn/installing-and-updating-secure-keys-ra-family).

You can update code above to handle AES128 key when you install its key.

3.) Run Benchmark and Crypto Test


## Appendix: command-line build and flash scripts

Once the `wolfssl` and `test` projects have each been built at least once in e2studio (to
generate their makefiles and `ra_gen`), `build.bat` and `debug_run.bat` let you rebuild and
flash from the command line without reopening e2studio.

### build.bat

```
build.bat [clean|crypt|bench|TLSClient|wolfssl]
```

+ *(no arg)* -- incremental build of both projects (`wolfssl` then `test`)
+ `clean` -- clean both projects
+ `crypt` / `bench` / `TLSClient` -- set the corresponding demo mode in `wolfssl_demo.h`
  (`CRYPT_TEST` / `BENCHMARK` / `TLS_CLIENT`) before building
+ `wolfssl` -- force a clean rebuild of the files that depend on `user_settings.h` (and other
  shared wolfSSL headers); needed after editing them, since the generated makefiles only track
  each `.c` file's own mtime, not the headers it includes

After a successful `all` build, it also greps `test_RA6M4.map` for `_SEGGER_RTT` and prints
the RTT control block address (see "Prepare SEGGER_RTT to logging" above).

`MAKE`, `ARM_GCC_BIN`, and `E2_BUSYBOX` are tied to one specific e2studio/toolchain install;
set them in the environment before calling `build.bat` if your install differs from the
defaults baked into the script.

### debug_run.bat

```
debug_run.bat [restart]
```

+ *(no arg)* -- flash `test\Debug\test_RA6M4.srec` via SEGGER J-Link Commander, then reset and
  run
+ `restart` -- reset and run the already-flashed target again, without reprogramming

`JLINK_DIR` (the J-Link install directory) and `QC_DELAY_MS` (how long the script keeps the
J-Link connection open after `go`, in ms, before disconnecting) can be overridden in the
environment.

## Support

For support inquiries and questions, please email support@wolfssl.com. Feel free to reach out to info@wolfssl.jp as well.
