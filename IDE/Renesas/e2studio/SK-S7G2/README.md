wolfSSL simple application projects for SK-S7G2 board
======

## 1. Overview
-----

This repository provides simple sample applications for evaluating wolfSSL on the SK-S7G2 evaluation board (R7FS7G27H3A01CFC, S7G2 MCU). The samples run on Express Logic ThreadX (a real-time operating system) and use NetX/NetX Driver for networking and the SSP-provided drivers for the SK-S7G2 board.

The sample package includes applications that demonstrate the following functions:

- Crypto Test: Automatically runs tests for various cryptographic operations.
- Benchmark: Measures execution speed for various cryptographic operations. The benchmark also includes TCP and TLS client tests against a peer server.

Because the required hardware and software configurations for the evaluation board are already prepared, only minimal setup is needed to run the samples.

The following sections will walk you through the steps leading up to running the sample application.

## 2. Target H/W, components and libraries
-----

This sample program uses the following hardware and software libraries. If a new version of any component is available, update it as appropriate.

| item | name & version |
|:--|:--|
| Board | SK-S7G2 Starter Kit |
| Device | R7FS7G27H3A01CFC |
| IDE | Renesas e2Studio — Version: 2025-01 (25.1.0) |
| Toolchain | GNU Arm Embedded Toolchain (arm-none-eabi-gcc), e.g. Arm GNU Toolchain 13.3.Rel1 (build arm-13.24) |
| SSP | 2.7.0 |

The project includes a configuration file that references the following software components. These components are not bundled with this sample; you must download or install them via the e2studio Smart Configurator.

| Component | version |
|:--|:--|
| Board support package for R7FS7G27H3A01CFC | 2.7.0 |
| Board Support Packages | 2.7.0 |
| SSP Common Code | 2.7.0 |
| Clock Generation Circuit: Provides=[CGC] | 2.7.0 |
| Event Link Controller: Provides=[ELC] | 2.7.0 |
| Factory MCU Information Module: Provides=[FMI] | 2.7.0 |
| I/O Port: Provides=[IO Port] | 2.7.0 |
| S7G2_SK Board Support Files | 2.7.0 |
| Express Logic ThreadX: Provides=[ThreadX] | 2.7.0 |
| Secure Cryptography Engine: Provides=[TRNG, AES, HASH, RSA, DSA, TDES, ARC4, ECC, KEY_INSTALLATION] | 2.7.0 |
| Express Logic NetX Synergy Port: Provides=[NetX Driver], Requires=[NetX] | 2.7.0 |
| General Purpose Timer: Provides=[Timer, GPT] | 2.7.0 |
| Real Time Clock: Provides=[RTC] | 2.7.0 |
| Express Logic NetX: Provides=[NetX], Requires=[ThreadX, NetX Driver] | 2.7.0 |

> Note: Hardware-accelerated algorithms supported on this board (via the Secure Cryptography Engine / SSP):
>
> - True Random Number Generator (TRNG)
> - SHA-256
> - AES in ECB mode: AES-128, AES-192, AES-256
>
> To use the hardware accelerators, enable the "Secure Cryptography Engine" component in the e2studio Smart Configurator and click "Generate Code". On the wolfSSL side, hardware SCE support is enabled with the `WOLFSSL_SCE` compile-time option. In this sample, `WOLFSSL_SCE` is defined in the `user_settings.h` file included in the `wolfSSL_SKS7G2` project (for example: `#define WOLFSSL_SCE`), so the sample will use the Secure Cryptography Engine for the primitives listed above. To force software fallbacks for testing, remove the `WOLFSSL_SCE` define from `user_settings.h` or disable the Secure Cryptography Engine component.

## 3. Importing sample application project into e2Studio
----
There is no need to create a new project. Since the project file is already prepared, import the project from the IDE by following the steps below.

- In e2studio: File > Open Project from File System... > Directory (R) ... Click the import source button and select the folder containing the project to import.
- Four projects are listed for import. Select only the three projects: `wolfbenchmark_test`, `wolfcrypt_test`, and `wolfssl_SKS7G2`, then click Finish.

You should see the `wolfbenchmark_test`, `wolfcrypt_test`, and `wolfssl_SKS7G2` projects in Project Explorer.

## 4. Smart configurator file generation
----
Follow the steps below:

1. Open the `wolfssl_SKS7G2` project in Project Explorer and double-click the `configuration.xml` file to open the Smart Configurator perspective.
2. Click the "Generate Code" button in the Smart Configurator (top-right of the component settings pane) to generate the required source files. This creates a `src/synergy_gen` folder under the project.

## 5. Build and run wolfcrypt_test application
-----
1. Build the `wolfssl_SKS7G2` project in Project Explorer, then build the `wolfcrypt_test` project.
2. After a successful build, connect the target board to your PC via USB.
3. Select Run > Debug to open the Debug perspective.
4. The application outputs operating status to standard output. Keep the "Renesas Debug Virtual Console" open to view this output.
5. Press the Run button to start the application.
6. After displaying the crypto test result, the application enters an infinite loop. If output stops, stop debugging.

## 7. Running benchmark application
-----

### 7.1 Prepare TCP server as a peer
The benchmark application includes a TCP client. You can use [this TCP server application](https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/server-tcp.c) as the peer server.

```
$ gcc server-tcp.c -o server-tcp
$ ./server-tcp
```

You can modify the server IP address and port. Those are defined in `app_entry.c` based on your environment:

```
#define SERVER_IP IP_ADDRESS(192,168,3,10)
#define TLS_PORT 11112
#define TCP_PORT 11111
```

### 7.2 Prepare TLS server as a peer
The benchmark application also includes a TLS client. You can use the wolfSSL example TLS server as the peer server:

```
$ git clone https://github.com/wolfSSL/wolfssl.git
$ cd wolfssl
$ ./autogen.sh
$ ./configure
$ make
$ ./examples/server/server -bdi -p 11112 -v d
```

The `-b` option binds the server to all network interfaces (instead of localhost only).
The `-d` option disables client authentication.
The `-i` option makes the server loop indefinitely (allow repeated connections).
The `-v` option sets the TLS version. The `d` value allows a downgrade to TLS 1.2 if a TLS 1.3 connection cannot be established.

### 7.3 Run benchmark application on the board
After building and running the benchmark on the board, the client connects to the server over TCP, exchanges a simple string, and prints output to the Renesas Debug Virtual Console similar to:

```
Pinging server to see if up .. got response from server
Benchmarking client TCP connection
Trying to connect to 0xC0A8030A on port 11111
100 TCP connections took 0.XXXXXX seconds
```

You will also see messages on the server console:

```
$ ./server-tcp
Waiting for a connection...
Client connected successfully
Client: Hello Server

Waiting for a connection...
```

For TLS benchmark, you will see messages like:

```
Benchmarking client TLSv1.2 connection using ECDHE-RSA-AES128-GCM-SHA256
Trying to connect to 0xC0A8030A on port 11112
100 TLS connections took YYY.XXXXXX seconds (and ZZZ.XXXXXX tx_time ticks)

Benchmarking client TLSv1.3 WOLFSSL_ECC_X25519 connection using TLS13_AES128_GCM_SHA256
Trying to connect to 0xC0A8030A on port 11112
100 TLS connections took YYY.XXXXXX seconds (and ZZZ.XXXXXX tx_time ticks)

Benchmarking client TLSv1.3 WOLFSSL_ECC_SECP256R1 connection using TLS13_AES128_GCM_SHA256
Trying to connect to 0xC0A8030A on port 11112
100 TLS connections took YYY.XXXXXX seconds (and ZZZ.XXXXXX tx_time ticks)

Benchmarking client TLSv1.3 WOLFSSL_FFDHE_2048 connection using TLS13_AES128_GCM_SHA256
Trying to connect to 0xC0A8030A on port 11112
100 TLS connections took YYY.XXXXXX seconds (and ZZZ.XXXXXX tx_time ticks)
```

On the server console you may see:

```
$ ./examples/server/server -bdi -p 11112 -v d
listening on port 11112
SSL version is TLSv1.2
SSL cipher suite is TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
SSL curve name is SECP256R1
...
SSL version is TLSv1.3
SSL cipher suite is TLS_AES_128_GCM_SHA256
SSL curve name is X25519
...
SSL version is TLSv1.3
SSL cipher suite is TLS_AES_128_GCM_SHA256
SSL curve name is SECP256R1
...
SSL version is TLSv1.3
SSL cipher suite is TLS_AES_128_GCM_SHA256
SSL curve name is FFDHE_2048
```

Finally, the application runs cryptographic benchmarks. You will see output like:

```
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
...
Benchmark complete
```

# 8. Support
----
For support inquiries, email support@wolfssl.com. For Japanese support, contact info@wolfssl.jp.
