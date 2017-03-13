# tenAsys INtime RTOS Port

## Overview

This port is for the tenAsys INtime RTOS available [here](http://www.tenasys.com/tenasys-products/intime-rtos-family/overview-rtos).

To enable use the define `INTIME_RTOS`.

## Usage

The wolfExamples.sln is a Visual Studio 2015 project. You must have the INtime SDK installed and an INtime RTOS agent running.

The default configuration is set inside the `IDE/INTIME-RTOS/user_settings.h` file.

The example application provides a simple menu interface to select difference application functions to test.

```
wolfExamples started
wolfExamples finished initialization

                                MENU

        t. WolfCrypt Test
        b. WolfCrypt Benchmark
        c. WolfSSL Client Example
        s. WolfSSL Server Example
        l. WolfSSL Localhost Client/Server Example
Please select one of the above options:
```

### `t`wolfCrypt Test

Performs testing of all crypto algorithms.

### `b` wolfCrypt Benchmark

Performs benchmark of crypto algorithms.

### `c` wolfSSL Client

To configure the host address and port modify the `TLS_HOST_REMOTE` and `TLS_PORT` macros at top of `wolfExamples.c`. This example uses TLS 1.2 to connect to a remote host.

### `s` wolfSSL Server

To configure the port to listen on modify `TLS_PORT` at top of `wolfExamples.c`.

### `l` wolfSSL Localhost Server/Client

Starts a TLS server thread listening on localhost. Starts the TLS client and performs connect, exchanges some data and disconnects.

## References

For more information please contact info@wolfssl.com.
