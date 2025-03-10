# Arduino Basic TLS Server

Open the [wolfssl_server.ino](./wolfssl_server.ino) file in the Arduino IDE.

Other IDE products are also supported, such as:

- [PlatformIO in VS Code](https://docs.platformio.org/en/latest/frameworks/arduino.html)
- [VisualGDB](https://visualgdb.com/tutorials/arduino/)
- [VisualMicro](https://www.visualmicro.com/)

For examples on other platforms, see the [IDE directory](https://github.com/wolfssl/wolfssl/tree/master/IDE).
Additional examples can be found on [wolfSSL/wolfssl-examples](https://github.com/wolfSSL/wolfssl-examples/).

## Connect with an Arduino Sketch

See the companion [Arduino Sketch Client](../wolfssl_client/wolfssl_client.ino).

## Connect with Linux Client

See also the [wolfSSL Example TLS Client](https://github.com/wolfSSL/wolfssl/tree/master/examples/client)
and [wolfSSL Example TLS Server](https://github.com/wolfSSL/wolfssl/tree/master/examples/server).

Assuming a listening [Arduino Sketch Server](./wolfssl_server.ino) at `192.168.1.38` on port `11111`,
connect with the `client` executable:

```
./examples/client/client -h 192.168.1.38 -p 11111 -v 3
```

## wolfSSL Error -308 wolfSSL_connect error state on socket

When using a wired Ethernet connection, and this error is encountered, simply
press the reset button or power cycle the Arduino before making a connection.

Here's one possible script to test the server from a command-line client:

```bash
#!/usr/bin/env bash
echo "client log " > client_log.txt
counter=1
THIS_ERR=0
while [ $THIS_ERR -eq 0 ]; do
    ./examples/client/client -h 192.168.1.38 -p 11111 -v 3 >> client_log.txt

    THIS_ERR=$?
    if [ $? -ne 0 ]; then
        echo "Failed!"
        exit 1
    fi
    echo "Iteration $counter"
    echo "Iteration $counter" >> client_log.txt
    ((counter++))
done
```

Output expected from the `client` command:

```
$ ./examples/client/client -h 192.168.1.38 -p 11111 -v 3
Alternate cert chain used
 issuer : /C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting/CN=www.wolfssl.com/emailAddress=info@wolfssl.com
 subject: /C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com
 altname = example.com
 altname = 127.0.0.1
 serial number:01
SSL version is TLSv1.2
SSL cipher suite is ECDHE-RSA-AES128-GCM-SHA256
SSL curve name is SECP256R1
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIE6DCCA9CgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMCVVMx
EDAOBgNVBAgMB01vbnRhbmExEDAOBgNVBAcMB0JvemVtYW4xETAPBgNVBAoMCFNh
d3Rvb3RoMRMwEQYDVQQLDApDb25zdWx0aW5nMRgwFgYDVQQDDA93d3cud29sZnNz
bC5jb20xHzAdBgkqhkiG9w0BCQEWEGluZm9Ad29sZnNzbC5jb20wHhcNMjMxMjEz
MjIxOTI4WhcNMjYwOTA4MjIxOTI4WjCBkDELMAkGA1UEBhMCVVMxEDAOBgNVBAgM
B01vbnRhbmExEDAOBgNVBAcMB0JvemVtYW4xEDAOBgNVBAoMB3dvbGZTU0wxEDAO
BgNVBAsMB1N1cHBvcnQxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG
SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAMCVCOFXQfJxbbfSRUEnAWXGRa7yvCQwuJXOL07W9hyIvHyf+6hn
f/5cnFF194rKB+c1L4/hvXvAL3yrZKgX/Mpde7rgIeVyLm8uhtiVc9qsG1O5Xz/X
GQ0lT+FjY1GLC2Q/rUO4pRxcNLOuAKBjxfZ/C1loeHOmjBipAm2vwxkBLrgQ48bM
QLRpo0YzaYduxLsXpvPo3a1zvHsvIbX9ZlEMvVSz4W1fHLwjc9EJA4kU0hC5ZMMq
0KGWSrzh1Bpbx6DAwWN4D0Q3MDKWgDIjlaF3uhPSl3PiXSXJag3DOWCktLBpQkIJ
6dgIvDMgs1gip6rrxOHmYYPF0pbf2dBPrdcCAwEAAaOCAUUwggFBMB0GA1UdDgQW
BBSzETLJkpiE4sn40DtuA0LKHw6OPDCB1AYDVR0jBIHMMIHJgBQnjmcRdMMmHT/t
M2OzpNgdMOXo1aGBmqSBlzCBlDELMAkGA1UEBhMCVVMxEDAOBgNVBAgMB01vbnRh
bmExEDAOBgNVBAcMB0JvemVtYW4xETAPBgNVBAoMCFNhd3Rvb3RoMRMwEQYDVQQL
DApDb25zdWx0aW5nMRgwFgYDVQQDDA93d3cud29sZnNzbC5jb20xHzAdBgkqhkiG
9w0BCQEWEGluZm9Ad29sZnNzbC5jb22CFDNEGqhsAez2YPJwUQpM0RT6vOlEMAwG
A1UdEwQFMAMBAf8wHAYDVR0RBBUwE4ILZXhhbXBsZS5jb22HBH8AAAEwHQYDVR0l
BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBK/7nl
hZvaU2Z/ByK/thnqQuukEQdi/zlfMzc6hyZxPROyyrhkOHuKmUgOpaRrsZlu4EZR
vRlSrbymfip6fCOnzNteQ31rBMi33ZWt8JGAWcUZkSYnkbhIHOtVtqp9pDjxA7xs
i6qU1jwFepbFBvEmFC51+93lNbMBLLOtYlohmgi+Vvz5okKHhuWpxZnPrhS+4LkI
JA0dXNYU4UyfQLOp6S1Si0y/rEQxZ8GNBoXsD+SZ10t7IQZm1OT1nf+O8IY5WB2k
W+Jj73zJGIeoAiUQPoco+fXvR56lgAgRkGj+0aOoUbk3/9XKfId/a7wsEsjFhYv8
DMa5hrjJBMNRN9JP
-----END CERTIFICATE-----
Session timeout set to 500 seconds
Client Random : 56A0BB9647B064D3F20947032B74B31FDB4C93DBAC9460BA8AEA213A2B2DD4A8
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    Session-ID: 3255404E997FA9C27ECB4F1A20A70E722E4AA504B63A945FC175434D1907EC31
    Session-ID-ctx:
    Master-Key: 67F22168BBADD678643BBA76B398277270C29788AC18FD05B57F6B715F49A7BCEEF75BEAF7FE266B0CC058534AF76C1F
    TLS session ticket: NONE
    Start Time: 1705533296
    Timeout   : 500 (sec)
    Extended master secret: no
I hear you fa shizzle!
```

### Troubleshooting

When encountering odd errors such as `undefined reference to ``_impure_ptr'`, such as this:

```text
c:/users/gojimmypi/appdata/local/arduino15/packages/esp32/tools/xtensa-esp32-elf-gcc/esp-2021r2-patch5-8.4.0/bin/../lib/gcc/xtensa-esp32-elf/8.4.0/../../../../xtensa-esp32-elf/bin/ld.exe: C:\Users\gojimmypi\AppData\Local\Temp\arduino\sketches\EAB8D79A02D1ECF107884802D893914E\libraries\wolfSSL\wolfcrypt\src\logging.c.o:(.literal.wolfssl_log+0x8): undefined reference to `_impure_ptr'
collect2.exe: error: ld returned 1 exit status

exit status 1

Compilation error: exit status 1
```

Try cleaning the Arduino cache directories. For Windows, that's typically in:

```text
C:\Users\%USERNAME%\AppData\Local\Temp\arduino\sketches
```

Remove all other boards from other serial ports, leaving one the one being programmed.
