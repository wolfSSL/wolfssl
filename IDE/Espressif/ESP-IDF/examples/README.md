# wolfSSL Examples for Espressif

## Core Examples

These are the core examples for wolfSSL:

- [Template](./template/README.md)

- [Benchmark](./wolfssl_benchmark/README.md)

- [Test](./wolfssl_test/README.md)

- [TLS Client](./wolfssl_client/README.md). See also [CLI Client](https://github.com/wolfSSL/wolfssl/tree/master/examples/client) and [more TLS examples](https://github.com/wolfSSL/wolfssl-examples/tree/master/tls).

- [TLS Server](./wolfssl_server/README.md). See also [CLI Server](https://github.com/wolfSSL/wolfssl/tree/master/examples/server)

## Other Espressif wolfSSL Examples

See these other repositories for additional examples:

- [wolfssl-examples/ESP32](https://github.com/wolfSSL/wolfssl-examples/tree/master/ESP32)

- [wolfssh/Espressif](https://github.com/wolfSSL/wolfssh/tree/master/ide/Espressif)

- [wolfssh-examples/Espressif](https://github.com/wolfSSL/wolfssh-examples/tree/main/Espressif)


## Interaction with wolfSSL CLI

See the [server](https://github.com/wolfSSL/wolfssl/tree/master/examples/server)
and [client](https://github.com/wolfSSL/wolfssl/tree/master/examples/client)
examples.

Here are some examples using wolfSSL from Linux to communicate with an
ESP32 TLS client or server:

TLS1.3 Linux Server
```
./examples/server/server -v 4 -b -d -p 11111 -c ./certs/server-cert.pem -k ./certs/server-key.pem
```

TLS1.3 Linux Client to Linux Server: `TLS_AES_128_GCM_SHA256` (default)
```
./examples/client/client -v 4 -h 127.0.0.1 -p 11111 -A ./certs/ca-cert.pem
```

TLS1.2 Linux Server
```
./examples/server/server -v 3 -b -d -p 11111 -c ./certs/server-cert.pem -k ./certs/server-key.pem
```

TLS1.2 Linux Client to Linux Server: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (default)
```
./examples/client/client -v 3 -h 127.0.0.1 -p 11111 -A ./certs/ca-cert.pem
```

TLS1.2 Linux Client to ESP32 Server: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
```
./examples/client/client -v 3 -h 192.168.1.109 -p 11111 -A ./certs/ca-cert.pem
```

TLS1.3 Linux Client to ESP32 Server: `TLS_AES_128_GCM_SHA256`
```
./examples/client/client -v 4 -h 192.168.1.109 -p 11111 -A ./certs/ca-cert.pem
```


There's an additional example that uses wolfSSL installed as a component to the shared ESP-IDF:

- [Test IDF](./wolfssl_test_idf/README.md)

## Installing wolfSSL for Espressif projects

[Core examples](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples)
have a local `components/wolfssl` directory with a special CMakeFile.txt that does not require
wolfSSL to be installed.

If you want to install wolfSSL, see the setup for [wolfSSL](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF#setup-for-linux)
and [wolfSSH](https://github.com/wolfSSL/wolfssh/tree/master/ide/Espressif#setup-for-linux).

The [Espressif Managed Component for wolfSSL](https://www.wolfssl.com/wolfssl-now-available-in-espressif-component-registry/)
also installs source code locally, instead of pointing to a source repository.

## VisualGDB

Users of [VisualGDB](https://visualgdb.com/) can find Espressif project files in each respective
example `.\VisualGDB` directory. For convenience, there are separate project for various
target SoC and ESP-IDF version.

For devices without a built-in JTAG, the projects are configured with the open source [Tigard](https://www.crowdsupply.com/securinghw/tigard)
and using port `COM20`.

For devices _with_ a built-in JTAG, the projects are using `COM9`.

Edit the COM port for your project:

- ESP-IDF Project; Bootloader COM Port.
- Raw Terminal; COM Port


## Troubleshooting

If unusual errors occur, exit Visual Studio and manually delete these directories to start over:

- `.\build`
- `.\VisualGDB\.visualgdb`
- `.\VisualGDB\.vs`

It may be helpful to also delete the `sdkconfig` file. (Save a backup if you've made changes to defaults)

## Other Topics

- esp32.com: [RSA peripheral 50% slower on ESP32-S3/C3 than S2](https://www.esp32.com/viewtopic.php?t=23830)

- esp32.com: [GPIO6,GPIO7,GPIO8,and GPIO9 changed for ESP32-WROOM-32E](https://esp32.com/viewtopic.php?t=29058)

See also the `ESP-FAQ Handbook`.
