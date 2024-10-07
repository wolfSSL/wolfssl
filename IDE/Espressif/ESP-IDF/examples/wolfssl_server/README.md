# wolfSSL TLS Server Example

This is the wolfSSL TLS Server demo, typically used with the [Espressif TLS Client](../wolfssl_client/README.md)
or the CLI [Client](https://github.com/wolfSSL/wolfssl/tree/master/examples/client).

When using the CLI, see the [example parameters](/IDE/Espressif/ESP-IDF/examples#interaction-with-wolfssl-cli).

For general information on [wolfSSL examples for Espressif](../README.md), see the
[README](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md) file.

## VisualGDB

Open the VisualGDB Visual Studio Project file in the VisualGDB directory and click the "Start" button.
No wolfSSL setup is needed. You may need to adjust your specific COM port. The default is `COM20`.

## ESP-IDF Commandline

The Example contains a wolfSSL simple server.

1. `idf.py menuconfig` to configure the project

    1-1. Example Connection Configuration ->

           WIFI SSID : your own WIFI, which is connected to the Internet.(default is "myssid")
           WIFI Password : WIFI password, and default is "mypassword"

When you want to test the wolfSSL simple server demo

1. `idf.py -p <PORT> flash` to compile the code and load the firmware
2. `idf.py monitor` to see the context. The assigned IP address can be found in output message.
3. Once the server connects to the wifi, it is waiting for client request.
    ("Waiting for a connection..." message will be displayed.)

4. You can use <wolfssl>/examples/client to test the server
    e.g ./example/client/client -h xx.xx.xx

See the README.md file in the upper level 'examples' directory for more information about examples.


```
# . /mnt/c/SysGCC/esp32/esp-idf/master/export.sh
. /mnt/c/SysGCC/esp32/esp-idf/v5.2/export.sh
cd /mnt/c/workspace/wolfssl-$USER/IDE/Espressif/ESP-IDF/examples/wolfssl_server

# optionally erase
idf.py erase-flash -p /dev/ttyS19 -b 115200

# Program flash
idf.py flash -p /dev/ttyS19 -b 115200 monitor
```


Linux Client to x108 SM server

```
cd /mnt/c/workspace/wolfssl-$USER

# show the ciphers
./examples/client/client -e

./examples/client/client  -h 192.168.1.108 -v 4 -l TLS_SM4_GCM_SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem   -A ./certs/sm2/root-sm2.pem -C
```


Linux Server

```
./examples/server/server                   -v 4 -l TLS13-SM4-CCM-SM3 -c ./certs/sm2/server-sm2.pem -k ./certs/sm2/server-sm2-priv.pem -A ./certs/sm2/client-sm2.pem -V
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

Ciphers to consider

```
TLS13-AES128-GCM-SHA256:
TLS13-AES256-GCM-SHA384:
TLS13-CHACHA20-POLY1305-SHA256:

TLS13-SM4-GCM-SM3:
TLS13-SM4-CCM-SM3:
ECDHE-ECDSA-SM4-CBC-SM3:
ECDHE-ECDSA-SM4-GCM-SM3:
ECDHE-ECDSA-SM4-CCM-SM3

DHE-RSA-AES128-SHA:
DHE-RSA-AES256-SHA:
ECDHE-RSA-AES128-SHA:
ECDHE-RSA-AES256-SHA:
ECDHE-ECDSA-AES128-SHA:
ECDHE-ECDSA-AES256-SHA:
DHE-RSA-AES128-SHA256:
DHE-RSA-AES256-SHA256:
DHE-RSA-AES128-GCM-SHA256:
DHE-RSA-AES256-GCM-SHA384:
ECDHE-RSA-AES128-GCM-SHA256:
ECDHE-RSA-AES256-GCM-SHA384:
ECDHE-ECDSA-AES128-GCM-SHA256:
ECDHE-ECDSA-AES256-GCM-SHA384:
ECDHE-RSA-AES128-SHA256:
ECDHE-ECDSA-AES128-SHA256:
ECDHE-RSA-AES256-SHA384:
ECDHE-ECDSA-AES256-SHA384:
ECDHE-RSA-CHACHA20-POLY1305:
ECDHE-ECDSA-CHACHA20-POLY1305:
DHE-RSA-CHACHA20-POLY1305:
ECDHE-RSA-CHACHA20-POLY1305-OLD:
ECDHE-ECDSA-CHACHA20-POLY1305-OLD:
DHE-RSA-CHACHA20-POLY1305-OLD:
```

See the README.md file in the upper level 'examples' directory for [more information about examples](../README.md).
