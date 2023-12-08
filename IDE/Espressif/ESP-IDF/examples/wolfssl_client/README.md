# wolfSSL TLS Client Example

This is the wolfSSL TLS Client demo, typically used with the [Espressif TLS Server](../wolfssl_server/README.md)
or the CLI [Server](https://github.com/wolfSSL/wolfssl/tree/master/examples/server).

When using the CLI, see the [example parameters](/IDE/Espressif/ESP-IDF/examples#interaction-with-wolfssl-cli).

For general information on [wolfSSL examples for Espressif](../README.md), see the
[README](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md) file.

## VisualGDB

Open the VisualGDB Visual Studio Project file in the VisualGDB directory and click the "Start" button.
No wolfSSL setup is needed. You may need to adjust your specific COM port. The default is `COM20`.

## ESP-IDF Commandline


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

## SM Ciphers

#### Working Linux Client to ESP32 Server

Command:

```
cd /mnt/c/workspace/wolfssl-$USER/IDE/Espressif/ESP-IDF/examples/wolfssl_server
. /mnt/c/SysGCC/esp32/esp-idf/v5.1/export.sh
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

See the README.md file in the upper level 'examples' directory for [more information about examples](../README.md).

