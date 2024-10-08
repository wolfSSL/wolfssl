# wolfSSL CSharp Wrappers

This directory contains the CSharp wrapper for the wolfSSL TLS layer with examples.

* `wolfSSL_CSharp`: wolfSSL TLS layer wrappers (library).
* `wolfCrypt-Test`: wolfCrypt layer wrapper testing.
* `user_settings.h`: wolfCrypt wrapper user settings.

Examples:
* `wolfSSL-DTLS-PSK-Server`
* `wolfSSL-DTLS-Server`
* `wolfSSL-Example-IOCallbacks`
* `wolfSSL-TLS-Client`
* `wolfSSL-TLS-PSK-Client`
* `wolfSSL-TLS-PSK-Server`
* `wolfSSL-TLS-Server`
* `wolfSSL-TLS-ServerThreaded`

## Windows

A Visual Studio solution `wolfSSL_CSharp.sln` is provided. This will allow you
to build the wrapper library and examples. It includes the wolfSSL Visual Studio
project directly.

To successfully run and build the solution on Windows Visual Studio you will
need to open a new solution `wolfSSL_CSharp.sln` located in `wrapper\CSharp\wolfSSL_CSharp.sln`.

Select the CPU type, configuration, and target file.
select `Build` and either `Rebuild Solution` or `Build Solution`.

## Linux (Ubuntu) using mono

Prerequisites for linux:

```
apt-get update
apt-get upgrade
apt-get install mono-complete
```

### Build wolfSSL and install

```
./autogen.sh
./configure --enable-keygen --enable-eccencrypt --enable-ed25519 --enable-curve25519 --enable-aesgcm
make
make check
sudo make install
```

### Build and run the wolfCrypt test wrapper

From the `wrapper/CSharp` directory (`cd wrapper/CSharp`):

Compile wolfCrypt test:

```
mcs wolfCrypt-Test/wolfCrypt-Test.cs wolfSSL_CSharp/wolfCrypt.cs -OUT:wolfcrypttest.exe
mono wolfcrypttest.exe
```

### Build and run the wolfSSL client/server test

From the `wrapper/CSharp` directory (`cd wrapper/CSharp`):

Compile server:

```
mcs wolfSSL_CSharp/wolfSSL.cs wolfSSL_CSharp/X509.cs wolfSSL-TLS-Server/wolfSSL-TLS-Server.cs -OUT:server.exe
```

Compile client:

```
mcs wolfSSL_CSharp/wolfSSL.cs wolfSSL_CSharp/X509.cs wolfSSL-TLS-Client/wolfSSL-TLS-Client.cs -OUT:client.exe
```

#### Run the example

In one terminal instance run the server:

```
mono server.exe
```

And in another terminal instance run the client:

```
mono client.exe
```

#### Enabling SNI

To enable SNI, just pass the `-S` argument with the specified hostname to the client:

```
mono client.exe -S hostname
```

And run the server with the `-S` flag:

```
mono server.exe -S
```
