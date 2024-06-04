# wolfSSL CSharp Wrappers

This directory contains the CSharp wrapper for the wolfSSL TLS layer with examples.

* `wolfSSL_CSharp`: wolfSSL TLS layer wrappers (library)

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
./configure --enable-wolftpm
make
make check
sudo make install
```

### Build and run the wrapper

```
cd wrapper/CSharp
```

Building the server:
```
mcs wolfSSL_CSharp/wolfSSL.cs wolfSSL_CSharp/X509.cs \
wolfSSL-TLS-Server/wolfSSL-TLS-Server.cs && \
cp wolfSSL_CSharp/wolfSSL.exe ../../certs/server.exe
```

Building the client:
```
mcs wolfSSL_CSharp/wolfSSL.cs wolfSSL_CSharp/X509.cs \
wolfSSL-TLS-Server/wolfSSL-TLS-Server.cs && \
cp wolfSSL_CSharp/wolfSSL.exe ../../certs/client.exe
```

### Run the example

In one terminal instance run:
```
cd ../../certs
mono server.exe
```

And in another terminal instance run:
```
cd ../../certs
mono client.exe
```

### Enabling SNI
To enable SNI, just pass the `-S` argument with the specified hostname:
```
mono client.exe -S hostname 
```
