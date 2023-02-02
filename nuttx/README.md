# wolfSSL NuttX integration

This folder contains the instructions, scripts and build files neccessary to build NuttX with wolfSSL

## Installation
```
cp -R ./wolfssl <path-to-nuttx-apps>/crypto/
cd <path-to-nuttx-apps>/crypto/wolfssl
./setup-wolfssl.sh
```

## NuttX Configuration

After installation, run `make menuconfig` and enable `Application Configuration > Cryptography Library Support > wolfSSL SSL/TLS Cryptography Library`.
Tests and examples can be enabled by enabling `wolfCrypt applications` and any of the tests it has in it's submenu.
After that NuttX can be built normally.
