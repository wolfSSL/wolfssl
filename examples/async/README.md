# wolfSSL Asynchronous Cryptography support

Supported with:
* Intel QuickAssist
* Marvell (Cavium) Nitrox
* Crypto Callbacks (`--enable-cryptocb`)
* PK Callbacks (`--enable-pkcallbacks`)

Requires files from https://github.com/wolfSSL/wolfAsyncCrypt
See `async-check.sh` for how to setup.

Tested with:
* `./configure --enable-asynccrypt --enable-rsa --disable-ecc`
* `./configure --enable-asynccrypt --disable-rsa --enable-ecc`
* `./configure --enable-asynccrypt --enable-cryptocb --enable-rsa --disable-ecc`
* `./configure --enable-asynccrypt --enable-cryptocb --disable-rsa --enable-ecc`
* `./configure --enable-asynccrypt --enable-pkcallbacks --enable-rsa --disable-ecc`
* `./configure --enable-asynccrypt --enable-pkcallbacks --disable-rsa --enable-ecc`

```
make
./examples/async/async_server
./examples/async/async_client 127.0.0.1
```

## Asynchronous Cryptography Design

When a cryptogaphic call is handed off to hardware it return `WC_PENDING_E` up to caller. Then it can keep calling until the operation completes. For some platforms it is required to call `wolfSSL_AsyncPoll`. At the TLS layer a "devId" (Device ID) must be set using `wolfSSL_CTX_SetDevId` to indicate desire to offload cryptography.

For further design details please see: https://github.com/wolfSSL/wolfAsyncCrypt#design

## Support

For questions please email support@wolfssl.com
