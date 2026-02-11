# wolfSSL Asynchronous Cryptography support

Supported with:
* Intel QuickAssist
* Marvell (Cavium) Nitrox
* Crypto Callbacks (`--enable-cryptocb`)
* PK Callbacks (`--enable-pkcallbacks`)

Tested with:
* `./configure --enable-asynccrypt --enable-rsa --disable-ecc`
* `./configure --enable-asynccrypt --disable-rsa --enable-ecc`
* `./configure --enable-asynccrypt --enable-cryptocb --enable-rsa --disable-ecc`
* `./configure --enable-asynccrypt --enable-cryptocb --disable-rsa --enable-ecc`
* `./configure --enable-asynccrypt --enable-pkcallbacks --enable-rsa --disable-ecc`
* `./configure --enable-asynccrypt --enable-pkcallbacks --disable-rsa --enable-ecc`

```
make -C examples/async
./examples/async/async_server --ecc
./examples/async/async_client --ecc 127.0.0.1 11111
./examples/async/async_client --x25519 ecc256.badssl.com 443
```

Optional ready-file sync (CI-friendly, avoids sleeps):
```
export WOLFSSL_ASYNC_READYFILE=/tmp/wolfssl_async_ready
./examples/async/async_server --ecc
WOLFSSL_ASYNC_READYFILE=/tmp/wolfssl_async_ready ./examples/async/async_client --ecc 127.0.0.1 11111
```

Porting the TCP/IP stack:
Define `NET_USER_HEADER` to include your network shim and provide the
`NET_*` macros plus `NET_IO_SEND_CB` / `NET_IO_RECV_CB`.

## Asynchronous Cryptography Design

When a cryptographic call is handed off to hardware it return `WC_PENDING_E` up to caller. Then it can keep calling until the operation completes. For some platforms it is required to call `wolfSSL_AsyncPoll`. At the TLS layer a "devId" (Device ID) must be set using `wolfSSL_CTX_SetDevId` to indicate desire to offload cryptography.

For further design details please see: https://github.com/wolfSSL/wolfAsyncCrypt#design

## Support

For questions please email support@wolfssl.com
