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

## Build Modes

The async examples support two mutually exclusive async modes controlled via the
`ASYNC_MODE` Makefile variable:

### Software Async Mode (default)
Uses `WOLFSSL_ASYNC_CRYPT_SW` with non-blocking ECC (`WC_ECC_NONBLOCK`):
```
make -C examples/async
# or explicitly:
make -C examples/async ASYNC_MODE=sw
```

### Crypto Callback Mode
Uses `WOLF_CRYPTO_CB` with the `AsyncTlsCryptoCb` callback that simulates hardware
crypto delays by returning `WC_PENDING_E` for a configurable number of iterations:
```
make -C examples/async ASYNC_MODE=cryptocb
```

To adjust the simulated pending count (default is 2), define `TEST_PEND_COUNT`:
```
make -C examples/async ASYNC_MODE=cryptocb EXTRA_CFLAGS="-DTEST_PEND_COUNT=5"
```

To enable crypto callback debug output:
```
make -C examples/async ASYNC_MODE=cryptocb EXTRA_CFLAGS="-DDEBUG_CRYPTOCB"
```

**Note:** `WOLFSSL_ASYNC_CRYPT_SW` and `WOLF_CRYPTO_CB` are mutually exclusive in the
async polling code (async.c uses `#elif`).

## Running the Examples

```
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
