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
crypto delays by returning `WC_PENDING_E` for a configurable number of iterations.
The simulated device keeps a job table keyed by the request, like a hardware
crypto manager: a request pends `TEST_PEND_COUNT` times (default 2) and the
next re-invocation with identical arguments completes it. On TLS 1.3 every supported
operation class pends (HKDF, AES-GCM, ECC/X25519 key generation and shared
secret, ECDSA/Ed25519 sign and verify), including mutual authentication. On
TLS 1.2 (`--tls12`) only the RSA and ECDSA signing set pends; the TLS 1.2 state
machines do not resume the other classes.
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

When a cryptographic call is handed off to hardware, `WC_PENDING_E` is returned up to the caller, which keeps calling until the operation completes. For some platforms it is required to call `wolfSSL_AsyncPoll`. At the TLS layer a "devId" (Device ID) must be set using `wolfSSL_CTX_SetDevId` to indicate the desire to offload cryptography.

For further design details please see: https://github.com/wolfSSL/wolfAsyncCrypt#design

## Support

For questions please email support@wolfssl.com
