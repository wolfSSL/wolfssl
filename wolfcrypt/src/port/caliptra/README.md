# wolfSSL Caliptra Cryptographic Mailbox Port

## Purpose

`caliptra_port.c` is a wolfSSL CryptoCb port that offloads cryptographic
operations to the Caliptra hardware security module via its Cryptographic
Mailbox protocol.

Supported operations:

| Algorithm       | wolfSSL algo_type  | Notes                                          |
|-----------------|--------------------|-------------------------------------------------|
| SHA-384         | WC_ALGO_TYPE_HASH  | Streaming Init/Update/Final                     |
| SHA-512         | WC_ALGO_TYPE_HASH  | Streaming Init/Update/Final                     |
| HMAC-SHA-384/512| WC_ALGO_TYPE_HMAC  | Single-shot; key as CMK in hmac->devCtx         |
| AES-GCM encrypt | WC_ALGO_TYPE_CIPHER| Single wolfSSL call → 3 mailbox calls           |
| AES-GCM decrypt | WC_ALGO_TYPE_CIPHER| Single wolfSSL call → 3 mailbox calls           |
| ECDSA sign      | WC_ALGO_TYPE_PK    | P-384; private key CMK in key->devCtx           |
| ECDSA verify    | WC_ALGO_TYPE_PK    | P-384; requires pre-imported CMK in key->devCtx |
| RNG             | WC_ALGO_TYPE_RNG   | Loops in 4096-byte chunks                       |

SHA-256 is not supported by Caliptra firmware; `caliptra_hash()` returns
`CRYPTOCB_UNAVAILABLE` for `WC_HASH_TYPE_SHA256` and wolfSSL falls back to
software.

## Build Guards

```c
#if defined(WOLFSSL_CALIPTRA) && defined(WOLF_CRYPTO_CB)
```

Both macros must be defined in your wolfSSL build configuration.

### WOLF_CRYPTO_CB_FREE requirement

`WOLF_CRYPTO_CB_FREE` must also be defined for correct operation.  It enables
the `caliptra_hash_free` callback that releases the `CaliptraShaCtx` heap
allocation when a streaming SHA object is freed before `Final` is called.
Without it, any SHA Init/Update sequence that is abandoned (e.g., due to an
error or early exit) will leak that allocation.

- **`--enable-caliptra`**: `WOLF_CRYPTO_CB_FREE` is set automatically by the
  build system; no user action is required.
- **Manual `user_settings.h` configuration** (i.e., `#define WOLFSSL_CALIPTRA`
  without the autoconf build): you must also add `#define WOLF_CRYPTO_CB_FREE`,
  otherwise abandoned streaming SHA objects will leak their `CaliptraShaCtx`
  allocation.

## Memory Requirements

All mailbox request/response structs are heap-allocated per operation via
`XMALLOC`/`XFREE`; nothing is statically allocated by the port.

Approximate heap in flight per operation:

| Operation              | Buffers | Peak heap  |
|------------------------|---------|------------|
| AES-GCM encrypt/decrypt| 6       | ~30 KB     |
| SHA-384/512 Update     | 2–3     | ~4.5 KB    |
| ECDSA sign/verify      | 2–4     | ~4 KB      |
| HMAC-SHA-384/512       | 2–3     | ~5 KB      |

The largest individual struct is the mailbox request with a full data payload,
at approximately 4.4 KB.  Integrators on constrained embedded targets should
size their heap accordingly, or provide a custom `XMALLOC` implementation
backed by a static pool.

## Integrator-Provided Transport Hook

The integrator must supply the following function.  It is responsible for
writing `cmd_id` to the Caliptra mailbox command register, streaming the
request bytes through the data FIFO, ringing the doorbell, and reading back
the response:

```c
int caliptra_mailbox_exec(word32      cmd_id,
                          const void* req,      word32 req_len,
                          void*       resp,     word32 resp_len);
```

Return 0 on success, or a negative wolfSSL error code on failure.

## Registration

```c
#include <wolfssl/wolfcrypt/port/caliptra/caliptra_port.h>

/* Register the Caliptra device with the wolfSSL CryptoCb framework */
wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);

/* Assign the device ID to any wolfSSL object that should use Caliptra */
wc_InitSha384_ex(&sha, NULL, WOLF_CALIPTRA_DEVID);
wc_ecc_init_ex(&key, NULL, WOLF_CALIPTRA_DEVID);
```

## Key Material

Keys are never passed as raw bytes at operation time.  Instead, the
application imports key material once via `wc_caliptra_import_key()` and
stores the returned 128-byte `CaliptraCmk` opaque handle in the relevant
wolfSSL object's `devCtx` field before any operation:

```c
CaliptraCmk aes_cmk;
wc_caliptra_import_key(raw_aes_key, 32, /*key_usage=*/0, &aes_cmk);

Aes aes;
wc_AesInit(&aes, NULL, WOLF_CALIPTRA_DEVID);
aes.devCtx = &aes_cmk;  /* set before wc_AesGcmEncrypt */
```

The same pattern applies to HMAC (`hmac->devCtx`) and ECDSA sign
(`key->devCtx`).

## Known Limitations

### ECDH is unavailable

`WC_PK_TYPE_ECDH` returns `CRYPTOCB_UNAVAILABLE`.

The Caliptra ECDH protocol (`CM_ECDH_GENERATE` + `CM_ECDH_FINISH`) returns
the derived shared secret as an opaque 128-byte `Cmk` handle, not as raw
bytes.  The wolfSSL ECDH CryptoCb interface (`info->pk.ecdh.out`) requires
raw shared-secret bytes.  These interfaces are fundamentally incompatible
and cannot be bridged without Caliptra firmware changes.

### AES-GCM encrypt ignores caller-provided IV

Caliptra generates the IV server-side during `CM_AES_GCM_ENCRYPT_INIT`.
The caller's `aesgcm_enc.iv` pointer is ignored.  After a successful
encrypt call, the server-generated IV (12 bytes) is cached in the `Aes`
object and must be retrieved via `wc_caliptra_aesgcm_get_iv()`:

```c
/* After wc_AesGcmEncrypt returns 0: */
byte iv[12];
wc_caliptra_aesgcm_get_iv(&aes, iv, sizeof(iv));
```

### HMAC is single-shot only

The HMAC handler processes the entire message in one mailbox call.
`info->hmac.in` must point to the complete message and `info->hmac.inSz`
must be at most `CMB_MAX_DATA_SIZE` (4096) bytes.  Streaming HMAC is not
supported.

HMAC-SHA-384 and HMAC-SHA-512 are supported.  HMAC-SHA-256 returns
`CRYPTOCB_UNAVAILABLE` and wolfSSL falls back to software.

### ECDSA verify requires a pre-imported public key CMK

The `CmImportReq` structure has a fixed 64-byte input field
(`CMK_MAX_KEY_SIZE_BITS / 8 = 64`).  A P-384 public key is 96 bytes
(Qx || Qy), which exceeds this limit.

If `key->devCtx` is NULL when `wc_EccVerify()` is called, the port returns
`CRYPTOCB_UNAVAILABLE` and wolfSSL performs a software ECC verification using
the raw public key coordinates in the `ecc_key` struct.

To use Caliptra for verify, the application must:

1. Import the P-384 public key into Caliptra via a firmware-specific mechanism
   (e.g., a dedicated public-key import command, or by retrieving a CMK for a
   key that was already generated or stored in the key vault).
2. Store the resulting `CaliptraCmk` pointer in `key->devCtx` before calling
   `wc_EccVerify()`.

The port will then use the pre-imported CMK directly and will NOT delete it
after verify (the caller owns the CMK lifetime).

## File Layout

```
wolfcrypt/src/port/caliptra/
    caliptra_port.c   — full implementation (this port)
    README.md         — this file

wolfssl/wolfcrypt/port/caliptra/
    caliptra_port.h   — public API, struct definitions, command IDs
```

## Testing

Production test coverage lives in `wolfcrypt/test/test.c` under
`#ifdef WOLFSSL_CALIPTRA`.  Build with `--enable-caliptra` and run
`wolfcrypt/test/testwolfcrypt` as normal.

The `wolfcrypt/src/port/caliptra/sim/` directory contains development
scaffolding — `caliptra_sim.c` provides a software mailbox simulator
(implementing `caliptra_mailbox_exec`) and `caliptra_test.c` is a standalone
test harness that links against it.  They exist solely for offline development
and are not required to validate the port.
