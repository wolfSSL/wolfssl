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

### ECDSA verify uses seed-based key derivation

Caliptra's ECDSA firmware treats the 48-byte CMK input as a **seed** for
deterministic key-pair derivation (`ecc384.key_pair(seed)`), not as the raw
private scalar.  This applies to both sign (`CM_ECDSA_SIGN`) and verify
(`CM_ECDSA_VERIFY`): the firmware re-derives the same `(d', Q')` from the seed
on every call.

Consequence: importing a raw software private key as an ECDSA CMK seed will
produce a signature from a *different* key pair than the one the software key
represents.  Software verification against the original public key will fail.

**Correct pattern for hardware sign + hardware verify:**

```c
byte seed[48];
wc_RNG_GenerateBlock(&rng, seed, sizeof(seed));

CaliptraCmk sign_cmk, verify_cmk;
wc_caliptra_import_key(seed, 48, CMB_KEY_USAGE_ECDSA, &sign_cmk);
wc_caliptra_import_key(seed, 48, CMB_KEY_USAGE_ECDSA, &verify_cmk);
/* Both CMKs hold the same seed; firmware derives the same Q' for each. */

ecc_key key;
wc_ecc_init_ex(&key, NULL, WOLF_CALIPTRA_DEVID);
wc_ecc_make_key_ex(&rng, 48, &key, ECC_SECP384R1);  /* init curve metadata */
key.devCtx = &sign_cmk;
wc_ecc_sign_hash(hash, hashSz, sig, &sigLen, &rng, &key);
wc_ecc_free(&key);

ecc_key vkey;
wc_ecc_init_ex(&vkey, NULL, WOLF_CALIPTRA_DEVID);
wc_ecc_make_key_ex(&rng, 48, &vkey, ECC_SECP384R1);
vkey.devCtx = &verify_cmk;
wc_ecc_verify_hash(sig, sigLen, hash, hashSz, &verify_res, &vkey);
wc_ecc_free(&vkey);
```

If `key->devCtx` is NULL when `wc_ecc_verify_hash()` is called, the port
returns `CRYPTOCB_UNAVAILABLE` and wolfSSL falls back to software ECC
verification using the raw public key coordinates in the `ecc_key` struct.

The caller owns the CMK lifetime; the port does not delete `verify_cmk` after
verify.

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

The `wolfcrypt/src/port/caliptra/sim/` directory contains two test backends:

- **`caliptra_sim.c`** — software mailbox stub for offline development (no
  external dependencies).
- **`caliptra_hwmodel.c`** + **`Makefile`** — runs `caliptra_test.c` against
  real Caliptra firmware via the [chipsalliance/caliptra-sw][caliptra-sw]
  hw-model C binding.

### Running the hw-model test

The hw-model test exercises actual Caliptra firmware (ROM + runtime) through
the hardware emulator.  All nine test cases pass: RNG, SHA-256, SHA-384,
AES-GCM, ECDSA sign+verify, and HMAC-SHA-384.

#### Prerequisites

| Requirement | Version / Notes |
|-------------|-----------------|
| Rust toolchain | 1.85 (set by `rust-toolchain.toml` in caliptra-sw) |
| RISC-V target | `riscv32imc-unknown-none-elf` (installed by `rustup` automatically) |
| C compiler | GCC or Clang |
| System libs | `libpthread`, `libstdc++`, `libdl`, `librt`, `libm` |
| wolfSSL | Built with `--enable-caliptra` (see step 3 below) |

#### Step 1 — Clone caliptra-sw

```sh
git clone https://github.com/chipsalliance/caliptra-sw.git ~/caliptra
cd ~/caliptra
```

The Makefile defaults to `~/caliptra`; override with `CALIPTRA_ROOT=<path>`
if you clone elsewhere.

#### Step 2 — Build the C binding and firmware image bundle

```sh
cd ~/caliptra

# Build the hw-model C binding static library and generate caliptra_model.h
cargo build -p caliptra-hw-model-c-binding
# Produces: target/debug/libcaliptra_hw_model_c_binding.a
#           hw-model/c-binding/out/caliptra_model.h

# Build the firmware image bundle (compiles FMC + runtime RISC-V firmware)
# Also produces a ROM binary; the frozen ROM in the repo can be used instead
# (see Makefile variables below).
cargo run --manifest-path=builder/Cargo.toml --bin image -- \
    --rom-with-log hw-model/c-binding/out/caliptra_rom.bin \
    --fw hw-model/c-binding/out/image_bundle.bin
# Produces: hw-model/c-binding/out/image_bundle.bin
#           hw-model/c-binding/out/caliptra_rom.bin (optional; see note below)
```

The Makefile's default `ROM_PATH` points to the pre-built frozen ROM already
checked into caliptra-sw (`rom/ci_frozen_rom/2.1/caliptra-rom-2.1.0-a72a76f.bin`).
To use the freshly built ROM instead, pass `ROM_PATH` on the make command line
(see table below).

#### Step 3 — Build wolfSSL with Caliptra support

```sh
cd <wolfssl-root>
./autogen.sh          # if building from git, not a release tarball
./configure --enable-caliptra
make -j$(nproc)
```

#### Step 4 — Build and run the hw-model test

```sh
make -C wolfcrypt/src/port/caliptra/sim/ run
```

Expected output (boot log abbreviated):

```
caliptra_hwmodel: runtime ready (boot status 0x600)
PASS: RNG generates nonzero
PASS: SHA-256 empty KAT
PASS: SHA-256 abc KAT
PASS: SHA-384 empty KAT
PASS: SHA-256 multi-update matches software
PASS: AES-GCM encrypt/decrypt roundtrip
PASS: Caliptra ECDSA sign+verify
PASS: HMAC-SHA-384 matches software
PASS: AES-GCM tampered tag returns AES_GCM_AUTH_E

9/9 tests passed
```

#### Makefile variables

| Variable | Default | Override example |
|----------|---------|-----------------|
| `CALIPTRA_ROOT` | `~/caliptra` | `make CALIPTRA_ROOT=/opt/caliptra run` |
| `ROM_PATH` | `$(CALIPTRA_ROOT)/rom/ci_frozen_rom/2.1/caliptra-rom-2.1.0-a72a76f.bin` | `make ROM_PATH=/path/to/rom.bin run` |
| `FW_PATH` | `$(CALIPTRA_ROOT)/hw-model/c-binding/out/image_bundle.bin` | `make FW_PATH=/path/to/fw.bin run` |
| `WOLFSSL_ROOT` | repo root (auto-detected) | `make WOLFSSL_ROOT=/path/to/wolfssl run` |

[caliptra-sw]: https://github.com/chipsalliance/caliptra-sw
