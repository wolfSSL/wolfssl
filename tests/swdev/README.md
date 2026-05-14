# wc_swdev: Software CryptoCb Device for Tests

`wc_swdev` is a **test-only** software backend used to exercise builds
that strip a wolfCrypt algorithm in favor of CryptoCb dispatch. It is
compiled separately from the main library, linked into the test
programs only, and exposes exactly two C symbols. **It is not a
production component and must not be linked into shipping binaries.**

The four switches it supports are:

| Macro                          | Strips         | Test target        |
|--------------------------------|----------------|--------------------|
| `WOLF_CRYPTO_CB_ONLY_RSA`      | software RSA   | RSA via CryptoCb   |
| `WOLF_CRYPTO_CB_ONLY_ECC`      | software ECC   | ECC via CryptoCb   |
| `WOLF_CRYPTO_CB_ONLY_SHA256`   | software SHA-256 | SHA-256 via CryptoCb |
| `WOLF_CRYPTO_CB_ONLY_AES`      | software AES   | AES via CryptoCb   |

When a test program calls e.g. `wc_AesCbcEncrypt()` against a libwolfssl
built with `-DWOLF_CRYPTO_CB_ONLY_AES`, the software AES path is gone;
the call routes through the CryptoCb dispatch layer. swdev registers
itself as that callback, executes the operation against its own
internal copy of the AES code, and returns the result.

## Architecture

```
   +-----------------------------------------------------------+
   | TEST PROGRAM (testwolfcrypt, unit.test, examples/...)     |
   |                                                           |
   |   wolfCrypt_Init()                                        |
   |   wc_SwDev_Init()       -- registers swdev device + a     |
   |                            WOLF_CRYPTO_CB_FIND hook       |
   |   ... wc_AesCbcEncrypt(), wc_Sha256Update(), etc. ...     |
   |   wc_SwDev_Cleanup()                                      |
   |   wolfCrypt_Cleanup()                                     |
   +-----------------------------------------------------------+
                |                                  ^
                |  call into LIBWOLFSSL            |  result
                v                                  |
   +-----------------------------------------------------------+
   | LIBWOLFSSL  (compiled with -DWOLF_CRYPTO_CB_ONLY_AES,     |
   |              -DWOLF_CRYPTO_CB_ONLY_SHA256, ...)           |
   |                                                           |
   |   wc_AesCbcEncrypt()                                      |
   |     - software AES is #ifdef'd out                        |
   |     - dispatch via wc_CryptoCb_AesCbc...()                |
   +-----------------------------------------------------------+
                |                                  ^
                |  CryptoCb dispatch               |
                v                                  |
   +-----------------------------------------------------------+
   | tests/swdev/build/swdev.o                                 |
   |   (single relocatable .o, only 2 visible symbols)         |
   |                                                           |
   |   wc_SwDev_Callback(devId, info, ctx)                     |
   |     - swdev_ensure_init() lazy wolfCrypt_Init             |
   |     - switch (info->algo_type):                           |
   |         PK     -> RSA / ECC software impl                 |
   |         HASH   -> SHA-256 software impl                   |
   |         CIPHER -> AES (CBC/CTR/ECB/GCM/CCM) software impl |
   |                                                           |
   |   swdev was compiled WITHOUT the WOLF_CRYPTO_CB_ONLY_*    |
   |   gates, so its private copy of wolfcrypt still has the   |
   |   full software implementations.                          |
   +-----------------------------------------------------------+
```

## How the Two-Compile Trick Works

The whole mechanism rests on compiling the wolfcrypt sources twice:

1. **libwolfssl** is built normally with the user's `_ONLY_*` flags
   set, so its software RSA/ECC/SHA-256/AES paths are gone.
2. **swdev** recompiles the same source set under
   `tests/swdev/user_settings.h`, which `#undef`s all four `_ONLY_*`
   macros. swdev therefore contains the full software implementations.

To prevent symbol collisions when both are linked into the same test
binary, `tests/swdev/Makefile` does the following:

- Compiles every swdev TU with `-fvisibility=hidden -fno-common`.
- Drops `-DBUILDING_WOLFSSL` so `WOLFSSL_API` does not re-promote
  symbols to default visibility.
- Links all swdev objects with `ld -r` into a single relocatable
  `swdev.partial.o`.
- Runs `objcopy --keep-global-symbol=wc_SwDev_Callback
  --keep-global-symbol=wc_SwDev_InternalCleanup` to localize every
  remaining global except the two intended exports.

The Makefile then enforces the invariant directly:

```sh
nm --extern-only --defined-only build/swdev.o
```

must list **only** `wc_SwDev_Callback` and `wc_SwDev_InternalCleanup`.
The build fails loudly otherwise (see `tests/swdev/Makefile:122-129`).
If you add a third `WC_SWDEV_EXPORT` API, update the keep-list in the
Makefile too.

## ABI Constraint

swdev and libwolfssl share C structs across the CryptoCb boundary
(`wc_Sha256`, `Aes`, `RsaKey`, `ecc_key`, ...). One compilation
allocates them, the other operates on them. They must therefore be
ABI-identical. The `_ONLY_*` macros only gate function bodies, not
struct layouts, so flipping them between the two compiles is safe.
**Do not introduce other macros that change struct layout into
`tests/swdev/user_settings.h`.**

## Building

`wc_swdev` is enabled with the `--enable-swdev` configure flag.

```sh
./autogen.sh
./configure --enable-swdev --enable-cryptocb \
            <other flags> \
            CPPFLAGS="-DWOLF_CRYPTO_CB_ONLY_ECC \
                      -DWOLF_CRYPTO_CB_ONLY_RSA \
                      -DWOLF_CRYPTO_CB_ONLY_SHA256 \
                      -DWOLF_CRYPTO_CB_ONLY_AES" \
            --disable-sha224
make
make check
```

Notes:

- `--enable-swdev` requires `--enable-cryptocb`, or `--enable-usersettings`
  with `WOLF_CRYPTO_CB` defined in the user's `user_settings.h`.
- `--enable-swdev` defines `WOLFSSL_SWDEV` and `WOLF_CRYPTO_CB_FIND`
  automatically; see `configure.ac`.
- `--enable-swdev` currently supports **in-tree builds only**.
  Out-of-tree (VPATH) builds fail at configure time. swdev is built
  from `wolfcrypt/test/include.am` and inherits `PARENT_SRCS`,
  `PARENT_BUILD_CFLAGS`, etc., from the parent build.
- `--disable-sha224` is required when `WOLF_CRYPTO_CB_ONLY_SHA256` is
  set: SHA-224 is unsupported for now.

For the full CI matrix that exercises each `_ONLY_*` macro, see
`.github/workflows/cryptocb-only.yml`.

## Files

| File                | Role                                                          |
|---------------------|---------------------------------------------------------------|
| `swdev.h`           | Public swdev interface (the two exported symbols)             |
| `swdev.c`           | CryptoCb dispatcher: PK / HASH / CIPHER algorithms            |
| `swdev_loader.h`    | Test-harness API: `wc_SwDev_Init`, `wc_SwDev_Cleanup`         |
| `swdev_loader.c`    | Refcounted Init/Cleanup; registers the callback + Find hook   |
| `user_settings.h`   | `#undef`s the `WOLF_CRYPTO_CB_ONLY_*` gates for swdev's TU    |
| `Makefile`          | Two-compile + objcopy + symbol-invariant check                |

## Production Use

**None.** swdev exists only to make the `WOLF_CRYPTO_CB_ONLY_*` builds
testable on a generic Linux runner. Real deployments are expected to
provide their own CryptoCb backed by a hardware engine (TPM, HSM, SoC
crypto block, etc.). swdev is not API-stable, not benchmarked, and not
audited as a production cryptographic provider.
