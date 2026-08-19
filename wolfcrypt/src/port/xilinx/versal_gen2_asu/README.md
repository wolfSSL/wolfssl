# wolfSSL port for the Versal Gen 2 ASU

Routes wolfCrypt operations to the ASU (Application Security Unit) on Versal
Gen 2 parts. The port registers a wolfSSL crypto callback device; anything the
ASU cannot do falls back to software, so a build with the port on still passes
the full wolfCrypt self-test.

## Turning it on

Define this in `user_settings.h`:

```c
#define WOLFSSL_VERSAL_GEN2_ASU
```

That is the whole setup. `wolfCrypt_Init()` registers the device and brings the
ASU client up, so an application needs no ASU calls of its own:

```c
ret = wolfCrypt_Init();     /* opens the mailbox, calls XAsu_ClientInit */
```

The BSP must have the `xilasu` and `xilmailbox` libraries enabled.

## What runs on hardware

| Engine | Covered |
| --- | --- |
| Hash | SHA2-256/384/512, SHA3-256/384/512, SHAKE256 |
| HMAC | over SHA2-256/384/512 and SHA3-256/384/512 |
| AES | CBC, ECB, CTR, CFB, OFB, GCM, CCM |
| CMAC | AES-CMAC |
| RSA | raw modexp, plus PSS and OAEP padding when `WOLF_CRYPTO_CB_RSA_PAD` is set |
| ECDSA | NIST P-192/256/384, Brainpool P-256/320/384/512 |
| EdDSA | plain Ed25519 and Ed448 sign and verify |
| ECDH | the same curves as ECDSA |
| ECIES | AES-GCM with HKDF-SHA256 |
| TRNG | seed and random block |

Anything outside this list is declined and wolfSSL runs it in software. That
includes AES-192, partial AES blocks, SHA-512/224 and 512/256, Keccak padding,
SHAKE128, deterministic ECDSA, and the older ECIES layouts.

## Settings

`WOLFSSL_VERSAL_GEN2_ASU` on its own offloads every engine above. Name one or
more of these instead and only those are offloaded:

```
WOLFSSL_VERSAL_GEN2_ASU_TRNG      WOLFSSL_VERSAL_GEN2_ASU_CMAC
WOLFSSL_VERSAL_GEN2_ASU_HASH      WOLFSSL_VERSAL_GEN2_ASU_RSA
WOLFSSL_VERSAL_GEN2_ASU_HMAC      WOLFSSL_VERSAL_GEN2_ASU_ECC
WOLFSSL_VERSAL_GEN2_ASU_CIPHER
```

`_ECC` also covers ECDH and ECIES when those features are built.

Other switches:

| Macro | Effect |
| --- | --- |
| `WOLFSSL_VERSAL_GEN2_ASU_DEVID` | device id for the callback, default `0x4153` |
| `WOLFSSL_VERSAL_GEN2_ASU_IPI_BASEADDR` | IPI channel, default `XPAR_XIPIPSU_0_BASEADDR` |
| `WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT` | the application calls `XAsu_ClientInit` itself |
| `WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD` | RSA on, padding in software |
| `WOLFSSL_VERSAL_GEN2_ASU_ECC_P521` | add P-521, off by default, see below |
| `WOLFSSL_VERSAL_GEN2_ASU_DEBUG` | print every ASU operation over the UART |
| `WOLFSSL_VERSAL_GEN2_ASU_RTC` | supply the benchmark time source from the port |
| `XASU_DISABLE_CACHE` | cache is off, so skip all buffer flush and reload work |

The port sets `WOLF_CRYPTO_CB`, `WOLF_CRYPTO_CB_CMD`, `WOLF_CRYPTO_CB_COPY` and
`WOLF_CRYPTO_CB_FREE` for you, and points `WC_USE_DEVID` at the ASU device so
the unmodified wolfCrypt test and benchmark route through it.

## Known limits

**P-521 is off by default.** Stock ASU firmware pads the digest wrong and the
client caps it at 64 bytes, which is short of the 66 P-521 needs. Turn it on
only with firmware that front-pads.

**ECIES is narrow.** Only the default AES-GCM scheme with HKDF-SHA256 offloads,
the KDF context must be non-empty, and a MAC salt sends it to software.

## Files

```
asu_cryptocb.c   device registration and the callback dispatcher
asu_util.c       client bring-up, waiting, cache handling, timer
asu_hash.c       SHA2, SHA3, SHAKE256
asu_hmac.c       HMAC
asu_cipher.c     AES
asu_cmac.c       AES-CMAC
asu_rsa.c        RSA
asu_ecc.c        ECDSA, Ed25519, Ed448
asu_ecdh.c       ECDH
asu_ecies.c      ECIES
asu_rng.c        TRNG
```

Headers live in `wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/`, with the
build settings in `asu_settings.h`.
