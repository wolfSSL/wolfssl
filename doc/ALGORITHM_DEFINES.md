# Algorithm Build Options

This guide is for developers deciding which cryptographic algorithms to include
in a wolfSSL build, and how to configure each one. Selecting only what your
product uses is the most effective way to reduce code size and memory, and on a
constrained target it is usually where the largest savings are found.

It is written for builds that configure wolfSSL through a hand-written
`user_settings.h` and `WOLFSSL_USER_SETTINGS`. Each table also lists the
`./configure` option that produces the same define, so you can reproduce an
autotools build by hand or check what your current one selected.

`examples/configs/user_settings_embedded.h` is an editable template that wires
most of these options to a block of on/off switches, and is the quickest way to
get a working configuration.

For the options that select the math back end and the assembly for your
processor, see the companion guide `doc/ASM_AND_MATH_DEFINES.md`. Where an
algorithm has a math or assembly dimension, this guide points there rather than
repeating it.

## Contents

1. [How selection works](#1-how-selection-works)
2. [Symmetric ciphers](#2-symmetric-ciphers)
3. [Hashes](#3-hashes)
4. [MAC and KDF](#4-mac-and-kdf)
5. [RSA](#5-rsa)
6. [ECC](#6-ecc)
7. [DH](#7-dh)
8. [Curve25519, Curve448, Ed25519, Ed448](#8-curve25519-curve448-ed25519-ed448)
9. [Post-quantum](#9-post-quantum)
10. [Random number generation](#10-random-number-generation)
11. [Other schemes](#11-other-schemes)
12. [FIPS builds](#12-fips-builds)
13. [Reducing an algorithm to what you use](#13-reducing-an-algorithm-to-what-you-use)
14. [Options that weaken security](#14-options-that-weaken-security)

---

## 1. How selection works

Two naming conventions run through wolfCrypt. Understanding the difference will
save you time, as mixing them up is the most common configuration mistake.

* **`HAVE_<thing>` / `WOLFSSL_<thing>`** turns on something that is **off by
  default**. You define it to opt in.
* **`NO_<thing>`** turns off something that is **on by default**. You define it
  to opt out.

The point to watch is that a feature's internal flag is often the `HAVE_` form,
while the setting you are meant to change is the `NO_` form. `settings.h`
derives one from the other:

```c
/* settings.h */
#ifndef NO_AES_CBC                  /* you set this */
    #define HAVE_AES_CBC            /* the library tests this */
#endif
```

So to remove AES-CBC you define `NO_AES_CBC`. Defining `HAVE_AES_CBC` to `0`,
or simply leaving it out, will not do it. The same pattern governs the ECC
operation flags (`NO_ECC_SIGN` gives `HAVE_ECC_SIGN`, and likewise for
`VERIFY`, `DHE`, `KEY_IMPORT`, `KEY_EXPORT` and `CHECK_KEY`). Whenever a table
below says *default: on*, look for a `NO_` define to switch it off.

**Where to find the complete list.** This guide covers the options most builds
need. Most algorithm sources also carry a build options block in the comment
header listing every define and its default. Those blocks are the complete
list, are longer than what is summarised here, and are maintained alongside
the code:

| Algorithm | Block |
| --- | --- |
| AES | top of `wolfcrypt/src/aes.c` |
| ECC | top of `wolfcrypt/src/ecc.c` |
| RSA | top of `wolfcrypt/src/rsa.c` |
| ML-DSA | top of `wolfcrypt/src/wc_mldsa.c` |
| ML-KEM | top of `wolfcrypt/src/wc_mlkem.c` |
| SHA-3 | top of `wolfcrypt/src/sha3.c` |
| SHA-256 | top of `wolfcrypt/src/sha256.c` |
| RNG | top of `wolfcrypt/src/random.c` |
| SP math | top of `wolfcrypt/src/sp_int.c` |

Refer to those when you need an option this guide does not describe.

One practical note if you test a `user_settings.h` through autotools: defining
an algorithm here selects the code inside the sources, but it does not add a
source file to the build. `./configure --enable-usersettings` reads no defines
from your header, so pass the matching `--enable-*` as well — otherwise the
algorithm's `.c` file is never compiled and you get undefined references at
link time. `doc/ASM_AND_MATH_DEFINES.md` § 13 covers this and the related
assembly cases.

---

## 2. Symmetric ciphers

### AES

Core:

The Default column describes the **feature**, not the define — "on" means the
feature is present unless you define the `NO_` form.

| Define | Effect | Feature default |
| --- | --- | --- |
| `NO_AES` | Remove AES entirely | on |
| `NO_AES_128` / `NO_AES_192` / `NO_AES_256` | *remove* a key size | all three on |
| `AES_MAX_KEY_SIZE` | Largest key size in bits. Also gates the sizes above: at 128 the 192 and 256 keys are dropped whether or not you named them | 256 |
| `NO_AES_DECRYPT` | *removes* decryption — suits an encrypt-only device | on |

`settings.h` turns each of those into the `WOLFSSL_AES_128`/`_192`/`_256` and
`HAVE_AES_DECRYPT` flags the library tests, so the `NO_` forms above are the
ones to set.

Modes. CBC is the only one on by default; the rest are opt-in:

| Define | Mode | `./configure` |
| --- | --- | --- |
| `NO_AES_CBC` | *removes* CBC | `--disable-aescbc` |
| `HAVE_AESGCM` | GCM | `--enable-aesgcm` |
| `HAVE_AESCCM` | CCM | `--enable-aesccm` |
| `WOLFSSL_AES_COUNTER` | CTR | `--enable-aesctr` |
| `HAVE_AES_ECB` | ECB — see the caution below | `--enable-aesecb` |
| `WOLFSSL_AES_CFB` / `WOLFSSL_AES_OFB` | CFB / OFB | `--enable-aescfb` / `--enable-aesofb` |
| `WOLFSSL_AES_XTS` | XTS (storage) | `--enable-aesxts` |
| `WOLFSSL_AES_SIV` | AES-SIV (RFC 5297) | `--enable-aessiv` |
| `WOLFSSL_AESGCM_SIV` | AES-GCM-SIV (RFC 8452), nonce-misuse resistant. Requires AES-GCM | `--enable-aesgcm-siv` |
| `WOLFSSL_AES_EAX` | EAX | `--enable-aeseax` |
| `WOLFSSL_AES_CTS` | Ciphertext stealing | `--enable-aescts` |
| `HAVE_AES_KEYWRAP` | Key wrap (RFC 3394) | `--enable-aeskeywrap` |
| `WOLFSSL_AES_DIRECT` | Single-block encrypt/decrypt API. No configure option of its own — define it in `user_settings.h`, or get it as a side effect of an option that needs it, such as `--enable-aesofb` | — |

For TLS you will want GCM, or CCM on a target where that is preferred; CBC
alone only reaches the older cipher suites.

As the API documentation notes, ECB is considered less secure in nearly all use
cases, and wolfSSL recommends avoiding it unless you are implementing a
construction that specifically requires the raw block operation.

`settings.h` pulls in `WOLFSSL_AES_DIRECT` automatically for XTS and CFB, which
call the single-block functions, but not for CTR. The library itself builds
without it; the bundled benchmark application does not, because its CTR
benchmark calls `wc_AesSetKeyDirect`. If you build the benchmark, define
`WOLFSSL_AES_DIRECT` alongside `WOLFSSL_AES_COUNTER`.

GHASH implementation — pick exactly one, largest and fastest first:

| Define | Table | Notes |
| --- | --- | --- |
| `GCM_TABLE` | 256-entry | Fastest, largest |
| `GCM_TABLE_4BIT` | 16-entry | The usual compromise |
| `GCM_WORD32` | none, 32-bit words | For CPUs without a fast 64-bit multiply |
| `GCM_SMALL` | none | Smallest, slowest |

If you define none of them the choice is made for you, but not by `settings.h`:
`aes.h` picks a table on ARM, and otherwise `aes.c` falls through to the
table-less implementation. On a constrained target choose explicitly — the
difference in both size and speed is substantial.

Size and side channels:

| Define | Effect |
| --- | --- |
| `WOLFSSL_AES_SMALL_TABLES` | 256-byte tables instead of 4 × 1 kB |
| `WOLFSSL_AES_NO_UNROLL` | Do not unroll the round loop |
| `WOLFSSL_AES_TOUCH_LINES` | Touch every cache line — cache-timing resistance |
| `WC_AES_BITSLICED` | Bitsliced implementation, constant time by construction |
| `AES_GCM_GMULT_NCT` | Non-constant-time GHASH. Faster, weaker |
| `WOLFSSL_AESGCM_STREAM` | Streaming GCM API for data that does not fit in memory |

Assembly (`WOLFSSL_AESNI`, `USE_INTEL_SPEEDUP`, `WOLFSSL_ARMASM`, …) is in
`doc/ASM_AND_MATH_DEFINES.md` § 6.

### ChaCha20-Poly1305

| Define | Effect | `./configure` |
| --- | --- | --- |
| `HAVE_CHACHA` | ChaCha20 stream cipher | `--enable-chacha` |
| `HAVE_POLY1305` | Poly1305 MAC | `--enable-poly1305` |
| `HAVE_XCHACHA` | XChaCha20, 24-byte nonce | `--enable-xchacha` |
| `HAVE_ONE_TIME_AUTH` | The one-time-auth wrapper TLS uses | — |

The TLS AEAD cipher suite needs all three of `HAVE_CHACHA`, `HAVE_POLY1305` and
`HAVE_ONE_TIME_AUTH`. On a processor with no AES instructions, ChaCha20-Poly1305
is usually both faster and smaller than AES-GCM, so it is worth considering as
your primary suite on such targets.

### Others

| Define | Algorithm | Notes |
| --- | --- | --- |
| `HAVE_CAMELLIA` | Camellia | |
| `WOLFSSL_SM4` | SM4. Each mode is selected individually with `WOLFSSL_SM4_ECB`, `_CBC`, `_CTR`, `_GCM` or `_CCM`, from `--enable-sm4-ecb` and so on | Chinese national standard |
| `HAVE_ARIA` | ARIA | Needs a third-party `MagicCrypto` source drop |
| `HAVE_ASCON` | ASCON | NIST lightweight standard |
| `NO_DES3` | *removes* 3DES | On by default; obsolete, remove it |
| `NO_DES3_TLS_SUITES` | Removes the 3DES TLS suites while keeping the primitive | |
| `NO_RC4` | *removes* ARC4 | Broken; remove it |

---

## 3. Hashes

| Define | Hash | Default |
| --- | --- | --- |
| `NO_MD5`, `NO_MD4` | *remove* MD5 / MD4 | on — remove both |
| `NO_SHA` | *removes* SHA-1 | on |
| `NO_SHA256` | *removes* SHA-256 | on |
| `WOLFSSL_SHA224` | SHA-224 | off |
| `WOLFSSL_SHA384` | SHA-384 | off |
| `WOLFSSL_SHA512` | SHA-512 | off |
| `WOLFSSL_NOSHA512_224` / `WOLFSSL_NOSHA512_256` | *remove* SHA-512/224 and SHA-512/256, which come with SHA-512 | on |
| `WOLFSSL_SHA3` | SHA-3 (all four sizes) | off |
| `WOLFSSL_SHAKE128` / `WOLFSSL_SHAKE256` | SHAKE XOFs | off |
| `WOLFSSL_SM3` | SM3 | off |
| `HAVE_BLAKE2B` / `HAVE_BLAKE2S` | BLAKE2 | off |
| `WOLFSSL_RIPEMD` | RIPEMD-160 | off |

Dependencies to be aware of:

* **SHA-384 lives in `sha512.c`.** Both are selected by `WOLFSSL_SHA384` and
  `WOLFSSL_SHA512` and by nothing else — `sha512.h:32` gates on those two. There
  is no `NO_SHA512` to reach for: `settings.h` defines that macro in places but
  no library source ever reads it.
* **SHA-224 shares the SHA-256 core.** `settings.h` raises an `#error` if
  `WOLFSSL_SHA224` is set with `NO_SHA256`. It costs almost nothing once
  SHA-256 is in.
* **Curves imply digests.** P-384 is signed with SHA-384 and P-521 with
  SHA-512. If the matching digest is not in your build, the wolfCrypt test
  suite reports `BAD_LENGTH_E`.
* **Ed25519 requires `WOLFSSL_SHA512`.** The build stops with an explicit
  `#error` if it is missing.
* **ML-KEM and ML-DSA require SHA-3 plus both SHAKEs**, since they are built on
  SHAKE. See § 9.
* **TLS 1.3 requires SHA-256.**

Size:

| Define | Effect |
| --- | --- |
| `USE_SLOW_SHA`, `USE_SLOW_SHA256`, `USE_SLOW_SHA512` | Loop rather than unroll the compression rounds. `USE_SLOW_SHA256` saves about 2 kB for roughly 25 % of the speed |
| `WOLFSSL_SHA3_SMALL` | Compact SHA-3 |
| `WOLFSSL_SHA256_ALT_CH_MAJ` | Ch/Maj forms some compilers optimise better |
| `SHA256_MANY_REGISTERS` | Keep state in registers, partially unrolled |

---

## 4. MAC and KDF

| Define | Effect | `./configure` |
| --- | --- | --- |
| `NO_HMAC` | *removes* HMAC | `--disable-hmac` |
| `WOLFSSL_CMAC` | AES-CMAC (RFC 4493). Requires `WOLFSSL_AES_DIRECT` — the CMAC functions are compiled only when it is defined, otherwise `wc_AesCmacGenerate_ex` and `wc_AesCmacVerify_ex` are left undefined at link time | `--enable-cmac` |
| `WOLFSSL_SIPHASH` | SipHash | `--enable-siphash` |
| `HAVE_HKDF` | HKDF — **required by TLS 1.3** | `--enable-hkdf` |
| `NO_PWDBASED` | *removes* the PBKDF family | `--disable-pwdbased` |
| `HAVE_X963_KDF` | ANSI X9.63 KDF, used by ECIES | `--enable-x963kdf` |
| `WOLFSSL_HAVE_PRF` | The TLS PRF | — |

`NO_PWDBASED` also removes what PKCS#8 and PKCS#12 need in order to decrypt
password-protected key files. That is usually safe to do unless your device
reads such files.

Password-based KDFs. All of these except Argon2 live inside the `NO_PWDBASED`
group, so `NO_PWDBASED` removes the lot of them; within that group PBKDF1 and
PBKDF2 are both **on by default** and are removed individually with the `NO_`
forms:

| Define | Effect | Default | `./configure` |
| --- | --- | --- | --- |
| `NO_PBKDF1` | *removes* PBKDF1 (PKCS#5 v1), legacy | on | — |
| `NO_PBKDF2` | *removes* PBKDF2 (PKCS#5 v2). PBKDF2 also needs HMAC, so it is unavailable under `NO_HMAC` regardless | on | — |
| `HAVE_SCRYPT` | scrypt (RFC 7914), memory-hard. Requires PWDBASED | off | `--enable-scrypt` |
| `HAVE_ARGON2` | Argon2 (RFC 9106), memory-hard, all three variants. Independent of PWDBASED, but requires BLAKE2b — `settings.h` implies `HAVE_BLAKE2B` for you | off | `--enable-argon2` |
| `WOLFSSL_ARGON2_THREADS` | Fill the segments of a slice on several threads. Requires `HAVE_ARGON2` and a build that is not `SINGLE_THREADED` | off | `--enable-argon2-threads` |
| `HAVE_CMAC_KDF` | CMAC-based KDF (SP 800-108). Requires `--enable-kdf` | off | `--enable-cmac-kdf` |

The `NO_` forms are not absolute: `settings.h` turns `HAVE_PBKDF1` back on for
`WOLFSSL_ENCRYPTED_KEYS`, PKCS#8 or PKCS#12, and `HAVE_PBKDF2` back on for
PKCS#7 or scrypt, because those features need the KDF to work. If you want a
KDF genuinely gone, check that nothing above it is pulling it back in.

scrypt and Argon2 are memory-hard by design — that is the point of them — so
check the parameters against the RAM you have before enabling either on a
small target. Argon2 asks for its whole cost in one contiguous allocation:
the `m` parameter is in KiB, so the 64 MiB that RFC 9106 recommends is a
single 64 MiB block. Both are left out of `--enable-all` on a kernel-module
build for that reason. Only version 0x13 of Argon2 is implemented; the
superseded 0x10 encoding is not offered.

`WOLFSSL_ARGON2_THREADS` does not change the derived tag — the
synchronization point at the end of every slice makes the result the same
however many threads filled it — so it is purely a speed/parallelism choice.

---

## 5. RSA

As above, the Default column describes the feature.

| Define | Effect | Feature default |
| --- | --- | --- |
| `NO_RSA` | Remove RSA | on |
| `WOLFSSL_RSA_PUBLIC_ONLY` | Public key operations only | off |
| `WOLFSSL_RSA_VERIFY_ONLY` | Verify only — smallest useful RSA | off |
| `WOLFSSL_RSA_VERIFY_INLINE` | Verify without copying the output | off |
| `WC_RSA_PSS` | RSA-PSS signatures — **required by TLS 1.3** | off |
| `WC_NO_RSA_OAEP` | Remove OAEP padding | off |
| `WC_RSA_NO_PADDING` | Raw, unpadded RSA | off |
| `WC_RSA_DIRECT` | Direct encrypt/decrypt API | off |
| `WOLFSSL_KEY_GEN` | Key generation | off |
| `WOLFSSL_RSA_KEY_CHECK` | Key pair consistency check | off |

Performance and hardening:

| Define | Effect |
| --- | --- |
| `WC_RSA_BLINDING` | Blind private key operations. Costs roughly 20 % in speed. **`./configure` sets this for you; a hand-written `user_settings.h` does not — you must define it yourself.** Your key must be associated with an RNG through `wc_RsaSetRNG()`. wolfSSL recommends it on any device holding a long-term private key |
| `RSA_LOW_MEM` | Private operations without CRT: far less memory, several times slower. Implies `SP_RSA_PRIVATE_EXP_D` and `WOLFSSL_SP_SMALL` |
| `WC_RSA_NONBLOCK` | Return and resume rather than block |

Key sizes come from the SP configuration (`WOLFSSL_SP_NO_2048`,
`WOLFSSL_SP_NO_3072`, `WOLFSSL_SP_4096`) — see
`doc/ASM_AND_MATH_DEFINES.md` § 5. `FP_MAX_BITS` bounds the size under
`USE_FAST_MATH` and is *twice* the key size: RSA-3072 needs `FP_MAX_BITS 6144`.

---

## 6. ECC

Enable with `HAVE_ECC`.

Curves. By default every supported size is built, which is rarely what a
product wants. Define `ECC_USER_CURVES` to take control, then opt in to the
curves you need:

| Define | Curve |
| --- | --- |
| `NO_ECC256` | *removes* P-256, which is otherwise on |
| `HAVE_ECC384`, `HAVE_ECC521` | P-384, P-521 |
| `HAVE_ECC192`, `HAVE_ECC224`, `HAVE_ECC239`, `HAVE_ECC320`, `HAVE_ECC512` | Other sizes |
| `HAVE_ECC112`, `HAVE_ECC128`, `HAVE_ECC160` | Legacy, below any current security floor |
| `HAVE_ECC_BRAINPOOL`, `HAVE_ECC_KOBLITZ`, `HAVE_ECC_SECPR2`, `HAVE_ECC_SECPR3` | Curve families |
| `WOLFSSL_CUSTOM_CURVES` | Allow non-standard curves (carries the curve `a` term) |
| `ECC_MIN_KEY_SZ` | Reject keys below this size |

The specialised SP implementations are selected separately, with
`WOLFSSL_SP_NO_256`, `WOLFSSL_SP_384` and `WOLFSSL_SP_521`. A curve enabled
here without its SP counterpart still works, but falls back to the generic math
and is markedly slower. See `doc/ASM_AND_MATH_DEFINES.md` § 5.

Operations are all on by default once `HAVE_ECC` is set. Remove the ones your
product does not perform, using the `NO_` form:

| Define | Removes |
| --- | --- |
| `NO_ECC_SIGN` | Signing |
| `NO_ECC_VERIFY` | Verification |
| `NO_ECC_DHE` | ECDH shared secret |
| `NO_ECC_KEY_IMPORT` / `NO_ECC_KEY_EXPORT` | Key import / export |
| `NO_ECC_CHECK_PUBKEY_ORDER` | Public key order validation. This is a security check and wolfSSL recommends leaving it enabled |

`WOLFSSL_ECC_BLIND_K` blinds the private scalar, adding protection against
side-channel recovery of the key at some cost in speed. It needs an RNG.

Opt-in extras: `HAVE_ECC_ENCRYPT` (ECIES), `HAVE_ECC_CDH` (cofactor DH),
`HAVE_COMP_KEY` (point compression), `WOLFSSL_VALIDATE_ECC_IMPORT` and
`WOLFSSL_VALIDATE_ECC_KEYGEN`.

Speed and memory:

| Define | Effect | Default |
| --- | --- | --- |
| `ECC_TIMING_RESISTANT` | Constant-time scalar multiplication | **not automatic — see below** |
| `ECC_SHAMIR` | Shamir's trick for verify: about twice as fast, larger working set | **not automatic — see below** |
| `FP_ECC` | Fixed-point cache. Faster repeat operations, holds a large table for the process lifetime — rarely worth it on a microcontroller. Sized by `FP_ENTRIES` (15) and `FP_LUT` (8) | off |
| `ALT_ECC_SIZE` | Size `ecc_point` from the curve, not from the largest RSA/DH key the math was built for. The single largest avoidable allocation in a build with both. Requires a heap — rejected with `WOLFSSL_NO_MALLOC` | off |
| `WC_ECC_NONBLOCK` | Non-blocking sign/verify/keygen. Needs `WOLFSSL_SP_NONBLOCK` | off |

**These are not on by default in a hand-written build.** `./configure` defines
`ECC_TIMING_RESISTANT`, `WC_RSA_BLINDING` and `ECC_SHAMIR` for you, and the
algorithm sources describe them as "default: on" on that basis. `settings.h`
only sets them inside platform blocks — Arduino and ESP-IDF — so a
`user_settings.h` build that does not name them gets **none of the three**,
including the two that are side-channel protections. Define them explicitly:

```c
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define ECC_SHAMIR      /* speed, not security */
```

`examples/configs/user_settings_embedded.h` sets all three unconditionally.

### Other elliptic-curve algorithms

| Define | Algorithm | `./configure` |
| --- | --- | --- |
| `WOLFSSL_SM2` | SM2 signatures and key exchange. Also pulls in `WOLFSSL_BASE16`. Pair with `WOLFSSL_SM3` and `WOLFSSL_SM4` for the full Chinese suite, and with `WOLFSSL_SP_SM2` for the specialised curve implementation | `--enable-sm2` |
| `WOLFCRYPT_HAVE_ECCSI` | ECCSI (RFC 6507), identity-based signatures | `--enable-eccsi` |
| `WOLFCRYPT_HAVE_SAKKE` | SAKKE (RFC 6508), identity-based key encapsulation. Uses the 1024-bit SP support, so pair it with `WOLFSSL_SP_1024` | `--enable-sakke` |
| `WOLFCRYPT_SAKKE_SMALL` | Smaller, slower SAKKE | `--enable-sakke=small` |

ECCSI and SAKKE are used together in MIKEY-SAKKE deployments. Both are large
additions; enable them only if your application implements those protocols.

---

## 7. DH

| Define | Effect |
| --- | --- |
| `NO_DH` | Remove DH — it is on by default |
| `HAVE_FFDHE_2048` / `_3072` / `_4096` / `_6144` / `_8192` | Named finite-field groups (RFC 7919) |
| `HAVE_DH_DEFAULT_PARAMS` | Built-in parameter sets |
| `WOLFSSL_DH_EXTRA` | Key import/export and additional API |
| `HAVE_PUBLIC_FFDHE` | Expose the group parameters |

**TLS 1.3 will not build with DH enabled and no group named.** The build stops
with `#error Please configure your TLS 1.3 DH key size using either:
HAVE_FFDHE_2048, …`. Choose at least one group, matching the RSA/DH sizes your
SP math was built for. ECDHE is smaller and faster than finite-field DH, so
unless you need to interoperate with a peer that requires DH, you can leave it
disabled.

---

## 8. Curve25519, Curve448, Ed25519, Ed448

| Define | Effect |
| --- | --- |
| `HAVE_CURVE25519` | X25519 key agreement |
| `HAVE_ED25519` | Ed25519 signatures. **Requires `WOLFSSL_SHA512`** |
| `HAVE_CURVE448` / `HAVE_ED448` | The 448-bit pair; needs SHAKE256 |
| `CURVE25519_SMALL` / `ED25519_SMALL` | Small, slow implementations for tight targets |
| `WOLFSSL_CURVE25519_BLINDING` | Blind the X25519 scalar against side-channel recovery. **On by default** for the C, non-small build (`settings.h:4711`), needing an RNG; opt out with `NO_CURVE25519_BLINDING`. Unavailable with `CURVE25519_SMALL` — `curve25519.c` rejects the pair — so choosing the small implementation forfeits it |
| `HAVE_ED25519_SIGN` / `_VERIFY` / `_KEY_IMPORT` / `_KEY_EXPORT` | Trim to what is used |
| `WC_X25519_NONBLOCK` | Non-blocking X25519. There is no Ed25519 equivalent — the non-blocking defines are `WC_X25519_NONBLOCK`, `WC_ECC_NONBLOCK`, `WC_RSA_NONBLOCK` and `WC_DH_NONBLOCK` |

X25519 is a good default on constrained targets. There is one curve and no
parameter choices to make, it is constant time by construction, and it does not
need the SP curve machinery that P-256 does.

---

## 9. Post-quantum

### ML-KEM (FIPS 203) and ML-DSA (FIPS 204)

| Define | Effect | `./configure` |
| --- | --- | --- |
| `WOLFSSL_HAVE_MLKEM` | ML-KEM key encapsulation | `--enable-mlkem` |
| `WOLFSSL_HAVE_MLDSA` | ML-DSA signatures | `--enable-mldsa` |
| `WOLFSSL_MLKEM_KYBER` | The original round-3 Kyber instead of FIPS 203 | `--enable-mlkem=original` |

These algorithms were previously named Kyber and Dilithium, and the older
`HAVE_DILITHIUM` and `--enable-dilithium` spellings remain valid. If you are
updating an existing configuration, `doc/dilithium-to-mldsa-migration.md` lists
every renamed build gate and API.

**Parameter sets are opt-out.** Defining `WOLFSSL_HAVE_MLKEM` alone builds all
three sets, so each one not wanted must be named:

| Define | Removes |
| --- | --- |
| `WOLFSSL_NO_ML_KEM_512` / `_768` / `_1024` | An ML-KEM parameter set |
| `WOLFSSL_NO_ML_DSA_44` / `_65` / `_87` | An ML-DSA parameter set |

This differs from `./configure`, where the parameter sets appear to be opt-in,
so take care when converting an autotools configuration by hand. ML-KEM-768 and
ML-DSA-44 are the widely deployed tiers and are a sensible default.

Operations and size:

| Define | Effect |
| --- | --- |
| `WOLFSSL_MLKEM_NO_MAKE_KEY` / `_NO_ENCAPSULATE` / `_NO_DECAPSULATE` | Drop an operation |
| `WOLFSSL_MLDSA_NO_MAKE_KEY` / `_NO_SIGN` / `_NO_VERIFY` | Drop an operation |
| `WOLFSSL_MLDSA_VERIFY_ONLY` | Verify only — the firmware-check case |
| `WOLFSSL_MLDSA_VERIFY_SMALL_MEM` | Stream the verify instead of expanding the key at once |
| `WOLFSSL_MLDSA_VERIFY_PRECOMP_A` | Allow a host-expanded matrix A to be attached with `wc_MlDsaKey_SetPrecompA()`, so verify skips the SHAKE128 expansion. Needs a verification key fixed at build time; works with both the default and small-memory verifiers. The stored matrix must be integrity-protected exactly as the public key is |
| `WOLFSSL_MLKEM_SMALL`, `WOLFSSL_MLKEM_NO_LARGE_CODE` | Loop rather than unroll |
| `WOLFSSL_MLDSA_SMALL`, `WOLFSSL_MLDSA_NO_LARGE_CODE` | As above for ML-DSA |
| `WOLFSSL_MLKEM_DYNAMIC_KEYS` | Allocate key buffers to the size actually needed, rather than carrying the largest in the key structure. Reduces handshake memory on constrained systems. **Cannot be used with `WOLFSSL_NO_MALLOC`** |
| `WOLFSSL_MLDSA_NO_ASN1` | No ASN.1 — for builds with no X.509 |

Both algorithms need `WOLFSSL_SHA3`, `WOLFSSL_SHAKE128` and `WOLFSSL_SHAKE256`,
as they are built on SHAKE. Budget for the SHA-3 code when sizing a
post-quantum build.

Neither uses the big-number math, so none of the SP options affect them. They
are accelerated through the per-algorithm assembly instead — see
`doc/ASM_AND_MATH_DEFINES.md` § 6.

### Falcon and FrodoKEM

Both are native implementations with no liboqs dependency, and both currently
require `--enable-experimental`.

| Define | Effect | `./configure` |
| --- | --- | --- |
| `HAVE_FALCON` | Falcon signatures | `--enable-falcon` |
| `WOLFSSL_FALCON_FPR_ASM`, `WOLFSSL_FALCON_FPR_DOUBLE` | Floating-point back end for the FFT: assembly, or the C double implementation | `--enable-falcon=asm,double` |
| `WOLFSSL_FALCON_FFT_AVX2`, `WOLFSSL_FALCON_FFT_NEON` | Vectorised FFT on x86_64 and Aarch64 | `--enable-falcon=avx2,neon` |
| `WOLFSSL_FALCON_SIGN_SMALL_MEM` | Low-memory signing | `--enable-falcon=small-mem` |
| `WOLFSSL_HAVE_FRODOKEM` | FrodoKEM key encapsulation | `--enable-frodokem` |
| `WOLFSSL_NO_FRODOKEM_640` / `_976` / `_1344` | Remove a parameter set — at least one must remain | |
| `WOLFSSL_FRODOKEM_SHAKE` / `WOLFSSL_FRODOKEM_AES` | Matrix generation method — at least one is required | `--enable-frodokem-shake` / `-aes` |
| `WOLFSSL_FRODOKEM_NO_MAKE_KEY` / `_NO_ENCAPSULATE` / `_NO_DECAPSULATE` | Drop an operation — at least one must remain | |
| `WOLFSSL_FRODOKEM_EPHEMERAL` | eFrodoKEM (ephemeral, salt-less) variants | `--enable-frodokem-ephemeral` |
| `WOLFSSL_FRODOKEM_SMALL` | Looped rather than unrolled matrix arithmetic | `--enable-frodokem=small` |
| `WOLFSSL_FRODOKEM_SVE` / `WOLFSSL_FRODOKEM_SME` | Aarch64 SVE and SME matrix acceleration | `--enable-frodokem-sve` / `-sme` |

FrodoKEM is conservative by design and its keys and ciphertexts are far larger
than ML-KEM's, so it is usually chosen for a specific compliance requirement
rather than for general use. ML-KEM is the better default.

### Stateful hash-based signatures

| Define | Effect |
| --- | --- |
| `WOLFSSL_HAVE_LMS` | LMS/HSS (RFC 8554) |
| `WOLFSSL_HAVE_XMSS` | XMSS/XMSS^MT (RFC 8391) |
| `WOLFSSL_HAVE_SLHDSA` | SLH-DSA (FIPS 205), stateless |

LMS and XMSS suit firmware verification well: verification is inexpensive and
the public key is small. They are **stateful**, meaning a signing key must never
reuse an index. That makes them an excellent fit for a device that only
verifies, and a demanding one for a device that signs, since you become
responsible for persisting the signing state reliably.

---

## 10. Random number generation

This is the most important section to get right on a bare-metal port. A weak or
repeating entropy source undermines every key the device generates, and it does
so silently.

| Define | Effect |
| --- | --- |
| `HAVE_HASHDRBG` | Hash-based DRBG (SP 800-90A). On by default and what you want |
| `WC_NO_HASHDRBG` | Use the raw source directly, no DRBG |
| `WC_NO_RNG` | No RNG at all. Only for a build that performs no operation needing randomness |
| `CUSTOM_RAND_GENERATE_SEED` | Your seed function — the usual bare-metal hook |
| `CUSTOM_RAND_GENERATE_BLOCK` | Your full block generator, e.g. a hardware RNG |
| `WC_RNG_SEED_CB` | Register the seed source at run time instead |
| `HAVE_ENTROPY_MEMUSE` | Memory-use based entropy where no hardware source exists |
| `HAVE_INTEL_RDRAND` | Seed from the Intel `RDRAND` instruction |
| `HAVE_INTEL_RDSEED` | Seed from the Intel `RDSEED` instruction |
| `HAVE_AMD_RDSEED` | Seed from the AMD `RDSEED` instruction |
| `WOLFSSL_GENSEED_FORTEST` | **Deterministic stub. Bring-up only — never ship it** |

On x86 and x86_64, `RDRAND` and `RDSEED` give you an on-chip entropy source
with no operating system involvement, which is often the simplest answer for a
bare-metal build on those parts. They depend on the CPUID feature detection,
which `cpuid.h` compiles only when one of `WOLFSSL_X86_64_BUILD`,
`USE_INTEL_SPEEDUP`, `WOLFSSL_AESNI` or `WOLFSSL_SP_X86_64_ASM` is defined and
`WOLFSSL_NO_ASM` is not. Enabling `HAVE_INTEL_RDRAND` in a build without one of
those leaves `IS_INTEL_RDRAND` and `cpuid_get_flags_ex` undeclared.

On a target with no operating system and no `/dev/random`, define
`NO_DEV_RANDOM` and supply entropy through one of the hooks above, or implement
`wc_GenerateSeed()` in your port. If you do neither, the build stops with
`#error "you need to write an os specific wc_GenerateSeed() here"`. wolfSSL
raises that error deliberately rather than fall back to a predictable source, so
treat it as a prompt to connect a real entropy source on your hardware.

---

## 11. Other schemes

| Define | Scheme | `./configure` |
| --- | --- | --- |
| `HAVE_HPKE` | Hybrid Public Key Encryption (RFC 9180). Pulls in HKDF, and needs a KEM — ECC or Curve25519 | `--enable-hpke` |
| `WOLFCRYPT_HAVE_SRP` | SRP password-authenticated key exchange (RFC 5054) | `--enable-srp` |
| `HAVE_PKCS7` | PKCS#7 / CMS signing and enveloping, used for firmware signing and S/MIME | `--enable-pkcs7` |

HPKE is what wolfSSL's Encrypted Client Hello support is built on, so enable it
if you need ECH.

---

## 12. FIPS builds

If you are building against a FIPS-validated wolfCrypt module, the choices in
this guide narrow considerably. The validated module has a fixed algorithm
boundary, and you cannot add an algorithm to it or replace one of its
implementations without invalidating the certificate.

In practice:

* The algorithm set is determined by the FIPS module you have, not by these
  defines. Options that remove an algorithm inside the boundary should not be
  used.
* Non-FIPS algorithms can still be built alongside the module, but they sit
  outside the boundary and cannot be used for FIPS-approved operations.
* `./configure` selects the correct settings for your module from
  `--enable-fips=<version>`. Start from that, and from the matching template in
  `examples/configs/` — `user_settings_fipsv2.h` or `user_settings_fipsv5.h` —
  rather than assembling a FIPS configuration by hand.

`doc/ASM_AND_MATH_DEFINES.md` § 8 covers what a FIPS build fixes on the math and
assembly side. If you are planning a FIPS build, contact **fips@wolfssl.com**
before finalising your configuration.

---

## 13. Reducing an algorithm to what you use

Beyond choosing algorithms, the largest remaining savings come from removing
operations your device never performs. A device that verifies firmware does not
sign; a sensor that only encrypts telemetry does not decrypt.

| What the device does | Defines |
| --- | --- |
| Verify signatures only (ECC) | `NO_ECC_SIGN`, `NO_ECC_DHE`, `NO_ECC_KEY_EXPORT` |
| Verify signatures only (RSA) | `WOLFSSL_RSA_VERIFY_ONLY`, `WOLFSSL_RSA_PUBLIC_ONLY` |
| Verify signatures only (ML-DSA) | `WOLFSSL_MLDSA_VERIFY_ONLY`, `WOLFSSL_MLDSA_VERIFY_SMALL_MEM` |
| Encrypt only | `NO_AES_DECRYPT` |
| No key generation | leave `WOLFSSL_KEY_GEN` undefined; `WOLFSSL_MLKEM_NO_MAKE_KEY`, `WOLFSSL_MLDSA_NO_MAKE_KEY` |

Two points to bear in mind when you do this.

**The TLS layer needs the full set of operations.** Once `HAVE_ECC` is defined,
the TLS code references ECC signing unconditionally, so a verify-only ECC build
will not link against TLS — not even a PSK-only one. Reductions of this kind
belong in wolfCrypt-only builds, or in a TLS build where the reduced algorithm
is not the one TLS uses.

**The bundled test application exercises the full API.**
`wolfcrypt/test/testwolfcrypt` signs as well as verifies, so a verify-only build
will report a failure there: `WOLFSSL_RSA_VERIFY_ONLY` produces `RSA test
failed!` with error `-231`, *Signature type not enabled/available*. This is the
test application exercising an operation you have deliberately removed, and does
not indicate a problem with your build. Similarly, a `NO_ASN` build does not
compile the test application at all, as it uses the ASN.1 API unconditionally.
Build `src/libwolfssl.la` on its own to check such configurations, and validate
them against your own application instead.

---

## 14. Options that weaken security

Several options in this guide and its companion buy speed or size by giving up
a protection. Each is reasonable in the right circumstances and wrong in most,
so they are collected here as a single list to check a configuration against
before it ships.

| Option | What you give up |
| --- | --- |
| `WC_NO_HARDEN` | Constant-time modular exponentiation in `sp_int.c`. It also silences the build warning that would otherwise tell you a build lacks hardening, so a configuration carrying it will not warn you about the other omissions below |
| `WC_NO_CACHE_RESISTANT` | Cache-resistant, constant-address table access |
| `WOLFSSL_NO_CT_OPS` | Constant-time helper operations |
| `USE_INTEGER_HEAP_MATH` | The `integer.c` back end is not timing resistant |
| `USE_FAST_MATH` without `TFM_TIMING_RESISTANT` | Timing resistance in the fastmath back end |
| `HAVE_ECC` without `ECC_TIMING_RESISTANT` | Constant-time ECC scalar multiplication. Not automatic in a hand-written build — see § 6 |
| RSA without `WC_RSA_BLINDING` | Blinding of RSA private key operations. Not automatic in a hand-written build — see § 5 |
| `WOLFSSL_SP_FAST_NCT_EXPTMOD` | Constant-time modular exponentiation. Intended for public key operations only, where the exponent is not secret |
| `AES_GCM_GMULT_NCT` | Constant-time GHASH |
| `NO_ECC_CHECK_PUBKEY_ORDER` | Validation of the order of a received public key |
| `NO_RSA_BOUNDS_CHECK` | Bounds checking on RSA input |
| `WC_RSA_NO_PADDING` | RSA padding. Raw RSA is only safe inside a scheme that provides its own padding |
| `WOLFSSL_GENSEED_FORTEST` | A real entropy source. This is a deterministic stub for bring-up and must never ship |
| `WC_BLINDING_NO_RNG_ACKNOWLEDGE_WEAKNESS` | Blinding, when `WC_NO_RNG` has removed the RNG it depends on. `settings.h` raises an `#error` precisely so that this cannot happen silently |

wolfSSL leaves the first several on by default, and `settings.h` emits a build
warning when a configuration is missing them — *"For timing resistance /
side-channel attack prevention consider using harden options"*. If you see that
warning, treat it as a finding rather than noise.

If any of these appear in a product configuration, it is worth recording why.
For a review of a configuration before release, contact
**support@wolfssl.com**.

## See also

* `doc/ASM_AND_MATH_DEFINES.md` — math back end, SP configuration and per-CPU
  assembly.
* `examples/configs/user_settings_embedded.h` — an editable template covering
  both guides.
* `examples/configs/README.md` — the full set of configuration templates,
  including profiles for TLS 1.3, DTLS, bare metal and post-quantum.
* `INSTALL` — full build instructions for every supported toolchain.

If you are unsure which algorithms your product needs, or want a configuration
reviewed before you ship it, contact **support@wolfssl.com**.
