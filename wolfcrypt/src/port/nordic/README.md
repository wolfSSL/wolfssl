# Nordic nRF54L CRACEN port

Crypto callback port for the CRACEN cryptographic accelerator on the nRF54L15,
nRF54L10 and nRF54L05. It programs the Cryptomaster (AES and hash engines), the
TRNG and the public key engine directly through their registers and needs no
Nordic SDK. The public key engine additionally needs its microcode, which the
application supplies (see below).

## Enabling

```c
#define WOLFSSL_NRF54L_CRACEN
```

in `user_settings.h`, then in the application:

```c
wc_CracenInit();                 /* registers device WOLFSSL_CRACEN_DEVID */
...
wc_CracenCleanup();
```

`WC_USE_DEVID` is mapped to `WOLFSSL_CRACEN_DEVID`, so `wolfcrypt/test` and
`wolfcrypt/benchmark` run on the hardware unmodified, and `wc_GenerateSeed()`
reads the TRNG. Objects created with `INVALID_DEVID` stay in software.

The build must run in the secure world: CRACEN is a secure-only peripheral and
its DMA carries the secure attribute. The CPU has no data cache, so DMA buffers
need no maintenance, but every buffer the pusher writes must be in RAM.

## What is offloaded

| Operation | Hardware | Notes |
|---|---|---|
| SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | BA413 | Multi-part through state export; padding done in software. SHA-512/224 and SHA-512/256 stay in software |
| HMAC | software over hardware hashes | The HMAC callback declines; inner hashes carry the devId |
| AES-ECB, AES-CBC | BA411E | Chaining block kept in `Aes.reg` |
| AES-CTR | BA411E | Partial blocks handled; unused key stream kept in `Aes.tmp` |
| AES-GCM | BA411E | 96-bit IV, tag 4..16 bytes; other IV sizes go to software |
| AES-CMAC | BA411E | Multi-part through state export |
| Seed | BA431 TRNG | Conditioned output feeds the Hash-DRBG; see RNG below |
| ECDSA sign and verify, ECDH, ECC key generation, public key derivation and validation | BA414EP | P-192/256/384/521 with the engine's own parameters; any other prime curve up to 521 bits (P-224, Brainpool, ...) with parameters loaded per operation |
| RSA public and private operation | BA414EP | Raw modular exponentiation, CRT for private keys with CRT parameters; padding stays in software |
| DH agreement | BA414EP | Modular exponentiation |
| X25519 | BA414EP | Key generation, shared secret, public key derivation |
| Ed25519, Ed25519ctx, Ed25519ph | BA414EP | Point multiplication and the signature arithmetic; the SHA-512 steps run on the key's devId |

Not offloaded: AES-CCM, AES-CFB/OFB/XTS, ChaCha20-Poly1305, SHA-3, RSA and DH
key generation, deterministic ECDSA (`WOLFSSL_ECDSA_DETERMINISTIC_K`) and
signing with a caller-chosen nonce, Ed448/X448. Anything the port declines runs
in software with no change of result.

Engines absent from `CRYPTMSTRHW.INCLIPSHWCFG`, or modes absent from the AES
and hash capability registers, are declined at runtime.

A hash object is taken over only when it is fresh (nothing hashed since its
init); once the hardware holds its state the request can no longer fall back,
so a hardware failure mid-stream is reported as `WC_HW_E`. The same holds for a
CMAC object after its init was accepted. Cipher calls are independent, so any
single call may fall back.

## RNG

The BA431 TRNG samples ring oscillators, runs the NIST SP 800-90B repetition
count and adaptive proportion tests and the AIS31 tests on them, and conditions
four raw 128-bit blocks into each output block with AES-CBC-MAC. The port
programs it as Nordic's drivers do: sample divider 241, 512-cycle start-up
wait, ring oscillators stopped as soon as the FIFO is full, and the
conditioning key loaded from the first FIFO words with a restart afterwards,
so nothing produced under the default key is handed out.

Conditioned output seeds wolfCrypt's Hash-DRBG: `wc_GenerateSeed()` is routed
to the TRNG (`CUSTOM_RAND_GENERATE_SEED`) and so is `WC_ALGO_TYPE_SEED` for
objects carrying the devId. The DRBG itself stays in software, so SP 800-90A
behaviour (reseed interval, health tests) is wolfCrypt's. With
`WOLFSSL_CRACEN_RNG_DIRECT` the callback also serves `WC_ALGO_TYPE_RNG`,
handing conditioned TRNG output out directly.

A health test failure or a start-up test failure puts the FSM in its error
state; the driver restarts the TRNG and retries up to
`WOLFSSL_CRACEN_TRNG_MAX_RECOVERIES` times, then fails with `RNG_FAILURE_E`.
A FIFO that never fills fails the same way after `WOLFSSL_CRACEN_TIMEOUT`
polls. Alarm flags are counted on their rising edge and available with
`wc_CracenTrngGetStats()`.

Application API:

```c
int  wc_CracenTrngRead(byte* out, word32 sz);     /* raw conditioned output */
void wc_CracenTrngOff(void);                       /* power down until next read */
int  wc_CracenTrngGetStats(wc_CracenTrngStats*);   /* starts, recoveries, alarms, bytes */
```

The TRNG stays powered between reads by default; `WOLFSSL_CRACEN_TRNG_ON_DEMAND`
powers it down after each one, which costs the start-up wait and a new
conditioning key on every read.

## Public key engine

The BA414EP runs microcode that is not part of the chip's ROM: Nordic's
drivers copy a 4.9 KB blob (`ba414ep_ucode`, nRF Connect SDK
`subsys/nrf_security/src/drivers/cracen/common/src/cracen/hardware/microcode_binary.h`,
LicenseRef-Nordic-5-Clause) into the engine's microcode RAM. The blob is not
distributed with wolfSSL; the application loads it once after init:

```c
wc_CracenInit();
wc_CracenPkLoadMicrocode(ba414ep_ucode, BA414EP_UCODE_SIZE);   /* words */
```

Until it has been loaded, `wc_CracenPkReady()` returns 0 and every public key
request is declined to software. Loading enables the PKE/IKG block, waits for
its RAM zeroisation, reads the engine's capability register (`pkCfg` in
`wc_CracenHwInfo`) and writes the words. `wc_CracenCleanup()` disables the
block again; a new `wc_CracenInit()` needs a new load.

Operands are placed in the engine's 16 slots of 512 bytes, big-endian values
right-aligned, the 25519 values little-endian; the slots that held private
material or results are cleared after each operation. Keys stay in wolfCrypt's
objects: the engine sees only the operands of the current operation.

Side channel countermeasures: ECDSA signing, ECC point multiplication with a
private scalar (key generation, ECDH, public key derivation) and the RSA and DH
private operations run with the engine's scalar/exponent and projective
coordinate or modulus randomisation, fed with a 64-bit blinding factor from the
TRNG. `WOLFSSL_CRACEN_PK_NO_CM` turns this off; it is also skipped when the
engine reports countermeasures disabled or when the operand is too large to
leave room for the extra 64 bits (4096-bit RSA).

ECDSA nonces come from `wc_ecc_gen_k()` with the RNG the caller passed, and
digests are truncated to the order length exactly as the software path does.
Signatures are produced and consumed in the usual DER form. RSA input range
checks (`RSA_OUT_OF_RANGE_E`) match the software path, including the
small-ciphertext check on private decrypt.

The chip's tamper controller (TAMPC) treats some misuse of the PKE/IKG block
as a tamper event and, with its reset defaults, resets the device. The
on-target test project can disable that reset and reports the TAMPC status at
the end of a run; see `IDE/Nordic/nRF54L15/README.md`.

## Options

| Macro | Default | Meaning |
|---|---|---|
| `WOLFSSL_CRACEN_DEVID` | `0x4352` | Device id |
| `WOLFSSL_CRACEN_HASH`, `_CIPHER`, `_CMAC`, `_TRNG`, `_PK` | all that the build has algorithms for | Engine selection; defining any one disables the others |
| `WOLFSSL_CRACEN_PK_NO_CM` | off | Run public key operations without the engine's side channel countermeasures |
| `WOLFSSL_CRACEN_PK_TIMEOUT` | `0x4000000` | Poll iterations before a public key operation fails with `WC_HW_E` |
| `WOLFSSL_CRACEN_NO_SEED` | off | Do not make the TRNG `wc_GenerateSeed()` |
| `WOLFSSL_CRACEN_RNG_DIRECT` | off | Serve `wc_RNG_GenerateBlock()` straight from the TRNG |
| `WOLFSSL_CRACEN_TIMEOUT` | `0x400000` | Poll iterations before an operation fails with `WC_HW_E` |
| `WOLFSSL_CRACEN_TRNG_CLKDIV` | 241 | Ring oscillator sample clock divider |
| `WOLFSSL_CRACEN_TRNG_INITWAIT` | 512 | Cycles to wait before sampling after start |
| `WOLFSSL_CRACEN_TRNG_OFFTIMER` | 0 | Cycles before the rings stop once the FIFO is full |
| `WOLFSSL_CRACEN_TRNG_MAX_RECOVERIES` | 3 | Restarts tried on a health test failure before giving up |
| `WOLFSSL_CRACEN_TRNG_ON_DEMAND` | off | Power the TRNG down after every read |
| `WOLFSSL_CRACEN_HOST_TEST` | off | Build against a shim on a PC; everything declines |
| `WOLFSSL_CRACEN_HOST_EMULATE` | off | Host build whose shim computes every operation in software behind the hardware interface |

## Host testing

```sh
./configure --enable-cracen --enable-aesctr --enable-aesecb --enable-cmac
make check
```

builds the dispatcher and the fall-back paths with no hardware.

```sh
./configure --enable-cracen=emulate --enable-aesctr --enable-aesecb --enable-cmac
make check
```

registers the emulated device as `WC_USE_DEVID`, so `testwolfcrypt` and the
unit tests run the port's streaming, padding, counter and CMAC logic on a PC.
The emulated public key engine is ready from init (the microcode load is
accepted and ignored) and computes each primitive with wolfCrypt's own
arithmetic, so the key unpacking, digest truncation, DER conversion, Ed25519
hashing and result handling of the handlers are exercised too. Only the
register encodings themselves are left to the target.

## Files

| File | Role |
|---|---|
| `cracen_hw_bare.c` | Register driver: Cryptomaster DMA, AES, hash, CMAC, TRNG, public key engine |
| `cracen_hw_shim.c` | Host-test stand-in for the above, declining or emulating |
| `cracen_cryptocb.c` | Device registration, dispatch, microcode load |
| `cracen_cb_hash.c`, `cracen_cb_cipher.c`, `cracen_cb_cmac.c`, `cracen_cb_rng.c`, `cracen_cb_pk.c` | One handler per algorithm type |
| `wolfssl/wolfcrypt/port/nordic/cracen_regs.h` | Register map, Cryptomaster and public key engine encodings |

The register offsets come from the nRF54L15 datasheet and the Nordic MDK; the
descriptor and AES encodings from nrfx (both BSD-3-Clause). The hash
configuration word, the tag's invalid-byte field, and the public key engine's
operation codes, slot assignments, operand placement and blinding factor format
are hardware facts observed in Nordic's nRF Connect SDK driver
(LicenseRef-Nordic-5-Clause); they are recorded in `cracen_regs.h` and
`cracen_hw_bare.c` in this port's own words and no code from that driver is
used. The engine microcode itself is Nordic's and is never copied into wolfSSL.

## On-target test

`IDE/Nordic/nRF54L15/` is a bare-metal project for the nRF54L15 DK that
cross-checks every offloaded algorithm against software and then runs
`wolfcrypt_test()`.
