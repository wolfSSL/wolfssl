# Microchip PolarFire SoC Athena F5200 (TeraFire)

Offload of SHA-2, AES, random number generation, ECDSA, ECDH and RSA to the
Athena F5200 "TeraFire" user cryptoprocessor, through the wolfCrypt crypto
callback.

## Hardware

The engine is present only on the "S" (security) grade PolarFire SoC devices --
MPFS250TS, for example; a plain MPFS250T has no engine and the port must not be
enabled for it. Register block `ATHENAREG` is at `0x20127000` (`ATHENA_CR`
+0x00, `STALL_CR` +0x04, `UPPER_ADDRESS` +0x08) and the user-crypto block the
CAL drives is at `0x22000000`.

`CRYPTO_CR_INFO.MSS_MODE` reads 0 in the stock Video Kit design, which the
Security User Guide describes as "held in reset". That register is read-only
informational and does not gate the block: software performs the un-reset and no
Libero change is needed.

The algorithm set has no lattice cryptography, so ML-DSA and ML-KEM stay in
software on this silicon.

## The CAL

All access goes through Microchip's CAL (Crypto Abstraction Library). There is
no register-level programming guide for the engine, so a hand-written driver is
not viable. CAL is **referenced by include path and never vendored**: it carries
a Mercury Systems licence.

Two published builds exist, and they differ in ways that matter:

| | `hart-software-services/services/crypto` | `polarfire-soc-bare-metal-examples/.../middleware/cal` |
|---|---|---|
| archive | `mpfs-rv64imac-user-crypto-lib.a` | `mss-user-crypto-lib.a` |
| ISA | `rv64imac` | `rv64imafd` |
| float ABI | soft | soft |
| `CALCONFIGH` | defined in its `calpolicy.h` | not defined; the caller must supply it |
| `PKX0_BASE` | compiled in as `0x22000000` | read from `g_user_crypto_base_addr` |

Both archives are **soft-float `lp64`**, so every object linked against them
must be built `-mabi=lp64`; an `lp64d` object will not link.

`g_user_crypto_base_addr` is defined by this port, because the second archive
lists it as an undefined external while the first never references it -- so in
the commoner build it is an unused word that `--gc-sections` drops. Define
`WC_MPFS_ATHENA_NO_BASE_ADDR` if the platform already supplies it.

The archives are freestanding and non-PIC: they reference no libc symbols, carry
no GOT relocations, and bake in physical addresses. **The port is M-mode bare
metal.** It cannot go into a shared library, a PIE, or Linux user space; a Linux
path would need the HSS crypto SBI extension through a kernel driver, or a UIO
mapping of the two register windows.

## Enabling

With autotools, point the build at the CAL directory:

```sh
./configure --host=riscv64-unknown-elf \
    --with-mpfs-athena=<hart-software-services>/services/crypto \
    CFLAGS="-march=rv64imac -mabi=lp64 -mcmodel=medany"
```

With a `user_settings.h`, add the CAL directory to the include path and define:

```c
#define WOLFSSL_MICROCHIP_MPFS   /* targeting PolarFire SoC */
#define WOLFSSL_MPFS_ATHENA      /* this part has the "S" grade engine */
```

`WOLFSSL_MICROCHIP_MPFS` selects the SoC family and offloads nothing by itself.
`WOLFSSL_MPFS_ATHENA` is what the port compiles against. `settings.h` reacts to
it by turning on `WOLF_CRYPTO_CB`,
`WOLF_CRYPTO_CB_COPY` and `WOLF_CRYPTO_CB_FREE` and maps `WC_USE_DEVID` so the
stock `wolfcrypt_test()` and `benchmark()` drive the engine with no argument.

What is offloaded follows the ordinary wolfCrypt feature gates, and each family
can be kept in software with a port opt-out:

| Offload | wolfCrypt gate | Opt-out |
|---|---|---|
| SHA-224, SHA-256 | `!NO_SHA256`, `WOLFSSL_SHA224` | `WC_MPFS_ATHENA_NO_SHA256` |
| SHA-384 | `WOLFSSL_SHA384` | |
| SHA-512, SHA-512/224, SHA-512/256 | `WOLFSSL_SHA512` | `WC_MPFS_ATHENA_NO_SHA512` |
| AES-ECB (and so AES-XTS) | `HAVE_AES_ECB` | |
| AES-CTR | `WOLFSSL_AES_COUNTER` | |
| AES-CBC | `HAVE_AES_CBC` | `WC_MPFS_ATHENA_NO_CBC` |
| AES-GCM (and so GMAC) | `HAVE_AESGCM` | `WC_MPFS_ATHENA_NO_GCM` |
| AES key wrap, RFC 3394 and RFC 5649 wrap | `HAVE_AES_KEYWRAP` | `WC_MPFS_ATHENA_NO_KEYWRAP` |
| AES-CMAC, one-shot | `WOLFSSL_CMAC` | `WC_MPFS_ATHENA_NO_CMAC` |
| NRBG seed for every RNG (`random.c`); engine DRBG with `WC_MPFS_ATHENA_RNG_DRBG` | `HAVE_HASHDRBG`, without `CUSTOM_RAND_GENERATE_BLOCK` | `WC_MPFS_ATHENA_NO_RNG` |
| ECDSA sign and verify, ECDH, EC key generation, P-192 to P-521 | `HAVE_ECC` | `WC_MPFS_ATHENA_NO_ECC` |
| RSA CRT private, and raw public with `WC_MPFS_ATHENA_RSA_PUBLIC`, up to `WC_MPFS_ATHENA_RSA_MAX_BITS` | `!NO_RSA` | `WC_MPFS_ATHENA_NO_RSA` |

AES runs at all three key sizes. Anything the port declines runs in software,
so a request it cannot serve is never an error: a GCM IV other than 96 bits,
streaming CMAC, an RFC 5649 unwrap or a key whose length is not a whole
number of words, a key wrap over 501 semiblocks, an RFC 3394 unwrap whose
output buffer is not at least as long as its input, a custom curve, an RSA key
without CRT parameters, or an operation whose input wolfCrypt would reject on
its own path, such as an all-zero ECDSA digest or an RSA input outside
1 < x < n - 1.

### AES-XTS

XTS is AES-ECB over tweak-masked data, and `_AesXtsHelper()` already issues one
bulk `wc_AesEcbEncrypt()`/`wc_AesEcbDecrypt()` per XTS call, which lands on this
port's ECB case. An `XtsAes` tagged with the port's devId is therefore offloaded
with no XTS code here, given:

- `HAVE_AES_ECB` (`--enable-aesecb`; configure adds it for `--with-mpfs-athena`
  with `--enable-aesxts`). Without it XTS runs a block at a time through
  `wc_AesEncryptDirect()`, slower than software.
- Distinct input and output buffers; the helper is not used in place.

The tweak encrypt and the stealing tail arrive as single-block calls and stay in
software, as do the GF(2^128) tweak multiply and both XORs. XTS therefore gains
less than bulk CTR, and improves with call size since the engine setup is paid
once per call - measure at the size the application uses.

Stock benchmark, MPFS250TS Video Kit, E51 at 600 MHz, bare metal; the software
column is wolfCrypt's default cache-line-touch-hardened C AES for RISC-V:

| Call size | AES-256-XTS software | AES-256-XTS engine | AES-256-CTR engine | SHA-384 engine |
|---|---|---|---|---|
| 512 B | 48 KiB/s | 1.23 MiB/s | 12.9 MiB/s | 11.4 MiB/s |
| 1 KiB | 49 KiB/s | 2.06 MiB/s | 14.6 MiB/s | 13.2 MiB/s |
| 4 KiB | 49 KiB/s | 4.2 MiB/s | 16.1 MiB/s | 14.8 MiB/s |

Software SHA-384 is 5.8 MiB/s.

## Using it

```c
wolfCrypt_Init();                                   /* before registering */
wc_MpfsAthena_RegisterDevice(WC_MPFS_ATHENA_DEVID);
wc_MpfsAthena_SelfTest();
```

then pass that devId to the `_ex` init of each object: `wc_InitSha256_ex()`,
`wc_AesInit()`, `wc_ecc_init_ex()`, `wc_InitRsaKey_ex()`, `wc_InitRng_ex()` and
so on. Objects tagged with any other devId stay in software. Seeding is the
exception: `wc_GenerateSeed()` reads the NRBG directly, so every RNG is seeded
from the engine whatever its devId (`WC_MPFS_ATHENA_NO_RNG` opts out, and a
`CUSTOM_RAND_GENERATE_SEED` takes precedence). The engine DRBG applies only to
an RNG created with the port's devId.

`wolfCrypt_Init()` must come first. It is what initialises the crypto callback
device table; without it every slot reads as occupied and
`wc_CryptoCb_RegisterDevice()` returns `BUFFER_E`. The port deliberately does
not call `wc_CryptoCb_Init()` itself, because that clears the whole table and
would unregister every other device.

`wc_MpfsAthena_SelfTest()` runs known-answer tests through the public wolfCrypt
API and **counts the callback entries the engine actually served**. It is
compiled only with `WC_MPFS_ATHENA_SELFTEST`; without it the stub returns
`NOT_COMPILED_IN`. That count is part of the pass condition: when registration has silently failed, wolfCrypt
computes the correct answer in software and a digest-only comparison still
passes. `wc_MpfsAthena_SelfTestDesc()` names what a failure tripped on and
`wc_MpfsAthena_GetCbCount()` exposes the count.

## Tunables

All overridable from `user_settings.h`. The defaults are in `mpfs_athena.h`,
except `WC_MPFS_ATHENA_DEVID`, which `settings.h` sets so it can also drive
`WC_USE_DEVID`.

| Macro | Default | Meaning |
|---|---|---|
| `WC_MPFS_ATHENA_DEVID` | `0xA7` | crypto callback device id |
| `WC_MPFS_ATHENA_HASH_SLOTS` | 4 | concurrent offloaded SHA-2 contexts when there is no heap |
| `WC_MPFS_ATHENA_AES_MIN_SZ` | 32 | smallest AES-ECB or AES-CBC request the engine serves; self-test needs twice this as scratch |
| `WC_MPFS_ATHENA_GCM_MIN_SZ` | 0 | smallest AES-GCM payload the engine serves |
| `WC_MPFS_ATHENA_RSA_MAX_BITS` | 4096 | largest RSA modulus the engine serves |
| `WC_MPFS_ATHENA_RSA_PUBLIC` | unset | also serve RSA public operations, which are slower on the engine than in software with a small public exponent |
| `WC_MPFS_ATHENA_RNG_DRBG` | unset | generate random output with the engine's DRBG rather than wolfCrypt's |
| `WC_MPFS_ATHENA_DRBG_RESEED` | 1024 | generate calls between reseeds of the engine's DRBG |
| `WC_MPFS_ATHENA_BASE_ADDR` | `0x22000000` | user-crypto base, for `g_user_crypto_base_addr` |
| `WC_MPFS_ATHENA_REG_BASE` | `0x20127000` | `ATHENAREG` |
| `WC_MPFS_ATHENA_SYSREG_BASE` | `0x20002000` | MSS SYSREG |
| `WC_MPFS_ATHENA_NO_BASE_ADDR` | unset | the platform defines `g_user_crypto_base_addr` |
| `WC_MPFS_ATHENA_NO_HW_INIT` | unset | the clock, reset and stall seed are already set up |
| `WC_MPFS_ATHENA_SELFTEST` | unset | compile the known-answer tests |
| `WC_MPFS_ATHENA_NO_HW_MUTEX` | unset | do not serialise CAL transactions |
| `WC_MPFS_ATHENA_NO_<family>` | unset | keep that family in software, per the table above |

Under `WOLFSSL_NO_MALLOC` or `WOLFSSL_STATIC_MEMORY` the per-context engine
state comes from a fixed pool of `WC_MPFS_ATHENA_HASH_SLOTS` entries, and
hashing falls back to software once it is empty; otherwise it is allocated.

## Engine behaviour worth knowing

None of this is in the CAL headers.

- **The bring-up runs once per image.** Asserting `ATHENA_CR` RESET after
  `CALIni()` leaves the symmetric engine silently dead -- `CALSymEncrypt()` keeps
  returning `SATR_SUCCESS` and the destination is never written -- while hashing
  continues to work, so it presents as an AES-only fault. Only another
  `CALIni()` recovers.
- **The stall seed is read from `rdcycle`, not `mcycle`**: an `mcycle` read traps
  in the S-mode builds.
- **A non-final `CALHashCtx()` call must carry a whole number of blocks**, or it
  fails with `SATR_BADHASHLEN` (30). The port feeds 128 bytes at a time for
  every SHA-2 type, which is also a whole number of SHA-256 blocks. The final
  call takes any remainder, including zero, and the engine pads.
- **`CALSymEncrypt()` only starts the transfer.** Without a following
  `CALSymTrfRes(SAT_TRUE)` the output buffer is never written while both calls
  report success.
- **The AES counter is advanced in place**, so consecutive calls on one context
  continue the keystream.
- **The engine's CTR counter is 32 bits wide.** It carries nothing past the low
  word, where `wc_AesCtrEncrypt()` counts over all 128. The port stops each
  transfer at that wrap and recomputes the counter itself; the self-test covers
  a stream across it.
- **DRBG generate and every public-key operation complete through
  `CALPKTrfRes()`**, not `CALSymTrfRes()`, and the operation's own result code
  arrives there. The NRBG read, DRBG instantiate and `CALPurge52()` are
  synchronous: a `CALPKTrfRes()` after them waits forever.
- **Public-key operands are 32-bit words, least significant word first.** On
  this little-endian core that is the big-endian value with its bytes reversed.
  The NIST primes are in the engine's ROM and are passed by address
  (`P256_MOD` and the rest) with no Barrett constant; the order and an RSA
  modulus need one from `CALPreCompute()`, one word longer than the modulus.
- **The engine keeps private-key operands in its own memory**, so every private
  operation ends with `CALPurge52()`.
- **The DMA entry points do nothing.** `CALHashDMA()` and `aesf5200dma()` are
  declared, but the shipped archive is built with `USE_X52EXEC_DMA 0` and they
  return success without moving data. The port uses the non-DMA calls.

## Limitations

- **Thread safety rests on the wolfCrypt hardware mutex.** CAL has one resource
  handle and the engine is a single block, so every CAL transaction is taken
  under `wolfSSL_CryptHwMutex*`, and `WOLFSSL_CRYPT_HW_MUTEX` is turned on
  unless the build is `SINGLE_THREADED`. `WC_MPFS_ATHENA_NO_HW_MUTEX` opts out,
  which is only safe single threaded. Concurrent use has not been exercised on
  hardware. The static hash pool used under `WOLFSSL_NO_MALLOC` or
  `WOLFSSL_STATIC_MEMORY` also takes that mutex to hand out and return slots;
  `wc_MpfsAthena_Init()` fails if it cannot be taken, so registration fails
  rather than running the pool unlocked.
- **The `FinalRaw()` hash functions do not see the engine.** They read the
  software digest state directly with no callback dispatch, so on an offloaded
  context they return the initial values. This affects every hash crypto
  callback port, not just this one.
- **A SHA-512 family context is identified by its initial value**, not by the
  event type: wolfCrypt reports every SHA-512/224 and SHA-512/256 update as
  `WC_HASH_TYPE_SHA512`, and retries a declined SHA-384 call the same way.
- **Software blinding does not run on an offloaded private-key operation.** The
  port uses the engine's countermeasure paths instead (`CALECDSASignCM()`,
  `CALECMultCM()`, `CALRSACRTCM()`).
- **The ECC and RSA handlers need operand scratch**: about 0.9 KiB for ECC and
  about 3.8 KiB for RSA at the default 4096-bit maximum. It is on the stack, or
  allocated with `WOLFSSL_SMALL_STACK`.
- **CI compiles the port but gives no target-ABI coverage.**
  `.github/workflows/mpfs-athena-compile.yml` compiles it with the runner's own
  host compiler against the CAL headers from the public hart-software-services
  repository at a pinned commit, and checks that every CAL symbol it references
  is defined in the archive. It is a host compile because both CAL archives are
  soft-float `lp64` and Ubuntu's riscv64 glibc is `lp64d` only, so `-mabi=lp64`
  cannot be satisfied there; what the job guards is a CAL header rename or a
  refactor in the wolfCrypt algorithm files or `cryptocb.h`, all of which the host
  compiler sees. The target ABI is proven by building for the board, and
  functional correctness by `wc_MpfsAthena_SelfTest()` on real silicon.

## Not offloaded

SHA-1, AES-CFB and AES-OFB stay in software by choice. HMAC needs no handler of
its own: its inner and outer hashes reach the engine through the SHA-2
offload. The engine has no AES-CCM mode, no prime generation for RSA key
generation, and no post-quantum algorithms. DSA and DH are exposed by the CAL
and not wired up.
