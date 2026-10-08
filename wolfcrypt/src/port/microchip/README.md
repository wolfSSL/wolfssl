# Microchip PolarFire SoC Athena F5200 (TeraFire)

SHA-384 and AES-256-CTR offload on the Athena F5200 "TeraFire" user
cryptoprocessor, through the wolfCrypt crypto callback.

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
    --enable-aesctr \
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

Which engines are offloaded follows the ordinary wolfCrypt feature gates rather
than port-specific ones: `WOLFSSL_SHA384` for the hash, and
`WOLFSSL_AES_COUNTER` with `!NO_AES` for AES-256-CTR. AES-128 and AES-192
requests are declined to software, as are all other hash types.

## Using it

```c
wolfCrypt_Init();                                   /* before registering */
wc_MpfsAthena_RegisterDevice(WC_MPFS_ATHENA_DEVID);
wc_MpfsAthena_SelfTest();
```

then pass that devId to `wc_InitSha384_ex()` and `wc_AesInit()`. Contexts tagged
with any other devId stay in software.

`wolfCrypt_Init()` must come first. It is what initialises the crypto callback
device table; without it every slot reads as occupied and
`wc_CryptoCb_RegisterDevice()` returns `BUFFER_E`. The port deliberately does
not call `wc_CryptoCb_Init()` itself, because that clears the whole table and
would unregister every other device.

`wc_MpfsAthena_SelfTest()` runs known-answer tests through the public wolfCrypt
API and **counts the callback entries the engine actually served**. It is
compiled by default; `WC_MPFS_ATHENA_NO_SELFTEST` drops it and the KAT tables
where size matters more, and the stub then returns `NOT_COMPILED_IN`. That count is
part of the pass condition: when registration has silently failed, wolfCrypt
computes the correct answer in software and a digest-only comparison still
passes. `wc_MpfsAthena_SelfTestDesc()` names what a failure tripped on and
`wc_MpfsAthena_GetCbCount()` exposes the count.

## Tunables

All overridable from `user_settings.h`; see `mpfs_athena.h` for the defaults.

| Macro | Default | Meaning |
|---|---|---|
| `WC_MPFS_ATHENA_DEVID` | `0xA7` | crypto callback device id |
| `WC_MPFS_ATHENA_HASH_SLOTS` | 4 | concurrent offloaded SHA-384 contexts when there is no heap |
| `WC_MPFS_ATHENA_BASE_ADDR` | `0x22000000` | user-crypto base, for `g_user_crypto_base_addr` |
| `WC_MPFS_ATHENA_REG_BASE` | `0x20127000` | `ATHENAREG` |
| `WC_MPFS_ATHENA_SYSREG_BASE` | `0x20002000` | MSS SYSREG |
| `WC_MPFS_ATHENA_NO_BASE_ADDR` | unset | the platform defines `g_user_crypto_base_addr` |
| `WC_MPFS_ATHENA_NO_HW_INIT` | unset | the clock, reset and stall seed are already set up |
| `WC_MPFS_ATHENA_NO_SELFTEST` | unset | drop the known-answer tests |
| `WC_MPFS_ATHENA_NO_HW_MUTEX` | unset | do not serialise CAL transactions |

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
- **A non-final `CALHashCtx()` call must carry a whole number of 128-byte
  blocks**, or it fails with `SATR_BADHASHLEN` (30). The final call takes any
  remainder, including zero, and the engine pads.
- **`CALSymEncrypt()` only starts the transfer.** Without a following
  `CALSymTrfRes(SAT_TRUE)` the output buffer is never written while both calls
  report success.
- **The AES counter is advanced in place**, so consecutive calls on one context
  continue the keystream.
- **The DMA entry points do nothing.** `CALHashDMA()` and `aesf5200dma()` are
  declared, but the shipped archive is built with `USE_X52EXEC_DMA 0` and they
  return success without moving data. The port uses the non-DMA calls.

## Limitations

- **Thread safety rests on the wolfCrypt hardware mutex.** CAL has one resource
  handle and the engine is a single block, so every CAL transaction is taken
  under `wolfSSL_CryptHwMutex*`, and `WOLFSSL_CRYPT_HW_MUTEX` is turned on
  unless the build is `SINGLE_THREADED`. `WC_MPFS_ATHENA_NO_HW_MUTEX` opts out,
  which is only safe single threaded. Concurrent use has not been exercised on
  hardware.
- **`wc_Sha384FinalRaw()` does not see the engine.** It reads the software digest
  state directly with no callback dispatch, so on an offloaded context it returns
  the SHA-384 initial values. This affects every hash crypto callback port, not
  just this one.
- **CI compiles the port but cannot run it.** `.github/workflows/mpfs-athena-compile.yml`
  cross-compiles it for `rv64imac` against the CAL headers from the public
  hart-software-services repository at a pinned commit, and checks that every
  CAL symbol it references is defined in the archive. Functional correctness is
  established by `wc_MpfsAthena_SelfTest()` on real silicon.

## Not yet offloaded

The CAL also exposes SHA-1/224/256/512, AES-128/192, AES-GCM/CCM/key-wrap, HMAC,
DRBG/NRBG, ECDSA, ECDH, RSA, DSA and DH. None of those have been run on this
silicon, so they are left in software rather than shipped untested. ECDSA P-384
verify is the one most worth adding next.
