# wolfSSL NXP Hardware Acceleration Ports

wolfSSL supports hardware acceleration on NXP DCP, LTC (KSDK), LPC55S69,
SE050, and the QorIQ SEC.

## NXP LPC55S69

The LPC55S69 is a general purpose edge computing device, with dual ARM
Cortex-M33 cores running up to 150 MHz, 640/320 KB internal flash/ram,
TrustZone-M, a DSP accelerator, and extensive cryptographic acceleration.

wolfSSL supports the following hardware acceleration on the LPC55S69:
- TRNG
- HashCrypt (Hash/AES Crypto Engine)
  - AES (128, 192, 256) encrypt/decrypt
    - AES-CBC, AES-ECB, AES-CTR, AES-OFB, AES-CFB
  - SHA-1, SHA-256
- CASPER (Asymmetric Crypto Accelerator)
  - RSA verify/encrypt/decrypt (up to 4096-bit, public key only)

### LPC55S69 Hardware Acceleration Caveats

The following caveats should be noted about the LPC55S69 hardware acceleration:
- AES-CTR mode fails when the counter wraps from all FF's to 0.  User should
ensure this never happens, by properly managing the iv/counter in use.
- AES-CFB and AES-OFB only support full 16-byte blocks and multiples thereof.
Encrypt/Decrypt requests of other sizes will fail.
- RSA acceleration is only supported for public keys.  Private key operations
will use a fully software implementation.
- When the HashCrypt engine is in use for SHA-1 or SHA-256, it must not be
interrupted with another hash request or an AES request.  The hash must be
completed before another operation is requested.

### wolfSSL LPC55S69 Hardware Acceleration Enable

To enable only the TRNG, define the following symbol:

**`WOLFSSL_NXP_RNG_1`**

To enable all LPC55S69 hardware acceleration, including the TRNG,
define the following symbol:

**`WOLFSSL_NXP_LPC55S6X`**

NOTE: Both can be defined with no problem.

## NXP SE050

For details on wolfSSL integration with NXP SE050,
see [README_SE050.md](./README_SE050.md).

## NXP QorIQ SEC

The SEC is the security engine on NXP's QorIQ PowerPC T-series parts. It
shares the CAAM descriptor architecture used by the i.MX parts, but this is a
separate, self-contained port under `wolfcrypt/src/port/nxp/`; it does not
build any of `wolfcrypt/src/port/caam/`.

### Supported hardware

Verified on real silicon:

| Part | Board | SEC | Era | CCSRBAR |
|---|---|---|---|---|
| T2080E rev 1.1 | Curtiss-Wright VPX3-152 | 5.2 | 6 | `0xEF000000` |
| T1040E rev 1.1 | NXP T1040D4RDB | 5.0 | 6 | `0xFE000000` |

Both place the SEC at `CCSRBAR + 0x300000` with four job rings at `+0x1000`,
`+0x2000`, `+0x3000` and `+0x4000`, and both declare `fsl,sec-v4.0`
compatibility, so one driver covers them. They differ only in instance counts
and PKHA version, which affect throughput rather than the programming model:

| | T2080 | T1040 |
|---|---|---|
| Job rings / DECOs | 4 / 4 | 4 / 2 |
| AESA / MDHA units | 4 / 4 | 2 / 2 |
| RNG / PKHA units | 1 / 1 | 1 / 1 |
| PKHA version | 2 | 1 |

Note the device trees for both parts declare `fsl,sec-era = <5>`, but the
`CCBVID` register reports era 6 on both. The driver trusts the register.

#### The "E" suffix matters

QorIQ parts ship in security-enabled and security-disabled orderable
variants. A part without the SEC has no engine to talk to. `wc_SecQoriqInit()`
checks this at run time from the SVR (bit `0x80000`) and returns
`NOT_COMPILED_IN` on a non-E part rather than touching the block. U-Boot
prints the same thing as a trailing `E` on the CPU name, for example
`CPU0: T2080E`.

### What is accelerated

| Algorithm | Status |
|---|---|
| AES-CBC, AES-CTR, AES-ECB (128/192/256) | Supported |
| AES-GCM, including AAD | Supported with a 12 byte IV and a full 16 byte tag; engine checks the tag on decrypt |
| ECDSA sign and verify | Supported on any prime curve wolfCrypt carries, up to 1023 bits |
| ECDH shared secret | Supported on the same curves |
| RSA public and private operations | Supported up to 4096 bit, private key form 1 (d and n) |
| Finite field DH key agreement | Supported on the fixed FFDHE groups, via the same modular exponentiation |
| SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, MD5 | Driver API only, see below |
| RNG4 | Supported, seeds the wolfCrypt DRBG |
| DES/3DES, HMAC, CMAC, XTS, CCM | Not implemented yet |

Everything not implemented returns `CRYPTOCB_UNAVAILABLE`, so wolfCrypt falls
back to software. An unimplemented algorithm is a performance question, never
a correctness one.

#### Public key passes the curve parameters explicitly

The i.MX CAAM parts let a descriptor name one of a handful of built-in curves
with a small index (ECDSEL) instead of carrying the domain parameters, and
wolfSSL's i.MX port uses that. **It does not work on the QorIQ parts tested
here.** Every flag position in bits 25:17 of the protocol block, combined with
every curve index 0 to 31, is refused with DECO error `0x82`. So is the
"message representative is already hashed" flag in the operation's PROTINFO,
which comes back as DECO error `0x81`.

This port therefore supplies the prime, order, base point and curve
coefficients in the descriptor. That costs four extra words and a small
conversion from wolfCrypt's parameter tables, and in exchange it works for
**any prime curve wolfCrypt carries** rather than the five the engine has
built in, Brainpool and the SECP-K1 curves included. The only ceiling is
the PKHA's 1023 bit width.

Two cases fall back to software because the engine cannot express them:

- A key with no public point loaded. wolfCrypt derives one during a software
  verify; the engine has no equivalent, and handing it zeros would produce a
  spurious "bad signature".
- A message representative that reduces to zero. ECDSA is degenerate there
  and the engine refuses it.

Signing draws its per-signature nonce from RNG4 inside the engine, so
`wc_SecQoriqEccSign()` instantiates the RNG if it is not already running.
A descriptor submitted without it fails with CCB error `0x54`, "RNG not
instantiated".

#### RSA and Diffie-Hellman

RSA reaches the callback at `wc_RsaFunction`, which is the raw exponentiation
with padding already applied or not yet stripped, so it maps straight onto the
engine's two RSA protocols. Private key operations use form 1, which takes `d`
and `n` directly; the CRT forms want the prime factors and buy speed this port
does not need to chase yet.

Offloading a private key operation bypasses wolfCrypt's own base blinding.
That blinding exists to protect the *software* modular exponentiation from
timing analysis, and the engine is not the code it defends, but a build that
would rather keep it can leave RSA in software with
`WOLFSSL_SEC_QORIQ_NO_RSA`.

Finite field Diffie-Hellman is the same modular exponentiation, so
`wc_SecQoriqEcdh()`'s finite field counterpart is just `wc_SecQoriqModExp()`
with the group prime as the modulus. Reaching it needed a new callback hook
in wolfCrypt: `WC_PK_TYPE_DH` was in the enum but had no entry in
`wc_CryptoInfo`, no `wc_CryptoCb_Dh()` and no call site in `dh.c`, so no port
could offload DH at all. That hook is part of this work.

Only key agreement is routed, and only over the fixed FFDHE groups. That is
what TLS uses, and it is the whole intended scope: **DH parameter generation
is not supported and will not be**, on the engine or through the callback.
Key generation also stays in software, so the private exponent comes from the
caller's `WC_RNG` rather than from a device.

#### Hashing is not routed through the crypto callback

The driver implements single-shot hashing (`wc_SecQoriqSha256()` and friends)
but does not answer `WC_ALGO_TYPE_HASH`. wolfCrypt calls the device once per
`Update` and again for `Final`, which needs either the streaming descriptor
(class 2 context saved and restored around each call) or `WOLFSSL_HASH_KEEP`
so wolfCrypt accumulates the message and asks once. The hardware supports
streaming; the driver does not implement it yet. Until then hashing through
the normal wolfCrypt API stays in software.

#### RNG feeds the DRBG, it does not replace it

The router answers `WC_ALGO_TYPE_SEED` only. `WC_ALGO_TYPE_RNG` is
deliberately left unhandled so `wc_RNG_GenerateBlock()` keeps running
wolfCrypt's own DRBG, seeded from the SEC through `wc_GenerateSeed()`.
Answering RNG directly would hand callers raw engine output and take
wolfCrypt's DRBG, its reseeding policy and its health checks out of the path.

RNG4 powers up with no DRBG state handle instantiated, and neither U-Boot nor
wolfBoot does it on the boards tested (`RDSTA` reads 0). `wc_SecQoriqRngInit()`
performs the instantiation, retrying with a wider entropy sample if the
statistical checks reject the first attempt.

### Building

    ./configure --host=powerpc-linux-gnu CC=powerpc-linux-gnu-gcc \
                --enable-sec-qoriq=baremetal --enable-aesgcm

`--enable-sec-qoriq` selects the environment backend:

- `baremetal` (default) is a flat, identity mapped address space, which is how
  U-Boot and wolfBoot leave the e5500/e6500. DMA memory comes from a static
  pool. This is the tested path.
- `linux` maps the SEC through `/dev/mem` and resolves DMA addresses with
  `/proc/self/pagemap`. It initialises correctly on a stock kernel, but it
  **does not offload anything yet**; see "The Linux backend on a 36-bit part"
  below before using it.

##### The Linux backend on a 36-bit part

Exercised on a T1040D4RDB running the board's stock Linux 3.12. Three things
have to be right before the engine is even reachable, and one of them is
currently a wall:

1. **Use the operating system's view of CCSR.** These parts have a 36-bit
   physical address space, so under Linux CCSR is at `0xF_FE000000`, not the
   `0xFE000000` that bare metal sees. Set `SEC_QORIQ_CCSRBAR_PHYS` (a 64-bit
   value, separate from `SEC_QORIQ_CCSRBAR`) and build with
   `-D_FILE_OFFSET_BITS=64` so `off_t` can carry the mmap offset. Getting this
   wrong maps ordinary DRAM, and `CONFIG_STRICT_DEVMEM` refuses it with
   "Program ... tried to access /dev/mem between fe0e0000->fe0e1000".
2. **Release the job ring from the kernel.** The in-tree `caam` driver claims
   all four rings at boot. Unbind the one this driver uses:
   `echo ffe301000.jr > /sys/bus/platform/drivers/caam_jr/unbind`.
3. **The 4 GB pointer limit stops the offload.** The driver runs the engine in
   32-bit descriptor pointer mode, so it refuses any buffer whose physical
   address does not fit in 32 bits. On a 4 GB board ordinary user pages sit
   well above that (measured: virtual `0x100b4f10` -> physical
   `0x1_EF9C2F10`), so every job is refused, the callback returns
   `CRYPTOCB_UNAVAILABLE`, and software quietly does the work.
   `wolfcrypt_test` therefore passes in full while offloading nothing, and the
   benchmark's HW and SW rows come out identical (RSA-2048 public 790.6 vs
   788.9 ops/s). Making this useful needs 64-bit descriptor pointer mode
   (`MCFGR[PS]`), or DMA buffers allocated below 4 GB, which userspace cannot
   arrange on its own.

The fallback behaving silently is by design, but it does mean a Linux user has
no signal that nothing is being accelerated. Check the offload counters in
`SecQoriqDev` rather than assuming.

Enabling the port forces `WOLF_CRYPTO_CB` on. A minimal build that wants to
call the driver API directly without the callback layer can define
`WOLFSSL_SEC_QORIQ_NO_CRYPTOCB`.

#### Configuration macros

| Macro | Default | Meaning |
|---|---|---|
| `SEC_QORIQ_CCSRBAR` | `0xFE000000` | Physical base of the CCSR window. Board and boot-loader specific: the CW VPX3-152 U-Boot relocates it to `0xEF000000`. |
| `SEC_QORIQ_CCSRBAR_PHYS` | `SEC_QORIQ_CCSRBAR` | The same window as the OS sees it, as a 64-bit value. Only the Linux backend uses it. On a 36-bit part CCSR is `0xF_FE000000`. |
| `SEC_QORIQ_JR_INDEX` | 0 | Which of the four job rings to claim. |
| `SEC_QORIQ_RING_SIZE` | 4 | Entries per ring. |
| `SEC_QORIQ_MIN_OFFLOAD_SZ` | 256 | Below this many bytes, AES-CBC/CTR/ECB go to software. See the benchmarks. |
| `SEC_QORIQ_DMA_POOL_SZ` | 8192 | Bare-metal static pool backing the job rings. |
| `WOLFSSL_SEC_QORIQ_DEVID` | `0x53454351` | devId used to select the engine. |
| `WOLFSSL_SEC_QORIQ_NO_PKHA` | undefined | Leave ECDSA and ECDH in software even on a part with a PKHA. |
| `WOLFSSL_SEC_QORIQ_SWAP_REGS` | undefined | Reserved. Defining it is currently a compile error: it would swap MMIO access but not descriptor or ring words, so a little-endian host needs that added first. |

### Verification

`wolfcrypt_test()` passes in full with the engine enabled: **28 tests, zero
failures**, on the CW VPX3-152 (T2080E) bare metal under wolfBoot's test-app.
That run pushed **3,407,201 descriptors** through the job ring.

The port also exposes offload counters on `SecQoriqDev` (`jobCount`,
`cbHashCount` / `cbHashOffload`, `cbCipherCount` / `cbCipherOffload`,
`cbPkCount` / `cbPkOffload`, `cbSeedCount`) so a build can prove what actually
reached the engine rather than inferring it from timings. On the run above:
cipher 3,407,450 seen and 3,407,201 offloaded, hash 343,747 seen and **0
offloaded**, which is exactly what the identical SHA software/hardware rows
below should look like.

### Performance

#### wolfCrypt benchmark, software versus engine

`wolfcrypt/benchmark`, `BENCH_EMBEDDED` (1 KB buffers), on the CW VPX3-152
(T2080E, CPU 1200 MHz). wolfCrypt prints the software and hardware rows from
the same run, so these are directly comparable. MiB/s.

| Algorithm | Software | SEC | Speedup |
|---|---:|---:|---:|
| AES-128-CBC-enc | 21.96 | **122.83** | 5.6x |
| AES-128-CTR | 22.08 | **119.06** | 5.4x |
| AES-128-GCM-enc | 8.07 | **107.42** | 13.3x |
| AES-256-GCM-enc | 6.94 | **102.50** | 14.8x |
| AES-128-GCM-enc-no_AAD | 8.19 | **118.99** | 14.5x |
| AES-256-GCM-enc-no_AAD | 7.19 | **107.20** | 14.9x |
| SHA-256 | 36.83 | 36.31 | not offloaded |
| SHA-384 | 20.25 | 20.09 | not offloaded |

Public key, same run, in operations per second:

| Operation | Software | SEC | Speedup |
|---|---:|---:|---:|
| ECDSA P-256 verify | 49.39 | **591.98** | **12.0x** |
| ECDSA P-256 sign | 89.53 | **785.66** | **8.8x** |
| ECDHE P-256 agree | 100.18 | **803.40** | **8.0x** |

Verify gains the most, which is the right way round: it is the operation a
TLS client performs on every handshake and the slowest of the three in
software. At 1.69 ms against 20.2 ms, certificate chain validation stops being
the dominant cost of a connection on this silicon.

AES-GCM is the standout at 13-15x, and it is also the TLS 1.3 record cipher.
Software GHASH on this core has no carryless-multiply support and runs at a
flat 7-8 MiB/s no matter the key size, so the engine wins by a wide margin.
The SHA rows are unchanged because hashing is deliberately not routed; see
above.

These numbers were taken with `NO_ASM=1`. The PPC assembly cannot be enabled
in the same run because wolfSSL's PPC asm SHA-512/384 currently fails the
large streaming-input case in `wolfcrypt_test()` (`test.c:7069`), a
pre-existing issue unrelated to this port.

#### Size sweep from the bring-up harness

A separate bare-metal harness measured the same operations across buffer
sizes to find where offloading starts to pay. Both sides ran in the same
binary over the same buffers, timed with the e6500 timebase, in KB/s.
`SEC/SW` above 1.00 means the engine wins.

Software here is the configuration wolfBoot ships on this board: PPC32
assembly for SHA, plain C for AES.

| Algorithm | Size | SEC | Software | SEC/SW |
|---|---:|---:|---:|---:|
| SHA-256 | 64 | 17568 | 20782 | 0.84x |
| SHA-256 | 256 | 63891 | 36286 | 1.76x |
| SHA-256 | 1400 | 218644 | 45021 | 4.85x |
| SHA-256 | 16384 | 440574 | 48021 | 9.17x |
| SHA-384 | 64 | 17459 | 7288 | 2.39x |
| SHA-384 | 256 | 58757 | 13123 | 4.47x |
| SHA-384 | 1400 | 194183 | 22217 | 8.74x |
| SHA-384 | 16384 | 368240 | 26954 | 13.66x |
| AES-128-CBC | 64 | 13720 | 22389 | 0.61x |
| AES-128-CBC | 256 | 49356 | 35612 | 1.38x |
| AES-128-CBC | 1392 | 165630 | 42376 | 3.90x |
| AES-128-CBC | 16384 | 322236 | 44089 | 7.30x |
| AES-128-GCM | 64 | 13269 | 5760 | 2.30x |
| AES-128-GCM | 256 | 47029 | 7528 | 6.24x |
| AES-128-GCM | 1400 | 161533 | 8169 | 19.77x |
| AES-128-GCM | 16384 | 320900 | 8335 | 38.50x |

There is a fixed per-job cost of roughly 3.5 microseconds: descriptor
construction, two cache flushes, the ring write, the MMIO kick and the
completion poll. That is why every SEC row at 64 bytes lands near 13-17.5
MB/s regardless of algorithm. Above about 1 KB it amortises away and the
engine reaches 320-440 MB/s.

Consequences worth knowing:

- **AES-GCM wins at every size**, including 64 bytes, because software GHASH
  on this core has no carryless-multiply support and runs at a flat 8 MB/s.
  This is also the TLS 1.3 record cipher, so it is the case that matters most.
- **SHA-384 wins at every size**, because the 64-bit SHA-512 core is expensive
  in 32-bit software.
- **SHA-256 and AES-CBC lose below roughly 128 bytes.** Both have fast
  software paths here. `SEC_QORIQ_MIN_OFFLOAD_SZ` keeps small AES buffers in
  software for this reason.

The driver currently uses one job ring, submits one descriptor at a time and
busy-waits for completion. The T2080 has four rings and four DECOs, so
batching or overlapping submissions would cut the effective per-job cost and
move the crossover down toward small-record sizes.

### Limitations

- Buffers must be physically contiguous. There is no scatter-gather support,
  so fragmented TLS records need to be linearised by the caller. The Linux
  backend verifies contiguity page by page and refuses a buffer that
  straddles non-adjacent frames rather than DMAing past the first one.
- A single command carries at most 64 KB. Hashing chains multiple FIFO loads
  to cover longer messages; AES does not, so the callback declines larger AES
  buffers and lets software take them.
- AES-GCM accepts only a 12 byte IV. The AESA derives J0 = IV || 0^31 || 1,
  which is the SP 800-38D construction for that length only; other lengths
  need J0 = GHASH(IV || pad || len(IV)), which the engine does not do.
- AES-GCM accepts only a full 16 byte tag. The engine performs the ICV
  comparison itself on decrypt and rejects a truncated tag, so shorter tags
  go to software. TLS always uses 16.
- Public key covers ECDSA and ECDH only. RSA and finite-field DH modular
  exponentiation are not wired up yet, and key generation stays in software so
  that the caller's `WC_RNG` remains the source of the private key.
- The domain parameters are converted from wolfCrypt's tables on every public
  key call. It is a few hundred bytes of byte-string work against a
  millisecond of engine time, so it does not show up in the measurements
  above, but caching them per curve is the obvious next saving.
- ECDSA sign uses the engine's internal per-signature nonce rather than the
  `WC_RNG` the caller passed, because the protocol descriptor generates it in
  hardware. Deterministic ECDSA (RFC 6979) therefore cannot be offloaded and
  falls back to software.
- A digest wider than the curve order is reduced to the leftmost order bits,
  as ECDSA prescribes, so SHA-384 or SHA-512 over P-256 offloads normally.
  The one shape declined is a curve whose order does not fill the fixed width
  block, because wolfCrypt finishes such a truncation with a sub-byte shift
  that this layout cannot express, and copying whole bytes instead would
  build a signature its own verifier rejects. No curve in common use is
  affected: P-256 and P-384 have byte aligned orders, and P-521 never
  truncates, no digest wolfCrypt carries being wider than its 521 bit order.
- The port is stack hungry on the public key paths, roughly 900 bytes on top
  of what wolfCrypt's own ECC frames need (a `MAX_ECC_BYTES * 9` domain
  parameter block plus a `MAX_ECC_BYTES * 4` scratch in the router). Bare
  metal targets should budget for it or build with `WOLFSSL_SMALL_STACK`,
  which moves both to the heap.
- 32-bit descriptor pointers only. All DMA buffers must live below 4 GB.
  `wc_SecQoriqInit()` refuses to run if the engine is already in 64-bit
  pointer mode, and buffer translation fails rather than truncating.
- AES-CBC/CTR/ECB require whole 16-byte blocks. Partial-block CTR, where
  wolfCrypt keeps leftover keystream, falls back to software.
- One job ring, polled, serialised on the wolfSSL hardware mutex. No
  interrupt support and no concurrent submission.
- Output buffers should not share a cache line with data another thread
  writes while a job is in flight. The driver flushes before submitting and
  invalidates afterwards, which is safe for its own accesses, but a
  concurrent writer to an adjacent object in the same line can still lose an
  update on a non-coherent path.
- There is no in-tree test for the port yet. It was validated with an
  external bare-metal known-answer harness covering hashing, AES CBC/CTR/ECB,
  GCM including a corrupted-tag rejection, RNG4, and ECDSA/ECDH cross-checked
  against the software implementation.

## Support

For questions please email support@wolfssl.com
