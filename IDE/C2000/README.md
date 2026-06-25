# TI C2000 C28x (CHAR_BIT == 16) support

wolfCrypt builds and runs on the TI C2000 C28x DSP family, a word-addressed
architecture where `CHAR_BIT == 16` (a C `char`/`unsigned char` is 16 bits and
is the smallest addressable unit). Support is gated behind `WOLFSSL_WIDE_BYTE`,
which `wolfssl/wolfcrypt/types.h` auto-enables when `CHAR_BIT != 8` or a known
16-bit-char TI toolchain macro is seen (`__TMS320C28XX__`, `__TMS320C2000__`,
etc.). On normal 8-bit-byte targets none of this code changes behavior.

## Validated on hardware (LAUNCHXL-F28P55X, TMS320F28P550SJ, cl2000)

- SHA-1; SHA-224/256, SHA-384/512, SHA-512/224, SHA-512/256
- SHA3-224/256/384/512, SHAKE128/256 (split-64 Keccak permutation auto-enabled
  for `WOLFSSL_WIDE_BYTE`, ~53% faster than the generic C path)
- ML-DSA-44/65/87 (Dilithium) verify and full keygen/sign/verify;
  ML-KEM-512/768/1024 (FIPS 203)
- AES-128/192/256 CBC/CTR/CFB/OFB/GCM/XTS; AES-CMAC, AES-CCM, AES-GMAC,
  AES-SIV, AES-EAX
- HMAC + HKDF; ChaCha20-Poly1305; Poly1305
- X25519 + Ed25519; X448 + Ed448 (CURVE448_SMALL/ED448_SMALL byte backend)
- ECDSA + ECDH (SECP256R1, SP math)
- RSA-2048 PKCS#1 v1.5 sign and verify; DH FFDHE-2048 (SP math)

The on-target acceptance gate is the per-algorithm KAT set the reference example
prints over JTAG (e.g. `ML-DSA-87 verify KAT: PASS`, `X448 a*Bpub: PASS`); the
split-64 Keccak path is additionally validated on a host build with
`-DWC_SHA3_SPLIT64` forced, and the compile-only CI below guards every
`WOLFSSL_WIDE_BYTE` source against build breakage.

## What `WOLFSSL_WIDE_BYTE` fixes

The `CHAR_BIT != 8` work falls into a few recurring classes, each a no-op on
8-bit targets:

- Byte/word aliasing. Serializing a `word32`/`word64` via a `byte*` cast moves
  cells, not octets. Replaced with shift-based octet I/O. Shared helpers live in
  `wolfcrypt/src/misc.c`: `WordsFromBytesBE32`/`BytesFromWordsBE32`,
  `BytesFromWordsLE32`, the 64-bit variants, and octet-correct
  `readUnalignedWord32`/`readUnalignedWord64`. `sp_int.c sp_read_unsigned_bin`
  uses the endian-/`CHAR_BIT`-agnostic shift loop for its leftover bytes.
- `(byte)x` not truncating to an octet (it keeps 16 bits). Masked with
  `WC_OCTET(x)` = `(byte)((x) & 0xFF)` (types.h). Used across the ML-KEM/ML-DSA
  encoders, the SP `*_to_bin` serializers, AES `GETBYTE`, base64, and DRBG.
- Integer-promotion bugs. `1U << n` is 16-bit on C28x (use `1UL`); a bit width
  written `sizeof(t) * 8` is wrong when `CHAR_BIT != 8` (use `CHAR_BIT *
  sizeof(t)`); a `byte` operand promotes to a 16-bit `int`.
- `sizeof` counting cells, not octets. e.g. `CHACHA_CHUNK_BYTES` is `16 * 4`,
  not `16 * sizeof(word32)` (= 32 on C28x, which halves the ChaCha block).

The SP backend file `wolfcrypt/src/sp_c32.c` is generated; the `& 0xFF` octet
masks added to its `sp_*_to_bin_*` serializers are also applied in the SP
generator templates so a regeneration preserves them (tracked separately).

## Enabling on your build

Define a user-settings header (see `IDE/C2000/user_settings.h` for a
minimal CHAR_BIT!=8 config) and build with `WOLFSSL_USER_SETTINGS`. For the SP
math backend on a 16-bit-int target also set `WOLFSSL_SP_MATH`,
`SP_WORD_SIZE 32`, and `WOLFSSL_SP_ALLOW_16BIT_CPU`.

## Reference example

A complete bare-metal example with KATs, benchmark, linker scripts, and per-
algorithm build toggles is in wolfSSL Examples:
`embedded/ti-c2000-f28p55x/` (see its `README.md` for the `make` options:
`ECC`, `MLKEM`, `AES`, `AESEXTRA`, `X25519`, `HKDF`, `CHACHA`, `RSA`, `SIGN`,
`BENCH`).

Representative throughput on the F28P55X at 150 MHz: SHA-256 ~284 KiB/s; SHA3-256
~264 KiB/s; SHAKE128 ~319 KiB/s; RNG Hash-DRBG ~122 KiB/s. ML-DSA-87 verify
~225 ms/op in ~10.7 KB RAM (zero heap, with `WOLFSSL_MLDSA_VERIFY_SMALLEST_MEM`
+ `WOLFSSL_MLDSA_ASSIGN_KEY`).

## Continuous integration

`IDE/C2000/compile.sh` runs `cl2000 --compile_only` over the
`CHAR_BIT != 8` wolfCrypt subset to guard these paths without hardware;
`.github/workflows/ti-c2000-compile.yml` runs it in CI. TI gates the C2000
code generation tools behind a login, so the workflow fetches the installer
from the `TI_C2000_CGT_URL` repo/org variable (mirror it to a wolfSSL release
asset or internal server; optionally pin `TI_C2000_CGT_SHA256`). When that
variable is unset the job is skipped with a notice rather than failing.
