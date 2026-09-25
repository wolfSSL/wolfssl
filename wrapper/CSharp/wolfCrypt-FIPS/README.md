# wolfCrypt FIPS C# wrapper

A .NET wrapper for the wolfCrypt FIPS 140-3 module, targeting .NET 10
(LTS, supported through November 2028) and .NET 8 (LTS, supported through
November 10, 2026). It binds only
the module's approved-service entry points (the `*_fips` functions of the
v5.2.3 boundary) and contains no cryptographic code of its own.

Tested against wolfCrypt FIPS v5.2.1 (certificate #4718) and v5.2.3.

Supported on Linux and macOS. The loader and size helper contain Windows
code paths, but there is no Windows build of the fingerprinted size helper
yet (`build-native.sh` is POSIX only), so the wrapper refuses to start on
Windows.

## Why a separate wrapper

In C, `fips.h` renames each API to its `_fips` wrapper
(`#define wc_ecc_sign_hash wc_ecc_sign_hash_fips`). The `_fips` wrapper is
where the module checks its status and self-test (CAST) state before running
the algorithm. A C# `DllImport` resolves names at runtime and never sees
that header, and a FIPS build exports both names, so binding the plain name
calls the implementation directly and bypasses the FIPS service layer. This
wrapper binds every entry point by its `_fips` name
(`EntryPoint = "..._fips"`), and `tools/fips-bind-audit.sh` enforces it.

## Contents

| File | Purpose |
|---|---|
| `Native.cs` | All P/Invoke declarations (the only file that binds native code) |
| `FipsHandle.cs`, `FipsObject.cs` | SafeHandle ownership of each native structure |
| `FipsModule.cs` | Status, mode, version, integrity test, CASTs, failure callback, seed source, private key read gate |
| `FipsRng.cs` | Hash_DRBG (SP 800-90A) |
| `FipsHash.cs`, `FipsHmac.cs`, `FipsCmac.cs` | SHA-1/2/3, HMAC, CMAC-AES |
| `FipsAes.cs`, `FipsAesGcm.cs` | AES ECB/CBC/CTR/OFB, GCM, GMAC, CCM |
| `FipsRsa.cs` | RSA key generation, PKCS#1 v1.5 and PSS signatures, RSA primitives with OAEP padding |
| `FipsEcc.cs`, `FipsDh.cs` | ECDSA, ECC CDH, finite field DH (RFC 7919 ffdhe2048) |
| `FipsKdf.cs` | TLS 1.2 KDF (EMS), TLS 1.3 KDF, SSH KDF |
| `native/fips_sizes.c` | Structure size helper (see below) |
| `tools/fips-bind-audit.sh` | Binding audit |
| `build-native.sh`, `run-tests.sh` | Build the helper; build and run the test suite |

### Native object lifetime

Each native structure is owned by a `SafeHandle` (`FipsHandle`) and passed to
the module as that type, so the marshaller keeps it alive for the whole call:
a finalizer or a `Dispose` on another thread cannot free it while the module
is using it. Releasing the handle runs the module's free routine, then zeroes
and frees the structure's memory.

Once the module is in the FAILED state, or the algorithm's CAST has failed,
it refuses `wc_FreeRng_fips`, `wc_FreeRsaKey_fips`, `wc_ecc_free_fips` and
`wc_FreeDhKey_fips`. Memory the module allocated behind the structure (for
example the Hash_DRBG working state of a `WC_RNG`) is then neither zeroized
nor freed, and the boundary offers no other way to reach it. The wrapper
still zeroes the structure itself and counts each refusal in
`FipsModule.RefusedFreeCount`.

`Dispose` (or `using`) is the zeroization procedure for keys and DRBG state
held in native memory. An object that is not disposed is zeroized only when
its finalizer runs, at a time the GC chooses, and .NET does not run
finalizers at process exit.

`FipsRng`, `FipsAes`, `FipsAesGcm`, `FipsAesCcm` and `FipsRsaKey` serialize
calls on one object, so a DRBG or cipher stream cannot be used by two threads
at once (which would repeat output or keystream), and two RSA operations never
share the module's per-key working buffer. Other objects are not thread-safe;
use one per thread or lock. A generated
`FipsEccKey` owns a private DRBG (bound to the native key for signing and CDH
blinding), so the `FipsRng` passed to `Generate` may be disposed afterwards.
`FipsRsaKey` needs no DRBG after generation: FIPS builds `#undef
WC_RSA_BLINDING` (settings.h), so `RsaKey` has no `rng` member, OAEP
decryption uses none, and the module does not keep the generation DRBG.
Signing takes its `FipsRng` explicitly.

### Size helper

The in-boundary initializers (`wc_InitRng_fips`, `wc_InitRsaKey_fips`, ...)
work on caller-allocated structures whose size depends on the library's
configure options. `native/fips_sizes.c` is compiled against the installed
`wolfssl/options.h` and reports those sizes. It contains no cryptography,
does not link libwolfssl, and is outside the module boundary.

The helper is bound to one exact libwolfssl binary: `build-native.sh` embeds
the POSIX `cksum` (CRC and size) of the installed library, and before the
first native structure is allocated the wrapper computes the same checksum of
the libwolfssl file it actually loaded and refuses to run on a mismatch. The
helper is always loaded from the directory libwolfssl was loaded from.
**Rebuild the helper (`build-native.sh`) after every reinstall of the
library.** The check runs on first use whether or not `Initialize` is called.

## Build and test

```sh
# wolfSSL FIPS library, per the OE User Guide, installed to <prefix>
./configure --enable-fips=v5 --prefix=<prefix>
make && ./fips-hash.sh && make && make install

# size helper + binding audit + test suite
wrapper/CSharp/wolfCrypt-FIPS/run-tests.sh <prefix>
```

`run-tests.sh` builds `libwolfssl_csharp_fips` into `<prefix>/lib`, runs the
binding audit, and builds and runs `wolfCrypt-FIPS-Test` for one target
framework (default `net10.0`). Each build runs only on its matching runtime;
there is no roll-forward, so a `net8.0` run needs a .NET 8 runtime. Building
either target needs the .NET 10 SDK (restore evaluates both target
frameworks). .NET 8 support ends November 10, 2026.

Environment:

| Variable | Effect |
|---|---|
| `WOLFSSL_FIPS_LIB_DIR` | Directory holding libwolfssl and the size helper (otherwise the normal search path, e.g. `/usr/local/lib`). When set, both must load from it; there is no fallback |
| `DOTNET_TFM` | Target framework to test: `net10.0` (default) or `net8.0` |
| `DOTNET_ROOT` | .NET install holding the runtime for `DOTNET_TFM`, if it is not the default install |
| `WOLFACVP_VECTORS` | Path to `fips/wolfACVP` of a FIPS bundle; enables the ACVP known-answer tests (they report SKIP otherwise) |

Forced-failure tests run automatically when the library exports
`wolfCrypt_SetStatus_fips` (an operational-test build, `HAVE_FORCE_FIPS_FAILURE`).

## Startup

```csharp
using wolfSSL.CSharp.Fips;

FipsModule.Initialize(onFailure: (ok, err, hash) =>
    Console.Error.WriteLine($"FIPS module error {FipsError.Name(err)}"));
```

`Initialize` loads the library (which runs the power-on self-tests and the
in-core integrity check in the library constructor), registers the failure
callback, registers the DRBG seed source, and throws unless the module is in
`FipsMode.Normal`. Call it once at startup, before any other use.

The wrapper requires a library built with `WC_RNG_SEED_CB` (the default for
`--enable-fips=v5`; not set with `--enable-kcapi-ecc` or in `user_settings.h`
builds that omit it): `wc_SetSeed_Cb_fips` exists only then, and `Initialize`,
`UseOsSeed` and `SetSeedCallback` fail with `EntryPointNotFoundException`
without it.

The module has no entropy source of its own. In `WC_RNG_SEED_CB` builds,
nothing that needs the DRBG works until a seed source is registered,
including the ECC self-tests. `Initialize` registers the library's OS source
(`wc_GenerateSeed`, `/dev/urandom` on Linux) by passing its native function
pointer to `wc_SetSeed_Cb_fips`. `FipsModule.SetSeedCallback` registers a
custom source instead (for example a hardware TRNG). A custom source is
kept: `Initialize` does not replace it, whether it is called before or
after `SetSeedCallback` or more than once. Only an explicit
`FipsModule.UseOsSeed()` switches back to the OS source.

A custom seed source is outside the module boundary and must:
- supply full-entropy bytes (the module credits 8 bits per byte and asks for
  196 bytes, or 132 with a caller nonce, at each instantiation);
- run its own SP 800-90B health tests and return non-zero on failure (the
  module only rejects repeated 4-byte words);
- write directly into the `seed` pointer, or zero any staging buffer.

Certificate #4718 carries the caveat that there is no assurance of the
minimum strength of generated keys; an ESV-validated entropy source is needed
to remove it. The module's automatic reseed (after 1,000,000 requests) draws
from `wc_GenerateSeed`, not from the callback (module behavior): the callback
covers instantiation only. An application that needs every seed from its own
source must dispose and recreate a `FipsRng` before 1,000,000 requests.

`FipsRng` refuses to serve any service once the module's DRBG CAST has failed
(`DRBG_KAT_FIPS_E`), including services the module itself would still run
from an instance created before the failure. A caller nonce for
`new FipsRng(nonce)` must be at least 16 bytes (SP 800-90A 8.6.7).

`Initialize` also runs the size helper check described above (exact binary
and FIPS major.minor), so a mismatch fails at startup.

Callbacks (`SetFailureCallback`, `SetSeedCallback`) are called from inside the
module. Every delegate registered stays alive for the life of the process,
and exceptions thrown by a callback are caught: a failing seed callback is
reported to the module as a seed failure instead of terminating the process.

`FipsModule.CoreHash` is the computed in-core hash. The module keeps it only
when the integrity check fails, so it is empty on an operational module.

## Private key read gate

The module gates services that output secret values behind
`wolfCrypt_SetPrivateKeyReadEnable_fips`: RSA key export, ECC public key
export, ECC and DH shared secrets, DH key pair generation and every KDF. The
gate is per thread (thread-local storage in the module).

The Security Policy requires the application to unlock the gate when working
with private key material and to lock it when done. The wrapper does this for
each call whose purpose is to return such a value (`SharedSecret`, `Agree`,
`GenerateKeyPair`, `FipsEccKey.ExportPublic`, the KDFs): it enables the
gate on the
current thread for that one synchronous call and restores the previous state
in a `finally`. This mirrors wolfSSL's own `PRIVATE_KEY_UNLOCK()` /
`PRIVATE_KEY_LOCK()` use.

The RSA public key is captured once, when `FipsRsaKey.Generate` creates the
key, through a gated full export (the module has no public-only export)
whose private components are zeroed immediately. `FipsRsaKey.ExportPublic`
returns copies of that cached n and e and does not call the module or open
the gate.
`FipsRsaKey.Export` (full private key export) does not open the gate.
`SetPrivateKeyReadEnable(true/false)` is an on/off switch: the module keeps a
nesting counter, and `false` closes the gate however many times it was
opened. Call
`FipsModule.SetPrivateKeyReadEnable(true)` on the same thread first, and do
not `await` between the two calls.

## IVs and nonces

- AES-GCM and GMAC encryption use IVs of 12 or 16 bytes generated entirely
  by the module DRBG (IG C.H Scenario 2). `UseInternalIV` is called once per
  `FipsAesGcm` object. These are RBG-based IVs (SP 800-38D 8.2.2), so at most
  2^32 encryptions are allowed per key (8.3): each object refuses the
  2^32nd + 1, and across objects and `FipsGmac.Compute` calls with the same
  key the application must stay within 2^32 in total. Encryption with a
  caller-supplied IV is not public: the module Security Policy allows external
  IVs only for TLS (IG C.H 1(a)).
- `FipsAesGcm` decrypts on a second native context, so decryption (even of a
  forged ciphertext with a chosen IV) never changes the encryption IV state.
- AES-GCM decryption and GMAC verification take the expected tag size
  (12 to 16 bytes, default 16) and require the received tag to have exactly
  that length. The module accepts tags from 1 byte on these paths, so a
  truncated tag would otherwise reduce forgery resistance. GMAC `Verify`
  returns false only for a tag mismatch and throws for anything else (bad
  key or IV length, module state).
- AES-GCM encryption and GMAC generation use 12 to 16-byte tags, the same
  range decryption and verification accept.
- AES-CCM decryption also takes the expected tag size (default 16) and
  refuses a tag of any other length. The boundary has no HMAC or CMAC verify
  service: recompute with `Compute` and compare with
  `CryptographicOperations.FixedTimeEquals`, with one fixed tag length per
  key.
- AES-CCM: call `SetNonce` once per object (a second call is refused, since
  it would restart the nonce sequence under the same key); the module
  advances the nonce per encryption. `SetNonce(rng)` draws the initial nonce
  (12 or 13 bytes) from the module DRBG and is the default choice; with
  `SetNonce(nonce)` the caller must keep nonces unique under the key across
  all objects (SP 800-38C 5.3).
  The payload must be shorter than 2^(8 x (15 - nonce length)) bytes (for a
  13-byte nonce, under 65,536 bytes); the v5.2.x module does not check this
  and longer input would wrap the counter.
- AES-CBC, OFB and CTR encryption: `CreateCbc(key, rng)`, `CreateOfb(key,
  rng)` and `CreateCtr(key, rng)` draw a fresh IV / initial counter from the
  module DRBG (read it from `IV`). Use one encryptor per message: after a
  message the chaining state is predictable.
- CBC with a caller IV is decrypt-only (`CreateCbcDecryptor`); `SetIV` is for
  CBC decryptors only. OFB and CTR encrypt and decrypt with the same
  operation, so `CreateOfb(key, iv, ...)` and `CreateCtr(key, iv)` can
  encrypt: the caller must then keep the OFB IV, and every CTR counter block,
  unique under the key (SP 800-38A App. B). The CTR counter is the whole
  16-byte block.
- ECB is a building block (single blocks, testing), not a mode for general
  data; the planned SP 800-38A revision is expected to limit its approval.
- CMAC: use one tag length per key (SP 800-38B 5.5) and at most 2^48 messages
  per key (Appendix B).

## Secret values outside the module

Values the module outputs are the application's to protect: DH private
keys, ECDH and DH shared secrets, KDF output, decrypted plaintext and
exported RSA key components are returned as `byte[]`. `FipsDhKeyPair` and
`FipsRsaKeyComponents` zero their private parts on `Dispose`; zero other
buffers with `CryptographicOperations.ZeroMemory` when done. The managed
heap can move arrays, so copies may remain until the memory is reused.

## Errors

Failures throw `WolfCryptFipsException`; `Code` holds the module's return
value (see `FipsError`). Verification APIs return `false` for an invalid
signature, tag or key, and throw when the error reports the module's state
(`FipsError.IsModuleStateError`), so a failed or degraded module is never
reported as an invalid signature.

## Scope

Only services in the v5.2.3 boundary are wrapped.

| Not provided | Reason |
|---|---|
| RSA key import (DER or raw) | Decoders are outside the boundary (`asn.c`); RSA keys come from `FipsRsaKey.Generate` |
| RSAES-PKCS1-v1_5 encryption | Disallowed for key transport after 2023 (SP 800-131A Rev. 2 Table 5); OAEP only |
| RSA key transport (SP 800-56B KTS) | The Security Policy makes no key transport claim (RSAEP/RSADP primitives only); `Encrypt`/`Decrypt` are the RSA primitives with OAEP padding on the object's own key |
| RSA PKCS#1 v1.5 signing with SHA-1 or SHA-3 | SHA-1 signing is disallowed (SP 800-131A); RSA SigGen is validated with SHA-2 only |
| PKCS#1 v1.5 DigestInfo encoding and signature comparison | Done by the caller, outside the module (`wc_EncodeSignature` is in asn.c, not in the boundary), as in the module's CAVP testing. `SignPkcs1v15(digestInfo, rng)` signs a caller-built DigestInfo; `RecoverPkcs1v15(signature)` returns the recovered block, which the caller compares with `CryptographicOperations.FixedTimeEquals` |
| General HKDF (RFC 5869 / SP 800-56C) | Not a validated service (HKDF appears only inside the TLS v1.3 KDF CVL); internal for testing |
| Explicit FIPS 186-type DH domains | KAS-FFC-SSC is validated for a safe-prime group only; the RFC 5114 constructor is internal |
| HMAC/CMAC verify, ECDSA r/s (DER, P1363) conversion, ECC import from separate X and Y | Not services of the boundary; the wrapper exposes only `_fips` functionality |
| `WOLF_CRYPTO_CB` builds | The boundary has no `wc_AesInit_fips` / `wc_HmacInit_fips` and `wc_InitCmac_ex` leaves `devId` 0, so Aes, Hmac and Cmac operations are offered to crypto callback device 0; do not register a device 0 |
| DH groups ffdhe3072 to ffdhe8192 | The #4718 Security Policy lists KAS-FFC-SSC with ffdhe2048 only; the module implements the others, but they are internal (ACVP testing only) |
| ECC CDH on P-192 and P-224 | KAS-ECC-SSC is validated on P-256, P-384 and P-521 |
| GCM encryption with a caller IV | External IVs are allowed only for TLS in the Security Policy |
| ECC private key import | Not in the boundary; ECC public key import (X9.63) is provided |
| DSA, Ed25519, Curve25519, ML-KEM, ML-DSA, ECIES, HPKE | Not approved services of the v5.2.3 module |
| MGF1 with SHA-3 (PSS, OAEP) | Not supported by the module |
| PSS salt discovery (`saltLen` -2) | Accepts any salt length |

## Checks enforced by the wrapper

The module accepts some inputs that are not permitted or not safe. The
wrapper rejects them before calling the module:

| Check | Module behavior |
|---|---|
| RSA key generation limited to 2048, 3072, 4096 bits | v5.2.1 and v5.2.3 also generate 1024-bit keys (bug 6367, `RsaSizeCheck`) |
| RSA public exponent odd and greater than 2^16 (FIPS 186-5 5.4(e)) | Module accepts any odd e >= 3 |
| `SignPkcs1v15` accepts only the exact DER DigestInfo of a SHA-224/256/384/512 digest (right OID, NULL parameters, digest length) | The module pads and signs any byte string, which would not be a FIPS 186-5 signature |
| No SHA-1 for RSA or ECDSA signature generation (SP 800-131A Table 8; Security Policy rule 3b) | Module signs SHA-1 digests; SHA-1 verification stays available for legacy signatures |
| `FipsEccKey.SignHash` and `VerifyHash` take the hash type and check the digest length | ECDSA signs any digest, and verification has no digest length bound, so a very short digest makes signatures forgeable (CVE-2026-5194 class) |
| ECC public keys are fully validated on import (by the module with `WOLFSSL_VALIDATE_ECC_IMPORT`, reported by the size helper, else by an explicit `wc_ecc_check_key_fips`) | The CDH path does not check that the peer point is on the curve |
| GCM: at most 2^32 encryptions per object (SP 800-38D 8.3); `UseInternalIV` once per object; decryption on a separate context | The module gives 12-byte RBG IVs a 2^64 counter |
| DH public keys left-padded to len(p); `GeneratePublic` checks x in [1, q-1] first | The module returns minimal-length keys and does not range-check x in `wc_DhGeneratePublic` |
| HMAC keys at most 128 bytes (validated range 112 to 1024 bits) | The module accepts any key length |
| TLS 1.2 EMS session hash must be a digest of the PRF hash; TLS 1.3 Expand-Label uses the "tls13 " prefix only, with a non-empty label | The module derives from any input |
| GCM and GMAC internal IVs of 12 or 16 bytes, with at least 12 DRBG-generated bytes after any fixed field (IG C.H Scenario 2, SP 800-38D 8.2.2) | Module also accepts 8-byte (64-bit) internal IVs and fills only the bytes after the fixed field from the DRBG |
| GCM, GMAC, CCM and CMAC verification require a tag of exactly the expected length | The module takes the tag length from the received tag |
| RSA-PSS salt length -1 (digest length) or 0 to hLen for signing and verification (FIPS 186-5 5.4(g)) | Builds with RSA-PSS define `WOLFSSL_PSS_LONG_SALT`, which removes the module's sLen <= hLen check |
| TLS 1.2 PRF refuses the non-EMS `"master secret"` derivation (FIPS 140-3 IG D.Q), checked on label \|\| seed since the module hashes them as one string (so splitting the label does not get around it); use `Tls12ExtendedMasterSecret` and `Tls12KeyBlock`. Raw P_hash is not public | The module derives any label |
| KDF labels and the TLS 1.3 protocol prefix must be ASCII | `Encoding.ASCII` would map other characters to `?`, so distinct labels would derive the same keys |
| CMAC and CCM tags of at least 64 bits (SP 800-38B A.2, SP 800-38C App. B) | Module accepts 32-bit tags |
| Internal explicit DH domains limited to the RFC 5114 2048-bit groups (2.2: 2048/224, 2.3: 2048/256), compared byte for byte | Module accepts any prime size and checks only that p is prime (not q, q dividing p-1, or g) |
| AES ECB and CBC input must be a multiple of 16 bytes | Without `WOLFSSL_AES_CBC_LENGTH_CHECKS` the module processes only whole blocks, returns success and leaves the tail of the output unencrypted |
| P-192 limited to public key import and verification | FIPS 186-5 disallows P-192 key generation and signing |
| CCM payload shorter than 2^(8 x (15 - nonce length)) | Module wraps the counter (keystream reuse) for longer input |
| DH peer keys checked with `wc_DhCheckPubKeyEx` before agreement (with q for the internal explicit domains, so y^q = 1 runs there) | `wc_DhAgree` only range-checks the peer key; for ffdhe2048 the module check is the range check (partial validation, allowed for ephemeral keys of a safe-prime group, SP 800-56A 5.6.2.2.2) |
| An empty HKDF salt is passed as NULL | The module uses HashLen zeros for NULL but rejects a zero-length non-NULL salt as a 0-byte HMAC key |
| An empty TLS 1.3 IKM is passed as HashLen zero bytes | For ikmLen 0 the module writes HashLen bytes into the IKM buffer |
| TLS 1.3 HkdfLabel within the module's `MAX_TLS13_HKDF_LABEL_SZ` (read from the library) and 255-byte fields | The module copies protocol, label and context into a fixed stack buffer without a capacity check |
| TLS 1.3 KDFs limited to SHA-256 and SHA-384 | SHA-512 is accepted only with `WOLFSSL_TLS13_SHA512` |
| SSH KDF refuses K with leading zero bytes, or zero (strip them before calling) | The module adds the mpint sign byte but keeps redundant leading zeros (RFC 4251 5) |
| RSA public exponent passed as the platform's C `long` (`CLong`) | The parameter is 32 bits on Windows and 32-bit platforms |
| `FipsModule.RunCast` and `GetCastState` refuse CAST ids outside 0 to `CastCount` - 1 | `wc_RunCast_fips` writes the CAST state array before checking the id |
| `FipsModule.IntegrityTest` returns the module status after the re-run | `wolfCrypt_IntegrityTest_fips` always returns 0; a failure shows only in the status |
| RSA key generation retried (up to 3 attempts) on `PRIME_GEN_E` | FIPS 186 prime generation reports failure after a bounded number of candidates; retrying with fresh randomness is permitted |

Other module rules the wrapper passes through:

- HMAC keys must be at least 14 bytes (112 bits); shorter values fail with
  `HMAC_MIN_KEYLEN_E`.
- The TLS v1.2 KDF, TLS v1.3 KDF and KDF SSH are CVLs: they shall only be
  used within the TLS 1.2, TLS 1.3 and SSHv2 protocols (IG 2.4.B). They are
  not general-purpose KDFs.
- The TLS 1.2 PRF takes TLS MAC algorithm ids (`sha256_mac` = 4) while HKDF,
  TLS 1.3 and SSH take `wc_HashType` (SHA-256 = 6). `FipsHashType` holds the
  v5 `wc_HashType` values and the wrapper maps them for the PRF. Note that
  `types.h` contains two `wc_HashType` enums; FIPS v5 uses the second.

## Tests

`wolfCrypt-FIPS-Test` is a dependency-free console runner (no NuGet access
needed on target devices).

- Embedded known answers that always run (no vectors needed): SHA-1/2/3
  "abc" digests, RFC 4231 HMAC, SP 800-38A AES ECB/CBC/OFB/CTR in both
  directions, RFC 4493 CMAC, GCM test case 2, RFC 3610 CCM and a CAVS
  Hash_DRBG vector, plus .NET cross-checks for HMAC, AES-ECB/CBC and (where
  the platform supports them) AES-GCM and AES-CCM.
- Known answers: the ACVP aegisolve vectors used by the wolfACVP harness
  (hashDRBG; SHA-1/2/3 AFT and Monte Carlo; HMAC; CMAC; AES ECB/CBC/OFB/CTR
  including Monte Carlo; GCM and GMAC with external and internal IV
  generation; CCM; ECDSA keyVer and sigVer; KAS-FFC VAL; TLS 1.2 and 1.3 KDF).
  With `WOLFACVP_VECTORS` unset these report SKIP; set to a path without
  the aegisolve directories they fail.
- Independent checks with .NET's own implementations where vectors cannot be
  used: RSA signatures and OAEP in both directions, ECDSA signatures, ECDH
  agreement, HKDF, TLS 1.2 PRF/EMS/key block and TLS 1.3 Expand-Label
  references, BigInteger references for DH (RFC 7919 primes) and PKCS#1
  v1.5 DigestInfo, and an RFC 4253 reference for the SSH KDF.
- Skipped by design: ACVP RSA sigVer/keyGen/decryptionPrimitive and KAS-ECC
  VAL (they supply keys the boundary cannot import).
- Forced failure (operational-test builds): each scenario runs in a child
  process. FAILED (`-203`): all services refuse with `FIPS_NOT_ALLOWED_E`,
  including operations on keys created before the failure, and every
  refused `wc_*Free_fips` is counted. CONTINUOUS TEST (`-209`,
  `DRBG_CONT_FIPS_E`): every service is refused while the mode stays NORMAL;
  the status reports -209 and `IsOperational` is false. DEGRADED (every other
  code `wolfCrypt_SetStatus_fips` handles): every service that depends on a
  CAST the module reports as failed
  is refused. On entering degraded mode the module re-runs all CASTs, so
  failures cascade (for example an HMAC failure also disables RSA, ECDSA,
  ECDH and DH); the test reads the resulting CAST states from the module.

### Observation from the forced-failure tests

With the DRBG CAST failed (`DRBG_KAT_FIPS_E`), the module refuses DRBG
instantiation and generation and RSA key generation, but would still run GMAC
with an internal IV, RSA signing and DH key pair generation from a DRBG
instance created before the failure. The wrapper refuses those too (every
DRBG use checks the DRBG CAST), and the -208 scenario requires it. The module
behavior is reported for review by the FIPS team.
