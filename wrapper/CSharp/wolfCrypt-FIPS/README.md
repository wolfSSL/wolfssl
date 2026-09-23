# wolfCrypt FIPS C# wrapper

A .NET (net8.0) wrapper for the wolfCrypt FIPS 140-3 module. It binds only
the module's approved-service entry points (the `*_fips` functions of the
v5.2.3 boundary) and contains no cryptographic code of its own.

Tested against wolfCrypt FIPS v5.2.1 (certificate #4718) and v5.2.3.

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
| `FipsModule.cs` | Status, mode, version, integrity test, CASTs, failure callback, seed source, private key read gate |
| `FipsRng.cs` | Hash_DRBG (SP 800-90A) |
| `FipsHash.cs`, `FipsHmac.cs`, `FipsCmac.cs` | SHA-1/2/3, HMAC, CMAC-AES |
| `FipsAes.cs`, `FipsAesGcm.cs` | AES ECB/CBC/CTR/OFB, GCM, GMAC, CCM |
| `FipsRsa.cs` | RSA key generation, PKCS#1 v1.5 and PSS signatures, OAEP / PKCS#1 v1.5 encryption |
| `FipsEcc.cs`, `FipsDh.cs` | ECDSA, ECC CDH, finite field DH |
| `FipsKdf.cs` | TLS 1.2 PRF, HKDF, TLS 1.3 HKDF, SSH KDF |
| `native/fips_sizes.c` | Structure size helper (see below) |
| `tools/fips-bind-audit.sh` | Binding audit |
| `build-native.sh`, `run-tests.sh` | Build the helper; build and run the test suite |

### Size helper

The in-boundary initializers (`wc_InitRng_fips`, `wc_InitRsaKey_fips`, ...)
work on caller-allocated structures whose size depends on the library's
configure options. `native/fips_sizes.c` is compiled against the installed
`wolfssl/options.h` and reports those sizes. It contains no cryptography,
does not link libwolfssl, and is outside the module boundary.

## Build and test

```sh
# wolfSSL FIPS library, per the OE User Guide, installed to <prefix>
./configure --enable-fips=v5 --prefix=<prefix>
make && ./fips-hash.sh && make && make install

# size helper + binding audit + test suite
wrapper/CSharp/wolfCrypt-FIPS/run-tests.sh <prefix>
```

`run-tests.sh` builds `libwolfssl_csharp_fips` into `<prefix>/lib`, runs the
binding audit, and runs `wolfCrypt-FIPS-Test`.

Environment:

| Variable | Effect |
|---|---|
| `WOLFSSL_FIPS_LIB_DIR` | Directory holding libwolfssl and the size helper (otherwise the normal search path, e.g. `/usr/local/lib`) |
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

The module has no entropy source of its own. In `WC_RNG_SEED_CB` builds,
nothing that needs the DRBG works until a seed source is registered,
including the ECC self-tests. `Initialize` registers the library's OS source
(`wc_GenerateSeed`, `/dev/urandom` on Linux) by passing its native function
pointer to `wc_SetSeed_Cb_fips`. `FipsModule.SetSeedCallback` registers a
custom source instead.

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
`GenerateKeyPair`, `ExportPublic`, the KDFs): it enables the gate on the
current thread for that one synchronous call and restores the previous state
in a `finally`. This mirrors wolfSSL's own `PRIVATE_KEY_UNLOCK()` /
`PRIVATE_KEY_LOCK()` use.

`FipsRsaKey.Export` (full private key export) does not do this. Call
`FipsModule.SetPrivateKeyReadEnable(true)` on the same thread first, and do
not `await` between the two calls.

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
| ECC private key import | Not in the boundary; ECC public key import (X9.63) is provided |
| DSA, Ed25519, Curve25519, ML-KEM, ML-DSA, ECIES, HPKE | Not approved services of the v5.2.3 module |
| MGF1 with SHA-3 (PSS, OAEP) | Not supported by the module |

## Checks enforced by the wrapper

The module accepts some inputs that are not permitted or not safe. The
wrapper rejects them before calling the module:

| Check | Module behavior |
|---|---|
| RSA key generation limited to 2048, 3072, 4096 bits | v5.2.1 and v5.2.3 also generate 1024-bit keys (bug 6367, `RsaSizeCheck`) |
| AES ECB and CBC input must be a multiple of 16 bytes | Without `WOLFSSL_AES_CBC_LENGTH_CHECKS` the module processes only whole blocks, returns success and leaves the tail of the output unencrypted |
| P-192 limited to public key import and verification | FIPS 186-5 disallows P-192 key generation and signing |
| An empty HKDF salt is passed as NULL | The module uses HashLen zeros for NULL but rejects a zero-length non-NULL salt as a 0-byte HMAC key |

Other module rules the wrapper passes through:

- HMAC keys, and HKDF salts (the HMAC key of HKDF-Extract), must be at least
  14 bytes (112 bits); shorter values fail with `HMAC_MIN_KEYLEN_E`.
- The TLS 1.2 PRF takes TLS MAC algorithm ids (`sha256_mac` = 4) while HKDF,
  TLS 1.3 and SSH take `wc_HashType` (SHA-256 = 6). `FipsHashType` holds the
  v5 `wc_HashType` values and the wrapper maps them for the PRF. Note that
  `types.h` contains two `wc_HashType` enums; FIPS v5 uses the second.

## Tests

`wolfCrypt-FIPS-Test` is a dependency-free console runner (no NuGet access
needed on target devices).

- Known answers: the ACVP aegisolve vectors used by the wolfACVP harness
  (hashDRBG; SHA-1/2/3 AFT and Monte Carlo; HMAC; CMAC; AES ECB/CBC/OFB/CTR
  including Monte Carlo; GCM and GMAC with external and internal IV
  generation; CCM; ECDSA keyVer and sigVer; KAS-FFC VAL; TLS 1.2 and 1.3 KDF).
- Independent checks with .NET's own implementations where vectors cannot be
  used: RSA signatures and OAEP in both directions, ECDSA signatures, ECDH
  agreement, HKDF, and an RFC 4253 reference for the SSH KDF.
- Skipped by design: ACVP RSA sigVer/keyGen/decryptionPrimitive and KAS-ECC
  VAL (they supply keys the boundary cannot import).
- Forced failure (operational-test builds): each scenario runs in a child
  process. FAILED (`-203`): all services refuse with `FIPS_NOT_ALLOWED_E`,
  including operations on keys created before the failure. DEGRADED (13 CAST
  codes): every service that depends on a CAST the module reports as failed
  is refused. On entering degraded mode the module re-runs all CASTs, so
  failures cascade (for example an HMAC failure also disables RSA, ECDSA,
  ECDH and DH); the test reads the resulting CAST states from the module.

### Observation from the forced-failure tests

With the DRBG CAST failed (`DRBG_KAT_FIPS_E`), the module refuses DRBG
instantiation and generation and RSA key generation, but GMAC with an
internal IV, RSA signing and DH key pair generation still succeed using a DRBG
instance created before the failure. This is module behavior, reported for
review by the FIPS team.
