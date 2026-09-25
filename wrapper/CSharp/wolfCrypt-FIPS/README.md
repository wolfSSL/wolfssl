# wolfCrypt FIPS C# wrapper

A .NET wrapper for the wolfCrypt FIPS 140-3 module v5.2.1 (certificate
#4718). It binds only the module's `*_fips` entry points and contains no
cryptographic code of its own: every operation runs inside the validated C
library.

- Targets .NET 10 (LTS) and .NET 8 (LTS, supported through November 10, 2026).
- Runs on Linux and macOS (Windows is not supported yet).
- Only services inside the module boundary are offered (see [Scope](#scope)).

## Contents

1. [Requirements](#requirements)
2. [Build](#build)
3. [Use the wrapper in an application](#use-the-wrapper-in-an-application)
4. [Examples](#examples)
5. [Rules to follow](#rules-to-follow)
6. [Run the tests](#run-the-tests)
7. [Scope](#scope)
8. [Checks enforced by the wrapper](#checks-enforced-by-the-wrapper)
9. [How it works](#how-it-works)

## Requirements

| What | Version / notes |
|---|---|
| wolfSSL FIPS library | wolfCrypt FIPS v5.2.1 (certificate #4718), built as a shared library per the Operational Environment user guide |
| Build option | `WC_RNG_SEED_CB` must be defined. It is by default with `--enable-fips=v5`; it is not set with `--enable-kcapi-ecc` or in `user_settings.h` builds that omit it |
| .NET SDK | .NET 10 SDK to build (restore evaluates both target frameworks) |
| .NET runtime | .NET 10 or .NET 8 runtime to run the matching build |
| C compiler | `cc` (or `CC`) to build the small native size helper |
| OS | Linux or macOS |

## Build

### 1. Build and install the FIPS library

Follow the wolfSSL FIPS user guide for your operational environment. For a
source bundle this is typically:

```sh
./configure --enable-fips=v5 --prefix=<prefix>
make
./fips-hash.sh        # update the in-core integrity hash
make
make install
```

`<prefix>` is the install directory used in the steps below (for example
`/usr/local` or `/opt/wolfssl-fips`).

### 2. Build the size helper

```sh
wrapper/CSharp/wolfCrypt-FIPS/build-native.sh <prefix>
```

This compiles `libwolfssl_csharp_fips` (`.so` on Linux, `.dylib` on macOS)
into `<prefix>/lib`, next to `libwolfssl`. The helper reports the sizes of
the module's structures for this exact build. It contains no cryptography
and is outside the module boundary.

**Rebuild the helper every time the FIPS library is rebuilt or
reinstalled.** It records a checksum of the `libwolfssl` it was built
against, and the wrapper refuses to run with any other library file.

### 3. Build the wrapper

```sh
dotnet build wrapper/CSharp/wolfCrypt-FIPS/wolfCrypt-FIPS.csproj -c Release
```

The output is `wolfCrypt.FIPS.dll` under `bin/Release/net10.0/` and
`bin/Release/net8.0/`.

## Use the wrapper in an application

1. Reference the wrapper from your project, for example:

   ```xml
   <ItemGroup>
     <ProjectReference Include="path/to/wrapper/CSharp/wolfCrypt-FIPS/wolfCrypt-FIPS.csproj" />
   </ItemGroup>
   ```

   or reference the built `wolfCrypt.FIPS.dll` directly.

2. Make the native libraries loadable. Either set `WOLFSSL_FIPS_LIB_DIR` to
   the directory that holds `libwolfssl` and `libwolfssl_csharp_fips`, or
   install them on the normal library search path. When
   `WOLFSSL_FIPS_LIB_DIR` is set, both libraries must load from it; there is
   no fallback.

   ```sh
   export WOLFSSL_FIPS_LIB_DIR=<prefix>/lib
   ```

3. Call `FipsModule.Initialize` once at startup, before any other call:

   ```csharp
   using wolfSSL.CSharp.Fips;

   FipsModule.Initialize(onFailure: (ok, err, hash) =>
       Console.Error.WriteLine($"FIPS module error {FipsError.Name(err)}"));
   ```

   `Initialize` loads the library (which runs the power-on self-tests and the
   in-core integrity check), checks that the size helper matches the loaded
   library, registers the failure callback, registers the DRBG seed source
   and throws `WolfCryptFipsException` unless the module is operational.

## Examples

All types are in the `wolfSSL.CSharp.Fips` namespace. Objects that hold
native state are `IDisposable`; use `using` so keys and DRBG state are
zeroized promptly.

### Random numbers (Hash_DRBG)

```csharp
using var rng = new FipsRng();
byte[] bytes = rng.Generate(32);
```

### Hash, HMAC and CMAC

```csharp
byte[] digest = FipsHash.Compute(FipsHashType.Sha256, data);
byte[] mac    = FipsHmac.Compute(FipsHashType.Sha256, hmacKey, data);   // key 14 to 128 bytes
byte[] tag    = FipsCmac.Compute(aesKey, data);                          // 16-byte tag

// There is no verify service in the boundary: recompute and compare
bool ok = CryptographicOperations.FixedTimeEquals(
    FipsHmac.Compute(FipsHashType.Sha256, hmacKey, data), receivedMac);
```

For incremental input, create `FipsHash`, `FipsHmac` or `FipsCmac` and call
`Update` then `Final`.

### AES-GCM (module-generated IVs)

```csharp
using var gcm = new FipsAesGcm(key);          // 16, 24 or 32-byte key
gcm.UseInternalIV(rng);                       // once per object: 12-byte IVs from the DRBG

FipsAeadResult r = gcm.Encrypt(plaintext, aad);
// send r.IV, r.Ciphertext and r.Tag

byte[] pt = gcm.Decrypt(r.IV, r.Ciphertext, r.Tag, aad);   // throws on a bad tag
```

### AES-CCM

```csharp
using var ccm = new FipsAesCcm(key);
ccm.SetNonce(rng);                            // once per object; 12-byte nonce from the DRBG
FipsAeadResult r = ccm.Encrypt(plaintext, aad);
byte[] pt = ccm.Decrypt(r.IV, r.Ciphertext, r.Tag, aad);
```

### AES-CBC, CTR, OFB

```csharp
using var enc = FipsAes.CreateCbc(key, rng);  // fresh DRBG IV; one message per encryptor
byte[] ct = enc.Transform(plaintext);         // CBC input must be a multiple of 16 bytes
byte[] iv = enc.IV!;

using var dec = FipsAes.CreateCbcDecryptor(key, iv);
byte[] pt = dec.Transform(ct);
```

`CreateCtr(key, rng)` and `CreateOfb(key, rng)` work the same way.

### RSA (key generation, PSS, PKCS#1 v1.5, OAEP)

```csharp
using var key = FipsRsaKey.Generate(3072, rng);      // 2048, 3072 or 4096 bits
FipsRsaPublicKey pub = key.ExportPublic();           // Modulus, Exponent

byte[] digest = FipsHash.Compute(FipsHashType.Sha256, message);

// RSASSA-PSS
byte[] pss = key.SignPss(FipsHashType.Sha256, digest, rng);
bool pssOk = key.VerifyPss(FipsHashType.Sha256, digest, pss);

// RSASSA-PKCS1-v1_5: the caller builds the DER DigestInfo (RFC 8017 9.2),
// as C applications do outside the module (wc_EncodeSignature); the module
// pads and signs
byte[] digestInfo = DigestInfoSha256(digest);
byte[] sig = key.SignPkcs1v15(digestInfo, rng);
byte[]? recovered = key.RecoverPkcs1v15(sig);        // null if it does not unpad
bool v15Ok = recovered != null && CryptographicOperations.FixedTimeEquals(recovered, digestInfo);

// RSA primitives with OAEP padding (on this key; there is no RSA key import)
byte[] ct = key.Encrypt(secret, rng);
byte[] pt = key.Decrypt(ct);

static byte[] DigestInfoSha256(byte[] digest)
{
    var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
    using (w.PushSequence()) {
        using (w.PushSequence()) {
            w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");   // SHA-256
            w.WriteNull();
        }
        w.WriteOctetString(digest);
    }
    return w.Encode();
}
```

### ECDSA and ECDH

```csharp
using var ec = FipsEccKey.Generate(FipsEccCurve.P256, rng);
byte[] digest = FipsHash.Compute(FipsHashType.Sha256, message);
byte[] der = ec.SignHash(FipsHashType.Sha256, digest);         // DER SEQUENCE { r, s }
bool ok = ec.VerifyHash(FipsHashType.Sha256, digest, der);

byte[] myPublic = ec.ExportPublic();                            // 04 || X || Y
using var peer = FipsEccKey.ImportPublic(FipsEccCurve.P256, peerPublic);   // validated on import
byte[] z = ec.SharedSecret(peer);                               // P-256, P-384, P-521 only
```

### Finite field DH (ffdhe2048)

```csharp
using var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
using FipsDhKeyPair kp = dh.GenerateKeyPair(rng);   // PrivateKey zeroed on Dispose
// send kp.PublicKey (256 bytes)
byte[] z = dh.Agree(kp.PrivateKey, peerPublicKey);  // 256 bytes, left-padded
```

### KDFs (TLS 1.2, TLS 1.3, SSH)

These are protocol KDFs (CVLs): use them only inside the TLS 1.2, TLS 1.3 and
SSHv2 protocols.

```csharp
// TLS 1.2 with the extended master secret (RFC 7627)
byte[] ms = FipsKdf.Tls12ExtendedMasterSecret(FipsHashType.Sha256, preMasterSecret, sessionHash);
byte[] keyBlock = FipsKdf.Tls12KeyBlock(FipsHashType.Sha256, ms, clientRandom, serverRandom, 104);

// TLS 1.3 (RFC 8446 7.1)
byte[] early = FipsKdf.Tls13Extract(FipsHashType.Sha256, null, psk);
byte[] derived = FipsKdf.Tls13ExpandLabel(FipsHashType.Sha256, early, "derived", emptyHash, 32);

// SSH (RFC 4253 7.2): K without leading zero bytes
byte[] ivCtoS = FipsKdf.SshKdf(FipsHashType.Sha256, 'A', k, exchangeHash, sessionId, 16);
```

### Module status and self-tests

```csharp
bool up = FipsModule.IsOperational;          // status 0 and mode Normal
int status = FipsModule.IntegrityTest();     // re-run the in-core integrity test
int failed = FipsModule.RunAllCasts();       // number of failed CASTs (0 = all passed)
```

## Rules to follow

**Startup and entropy.** The module has no entropy source of its own.
`Initialize` registers the library's OS source (`wc_GenerateSeed`,
`/dev/urandom` on Linux). To use a hardware TRNG instead, call
`FipsModule.SetSeedCallback`; `Initialize` keeps it, and only
`FipsModule.UseOsSeed()` switches back. A custom source is outside the module
boundary and must:
- supply full-entropy bytes (the module asks for 196 bytes, or 132 with a
  caller nonce, at each instantiation);
- run its own SP 800-90B health tests and return non-zero on failure;
- write directly into the `seed` pointer, or zero any staging buffer.

The module's automatic reseed (after 1,000,000 requests) draws from
`wc_GenerateSeed`, not from the callback. To seed only from your source,
dispose and recreate a `FipsRng` before that point. Certificate #4718 carries
the caveat that there is no assurance of the minimum strength of generated
keys; an ESV-validated entropy source is needed to remove it.

**Private key read gate.** The module locks output of private values (RSA
key export, ECC public key export, shared secrets, DH key generation, KDF
output) behind a per-thread gate. Each wrapper call that returns such a value
opens the gate for that one call and closes it again. `FipsRsaKey.Export()`
(full private key export) does not open it: call
`FipsModule.SetPrivateKeyReadEnable(true)` on the same thread first, and
`false` when done, without an `await` in between.

**IVs and nonces.**
- AES-GCM: `UseInternalIV` once per object (12 or 16-byte IVs, all from the
  DRBG). At most 2^32 encryptions per key (SP 800-38D 8.3): each object
  refuses encryption 2^32 + 1, and across objects and `FipsGmac.Compute`
  calls with the same key the application must stay within 2^32.
  Encryption with a caller-chosen IV is not offered.
- AES-CCM: `SetNonce` once per object. `SetNonce(rng)` is the default; with
  `SetNonce(nonce)` the caller must keep nonces unique under the key.
- AES-CBC/CTR/OFB: encrypt with `Create*(key, rng)`, one message per object.
  CBC with a caller IV is decrypt-only (`CreateCbcDecryptor`). `CreateOfb(key,
  iv, ...)` and `CreateCtr(key, iv)` can encrypt, so the caller must keep that
  IV (OFB) or every counter block (CTR) unique under the key.
- ECB is a building block (single blocks, testing), not a mode for general
  data.

**Tags.** GCM and GMAC tags are 12 to 16 bytes, CCM tags 8 to 16 (even),
CMAC tags 8 to 16. Decryption and GMAC verification take the expected tag
size and refuse a tag of any other length. Use one tag length per key.

**Secrets returned to you.** DH private keys, shared secrets, KDF output,
decrypted plaintext and exported RSA components are returned as `byte[]`.
`FipsDhKeyPair` and `FipsRsaKeyComponents` zero their private parts on
`Dispose`; zero other buffers with `CryptographicOperations.ZeroMemory` when
done.

**Dispose.** `Dispose` (or `using`) is how keys and DRBG state in native
memory are zeroized. An object that is not disposed is zeroized only when its
finalizer runs, and .NET does not run finalizers at process exit.

**Threads.** `FipsRng`, `FipsAes`, `FipsAesGcm`, `FipsAesCcm` and
`FipsRsaKey` serialize calls on one object and may be shared between threads.
Other objects are not thread-safe: use one per thread or lock.

**Errors.** Failures throw `WolfCryptFipsException`; `Code` is the module's
return value and `FipsError.Name(code)` its name. Verification returns
`false` (or `null` for `RecoverPkcs1v15`) for a bad signature or tag and
throws when the error reports the module's state
(`FipsError.IsModuleStateError`), so a failed or degraded module is never
reported as an invalid signature. After a DRBG self-test failure, every
service that uses a `FipsRng` is refused (`DRBG_KAT_FIPS_E`).

## Run the tests

```sh
# default target .NET 10
wrapper/CSharp/wolfCrypt-FIPS/run-tests.sh <prefix>

# .NET 8 build (needs a .NET 8 runtime; DOTNET_ROOT if it is a separate install)
DOTNET_TFM=net8.0 wrapper/CSharp/wolfCrypt-FIPS/run-tests.sh <prefix>

# include the ACVP known-answer tests from a FIPS bundle
WOLFACVP_VECTORS=<fips-bundle>/fips/wolfACVP wrapper/CSharp/wolfCrypt-FIPS/run-tests.sh <prefix>
```

`run-tests.sh` builds the size helper, runs the binding audit
(`tools/fips-bind-audit.sh`), then builds and runs `wolfCrypt-FIPS-Test`. The
last line reports `N passed, 0 failed, M skipped`; the exit code is non-zero
on any failure.

| Variable | Effect |
|---|---|
| `DOTNET_TFM` | Target framework to test: `net10.0` (default) or `net8.0` |
| `DOTNET_ROOT` | .NET install that holds the runtime for `DOTNET_TFM`, if not the default |
| `WOLFACVP_VECTORS` | Path to `fips/wolfACVP` of a FIPS bundle. Unset: the ACVP tests report SKIP. Set to a path without the vectors: they fail |
| `WOLFSSL_FIPS_LIB_DIR` | Set by `run-tests.sh` to `<prefix>/lib` |

The suite (a dependency-free console runner) covers:
- embedded known answers that always run (SHA-1/2/3, RFC 4231 HMAC,
  SP 800-38A AES, RFC 4493 CMAC, GCM, RFC 3610 CCM, a CAVS Hash_DRBG vector);
- the ACVP aegisolve vectors used by the wolfACVP harness;
- independent checks against .NET (RSA, ECDSA, ECDH, HMAC, AES, GCM, TLS
  KDF references) and BigInteger references (DH, PKCS#1 v1.5);
- forced-failure scenarios (FAILED, DRBG continuous test, and every DEGRADED
  code) when the library is an operational-test build that exports
  `wolfCrypt_SetStatus_fips` (`HAVE_FORCE_FIPS_FAILURE`); otherwise they are
  skipped.

## Scope

Only services inside the v5.2.1 module boundary are wrapped. Not provided:

| Not provided | Reason |
|---|---|
| RSA key import (DER or raw), ECC private key import | Decoders are outside the boundary (`asn.c`) |
| PKCS#1 v1.5 DigestInfo encoding and signature comparison | Outside the boundary (`wc_EncodeSignature` is in `asn.c`); the caller does these, as in the module's CAVP testing |
| RSA PKCS#1 v1.5 signing with SHA-1 or SHA-3 | SHA-1 signing is disallowed (SP 800-131A); RSA SigGen is validated with SHA-2 only |
| RSAES-PKCS1-v1_5 encryption | Disallowed (SP 800-131A Rev. 2); OAEP only |
| RSA key transport (SP 800-56B KTS) | The Security Policy makes no key transport claim; `Encrypt`/`Decrypt` are the RSA primitives with OAEP padding |
| HMAC and CMAC verify, ECDSA r/s conversion (DER, P1363), ECC import from separate X and Y | Not services of the boundary |
| General HKDF (RFC 5869 / SP 800-56C) | Not a validated service; HKDF is covered only inside the TLS 1.3 KDF |
| DH groups ffdhe3072 to ffdhe8192, explicit FIPS 186-type DH domains | The Security Policy lists KAS-FFC-SSC with ffdhe2048 only |
| ECC CDH on P-192 and P-224 | KAS-ECC-SSC is validated on P-256, P-384 and P-521 |
| P-192 key generation and signing | Disallowed by FIPS 186-5 (P-192 import and verification are allowed) |
| GCM encryption with a caller IV | External IVs are allowed only for TLS in the Security Policy |
| MGF1 with SHA-3 (PSS, OAEP), PSS salt discovery | Not supported by the module / accepts any salt length |
| DSA, Ed25519, Curve25519, ML-KEM, ML-DSA, ECIES, HPKE | Not approved services of the v5.2.1 module |
| `WOLF_CRYPTO_CB` builds | The boundary cannot set `devId` on Aes, Hmac or Cmac, so their operations go to crypto callback device 0 first; do not register a device 0 |

## Checks enforced by the wrapper

The module accepts some inputs that are not permitted or not safe. The
wrapper refuses them before calling the module. These checks only refuse
input; they add no functionality.

| Check | Why |
|---|---|
| RSA key sizes 2048, 3072, 4096 only; exponent odd and greater than 2^16 | The module also generates 1024-bit keys and accepts any odd e >= 3 |
| `SignPkcs1v15` accepts only the exact DER DigestInfo of a SHA-224/256/384/512 digest | The module pads and signs any byte string |
| No SHA-1 for RSA or ECDSA signature generation | SP 800-131A; the module signs SHA-1 digests |
| RSA-PSS salt length -1 (digest length) or 0 to hLen | `WOLFSSL_PSS_LONG_SALT` removes the module's own check |
| `SignHash` and `VerifyHash` take the hash type and check the digest length | ECDSA verification has no digest length bound, so a very short digest makes signatures forgeable |
| ECC public keys fully validated on import | Done by the module with `WOLFSSL_VALIDATE_ECC_IMPORT`, otherwise by an explicit key check |
| GCM/GMAC internal IVs of 12 or 16 bytes; at most 2^32 encryptions per object | The module also accepts 8-byte IVs and allows 2^64 invocations for 12-byte IVs |
| GCM, GMAC and CCM decryption require a tag of exactly the expected length | The module takes the tag length from the received tag |
| CMAC and CCM tags of at least 64 bits | The module accepts 32-bit tags |
| CCM payload shorter than 2^(8 x (15 - nonce length)) bytes | The module wraps the counter (keystream reuse) for longer input |
| AES ECB and CBC input a multiple of 16 bytes | The module otherwise leaves the tail of the output unencrypted |
| DH peer keys checked with `wc_DhCheckPubKeyEx` before agreement; public keys left-padded to the prime size | `wc_DhAgree` alone checks less; the module returns minimal-length keys |
| HMAC keys at most 128 bytes | The validated key range is 112 to 1024 bits |
| TLS 1.2: the non-EMS "master secret" derivation is refused; the EMS session hash must be a digest of the PRF hash | FIPS 140-3 IG D.Q allows the TLS 1.2 KDF only with the extended master secret |
| TLS 1.3: SHA-256/384 only, "tls13 " prefix, non-empty ASCII label, HkdfLabel within the module's buffer | The module copies the label into a fixed stack buffer without a capacity check |
| SSH KDF: K must be non-zero and without leading zero bytes | The module keeps redundant leading zeros in the mpint encoding |
| `RunCast` and `GetCastState` refuse CAST ids outside 0 to 14; `IntegrityTest` returns the status | The module writes its CAST array before checking the id, and its integrity test always returns 0 |

## How it works

**Why a separate wrapper.** In C, `fips.h` renames each API to its `_fips`
version (`#define wc_ecc_sign_hash wc_ecc_sign_hash_fips`). The `_fips`
function is where the module checks its status and self-test state before
running the algorithm. A C# `DllImport` binds names at runtime and never sees
that header, and a FIPS library exports both names, so binding the plain name
would call the algorithm directly and bypass those checks. This wrapper binds
every entry point by its `_fips` name, and `tools/fips-bind-audit.sh` fails
the build if any binding is not a `_fips` function declared in `fips.h` and
exported by the library.

**Size helper.** The boundary's initializers (`wc_InitRng_fips`,
`wc_InitRsaKey_fips`, ...) work on caller-allocated structures whose size
depends on the library's configure options. `native/fips_sizes.c`, compiled
against the installed `wolfssl/options.h`, reports those sizes. It is bound to
one exact `libwolfssl` file by checksum and is always loaded from the
directory `libwolfssl` was loaded from.

**Native memory.** Each native structure is owned by a `SafeHandle`, so it
cannot be freed while the module is using it. Releasing it runs the module's
free routine, then zeroes and frees the memory. In the FAILED state, or after
the algorithm's CAST failed, the module refuses its RNG, RSA, ECC and DH free
routines; the wrapper still zeroes the structure and counts the refusal in
`FipsModule.RefusedFreeCount`.

**Files.**

| File | Purpose |
|---|---|
| `Native.cs` | All P/Invoke declarations (the only file that binds native code) |
| `NativeLoader.cs` | Loads `libwolfssl` and the size helper |
| `FipsHandle.cs`, `FipsObject.cs` | Native structure ownership |
| `FipsModule.cs` | Initialization, status, self-tests, callbacks, seed source, private key read gate |
| `FipsRng.cs` | Hash_DRBG |
| `FipsHash.cs`, `FipsHmac.cs`, `FipsCmac.cs` | SHA-1/2/3, HMAC, CMAC-AES |
| `FipsAes.cs`, `FipsAesGcm.cs` | AES ECB/CBC/CTR/OFB, GCM, GMAC, CCM |
| `FipsRsa.cs` | RSA key generation, PSS and PKCS#1 v1.5 signatures, OAEP |
| `FipsEcc.cs`, `FipsDh.cs` | ECDSA, ECC CDH, finite field DH |
| `FipsKdf.cs` | TLS 1.2, TLS 1.3 and SSH KDFs |
| `FipsError.cs` | Error codes and names |
| `native/fips_sizes.c`, `build-native.sh` | Size helper and its build script |
| `tools/fips-bind-audit.sh` | Binding audit |
| `run-tests.sh` | Build and run the test suite |
