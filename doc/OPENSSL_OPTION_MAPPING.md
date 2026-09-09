# OpenSSL to wolfSSL Build Option Mapping

A reference for teams moving a build from OpenSSL to wolfSSL. It maps OpenSSL
`Configure` options and runtime knobs onto wolfSSL `./configure` options and
their CMake equivalents, and states plainly where there is no equivalent.

Verified against OpenSSL 1.1.1w, 3.0.19, 3.1.8, 3.2.4, 3.3.7, 3.5.5, 3.5.8 and
the 4.0.0 release notes, and against wolfSSL 5.9.2. The OpenSSL releases differ
enough to matter, so rows that changed say which version they describe, and
"Availability by OpenSSL version" below gives the boundaries.

**Which OpenSSL are you migrating from?** 3.5 is the current long-term-stable
release, supported until 8 April 2030. 4.0 (14 April 2026) is *not* LTS and is
supported only until 14 May 2027, so most long-lived deployments will still be
on 3.5. 4.0 removes SSLv3 and the whole ENGINE API, adds ECH, cSHAKE, the SNMP
and SRTP KDFs and RFC 8998 ShangMi TLS, and turns deprecated and explicit
elliptic curves off at compile time by default.

## Read this first: the two builds mean different things by "enabled"

OpenSSL and wolfSSL divide the same work between build time and run time in
opposite ways, and every table below is easier to read once that is clear.

**OpenSSL decides at run time.** A default build compiles in nearly everything
and then narrows it through three runtime layers:

- **Providers.** Algorithms live in `default`, `legacy`, `base` and `fips`
  modules. Only `default` is loaded unless configured otherwise, so a legacy
  algorithm is present in the binary but unusable until you ask for it. The
  legacy provider is still present in 4.0; the ENGINE API it replaced is not.
- **Security level.** `@SECLEVEL=n` (default 1) refuses weak keys, protocol
  versions and cipher suites without removing them.
- **`openssl.cnf`**, plus the distribution's system-wide crypto policy.

**wolfSSL decides at build time.** Every feature is a preprocessor macro fixed
by `./configure` or CMake. There are no providers and no security level: if a
feature is compiled in, it is available, and if it is not, it does not exist.

Two consequences worth planning around:

1. Where OpenSSL ships something disarmed, wolfSSL must either compile it in
   (and it is live) or leave it out. `--enable-enterprise` deliberately enables
   TLS 1.0/1.1 for feature parity, and unlike OpenSSL they will be negotiated.
   Restrict them at run time with a crypto policy, or drop them at build time
   with `--disable-oldtls`.
2. The application must be built with the same macros as the library. Include
   `<wolfssl/options.h>` before any other wolfSSL header, or compile with
   `-DWOLFSSL_USE_OPTIONS_H`. A mismatch changes struct layouts, compiles
   cleanly, and corrupts memory at run time.

## If you are coming from OpenSSL 1.1.1

1.1.1 predates the provider model entirely, and that changes the shape of the
migration more than any individual algorithm does.

- **There is no provider split.** RC2, RC4, Blowfish, SEED, single DES, MD4 and
  Whirlpool are usable straight out of a stock 1.1.1 build -- verified on
  1.1.1w. From 3.0 the same algorithms moved to the `legacy` provider and stop
  working until it is loaded. So an application that quietly relied on RC4 or
  MD4 breaks on the way to 3.x, before wolfSSL is even in the picture.
- **ENGINE is the only extension mechanism.** There are no providers to write,
  and 4.0 removes ENGINE altogether, so an ENGINE-based integration has no
  forward path on either side. wolfSSL's equivalent is crypto callbacks
  (`--enable-cryptocb`) or PKCS#11.
- **`openssl list -mac-algorithms` and `-kdf-algorithms` do not exist**, so the
  EVP_MAC and EVP_KDF tables below describe 3.0 and later only.
- **Missing relative to 3.x:** AES-SIV, AES-CBC-CTS and AES key wrap (3.0),
  AES-GCM-SIV and Argon2 (3.2), ML-KEM, ML-DSA and SLH-DSA (3.5), ECH, cSHAKE
  and the SNMP/SRTP KDFs (4.0).

Everything else in this document applies unchanged: the wolfSSL side does not
vary with which OpenSSL you are leaving.

## Availability by OpenSSL version

Verified by running each release. "legacy" means present but not usable until
the legacy provider is loaded.

| | 1.1.1w | 3.0 | 3.1 | 3.2 | 3.3 | 3.5 | 4.0 |
|---|---|---|---|---|---|---|---|
| Provider model | no | yes | yes | yes | yes | yes | yes |
| RC2, RC4, Blowfish, SEED, single DES | direct | legacy | legacy | legacy | legacy | legacy | legacy |
| MD4, Whirlpool, MDC2, MD2 | direct | legacy | legacy | legacy | legacy | legacy | legacy |
| RIPEMD-160 | direct | direct | direct | direct | direct | direct | direct |
| AES-SIV, AES-CBC-CTS, AES key wrap | no | yes | yes | yes | yes | yes | yes |
| AES-GCM-SIV, Argon2 | no | no | no | yes | yes | yes | yes |
| EVP_MAC: CMAC, GMAC, KMAC, Poly1305, SipHash | n/a | yes | yes | yes | yes | yes | yes |
| EVP_KDF: HKDF, KBKDF, KRB5, SSH, SSKDF, X9.42, X9.63, scrypt | n/a | yes | yes | yes | yes | yes | yes |
| ML-KEM, ML-DSA, SLH-DSA | no | no | no | no | no | yes | yes |
| LMS (verification only) | no | no | no | no | no | no | 3.6+ |
| ECH, cSHAKE, SNMP KDF, SRTP KDF | no | no | no | no | no | no | yes |
| SSLv3 | build option, off | off | off | off | off | off | **removed** |
| ENGINE API | yes | deprecated | deprecated | deprecated | deprecated | deprecated | **removed** |
| 3DES and RC4 TLS cipher suites | no | no | no | no | no | no | no |

No stock build tested offered a 3DES or RC4 TLS cipher suite, even at
`@SECLEVEL=0` -- including 1.1.1w. They require `enable-weak-ssl-ciphers` at
build time, so treat their absence as the norm and check your own build if you
believe otherwise.

## Start here

| Goal | Autotools | CMake |
|---|---|---|
| Closest match to a default OpenSSL build | `--enable-enterprise` | `-DWOLFSSL_ENTERPRISE=yes` |
| Every wolfSSL feature that can coexist | `--enable-all` | `-DWOLFSSL_ALL=yes` |
| All wolfCrypt algorithms, no TLS extras | `--enable-all-crypto` | `-DWOLFSSL_ALL_CRYPTO=yes` |
| Post-quantum asymmetric algorithms | `--enable-all-quantum-crypto` | `-DWOLFSSL_ALL_QUANTUM_CRYPTO=yes` |
| OpenSSL compatibility API only | `--enable-opensslall` | `-DWOLFSSL_OPENSSLALL=yes` |
| Link beside a real libcrypto | `--enable-opensslcoexist` | `-DWOLFSSL_OPENSSL_COEXIST=yes` |

`--enable-enterprise` is the recommended starting point. It is `--enable-all`
plus the protocol versions, algorithms and behaviours a default OpenSSL build
still ships, minus a short list of deliberate exclusions (see
"Where enterprise departs from OpenSSL"). Any explicit `--enable-`/`--disable-`
on the same command line overrides it, so treat it as a baseline to trim.

## Protocol versions

| OpenSSL | wolfSSL autotools | CMake |
|---|---|---|
| SSL 3.0 — 3.5: `enable-ssl3`, off by default. **Removed outright in 4.0**, along with the SSLv2 ClientHello | `--enable-sslv3` | `-DWOLFSSL_SSLV3=yes` |
| TLS 1.0 (`no-tls1`) | `--enable-tlsv10` | `-DWOLFSSL_TLSV10=yes` |
| TLS 1.1 (`no-tls1_1`) | `--enable-oldtls` | `-DWOLFSSL_OLD_TLS=yes` |
| TLS 1.2 (`no-tls1_2`) | on by default; `--disable-tlsv12` | `-DWOLFSSL_TLSV12=no` |
| TLS 1.3 (`no-tls1_3`) | on by default; `--disable-tls13` | `-DWOLFSSL_TLS13=no` |
| DTLS 1.0/1.2 (`no-dtls`) | `--enable-dtls` | `-DWOLFSSL_DTLS=yes` |
| DTLS 1.3 — *not in OpenSSL* | `--enable-dtls13` | `-DWOLFSSL_DTLS13=yes` |
| QUIC | `--enable-quic` | `-DWOLFSSL_QUIC=yes` |
| SCTP (`enable-sctp`) | `--enable-sctp` | — |
| SRTP (`no-srtp`) | `--enable-srtp` | `-DWOLFSSL_SRTP=yes` |
| Negotiated FFDHE in TLS 1.2, RFC 7919 — *4.0 only* | on with `--enable-dh` (FFDHE 2048/3072 groups) | `-DWOLFSSL_DH=yes` |

wolfSSL builds TLS 1.2 and 1.3 by default and everything older must be asked
for; OpenSSL is the reverse.

## Ciphers and digests

| OpenSSL | Provider | wolfSSL autotools | CMake |
|---|---|---|---|
| AES-CBC/CTR/OFB/CFB/ECB | default | on by default; `--enable-aesctr`, `--enable-aesofb`, `--enable-aescfb`, `--enable-aesecb` | `-DWOLFSSL_AESCTR=yes` … |
| AES-GCM / CCM | default | `--enable-aesgcm` (default on), `--enable-aesccm` | `-DWOLFSSL_AESGCM=yes`, `-DWOLFSSL_AESCCM=yes` |
| AES-XTS | default | `--enable-aesxts` | — |
| AES-SIV — *3.0+* | default | `--enable-aessiv` | `-DWOLFSSL_AESSIV=yes` |
| AES-GCM-SIV — *3.2+* | default | `--enable-aesgcm-siv` | `-DWOLFSSL_AESGCMSIV=yes` |
| AES-CTS — *3.0+* | default | `--enable-aescts` | `-DWOLFSSL_AESCTS=yes` |
| AES-OCB | default | **no equivalent** | — |
| AES key wrap — *3.0+* | default | `--enable-aeskeywrap` | `-DWOLFSSL_AESKEYWRAP=yes` |
| ChaCha20-Poly1305 | default | on by default | `-DWOLFSSL_CHACHA=yes` |
| Camellia | default | `--enable-camellia` | `-DWOLFSSL_CAMELLIA=yes` |
| ARIA | default | `--enable-aria` — **requires the external MagicCrypto SDK** | `-DWOLFSSL_ARIA=yes` |
| SM4 | default | `--enable-sm4-{ecb,cbc,ctr,gcm,ccm}` — **requires [wolfsm](https://github.com/wolfSSL/wolfsm)** | `-DWOLFSSL_SM4_*=yes` |
| TLS 1.3 SM suites `TLS_SM4_GCM_SM3`, `TLS_SM4_CCM_SM3`, RFC 8998 — *4.0 only* | default | `--enable-sm2 --enable-sm3 --enable-sm4-gcm` — **requires wolfsm** | — |
| 3DES (`no-des`) | default | `--enable-des3` | `-DWOLFSSL_DES3=yes` |
| 3DES TLS cipher suites — need `enable-weak-ssl-ciphers` at build time; stock 3.5 and 4.0 builds offer none at any security level | — | `--enable-des3-tls-suites` | `-DWOLFSSL_DES3_TLS_SUITES=yes` |
| RC4 (`no-rc4`) | legacy | `--enable-arc4` | `-DWOLFSSL_ARC4=yes` |
| RC2 (`no-rc2`) | legacy | `--enable-rc2` | `-DWOLFSSL_RC2=yes` |
| NULL cipher | default | `--enable-nullcipher` | — |
| Blowfish, CAST5, IDEA, SEED, DESX, single DES | legacy | **no equivalent** (single DES exists inside wolfCrypt's 3DES module but is not exposed as a build option) | — |
| RC5 | legacy, and needs `enable-rc5` | **no equivalent** | — |
| SHA-1, SHA-2 | default | on by default | — |
| SHA-3, SHAKE | default | `--enable-sha3`, `--enable-shake128/256` | `-DWOLFSSL_SHA3=yes` … |
| MD5 / MD4 (`no-md4`) | default / legacy | `--enable-md5`, `--enable-md4` | `-DWOLFSSL_MD5=yes`, `-DWOLFSSL_MD4=yes` |
| MD2 | legacy, and needs `enable-md2` | `--enable-md2` | `-DWOLFSSL_MD2=yes` |
| RIPEMD-160 (`no-rmd160`) | default **and** legacy — usable without loading legacy, unlike the other legacy digests | `--enable-ripemd` | `-DWOLFSSL_RIPEMD=yes` |
| BLAKE2b / BLAKE2s (`no-blake2`) | default | `--enable-blake2b`, `--enable-blake2s` | `-DWOLFSSL_BLAKE2=yes`, `-DWOLFSSL_BLAKE2S=yes` |
| SM3 | default | `--enable-sm3` — **requires wolfsm** | `-DWOLFSSL_SM3=yes` |
| cSHAKE, SP 800-185 — *4.0 only* | default | `--enable-cshake` | `-DWOLFSSL_CSHAKE=yes` |
| Whirlpool, MDC2 | legacy | **no equivalent** | — |

## MACs and KDFs

| OpenSSL | wolfSSL autotools | CMake |
|---|---|---|
| HMAC | on by default | — |
| CMAC | `--enable-cmac` | `-DWOLFSSL_CMAC=yes` |
| GMAC | comes with `--enable-aesgcm` | — |
| KMAC | `--enable-kmac` | `-DWOLFSSL_KMAC=yes` |
| Poly1305 | on by default | `-DWOLFSSL_POLY1305=yes` |
| SipHash (`no-siphash`) | `--enable-siphash` | `-DWOLFSSL_SIPHASH=yes` |
| HKDF | `--enable-hkdf` | `-DWOLFSSL_HKDF=yes` |
| TLS1-PRF / TLS13-KDF | built in with the protocol | — |
| PBKDF2 | `--enable-pwdbased` | `-DWOLFSSL_PWDBASED=yes` |
| scrypt (`no-scrypt`) | `--enable-scrypt` | — |
| KBKDF, SP 800-108 | **no equivalent** (`--enable-cmac-kdf` covers the CMAC variant only) | — |
| KRB5KDF | **no equivalent** | — |
| PKCS12KDF | comes with `--enable-pkcs12` | `-DWOLFSSL_PKCS12=yes` |
| Argon2 (`no-argon2`) — *3.2+* | **not yet in wolfCrypt**; the implementation exists on an unmerged branch | — |
| X9.63 KDF | `--enable-x963kdf` | `-DWOLFSSL_X963KDF=yes` |
| X9.42 KDF | **no equivalent** | — |
| SSKDF (SP 800-56C) | comes with `--enable-all-crypto` | — |
| SSHKDF | `--enable-ssh` | — |
| SRTP-KDF — *4.0 only* | `--enable-srtp-kdf` | — |
| SNMP KDF — *4.0 only* | **no equivalent** | — |

## Public key

| OpenSSL | wolfSSL autotools | CMake |
|---|---|---|
| RSA, RSA-OAEP | on by default; `--enable-oaep` | `-DWOLFSSL_OAEP=yes` |
| RSA-PSS | `--enable-rsapss` | `-DWOLFSSL_RSA_PSS=yes` |
| DH (`no-dh`) | `--enable-dh` | `-DWOLFSSL_DH=yes` |
| DSA (`no-dsa`) | `--enable-dsa` | `-DWOLFSSL_DSA=yes` |
| ECDSA / ECDH (`no-ec`) | on by default | `-DWOLFSSL_ECC=yes` |
| Brainpool, Koblitz, secp*r2/r3 | `--enable-ecccustcurves`, `--enable-brainpool` | `-DWOLFSSL_ECCCUSTCURVES=yes` |
| RFC 8422 deprecated TLS curves — *4.0 disables these at compile time by default* | governed by `--enable-ecccustcurves` and the curve options above | — |
| Explicit (non-named) EC curve parameters — *4.0 disables these by default* | `--enable-ecccustcurves` | `-DWOLFSSL_ECCCUSTCURVES=yes` |
| Binary/`ec2m` curves (`no-ec2m`) | **no equivalent** | — |
| X25519 / Ed25519 | `--enable-curve25519`, `--enable-ed25519` | `-DWOLFSSL_CURVE25519=yes`, `-DWOLFSSL_ED25519=yes` |
| X448 / Ed448 | `--enable-curve448`, `--enable-ed448` | `-DWOLFSSL_CURVE448=yes`, `-DWOLFSSL_ED448=yes` |
| SM2 (4.0 adds `sm2sig_sm3`, `curveSM2` and `curveSM2MLKEM768`, RFC 8998) | `--enable-sm2` — **requires wolfsm** | `-DWOLFSSL_SM2=yes` |
| ML-KEM — *3.5+* | `--enable-mlkem` | `-DWOLFSSL_MLKEM=yes` |
| ML-DSA — *3.5+*; 4.0 adds the `ML-DSA-MU` digest | `--enable-mldsa` | `-DWOLFSSL_MLDSA=yes` |
| SLH-DSA — *3.5+* | `--enable-slhdsa` | `-DWOLFSSL_SLHDSA=yes` |
| LMS — absent from 3.5; verification only from 3.6, reaching `openssl pkeyutl` in 4.0 | `--enable-lms`, sign **and** verify | `-DWOLFSSL_LMS=yes` |
| XMSS — *not in OpenSSL* | `--enable-xmss` | `-DWOLFSSL_XMSS=yes` |

## TLS features and PKI

| OpenSSL | wolfSSL autotools | CMake |
|---|---|---|
| SNI, ALPN | `--enable-sni`, `--enable-alpn` | `-DWOLFSSL_SNI=yes`, `-DWOLFSSL_ALPN=yes` |
| Session tickets | `--enable-session-ticket` | `-DWOLFSSL_SESSION_TICKET=yes` |
| Early data / 0-RTT | `--enable-earlydata` | `-DWOLFSSL_EARLYDATA=yes` |
| Secure renegotiation | `--enable-secure-renegotiation` | `-DWOLFSSL_SECURE_RENEGOTIATION=yes` |
| `SSL_OP_LEGACY_SERVER_CONNECT` (on by default) | `--enable-legacy-server-connect` | — |
| `SSL_export_keying_material` | `--enable-keying-material` | `-DWOLFSSL_KEYING_MATERIAL=yes` |
| `SSL_CTX_set_keylog_callback` | `--enable-keylog-export` | `-DWOLFSSL_KEYLOG_EXPORT=yes` |
| PSK (`no-psk`) | `--enable-psk` | — |
| SRP (`no-srp`) | `--enable-srp` | `-DWOLFSSL_SRP=yes` |
| OCSP (`no-ocsp`) | `--enable-ocsp` | `-DWOLFSSL_OCSP=yes` |
| OCSP stapling | `--enable-ocspstapling`, `--enable-ocspstapling2` | `-DWOLFSSL_OCSPSTAPLING=yes` |
| CRL | `--enable-crl` | `-DWOLFSSL_CRL=yes` |
| CMS / PKCS#7 (`no-cms`) | `--enable-pkcs7` | `-DWOLFSSL_PKCS7=yes` |
| S/MIME | `--enable-smime` | `-DWOLFSSL_SMIME=yes` |
| Timestamping, `openssl ts` (`no-ts`) | `--enable-tsp` | `-DWOLFSSL_TSP=yes` |
| PKCS#12 | `--enable-pkcs12` (default on) | `-DWOLFSSL_PKCS12=yes` |
| PKCS#8 | `--enable-pkcs8` (default on) | `-DWOLFSSL_PKCS8=yes` |
| Certificate Transparency (`no-ct`) | **no equivalent** | — |
| DANE/TLSA (`no-dane`) | **no equivalent** | — |
| CMP / CRMF, RFC 4210 | **no equivalent** (`--enable-scep` covers a different enrolment protocol) | — |
| Attribute certificates — *not in OpenSSL* | `--enable-acert` | — |
| Encrypted Client Hello — not in 3.5; **added in 4.0** (RFC 9849) | `--enable-ech` | `-DWOLFSSL_ECH=yes` |
| Compression (`no-comp`, zlib) | `--with-libz` | `-DWOLFSSL_LIBZ=yes` |
| Per-thread error queue | `--enable-error-queue-per-thread` (auto-detected) | `-DWOLFSSL_ERROR_QUEUE_PER_THREAD=yes` |
| System CA store | `--enable-sys-ca-certs` (default on) | `-DWOLFSSL_SYS_CA_CERTS=yes` |

## Runtime behaviour, not build options

These are the OpenSSL knobs with no `./configure` counterpart, because wolfSSL
places the same control somewhere else.

| OpenSSL | wolfSSL |
|---|---|
| Providers (`default`, `legacy`, `fips`) | No equivalent. Compile in what you need; `--enable-fips=<ver>` selects a licensed FIPS module. |
| `@SECLEVEL=n` | No direct equivalent. Nearest is the system crypto policy below. |
| `openssl.cnf`, `/etc/crypto-policies` | `--with-sys-crypto-policy[=PATH]` reads `/etc/crypto-policies/back-ends/wolfssl.config`; sample policies in `examples/crypto_policies/`. Compiling it in only exposes `wolfSSL_crypto_policy_enable()`; nothing is read until the application calls it. Enabled by `--enable-enterprise`. |
| ENGINE API — **removed entirely in 4.0**; `no-engine` and `OPENSSL_NO_ENGINE` are now unconditional | Crypto callbacks (`--enable-cryptocb`, `wc_CryptoCb_RegisterDevice`) or PKCS#11 (`--enable-pkcs11`). To keep OpenSSL's API and swap the crypto underneath, [wolfProvider](https://github.com/wolfSSL/wolfProvider) works with 3.x and 4.0; [wolfEngine](https://github.com/wolfSSL/wolfEngine) is an ENGINE and therefore **cannot be used with OpenSSL 4.0**. |
| The `openssl` command | Not shipped. See [wolfCLU](https://github.com/wolfSSL/wolfCLU). |
| `no-threads` | `--enable-singlethreaded` |
| `no-stdio` / `no-filenames` | `--disable-filesystem` |
| `no-shared` | `--disable-shared` |
| `enable-fips` | `--enable-fips=<v2\|v5\|v6\|ready\|dev>`. Certified versions need a licensed bundle from wolfSSL; `ready` and `dev` work with the free FIPS Ready download. No FIPS variant configures from a plain git checkout. |
| `no-deprecated`, `--api=` | No equivalent; wolfSSL's compatibility surface is chosen by `--enable-opensslextra` vs `--enable-opensslall`. |
| Custom `EVP_CIPHER` / `EVP_MD` / `EVP_PKEY` methods — **removed in 4.0** | Crypto callbacks (`--enable-cryptocb`) are the supported extension point. |

## Where `--enable-enterprise` departs from OpenSSL

Three deliberate exclusions, all overridable:

- **RC2** is not compiled in. OpenSSL ships it, but in the `legacy` provider,
  which is not loaded by default — `openssl enc -rc2` fails on a stock build.
  Leaving it out is closer to OpenSSL's effective behaviour than including it.
- **3DES cipher suites** are off (`NO_DES3_TLS_SUITES`), matching OpenSSL 3.5,
  which no longer compiles them in at any security level. The 3DES *algorithm*
  stays available, as it does in OpenSSL's default provider.
- **SAKKE** (RFC 6508) is off. It has no OpenSSL counterpart and nothing an
  OpenSSL deployment talks to will offer it.

RC4, MD2, MD4, MD5 and the NULL cipher remain enabled, because OpenSSL also
ships them and several application compatibility profiles require them.

## Application compatibility profiles

wolfSSL ships flag sets matching what specific projects need, which is usually
faster than deriving the option list by hand:

```
--enable-curl      --enable-nginx      --enable-haproxy    --enable-openssh
--enable-openvpn   --enable-stunnel    --enable-libssh2    --enable-lighty
--enable-wpas      --enable-net-snmp   --enable-openldap   --enable-krb
```

`--enable-all-osp` (`-DWOLFSSL_ALL_OSP=yes`) enables all of them at once and is
included in `--enable-all`.

## Checking what you got

```sh
./configure --enable-enterprise && make
grep '#define' wolfssl/options.h        # every macro the build settled on
./wolfcrypt/test/testwolfcrypt          # algorithm self-tests
make check                              # full suite
```

`./configure --help` lists every option; `configure.ac` is the source of truth
for the macros each one sets.

Two caveats when comparing builds:

- `wolfssl/options.h` is generated per build. Never commit it, and never mix one
  build's copy with another's objects.
- The CMake build generates its `options.h` from a fixed template, so it records
  fewer macros than the autotools one even when the compiled result matches.
  Compare CMake builds using the compiler flags, not `options.h`.

## How these tables were checked

The legacy provider is unchanged in 4.0 and still carries MD2, MD4, MDC2,
Whirlpool, RIPEMD-160, Blowfish, CAST, DES, DESX, IDEA, RC2, RC4, RC5 and SEED
-- present in the binary, inert until the provider is loaded.

Every OpenSSL release named at the top was run and probed, not read about:
1.1.1w, 3.0.19, 3.1.8, 3.2.4, 3.3.7 and 3.5.8 in containers, 3.5.5 on the host.
The probes were `openssl list` (`-cipher-algorithms`, `-digest-algorithms`,
`-mac-algorithms`, `-kdf-algorithms`, `-signature-algorithms`, `-kem-algorithms`,
`-tls-groups`, `-providers`), `openssl ciphers -v 'ALL:@SECLEVEL=0'`, and
functional checks -- `openssl enc`, `dgst` and `genpkey` per algorithm -- since
listing an algorithm and being able to use it are different questions once
providers exist. 4.0 rows come from the 4.0.0 release notes and its shipped
`OSSL_PROVIDER-legacy` page, as no 4.0 build was available to run.

Re-run those probes against your own build before relying on a row. Several
entries are build-time choices a distribution can change -- `enable-ssl3`,
`enable-weak-ssl-ciphers`, `no-idea` and `no-cast` most of all. Debian's 1.1.1w,
for instance, ships RC2, RC4, Blowfish and SEED but not CAST5 or IDEA.

## Further reading

- `INSTALL` — platform-by-platform build notes
- `examples/configs/user_settings_openssl_compat.h` — the same feature set for
  IDE, RTOS and bare-metal builds with no configure step
- wolfSSL manual — <https://www.wolfssl.com/documentation/manuals/wolfssl/>
- Porting help and commercial licensing — support@wolfssl.com
