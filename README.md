<a href="https://repology.org/project/wolfssl/versions">
    <img src="https://repology.org/badge/vertical-allrepos/wolfssl.svg" alt="Packaging status" align="right">
</a>

# wolfSSL Embedded SSL/TLS Library

The [wolfSSL embedded SSL library](https://www.wolfssl.com/products/wolfssl/) 
(formerly CyaSSL) is a lightweight SSL/TLS library written in ANSI C and
targeted for embedded, RTOS, and resource-constrained environments - primarily
because of its small size, speed, and feature set.  It is commonly used in
standard operating environments as well because of its royalty-free pricing
and excellent cross platform support. wolfSSL supports industry standards up
to the current [TLS 1.3](https://www.wolfssl.com/tls13) and DTLS 1.2, is up to
20 times smaller than OpenSSL, and offers progressive ciphers such as ChaCha20,
Curve25519, Blake2b and Post-Quantum TLS 1.3 groups. User benchmarking and
feedback reports dramatically better performance when using wolfSSL over
OpenSSL.

wolfSSL is powered by the wolfCrypt cryptography library. Two versions of
wolfCrypt have been FIPS 140-2 validated (Certificate #2425 and
certificate #3389). FIPS 140-3 validation is in progress. For additional
information, visit the [wolfCrypt FIPS FAQ](https://www.wolfssl.com/license/fips/)
or contact fips@wolfssl.com.

## Why Choose wolfSSL?

There are many reasons to choose wolfSSL as your embedded, desktop, mobile, or
enterprise SSL/TLS solution. Some of the top reasons include size (typical
footprint sizes range from 20-100 kB), support for the newest standards
(SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, DTLS 1.0, and DTLS 1.2), current
and progressive cipher support (including stream ciphers), multi-platform,
royalty free, and an OpenSSL compatibility API to ease porting into existing
applications which have previously used the OpenSSL package. For a complete
feature list, see [Chapter 4](https://www.wolfssl.com/docs/wolfssl-manual/ch4/)
of the wolfSSL manual.

## Notes, Please Read

### Note 1
wolfSSL as of 3.6.6 no longer enables SSLv3 by default.  wolfSSL also no longer
supports static key cipher suites with PSK, RSA, or ECDH. This means if you
plan to use TLS cipher suites you must enable DH (DH is on by default), or
enable ECC (ECC is on by default), or you must enable static key cipher suites
with one or more of the following defines:

```
WOLFSSL_STATIC_DH
WOLFSSL_STATIC_RSA
WOLFSSL_STATIC_PSK
```
Though static key cipher suites are deprecated and will be removed from future
versions of TLS.  They also lower your security by removing PFS.

When compiling `ssl.c`, wolfSSL will now issue a compiler error if no cipher
suites are available. You can remove this error by defining
`WOLFSSL_ALLOW_NO_SUITES` in the event that you desire that, i.e., you're
not using TLS cipher suites.

### Note 2
wolfSSL takes a different approach to certificate verification than OpenSSL
does. The default policy for the client is to verify the server, this means
that if you don't load CAs to verify the server you'll get a connect error,
no signer error to confirm failure (-188).

If you want to mimic OpenSSL behavior of having `SSL_connect` succeed even if
verifying the server fails and reducing security you can do this by calling:

```c
wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
```

before calling `wolfSSL_new();`. Though it's not recommended.

### Note 3
The enum values SHA, SHA256, SHA384, SHA512 are no longer available when
wolfSSL is built with `--enable-opensslextra` (`OPENSSL_EXTRA`) or with the
macro `NO_OLD_SHA_NAMES`. These names get mapped to the OpenSSL API for a
single call hash function. Instead the name `WC_SHA`, `WC_SHA256`, `WC_SHA384` and
`WC_SHA512` should be used for the enum name.


# wolfSSL Release 5.2.0 (Feb 21, 2022)

## Vulnerabilities

* \[High\] A TLS v1.3 server who requires mutual authentication can be
  bypassed. If a malicious client does not send the certificate_verify
  message a client can connect without presenting a certificate even
  if the server requires one. Thank you to Aina Toky Rasoamanana and
  Olivier Levillain of Télécom SudParis.
* \[High\] A TLS v1.3 client attempting to authenticate a TLS v1.3
  server can have its certificate check bypassed. If the sig_algo in
  the certificate_verify message is different than the certificate
  message checking may be bypassed. Thank you to Aina Toky Rasoamanana and
  Olivier Levillain of Télécom SudParis.

## New Feature Additions

* Example applications for Renesas RX72N with FreeRTOS+IoT
* Renesas FSP 3.5.0 support for RA6M3
* For TLS 1.3, improved checks on order of received messages.
* Support for use of SHA-3 cryptography instructions available in
  ARMv8.2-A architecture extensions. (For Apple M1)
* Support for use of SHA-512 cryptography instructions available in
  ARMv8.2-A architecture extensions.  (For Apple M1)
* Fixes for clang -Os on clang >= 12.0.0
* Expose Sequence Numbers so that Linux TLS (kTLS) can be configured
* Fix bug in TLSX_ALPN_ParseAndSet when using ALPN select callback.
* Allow DES3 with FIPS v5-dev.
* Include HMAC for deterministic ECC sign build
* Add --enable-chrony configure option. This sets build options needed
  to build the Chrony NTP (Network Time Protocol) service.
* Add support for STM32U575xx boards.
* Fixes for NXP’s SE050 Ed25519/Curve25519.
* TLS: Secure renegotiation info on by default for compatibility.
* Inline C code version of ARM32 assembly for cryptographic algorithms
  available and compiling for improved performance on ARM platforms
* Configure HMAC: define NO_HMAC to disable HMAC (default: enabled)
* ISO-TP transport layer support added to wolfio for TLS over CAN Bus
* Fix initialization bug in SiLabs AES support
* Domain and IP check is only performed on leaf certificates

## ARM PSA Support (Platform Security Architecture) API

* Initial support added for ARM’s Platform Security Architecture (PSA)
  API in wolfCrypt which allows support of ARM PSA enabled devices by
  wolfSSL, wolfSSH, and wolfBoot and wolfCrypt FIPS.
* Included algorithms: ECDSA, ECDH, HKDF, AES, SHA1, SHA256, SHA224, RNG

## ECICE Updates

* Support for more encryption algorithms: AES-256-CBC, AES-128-CTR,
  AES-256-CTR
* Support for compressed public keys in messages.

## Math Improvements

* Improved performance of X448 and Ed448 through inlining Karatsuba in
  square and multiplication operations for 128-bit implementation
  (64-bit platforms with 128-bit type support).
* SP Math C implementation: fix for corner case in curve specific
  implementations of Montgomery Reduction (P-256, P-384).
* SP math all: assembly snippets added for ARM Thumb. Performance
  improvement on platform.
* SP math all: ARM64/32 sp_div_word assembly snippets added to remove
  dependency on __udiv3.
* SP C implementation: multiplication of two signed types with overflow
  is undefined in C. Now cast to unsigned type before multiplication is
  performed.
* SP C implementation correctly builds when using CFLAG: -m32

## OpenSSL Compatibility Layer

* Added DH_get_2048_256 to compatibility layer.
* wolfSSLeay_version now returns the version of wolfSSL
* Added C++ exports for API’s in wolfssl/openssl/crypto.h. This allows
  better compatibility when building with a C++ compiler.
* Fix for OpenSSL x509_NAME_hash mismatch
* Implement FIPS_mode and FIPS_mode_set in the compat layer.
* Fix for certreq and certgen options with openssl compatibility
* wolfSSL_BIO_dump() and wolfSSL_OBJ_obj2txt() rework
* Fix IV length bug in EVP AES-GCM code.
* Add new ASN1_INTEGER compatibility functions.
* Fix wolfSSL_PEM_X509_INFO_read with NO_FILESYSTEM

## CMake Updates

* Check for valid override values.
* Add `KEYGEN` option.
* Cleanup help messages.
* Add options to support wolfTPM.

## VisualStudio Updates

* Remove deprecated VS solution
* Fix VS unreachable code warning

## New Algorithms and Protocols

* AES-SIV (RFC 5297)
* DTLS SRTP (RFC 5764), used with WebRTC to agree on profile for new
  real-time session keys
* SipHash MAC/PRF for hash tables. Includes inline assembly for
  x86_64 and Aarch64.

## Remove Obsolete Algorithms

* IDEA
* Rabbit
* HC-128

If this adversely affects you or your customers, please get in cotact with the wolfSSL team. (support@wolfssl.com)

For additional vulnerability information visit the vulnerability page at:
https://www.wolfssl.com/docs/security-vulnerabilities/

See INSTALL file for build instructions.
More info can be found on-line at: https://wolfssl.com/wolfSSL/Docs.html



# Resources

[wolfSSL Website](https://www.wolfssl.com/)

[wolfSSL Wiki](https://github.com/wolfSSL/wolfssl/wiki)

[FIPS 140-2/140-3 FAQ](https://wolfssl.com/license/fips)

[wolfSSL Documentation](https://wolfssl.com/wolfSSL/Docs.html)

[wolfSSL Manual](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-toc.html)

[wolfSSL API Reference](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-17-wolfssl-api-reference.html)

[wolfCrypt API Reference](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-18-wolfcrypt-api-reference.html)

[TLS 1.3](https://www.wolfssl.com/docs/tls13/)

[wolfSSL Vulnerabilities](https://www.wolfssl.com/docs/security-vulnerabilities/)

[Additional wolfSSL Examples](https://github.com/wolfssl/wolfssl-examples)
