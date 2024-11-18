# wolfSSL Embedded SSL/TLS Library

The [wolfSSL embedded SSL library](https://www.wolfssl.com/products/wolfssl/)
(formerly CyaSSL) is a lightweight SSL/TLS library written in ANSI C and
targeted for embedded, RTOS, and resource-constrained environments - primarily
because of its small size, speed, and feature set.  It is commonly used in
standard operating environments as well because of its royalty-free pricing
and excellent cross platform support. wolfSSL supports industry standards up
to the current [TLS 1.3](https://www.wolfssl.com/tls13) and DTLS 1.3, is up to
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
(SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, DTLS 1.0, DTLS 1.2, and DTLS 1.3),
current and progressive cipher support (including stream ciphers), multi-platform,
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


# wolfSSL Release 5.7.4 (Oct 24, 2024)

Release 5.7.4 has been developed according to wolfSSL's development and QA
process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE: * --enable-heapmath is being deprecated and will be removed by end of 2024

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request
 number where the code change was added.


## Vulnerabilities
* [Low] When the OpenSSL compatibility layer is enabled, certificate
 verification behaved differently in wolfSSL than OpenSSL, in the
 X509_STORE_add_cert() and X509_STORE_load_locations() implementations.
 Previously, in cases where an application explicitly loaded an intermediate
 certificate, wolfSSL was verifying only up to that intermediate certificate,
 rather than verifying up to the root CA. This only affects use cases where the
 API is called directly, and does not affect TLS connections. Users that call
 the API X509_STORE_add_cert() or X509_STORE_load_locations() directly in their
 applications are recommended to update the version of wolfSSL used or to have
 additional sanity checks on certificates loaded into the X509_STORE when
 verifying a certificate. (https://github.com/wolfSSL/wolfssl/pull/8087)


## PQC TLS Experimental Build Fix
* When using TLS with post quantum algorithms enabled, the connection uses a
 smaller EC curve than agreed on. Users building with --enable-experimental and
 enabling PQC cipher suites with TLS connections are recommended to update the
 version of wolfSSL used. Thanks to Daniel Correa for the report.
 (https://github.com/wolfSSL/wolfssl/pull/8084)


## New Feature Additions
* RISC-V 64 new assembly optimizations added for SHA-256, SHA-512, ChaCha20,
 Poly1305, and SHA-3 (PR 7758,7833,7818,7873,7916)
* Implement support for Connection ID (CID) with DTLS 1.2 (PR 7995)
* Add support for (DevkitPro)libnds (PR 7990)
* Add port for Mosquitto OSP (Open Source Project) (PR 6460)
* Add port for init sssd (PR 7781)
* Add port for eXosip2 (PR 7648)
* Add support for STM32G4 (PR 7997)
* Add support for MAX32665 and MAX32666 TPU HW and ARM ASM Crypto Callback
 Support (PR 7777)
* Add support for building wolfSSL to be used in libspdm (PR 7869)
* Add port for use with Nucleus Plus 2.3 (PR 7732)
* Initial support for RFC5755 x509 attribute certificates (acerts). Enabled with
 --enable-acert (PR 7926)
* PKCS#11 RSA Padding offload allows tokens to perform CKM_RSA_PKCS
 (sign/encrypt), CKM_RSA_PKCS_PSS (sign), and CKM_RSA_PKCS_OAEP (encrypt).
 (PR 7750)
* Added “new” and “delete” style functions for heap/pool allocation and freeing
 of low level crypto structures (PR 3166 and 8089)


## Enhancements and Optimizations
* Increase default max alt. names from 128 to 1024 (PR 7762)
* Added new constant time DH agree function wc_DhAgree_ct (PR 7802)
* Expanded compatibility layer with the API EVP_PKEY_is_a (PR 7804)
* Add option to disable cryptocb test software test using
 --disable-cryptocb-sw-test (PR 7862)
* Add a call to certificate verify callback before checking certificate dates
 (PR 7895)
* Expanded algorithms supported with the wolfCrypt CSharp wrapper. Adding
 support for RNG, ECC(ECIES and ECDHE), RSA, ED25519/Curve25519, AES-GCM, and
 Hashing (PR 3166)
* Expand MMCAU support for use with DES ECB (PR 7960)
* Update AES SIV to handle multiple associated data inputs (PR 7911)
* Remove HAVE_NULL_CIPHER from --enable-openssh (PR 7811)
* Removed duplicate if(NULL) checks when calling XFREE (macro does) (PR 7839)
* Set RSA_MIN_SIZE default to 2048 bits (PR 7923)
* Added support for wolfSSL to be used as the default TLS in the zephyr kernel
 (PR 7731)
* Add enable provider build using --enable-wolfprovider with autotools (PR 7550)
* Renesas RX TSIP ECDSA support (PR 7685)
* Support DTLS1.3 downgrade when the server supports CID (PR 7841)
* Server-side checks OCSP even if it uses v2 multi (PR 7828)
* Add handling of absent hash params in PKCS7 bundle parsing and creation
 (PR 7845)
* Add the use of w64wrapper for Poly1305, enabling Poly1305 to be used in
 environments that do not have a word64 type (PR 7759)
* Update to the maxq10xx support (PR 7824)
* Add support for parsing over optional PKCS8 attributes (PR 7944)
* Add support for either side method with DTLS 1.3 (PR 8012)
* Added PKCS7 PEM support for parsing PEM data with BEGIN/END PKCS7 (PR 7704)
* Add CMake support for WOLFSSL_CUSTOM_CURVES (PR 7962)
* Add left-most wildcard matching support to X509_check_host() (PR 7966)
* Add option to set custom SKID with PKCS7 bundle creation (PR 7954)
* Building wolfSSL as a library with Ada and corrections to Alire manifest
 (PR 7303,7940)
* Renesas RX72N support updated (PR 7849)
* New option WOLFSSL_COPY_KEY added to always copy the key to the SSL object
 (PR 8005)
* Add the new option WOLFSSL_COPY_CERT to always copy the cert buffer for each
 SSL object (PR 7867)
* Add an option to use AES-CBC with HMAC for default session ticket enc/dec.
 Defaults to AES-128-CBC with HMAC-SHA256 (PR 7703)
* Memory usage improvements in wc_PRF, sha256 (for small code when many
 registers are available) and sp_int objects (PR 7901)
* Change in the configure script to work around ">>" with no command. In older
 /bin/sh it can be ambiguous, as used in OS’s such as FreeBSD 9.2 (PR 7876)
* Don't attempt to include system headers when not required (PR 7813)
* Certificates: DER encoding of ECC signature algorithm parameter is now
 allowed to be NULL with a define (PR 7903)
* SP x86_64 asm: check for AVX2 support for VMs (PR 7979)
* Update rx64n support on gr-rose (PR 7889)
* Update FSP version to v5.4.0 for RA6M4 (PR 7994)
* Update TSIP driver version to v1.21 for RX65N RSK (PR 7993)
* Add a new crypto callback for RSA with padding (PR 7907)
* Replaced the use of pqm4 with wolfSSL implementations of Kyber/MLDSA
 (PR 7924)
* Modernized memory fence support for C11 and clang (PR 7938)
* Add a CRL error override callback (PR 7986)
* Extend the X509 unknown extension callback for use with a user context
 (PR 7730)
* Additional debug error tracing added with TLS (PR 7917)
* Added runtime support for library call stack traces with
 –enable-debug-trace-errcodes=backtrace, using libbacktrace (PR 7846)
* Expanded C89 conformance (PR 8077)
* Expanded support for WOLFSSL_NO_MALLOC (PR 8065)
* Added support for cross-compilation of Linux kernel module (PR 7746)
* Updated Linux kernel module with support for kernel 6.11 and 6.12 (PR 7826)
* Introduce WOLFSSL_ASN_ALLOW_0_SERIAL to allow parsing of certificates with a
 serial number of 0 (PR 7893)
* Add conditional repository_owner to all wolfSSL GitHub workflows (PR 7871)

### Espressif / Arduino Updates
* Update wolfcrypt settings.h for Espressif ESP-IDF, template update (PR 7953)
* Update Espressif sha, util, mem, time helpers (PR 7955)
* Espressif _thread_local_start and _thread_local_end fix (PR 8030)
* Improve benchmark for Espressif devices (PR 8037)
* Introduce Espressif common CONFIG_WOLFSSL_EXAMPLE_NAME, Kconfig (PR 7866)
* Add wolfSSL esp-tls and Certificate Bundle Support for Espressif ESP-IDF
 (PR 7936)
* Update wolfssl Release for Arduino (PR 7775)

### Post Quantum Crypto Updates
* Dilithium: support fixed size arrays in dilithium_key (PR 7727)
* Dilithium: add option to use precalc with small sign (PR 7744)
* Allow Kyber to be built with FIPS (PR 7788)
* Allow Kyber asm to be used in the Linux kernel module (PR 7872)
* Dilithium, Kyber: Update to final specification (PR 7877)
* Dilithium: Support FIPS 204 Draft and Final Draft (PR 7909,8016)

### ARM Assembly Optimizations
* ARM32 assembly optimizations added for ChaCha20 and Poly1305 (PR 8020)
* Poly1305 assembly optimizations improvements for Aarch64 (PR 7859)
* Poly1305 assembly optimizations added for Thumb-2 (PR 7939)
* Adding ARM ASM build option to STM32CubePack (PR 7747)
* Add ARM64 to Visual Studio Project (PR 8010)
* Kyber assembly optimizations for ARM32 and Aarch64 (PR 8040,7998)
* Kyber assembly optimizations for ARMv7E-M/ARMv7-M (PR 7706)


## Fixes
* ECC key load: fixes for certificates with parameters that are not default for
 size (PR 7751)
* Fixes for building x86 in Visual Studio for non-windows OS (PR 7884)
* Fix for TLS v1.2 secret callback, incorrectly detecting bad master secret
 (PR 7812)
* Fixes for PowerPC assembly use with Darwin and SP math all (PR 7931)
* Fix for detecting older versions of Mac OS when trying to link with
 libdispatch (PR 7932)
* Fix for DTLS1.3 downgrade to DTLS1.2 when the server sends multiple handshake
 packets combined into a single transmission. (PR 7840)
* Fix for OCSP to save the request if it was stored in ssl->ctx->certOcspRequest
 (PR 7779)
* Fix to OCSP for searching for CA by key hash instead of ext. key id (PR 7934)
* Fix for staticmemory and singlethreaded build (PR 7737)
* Fix to not allow Shake128/256 with Xilinx AFALG (PR 7708)
* Fix to support PKCS11 without RSA key generation (PR 7738)
* Fix not calling the signing callback when using PK callbacks + TLS 1.3
 (PR 7761)
* Cortex-M/Thumb2 ASM fix label for IAR compiler (PR 7753)
* Fix with PKCS11 to iterate correctly over slotId (PR 7736)
* Stop stripping out the sequence header on the AltSigAlg extension (PR 7710)
* Fix ParseCRL_AuthKeyIdExt with ASN template to set extAuthKeyIdSet value
 (PR 7742)
* Use max key length for PSK encrypt buffer size (PR 7707)
* DTLS 1.3 fix for size check to include headers and CID fixes (PR 7912,7951)
* Fix STM32 Hash FIFO and add support for STM32U5A9xx (PR 7787)
* Fix CMake build error for curl builds (PR 8021)
* SP Maths: PowerPC ASM fix to use XOR instead of LI (PR 8038)
* SSL loading of keys/certs: testing and fixes (PR 7789)
* Misc. fixes for Dilithium and Kyber (PR 7721,7765,7803,8027,7904)
* Fixes for building wolfBoot sources for PQ LMS/XMSS (PR 7868)
* Fixes for building with Kyber enabled using CMake and zephyr port (PR 7773)
* Fix for edge cases with session resumption with TLS 1.2 (PR 8097)
* Fix issue with ARM ASM with AES CFB/OFB not initializing the "left" member
 (PR 8099)

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

# Directory structure

```
<wolfssl_root>
├── certs   [Certificates used in tests and examples]
├── cmake   [Cmake build utilities]
├── debian  [Debian packaging files]
├── doc     [Documentation for wolfSSL (Doxygen)]
├── Docker  [Prebuilt Docker environments]
├── examples    [wolfSSL examples]
│   ├── asn1    [ASN.1 printing example]
│   ├── async   [Asynchronous Cryptography example]
│   ├── benchmark   [TLS benchmark example]
│   ├── client  [Client example]
│   ├── configs [Example build configurations]
│   ├── echoclient  [Echoclient example]
│   ├── echoserver  [Echoserver example]
│   ├── pem [Example for convert between PEM and DER]
│   ├── sctp    [Servers and clients that demonstrate wolfSSL's DTLS-SCTP support]
│   └── server  [Server example]
├── IDE     [Contains example projects for various development environments]
├── linuxkm [Linux Kernel Module implementation]
├── m4      [Autotools utilities]
├── mcapi   [wolfSSL MPLAB X Project Files]
├── mplabx  [wolfSSL MPLAB X Project Files]
├── mqx     [wolfSSL Freescale CodeWarrior Project Files]
├── rpm     [RPM packaging metadata]
├── RTOS
│   └── nuttx   [Port of wolfSSL for NuttX]
├── scripts [Testing scripts]
├── src     [wolfSSL source code]
├── sslSniffer  [wolfSSL sniffer can be used to passively sniff SSL traffic]
├── support [Contains the pkg-config file]
├── tests   [Unit and configuration testing]
├── testsuite   [Test application that orchestrates tests]
├── tirtos  [Port of wolfSSL for TI RTOS]
├── wolfcrypt   [The wolfCrypt component]
│   ├── benchmark   [Cryptography benchmarking application]
│   ├── src         [wolfCrypt source code]
│   │   └── port    [Supported hardware acceleration ports]
│   └── test        [Cryptography testing application]
├── wolfssl [Header files]
│   ├── openssl [Compatibility layer headers]
│   └── wolfcrypt   [Header files]
├── wrapper [wolfSSL language wrappers]
└── zephyr  [Port of wolfSSL for Zephyr RTOS]
```
