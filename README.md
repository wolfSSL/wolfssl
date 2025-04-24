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
certificate #3389). FIPS 140-3 validated (Certificate #4718). For additional
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


# wolfSSL Release 5.8.0 (Apr 24, 2025)

Release 5.8.0 has been developed according to wolfSSL's development and QA
process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE: * --enable-heapmath is deprecated

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request
 number where the code change was added.


## New Feature Additions
* Algorithm registration in the Linux kernel module for all supported FIPS AES,
 SHA, HMAC, ECDSA, ECDH, and RSA modes, key sizes, and digest sizes.
* Implemented various fixes to support building for Open Watcom including OS/2
 support and Open Watcom 1.9 compatibility (PR 8505, 8484)
* Added support for STM32H7S (tested on NUCLEO-H7S3L8) (PR 8488)
* Added support for STM32WBA (PR 8550)
* Added Extended Master Secret Generation Callback to the --enable-pkcallbacks
 build (PR 8303)
* Implement AES-CTS (configure flag --enable-aescts) in wolfCrypt (PR 8594)
* Added support for libimobiledevice commit 860ffb (PR 8373)
* Initial ASCON hash256 and AEAD128 support based on NIST SP 800-232 IPD
 (PR 8307)
* Added blinding option when using a Curve25519 private key by defining the
 macro WOLFSSL_CURVE25519_BLINDING (PR 8392)


## Linux Kernel Module
* Production-ready LKCAPI registration for cbc(aes), cfb(aes), gcm(aes),
 rfc4106 (gcm(aes)), ctr(aes), ofb(aes), and ecb(aes), ECDSA with P192, P256,
 P384, and P521 curves, ECDH with P192, P256, and P384 curves, and RSA with
 bare and PKCS1 padding
* Various fixes for LKCAPI wrapper for AES-CBC and AES-CFB (PR 8534, 8552)
* Adds support for the legacy one-shot AES-GCM back end (PR 8614, 8567) for
 compatibility with FIPS 140-3 Cert #4718.
* On kernel >=6.8, for CONFIG_FORTIFY_SOURCE, use 5-arg fortify_panic() override
 macro (PR 8654)
* Update calls to scatterwalk_map() and scatterwalk_unmap() for linux commit
 7450ebd29c (merged for Linux 6.15) (PR 8667)
* Inhibit LINUXKM_LKCAPI_REGISTER_ECDH on kernel <5.13 (PR 8673)
* Fix for uninitialized build error with fedora (PR 8569)
* Register ecdsa, ecdh, and rsa for use with linux kernel crypto (PR 8637, 8663,
 8646)
* Added force zero shared secret buffer, and clear of old key with ecdh
 (PR 8685)
* Update fips-check.sh script to pickup XTS streaming support on aarch64 and
 disable XTS-384 as an allowed use in FIPS mode (PR 8509, 8546)


## Enhancements and Optimizations

### Security & Cryptography
* Add constant-time implementation improvements for encoding functions. We thank
 Zhiyuan and Gilles for sharing a new constant-time analysis tool (CT-LLVM) and
 reporting several non-constant-time implementations. (PR 8396, 8617)
* Additional support for PKCS7 verify and decode with indefinite lengths
 (PR 8520, 834, 8645)
* Add more PQC hybrid key exchange algorithms such as support for combinations
 with X25519 and X448 enabling compatibility with the PQC key exchange support
 in Chromium browsers and Mozilla Firefox (PR 7821)
* Add short-circuit comparisons to DH key validation for RFC 7919 parameters
 (PR 8335)
* Improve FIPS compatibility with various build configurations for more resource
 constrained builds (PR 8370)
* Added option to disable ECC public key order checking (PR 8581)
* Allow critical alt and basic constraints extensions (PR 8542)
* New codepoint for MLDSA to help with interoperability (PR 8393)
* Add support for parsing trusted PEM certs having the header
 “BEGIN_TRUSTED_CERT” (PR 8400)
* Add support for parsing only of DoD certificate policy and Comodo Ltd PKI OIDs
 (PR 8599, 8686)
* Update ssl code in `src/*.c` to be consistent with wolfcrypt/src/asn.c
 handling of ML_DSA vs Dilithium and add dual alg. test (PR 8360, 8425)

### Build System, Configuration, CI & Protocols
* Internal refactor for include of config.h and when building with
 BUILDING_WOLFSSL macro. This refactor will give a warning of “deprecated
 function” when trying to improperly use an internal API of wolfSSL in an
 external application. (PR 8640, 8647, 8660, 8662, 8664)
* Add WOLFSSL_CLU option to CMakeLists.txt (PR 8548)
* Add CMake and Zephyr support for XMSS and LMS (PR 8494)
* Added GitHub CI for CMake builds (PR 8439)
* Added necessary macros when building wolfTPM Zephyr with wolfSSL (PR 8382)
* Add MSYS2 build continuous integration test (PR 8504)
* Update DevKitPro doc to list calico dependency with build commands (PR 8607)
* Conversion compiler warning fixes and additional continuous integration test
 added (PR 8538)
* Enable DTLS 1.3 by default in --enable-jni builds (PR 8481)
* Enabled TLS 1.3 middlebox compatibility by default for --enable-jni builds
 (PR 8526)

### Performance Improvements
* Performance improvements AES-GCM and HMAC (in/out hash copy) (PR 8429)
* LMS fixes and improvements adding API to get Key ID from raw private key,
 change to identifiers to match standard, and fix for when
 WOLFSSL_LMS_MAX_LEVELS is 1 (PR 8390, 8684, 8613, 8623)
* ML-KEM/Kyber improvements and fixes; no malloc builds, small memory usage,
 performance improvement, fix for big-endian (PR 8397, 8412, 8436, 8467, 8619,
 8622, 8588)
* Performance improvements for AES-GCM and when doing multiple HMAC operations
 (PR 8445)

### Assembly and Platform-Specific Enhancements
* Poly1305 arm assembly changes adding ARM32 NEON implementation and fix for
 Aarch64 use (PR 8344, 8561, 8671)
* Aarch64 assembly enhancement to use more CPU features, fix for FreeBSD/OpenBSD
 (PR 8325, 8348)
* Only perform ARM assembly CPUID checks if support was enabled at build time
 (PR 8566)
* Optimizations for ARM32 assembly instructions on platforms less than ARMv7
 (PR 8395)
* Improve MSVC feature detection for static assert macros (PR 8440)
* Improve Espressif make and CMake for ESP8266 and ESP32 series (PR 8402)
* Espressif updates for Kconfig, ESP32P4 and adding a sample user_settings.h
 (PR 8422, PR 8641)

### OpenSSL Compatibility Layer
* Modification to the push/pop to/from in OpenSSL compatibility layer. This is
 a pretty major API change in the OpenSSL compatibility stack functions.
 Previously the API would push/pop from the beginning of the list but now they
 operate on the tail of the list. This matters when using the sk_value with
 index values. (PR 8616)
* OpenSSL Compat Layer: OCSP response improvements (PR 8408, 8498)
* Expand the OpenSSL compatibility layer to include an implementation of
 BN_CTX_get (PR 8388)

### API Additions and Modifications
* Refactor Hpke to allow multiple uses of a context instead of just one shot
 mode (PR 6805)
* Add support for PSK client callback with Ada and use with Alire (thanks
 @mgrojo, PR 8332, 8606)
* Change wolfSSL_CTX_GenerateEchConfig to generate multiple configs and add
 functions wolfSSL_CTX_SetEchConfigs and wolfSSL_CTX_SetEchConfigsBase64 to
 rotate the server's echConfigs (PR 8556)
* Added the public API wc_PkcsPad to do PKCS padding (PR 8502)
* Add NULL_CIPHER_TYPE support to wolfSSL_EVP_CipherUpdate (PR 8518)
* Update Kyber APIs to ML-KEM APIs (PR 8536)
* Add option to disallow automatic use of "default" devId using the macro
 WC_NO_DEFAULT_DEVID (PR 8555)
* Detect unknown key format on ProcessBufferTryDecode() and handle RSA-PSSk
 format (PR 8630)

### Porting and Language Support
* Update Python port to support version 3.12.6 (PR 8345)
* New additions for MAXQ with wolfPKCS11 (PR 8343)
* Port to ntp 4.2.8p17 additions (PR 8324)
* Add version 0.9.14 to tested libvncserver builds (PR 8337)

### General Improvements and Cleanups
* Cleanups for STM32 AES GCM (PR 8584)
* Improvements to isascii() and the CMake key log option (PR 8596)
* Arduino documentation updates, comments and spelling corrections (PR 8381,
 8384, 8514)
* Expanding builds with WOLFSSL_NO_REALLOC for use with --enable-opensslall and
 --enable-all builds (PR 8369, 8371)


## Fixes
* Fix a use after free caused by an early free on error in the X509 store
 (PR 8449)
* Fix to account for existing PKCS8 header with
 wolfSSL_PEM_write_PKCS8PrivateKey (PR 8612)
* Fixed failing CMake build issue when standard threads support is not found in
 the system (PR 8485)
* Fix segmentation fault in SHA-512 implementation for AVX512 targets built with
 gcc -march=native -O2 (PR 8329)
* Fix Windows socket API compatibility warning with mingw32 build (PR 8424)
* Fix potential null pointer increments in cipher list parsing (PR 8420)
* Fix for possible stack buffer overflow read with wolfSSL_SMIME_write_PKCS7.
 Thanks to the team at Code Intelligence for the report. (PR 8466)
* Fix AES ECB implementation for Aarch64 ARM assembly (PR 8379)
* Fixed building with VS2008 and .NET 3.5 (PR 8621)
* Fixed possible error case memory leaks in CRL and EVP_Sign_Final (PR 8447)
* Fixed SSL_set_mtu compatibility function return code (PR 8330)
* Fixed Renesas RX TSIP (PR 8595)
* Fixed ECC non-blocking tests (PR 8533)
* Fixed CMake on MINGW and MSYS (PR 8377)
* Fixed Watcom compiler and added new CI test (PR 8391)
* Fixed STM32 PKA ECC 521-bit support (PR 8450)
* Fixed STM32 PKA with P521 and shared secret (PR 8601)
* Fixed crypto callback macro guards with `DEBUG_CRYPTOCB` (PR 8602)
* Fix outlen return for RSA private decrypt with WOLF_CRYPTO_CB_RSA_PAD
 (PR 8575)
* Additional sanity check on r and s lengths in DecodeECC_DSA_Sig_Bin (PR 8350)
* Fix compat. layer ASN1_TIME_diff to accept NULL output params (PR 8407)
* Fix CMake lean_tls build (PR 8460)
* Fix for QUIC callback failure (PR 8475)
* Fix missing alert types in AlertTypeToString for print out with debugging
 enabled (PR 8572)
* Fixes for MSVS build issues with PQC configure (PR 8568)
* Fix for SE050 port and minor improvements (PR 8431, 8437)
* Fix for missing rewind function in zephyr and add missing files for compiling
 with assembly optimizations (PR 8531, 8541)
* Fix for quic_record_append to return the correct code (PR 8340, 8358)
* Fixes for Bind 9.18.28 port (PR 8331)
* Fix to adhere more closely with RFC8446 Appendix D and set haveEMS when
 negotiating TLS 1.3 (PR 8487)
* Fix to properly check for signature_algorithms from the client in a TLS 1.3
 server (PR 8356)
* Fix for when BIO data is less than seq buffer size. Thanks to the team at Code
 Intelligence for the report (PR 8426)
* ARM32/Thumb2 fixes for WOLFSSL_NO_VAR_ASSIGN_REG and td4 variable declarations
 (PR 8590, 8635)
* Fix for Intel AVX1/SSE2 assembly to not use vzeroupper instructions unless ymm
 or zmm registers are used (PR 8479)
* Entropy MemUse fix for when block size less than update bits (PR 8675)

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
