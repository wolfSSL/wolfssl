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
wolfSSL as of 3.6.6 no longer enables SSLv3 by default. By default, wolfSSL
disables static key cipher suites that use PSK, RSA, or ECDH without ephemeral
key exchange. Instead, wolfSSL enables cipher suites that provide perfect
forward secrecy (PFS) using ephemeral Diffie-Hellman (DH) or Elliptic Curve
(ECC) key exchange, both of which are enabled by default.

If you need to support legacy systems that require static key cipher suites,
you can enable them using one or more of these defines:

* `WOLFSSL_STATIC_DH`
* `WOLFSSL_STATIC_RSA`
* `WOLFSSL_STATIC_PSK`

**Important:** Static key cipher suites reduce security by eliminating perfect
forward secrecy. These cipher suites reuse the same long-term private key for
all session key exchanges. In contrast, PFS-enabled cipher suites (the wolfSSL
default) generate a new ephemeral key for each session, ensuring that
compromising a long-term key cannot decrypt past sessions.

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


# wolfSSL Release 5.8.2 (July 17, 2025)

Release 5.8.2 has been developed according to wolfSSL's development and QA
process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE: * wolfSSL is now GPLv3 instead of GPLv2
            * --enable-heapmath is deprecated
            * MD5 is now disabled by default


PR stands for Pull Request, and PR (NUMBER) references a GitHub pull request number where the code change was added.

## Vulnerabilities

* [Low] There is the potential for a fault injection attack on ECC and Ed25519 verify operations. In versions of wolfSSL 5.7.6 and later the --enable-faultharden option is available to help mitigate against potential fault injection attacks. The mitigation added in wolfSSL version 5.7.6 is to help harden applications relying on the results of the verify operations, such as when used with wolfBoot. If doing ECC or Ed25519 verify operations on a device at risk for fault injection attacks then --enable-faultharden could be used to help mitigate it. Thanks to Kevin from Fraunhofer AISEC for the report.

Hardening option added in PR https://github.com/wolfSSL/wolfssl/pull/8289


* [High CVE-2025-7395] When using WOLFSSL_SYS_CA_CERTS and WOLFSSL_APPLE_NATIVE_CERT_VALIDATION on an Apple platform, the native trust store verification routine overrides errors produced elsewhere in the wolfSSL certificate verification process including failures due to hostname matching/SNI, OCSP, CRL, etc. This allows any trusted cert chain to override other errors detected during chain verification that should have resulted in termination of the TLS connection. If building wolfSSL on versions after 5.7.6 and before 5.8.2 with use of the system CA support and the apple native cert validation feature enabled on Apple devices (on by default for non-macOS Apple targets when using autotools or CMake) we recommend updating to the latest version of wolfSSL. Thanks to Thomas Leong from ExpressVPN for the report.

Fixed in PR https://github.com/wolfSSL/wolfssl/pull/8833


* [Med. CVE-2025-7394] In the OpenSSL compatibility layer implementation, the function RAND_poll() was not behaving as expected and leading to the potential for predictable values returned from RAND_bytes() after fork() is called. This can lead to weak or predictable random numbers generated in applications that are both using RAND_bytes() and doing fork() operations. This only affects applications explicitly calling RAND_bytes() after fork() and does not affect any internal TLS operations. Although RAND_bytes() documentation in OpenSSL calls out not being safe for use with fork() without first calling RAND_poll(), an additional code change was also made in wolfSSL to make RAND_bytes() behave similar to OpenSSL after a fork() call without calling RAND_poll(). Now the Hash-DRBG used gets reseeded after detecting running in a new process. If making use of RAND_bytes() and calling fork() we recommend updating to the latest version of wolfSSL. Thanks to Per Allansson from Appgate for the report.

Fixed in the following PR’s
https://github.com/wolfSSL/wolfssl/pull/8849
https://github.com/wolfSSL/wolfssl/pull/8867
https://github.com/wolfSSL/wolfssl/pull/8898



* [Low CVE-2025-7396] In wolfSSL 5.8.0 the option of hardening the C implementation of Curve25519 private key operations was added with the addition of blinding support (https://www.wolfssl.com/curve25519-blinding-support-added-in-wolfssl-5-8-0/). In wolfSSL release 5.8.2 that blinding support is turned on by default in applicable builds. The blinding configure option is only for the base C implementation of Curve25519. It is not needed, or available with; ARM assembly builds, Intel assembly builds, and the small Curve25519 feature. While the attack would be very difficult to execute in practice, enabling blinding provides an additional layer of protection for devices that may be more susceptible to physical access or side-channel observation. Thanks to Arnaud Varillon, Laurent Sauvage, and Allan Delautre from Telecom Paris for the report.

Blinding enabled by default in PR https://github.com/wolfSSL/wolfssl/pull/8736


## New Features
* Multiple sessions are now supported in the sniffer due to the removal of a cached check. (PR #8723)
* New API ssl_RemoveSession() has been implemented for sniffer cleanup operations. (PR #8768)
* The new ASN X509 API, `wc_GetSubjectPubKeyInfoDerFromCert`, has been introduced for retrieving public key information from certificates. (PR #8758)
* `wc_PKCS12_create()` has been enhanced to support PBE_AES(256|128)_CBC key and certificate encryptions. (PR #8782, PR #8822, PR #8859)
* `wc_PKCS7_DecodeEncryptedKeyPackage()` has been added for decoding encrypted key packages. (PR #8976)
* All AES, SHA, and HMAC functionality has been implemented within the Linux Kernel Module. (PR #8998)
* Additions to the compatibility layer have been introduced for X.509 extensions and RSA PSS. Adding the API i2d_PrivateKey_bio, BN_ucmp and X509v3_get_ext_by_NID. (PR #8897)
* Added support for STM32N6. (PR #8914)
* Implemented SHA-256 for PPC 32 assembly. (PR #8894)

## Improvements / Optimizations

### Linux Kernel Module (LinuxKM) Enhancements
* Registered DH and FFDHE for the Linux Kernel Module. (PR #8707)
* Implemented fixes for standard RNG in the Linux Kernel Module. (PR #8718)
* Added an ECDSA workaround for the Linux Kernel Module. (PR #8727)
* Added more PKCS1 pad SHA variants for RSA in the Linux Kernel Module. (PR #8730)
* Set default priority to 100000 for LKCAPI in the Linux Kernel Module. (PR #8740)
* Ensured ECDH never has FIPS enabled in the Linux Kernel Module. (PR #8751)
* Implemented further Linux Kernel Module and SP tweaks. (PR #8773)
* Added sig_alg support for Linux 6.13 RSA in the Linux Kernel Module. (PR #8796)
* Optimized wc_linuxkm_fpu_state_assoc. (PR #8828)
* Ensured DRBG is multithread-round-1 in the Linux Kernel Module. (PR #8840)
* Prevented toggling of fips_enabled in the Linux Kernel Module. (PR #8873)
* Refactored drbg_ctx clear in the Linux Kernel Module. (PR #8876)
* Set sig_alg max_size and digest_size callbacks for RSA in the Linux Kernel Module. (PR #8915)
* Added get_random_bytes for the Linux Kernel Module. (PR #8943)
* Implemented distro fix for the Linux Kernel Module. (PR #8994)
* Fixed page-flags-h in the Linux Kernel Module. (PR #9001)
* Added MODULE_LICENSE for the Linux Kernel Module. (PR #9005)

### Post-Quantum Cryptography (PQC) & Asymmetric Algorithms
* Kyber has been updated to the MLKEM ARM file for Zephyr (PR #8781)
* Backward compatibility has been implemented for ML_KEM IDs (PR #8827)
* ASN.1 is now ensured to be enabled when only building PQ algorithms (PR #8884)
* Building LMS with verify-only has been fixed (PR #8913)
* Parameters for LMS SHA-256_192 have been corrected (PR #8912)
* State can now be saved with the private key for LMS (PR #8836)
* Support for OpenSSL format has been added for ML-DSA/Dilithium (PR #8947)
* `dilithium_coeff_eta2[]` has been explicitly declared as signed (PR #8955)

### Build System & Portability
* Prepared for the inclusion of v5.8.0 in the Ada Alire index. (PR #8714)
* Introduced a new build option to allow reuse of the Windows crypt provider handle. (PR #8706)
* Introduced general fixes for various build configurations. (PR #8763)
* Made improvements for portability using older GCC 4.8.2. (PR #8753)
* Macro guards updated to allow tests to build with opensslall and no server. (PR #8776)
* Added a check for STDC_NO_ATOMICS macro before use of atomics. (PR #8885)
* Introduced CMakePresets.json and CMakeSettings.json. (PR #8905)
* Added an option to not use constant time code with min/max. (PR #8830)
* Implemented proper MacOS dispatch for conditional signal/wait. (PR #8928)
* Disabled MD5 by default for both general and CMake builds. (PR #8895, PR #8948)
* Improved to allow building OPENSSL_EXTRA without KEEP_PEER_CERT. (PR #8926)
* Added introspection for Intel and ARM assembly speedups. (PR #8954)
* Fixed cURL config to set HAVE_EX_DATA and HAVE_ALPN. (PR #8973)
* Moved FREESCALE forced algorithm HAVE_ECC to IDE/MQX/user_settings.h. (PR #8977)

### Testing & Debugging
* Fixed the exit status for testwolfcrypt. (PR #8762)
* Added WOLFSSL_DEBUG_PRINTF and WOLFSSL_DEBUG_CERTIFICATE_LOADS for improved debugging output. (PR #8769, PR #8770)
* Guarded some benchmark tests with NO_SW_BENCH. (PR #8760)
* Added an additional unit test for wolfcrypt PKCS12 file to improve code coverage. (PR #8831)
* Added an additional unit test for increased DH code coverage. (PR #8837)
* Adjusted for warnings with NO_TLS build and added GitHub actions test. (PR #8851)
* Added additional compatibility layer RAND tests. (PR #8852)
* Added an API unit test for checking domain name. (PR #8863)
* Added bind v9.18.33 testing. (PR #8888)
* Fixed issue with benchmark help options and descriptions not lining up. (PR #8957)

### Certificates & ASN.1
* Changed the algorithm for sum in ASN.1 OIDs. (PR #8655)
* Updated PKCS7 to use X509 STORE for internal verification. (PR #8748)
* Improved handling of temporary buffer size for X509 extension printing. (PR #8710)
* Marked IP address as WOLFSSL_V_ASN1_OCTET_STRING for ALT_NAMES_OID. (PR #8842)
* Fixed printing empty names in certificates. (PR #8880)
* Allowed CA:FALSE on wolftpm. (PR #8925)
* Fixed several inconsistent function prototype parameter names in wc/asn. (PR #8949)
* Accounted for custom extensions when creating a Cert from a WOLFSSL_X509. (PR #8960)

### TLS/DTLS & Handshake
* Checked group correctness outside of TLS 1.3 too for TLSX_UseSupportedCurve. (PR #8785)
* Dropped records that span datagrams in DTLS. (PR #8642)
* Implemented WC_NID_netscape_cert_type. (PR #8800)
* Refactored GetHandshakeHeader/GetHandShakeHeader into one function. (PR #8787)
* Correctly set the current peer in dtlsProcessPendingPeer. (PR #8848)
* Fixed set_groups for TLS. (PR #8824)
* Allowed trusted_ca_keys with TLSv1.3. (PR #8860)
* Moved Dtls13NewEpoch into DeriveTls13Keys. (PR #8858)
* Cleared tls1_3 on downgrade. (PR #8861)
* Always sent ACKs on detected retransmission for DTLS1.3. (PR #8882)
* Removed DTLS from echo examples. (PR #8889)
* Recalculated suites at SSL initialization. (PR #8757)
* No longer using BIO for ALPN. (PR #8969)
* Fixed wolfSSL_BIO_new_connect's handling of IPV6 addresses. (PR #8815)
* Memory Management & Optimizations
* Performed small stack refactors, improved stack size with mlkem and dilithium, and added additional tests. (PR #8779)
* Implemented FREE_MP_INT_SIZE in heap math. (PR #8881)
* Detected correct MAX_ENCODED_SIG_SZ based on max support in math lib. (PR #8931)
* Fixed improper access of sp_int_minimal using sp_int. (PR #8985)

### Cryptography & Hash Functions
* Implemented WC_SIPHASH_NO_ASM for not using assembly optimizations with siphash. (PR #8789, PR #8791)
* Added missing DH_MAX_SIZE define for FIPS and corrected wolfssl.rc FILETYPE to VFT_DLL. (PR #8794)
* Implemented WC_SHA3_NO_ASM for not using assembly with SHA3. (PR #8817)
* Improved Aarch64 XFENCE. (PR #8832)
* Omitted frame pointer for ARM32/Thumb2/RISC-V 64 assembly. (PR #8893)
* Fixed branch instruction in ARMv7a ASM. (PR #8933)
* Enabled EVP HMAC to work with WOLFSSL_HMAC_COPY_HASH. (PR #8944)
* Platform-Specific & Hardware Integration
* Added HAVE_HKDF for wolfssl_test and explicit support for ESP32P4. (PR #8742)
* Corrected Espressif default time setting. (PR #8829)
* Made wc_tsip_* APIs public. (PR #8717)
* Improved PlatformIO Certificate Bundle Support. (PR #8847)
* Fixed the TSIP TLS example program. (PR #8857)
* Added crypto callback functions for TROPIC01 secure element. (PR #8812)
* Added Renesas RX TSIP AES CTR support. (PR #8854)
* Fixed TSIP port using crypto callback. (PR #8937)

### General Improvements & Refactoring
* Attempted wolfssl_read_bio_file in read_bio even when XFSEEK is available. (PR #8703)
* Refactored GetHandshakeHeader/GetHandShakeHeader into one function. (PR #8787)
* Updated libspdm from 3.3.0 to 3.7.0. (PR #8906)
* Fixed missing dashes on the end of header and footer for Falcon PEM key. (PR #8904)
* Fixed minor code typos for macos signal and types.h max block size. (PR #8934)
* Make the API wolfSSL_X509_STORE_CTX_get_error accessible to more build configurations for ease of getting the "store" error code and depth with certificate failure callback implementations. (PR #8903)

## Bug Fixes
* Fixed issues to support _WIN32_WCE (VS 2008 with WinCE 6.0/7.0). (PR #8709)
* Fixed STM32 Hash with IRQ enabled. (PR #8705)
* Fixed raw hash when using crypto instructions on RISC-V 64-bit. (PR #8733)
* Fixed ECDH decode secret in the Linux Kernel Module. (PR #8729)
* Passed in the correct hash type to wolfSSL_RSA_verify_ex. (PR #8726)
* Fixed issues for Intel QuickAssist latest driver (4.28). (PR #8728)
* Speculative fix for CodeSonar overflow issue in ssl_certman.c. (PR #8715)
* Fixed Arduino progmem print and AVR WOLFSSL_USER_IO. (PR #8668)
* Correctly advanced the index in wc_HKDF_Expand_ex. (PR #8737)
* Fixed STM32 hash status check logic, including NO_AES_192 and NO_AES_256. (PR #8732)
* Added missing call to wolfSSL_RefFree in FreeCRL to prevent memory leaks. (PR #8750)
* Fixed sanity check on --group with unit test app and null sanity check with des decrypt. (PR #8711)
* Fixed Curve25519 and static ephemeral issue with blinding. (PR #8766)
* Fixed edge case issue with STM32 AES GCM auth padding. (PR #8745)
* Removed redefinition of MlKemKey and fixed build issue in benchmark. (PR #8755)
* Used proper heap hint when freeing CRL in error case. (PR #8713)
* Added support for no malloc with wc_CheckCertSigPubKey. (PR #8725)
* Fixed C# wrapper Release build. (PR #8802)
* Handled malformed CCS and CCS before CH in TLS1.3. (PR #8788)
* Fixed ML-DSA with WOLFSSL_DILITHIUM_NO_SIGN. (PR #8798)
* Fixed AesGcmCrypt_1 no-stream in the Linux Kernel Module. (PR #8814)
* Fixed return value usage for crypto_sig_sign in the Linux Kernel Module. (PR #8816)
* Fixed issue with CSharp and Windows CE with conversion of ASCII and Unicode. (PR #8799)
* Fixed Renesas SCE on RA6M4. (PR #8838)
* Fixed tests for different configs for ML-DSA. (PR #8865)
* Fixed bug in ParseCRL_Extensions around the size of a CRL number handled and CRL number OID. (PR #8587)
* Fixed uninitialized wc_FreeRng in prime_test. (PR #8886)
* Fixed ECC configuration issues with ECC verify only and no RNG. (PR #8901)
* Fixed issues with max size, openssl.test netcat, and clang-tidy. (PR #8909)
* Fixed for casting down and uninit issues in Dilithium/ML-DSA. (PR #8868)
* Fixed memory allocation failure testing and related unit test cases. (PR #8945, PR #8952)
* Fixed build issue with ML-DSA 44 only. (PR #8981)
* Fixed possible memory leak with X509 reference counter when using x509small. (PR #8982)

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
