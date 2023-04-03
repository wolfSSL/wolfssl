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


# wolfSSL Release 5.6.0 (Mar 24, 2023)

Release 5.6.0 has been developed according to wolfSSL's development and QA process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE: * --enable-heapmath is being deprecated and will be removed by 2024
      * This release makes ASN Template the default with ./configure, the previous ASN parsing can be built with --enable-asn=original

Release 5.6.0 of wolfSSL embedded TLS has bug fixes and new features including:

## New Feature Additions

* ASN template is now the default ASN parsing implementation when compiling with configure
* Added in support for TLS v1.3 Encrypted Client Hello (ECH) and HPKE (Hybrid Public Key Encryption)
* DTLS 1.3 stateless server ClientHello parsing support added

### Ports
* Add RX64/RX71 SHA hardware support
* Port to RT1170 and expand NXP CAAM driver support
* Add NuttX integration files for ease of use
* Updated Stunnel support for version 5.67
Compatibility Layer
* Add in support for AES-CCM with EVP
* BN compatibility API refactoring and separate API created
* Expanding public key type cipher suite list strings support

### Misc.
* Support pthread_rwlock and add enable option
* Add wolfSSL_CertManagerLoadCABuffer_ex() that takes a user certificate chain flag and additional verify flag options
* Docker build additions for wolfSSL library and wolfCLU application
* Add favorite drink pilot attribute type to get it from the encoding
* Added in support for indefinite length BER parsing with PKCS12
* Add dynamic session cache which allocates sessions from the heap with macro SESSION_CACHE_DYNAMIC_MEM


## Improvements / Optimizations

### Tests
* Additional CI (continuous integration) testing and leveraging of GitHub workflows
* Add CI testing for wpa_supplicant, OpenWrt and OpenVPN using GitHub workflows
* Add compilation of Espressif to GitHub workflows tests
* Refactoring and improving error results with wolfCrypt unit test application
* Minor warning fixes from Coverity static analysis scan
* Add new SHA-512/224 and SHA-512/256 tests
* Used codespell and fixed some minor typos

### Ports
* Improve TLS1.2 client authentication to use TSIP
* Updated Kyber macro to be WOLFSSL_HAVE_KYBER and made changes that make Kyber work on STM32
* AES-GCM Windows assembly additions
* CRLF line endings, trailing spaces for C# Wrapper Projects
Compatibility Layer
* Update `PubKey` and `Key` PEM-to-DER APIs to support return of needed DER size
* Allow reading ENC EC PRIVATE KEY as well via wolfSSL_PEM_read_bio_ECPrivateKey
* Improve wolfSSL_EC_POINT_cmp to handle Jacobian ordinates
* Fix issue with BIO_reset() and add BIO_FLAGS_MEM_RDONLY flag support for read only BIOs

### SP
* In SP math library rework mod 3 and use count leading zero instruction
* Fix with SP ECC sign to reject the random k generated when r is 0
* With SP math add better detection of when add won't work and double is needed with point_add_qz1 internal function
* With SP int fail when buffer writing to is too small for number rather than discarding the extra values

### Builds
* Define WOLFSSL_SP_SMALL_STACK if wolfSSL is build with --enable-smallstack
* Fix CMake to exclude libm when DH is not enabled
* Allow building of SAKKE as external non-FIPS algorithm with wolfmikey product
* Add option to add library suffix, --with-libsuffix
* ASN template compile option WOLFSSL_ASN_INT_LEAD_0_ANY to allow leading zeros
* Add user_settings.h template for wolfTPM to examples/configs/user_settings_wolftpm.h
* Purge the AES variant of Dilithium
* Expand WOLFSSL_NO_ASN_STRICT to allow parsing of explicit ECC public key
* Remove relocatable text in ARMv7a AES assembly for use with FIPS builds
* Expand checking for hardware that supports ARMv7a neon with autotools configure
* Sanity check on allocation fails with DSA and FP_ECC build when zeroizing internal buffer
* Additional TLS alerts sent when compiling with WOLFSSL_EXTRA_ALERTS macro defined

### Benchmarking
* Update wolfCrypt benchmark Windows build files to support x64 Platform
* Add SHA512/224 and SHA512/256 benchmarks, fixed CVS macro and display sizes
* Separate AES-GCM streaming runs when benchmarked
* No longer call external implementation of Kyber from benchmark
* Fix for benchmarking shake with custom block size
* Fixes for benchmark help `-alg` list and block format
Documentation/Examples
* Document use of wc_AesFree() and update documentation of Ed25519 with Doxygen
* Move the wolfSSL Configuration section higher in QUIC.md
* Add Japanese Doxygen documentation for cmac.h, quic.h and remove incomplete Japanese doxygen in asn_public.h
* Espressif examples run with local wolfSSL now with no additional setup needed
* Added a fix for StartTLS use In the example client
* Add a base-line user_settings.h for use with FIPS 140-3 in XCode example app

### Optimizations
* AES-NI usage added for AES modes ECB/CTR/XTS

### Misc
* Update AES-GCM stream decryption to allow long IVs
* Internal refactor to use wolfSSL_Ref functions when incrementing or decrementing the structures reference count and fixes for static analysis reports
* Cleanup function logging making adjustments to the debug log print outs
* Remove realloc dependency in DtlsMsgCombineFragBuckets function
* Refactor to use WOLFSSL_CTX’s cipher suite list when possible
* Update internal padding of 0’s with DSA sign and additional tests with mp_to_unsigned_bin_len function
* With DTLS SRTP use wolfSSL_export_keying_material instead of wc_PRF_TLS
* Updated macro naming from HAVE_KYBER to be WOLFSSL_HAVE_KYBER
* Update AES XTS encrypt to handle in-place encryption properly
* With TLS 1.3 add option to require only PSK with DHE

## Fixes

### Ports
* Fix for AES use with CAAM on imx8qxp with SECO builds
* Fix for PIC32 crypto HW and unused `TLSX_SetResponse`
* Fix warning if ltime is unsigned seen with QNX build
* Updates and fix for Zephyr project support
* Include sys/time.h for WOLFSSL_RIOT_OS
* Move X509_V errors from enums to defines for use with HAProxy CLI
* Fix IAR compiler warnings resolved
* Fix for STM32 Hash peripherals (like on F437) with FIFO depth = 1
* ESP32 fix for SHA384 init with hardware acceleration

### Builds
* Add WOLFSSL_IP_ALT_NAME macro define to --enable-curl
* Fixes for building with C++17 and avoiding clashing with byte naming
* Fixes SP math all build issue with small-stack and no hardening
* Fix for building with ASN template with `NO_ASN_TIME` defined
* Fix building FIPSv2 with WOLFSSL_ECDSA_SET_K defined
* Don't allow aesgcm-stream option with kcapi
* Fix DTLS test case for when able to read peers close notify alert on FreeBSD systems
* Fix for "expression must have a constant value" in tls13.c with Green Hills compiler
* Fixes for building KCAPI with opensslextra enabled
* Fix warnings of shadows min and subscript with i486-netbsd-gcc compiler
* Fix issue with async and `WOLFSSL_CHECK_ALERT_ON_ERR`
* Fix for PKCS7 with asynchronous crypto enabled

### Math Library
* SP Aarch64 fix for conditional changed in asm needing "cc" and fix for ECC P256 mont reduce
* In SP builds add sanity check with DH exp. to check the output length for minimum size
* In SP math fix scalar length check with EC scalar multiply
* With SP int fix handling negative character properly with read radix
* Add error checks before setting variable err in SP int with the function sp_invmod_mont_ct
* Fix to add sanity check for malloc of zero size in fastmath builds
* In fastmath  fix a possible overflow in fp_to_unsigned_bin_len length check
* Heapmath fast mod. reduce fix

### Compatibility Layer
* Fixes for encoding/decoding ecc public keys and ensure i2d public key functions do not include any private key information
* Fix for EVP_EncryptUpdate to update outl on empty input
* Fix SE050 RSA public key loading and RSA/ECC SE050 TLS Compatibility
* Rework EC API and validate point after setting it
* Fix for X509 RSA PSS with compatibility layer functions
* Fix size of structures used with SHA operations when built with opensslextra for Espressif hardware accelerated hashing
* Added sanity check on key length with wolfSSL_CMAC_Init function
* Fix for return value type conversion of bad mutex error in logging function
* Fix NID conflict NID_givenName and NID_md5WithRSAEncryption
* Fix unguarded XFPRINTF calls with opensslextra build
* Fix wolfSSL_ASN1_INTEGER_to_BN for negative values
* Fix for potential ASN1_STRING leak in wolfSSL_X509_NAME_ENTRY_create_by_txt  and wolfSSL_X509_NAME_ENTRY_create_by_NID when memory allocation fails

### Misc.
* Add sanity check to prevent an out of bounds read with OCSP response decoding
* Sanity check to not allow 0 length with bit string and integer when parsing ASN1 syntax
* Adjust RNG sanity checks and remove error prone first byte comparison
* With PKCS7 add a fix for GetAsnTimeString() to correctly increment internal data pointer
* PKCS7 addition of sequence around algo parameters with authenvelop
* DSA fixes for clearing mp_int before re-reading data and avoid mp_clear without first calling mp_init
* Fix for SRTP setting bitfield when it is encoded for the TLS extension
* Fix for handling small http headers when doing CRL verification
* Fix for ECCSI hash function to validate the output size and curve size
* Fix for value of givenName and name being reversed with CSR generation
* Fix for error type returned (OCSP_CERT_UNKNOWN) with OCSP verification
* Fix for a potential memory leak with ProcessCSR when handling OCSP responses
* Fix for VERIFY_SKIP_DATE flag not ignoring date errors when set
* Fix for zlib decompression buffer issue with PKCS7
* Fix for DTLS message pool send size used and DTLS server saving of the handshake sequence
* Fix to propagate WOLFSSL_TICKET_RET_CREATE error return value from DoDecryptTicket()
* Fix for handling long session IDs with TLS 1.3 session tickets
* Fix for AES-GCM streaming when caching an IV
* Fix for test case with older selftest that returns bad padding instead of salt len error
* Add fix for siphash cache and added in additional tests
* Fix potential out of bounds memset to 0 in error case with session export function used with --enable-sessionexport builds
* Fix possible NULL dereference in TLSX_CSR_Parse with TLS 1.3
* Fix for sanity check on RSA pad length with no padding using the build macro WC_RSA_NO_PADDING

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
