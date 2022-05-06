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


# wolfSSL Release 5.3.0 (May 3rd, 2022)

Release 5.3.0 of wolfSSL embedded TLS has bug fixes and new features including:

## New Feature Additions

### Ports
* Updated support for Stunnel to version 5.61
* Add i.MX8 NXP SECO use for secure private ECC keys and expand cryptodev-linux for use with the RSA/Curve25519 with the Linux CAAM driver
* Allow encrypt then mac with Apache port
* Update Renesas TSIP version to 1.15 on GR-ROSE and certificate signature data for TSIP / SCE example
* Add IAR MSP430 example, located in IDE/IAR-MSP430 directory
* Add support for FFMPEG with the enable option `--enable-ffmpeg`, FFMPEG is used for recording and converting video and audio (https://ffmpeg.org/)
* Update the bind port to version 9.18.0

### Post Quantum
* Add Post-quantum KEM benchmark for STM32
* Enable support for using post quantum algorithms with embedded STM32 boards and port to STM32U585

### Compatibility Layer Additions
* Add port to support libspdm (https://github.com/DMTF/libspdm/blob/main/README.md), compatibility functions added for the port were:
	- ASN1_TIME_compare
	- DH_new_by_nid
	- OBJ_length, OBJ_get0_data,
	- EVP layer ChaCha20-Poly1305, HKDF
	- EC_POINT_get_affine_coordinates
	- EC_POINT_set_affine_coordinates
* Additional functions added were:
	- EC_KEY_print_fp
	- EVP_PKEY_paramgen
	- EVP_PKEY_sign/verify functionality
	- PEM_write_RSAPublicKey
	- PEM_write_EC_PUBKEY
	- PKCS7_sign
	- PKCS7_final
	- SMIME_write_PKCS7
	- EC_KEY/DH_up_ref
	- EVP_DecodeBlock
	- EVP_EncodeBlock
	- EC_KEY_get_conv_form
	- BIO_eof
	- Add support for BIO_CTRL_SET and BIO_CTRL_GET
* Add compile time support for the type SSL_R_NULL_SSL_METHOD_PASSED
* Enhanced X509_NAME_print_ex() to support RFC5523 basic escape
* More checks on OPENSSL_VERSION_NUMBER for API prototype differences
* Add extended key usage support to wolfSSL_X509_set_ext
* SSL_VERIFY_FAIL_IF_NO_PEER_CERT now can also connect with compatibility layer enabled and a TLS 1.3 PSK connection is used
* Improve wolfSSL_BN_rand to handle non byte boundaries and top/bottom parameters
* Changed X509_V_ERR codes to better match OpenSSL values used
* Improve wolfSSL_i2d_X509_name to allow for a NULL input in order to get the expected resulting size
* Enhance the smallstack build to reduce stack size farther when built with compatibility layer enabled

### Misc.
* Sniffer asynchronous support addition, handling of DH shared secret and tested with Intel QuickAssist
* Added in support for OCSP with IPv6
* Enhance SP (single precision) optimizations for use with the ECC P521
* Add new public API wc_CheckCertSigPubKey() for use to easily check the signature of a certificate given a public key buffer
* Add CSR (Certificate Signing Request) userId support in subject name
* Injection and parsing of custom extensions in X.509 certificates
* Add WOLF_CRYPTO_CB_ONLY_RSA and WOLF_CRYPTO_CB_ONLY_ECC to reduce code size if using only crypto callback functions with RSA and ECC
* Created new --enable-engine configure flag used to build wolfSSL for use with wolfEngine
* With TLS 1.3 PSK, when WOLFSSL_PSK_MULTI_ID_PER_CS is defined multiple IDs for a cipher suite can be handled
* Added private key id/label support with improving the PK (Public Key) callbacks
* Support for Intel QuickAssist ECC KeyGen acceleration
* Add the function wolfSSL_CTX_SetCertCbCtx to set user context for certificate call back
* Add the functions wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx) and wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx) for setting and getting a user context
* wolfRand for AMD --enable-amdrand

## Fixes
### PORT Fixes
* KCAPI memory optimizations and page alignment fixes for ECC, AES mode fixes and reduction to memory usage
* Add the new kdf.c file to the TI-RTOS build
* Fix wait-until-done in RSA hardware primitive acceleration of ESP-IDF port
* IOTSafe workarounds when reading files with ending 0’s and for ECC signatures

### Math Library Fixes
* Sanity check with SP math that ECC points ordinates are not greater than modulus length
* Additional sanity checks that _sp_add_d does not error due to overflow
* Wycheproof fixes, testing integration, and fixes for AVX / AArch64 ASM edge case tests 
* TFM fp_div_2_ct rework to avoid potential overflow

### Misc.
* Fix for PKCS#7 with Crypto Callbacks
* Fix for larger curve sizes with deterministic ECC sign
* Fixes for building wolfSSL alongside openssl using --enable-opensslcoexist
* Fix for compatibility layer handling of certificates with SHA256 SKID (Subject Key ID)
* Fix for wolfSSL_ASN1_TIME_diff erroring out on a return value of 0 from mktime
* Remove extra padding when AES-CBC encrypted with PemToDer
* Fixes for TLS v1.3 early data with async.
* Fixes for async disables around the DevCopy calls
* Fixes for Windows AES-NI with clang compiler
* Fix for handling the detection of processing a plaintext TLS alert packet
* Fix for potential memory leak in an error case with TLSX supported groups
* Sanity check on `input` size in `DecodeNsCertType`
* AES-GCM stack alignment fixes with assembly code written for AVX/AVX2
* Fix for PK callbacks with server side and setting a public key

## Improvements/Optimizations
### Build Options and Warnings
* Added example user settings template for FIPS v5 ready
* Automake file touch cleanup for use with Yocto devtool
* Allow disabling forced 'make clean' at the end of ./configure by using --disable-makeclean
* Enable TLS 1.3 early data when specifying `--enable-all` option
* Disable PK Callbacks with JNI FIPS builds
* Add a FIPS cert 3389 ready option, this is the fips-ready build
* Support (no)inline with Wind River Diab compiler
* ECDH_compute_key allow setting of globalRNG with FIPS 140-3
* Add logic equivalent to configure.ac in settings.h for Poly1305
* Fixes to support building opensslextra with SP math
* CPP protection for extern references to x86_64 asm code
* Updates and enhancements for Espressif ESP-IDF wolfSSL setup_win.bat
* Documentation improvements with auto generation
* Fix reproducible-build for working an updated version of libtool, version 2.4.7
* Fixes for Diab C89 and armclang
* Fix `mcapi_test.c` to include the settings.h before crypto.h
* Update and handle builds with NO_WOLFSSL_SERVER and NO_WOLFSSL_CLIENT
* Fix for some macro defines with FIPS 140-3 build so that RSA_PKCS1_PSS_PADDING can be used with RSA sign/verify functions

### Math Libraries
* Add RSA/DH check for even modulus
* Enhance TFM math to handle more alloc failure cases gracefully
* SP ASM performance improvements mostly around AArch64
* SP ASM improvements for additional cache attack resistance
* Add RSA check for small difference between p and q
* 6-8% performance increase with ECC operations using SP int by improving the Montgomery Reduction

### Testing and Validation
* All shell scripts in source tree now tested for correctness using shellcheck and bash -n
* Added build testing under gcc-12 and -std=c++17 and fixed warnings
* TLS 1.3 script test improvement to wait for server to write file
* Unit tests for ECC r/s zeroness handling
* CI server was expanded with a very “quiet” machine that can support multiple ContantTime tests ensuring ongoing mitigation against side-channel timing based attacks. Algorithms being assessed on this machine are: AES-CBC, AES-GCM, CHACHA20, ECC, POLY1305, RSA, SHA256, SHA512, CURVE25519.
* Added new multi configuration windows builds to CI testing for greater testing coverage of windows use-cases

### Misc.
* Support for ECC import to check validity of key on import even if one of the coordinates (x or y) is 0
* Modify example app to work with FreeRTOS+IoT
* Ease of access for cert used for verifying a PKCS#7 bundle
* Clean up Visual Studio output and intermediate directories
* With TLS 1.3 fail immediately if a server sends empty certificate message
* Enhance the benchmark application to support multi-threaded testing
* Improvement for `wc_EccPublicKeyToDer` to not overestimate the buffer size required
* Fix to check if `wc_EccPublicKeyToDer` has enough output buffer space
* Fix year 2038 problem in wolfSSL_ASN1_TIME_diff
* Various portability improvements (Time, DTLS epoch size, IV alloc)
* Prefer status_request_v2 over status_request when both are present
* Add separate "struct stat" definition XSTATSTRUCT to make overriding XSTAT easier for portability
* With SipHash replace gcc specific ASM instruction with generic
* Don't force a ECC CA when a custom CA is passed with `-A`
* Add peer authentication failsafe for TLS 1.2 and below
* Improve parsing of UID from subject and issuer name with the compatibility layer by
* Fallback to full TLS handshake if session ticket fails
* Internal refactoring of code to reduce ssl.c file size

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
