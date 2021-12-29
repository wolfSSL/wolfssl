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

# wolfSSL Release 5.1.0 (Dec 27, 2021)
Release 5.1.0 of wolfSSL embedded TLS has bug fixes and new features including:

### Vulnerabilities
* \[Low\]  Potential for DoS attack on a wolfSSL client due to processing hello packets of the incorrect side. This affects only connections using TLS v1.2 or less that have also been compromised by a man in the middle attack. Thanks to James Henderson, Mathy Vanhoef, Chris M. Stone, Sam L. Thomas, Nicolas Bailleut, and Tom Chothia (University of Birmingham, KU Leuven, ENS Rennes for the report.
* \[Low\] Client side session resumption issue once the session resumption cache has been filled up. The hijacking of a session resumption has been demonstrated so far with only non verified peer connections. That is where the client is not verifying the server’s CA that it is connecting to. There is the potential though for other cases involving proxies that are verifying the server to be at risk, if using wolfSSL in a case involving proxies use wolfSSL_get1_session and then wolfSSL_SESSION_free when done where possible. If not adding in the session get/free function calls we recommend that users of wolfSSL that are resuming sessions update to the latest version (wolfSSL version 5.1.0 or later). Thanks to the UK's National Cyber Security Centre (NCSC) for the report.

### New Feature Additions
###### Ports
* Curve25519 support with NXP SE050 added
* Renesas RA6M4 support with SCE Protected Mode and FSP 3.5.0
* Renesas TSIP 1.14 support for RX65N/RX72N

###### Post Quantum
* Post quantum resistant algorithms used with Apache port
* NIST round 3 FALCON Signature Scheme support added to TLS 1.3 connections
* FALCON added to the benchmarking application
* Testing of cURL with wolfSSL post quantum resistant build

###### Compatibility Layer Additions
* Updated NGINX port to NGINX version 1.21.4
* Updated Apache port to Apache version 2.4.51
* Add support for SSL_OP_NO_TLSv1_2 flag with wolfSSL_CTX_set_options function
* Support added for the functions
    - SSL_CTX_get_max_early_data
    - SSL_CTX_set_max_early_data
    - SSL_set_max_early_data
    - SSL_get_max_early_data
    - SSL_CTX_clear_mode
    - SSL_CONF_cmd_value_type
    - SSL_read_early_data
    - SSL_write_early_data

###### Misc.
* Crypto callback support for AES-CCM added. A callback function can be registered and used instead of the default AES-CCM implementation in wolfSSL.
* Added AES-OFB to the FIPS boundary for future FIPS validations.
* Add support for custom OIDs used with CSR (certificate signing request) generation using the macro WOLFSSL_CUSTOM_OID
* Added HKDF extract callback function for use with TLS 1.3
* Add variant from RFC6979 of deterministic ECC signing that can be enabled using the macro WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT
* Added the function wc_GetPubKeyDerFromCert to get the public key from a DecodedCert structure
* Added the functions wc_InitDecodedCert, wc_ParseCert and wc_FreeDecodedCert for access to decoding a certificate into a DecodedCert structure
* Added the macro WOLFSSL_ECC_NO_SMALL_STACK for hybrid builds where the numerous malloc/free with ECC is undesired but small stack use is desired throughout the rest of the library
* Added the function wc_d2i_PKCS12_fp for reading a PKCS12 file and parsing it

### Fixes
###### PORT Fixes
* Building with Android wpa_supplicant and KeyStore
* Setting initial value of CA certificate with TSIP enabled
* Cryptocell ECC build fix and fix with RSA disabled 
* IoT-SAFE improvement for Key/File slot ID size, fix for C++ compile, and fixes for retrieving the public key after key generation

###### Math Library Fixes
* Check return values on TFM library montgomery function in case the system runs out of memory. This resolves an edge case of invalid ECC signatures being created.
* SP math library sanity check on size of values passed to sp_gcd.
* SP math library sanity check on exponentiation by 0 with mod_exp
* Update base ECC mp_sqrtmod_prime function to handle an edge case of zero
* TFM math library with Intel MULX multiply fix for carry in assembly code

###### Misc.
* Fix for potential heap buffer overflow with compatibility layer PEM parsing
* Fix for edge memory leak case with an error encountered during TLS resumption
* Fix for length on inner sequence created with wc_DhKeyToDer when handling small DH keys
* Fix for sanity check on input argument to DSA sign and verify
* Fix for setting of the return value with ASN1 integer get on an i386 device
* Fix for BER to DER size checks with PKCS7 decryption
* Fix for memory leak with PrintPubKeyEC function in compatibility layer
* Edge case with deterministic ECC key generation when the private key has leading 0’s
* Fix for build with OPENSSL_EXTRA and NO_WOLFSSL_STUB both defined
* Use page aligned memory with ECDSA signing and KCAPI
* Skip expired sessions for TLS 1.3 rather than turning off the resume behavior
* Fix for DTLS handling dropped or retransmitted messages

### Improvements/Optimizations
###### Build Options and Warnings
* Bugfix: could not build with liboqs and without DH enabled
* Build with macro NO_ECC_KEY_EXPORT fixed
* Fix for building with the macro HAVE_ENCRYPT_THEN_MAC when session export is enabled
* Building with wolfSentry and HAVE_EX_DATA macro set

###### Math Libraries
* Improvement for performance with SP C implementation of montgomery reduction for ECC (P256 and P384) and SP ARM64 implementation for ECC (P384)
* With SP math handle case of dividing by length of dividend
* SP math improvement for lo/hi register names to be used with older GCC compilers

###### Misc.
* ASN name constraints checking code refactor for better efficiency and readability
* Refactor of compatibility layer stack free’ing calls to simplify and reduce code
* Scrubbed code for trailing spaces, hard tabs, and any control characters
* Explicit check that leaf certificate's public key type match cipher suite signature algorithm
* Additional NULL sanity checks on WOLFSSL struct internally and improve switch statement fallthrough
* Retain OCSP error value when CRL is enabled with certificate parsing
* Update to NATIVE LwIP support for TCP use
* Sanity check on PEM size when parsing a PEM with OpenSSL compatibility layer API.
* SWIG wrapper was removed from the codebase in favor of dedicated Java and Python wrappers.
* Updates to bundled example client for when to load the CA, handling print out of IP alt names, and printing out the peers certificate in PEM format
* Handling BER encoded inner content type with PKCS7 verify
* Checking for SOCKET_EPIPE errors from low level socket
* Improvements to cleanup in the case that wolfSSL_Init fails
* Update test and example certificates expiration dates


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
