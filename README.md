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

# wolfSSL Release 5.5.1 (Sep 28, 2022)
Release 5.5.1 of wolfSSL embedded TLS has bug fixes and new features including:

## Vulnerabilities
* [Med] Denial of service attack and buffer overflow against TLS 1.3 servers using session ticket resumption. When built with --enable-session-ticket and making use of TLS 1.3 server code in wolfSSL, there is the possibility of a malicious client to craft a malformed second ClientHello packet that causes the server to crash. This issue is limited to when using both --enable-session-ticket and TLS 1.3 on the server side. Users with TLS 1.3 servers, and having --enable-session-ticket, should update to the latest version of wolfSSL. Thanks to Max at Trail of Bits for the report, found by Lucca Hirschi from LORIA, Inria, France with the tlspuffin tool developed partly at LORIA and Trail of Bits. CVE-2022-39173

## New Feature Additions
* Add support for non-blocking ECC key gen and shared secret gen for P-256/384/521
* Add support for non-blocking ECDHE/ECDSA in TLS/DTLS layer.
* Port to NXP RT685 with FreeRTOS
* Add option to build post quantum Kyber API (--enable-kyber)
* Add post quantum algorithm sphincs to wolfCrypt
* Config. option to force no asm with SP build (--enable-sp=noasm)
* Allow post quantum keyshare for DTLS 1.3

## Enhancements
* DTLSv1.3: Do HRR Cookie exchange by default
* Add wolfSSL_EVP_PKEY_new_CMAC_key to OpenSSL compatible API 
* Update ide win10 build files to add missing sp source files 
* Improve Workbench docs 
* Improve EVP support for CHACHA20_POLY1305
* Improve `wc_SetCustomExtension` documentation
* RSA-PSS with OCSP and add simple OCSP response DER verify test case
* Clean up some FIPS versioning logic in configure.ac and WIN10 user_settings.h
* Don't over-allocate memory for DTLS fragments
* Add WOLFSSL_ATECC_TFLXTLS for Atmel port
* SHA-3 performance improvements with x86_64 assembly
* Add code to fallback to S/W if TSIP cannot handle 
* Improves entropy with VxWorks
* Make time in milliseconds 64-bits for longer session ticket lives
* Support for setting cipher list with bytes
* wolfSSL_set1_curves_list(), wolfSSL_CTX_set1_curves_list() improvements
* Add to RSAES-OAEP key parsing for pkcs7
* Add missing DN nid to work with PrintName()
* SP int: default to 16 bit word size when NO_64BIT defined 
* Limit the amount of fragments we store per a DTLS connection and error out when max limit is reached
* Detect when certificate's RSA public key size is too big and fail on loading of certificate

## Fixes
* Fix for async with OCSP non-blocking in `ProcessPeerCerts`
* Fixes for building with 32-bit and socket size sign/unsigned mismatch
* Fix Windows CMakeList compiler options 
* TLS 1.3 Middle-Box compat: fix missing brace 
* Configuration consistency fixes for RSA keys and way to force disable of private keys 
* Fix for Aarch64 Mac M1 SP use
* Fix build errors and warnings for MSVC with DTLS 1.3
* Fix HMAC compat layer function for SHA-1
* Fix DTLS 1.3 do not negotiate ConnectionID in HelloRetryRequest
* Check return from call to wc_Time
* SP math: fix build configuration with opensslall
* Fix for async session tickets
* SP int mp_init_size fixes when SP_WORD_SIZE == 8 
* Ed. function to make public key now checks for if the private key flag is set
* Fix HashRaw WC_SHA256_DIGEST_SIZE for wc_Sha256GetHash 
* Fix for building with PSK only
* Set correct types in wolfSSL_sk_*_new functions
* Sanity check that size passed to mp_init_size() is no more than SP_INT_DIGITS

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
