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


# wolfSSL Release 5.5.3 (Nov 2, 2022)

Release 5.5.3 of wolfSSL embedded TLS has the following bug fix:

## Fixes

* Fix for possible buffer zeroization overrun introduced at the end of v5.5.2 release cycle in GitHub pull request 5743 (https://github.com/wolfSSL/wolfssl/pull/5743) and fixed in pull request 5757 (https://github.com/wolfSSL/wolfssl/pull/5757). In the case where a specific memory allocation failed or a hardware fault happened there was the potential for an overrun of 0’s when masking the buffer used for (D)TLS 1.2 and lower operations. (D)TLS 1.3 only and crypto only users are not affected by the issue. This is not related in any way to recent issues reported in OpenSSL.


# wolfSSL Release 5.5.2 (Oct 28, 2022)
Release 5.5.2 of wolfSSL embedded TLS has bug fixes and new features including:

## Vulnerabilities
* [Med] In the case that the WOLFSSL_CALLBACKS macro is set when building wolfSSL, there is a potential heap over read of 5 bytes when handling TLS 1.3 client connections. This heap over read is limited to wolfSSL builds explicitly setting the macro WOLFSSL_CALLBACKS, the feature does not get turned on by any other build options. The macro WOLFSSL_CALLBACKS is intended for debug use only, but if having it enabled in production, users are recommended to disable WOLFSSL_CALLBACKS. Users enabling WOLFSSL_CALLBACKS are recommended to update their version of wolfSSL. Thanks to Lucca Hirschi and Steve Kremer from LORIA, Inria and Max Ammann from Trail of Bits for finding and reporting the bug with the tlspuffin tool developed partly at LORIA and Trail of Bits. CVE 2022-42905

Release 5.5.2 of wolfSSL embedded TLS has bug fixes and new features including:

## New Feature Additions
* Add function wolfSSL_CTX_load_system_CA_certs to load system CA certs into a WOLFSSL_CTX and  --sys-ca-certs option to example client
* Add wolfSSL_set1_host to OpenSSL compatible API
* Added the function sk_X509_shift
* AES x86 ASM for AES-CBC and GCM performance enhancements
* Add assembly for AES for ARM32 without using crypto hardware instructions
* Xilinx Versal port and hardware acceleration tie in
* SP Cortex-M support for ICCARM

## Enhancements
* Add snifftest vcxproj file and documentation
* Nucleus Thread Types supported
* Handle certificates with RSA-PSS signature that have RSAk public keys
* Small stack build improvements
* DTLS 1.3 improvements for Alerts and unit tests
* Add a binary search for CRL
* Improvement of SSL/CTX_set_max_early_data() for client side
* Remove unused ASN1_GENERALIZEDTIME enum value from wolfssl/ssl.h
* Add user_settings.h for Intel/M1 FIPSv2 macOS C++ projects
* Add dtlscid.test to ‘make check’ unit testing
* Generate an assembler-safe user_settings.h in configure.ac and CMakeLists.txt
* ForceZero enabled with USE_FAST_MATH
* Add TLS 1.3 support of ticketNonce sizes bigger than MAX_TICKET_NONCE_SZ
* FIPSv2 builds on win10 adjust for new fastmath default in settings.h
* Add IRQ install for Aruix example

## Fixes
* When looking up the session by ID on the server, check that the protocol version of the SSL and session match on TLS 1.3 or not
* Fix for potential EVP_PKEY_DH memory leak with OPENSSL_EXTRA
* Curve448 32-bit C code: handle corner case
* Fixup builds using WOLFSSL_LOG_PRINTF
* Correct DIST_POINT_NAME type value
* Do not perform IV Wrap test when using cert3389 inlined armasm
* Fix for Linux kernel module and stdio.h
* (D)TLS: send alert on version mismatch
* Fix PKCS#7 SignedData verification when signer cert is not first in SET
* Fix bug with wolfIO_TcpConnect not working with timeout on Windows
* Fix output length bug in SP non-blocking ECC shared secret gen
* Fix build with enable-fastmath and disable-rsa
* Correct wolfSSL_sk_X509_new in OpenSSL compatible API
* Fixes for SP and x86_64 with MSVC
* Fix wrong size using DTLSv1.3 in RestartHandshakeHashWithCookie
* Fix redundant file include with TI RTOS build
* Fix wolfCrypt only build with wincrypt.h
* DTLS 1.2: Reset state when sending HelloVerifyRequest

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
