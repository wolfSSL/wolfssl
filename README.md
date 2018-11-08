# Description

The wolfSSL embedded SSL library (formerly CyaSSL) is a lightweight SSL/TLS library written in ANSI C and targeted for embedded, RTOS, and resource-constrained environments - primarily because of its small size, speed, and feature set.  It is commonly used in standard operating environments as well because of its royalty-free pricing and excellent cross platform support.  wolfSSL supports industry standards up to the current TLS 1.3 and DTLS 1.3 levels, is up to 20 times smaller than OpenSSL, and offers progressive ciphers such as ChaCha20, Curve25519, NTRU, and Blake2b.  User benchmarking and feedback reports dramatically better performance when using wolfSSL over OpenSSL.

wolfSSL is powered by the wolfCrypt library. A version of the wolfCrypt cryptography library has been FIPS 140-2 validated (Certificate #2425). For additional information, visit the [wolfCrypt FIPS FAQ](https://www.wolfssl.com/license/fips/) or contact fips@wolfssl.com

## Why Choose wolfSSL?
There are many reasons to choose wolfSSL as your embedded SSL solution. Some of the top reasons include size (typical footprint sizes range from 20-100 kB), support for the newest standards (SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, DTLS 1.0, and DTLS 1.2), current and progressive cipher support (including stream ciphers), multi-platform, royalty free, and an OpenSSL compatibility API to ease porting into existing applications which have previously used the OpenSSL package. For a complete feature list, see [Section 4.1.](https://www.wolfssl.com/docs/wolfssl-manual/ch4/)

***

# Notes - Please read

## Note 1
```
wolfSSL as of 3.6.6 no longer enables SSLv3 by default.  wolfSSL also no
longer supports static key cipher suites with PSK, RSA, or ECDH.  This means
if you plan to use TLS cipher suites you must enable DH (DH is on by default),
or enable ECC (ECC is on by default), or you must enable static
key cipher suites with
    WOLFSSL_STATIC_DH
    WOLFSSL_STATIC_RSA
    or
    WOLFSSL_STATIC_PSK

though static key cipher suites are deprecated and will be removed from future
versions of TLS.  They also lower your security by removing PFS.  Since current
NTRU suites available do not use ephemeral keys, WOLFSSL_STATIC_RSA needs to be
used in order to build with NTRU suites.


When compiling ssl.c, wolfSSL will now issue a compiler error if no cipher suites
are available.  You can remove this error by defining WOLFSSL_ALLOW_NO_SUITES
in the event that you desire that, i.e., you're not using TLS cipher suites.
```

## Note 2
```

wolfSSL takes a different approach to certificate verification than OpenSSL
does.  The default policy for the client is to verify the server, this means
that if you don't load CAs to verify the server you'll get a connect error,
no signer error to confirm failure (-188).  If you want to mimic OpenSSL
behavior of having SSL_connect succeed even if verifying the server fails and
reducing security you can do this by calling:

wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

before calling wolfSSL_new();  Though it's not recommended.
```

## Note 3
```
The enum values SHA, SHA256, SHA384, SHA512 are no longer available when
wolfSSL is built with --enable-opensslextra (OPENSSL_EXTRA) or with the macro
NO_OLD_SHA_NAMES. These names get mapped to the OpenSSL API for a single call
hash function. Instead the name WC_SHA, WC_SHA256, WC_SHA384 and WC_SHA512
should be used for the enum name.
```

# wolfSSL Release 3.15.5 (11/07/2018)

Release 3.15.5 of wolfSSL embedded TLS has bug fixes and new features including:

* Fixes for GCC-8 warnings with strings
* Additional compatibility API’s added, including functions like wolfSSL_X509_CA_num and wolfSSL_PEM_read_X509_CRL
* Fixes for OCSP use with NGINX port
* Renamed the macro INLINE to WC_INLINE for inline functions
* Doxygen updates and formatting for documentation generation
* Added support for the STM32L4 with AES/SHA hardware acceleration
* Adds checking for critical extension with certificate Auth ID and the macro WOLFSSL_ALLOW_CRIT_SKID to override the check
* Added public key callbacks to ConfirmSignature function to expand public key callback support
* Added ECC and Curve25519 key generation callback support
* Fix for memory management with wolfSSL_BN_hex2bn function
* Added support for dynamic allocation of PKCS7 structure using wc_PKCS7_New and wc_PKCS7_Free
* Port to apache mynewt added in the directory wolfssl-3.15.5/IDE/mynewt/*
* OCSP stapling in TLS 1.3 additions
* Port for ASIO added with --enable-asio configure flag
* Contiki port added with macro WOLFSSL_CONTIKI
* Memory free optimizations with adding in earlier free’s where possible
* Made modifications to the primality testing so that the Miller-Rabin tests check against up to 40 random numbers rather than a fixed list of small primes
* Certificate validation time generation updated
* Fixes for MQX classic 4.0 with IAR-EWARM
* Fix for assembly optimized version of Curve25519
* Make SOCKET_PEER_CLOSED_E consistent between read and write cases
* Relocate compatibility layer functions for OpenSSH port update
* Update to Intel® SGX port, files included by Windows version and macros defined when using WOLFSSL_SGX
* Updates to Nucleus version supported
* Stack size reduction with smallstack build
* Updates to Rowley-Crossworks settings for CMSIS 4
* Added reference STSAFE-A100 public key callbacks for TLS support
* Added reference ATECC508A/ATECC608A public key callbacks for TLS support
* Updated support for latest CryptoAuthLib (10/25/2018)
* Added a wolfSSL static library project for Atollic TrueSTUDIO
* Flag to disable AES-CBC and have only AEAD cipher suites with TLS
* AF_ALG and cryptodev-linux crypto support added
* Update to IO callbacks with use of WOLFSSL_BIO
* Additional support for parsing certificate subject OIDs (businessCategory, jurisdiction of incorporation country, and jurisdiction of incorporation state)
* Added  wc_ecc_ecport_ex and wc_export_inti API's for ECC hex string exporting
* Updates to XCODE build with wolfSSL
* Fix for guard on when to include sys/time.h header
* Updates and enhancements to the GCC-ARM example
* Fix for PKCS8 padding with encryption
* Updates for wolfcrypt JNI wrapper
* ALT_ECC_SIZE use with SP math
* PIC32MZ hardware acceleration buffer alignment fixes
* Renesas e2studio project files added
* Renesas RX example project added
* Fix for DH algorithm when using SP math with ARM assembly
* Fixes and enhancements for NXP K82 support
* Benchmark enhancements to print in CSV format and in Japanese
* Support for PKCS#11 added with --enable-pkcs11
* Fixes for asynchronous crypto use with TLS 1.3
* TLS 1.3 only build, allows for disabling TLS 1.2 and earlier protocols
* Fix for GCC warnings in function wolfSSL_ASN1_TIME_adj
* Added --enable-asn=nocrypt for certificate only parsing support
* Added support for parsing PIV format certificates with the function wc_ParseCertPIV and macro WOLFSSL_CERT_PIV
* Added APIs to support GZIP
* Updates to support Lighttpd
* Version resource added for Windows DLL builds
* Increased code coverage with additional testing
* Added support for constructed OCTET_STRING with PKCS#7 signed data
* Added DTLS either (server/client) side initialization setting
* Minor fixes for building with MINGW32 compiler
* Added support for generic ECC PEM header/footer with PKCS8 parsing
* Added Japanese output to example server and client with “-1 1” flag
* Added USE_ECDSA_KEYSZ_HASH_ALGO macro for building to use digest sizes that match ephemeral key size
* Expand PKCS#7 CMS support with KEKRI, PWRI and ORI
* Streaming capability for PKCS#7 decoding and sign verify added


See INSTALL file for build instructions.
More info can be found on-line at http://wolfssl.com/wolfSSL/Docs.html

# Resources

[wolfSSL Website](https://www.wolfssl.com/)

[wolfSSL Wiki](https://github.com/wolfSSL/wolfssl/wiki)

[FIPS FAQ](https://www.wolfssl.com/wolfSSL/fips.html)

[wolfSSL Manual](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-toc.html)

[wolfSSL API Reference](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-17-wolfssl-api-reference.html)

[wolfCrypt API Reference](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-18-wolfcrypt-api-reference.html)

[TLS 1.3](https://www.wolfssl.com/docs/tls13/)
