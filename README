*** Description ***

The wolfSSL embedded SSL library (formerly CyaSSL) is a lightweight SSL/TLS
library written in ANSI C and targeted for embedded, RTOS, and
resource-constrained environments - primarily because of its small size, speed,
and feature set.  It is commonly used in standard operating environments as well
because of its royalty-free pricing and excellent cross platform support.
wolfSSL supports industry standards up to the current TLS 1.3 and DTLS 1.2
levels, is up to 20 times smaller than OpenSSL, and offers progressive ciphers
such as ChaCha20, Curve25519, NTRU, and Blake2b. User benchmarking and feedback
reports dramatically better performance when using wolfSSL over OpenSSL.

wolfSSL is powered by the wolfCrypt library. A version of the wolfCrypt
cryptography library has been FIPS 140-2 validated (Certificate #2425). For
additional information, visit the wolfCrypt FIPS FAQ
(https://www.wolfssl.com/license/fips/) or contact fips@wolfssl.com

*** Why choose wolfSSL? ***

There are many reasons to choose wolfSSL as your embedded SSL solution. Some of
the top reasons include size (typical footprint sizes range from 20-100 kB),
support for the newest standards (SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3,
DTLS 1.0, and DTLS 1.2), current and progressive cipher support (including
stream ciphers), multi-platform, royalty free, and an OpenSSL compatibility API
to ease porting into existing applications which have previously used the
OpenSSL package. For a complete feature list, see chapter 4 of the wolfSSL
manual. (https://www.wolfssl.com/docs/wolfssl-manual/ch4/)

*** Notes, Please read ***

Note 1)
wolfSSL as of 3.6.6 no longer enables SSLv3 by default.  wolfSSL also no longer
supports static key cipher suites with PSK, RSA, or ECDH. This means if you
plan to use TLS cipher suites you must enable DH (DH is on by default), or
enable ECC (ECC is on by default), or you must enable static key cipher suites
with

    WOLFSSL_STATIC_DH
    WOLFSSL_STATIC_RSA
      or
    WOLFSSL_STATIC_PSK

though static key cipher suites are deprecated and will be removed from future
versions of TLS.  They also lower your security by removing PFS.  Since current
NTRU suites available do not use ephemeral keys, WOLFSSL_STATIC_RSA needs to be
used in order to build with NTRU suites.

When compiling ssl.c, wolfSSL will now issue a compiler error if no cipher
suites are available. You can remove this error by defining
WOLFSSL_ALLOW_NO_SUITES in the event that you desire that, i.e., you're not
using TLS cipher suites.

Note 2)
wolfSSL takes a different approach to certificate verification than OpenSSL
does. The default policy for the client is to verify the server, this means
that if you don't load CAs to verify the server you'll get a connect error,
no signer error to confirm failure (-188).

If you want to mimic OpenSSL behavior of having SSL_connect succeed even if
verifying the server fails and reducing security you can do this by calling:

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

before calling wolfSSL_new();. Though it's not recommended.

Note 3)
The enum values SHA, SHA256, SHA384, SHA512 are no longer available when
wolfSSL is built with --enable-opensslextra (OPENSSL_EXTRA) or with the macro
NO_OLD_SHA_NAMES. These names get mapped to the OpenSSL API for a single call
hash function. Instead the name WC_SHA, WC_SHA256, WC_SHA384 and WC_SHA512
should be used for the enum name.

*** end Notes ***


********* wolfSSL Release 4.0.0 (03/20/2019)

Release 4.0.0 of wolfSSL embedded TLS has bug fixes and new features including:

* Support for wolfCrypt FIPS v4.0.0, certificate #3389
* FIPS Ready Initiative
* Compatibility fixes for secure renegotiation with Chrome
* Better size check for TLS record fragment reassembly
* Improvements to non-blocking and handshake message retry support for DTLS
* Improvements to OCSP with ECDSA signers
* Added TLS server side secure renegotiation
* Added TLS Trusted CA extension
* Add support for the Deos Safety Critical RTOS
* OCSP fixes for memory management and initializations
* Fixes for EVP Cipher decryption padding checks
* Removal of null terminators on `wolfSSL_X509_print` substrings
* `wolfSSL_sk_ASN1_OBJCET_pop` function renamed to `wolfSSL_sk_ASN1_OBJECT_pop`
* Adjustment to include path in compatibility layer for evp.h and objects.h
* Fixes for decoding BER encoded PKCS7 contents
* TLS handshake now supports using PKCS #11 for private keys
* PKCS #11 support of HMAC, AES-CBC and random seeding/generation
* Support for named FFDHE parameters in TLS 1.2 (RFC 7919)
* Port to Zephyr Project
* Move the TLS PRF to wolfCrypt.
* Update to CMS KARI support
* Added ESP32 WROOM support
* Fixes and additions to the OpenSSL compatibility layer
* Added WICED Studio Support
* MDK CMSIS RTOS v2
* Xcode project file update
* Fixes for ATECC508A/ATECC608A
* Fixes issue with CA path length for self signed root CA's
* Fixes for Single Precision (SP) ASM when building sources directly
* Fixes for STM32 AES GCM
* Fixes for ECC sign with hardware to ensure the input is truncated
* Fixes for proper detection of PKCS7 buffer overflow case
* Fixes to handle degenerate PKCS 7 with BER encoding
* Fixes for TLS v1.3 handling of 6144 and 8192 bit keys
* Fixes for possible build issues with SafeRTOS
* Added `ECC_PUBLICKEY_TYPE` to the support PEM header types
* Added strict checking of the ECDSA signature DER encoding length
* Added ECDSA option to limit sig/algos in client_hello to key size with
  `USE_ECDSA_KEYSZ_HASH_ALGO`
* Added Cortex-M support for Single Precision (SP) math
* Added wolfCrypt RSA non-blocking time support
* Added 16-bit compiler support using --enable-16bit option
* Improved Arduino sketch example
* Improved crypto callback features
* Improved TLS benchmark tool
* Added new wrapper for snprintf for use with certain Visual Studio builds,
  thanks to David Parnell (Cambridge Consultants)

This release of wolfSSL includes a fix for 1 security vulnerability.

* Fixed a bug in tls_bench.c example test application unrelated to the crypto
  or TLS portions of the library. (CVE-2019-6439)


*** Resources ***


[wolfSSL Website](https://www.wolfssl.com/)

[wolfSSL Wiki](https://github.com/wolfSSL/wolfssl/wiki)

[FIPS FAQ](https://www.wolfssl.com/wolfSSL/fips.html)

[wolfSSL Manual](https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-toc.html)

[wolfSSL API Reference]
(https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-17-wolfssl-api-reference.html)

[wolfCrypt API Reference]
(https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-18-wolfcrypt-api-reference.html)

[TLS 1.3](https://www.wolfssl.com/docs/tls13/)
