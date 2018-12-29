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

# wolfSSL Release 3.15.7 (12/26/2018)

Release 3.15.7 of wolfSSL embedded TLS has bug fixes and new features including:

* Support for Espressif ESP-IDF development framework
* Fix for XCode build with iPhone simulator on i386
* PKCS7 support for generating and verify bundles using a detached signature
* Fix for build disabling AES-CBC and enabling opensslextra compatibility layer
* Updates to sniffer for showing session information and handling split messages across records
* Port update for Micrium uC/OS-III
* Feature to adjust max fragment size post handshake when compiled with the macro WOLFSSL_ALLOW_MAX_FRAGMENT_ADJUST
* Adding the macro NO_MULTIBYTE_PRINT for compiling out special characters that embedded devices may have problems with
* Updates for Doxygen documentation, including PKCS #11 API and more
* Adding Intel QuickAssist v1.7 driver support for asynchronous crypto
* Adding Intel QuickAssist RSA key generation and SHA-3 support
* RSA verify only (--enable-rsavfy) and RSA public only (--enable-rsapub) builds added
* Enhancements to test cases for increased code coverage
* Updates to VxWorks port for use with Mongoose, including updates to the OpenSSL compatibility layer
* Yocto Project ease of use improvements along with many updates and build instructions added to the INSTALL file
* Maximum ticket nonce size was increased to 8
* Updating --enable-armasm build for ease of use with autotools
* Updates to internal code checking TLS 1.3 version with a connection
* Removing unnecessary extended master secret from ServerHello if using TLS 1.3
* Fix for TLS v1.3 HelloRetryRequest to be sent immediately and not grouped



This release of wolfSSL includes a fix for 1 security vulnerability.

Medium level fix for potential cache attack with a variant of Bleichenbacher’s attack. Earlier versions of wolfSSL leaked PKCS #1 v1.5 padding information during private key decryption that could lead to a potential padding oracle attack. It is recommended that users update to the latest version of wolfSSL if they have RSA cipher suites enabled and have the potential for malicious software to be ran on the same system that is performing RSA operations. Users that have only ECC cipher suites enabled and are not performing RSA PKCS #1 v1.5 Decryption operations are not vulnerable. Also users with TLS 1.3 only connections are not vulnerable to this attack. Thanks to Eyal Ronen (Weizmann Institute), Robert Gillham (University of Adelaide), Daniel Genkin (University of Michigan), Adi Shamir (Weizmann Institute), David Wong (NCC Group), and Yuval Yarom (University of Adelaide and Data61) for the report.

The paper for further reading on the attack details can be found at http://cat.eyalro.net/cat.pdf.


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
