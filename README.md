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

# wolfSSL Release 5.5.0 (Aug 30, 2022)

Note:
** If not free’ing FP_ECC caches per thread by calling wc_ecc_fp_free there is a possible memory leak during TLS 1.3 handshakes which use ECC. Users are urged to confirm they are free’ing FP_ECC caches per thread if enabled to avoid this issue.

Release 5.5.0 of wolfSSL embedded TLS has bug fixes and new features including:

## Vulnerabilities
* [Low] Fault injection attack on RAM via Rowhammer leads to ECDSA key disclosure. Users doing operations with private ECC keys such as server side TLS connections and creating ECC signatures, who also have hardware that could be targeted with a sophisticated Rowhammer attack should update the version of wolfSSL and compile using the macro WOLFSSL_CHECK_SIG_FAULTS. Thanks to Yarkin Doroz, Berk Sunar, Koksal Must, Caner Tol, and Kristi Rahman all affiliated with the Vernam Applied Cryptography and Cybersecurity Lab at Worcester Polytechnic Institute for the report.
* [Low] In wolfSSL version 5.3.0 if compiled with --enable-session-ticket and the client has non-empty session cache, with TLS 1.2 there is the possibility of a man in the middle passing a large session ticket to the client and causing a crash due to an invalid free. There is also the potential for a malicious TLS 1.3 server to crash a client in a similar manner except in TLS 1.3 it is not susceptible to a man in the middle attack. Users on the client side with –enable-session-ticket compiled in and using wolfSSL version 5.3.0 should update their version of wolfSSL. Thanks to Max at Trail of Bits for the report and "LORIA, INRIA, France" for research on tlspuffin.
* [Low] If using wolfSSL_clear to reset a WOLFSSL object (vs the normal wolfSSL_free/wolfSSL_new) it can result in runtime issues. This exists with builds using the wolfSSL compatibility layer (--enable-opnesslextra) and only when the application is making use of wolfSSL_clear instead of SSL_free/SSL_new. In the case of a TLS 1.3 resumption, after continuing to use the WOLFSSH object after having called wolfSSL_clear, an application could crash. It is suggested that users calling wolfSSL_clear update the version of wolfSSL used. Thanks to Max at Trail of Bits for the report and "LORIA, INRIA, France" for research on tlspuffin.
* Potential DoS attack on DTLS 1.2. In the case of receiving a malicious plaintext handshake message at epoch 0 the connection will enter an error state reporting a duplicate message. This affects both server and client side. Users that have DTLS enabled and in use should update their version of wolfSSL to mitigate the potential for a DoS attack.

## New Feature Additions
* QUIC support added, for using wolfSSL with QUIC implementations like ngtcp2
* SE050 port additions and fixes
* Added support for Dilithium post quantum algorithm use with TLS
* Support for RSA-PSS signed certificates
* Support for Infineon AURIX IDE
* Add Zephyr support for nRF5340 with CryptoCell-312

## Enhancements
* Expanded ABI support by 50 APIs to include wolfCrypt and Certificates making a total of 113 ABIs controlled and maintained
* DTLS 1.3 partial support for ConnectionID as described by RFC9146 and RFC9147
* Added support for X509_CRL_print function
* Remove deprecated algorithms in Renesas cs+ project
* Support more build options disable/enable with i.MX CAAM build
* wolfSSL_CTX_set_options and wolfSSL_CTX_get_options functions added to non compatibility layer builds
* TFM: change inline x86 asm code to compile with clang
* Improvements to error queue and fix for behavior of wolfSSL_ERR_get_error
* scripts/makedistsmall.sh script added for creating a small source/header only package
* TLS 1.3: restrict extension validity by message, Extensions ServerName, SupportedGroups and ALPN must not appear in server_hello
* Add liboqs integration to CMake build system
* Adds wolfSSL_PEM_read_RSAPrivateKey() to the OpenSSL compatible API
* Added support for P384 pre-share in bundled example server
* Replace clz assembly instruction in ARM 32 builds when not supported
* Integrate chacha20-poly1305 into the EVP interface
* Additional validation that extensions appear in correct messages
* Allow SAN to be critical with ASN template build
* Support wolfSSL_CTX_set1_curves_list being available when X25519 and/or X448 only defined
* Adds wolfSSL_PEM_read_RSA_PUBKEY() to the OpenSSL compatible API
* Match OpenSSL self signed error return with compatibility layer build
* Added wolfSSL_dtls_create_peer and wolfSSL_dtls_free_peer to help with Python and Go wrappers for DTLS

## Fixes
* DTLS 1.3 asynchronous use case fixes
* Fix handling of counter to support incrementing across all bytes in ARM crypto asm
* Fixes for ED25519/ED448 private key with public key export (RFC8410)
* Fix for build with NO_TLS macro
* Fix for write dup function to copy over TLS version
* Fix to handle path lengths of 0 when checking certificate CA path lengths
* Fix for CMake not installing sp_int.h for SP math all
* When WOLFSSL_VALIDATE_ECC_IMPORT is defined ECC import validates private key value is less than order
* PSA crypto fixes
* Fix for not having default pkcs7 signed attributes
* DTLS socket and timeout fixes
* SP int: exptmod ensure base is less than modulus
* Fix for AddPacketInfo with WOLFSSL_CALLBACKS to not pass encrypted TLS 1.3 handshake messages to callbacks
* Fix for sniffer to ensure the session was polled before trying to reprocess it


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
