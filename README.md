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
Curve25519, NTRU, and Blake2b. User benchmarking and feedback reports
dramatically better performance when using wolfSSL over OpenSSL.

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

**Note 1)**
wolfSSL as of 3.6.6 no longer enables SSLv3 by default.  wolfSSL also no longer
supports static key cipher suites with PSK, RSA, or ECDH. This means if you
plan to use TLS cipher suites you must enable DH (DH is on by default), or
enable ECC (ECC is on by default), or you must enable static key cipher suites
with one or more of the following defines:

    WOLFSSL_STATIC_DH
    WOLFSSL_STATIC_RSA
    WOLFSSL_STATIC_PSK

Though static key cipher suites are deprecated and will be removed from future
versions of TLS.  They also lower your security by removing PFS.  Since current
NTRU suites available do not use ephemeral keys, ```WOLFSSL_STATIC_RSA``` needs
to be used in order to build with NTRU suites.

When compiling ssl.c, wolfSSL will now issue a compiler error if no cipher
suites are available. You can remove this error by defining
```WOLFSSL_ALLOW_NO_SUITES``` in the event that you desire that, i.e., you're
not using TLS cipher suites.

**Note 2)**
wolfSSL takes a different approach to certificate verification than OpenSSL
does. The default policy for the client is to verify the server, this means
that if you don't load CAs to verify the server you'll get a connect error,
no signer error to confirm failure (-188).

If you want to mimic OpenSSL behavior of having SSL\_connect succeed even if
verifying the server fails and reducing security you can do this by calling:

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

before calling wolfSSL\_new();. Though it's not recommended.

**Note 3)**
The enum values SHA, SHA256, SHA384, SHA512 are no longer available when
wolfSSL is built with --enable-opensslextra (```OPENSSL_EXTRA```) or with the
macro ```NO_OLD_SHA_NAMES```. These names get mapped to the OpenSSL API for a
single call hash function. Instead the name WC_SHA, WC_SHA256, WC_SHA384 and
WC_SHA512 should be used for the enum name.

# wolfSSL Release 4.8.1 (July 16, 2021)
Release 4.8.1 of wolfSSL embedded TLS has an OCSP vulnerability fix:

### Vulnerabilities
* [High] OCSP verification issue when response is for a certificate with no relation to the chain in question BUT that response contains the NoCheck extension which effectively disables ALL verification of that one cert. Users who should upgrade to 4.8.1 are TLS client users doing OCSP, TLS server users doing mutual auth with OCSP, and CertManager users doing OCSP independent of TLS. Thanks to Jan Nauber, Marco Smeets, Werner Rueschenbaum and Alissa Kim for the report.

# wolfSSL Release 4.8.0 (July 09, 2021)
Release 4.8.0 of wolfSSL embedded TLS has bug fixes and new features including:

### Vulnerabilities
* [Low] OCSP request/response verification issue. In the case that the serial number in the OCSP request differs from the serial number in the OCSP response the error from the comparison was not resulting in a failed verification. We recommend users that have wolfSSL version 4.6.0 and 4.7.0 with OCSP enabled update their version of wolfSSL. Version 4.5.0 and earlier are not affected by this report. Thanks to Rainer, Roee, Barak, Hila and Shoshi (from Cymotive and CARIAD) for the report.
* [Low] CVE-2021-24116: Side-Channel cache look up vulnerability in base64 PEM decoding for versions of wolfSSL 4.5.0 and earlier. Versions 4.6.0 and up contain a fix and do not need to be updated for this report. If decoding a PEM format private key using version 4.5.0 and older of wolfSSL then we recommend updating the version of wolfSSL used. Thanks to Florian Sieck, Jan Wichelmann, Sebastian Berndt and Thomas Eisenbarth for the report.

### New Feature Additions
###### New Product
* Added wolfSentry build with --enable-wolfsentry and tie-ins to wolfSSL code for use with wolfSentry

###### Ports
* QNX CAAM driver added, supporting ECC black keys, CMAC, BLOBs, and TRNG use
*  _WIN32_WCE wolfCrypt port added
* INTIME_RTOS directory support added
* Added support for STM32G0
* Renesas RX: Added intrinsics for rot[rl], revl (thanks @rliebscher)
* Added support for running wolfcrypt/test/testwolfcrypt on Dolphin emulator to test DEVKITPRO port
* Zephyr project port updated to latest version 2.6.X

###### ASN1 and PKCS
* Storing policy constraint extension from certificate added
* Added support for NID_favouriteDrink pilot
* Added the API function wc_EncryptPKCS8Key to handle encrypting a DER, PKCS#8-formatted key

###### Compatibility Layer Additions
* Open Source PORTS Added/Updated
    - OpenVPN
    - OpenLDAP
    - socat-1.7.4.1
    - Updated QT port for 5.15.2
* Changes to extend set_cipher_list() compatibility layer API to have set_ciphersuites compatibility layer API capability
* Added more support for SHA3 in the EVP layer
* API Added
    - MD5/MD5_Transform
    - SHA/SHA_Transform/SHA1_Transform
    - SHA224/SHA256_Transform/SHA512_Transform
    - SSL_CTX_get0_param/SSL_CTX_set1_param
    - X509_load_crl_file
    - SSL_CTX_get_min_proto_version
    - EVP_ENCODE_CTX_new
    - EVP_ENCODE_CTX_free
    - EVP_EncodeInit
    - EVP_EncodeUpdate
    - EVP_EncodeFinal
    - EVP_DecodeInit
    - EVP_DecodeUpdate
    - EVP_DecodeFinal
    - EVP_PKEY_print_public
    - BIO_tell
    - THREADID_current
    - THREADID_hash
    - SSL_CTX_set_ecdh_auto
    - RAND_set_rand_method()
    - X509_LOOKUP_ctrl()
    - RSA_bits
    - EC_curve_nist2nid
    - EC_KEY_set_group
    - SSL_SESSION_set_cipher
    - SSL_set_psk_use_session_callback
    - EVP_PKEY_param_check
    - DH_get0_pqg
    - CRYPTO_get_ex_new_index
    - SSL_SESSION_is_resumable
    - SSL_CONF_cmd
    - SSL_CONF_CTX_finish
    - SSL_CTX_keylog_cb_func
    - SSL_CTX_set_keylog_callback
    - SSL_CTX_get_keylog_callback

###### Misc.
* Added wolfSSL_CTX_get_TicketEncCtx getter function to return the ticket encryption ctx value
* Added wc_AesKeyWrap_ex and wc_AesKeyUnWrap_ex APIs to accept an Aes object to use for the AES operations
* Added implementation of AES-GCM streaming (--enable-aesgcm-stream)
* Added deterministic generation of k with ECC following RFC6979 when the macro WOLFSL_ECDSA_DETERMINISTIC_K is defined and wc_ecc_set_deterministic function is called
* Implemented wc_DsaParamsDecode and wc_DsaKeyToParamsDer
* Asynchronous support for TLS v1.3 TLSX ECC/DH key generation and key agreement
* Added crypto callback support for Ed/Curve25519 and SHA2-512/384
* TLS 1.3 wolfSSL_key_update_response function added to see if a update response is needed

### Fixes
* Fix for detecting extra unused bytes that are in an ASN1 sequence appended to the end of a valid ECC signature
* Fix for keyid with ktri CMS (breaks compatibility with previous keyid ASN1 syntax)
* Fix for failed handshake if a client offers more than 150 cipher suites. Thanks to Marcel Maehren, Philipp Nieting, Robert Merget from Ruhr University Bochum Sven Hebrok, Juraj Somorovsky from Paderborn University
* Fix for default order of deprecated elliptic curves SECP224R1, SECP192R1, SECP160R1. Thanks to Marcel Maehren, Philipp Nieting, Robert Merget from Ruhr University Bochum Sven Hebrok, Juraj Somorovsky from Paderborn University
* Fix for corner TLS downgrade case where a TLS 1.3 setup that allows for downgrades but has TLS 1.3 set as the minimum version would still downgrade to TLS 1.2

###### PKCS7 (Multiple fixes throughout regarding memory leaks with SMIME and heap buffer overflows due to streaming functionality)
* Fix PKCS7 dynamic content save/restore in PKCS7_VerifySignedData
* Fix for heap buffer overflow on compare with wc_PKCS7_DecryptKtri
* Fix for heap buffer overflow with wc_PKCS7_VerifySignedData
* Fix for heap buffer overflow with wc_PKCS7_DecodeEnvelopedData
* Check size of public key used with certificate passed into wc_PKCS7_InitWithCert before XMEMCPY to avoid overflow
* Fix for heap buffer overflow fix for wolfSSL_SMIME_read_PKCS7
* Fix to cleanly free memory in error state with wolfSSL_SMIME_read_PKCS7
* SMIME error checking improvements and canonicalize multi-part messages before hashing

###### DTLS Fixes
* DTLS fix to correctly move the Tx sequence number forward
* DTLS fix for sequence and epoch number with secure renegotiation cookie exchange
* Fix for Chacha-Poly AEAD for DTLS 1.2 with secure renegotiation

###### PORT Fixes
* Fix AES, aligned key for the HW module with DCP port
* Fix ATECC608A TNGTLS certificate size issue (thanks @vppillai)
* Fixes for mingw compile warnings
* Fixes for NXP LTC ECC/RSA
* Fix ESP32 RSA hw accelerator initialization issue
* Fixes for STM32 PKA with ECC
* Fixes for STM32 AES GCM for HAL's that support byte sized headers
* Espressif ESP32 SHA_CTX macro conflict resolved

###### Math Library Fixes
* For platforms that support limits.h or windows make sure both SIZEOF_LONG_LONG and SIZEOF_LONG are set to avoid issues with CTC_SETTINGS
* SP C 32/64: fix corner cases around subtraction affecting RSA PSS use
* Fix to return the error code from sp_cond_swap_ct when malloc fails
* Fix potential memory leak with small stack in the function fp_gcd
* Static Analysis Fixes
* Fixes made from Coverity analysis including:
* Cleanups for some return values,
* Fix for leak with wolfSSL_a2i_ASN1_INTEGER
* Sanity check on length in wolfSSL_BN_rand
* Sanity check size in TLSX_Parse catching a possible integer overflow
* Fixes found with -fsanitize=undefined testing
* Fix null dereferences or undefined memcpy calls
* Fix alignment in myCryptoDevCb
* Fix default DTLS context assignment
* Added align configure option to force data alignment

###### Misc.
* Fix for wolfSSL_ASN1_TIME_adj set length
* Fix for freeing structure on error case in the function AddTrustedPeer
* Return value of SSL_read when called after bidirectional shutdown
* Fix for build options ./configure --enable-dtls --disable-asn
* FIx for detection of a salt length from an RSA PSS signature
* Fix to free up globalRNGMutex mutex when cleaning up global RNG
* Fix leak when multiple hardware names are in SAN
* Fix nonblocking ret value from CRL I/O callbacks
* Fix wolfSSL_BIO_free_all return type to better match for compatibility layer
* Fix for make distcheck, maintainer-clean, to allow distribution builds
* Fix for async with fragmented packets
* Fix for the build or RSA verify or public only
* Fix for return value of wolfSSL_BIO_set_ssl to better match expected compatibility layer return value
* Fix for sanity checks on size of issuer hash and key along with better freeing on error cases with DecodeBasicOcspResponse
* Fix for potential memory leak with wolfSSL_OCSP_cert_to_id

### Improvements/Optimizations
###### DTLS/TLS Code Base
* Improved TLS v1.3 time rollover support
* TLS 1.3 PSK: use the hash algorithm to choose cipher suite
* TLS Extended Master Secret ext: TLS13 - send in second Client Hello if in first
* TLS Encrypt then MAC: check all padding bytes are the same value
* wolfSSL_GetMaxRecordSize updated to now take additional cipher data into account
* Updated session export/import with DTLS to handle a new internal options flag
* Refactored dtls_expected_peer_handshake_number handling
* Added wolfSSL_CTX_get_ephemeral_key and wolfSSL_get_ephemeral_key for loading a constant key in place of an ephemeral one
* Improved checking of XSNPRINTF return value in DecodePolicyOID

###### Build Options and Warnings
* Added wolfSSL_CTX_set_verify to the ABI list
* Adjusted FP_ECC build to not allow SECP160R1, SECP160R2, SECP160K1 and SECP224K1. FP_ECC does not work with scalars that are the length of the order when the order is longer than the prime.
* Added CMake support for CURVE25519, ED25519, CURVE448, and ED448
* cmake addition to test paths when building
* Added support for session tickets in CMake
* Added support for reproducible builds with CMake
* Turn on reproducible-build by default when enable-distro
* Windows Project: Include the X448 and Ed448 files
* GCC-11 compile time warning fixes
* Fix for compiling build of ./configure '--disable-tlsv12' '-enable-pkcallbacks'
* Added build error for insecure build combination of secure renegotiation enabled with extended master secret disabled when session resumption is enabled
* Updated building and running with Apple M1
* Apache httpd build without TLS 1.3 macro guard added
* Enable SHA3 and SHAKE256 requirements automatically when ED448 is enabled
* Added option for AES CBC cipher routines to return BAD_LENGTH_E when called with an input buffer length not a multiple of AES_BLOCK_SIZE
* Macro WOLFSSL_SP_INT_DIGIT_ALIGN added for alignment on buffers with SP build. This was needed for compiler building on a Renesas board.
* Build support with no hashes enabled an no RNG compiled in
* Allow use of FREESCALE hardware RNG without a specific port
* Resolved some warnings with Windows builds and PBKDF disabled
* Updated the version of autoconf and automake along with fixes for some new GCC-10 warnings

###### Math Libraries
* SP: Thumb implementation that works with clang
* SP math all: sp_cmp handling of negative values
* SP C ECC: mont sub - always normalize after sub before check for add
* TFM math library prime checking, added more error checks with small stack build
* Sanity checks on 0 value with GCD math function
* fp_exptmod_ct error checking and small stack variable free on error
* Sanity check on supported digit size when calling mp_add_d in non fastmath builds
* Support for mp_dump with SP Math ALL
* WOLFSSL_SP_NO_MALLOC for both the normal SP build and small SP build now
* WOLFSSL_SP_NO_DYN_STACK added for SP small code that is not small stack build to avoid dynamic stack

###### PKCS 7/8
* wc_PKCS7_DecodeCompressedData to optionally handle a packet without content wrapping
* Added setting of content type parsed with PKCS7  wc_PKCS7_DecodeAuthEnvelopedData and wc_PKCS7_DecodeEnvelopedData
* PKCS8 code improvements and refactoring

###### Misc.
* Sanity checks on null inputs to the functions wolfSSL_X509_get_serialNumber and wolfSSL_X509_NAME_print_ex
* Added ARM CryptoCell support for importing public key with wc_ecc_import_x963_ex()
* Improved checking for possible use of key->dp == NULL cases with ECC functions
* Updated SHAKE256 to compile with NIST FIPS 202 standard and added support for OID values (thanks to strongX509)
* Improved ECC operations when using WOLFSSL_NO_MALLOC
* Added WOLFSSL_SNIFFER_FATAL_ERROR for an return value when sniffer is in a fatal state
* Allow parsing spaces in Base64_SkipNewline
* Issue callback when exceeding depth limit rather than error out with OPENSSL_EXTRA build
* Added NXP LTC RSA key generation acceleration


For additional vulnerability information visit the vulnerability page at
https://www.wolfssl.com/docs/security-vulnerabilities/

See INSTALL file for build instructions.
More info can be found on-line at https://wolfssl.com/wolfSSL/Docs.html



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
