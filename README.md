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
Curve25519, Blake2b and OQS TLS 1.3 groups. User benchmarking and feedback
reports dramatically better performance when using wolfSSL over OpenSSL.

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
wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
```

before calling `wolfSSL_new();`. Though it's not recommended.

### Note 3
The enum values SHA, SHA256, SHA384, SHA512 are no longer available when
wolfSSL is built with `--enable-opensslextra` (`OPENSSL_EXTRA`) or with the
macro `NO_OLD_SHA_NAMES`. These names get mapped to the OpenSSL API for a
single call hash function. Instead the name `WC_SHA`, `WC_SHA256`, `WC_SHA384` and
`WC_SHA512` should be used for the enum name.

# wolfSSL Release 5.0.0 (Nov 01, 2021)
Release 5.0.0 of wolfSSL embedded TLS has bug fixes and new features including:

### Vulnerabilities
* [\Low\] Hang with DSA signature creation when a specific q value is used in a maliciously crafted key. If a DSA key with an invalid q value of either 1 or 0 was decoded and used for creating a signature, it would result in a hang in wolfSSL. Users that are creating signatures with DSA and are using keys supplied from an outside source are affected.
* [\Low\] Issue with incorrectly validating a certificate that has multiple subject alternative names when given a name constraint. In the case where more than one subject alternative name is used in the certificate, previous versions of wolfSSL could incorrectly validate the certificate. Users verifying certificates with multiple alternative names and name constraints, are recommended to either use the certificate verify callback to check for this case or update the version of wolfSSL used. Thanks to Luiz Angelo Daros de Luca for the report.

### New Feature Additions
###### New Product
* FIPS 140-3 -- currently undergoing laboratory testing, code review and ultimately CMVP validation. Targeting the latest FIPS standard.

###### Ports
* IoT-Safe with TLS demo
* SE050 port with support for RNG, SHA, AES, ECC (sign/verify/shared secret) and ED25519
* Support for Renesas TSIP v1.13 on RX72N

###### Post Quantum
* Support for OQS's (liboqs version 0.7.0) implementation of NIST Round 3 KEMs as TLS 1.3 groups --with-liboqs
* Hybridizing NIST ECC groups with the OQS groups
* Remove legacy NTRU and QSH
* Make quantum-safe groups available to the compatibility layer

###### Linux Kernel Module
* Full support for FIPS 140-3, with in-kernel power on self test (POST) and conditional algorithm self test(s) (CAST)
* --enable-linuxkm-pie -- position-independent in-kernel wolfCrypt container, for FIPS
* Vectorized x86 acceleration in PK algs (RSA, ECC, DH, DSA) and AES/AES-GCM
* Vectorized x86 acceleration in interrupt handlers
* Support for Linux-native module signatures
* Complete SSL/TLS and Crypto API callable from other kernel module(s)
* Support for LTS kernel lines: 3.16, 4.4, 4.9, 5.4, 5.10

###### Compatibility Layer Additions
* Ports
	- Add support for libssh2
	- Add support for pyOpenSSL
	- Add support for libimobiledevice
	- Add support for rsyslog
	- Add support for OpenSSH 8.5p1
	- Add support for Python 3.8.5
* API/Structs Added
	- ERR_lib_error_string
	- EVP_blake2
	- wolfSSL_set_client_CA_list
	- wolfSSL_EVP_sha512_224
	- wolfSSL_EVP_sha512_256
	- wc_Sha512_224/2256Hash
	- wc_Sha512_224/256Hash
	- wc_InitSha512_224/256
	- wc_InitSha512_224/256_ex
	- wc_Sha512_224/256Update
	- wc_Sha512_224/256FinalRaw
	- wc_Sha512_224/256Final
	- wc_Sha512_224/256Free
	- wc_Sha512_224/256GetHash
	- wc_Sha512_224/256Copy
	- wc_Sha512_224/256SetFlags
	- wc_Sha512_224/256GetFlags
	- wc_Sha512_224/256Transform
	- EVP_MD_do_all and OBJ_NAME_do_all
	- EVP_shake128
	- EVP_shake256
	- SSL_CTX_set_num_tickets
	- SSL_CTX_get_num_tickets
	- SSL_CIPHER_get_auth_nid
	- SSL_CIPHER_get_cipher_nid
	- SSL_CIPHER_get_digest_nid
	- SSL_CIPHER_get_kx_nid
	- SSL_CIPHER_is_aead
	- SSL_CTX_set_msg_callback
	- a2i_IPADDRESS
	- GENERAL_NAME_print
	- X509_VERIFY_PARAM_set1_ip
	- EVP_CIPHER_CTX_set_iv_length
	- PEM_read_bio_RSA_PUBKEY
	- i2t_ASN1_OBJECT
	- DH_set_length
	- Set_tlsext_max_fragment_length
	- AUTHORITY_iNFO_ACCESS_free
	- EVP_PBE_scrypt
	- ASN1_R_HEADER_TOO_LONG
	- ERR_LIB
	- X509_get_default_cert_file/file_env/dir/dir_env() stubs
	- SSL_get_read_ahead/SSL_set_read_ahead()
	- SSL_SESSION_has_ticket()
	- SSL_SESSION_get_ticket_lifetime_hint()
	- DIST_POINT_new
	- DIST_POINT_free 
	- DIST_POINTS_free
	- CRL_DIST_POINTS_free
	- sk_DIST_POINT_push
	- sk_DIST_POINT_value
	- sk_DIST_POINT_num
	- sk_DIST_POINT_pop_free
	- sk_DIST_POINT_free
	- X509_get_extension_flags
	- X509_get_key_usage
	- X509_get_extended_key_usage
	- ASN1_TIME_to_tm
	- ASN1_TIME_diff
	- PEM_read_X509_REQ
	- ERR_load_ERR_strings
	- BIO_ssl_shutdown
	- BIO_get_ssl
	- BIO_new_ssl_connect
	- BIO_set_conn_hostname
	- NID_pkcs9_contentType

###### Misc.
* KCAPI: add support for using libkcapi for crypto (Linux Kernel)
* Configure option for --with-max-rsa-bits= and --with-max-ecc-bits=
* SP ARM Thumb support for Keil and performance improvements
* Add support for WOLFSSL_VERIFY_POST_HANDSHAKE verify mode
* PKCS #11: support static linking with PKCS #11 library --enable-pkcs11=static LIBS=-l
* Add build option --enable-wolfclu for use with wolfCLU product
* Add support for X9.42 header i.e “BEGIN X9.42 DH PARAMETERS”
* Add --enable-altcertchains for configuring wolfSSL with alternate certificate chains feature enabled
* Add public API wc_RsaKeyToPublicDer_ex to allow getting RSA public key without ASN.1 header (can return only seq + n + e)
* Add SNI and TLSx options to CMake build

### Fixes
###### PORT Fixes
* Add return value checking for FREESCALE_RNGA
* Fix MMCAU_SHA256 type warnings
* Fixes for building with Microchip XC32 and ATECC

###### Math Library Fixes
* TFM check that the modulus length is valid for fixed data array size
* TFM fp_submod_ct fix check for greater
* Check return value of mp_grow in mp_mod_2d
* Fix for ECC point multiply to error out on large multipliers
* SP ECC error on multiplier larger than curve order

###### TLS 1.3
* TLS1.3 sanity check for cases where a private key is larger than the configured maximum
* Fix early data max size handling in TLS v1.3
* Fixes for PK callbacks with TLS v1.3
* Check min downgrade when no extensions are sent with the ServerHello

###### Misc.
* Previously wolfSSL enum values were used as NID’s. Now only the compatibility layer NID enums are the NID values:
	- CTC_SHAwDSA -> NID_dsaWithSHA1
	- CTC_SHA256wDSA -> NID_dsa_with_SHA256
	- CTC_MD2wRSA -> NID_md2WithRSAEncryption
	- CTC_MD5wRSA -> NID_md5WithRSAEncryption
	- CTC_SHAwRSA -> NID_sha1WithRSAEncryption
	- CTC_SHA224wRSA -> NID_sha224WithRSAEncryption
	- CTC_SHA256wRSA -> NID_sha256WithRSAEncryption
	- CTC_SHA384wRSA -> NID_sha384WithRSAEncryption
	- CTC_SHA512wRSA -> NID_sha512WithRSAEncryption
	- CTC_SHA3_224wRSA -> NID_RSA_SHA3_224
	- CTC_SHA3_256wRSA -> NID_RSA_SHA3_256
	- CTC_SHA3_384wRSA -> NID_RSA_SHA3_384
	- CTC_SHA3_512wRSA -> NID_RSA_SHA3_512
	- CTC_SHAwECDSA -> NID_ecdsa_with_SHA1
	- CTC_SHA224wECDSA -> NID_ecdsa_with_SHA224
	- CTC_SHA256wECDSA -> NID_ecdsa_with_SHA256
	- CTC_SHA384wECDSA -> NID_ecdsa_with_SHA384
	- CTC_SHA512wECDSA -> NID_ecdsa_with_SHA512
	- CTC_SHA3_224wECDSA -> NID_ecdsa_with_SHA3_224
	- CTC_SHA3_256wECDSA -> NID_ecdsa_with_SHA3_256
	- CTC_SHA3_384wECDSA -> NID_ecdsa_with_SHA3_384
	- CTC_SHA3_512wECDSA -> NID_ecdsa_with_SHA3_512
	- DSAk -> NID_dsa
	- RSAk -> NID_rsaEncryption
	- ECDSAk -> NID_X9_62_id_ecPublicKey
	- BASIC_CA_OID -> NID_basic_constraints
	- ALT_NAMES_OID -> NID_subject_alt_name
	- CRL_DIST_OID -> NID_crl_distribution_points
	- AUTH_INFO_OID -> NID_info_access
	- AUTH_KEY_OID -> NID_authority_key_identifier
	- SUBJ_KEY_OID -> NID_subject_key_identifier
	- INHIBIT_ANY_OID -> NID_inhibit_any_policy
* Fix for DES IV size used with FIPSv2
* Fix signed comparison issue with serialSz
* Fix missing CBIOSend and properly guard hmac in DupSSL()
* Fix calculation of length of encoding in ssl.c
* Fix encoding to check proper length in asn.c
* Fix for wc_ecc_ctx_free and heap hint
* Fix for debug messages with AF_ALG build
* Fix for static memory with bucket size matching.
* Fixes for SRP with heap hint.
* Fixes for CAAM build macros and spelling for Keil build
* Sniffer fix for possible math issue around 64-bit pointer and 32-bit unsigned int
* Fix for sniffer TCP sequence rollover
* wolfSSL_PEM_write_bio_PUBKEY to write only the public part
* Fix for sending only supported groups in TLS extension
* Fix for sniffer to better handle spurious retransmission edge case
* SSL_set_alpn_protos and SSL_CTX_set_alpn_protos now returns 0 on successFixes issue with SSL_CTX_set1_curves_list and SSL_set1_curves_list not checking the last character of the names variable provided, non-0 on failure to better match expected return values
* Fixes and improvements for crypto callbacks with TLS (mutual auth)
* Fix for bad memory_mutex lock on static memory cleanup
* Zero terminate name constraints strings when parsing certificates
* Fix for verifying a certificate when multiple permitted name constraints are used
* Fix typo in ifdef for HAVE_ED448
* Fix typos in comments in SHA512
* Add sanity check on buffer size with ED25519 key decode
* Sanity check on PKCS7 stream amount read
* PKCS7 fix for double free on error case and sanity check on set serial number
* Sanity check on PKCS7 input size wc_PKCS7_ParseSignerInfo
* Forgive a DTLS session trying to send too much at once

### Improvements/Optimizations
###### Build Options and Warnings
* Rework of RC4 disable by default and depreciation
* wolfSSL as a Zephyr module (without setup.sh)
* Add include config.h to bio.c
* Support for PKCS7 without AES CBC.
* Fixes for building without AES CBC
* Added WOLFSSL_DH_EXTRA to --enable-all and --enable-sniffer
* Add a CMake option to build wolfcrypt test and bench code as libraries
* GCC makefile: allow overriding and provide more flexibility

###### Math Libraries
* Improve performance of fp_submod_ct() and fp_addmod_ct()
* Improve performance of sp_submod_ct() and sp_addmod_ct()
* SP int, handle even modulus with exponentiation

###### Misc.
* Cleanups for Arduino examples and memory documentation
* Refactor hex char to byte conversions
* Added GCC-ARM TLS server example
* Improvements to session locking to allow per-row
* Improved sniffer statistics and documentation
* EVP key support for heap hint and crypto callbacks
* Reduced stack size for dh_generation_test and Curve ASN functions
* Espressif README Syntax / keyword highlighting / clarifications
* AARCH64 SHA512: implementation using crypto instructions added
* wc_RsaPSS_CheckPadding_ex2 added for use with HEAP hint
* wc_AesKeyWrap_ex and wc_AesKeyUnWrap_ex bound checks on input and output sizes
* Add additional error handling to wolfSSL_BIO_get_len
* Add code to use popen and the command 'host', useful with qemu
* Adjustment to subject alt names order with compatibility layer to better match expected order
* Reduce BIO compatibility layer verbosity
* Set a default upper bound on error queue size with compatibility layer
* WOLFSSL_CRL_ALLOW_MISSING_CDP macro for Skip CRL verification in case no CDP in peer cert
* Fixes for scan-build LLVM-13 and expanded coverage
* Increase the default DTLS_MTU_ADDITIONAL_READ_BUFFER and make it adjustable


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
