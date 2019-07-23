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


********* wolfSSL Release 4.1.0 (07/22/2019)

Release 4.1.0 of wolfSSL embedded TLS has bug fixes and new features including:

* A fix for the check on return value when verifying PKCS7 bundle signatures, all users with applications using the function wc_PKCS7_VerifySignedData should update
* Adding the function wc_PKCS7_GetSignerSID for PKCS7 firmware bundles as a getter function for the signers SID
* PKCS7 callback functions for unwrapping of CEK and for decryption
* Adding the error value PKCS7_SIGNEEDS_CHECK when no certificates are available in a PKCS7 bundle to verify the signature
* TLS 1.3 fixes including if major version is TLS Draft then it is now ignored and if version negotiation occurs but none were matched then an alert is now sent
* Addition of the WOLFSSL_PSK_ONE_ID macro for indicating that only one identity in TLS 1.3 PSK is available and will be cached
* Adding sanity checks on length of PSK identity from a TLS 1.3 pre-shared key extension
* Additional sanity checks and alert messages added for TLS 1.3
* Adding XTIME_MS macro to simplify the tls13.c time requirement
* Improvements and refactoring of code related to parsing and creating TLS 1.3 client hello packets
* TLS 1.3 version renegotiation now happens before interpreting ClientHello message
* Chacha20 algorithm optimizations on the ARM architecture for performance increase
* Poly1305 algorithm performance enhancements for the ARM architecture using the SIMD NEON extension
* Curve25519 and Ed25519 optimized for ARM architecture for performance increase
* SHA-512/384 optimizations for performance with ARM architecture using the SIMD NEON extension
* Sniffer updates including adding support for the null cipher and static ECDH key exchange and new SSLWatchCb callback
* Cipher suite TLS_RSA_WITH_NULL_MD5 for use with the sniffer (off by default)
* Sniffer statistic print outs with the macro WOLFSSL_SNIFFER_STATS defined
* A fix for wolfSSL_DH_generate_key when WOLFSSL_SMALL_STACK is defined
* wolfSSL_BN_Init implementation for opensslextra builds
* Updates to the function wolfSSL_i2d_RSAPrivateKey and additional automated tests
* Fixes for EVP_CipherFinal edge cases to match behavior desired
* Check for appropriate private vs public flag with ECC key decode in wolfSSL_EC_KEY_LoadDer_ex, thanks to Eric Miller for the report
* Implementation of the function wolfSSL_PEM_write_DHparams
* wolfSSL_RAND_seed is called in wolfSSL_Init now when opensslextra is enabled
* CryptoCell-310 support on nRF52840 added
* Fixes for atmel_ecc_create_pms to free the used slot.
* Fixes for building ATECC with ATCAPRINTF or WOLFSSL_PUBLIC_MP
* Cortex-M code changes to support IAR compiler
* Improvements to STM32 AES-GCM performance
* Fixes for 16-bit systems including PK callbacks, ATECC and LowResTimer function ptoto.
* IAR-EWARM compiler warning fix
* Clean up of user_settings for CS+ port
* Updating Renesas example projects to the latest version
* Micrium updates adjusting STATIC macro name and added inline flag
* Fixes for building with WOLFSSL_CUSTOM_CURVES on Windows
* Updates and refactor to the default build settings with Arduino
* Fixes for visibility tags with Cygwin build
* STSAFE Improvements to support wolfSSL Crypto Callbacks
* Improvements to NetBSD builds and mutex use in test case
* Updating TI hardware offload with WOLFSSL_TI_CRYPT build
* Maintaining Xilinx FreeRTOS port by adjusting time.h include in wolfSSL
* SiFive HiFive E31 RISC‐V core family port
* Port for Telit IoT AppZone SDK
* OCSP Response signed by issuer with identical SKID fix
* Fix for sending revoked certificate with OCSP
* Honor the status sent over connection with peers and do not perform an internal OCSP lookup
* Adding the build flag `--enable-ecccustcurves=all` to enable all curve types
* Support add for Ed25519ctx and Ed25519ph sign/verify algorithms as per RFC 8032
* Addition of the macro WOLFSSL_NO_SIGALG to disable signature algorithms extension
* wc_AesCtrEncrypt in place addition, where input and output buffer can be the same buffer
* Single shot API added for SHA3; wc_Sha3_224Hash, wc_Sha3_256Hash, wc_Sha3_384Hash, wc_Sha3_512Hash
* Function additions for JSSE support some of which are wolfSSL_get_ciphers_iana and wolfSSL_X509_verify along with expansion of the --enable-jni option
* Macro guards for more modular SHA3 build (i.e. support for 384 size only)
* Benchmarking -thread <num> argument support for asynchronous crypto
* Blake2s support (--enable-blake2s), which provides 32-bit Blake2 support
* Macro SHA256_MANY_REGISTERS addition to potentially speed up SHA256 depending on architecture
* Additional TLS alert messages sent with the macro WOLFSSL_EXTRA_ALERTS defined
* Feature to fail resumption of a session if the session’s cipher suite is not in the client’s list, this can be overridden by defining the macro NO_RESUME_SUITE_CHECK
* Fallback SCSV (Signaling Cipher Suite Value) support on Server only (--enable-fallback-scsv)
* DTLS export state only (wolfSSL_dtls_export_state_only) which is a subset of the information exported from previous DTLS export function
* Function wc_DhCheckPubValue added to perform simple validity checks on DH keys
* Support for RSA SHA-224 signatures with TLS added
* Additional option “-print” to the benchmark app for printing out a brief summary after benchmarks are complete
*  Adding (--disable-pkcs12) option and improvements for disabled sections in pwdbased.c, asn.c, rsa.c, pkcs12.c and wc_encrypt
* Added DES3 support to the wolfSSL crypto callbacks
* Compile time fixes for build case with SP math and RSA only
* Fixes for Coverity static analysis report including explicit initialization of reported stack variables some additional Coverity fixes added thanks to Martin
* Fixes for scan build warnings (i.e possible null dereference in ecc.c)
* Resetting verify send value with a call to wolfSSL_clear function
* Fix for extern with sp_ModExp_2048 when building with --cpp option
* Fix for typo issue with --enable-sp=cortexm
* Adding #pragma warning disable 4127 for tfm.c when building with Visual Studio
* Improvements to the maximum ECC signature calculations
* Improvements to TLS write handling in error cases which helps user application not go through with a wolfSSL_write attempt after a wolfSSL_read failure
* Fix for read directory functions with Windows (wc_ReadDirFirst and wc_ReadDirNext)
* Sanity check on index before accessing domain component buffer in call to wolfSSL_X509_NAME_get_entry
* Sending fatal alert from client side on version error
* Fix for static RSA cipher suite with PK callback and no loaded private key
* Fix for potential memory leak in error case with the function wc_DsaKeyToDer, thanks to Chris H. for the report
* Adjusting STRING_USER macro to remove includes of standard lib <string.h> or <stdio.h>
* Bug fix for checking wrong allocation assignment in the function wc_PBKDF2 and handling potential leak on allocation failure. This case is only hit when the specific call to malloc fails in the function wc_PBKDF2. Thanks to Robert Altnoeder (Linbit) for the report
* Improved length checks when parsing ASN.1 certificates
* extern "C" additions to header files that were missing them
* Improved checking of return values with TLS extension functions and error codes
* Removing redundant calls to the generate function when instantiating and reseeding DRBG
* Refactoring and improvements to autoconf code with consolidating AM_CONDITIONAL statements
* Improvements for handling error return codes when reading input from transport layer
* Improvements to efficiency of SNI extension parsing and error checking with ALPN parsing
* Macro WOLFSSL_DEBUG_TLS addition for printing out extension data being parsed during a TLS connection
* Adjustment of prime testing with --disable-fastmath builds


This release of wolfSSL includes a fix for 2 security vulnerabilities.

There is a fix for a potential buffer overflow case with the TLSv1.3 PSK extension parsing. This affects users that are enabling TLSv1.3 (--enable-tls13). Thanks to Robert Hoerr for the report. The CVE associated with the report is CVE-2019-11873.

There is a fix for the potential leak of nonce sizes when performing ECDSA signing operations. The leak is considered to be difficult to exploit but it could potentially be used maliciously to perform a lattice based timing attack against previous wolfSSL versions. ECC operations with --enable-sp and --enable-sp-asm are not affected, users with private ECC keys in other builds that are performing ECDSA signing operations should update versions of wolfSSL along with private ECC keys. Thanks to Ján Jančár from Masaryk University for the report.


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
