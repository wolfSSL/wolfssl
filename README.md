# wolfSSL Embedded SSL/TLS Library

The [wolfSSL embedded SSL library](https://www.wolfssl.com/products/wolfssl/)
(formerly CyaSSL) is a lightweight SSL/TLS library written in ANSI C and
targeted for embedded, RTOS, and resource-constrained environments - primarily
because of its small size, speed, and feature set.  It is commonly used in
standard operating environments as well because of its royalty-free pricing
and excellent cross platform support. wolfSSL supports industry standards up
to the current [TLS 1.3](https://www.wolfssl.com/tls13) and DTLS 1.3, is up to
20 times smaller than OpenSSL, and offers progressive ciphers such as ChaCha20,
Curve25519, BLAKE2b/BLAKE2s and Post-Quantum TLS 1.3 groups. User benchmarking
and feedback reports dramatically better performance when using wolfSSL over
OpenSSL.

wolfSSL is powered by the wolfCrypt cryptography library. Two versions of
wolfCrypt have been FIPS 140-2 validated (Certificate #2425 and
certificate #3389). FIPS 140-3 validated (Certificate #4718). For additional
information, visit the [wolfCrypt FIPS FAQ](https://www.wolfssl.com/license/fips/)
or contact fips@wolfssl.com.

## Why Choose wolfSSL?

There are many reasons to choose wolfSSL as your embedded, desktop, mobile, or
enterprise SSL/TLS solution. Some of the top reasons include size (typical
footprint sizes range from 20-100 kB), support for the newest standards
(SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, DTLS 1.0, DTLS 1.2, and DTLS 1.3),
current and progressive cipher support (including stream ciphers), multi-platform,
royalty free, and an OpenSSL compatibility API to ease porting into existing
applications which have previously used the OpenSSL package. For a complete
feature list, see [Chapter 4](https://www.wolfssl.com/docs/wolfssl-manual/ch4/)
of the wolfSSL manual.

## Notes, Please Read

### Note 1
wolfSSL as of 3.6.6 no longer enables SSLv3 by default. By default, wolfSSL
disables static key cipher suites that use PSK, RSA, or ECDH without ephemeral
key exchange. Instead, wolfSSL enables cipher suites that provide perfect
forward secrecy (PFS) using ephemeral Diffie-Hellman (DH) or Elliptic Curve
(ECC) key exchange, both of which are enabled by default.

If you need to support legacy systems that require static key cipher suites,
you can enable them using one or more of these defines:

* `WOLFSSL_STATIC_DH`
* `WOLFSSL_STATIC_RSA`
* `WOLFSSL_STATIC_PSK`

**Important:** Static key cipher suites reduce security by eliminating perfect
forward secrecy. These cipher suites reuse the same long-term private key for
all session key exchanges. In contrast, PFS-enabled cipher suites (the wolfSSL
default) generate a new ephemeral key for each session, ensuring that
compromising a long-term key cannot decrypt past sessions.

When compiling `ssl.c`, wolfSSL will now issue a compiler error if no cipher
suites are available. You can remove this error by defining
`WOLFSSL_ALLOW_NO_SUITES` in the event that you desire that, i.e., you're
not using TLS cipher suites.

### AES CryptoCB Key Import Support

wolfSSL supports hardware-accelerated AES operations via CryptoCB.

When `WOLF_CRYPTO_CB_AES_SETKEY` is defined, wolfSSL invokes a CryptoCB
callback during AES key setup. The callback behavior determines the mode:

**If callback returns 0 (success):**
- Key is imported to Secure Element/HSM
- Key is NOT copied to wolfSSL RAM (true key isolation)
- GCM tables are NOT generated (full hardware offload)
- All subsequent AES operations route through CryptoCB

**If callback returns CRYPTOCB_UNAVAILABLE:**
- SE doesn't support key import
- Normal software AES path is used
- Key is copied to devKey for CryptoCB encrypt/decrypt acceleration

This feature enables TLS 1.3 traffic key protection on embedded platforms
where symmetric keys must never exist in main RAM.

Enable with: `CPPFLAGS="-DWOLF_CRYPTO_CB_AES_SETKEY -DWOLF_CRYPTO_CB_FREE"`

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


# wolfSSL Release 5.9.0 (Mar. 18, 2026)

Release 5.9.0 has been developed according to wolfSSL's development and QA
process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE: * --enable-heapmath is deprecated
      * MD5 is now disabled by default

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request number where the code change was added.

## Vulnerabilities

* [High] CVE-2026-3548
Two buffer overflow vulnerabilities existed in the wolfSSL CRL parser when parsing CRL numbers: a heap-based buffer overflow could occur when improperly storing the CRL number as a hexadecimal string, and a stack-based overflow for sufficiently sized CRL numbers. With appropriately crafted CRLs, either of these out of bound writes could be triggered. Note this only affects builds that specifically enable CRL support, and the user would need to load a CRL from an untrusted source. Found with internal wolfSSL testing. Fixed in PR 9628 and PR 9873.

* [High] CVE-2026-3549
Heap Overflow in TLS 1.3 ECH parsing. An integer underflow existed in ECH extension parsing logic when calculating a buffer length, which resulted in writing beyond the bounds of an allocated buffer. Note that in wolfSSL, ECH is off by default, and the ECH standard is still evolving. Found with internal wolfSSL testing, thanks to Oleh Konko for testing. Fixed in PR 9817.

* [High] CVE-2026-3547
Out-of-bounds read in ALPN parsing due to incomplete validation. wolfSSL 5.8.4 and earlier contained an out-of-bounds read in ALPN handling when built with ALPN enabled (HAVE_ALPN / --enable-alpn). A crafted ALPN protocol list could trigger an out-of-bounds read, leading to a potential process crash (denial of service). Note that ALPN is disabled by default, but is enabled for these 3rd party compatibility features: enable-apachehttpd, enable-bind, enable-curl, enable-haproxy, enable-hitch, enable-lighty, enable-jni, enable-nginx, enable-quic. Users of these features are recommended to update to 5.9.0. Thanks to Oleh Konko for the report. Fixed in PR 9860.

* [Med] CVE-2026-2646
A heap-buffer-overflow vulnerability exists in wolfSSL's wolfSSL_d2i_SSL_SESSION() function. When deserializing session data with SESSION_CERTS enabled, certificate and session id lengths are read from an untrusted input without bounds validation, allowing an attacker to overflow fixed-size buffers and corrupt heap memory. A maliciously crafted session would need to be loaded from an external source to trigger this vulnerability. Internal sessions were not vulnerable. Thanks to Jonathan Bar Or, and Haruto Kimura (Stella) for the report. Fixed in PR 9748 and PR 9949.

* [Med] CVE-2026-3849
Stack Buffer Overflow in wc_HpkeLabeledExtract via oversized ECH config. A vulnerability exists in wolfSSL 5.8.4 and earlier ECH (Encrypted Client Hello) support, where a maliciously crafted ECH config could cause a stack buffer overflow on the client side, leading to client program crash, with a potential for remote execution. This could be exploited by a malicious TLS server supporting ECH. Note that ECH is off by default, and is only enabled with enable-ech. Thanks to Haruto Kimura (Stella) for the report. Fixed in PR 9737.

* [Low] CVE-2026-0819
wolfSSL PKCS7 SignedData encoding OOB write (signed attributes). A vulnerability existed in the API wc_PKCS7_EncodeSignedData, and wc_PKCS7_EncodeSignedData_ex, where when encoding signed data with custom attributes, wolfSSL could write past a fixed size array resulting in a stack out of bounds write. This vulnerability only occurred when trying to create a signed PKCS7 encoding with more than 7 signed attributes, and did not affect PKCS7 parsing in general. Thanks to Maor Caplan for the report. Fixed in PR 9630.

* [Low] CVE-2026-1005
Integer underflow in wolfSSL packet sniffer. wolfSSL 5.8.4 and earlier allows an attacker to cause a buffer overflow in the AEAD decryption path by injecting a TLS record shorter than the explicit IV plus authentication tag into traffic inspected by ssl_DecodePacket. The underflow wraps a 16-bit length to a large value that is passed to AEAD decryption routines, causing a heap buffer overflow and a potential crash. An unauthenticated attacker can trigger this remotely via malformed TLS Application Data records. The sniffer feature is disabled by default and this only affects builds with --enable-sniffer and AEAD support. Thanks to Prasanth Sundararajan for the report. Fixed in PR 9571.

* [Low] CVE-2026-2645
In wolfSSL 5.8.2 and earlier, a logic flaw existed in the TLS 1.2 server state machine implementation. The server could incorrectly accept the CertificateVerify message before the ClientKeyExchange message had been received. This issue affects wolfSSL before 5.8.4 (wolfSSL 5.8.2 and earlier is vulnerable, 5.8.4 is not vulnerable). In 5.8.4 wolfSSL would detect the issue later in the handshake. 5.9.0 was further hardened to catch the issue earlier in the handshake. Thanks to Kai Tian for the report. Fixed in PR 9694.

* [Low] CVE-2026-3230
In versions of wolfSSL 5.8.4 and earlier the client does not catch if the required key_share extension is missing from a ServerHello sent after a crafted HelloRetryRequest. In the missing key_share extension case the client still goes through the process of authenticating the server correctly, and would then continue on to establish a connection with a predictable key being derived. Since the authentication of the server is still established, this only is an issue if the server can unknowingly be forced to send the malformed HelloRetryRequest followed by the ServerHello that omits the key_share extension. Thanks to Jaehun Lee for the report. Fixed in PR 9754.

* [Low] CVE-2026-3229. Integer Overflow in Certificate Chain Allocation. An integer overflow vulnerability existed in the static function wolfssl_add_to_chain, that caused heap corruption when certificate data was written out of bounds of an insufficiently sized certificate buffer. wolfssl_add_to_chain is called by these API: wolfSSL_CTX_add_extra_chain_cert, wolfSSL_CTX_add1_chain_cert, wolfSSL_add0_chain_cert. These API are enabled for 3rd party compatibility features: enable-opensslall, enable-opensslextra, enable-lighty, enable-stunnel, enable-nginx, enable-haproxy. This issue is not remotely exploitable, and would require that the application context loading certificates is compromised. Thanks to Pelioro and Kunyuk for responsibly reporting this issue. Fixed in PR 9827.

* [Low] CVE-2026-3579
wolfSSL 5.8.4 and earlier on RISC-V RV32I architectures lacks a constant-time software implementation for 64-bit multiplication. The compiler-inserted __muldi3 subroutine executes in variable time based on operand values. This affects multiple SP math functions (sp_256_mul_9, sp_256_sqr_9, etc.), leading to a timing side-channel that may expose sensitive cryptographic data. Thanks to Wind Wong for the report. Fixed in PR 9855.

* [Low] CVE-2026-3580. Compiler-induced timing leak in sp_256_get_entry_256_9 on RISC-V. In wolfSSL 5.8.4 and earlier, constant-time masking logic in sp_256_get_entry_256_9 is optimized into conditional branches (bnez) by GCC when targeting RISC-V RV32I with -O3. This transformation breaks the side-channel resistance of ECC scalar multiplication, potentially allowing a local attacker to recover secret keys via timing analysis. Thanks to Wind Wong for the report. Also fixed in PR 9855.

* [Low] CVE-2026-3503
A protection mechanism failure in wolfCrypt post-quantum implementations (ML-KEM and ML-DSA) in wolfSSL on ARM Cortex-M microcontrollers allows a physical attacker to compromise key material and/or cryptographic outcomes via induced transient faults that corrupt or redirect seed/pointer values during Keccak-based expansion. This issue affects wolfSSL (wolfCrypt): commit hash d86575c766e6e67ef93545fa69c04d6eb49400c6. Thanks to Hariprasad Kelassery Valsaraj of Temasek Laboratories for the report. Fixed in PR 9734.

* [Low] CVE-2026-4159
1-byte OOB heap read in wc_PKCS7_DecodeEnvelopedData via zero-length encrypted content. A vulnerability existed in wolfSSL 5.8.4 and earlier, where a 1-byte out-of-bounds heap read in wc_PKCS7_DecodeEnvelopedData could be triggered by a crafted CMS EnvelopedData message with zero-length encrypted content. Note that PKCS7 support is disabled by default. Thanks to Haruto Kimura (Stella). Fixed in PR9945.

* [Low] CVE-2026-4395
A heap buffer out of bounds write case existed in wolfSSL version 5.8.4 and earlier when importing an ECC key while built with KCAPI support. The fix implemented added a check on the raw pubkey length in wc_ecc_import_x963 before copying it to an internal struct. KCAPI support is turned off by default and only enabled with builds using --enable-kcapi. Thanks to Haruto Kimura (Stella) for the report. Fixed in PR 9988.

## New features
* FIPS 205, SLH-DSA implementation by @SparkiDev (PR 9838).
* Added OCSP responder API and support by @julek-wolfssl (PR 9761).
* Add AES CryptoCB key import support by @sameehj (PR 9658).
* Add the RNG bank facility to wolfCrypt, wc_rng_new_bankref() to avoid expensive seeding operations at runtime by @douzzer (PR 9616).

## Ports, Hardware Integration, and ASM enhancements
* Add Renesas SK-S7G2 support by @miyazakh (PR 9561).
* Support for STM32 HMAC hardware by @dgarske (PR 9745).
* Add STM32G0 hardware crypto support by @danielinux (PR 9707).
* Misc STM32 fixes and testing improvements by @dgarske, @LinuxJedi (PRs 9446, 9563).
* Various Thumb2 AES/SP ASM enhancements and fixes by @SparkiDev (PRs 9464, 9491, 9547, 9615, 9767)
* Add Zephyr 4.1+ build compatibility for wolfssl_tls_sock sample by @night1rider (PR 9765)

## Rust wrapper
* Added FIPS support by @holtrop (PR 9739).
* Added modules for dilithium (PR 9819), chacha20-poly1305 (PR 9599), curve25519 (PR 9594), blake2 (PR 9586), and LMS (PR 9910), ml-kem (PR 9833) by @holtrop.
* Miscellaneous fixes and enhancements for RSA, ECC, HASHDRBG, HMAC-BLAKE2, and XChaCha20-Poly1305 by @holtrop (PRs 9453, 9499, 9500, 9624, 9687).

## Post-Quantum Cryptography (PQC)
* General improvements for WOLFSSL_NO_MALLOC PQC support by @douzzer (PR 9674).
* Various ML-DSA bug fixes by @SparkiDev  (PRs 9575, 9696).
* Fixed a bug with ML-DSA verification with WOLFSSL_DILITHIUM_SMALL, by @SparkiDev (PR 9760). Reported by Sunwoo Lee and Seunghyun Yoon of Korea Institute of Energy Technology (KENTECH).
* ML-KEM bug fixes and improvements by @lealem47, @SparkiDev (PRs 9470, 9621, 9822).
* Collection of ML-KEM fixes including DTLS 1.3 cookie and ClientHello fragment handling, static memory handling, a memory leak in TLS server PQC handling with ECH, and expanded hybrid/individual ML-KEM level test coverage. @Frauschi (PR 9968)

## TLS/DTLS
* Add support for TLS 1.3 Brainpool curves by @Frauschi (PR 9701).
* DTLS retransmission enhancement by @julek-wolfssl (PR 9623).
* Fix DTLS header size calculation by @rizlik (PR 9513).
* Fix (D)TLS fragmentation size checks by @julek-wolfssl (PR 9592).
* Extend AIA interface by @padelsbach (PR 9728).
* Various TLS 1.3 and extension fixes by @SparkiDev, @AlexLanzano, @embhorn (PRs 9528, 9538, 9466, 9662, 9824, 9934). Thanks to Muhammad Arya Arjuna (pelioro) for the report.
* Improve TLS message order checks by @SparkiDev (PRs 9694, 9718).
* TLS ECH improvements by @sebastian-carpenter (PR 9737).
* Harden compare of mac with TLS 1.3 finished by @JacobBarthelmeh (PR 9864).

## PKCS
* Add PKCS7 ECC raw sign callback support by @jackctj117 (PR 9656).
* Add RSA-PSS support for SignedData by @sameehj (PR 9742).
* Support for ML-DSA via PKCS#11 by @Frauschi (PRs 9726, 9836).
* Fix PKCS11 object leak in Pkcs11ECDH by @mattia-moffa (PR 9780).
* Fix PKCS#7 SignedData parsing for non-OCTET_STRING content types by @cconlon (PR 9559).
* Add RSA-PSS certificate support for PKCS7 EnvelopedData KTRI by @sameehj (PR 9854).

## Kernel
* Various linuxkm fixes and enhancements for Tegra kernels by @sameehj, @douzzer (PRs 9478, 9540, 9512).
* freebsdkm: FIPS support (PR 9590), and x86 crypto acceleration support by @philljj (PR 9714).
* Support offline FIPS hash calculation in linuxkm by @douzzer (PR 9800).

## Testing improvements
* Increase test coverage for PQC and CMake by @Frauschi (PR 9637).
* API testing: split out and better organized test cases by @SparkiDev (PR 9641).
* Added test for session deserialization input validation by @gasbytes (PR 9759).
* Added TLS Anvil workflow by @embhorn (PR 9804).
* Added rng-tools 6.17 testing by @julek-wolfssl (PR 9810).
* Added openldap 2.6.9 testing by @julek-wolfssl (PR 9805).
* Add bind 9.20.11 to the test matrix by @julek-wolfssl (PR 9806).
* Misc testing fixes by @miyazakh, @SparkiDev, @julek-wolfssl, @padelsbach, @rlm2002 (PRs 9584, 9670, 9688, 9710, 9716, 9755).
* Implement a stateful port tracking mechanism for test port assignment that eliminates collisions  during high-concurrency test loops in CI by @kaleb-himes (PR 9850).

## Bug Fixes
* Fix for buffer overflow write in the wolfSSL CAAM (Cryptographic Acceleration and Assurance Module) driver for Integrity OS on i.MX6. Thanks to Luigino Camastra for the report.
* API Documentation: various fixes and improvements: @LinuxJedi, @tamasan238,  @kareem-wolfssl, @dgarske (PRs 9458, 9552, 9570, 9585).
* Fix potential memory under-read in TLS ticket processing function.  Thanks to Arjuna Arya for the report.
* Fix IP address check in wolfSSL_X509_check_host() by @rlm2002 (PR 9502).
* Check if ctx and ssl are null when checking public key in certificate by @rlm2002 (PR 9506).
* Fix test when ECH and harden are enabled by @embhorn (PR 9510).
* Fix wc_CmacFree() to use correct heap pointer from internal Aes structure by @night1rider (PR 9527).
* Various Coverity analyzer fixes by @rlm2002 (PRs 9437, 9534, 9619, 9646, 9812, 9842, 9887, 9933).
* Fix dereference before Null check by @rlm2002 (PR 9591).
* Fix memory leak in case of handshake error by @Frauschi (PR 9609).
* Fix MatchBaseName by @rizlik (PR 9626).
* ChaCha20 Aarch64 ASM fix by @SparkiDev (PR 9627).
* Fix TLSX_Parse to correctly handle client and server cert type ext with TLS1.3 by @embhorn (PR 9657).
* Fix cert SW issues in Aes and rng by @tmael (PR 9681).
* Various fixes for NO_RNG builds by @dgarske (PRs 9689, 9698).
* Fixes for STSAFE-A120 ECDHE by @dgarske (PR 9703).
* Fix Crash when using Sha224 Callback with MAX32666 by @night1rider (PR 9712).
* Fix for RSA private key parsing (allowing public) and RSA keygen no malloc support by @dgarske (PR 9715).
* Fix null check in ECDSA encode by @padelsbach (PR 9771).
* Various static analyzer fixes by @LinuxJedi (PRs 9786, 9788, 9795, 9801, 9817).
* Fix switch case handling in TLSX_IsGroupSupported function by @Pushyanth-Infineon (PR 9777).
* Fixes to big-endian bugs found in Curve448 and Blake2S by @LinuxJedi (PR 9778).
* Fix cert chain size issue by @embhorn (PR 9827).
* Fix potential memory leak when copying into existing SHA contexts and zero init tmpSha by @night1rider (PR 9829).
* Add sanity checks in key export by @embhorn (PR9823). Thanks to Muhammad Arya Arjuna (pelioro) for the report.
* CRL enhancements for revoked entries by @padelsbach (PR 9839).
* Fix DRBG_internal alloc in wc_RNG_HealthTestLocal by @embhorn (PR 9847).
* Various CMake fixes and improvements by @Frauschi (PRs 9605, 9725).
* RISC-V 32 no mul SP C: implement multiplication by @SparkiDev in (PR 9855).
* ASN: improve handling of ASN.1 parsing/encoding by @SparkiDev (PR 9872).
* Various fixes to CRL parsing by @miyazakh in (PRs 9628, 9873).
* Harden hash comparison in TLS1.2 finished by @Frauschi (PR 9874).
* Various fixes to TLS sniffer by @mattia-moffa, @embhorn, @julek-wolfssl, @Frauschi (PRs 9571, 9643, 9867, 9901, 9924).
* Check ivLen in wolfSSL_EVP_CIPHER_CTX_set_iv_length by @philljj (PR 9943). Thanks to Haruto Kimura (Stella) for the report.
* Validate that the ticket length is at least ID_LEN  before use in SetTicket, preventing an undersized buffer from being processed. @kareem-wolfssl (PR 9782).
* Enforce null compression in compression_methods list by @julek-wolfssl (PR 9913).
* Additional sanity check on number of groups in set groups function by @JacobBarthelmeh (PR 9861).
* Resolves issues with asynchronous and crypto callback handling, adding test coverage to prevent regressions. by @dgarske (https://github.com/wolfSSL/wolfssl/pull/9784).
* Fix checkPad to reject zero PKCS#7 padding value by @embhorn (PR 9878).
* Add sanity check on keysize found with ECC point import by @JacobBarthelmeh (PR 9989).
* Adds a range check to ensure session ticket lifetimes are within the bounds permitted by the TLS specification by @Frauschi (PR 9881).
* Fix potential overflows in hash used-size calculation for TI and SE050 implementations by @kareem-wolfssl (PR 9954).
* Correct a constant mismatch where the draft QUIC transport params branch was returning the wrong extension constant, causing incorrect version detection by @embhorn (PR 9868).
* Correct the key type detection logic in Falcon and the SPHINCS+ signature algorithm's else-if chain to properly identify all key variants by @anhu (PR 9979, 9980).
* XMSS: Fix index copy for signing by @SparkiDev (PR 9978).
* Fix pathlen not copied in ASN1_OBJECT_dup and not marked set in X509_add_ext by @cconlon (PR 9940).
* Ensure CheckHeaders length does not exceed packet size in sniffer by @kareem-wolfssl (PR 9947).
* SP fixes: 32-bit ARM assembly fixes modular exponentiation bug by @SparkiDev (PR 9964).
* Fix buffer-overflow in LMS leaf cache indexing by @anhu (PR 9919).

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

# Directory structure

```
<wolfssl_root>
├── certs   [Certificates used in tests and examples]
├── cmake   [Cmake build utilities]
├── debian  [Debian packaging files]
├── doc     [Documentation for wolfSSL (Doxygen)]
├── Docker  [Prebuilt Docker environments]
├── examples    [wolfSSL examples]
│   ├── asn1    [ASN.1 printing example]
│   ├── async   [Asynchronous Cryptography example]
│   ├── benchmark   [TLS benchmark example]
│   ├── client  [Client example]
│   ├── configs [Example build configurations]
│   ├── echoclient  [Echoclient example]
│   ├── echoserver  [Echoserver example]
│   ├── pem [Example for convert between PEM and DER]
│   ├── sctp    [Servers and clients that demonstrate wolfSSL's DTLS-SCTP support]
│   └── server  [Server example]
├── IDE     [Contains example projects for various development environments]
├── linuxkm [Linux Kernel Module implementation]
├── m4      [Autotools utilities]
├── mcapi   [wolfSSL MPLAB X Project Files]
├── mplabx  [wolfSSL MPLAB X Project Files]
├── mqx     [wolfSSL Freescale CodeWarrior Project Files]
├── rpm     [RPM packaging metadata]
├── RTOS
│   └── nuttx   [Port of wolfSSL for NuttX]
├── scripts [Testing scripts]
├── src     [wolfSSL source code]
├── sslSniffer  [wolfSSL sniffer can be used to passively sniff SSL traffic]
├── support [Contains the pkg-config file]
├── tests   [Unit and configuration testing]
├── testsuite   [Test application that orchestrates tests]
├── tirtos  [Port of wolfSSL for TI RTOS]
├── wolfcrypt   [The wolfCrypt component]
│   ├── benchmark   [Cryptography benchmarking application]
│   ├── src         [wolfCrypt source code]
│   │   └── port    [Supported hardware acceleration ports]
│   └── test        [Cryptography testing application]
├── wolfssl [Header files]
│   ├── openssl [Compatibility layer headers]
│   └── wolfcrypt   [Header files]
├── wrapper [wolfSSL language wrappers]
└── zephyr  [Port of wolfSSL for Zephyr RTOS]
```
