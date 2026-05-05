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

wolfCrypt also includes support for deriving device-unique keys from hardware entropy
(`--enable-puf`). An example exists at
[SRAM PUF](https://github.com/wolfSSL/wolfssl-examples/tree/master/puf).

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


# wolfSSL Release 5.9.1 (Apr. 8, 2026)

Release 5.9.1 has been developed according to wolfSSL's development and QA
process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE:
* --enable-heapmath is deprecated
* MD5 is now disabled by default

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request number where the code change was added.

## Vulnerabilities

* [Critical] CVE-2026-5194
Missing hash/digest size and OID checks allow digests smaller than allowed by FIPS 186-4 or 186-5 (as appropriate), or smaller than is appropriate for the relevant key type, to be accepted by signature verification functions, reducing the security of certificate-based authentication. Affects multiple signature algorithms, including ECDSA/ECC, DSA, ML-DSA, ED25519, and ED448. Builds that have both ECC and EdDSA or ML-DSA enabled that are doing certificate verification are recommended to update to the latest wolfSSL release. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10131.

* [High] CVE-2026-5264
Heap buffer overflow in DTLS 1.3 ACK message processing. A remote attacker can send a crafted DTLS 1.3 ACK message that triggers a heap buffer overflow. Thanks to Sunwoo Lee and Seunghyun Yoon, Korea Institute of Energy Technology (KENTECH). Fixed in PR 10076.

* [High] CVE-2026-5263
URI nameConstraints from constrained intermediate CAs are parsed but not enforced during certificate chain verification in wolfcrypt/src/asn.c. A compromised or malicious sub-CA could issue leaf certificates with URI SAN entries that violate the nameConstraints of the issuing CA, and wolfSSL would accept them as valid. Thanks to Oleh Konko @1seal for the report. Fixed in PR 10048.

* [High] CVE-2026-5295
Stack buffer overflow in PKCS7 ORI (Other Recipient Info) OID processing. When parsing a PKCS7 envelope with a crafted ORI OID value, a stack-based buffer overflow can be triggered. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH). Fixed in PR 10116.

* [High] CVE-2026-5466
wolfSSL's ECCSI signature verifier `wc_VerifyEccsiHash` decodes the `r` and `s` scalars from the signature blob via `mp_read_unsigned_bin` with no check that they lie in `[1, q-1]`. A crafted forged signature could verify against any message for any identity, using only publicly-known constants. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5477
Potential for AES-EAX AEAD and CMAC authentication bypass on messages larger than 4 GiB. An attacker who observes one valid (ciphertext, tag) pair for a >4 GiB EAX message can replace the first 4 GiB of ciphertext arbitrarily while the tag still verifies. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5447
Heap buffer overflow in CertFromX509 via AuthorityKeyIdentifier size confusion. A heap buffer overflow occurs when converting an X.509 certificate internally due to incorrect size handling of the AuthorityKeyIdentifier extension. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10112.

* [High] CVE-2026-5500
wolfSSL's `wc_PKCS7_DecodeAuthEnvelopedData()` does not properly sanitize the AES-GCM authentication tag length received and has no lower bounds check. A man-in-the-middle can therefore truncate the `mac` field from 16 bytes to 1 byte, reducing the tag check from 2⁻¹²⁸ to 2⁻⁸. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5501
`wolfSSL_X509_verify_cert()` in the OpenSSL compatibility layer accepts a certificate chain in which the leaf's signature is not checked, if the attacker supplies an untrusted intermediate with Basic Constraints `CA:FALSE` that is legitimately signed by a trusted root. An attacker who obtains any leaf certificate from a trusted CA (e.g. a free DV cert from Let's Encrypt) can forge a certificate for any subject name with any public key and arbitrary signature bytes, and the function returns `WOLFSSL_SUCCESS` / `X509_V_OK`. The native wolfSSL TLS handshake path (`ProcessPeerCerts`) is not susceptible and the issue is limited to applications using the OpenSSL compatibility API directly. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5503
In TLSX_EchChangeSNI, the ctx->extensions branch set extensions unconditionally even when TLSX_Find returned NULL. This caused TLSX_UseSNI to attach the attacker-controlled publicName to the shared WOLFSSL_CTX when no inner SNI was configured. TLSX_EchRestoreSNI then failed to clean it up because its removal was gated on serverNameX != NULL. The inner ClientHello was sized before the pollution but written after it, causing TLSX_SNI_Write to memcpy 255 bytes past the allocation boundary. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5479
In wolfSSL's EVP layer, the ChaCha20-Poly1305 AEAD decryption path in wolfSSL_EVP_CipherFinal (and related EVP cipher finalization functions) fails to verify the authentication tag before returning plaintext to the caller. When an application uses the EVP API to perform ChaCha20-Poly1305 decryption, the implementation computes or accepts the tag but does not compare it against the expected value. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [Med] CVE-2026-5392
Heap out-of-bounds read in PKCS7 parsing. A crafted PKCS7 message can trigger an OOB read on the heap. The missing bounds check is in the indefinite-length end-of-content verification loop in PKCS7_VerifySignedData(). This only affects builds with PKCS7 support enabled. Thanks to J Laratro (d0sf3t) for the report. Fixed in PR 10039.

* [Med] CVE-2026-5446
ARIA-GCM nonce reuse in TLS 1.2 record encryption. ARIA cipher support requires a proprietary Korean library (MagicCrypto) and --enable-aria, limiting real-world exposure. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10111.

* [Med] CVE-2026-5460
When a malicious TLS 1.3 server sends a ServerHello with a truncated PQC hybrid KeyShare (e.g., P256_ML_KEM_512 with 10 bytes instead of the required 768+), the error cleanup path double-frees the KyberKey. Thanks to Calvin Young (eWalker Consulting Inc.) and Enoch Chow (Isomorph Cyber). Fixed in PR 10092.

* [Med] CVE-2026-5504
A padding oracle exists in wolfSSL's PKCS7 CBC decryption that could allow an attacker to recover plaintext through repeated decryption queries with modified ciphertext. In previous versions of wolfSSL the interior padding bytes are not validated. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon of Korea Institute of Energy Technology (KENTECH) for the report. Fixed in PR 10088.

* [Med] CVE-2026-5507
When restoring a session from cache, a pointer from the serialized session data is used in a free operation without validation. An attacker who can poison the session cache could trigger an arbitrary free. Exploitation requires the ability to inject a crafted session into the cache and for the application to call specific session restore APIs. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon of Korea Institute of Energy Technology (KENTECH) for the report. Fixed in PR 10088.

* [Low] CVE-2026-5187
Heap out-of-bounds write in DecodeObjectId() caused by an off-by-one bounds check combined with a sizeof mismatch. A crafted ASN.1 object identifier can trigger a small heap OOB write. Thanks to Yuteng for the report. Fixed in PR 10025.

* [Low] CVE-2026-5188
An integer underflow issue exists in wolfSSL when parsing the Subject Alternative Name (SAN) extension of X.509 certificates. A malformed certificate can specify an entry length larger than the enclosing sequence, causing the internal length counter to wrap during parsing. This results in incorrect handling of certificate data. The issue is limited to configurations using the original ASN.1 parsing implementation. The original ASN.1 parsing implementation is off by default. Thanks to Muhammad Arya Arjuna Habibullah for the report. Fixed in PR 10024.

* [Low] CVE-2026-5448
X.509 date buffer overflow in wolfSSL_X509_notAfter / wolfSSL_X509_notBefore. A buffer overflow may occur when parsing date fields from a crafted X.509 certificate via the compatibility layer API. This is only triggered when calling these two APIs directly from an application, and does not affect TLS or certificate verify operations in wolfSSL. Thanks to Sunwoo Lee and Seunghyun Yoon, Korea Institute of Energy Technology (KENTECH) for the report. Fixed in PR 10071.

* [Low] CVE-2026-5772
A 1-byte stack buffer over-read exists in the MatchDomainName function in src/internal.c when processing wildcard patterns with the LEFT_MOST_WILDCARD_ONLY flag active. When a wildcard '*' exhausts the entire hostname string (strLen reaches 0), the function proceeds to compare remaining pattern characters against the now-exhausted buffer without a bounds check, causing an out-of-bounds read. Thanks to Zou Dikai for the report. Fixed in PR 10119.

* [Low] CVE-2026-5778
An integer underflow exists in the ChaCha20-Poly1305 decryption path where a malformed TLS 1.2 record with a payload shorter than the AEAD MAC size causes the message length calculation to underflow, resulting in an out-of-bounds read. This only affects sniffer builds. Thanks to Zou Dikai for the report. Fixed in PR 10125.

## Experimental Build Vulnerability

* [Med] CVE-2026-5393
Dual-Algorithm CertificateVerify out-of-bounds read. When processing a dual-algorithm CertificateVerify message, an out-of-bounds read can occur on crafted input. This can only occur when --enable-experimental and --enable-dual-alg-certs is used when building wolfSSL. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH) for testing the fix. Fixed in PR 10079.

## New Features
* Enabled PQC algorithm ML-KEM (FIPS203) on by default. by @Frauschi (PR 9732)
* Added brainpool curve support to wolfSSL_CTX_set1_sigalgs_list. by @kojo1 (PR 9993)
* Implemented wolfSSL_Atomic_Int_Exchange() in wolfssl/wolfcrypt/wc_port.h and wolfcrypt/src/wc_port.c. by @douzzer (PR 10036)
* Added a GPLv2 license exception for VDE (Virtual Distributed Ethernet) to the licensing terms. by @danielinux (PR 10107)
* Added DTLS 1.3/TLS 1.3 write-dup (Duplicate SSL) support so the read-side can delegate post-handshake work (KeyUpdate responses, DTLS13 ACK sending, post-handshake auth) to the write-side, along with new tests and CI coverage. (PR 10006)

## Post-Quantum Cryptography (PQC)
* Fixed Dilithium API to use byte type for context length parameters, enforcing the 0–255 byte constraint. by @SparkiDev (PR 10010)
* Fixed benchmarking for ML-DSA with static memory enabled. by @JacobBarthelmeh (PR 9970)
* Added checks to verify the private key is set before performing private key operations in Ed25519, Ed448, ML-DSA, and ML-KEM. by @anhu (PR 10083)
* Added buffer size and callback validation checks to wc_LmsKey_Sign to prevent signing with insufficient output buffer or missing required callbacks. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH) for the report. (PR 10084)
* Fixed an out-of-bounds shift in the ML-DSA implementation by ensuring the cast is performed before large shift operations in dilithium.c. Thanks to Dominik Blain / COBALT Security for the bug report. by @padelsbach (PR 10096)
* Zeroize sensitive memory buffers in the ML-DSA (Dilithium) implementation to prevent leakage of cryptographic material. by @Frauschi (PR 10100)
* Fixed undefined behavior in SLH-DSA key initialization by casting to unsigned before performing a left shift that could set the MSB. by @padelsbach (PR 10104)
* Added null checks for buffer size and callback validity in the external wc_LmsKey_Sign function to prevent CI failures. by @padelsbach (PR 10105)
* Ensured that the heap buffer used (among others) to store sensitive data during ML-DSA signing is zeroized before freeing the memory. Thanks to Abhinav Agarwal (@abhinavagarwal07) for the report. (PR 10113)
* The legacy non-context ML-DSA (Dilithium) API is now guarded behind WOLFSSL_DILITHIUM_NO_CTX, making the context-aware FIPS 204 API the default and adding a no-ctx configure option to explicitly re-enable the legacy path. by @Frauschi (PR 10047)

## TLS/DTLS
* Fixed handling of OCSP_WANT_READ return value in the TLS 1.3 handshake message type processing to prevent incorrect error propagation during OCSP stapling operations. by @julek-wolfssl (PR 9995)
* Fixed a bug in the HPKE implementation where the KDF digest was incorrectly used for the KEM, and refactored HPKE-related code out of the TLS/ECH layer into dedicated local functions, adding tests for all 24 algorithm combination variants. by @sebastian-carpenter (PR 9999)
* Fixed DTLS 1.3 ServerHello to not echo the legacy_session_id field, bringing the implementation into compliance with the DTLS 1.3 specification. by @julek-wolfssl (PR 10007)
* Fixed a TLS 1.3 server issue where a mismatched ciphersuite in a second ClientHello following a HelloRetryRequest was incorrectly accepted instead of rejected. by @sebastian-carpenter (PR 10034)
* Fixed a possible memory leak in ECC non-blocking cryptography operations within the TLS layer. by @dgarske (PR 10065)
* Fixed multiple correctness issues in DTLS 1.3 and TLS 1.3 including wrong return values, missing bounds checks, a PSK identity buffer overread, swapped server/client parameters in finished secret derivation, a static array data race, resource leaks, and a potential NULL dereference in the SM3 exporter path. by @gasbytes (PR 10117)

## ASN and Certificate Parsing
* Added wolfSSL_check_ip_address() to support filtering connections based on Subject Alternative Name (SAN) IP address entries, mirroring the existing domain name check functionality. by @padelsbach (PR 9935)
* Added host name verification from the verification context parameter when calling wolfSSL_X509_verify_cert. by @julek-wolfssl (PR 9952)
* Moved non-template (WOLFSSL_ASN_ORIGINAL) code into asn_orig.c and include from asn.c. by @dgarske (PR 9920)
* Fixed additional potential null pointer dereferences in ASN parsing code identified by Coverity static analysis. by @rlm2002 (PR 9990)
* Fixed wolfssl/wolfcrypt/asn.h to directly include wolfssl/wolfcrypt/sha512.h for WC_SHA384_DIGEST_SIZE and WC_SHA512_DIGEST_SIZE. Previously this relied on transitive include order and broke builds where asn.h is parsed before hash.h/sha512.h. by @danielinux (PR 10014)
* Removed FIPS-conditional guards from the GetASN_BitString length check so the validation applies in all builds. by @embhorn (PR 10027)
* Added validation to reject negative ASN.1 integers in CRL number fields during decoding, preventing an overflow that could corrupt the adjacent hash field. Thanks to Sunwoo Lee for the bug report. by @padelsbach (PR 10087)

## Hardware and Embedded Ports
* Fixed SE050 hardware security module integration by routing RSA-PSS sign/verify operations through the software path to prevent double-hashing, releasing persistent SE050 key slots on free for RSA, ECC, Ed25519, and Curve25519 keys, and adding missing mutex unlock calls before early returns in RSA crypto functions. by @LinuxJedi (PR 9912)
* When WOLFSSL_NO_HASH_RAW is defined due to hardware hash offload, turn on LMS and XMSS full hash. Without this they will not compile automatically when there is hardware SHA acceleration. by @LinuxJedi (PR 9946)
* Applied AI-review fixes across hardware and embedded port implementations spanning Espressif, Renesas, Silicon Labs, NXP, STM32, TI, Xilinx, and numerous other targets to improve correctness and code quality. by @SparkiDev (PR 10003)
* Fixed issues found by the testing of the MAX32666 tests. by @night1rider (PR 10035)
* Fixed buffer overflows, key material exposure, mutex leaks, and logic errors across hardware crypto port backends. by @JeremiahM37 (PR 10080)

## Rust Wrapper
* Released version 1.2.0 of the wolfssl-wolfcrypt Rust crate with updated changelog and README. by @holtrop-wolfssl (PR 9953)
* Updated the Rust wrapper's build script to support cross-compiling and bare-metal targets, including RISC-V architectures. by @holtrop-wolfssl (PR 10031)

## Build System and Portability
* Removed default declaration of WC_ALLOC_DO_ON_FAILURE. by @julek-wolfssl (PR 9905)
* Refactored wc_Hash* so that known wc_HashType values are unconditionally defined in enum wc_HashType, and always either succeed if used properly, or return HASH_TYPE_E if gated out or used improperly; added detailed error code tracing. by @douzzer (PR 9937)
* Removed the forced enabling of MD5 when building with --enable-jni so that MD5 can be explicitly disabled in FIPS builds. by @mattia-moffa (PR 10011)
* Changed the example server/client to not modify macro defines that come from how the wolfSSL library is configured when built. by @JacobBarthelmeh (PR 10037)
* Added __extension__ to __GNUC__&&!__STRICT_ANSI__ variant of wc_debug_trace_error_codes_enabled() in wolfssl/wolfcrypt/error-crypt.h, to inhibit false positive "error: ISO C forbids braced-groups within expressions" with -pedantic. by @douzzer (PR 10041)
* Fixed IAR compiler warnings about undefined volatile access order by reading volatile values into local copies before use in expressions. by @embhorn (PR 10045)
* Automatically enables WOLFSSL_SP_4096 when WOLFSSL_HAVE_SP_DH is defined under the --enable-usersettings configuration to fix a missing dependency for C# user settings builds. by @kojo1 (PR 10054)
* Added volatile casting to a port header definition to address a correctness issue. by @anhu (PR 10062)
* Extended the WC_MAYBE_UNUSED macro definition to cover GCC versions greater than 3 to fix a build error in GCC 3.4.0. by @embhorn (PR 10101)
* Fixed a compile error when building with --enable-crl and --disable-ecc by adding the appropriate preprocessor guards around SetBitString in asn.c. by @padelsbach (PR 10118)
* Fixed -Wcast-qual hygiene in wolfCrypt. by @douzzer (PR 10120)

## Bug Fixes
* Fixed stack memory tracking for the wolfCrypt benchmark. by @Frauschi (PR 9983)
* Fixed a bug in FillSigner where pubKeyStored and subjectCNStored flags were not cleared after transferring pointers from a DecodedCert to a signer, preventing stale NULL pointers from being copied on subsequent calls. by @embhorn (PR 10033)
* Fixed a heap overflow in ssl_DecodePacketInternal caused by silent truncation when summing 64-bit iov_len values into a 32-bit integer, which resulted in an undersized buffer allocation followed by an out-of-bounds copy. by @embhorn (PR 10017)
* Added a bounds check in GetSafeContent to prevent an unsigned integer underflow in the content size calculation when the OID parsed by GetObjectId exceeds the declared ContentInfo SEQUENCE length. by @embhorn (PR 10018)
* Fixed a potential double free issue in non-blocking async handling within ASN parsing. by @dgarske (PR 10022)
* Fixed bounds checking and buffer size calculation in DecodeObjectId to correctly validate two output slots before writing and pass the proper element count instead of byte count when handling unknown ASN.1 extensions. by @embhorn (PR 10025)
* Fixed stack buffer overflow in RSA exponent print via wolfSSL_EVP_PKEY_print_public in evp.c. Printing an RSA public key with a large exponent can overflow a stack buffer in the EVP printing routine. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH) for the bug report. (PR 10088)
* Fixed sanity check on hashLen provided to wc_dilithium_verify_ctx_hash. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH) for the bug report. (PR 10131)
* Disallowed wildcard partial domains when using MatchDomainName. Thanks to Oleh Konko (@1seal) for the report. (PR 9991)
* Fixed a buffer underflow that occurred when a zero-length size was passed to the devcrypto AES-CBC implementation. by @JeremiahM37 (PR 10005)
* Routed BIO_ctrl_pending, BIO_reset, and BIO_get_mem_data through the custom method's ctrlCb when set, enabling fully custom BIO types to handle these operations. by @julek-wolfssl (PR 10004)
* Fixed multiple issues in the SP integer implementation including negative number handling, edge cases when a->used is zero, missing bounds checks, and redundant code, while also re-implementing wc_PKCS12_PBKDF() without MP and adding 128-bit integer types for cleaner PKCS#12 support. by @SparkiDev (PR 10020)
* Fixed functional bugs in x86_64 AES-XTS register clobbering and ARM32 multiply/accumulate source registers, along with assembly label typos, instruction mnemonic corrections, and comment fixes across AES, ChaCha, SHA-3, SHA-512, ML-KEM, and Curve25519 assembly for x86_64, ARM32, and ARM64 targets. by @SparkiDev (PR 10023)
* Fixed a bug in the SP non-blocking ECC mont_inv_order function where the last bit was not being processed during modular inverse computation. by @SparkiDev (PR 10044)
* Added bounds check to prevent potential out-of-bounds access when parsing end-of-content octets in PKCS7 streaming indefinite-length encoding. by @anhu (PR 10039)
* Refactored the "Increment B by 1" loop in wc_PKCS12_PBKDF_ex() to avoid bugprone-inc-dec-in-conditions. by @douzzer (PR 10059)
* Fixed OpenSSL compatibility layer ASN1_INTEGER and ASN1_STRING to be compatible structs. by @julek-wolfssl (PR 10089)
* Fixed potential data truncation in wc_XChaCha20Poly1305_crypt_oneshot() by replacing long int casts with size_t to correctly handle 64-bit sizes on platforms where long int is 32-bit. by @rlm2002 (PR 10091)
* Fixed error handling in the Linux kernel AES AEAD glue code so that scatterwalk_map failures correctly propagate an error code instead of returning success with uninitialized data. by @sameehj (PR 9996)
* Fixed DTLS Fragment Reassembly to not read uninitialized heap contents. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH) for the report. (PR 10090)
* Fixed DTLS 1.3 word16 truncation on handshake send size. A handshake message exceeding 65535 bytes causes silent integer truncation when the size is stored in a word16, leading to malformed or truncated handshake transmissions. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH) for the report. (PR 10103)
* Fixed invalid-pointer-pair memory errors reported by clang sanitizer with detect_invalid_pointer_pairs=2 in ASAN_OPTIONS. by @douzzer (PR 10095)
* Hardened default builds by enabling ECC curve validation unconditionally, removing the previous dependency on USE_ECC_B_PARAM. Users on older versions can also harden their builds by enabling WOLFSSL_VALIDATE_ECC_IMPORT. by @Frauschi (PR 10133)

## Documentation and Maintenance
* Added inline Doxygen documentation for previously undocumented macros across TLS, cryptography, and ASN source files, and corrected spelling errors throughout the codebase. by @dgarske (PR 9992)
* Fixed typos in documentation for SSL API function argument descriptions. by @dgarske (PR 10021)
* Updated documentation to reflect support for both FIPS 140-2 and FIPS 140-3. by @anhu (PR 10061)

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

[wolfSSL MemBrowse Dashboard](https://membrowse.com/public/wolfSSL/wolfssl)

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
