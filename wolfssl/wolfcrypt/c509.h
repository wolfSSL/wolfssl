/* c509.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

/*!
    \file wolfssl/wolfcrypt/c509.h
    \brief Decode and verify C509 certificates (CBOR-encoded X.509).
*/

/*
 * C509 (draft-ietf-cose-cbor-encoded-cert) is a compact CBOR encoding of an
 * X.509 certificate, used by constrained protocols such as EDHOC (RFC 9528).
 * Two certificate types are defined:
 *   - type 2: "natively signed" -- the issuer signature covers the CBOR
 *     sequence of the TBSCertificate fields;
 *   - type 3: "CBOR re-encoded X.509" -- the signature covers the ORIGINAL
 *     DER TBSCertificate, so verification reconstructs that DER and checks the
 *     signature over the reconstructed TBSCertificate with the same
 *     per-algorithm verify helpers as the type-2 path (ECDSA over any supported
 *     curve/hash with keyType selecting the curve, RSA sha256WithRSAEncryption
 *     only, and Ed25519 / Ed448).
 *
 * This module decodes and verifies only; it does not issue (encode) C509
 * certificates. It is enabled with --enable-c509 (WOLFSSL_C509) and needs
 * certificate support (ASN.1) plus the relevant signature algorithm(s).
 */

#ifndef WOLF_CRYPT_C509_H
#define WOLF_CRYPT_C509_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_C509

/* C509 needs certificate (ASN.1) support; a user_settings build that enables
 * WOLFSSL_C509 but also defines NO_ASN would compile this header and the test
 * but not the implementation. Fail loudly instead. */
#ifdef NO_ASN
    #error "WOLFSSL_C509 requires ASN.1 support (do not define NO_ASN)"
#endif

/* RSA_MAX_SIZE (the compiled-in maximum RSA modulus, in bits) sizes the default
 * WC_C509_MAX_DER below. Pulled in only when RSA is compiled in; an EC/EdDSA
 * only build never references it. */
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

/* Type-3 (CBOR re-encoded X.509) support reconstructs the original DER
 * certificate so the issuer signature over it can be verified, and backs
 * wc_C509_ToDer. It is a sizable sub-feature and is enabled by default; define
 * WOLFSSL_C509_NO_TYPE3 to compile it out, leaving type-2 (natively
 * CBOR-signed) verification and subject-public-key extraction. When it is
 * compiled out, wc_C509_ToDer and verifying a type-3 certificate return
 * NOT_COMPILED_IN. The autotools --disable-c509-type3 and CMake
 * -DWOLFSSL_C509_TYPE3=no options define WOLFSSL_C509_NO_TYPE3 and record it in
 * wolfssl/options.h, so the library and application agree. If instead you
 * define WOLFSSL_C509_NO_TYPE3 by hand (user_settings.h or CFLAGS) it is not
 * recorded in options.h, so define it for both the library and application. */
#ifndef WOLFSSL_C509_NO_TYPE3
    #undef  WOLFSSL_C509_TYPE3
    #define WOLFSSL_C509_TYPE3
#else
    /* The opt-out wins even over a stale or user-defined WOLFSSL_C509_TYPE3. */
    #undef  WOLFSSL_C509_TYPE3
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Subject public key type reported by wc_C509_GetPubKey. */
enum wc_C509_KeyType {
    WC_C509_KEY_UNKNOWN = 0,
    WC_C509_KEY_ED25519 = 1,  /* 32-byte raw public key                    */
    WC_C509_KEY_P256    = 2,  /* 64-byte X||Y (uncompressed point, no 0x04) */
    WC_C509_KEY_P384    = 3,  /* 96-byte X||Y                              */
    WC_C509_KEY_P521    = 4,  /* 132-byte X||Y (secp521r1)                 */
    WC_C509_KEY_ED448   = 5,  /* 57-byte raw public key                    */
    WC_C509_KEY_BP256   = 6,  /* 64-byte X||Y  (brainpoolP256r1)           */
    WC_C509_KEY_BP384   = 7,  /* 96-byte X||Y  (brainpoolP384r1)           */
    WC_C509_KEY_BP512   = 8,  /* 128-byte X||Y (brainpoolP512r1)           */
    WC_C509_KEY_RSA     = 9   /* RSA modulus (exponent assumed 65537)      */
};

/* Reconstructed-DER buffer bound. It sizes the suggested CALLER buffer for
 * wc_C509_ToDer and the library's fixed type-3 reconstruction buffer, and caps
 * the accepted RSA signature length.
 *
 * On a heap-capable build (WOLFSSL_SMALL_STACK) wc_C509_VerifyEx measures the
 * exact DER length and allocates precisely that, so there this bound only sizes
 * the ToDer size hint and the RSA-signature cap - a type-3 certificate verifies
 * regardless of this value, as long as each reconstructed DER element is within
 * the 64 KB DER length limit (der_len encodes lengths up to 65535; a single
 * element at or above that returns BUFFER_E on every build). Only a
 * no-dynamic-allocation build reconstructs into the fixed WC_C509_MAX_DER buffer
 * and returns BUFFER_E for a certificate that overruns it; there the size query
 * (wc_C509_ToDer with out == NULL) still reports the exact length needed.
 *
 * The default is derived from the compiled-in algorithms rather than a flat
 * guess, so it tracks the build, with a 1024-byte floor that fits the in-profile
 * EC/EdDSA certificates the tests cover (the draft 3.6 secp521r1/ES512 type-3
 * certificate reconstructs to 811 bytes). With RSA the reconstructed DER carries
 * the modulus (in the SPKI) and the signature, each up to RSA_MAX_SIZE/8 bytes,
 * plus ~512 bytes for the serial, names, validity and extensions; without RSA
 * the largest material is an EC/EdDSA SPKI plus an ECDSA/EdDSA signature.
 * RSA_MAX_SIZE (rsa.h) is the compiled maximum (FP_MAX_BITS / SP_INT_BITS, else
 * the 4096/8192 fallback), so an RSA build up to RSA-2048 (and a NO_RSA build)
 * gives the 1024 floor, RSA-4096 gives 1536 and RSA-8192 gives 2560. Because
 * both the library and the application derive it from the same compile-time
 * macros, the default already agrees on both sides. A hand-set WC_C509_MAX_DER
 * (to bound a no-malloc build, or admit a larger profile) must still match
 * between them. */
#ifndef WC_C509_MAX_DER
    #ifdef NO_RSA
        #define WC_C509_MAX_DER 1024
    #elif (512 + 2 * (RSA_MAX_SIZE / 8)) > 1024
        #define WC_C509_MAX_DER (512 + 2 * (RSA_MAX_SIZE / 8))
    #else
        #define WC_C509_MAX_DER 1024
    #endif
#endif

#ifndef NO_RSA
/* Minimum RSA issuer-key modulus (in bits) the verifier accepts. The floor
 * rejects an EC X||Y key fed in as an RSA modulus (P-256 is 64 bytes, P-384 96)
 * while still admitting a legitimate smaller-than-RSA_MIN_SIZE issuer key. It
 * defaults to 1024, but a hardened build raises it - to 2048 bits under
 * WOLFSSL_HARDEN_TLS (>= 112) or 3072 under WOLFSSL_MAX_STRENGTH, mirroring how
 * those options raise the RSA minimum elsewhere - and WC_C509_RSA_MIN_BITS can
 * be defined to override it directly. A certificate signed by an RSA issuer key
 * whose modulus is shorter than this floor verifies as BAD_FUNC_ARG. */
#ifndef WC_C509_RSA_MIN_BITS
    #if defined(WOLFSSL_MAX_STRENGTH)
        #define WC_C509_RSA_MIN_BITS 3072
    #elif defined(WOLFSSL_HARDEN_TLS) && (WOLFSSL_HARDEN_TLS >= 112)
        #define WC_C509_RSA_MIN_BITS 2048
    #else
        #define WC_C509_RSA_MIN_BITS 1024
    #endif
#endif
#endif /* !NO_RSA */

/* Extract the subject public key from a C509 certificate: raw key bytes into
 * out, with the inferred wc_C509_KeyType reported via keyType (may be NULL).
 * For RSA only the modulus is returned; a [modulus, exponent] array is accepted
 * only when its exponent is 65537 (any other exponent returns NOT_COMPILED_IN),
 * so a 0 return always implies exponent 65537. Full contract in
 * doc/dox_comments/header_files/c509.h. */
WOLFSSL_API int wc_C509_GetPubKey(const byte* c509, word32 c509Sz,
    byte* out, word32* outLen, int* keyType);

/* Like wc_C509_GetPubKey but with a heap hint for the internal EC
 * point-decompression key, so a compressed-point extraction can draw from a
 * static-memory pool. There is no devId: the only crypto here is public-point
 * decompression, which is never routed to a crypto-callback device.
 * wc_C509_GetPubKey is the same call with heap == NULL. Full contract in
 * doc/dox_comments/header_files/c509.h. */
WOLFSSL_API int wc_C509_GetPubKeyEx(const byte* c509, word32 c509Sz,
    byte* out, word32* outLen, int* keyType, void* heap);

/* Reconstruct the byte-exact DER X.509 certificate from a type-3 C509 (type 2
 * has no DER equivalent and returns BAD_FUNC_ARG). Needs WOLFSSL_C509_TYPE3 or
 * returns NOT_COMPILED_IN. Covers authorityKeyIdentifier (keyIdentifier
 * byte-string form only) and the single-dNSName subjectAltName shortcut; a
 * CBOR-tagged (EUI/MAC) name, the AKI [keyId, certIssuer, serial] array form
 * and the other registered compact extension forms (e.g. RFC 3779
 * IPAddrBlocks) yield NOT_COMPILED_IN. A NULL out is a size query: *outLen is
 * set to the required DER length and LENGTH_ONLY_E is returned (the wolfSSL
 * convention). On any error - uniformly, including the NULL-c509/zero-size
 * BAD_FUNC_ARG and the NOT_COMPILED_IN of a WOLFSSL_C509_NO_TYPE3 build - the
 * output buffer is cleared and *outLen set to 0 whenever out and outLen are
 * both non-NULL (a NULL out has nothing to clear). Full contract in
 * doc/dox_comments/header_files/c509.h. */
WOLFSSL_API int wc_C509_ToDer(const byte* c509, word32 c509Sz,
    byte* out, word32* outLen);

/* Verify a C509 certificate's issuer signature with the issuer's raw public
 * key. Checks ONLY the signature -- not the validity period, basicConstraints,
 * keyUsage, name chaining or revocation; a 0 return means the signature is
 * valid, not that the certificate is trusted. Returns ASN_SIG_CONFIRM_E on a
 * bad signature. Infers the key type, so it returns BAD_FUNC_ARG for an RSA
 * signature algorithm: an RSA issuer (like a SHAKE or brainpool issuer) MUST
 * use wc_C509_VerifyEx -- for RSA with WC_C509_KEY_RSA. Full contract in
 * doc/dox_comments/header_files/c509.h. */
WOLFSSL_API int wc_C509_Verify(const byte* issuerPub, word32 issuerPubSz,
    const byte* c509, word32 c509Sz);

/* Like wc_C509_Verify but with the issuer key type supplied (a wc_C509_KeyType)
 * to disambiguate a brainpool key from the wire-identical NIST curve, to select
 * the curve for the SHAKE signature algorithms, and to name an RSA issuer
 * (WC_C509_KEY_RSA) that wc_C509_Verify refuses; keyType selects the curve for
 * both type-2 and type-3 ECDSA. WC_C509_KEY_UNKNOWN infers as wc_C509_Verify
 * does, a keyType whose family does not match the certificate's signature
 * algorithm returns BAD_FUNC_ARG (not ASN_SIG_CONFIRM_E), and an out-of-range
 * value returns BAD_FUNC_ARG. Full contract in
 * doc/dox_comments/header_files/c509.h. */
WOLFSSL_API int wc_C509_VerifyEx(const byte* issuerPub, word32 issuerPubSz,
    int keyType, const byte* c509, word32 c509Sz);

/* Like wc_C509_VerifyEx but with a heap hint and device id so the issuer-key
 * import and the signature check can use a static-memory pool and/or a
 * crypto-callback device (PKCS#11, a secure element). wc_C509_VerifyEx is the
 * same call with heap == NULL and devId == INVALID_DEVID. This is the entry
 * point for the constrained / offloaded targets C509 serves. Full contract in
 * doc/dox_comments/header_files/c509.h. */
WOLFSSL_API int wc_C509_VerifyEx2(const byte* issuerPub, word32 issuerPubSz,
    int keyType, const byte* c509, word32 c509Sz, void* heap, int devId);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_C509 */
#endif /* WOLF_CRYPT_C509_H */
