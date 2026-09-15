/* c509.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_C509

#include <wolfssl/wolfcrypt/c509.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    #include <wolfssl/wolfcrypt/sha512.h>
#endif
#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
    #include <wolfssl/wolfcrypt/sha3.h>
#endif

/* Fine-grained capability gates. wolfCrypt declares the verify / key-import /
 * key-export primitives only under these macros (ecc.h, ed25519.h, ed448.h),
 * and settings.h omits them under the matching NO_* option even when the family
 * is enabled. A C509 build that turns a family on but compiles one of these
 * helpers out must treat that algorithm as uncompiled (NOT_COMPILED_IN from the
 * dispatcher) rather than reference an undeclared function - the same gating
 * asn.c applies to the same calls. In a default build all of these are defined,
 * so these gates are transparent there.
 *
 * ECDSA verify does NOT require SHA-256: only the ES256 codepoint hashes with
 * SHA-256, and that case is individually #ifndef NO_SHA256 guarded (like the
 * SHA-384/512/SHAKE cases). A SHA-384-only build therefore keeps ES384/ES512/
 * SHAKE verification instead of losing the whole family. */
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY) && \
    defined(HAVE_ECC_KEY_IMPORT)
    #define C509_HAVE_ECDSA_VERIFY
#endif
#if defined(HAVE_ECC) && defined(HAVE_COMP_KEY) && \
    defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT)
    #define C509_HAVE_EC_DECOMPRESS
#endif
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY) && \
    defined(HAVE_ED25519_KEY_IMPORT)
    #define C509_HAVE_ED25519_VERIFY
#endif
#if defined(HAVE_ED448) && defined(HAVE_ED448_VERIFY) && \
    defined(HAVE_ED448_KEY_IMPORT)
    #define C509_HAVE_ED448_VERIFY
#endif

/* WOLFSSL_C509_TYPE3 (type-3 reconstruction) is defined by c509.h, above, when
 * not disabled with WOLFSSL_C509_NO_TYPE3 -- see there for the sub-feature it
 * gates. */

/* The bounded DER builder (db_* plus der_serial / der_int_minimal) is needed
 * both by type-3 reconstruction and by the type-2 ECDSA verify path, which
 * re-encodes the raw r||s signature as a DER ECDSA-Sig-Value. Compile it
 * whenever either consumer is present. */
#if defined(WOLFSSL_C509_TYPE3) || defined(C509_HAVE_ECDSA_VERIFY)
    #define C509_NEED_DER_BUILDER
#endif

/* This module's scratch buffers and key objects use the standard
 * WC_DECLARE_VAR family from types.h: stack arrays by default, heap under
 * WOLFSSL_SMALL_STACK. A pure WOLFSSL_NO_MALLOC build (no WOLFSSL_SMALL_STACK)
 * therefore allocates nothing; NO_MALLOC + SMALL_STACK is only legal with
 * WOLFSSL_STATIC_MEMORY, where XMALLOC draws from a static pool and keeps these
 * KB-scale buffers off the stack - which is the point of asking for a small
 * stack. The pool is the heap passed in: the base entry points (wc_C509_Verify
 * / wc_C509_VerifyEx / wc_C509_GetPubKey / wc_C509_ToDer) use the default heap
 * (NULL), while wc_C509_VerifyEx2 and wc_C509_GetPubKeyEx thread the caller's
 * heap down to every allocation on their path. devId (wc_C509_VerifyEx2 only)
 * reaches the issuer signature-verify key objects (the RsaKey / ecc_key /
 * ed25519_key / ed448_key) so that check can run on a crypto-callback device;
 * it is NOT applied to the EC point-decompression scratch key (a public-point
 * local operation) nor to the one-shot TBS message hash (wc_Sha*Hash, which
 * takes no heap/devId). Each allocation pairs WC_ALLOC_VAR_EX(..., TYPE, ...)
 * with WC_FREE_VAR_EX so the free matches its DYNAMIC_TYPE. */

/* Raw public-key / signature sizes for the algorithms this module handles. */
#define C509_ED25519_PUB 32  /* Ed25519 raw public key length         */
#define C509_ED25519_SIG 64  /* Ed25519 signature length              */
#define C509_ED448_PUB   57  /* Ed448 raw public key length           */
#define C509_ED448_SIG   114 /* Ed448 signature length                */
#define C509_P256_XY     64  /* secp256r1/bp256 X||Y, no leading 0x04 */
#define C509_P256_POINT  65  /* secp256r1/bp256 point 0x04||X||Y      */
/* The RSA issuer-key floor is WC_C509_RSA_MIN_BITS (defined, documented and
 * overridable in c509.h, defaulting to 1024 and rising under
 * WOLFSSL_HARDEN_TLS / WOLFSSL_MAX_STRENGTH). It is enforced in bits on the
 * RSA verify path (c509_rsa_eff_mod_bits), not as a byte count. */
#define C509_P384_XY     96  /* secp384r1/bp384 X||Y                  */
#define C509_P384_POINT  97  /* secp384r1/bp384 point 0x04||X||Y      */
#define C509_P521_XY     132 /* secp521r1 X||Y                        */
#define C509_P521_POINT  133 /* secp521r1 point 0x04||X||Y            */
#define C509_BP512_XY    128 /* brainpoolP512r1 X||Y                  */
#define C509_BP512_POINT 129 /* brainpoolP512r1 point 0x04||X||Y      */

/* C509 issuerSignatureAlgorithm registry values (draft Section 9). */
#define C509_SIG_ES256      0  /* ecdsa-with-SHA256   */
#define C509_SIG_ES384      1  /* ecdsa-with-SHA384   */
#define C509_SIG_ES512      2  /* ecdsa-with-SHA512   */
#define C509_SIG_ES_SHAKE128 3 /* ecdsa-with-SHAKE128 (RFC 8692: 256-bit) */
#define C509_SIG_ES_SHAKE256 4 /* ecdsa-with-SHAKE256 (RFC 8692: 512-bit) */
#define C509_SIG_ED25519    12 /* Ed25519           */
#define C509_SIG_ED448      13 /* Ed448             */
#define C509_SIG_RSA_SHA256 23 /* sha256WithRSAEncryption (PKCS#1 v1.5) */
#define C509_SIG_RSA_SHA384 24 /* sha384WithRSAEncryption */
#define C509_SIG_RSA_SHA512 25 /* sha512WithRSAEncryption */
#define C509_SIG_PSS_SHA256 26 /* rsassa-pss-with-sha256 (MGF1-SHA256)  */
#define C509_SIG_PSS_SHA384 27 /* rsassa-pss-with-sha384 (MGF1-SHA384)  */
#define C509_SIG_PSS_SHA512 28 /* rsassa-pss-with-sha512 (MGF1-SHA512)  */

/* C509 subjectPublicKeyAlgorithm registry values. */
#define C509_PK_RSA     0  /* rsaEncryption          */
#define C509_PK_P256    1  /* id-ecPublicKey secp256r1 */
#define C509_PK_P384    2  /* id-ecPublicKey secp384r1 */
#define C509_PK_P521    3  /* id-ecPublicKey secp521r1 */
#define C509_PK_ED25519 12 /* id-Ed25519             */
#define C509_PK_ED448   13 /* id-Ed448               */
#define C509_PK_BP256   24 /* brainpoolP256r1        */
#define C509_PK_BP384   25 /* brainpoolP384r1        */
#define C509_PK_BP512   26 /* brainpoolP512r1        */

/* ASN.1 DER identifier octets used by the type-3 reconstruction. Primitive
 * tags use the ASN_* enum from <wolfssl/wolfcrypt/asn.h> (ASN_INTEGER,
 * ASN_BIT_STRING, ASN_OCTET_STRING, ASN_OBJECT_ID, ASN_BOOLEAN, ...); the
 * constructed and context-specific forms have no single enum and are built
 * from ASN_CONSTRUCTED (0x20) and ASN_CONTEXT_SPECIFIC (0x80). */
#define C509_ASN_SEQ  (ASN_SEQUENCE | ASN_CONSTRUCTED)      /* 0x30 */
#define C509_ASN_SET  (ASN_SET | ASN_CONSTRUCTED)           /* 0x31 */
/* Context-specific [n]: constructed (0xaN) and primitive (0x8N) forms. */
#define C509_ASN_CONSTR_CTX(n) (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | (n))
#define C509_ASN_CTX(n)        (ASN_CONTEXT_SPECIFIC | (n))

/* DER scratch-buffer sizes for the type-3 reconstruction, in bytes. Named so
 * the size is not a magic number duplicated at the buffer's declaration and
 * its db_init; a generic name is shared where the size and role match. */
#define C509_MAX_EC_POINT    133 /* largest uncompressed point 0x04||X||Y  */
#define C509_DIGESTINFO_BUF  128 /* RSA/PSS DigestInfo build scratch       */
#ifndef NO_RSA
    /* Buffer the RSA signature is recovered into (PSS output / PKCS#1 v1.5
     * in-place decrypt). The recovered data is at most the modulus size, so it
     * is sized from the largest supported modulus (RSA_MAX_SIZE is in bits),
     * not the larger WC_C509_MAX_DER - which would keep a buffer more than
     * twice as big as needed on the no-malloc stack. */
    #define C509_RSA_RECOVER_BUF (RSA_MAX_SIZE / 8)
#endif
#define C509_ECDSA_SIG_INNER 146 /* SEQUENCE { INTEGER r, INTEGER s } body */
#define C509_ECDSA_SIG_DER   (C509_ECDSA_SIG_INNER + 4) /* + SEQUENCE head */

/* ==================================================================== *
 *  Minimal CBOR reader
 *
 *  C509 is a flat CBOR sequence/array of definite-length items. Only the
 *  major types C509 uses are handled. Every length is bounds-checked with the
 *  overflow-safe form `len > remaining` (never `idx + len > total`, which
 *  wraps for a length near the word size).
 * ==================================================================== */

/* Cursor over a CBOR input buffer used by the minimal reader. */
typedef struct C509Dec {
    const byte* buf; /* the CBOR input being decoded                     */
    word32      len; /* total length of buf in bytes                     */
    word32      idx; /* current read offset into buf (0 <= idx <= len)   */
} C509Dec;

/* CBOR major types (the top three bits of the initial byte). */
#define C509_CBOR_UINT   0 /* unsigned integer                          */
#define C509_CBOR_NINT   1 /* negative integer                          */
#define C509_CBOR_BSTR   2 /* byte string                               */
#define C509_CBOR_TSTR   3 /* text string                               */
#define C509_CBOR_ARRAY  4 /* array of data items                       */
#define C509_CBOR_MAP    5 /* map of key/value pairs                    */
#define C509_CBOR_TAG    6 /* a tagged data item (head + one nested item) */
#define C509_CBOR_SIMPLE 7 /* simple values (null/true/false) + floats  */

/* CBOR initial-byte layout: the major type is the top three bits and the
 * additional information is the low five bits. */
#define C509_CBOR_MAJOR_SHIFT 5    /* right-shift to isolate the major type */
#define C509_CBOR_AI_MASK     0x1f /* mask to isolate the additional info   */

/* CBOR additional-information values: below C509_CBOR_AI_1BYTE the argument is
 * the additional-info value itself; 24-27 carry the argument in the next 1, 2,
 * 4 or 8 bytes; 28-31 are reserved / indefinite (unused by C509). */
#define C509_CBOR_AI_1BYTE 24 /* argument in the next 1 byte (uint8)  */
#define C509_CBOR_AI_2BYTE 25 /* argument in the next 2 bytes (uint16) */
#define C509_CBOR_AI_4BYTE 26 /* argument in the next 4 bytes (uint32) */
#define C509_CBOR_AI_8BYTE 27 /* argument in the next 8 bytes (uint64) */

/* Initialize a CBOR decoder over buf/len, positioned at the first item.
 *
 * @param [in, out] d    Decoder cursor to initialize.
 * @param [in]      buf  CBOR input buffer.
 * @param [in]      len  Length of buf in bytes.
 */
static void c509_dec_init(C509Dec* d, const byte* buf, word32 len)
{
    d->buf = buf;
    d->len = len;
    d->idx = 0;
}

/* Read a CBOR head: major type and argument, advancing past the head. A 64-bit
 * argument that exceeds word32 is consumed and saturated to 0xFFFFFFFF so a
 * length-based use fails the bounds check while a skipped scalar steps over it.
 *
 * @param [in, out] d          Decoder cursor.
 * @param [out]     major      Receives the CBOR major type (0-7).
 * @param [out]     arg        Receives the head argument (length/count/value).
 * @param [out]     truncated  Optional (may be NULL); set to 1 when an 8-byte
 *                             argument exceeded word32 and arg was saturated to
 *                             0xFFFFFFFF, so an integer caller can reject it
 *                             rather than read the saturated value.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a truncated or reserved head.
 */
static int c509_dec_head(C509Dec* d, int* major, word32* arg, int* truncated)
{
    byte ib;
    byte ai;
    word32 n;
    word32 i;
    word32 v = 0;

    if (truncated != NULL) {
        *truncated = 0;
    }
    if (d->idx >= d->len) {
        return ASN_PARSE_E;
    }
    ib = d->buf[d->idx++];
    *major = (int)(ib >> C509_CBOR_MAJOR_SHIFT);
    ai = (byte)(ib & C509_CBOR_AI_MASK);
    if (ai < C509_CBOR_AI_1BYTE) {
        *arg = (word32)ai;
        return 0;
    }
    if (ai == C509_CBOR_AI_1BYTE) {
        n = 1;
    }
    else if (ai == C509_CBOR_AI_2BYTE) {
        n = 2;
    }
    else if (ai == C509_CBOR_AI_4BYTE) {
        n = 4;
    }
    else if (ai == C509_CBOR_AI_8BYTE) {
        if ((word32)8 > d->len - d->idx) {
            return ASN_PARSE_E;
        }
        if ((d->buf[d->idx] | d->buf[d->idx + 1] | d->buf[d->idx + 2] |
                d->buf[d->idx + 3]) != 0) {
            /* The value exceeds word32. It cannot be a length/count that
             * addresses this buffer, but it is legitimate for a scalar this
             * decoder only skips (e.g. a 64-bit IPAddrBlock prefix in an
             * extension). Consume all 8 bytes and saturate arg, so any
             * length-based use (bstr/tstr/array/map/tag) fails the bounds
             * check below while a skipped uint/nint is stepped over cleanly. */
            if (truncated != NULL) {
                *truncated = 1;
            }
            d->idx += 8;
            *arg = 0xFFFFFFFFU;
            return 0;
        }
        d->idx += 4;
        n = 4;
    }
    else {
        return ASN_PARSE_E; /* 28-31: reserved / indefinite, unused by C509 */
    }
    /* Overflow-safe: d->idx <= d->len, so compare against remaining space. */
    if (n > d->len - d->idx) {
        return ASN_PARSE_E;
    }
    for (i = 0; i < n; i++) {
        v = (v << 8) | (word32)d->buf[d->idx++];
    }
    /* RFC 8949 preferred serialization: an integer head MUST use the shortest
     * form. Reject a non-shortest head so a C509 certificate's CBOR has a
     * single canonical encoding at the CBOR-head level - otherwise a third
     * party could re-encode it (e.g. "8b" as "98 0b") into different bytes that
     * still verify. For a TYPE-2 (natively signed) certificate with a
     * DETERMINISTIC signature (RSA PKCS#1 v1.5, Ed25519/Ed448) this gives
     * byte-level uniqueness, so a relying party may pin, blocklist or
     * deduplicate by the C509 bytes or their hash. It does NOT hold for a
     * type-2 ECDSA certificate: ECDSA is algebraically malleable - (r, s) and
     * (r, n-s) both verify (wolfCrypt does not enforce low-s), so a third party
     * can flip s and produce different verifying bytes without the private key.
     * It also does NOT hold for a TYPE-3 certificate: the signature there
     * covers the RECONSTRUCTED DER, and the
     * reconstruction accepts several application-level alternatives that
     * rebuild identical DER (the compact KeyUsage int vs the [codepoint, value]
     * array, a single-dNSName SAN as bare text vs [2, text], an EKU as a bare
     * int vs a one-element array, an uncompressed 0x04 point vs the 0xfe/0xfd
     * compressed markers), so a type-3 cert can be re-encoded into different
     * C509 bytes that still verify. Pin or deduplicate a type-3 certificate by
     * the hash of its wc_C509_ToDer output, not by its C509 bytes. Major 7
     * (simple/float) is exempt: there, ai 25-27 are floats, not a non-preferred
     * integer, and the
     * 8-byte branch above has already consumed and saturated a genuine >= 2^32
     * scalar, so reaching here with an 8-byte head means a value < 2^32 that
     * should have used a shorter form. */
    if ((*major != C509_CBOR_SIMPLE) &&
            (((ai == C509_CBOR_AI_1BYTE) && (v < 24u)) ||
             ((ai == C509_CBOR_AI_2BYTE) && (v < 0x100u)) ||
             ((ai == C509_CBOR_AI_4BYTE) && (v < 0x10000u)) ||
             (ai == C509_CBOR_AI_8BYTE))) {
        return ASN_PARSE_E;
    }
    *arg = v;
    return 0;
}

/* Read a CBOR unsigned or negative integer into *out (a small signed value).
 *
 * @param [in, out] d    Decoder cursor.
 * @param [out]     out  Receives the decoded signed value.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E if the next item is not an integer.
 */
static int c509_dec_int(C509Dec* d, sword32* out)
{
    int major;
    word32 arg;
    int truncated = 0;
    int ret = c509_dec_head(d, &major, &arg, &truncated);

    if (ret != 0) {
        return ret;
    }
    if (truncated) {
        return ASN_PARSE_E; /* value exceeded word32: not a C509 codepoint */
    }
    if (major == C509_CBOR_UINT) {
        /* Reject a uint that does not fit a positive sword32, so the result
         * stays in [0, 2^31-1] and a later "type = -type" negation is safe. */
        if (arg > (word32)0x7FFFFFFF) {
            return ASN_PARSE_E;
        }
        *out = (sword32)arg;
    }
    else if (major == C509_CBOR_NINT) {
        /* nint value is -1-arg; cap arg so the value stays >= -(2^31-1),
         * i.e. never INT32_MIN, keeping its negation well-defined. */
        if (arg > (word32)0x7FFFFFFE) {
            return ASN_PARSE_E;
        }
        *out = -1 - (sword32)arg;
    }
    else {
        return ASN_PARSE_E;
    }
    return 0;
}

#ifdef WOLFSSL_C509_TYPE3
/* Read a CBOR unsigned integer into *out (a full word32, e.g. a validity time
 * beyond the sword32 range in 2038+). Used only by the type-3 reconstruction.
 *
 * @param [in, out] d    Decoder cursor.
 * @param [out]     out  Receives the decoded unsigned value.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E if the next item is not an unsigned int.
 */
static int c509_dec_uint(C509Dec* d, word32* out)
{
    int major;
    word32 arg;
    int truncated = 0;
    int ret = c509_dec_head(d, &major, &arg, &truncated);

    if (ret == 0) {
        if (truncated) {
            /* A 64-bit epoch beyond word32: reject rather than silently
             * saturate it to 0xFFFFFFFF (year 2106). */
            ret = ASN_PARSE_E;
        }
        else if (major == C509_CBOR_UINT) {
            *out = arg;
        }
        else {
            ret = ASN_PARSE_E;
        }
    }
    return ret;
}

/* Read a type-3 validity bound. A CBOR unsigned int is the in-profile value; a
 * negative int or a CBOR tag (an out-of-profile tagged / relative time) is
 * NOT_COMPILED_IN; anything else (a truncated head or wrong major type) is
 * ASN_PARSE_E - so a cut-off certificate reads as malformed, not "feature not
 * built".
 *
 * @param [in, out] d    Decoder cursor.
 * @param [out]     out  Receives the decoded unsigned time value.
 *
 * @return  0 on an unsigned int; NOT_COMPILED_IN for a negative/tagged time;
 *          ASN_PARSE_E for a truncated or ill-formed item.
 */
static int c509_dec_validity(C509Dec* d, word32* out)
{
    int major = (d->idx < d->len) ?
        (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) : -1;

    if ((major == C509_CBOR_NINT) || (major == C509_CBOR_TAG)) {
        return NOT_COMPILED_IN; /* negative / tagged time: out of profile */
    }
    return (c509_dec_uint(d, out) != 0) ? ASN_PARSE_E : 0;
}
#endif /* WOLFSSL_C509_TYPE3 */

/* Decode an AlgorithmIdentifier / KeyPurposeId that the draft CDDL allows as
 * int / ~oid / [~oid, params]. This module supports only the integer
 * (codepoint) form; a byte string (~oid) or array ([~oid, params]) is a legal
 * but out-of-profile form, so report it as NOT_COMPILED_IN ("unsupported")
 * rather than ASN_PARSE_E ("malformed"). A truncated head or any other major
 * type stays ASN_PARSE_E. On the integer form, *out gets the codepoint. Not
 * type-3-only: the type-2 verify path reads signatureAlgorithm with it too, so
 * a truncated cert is reported as malformed, not "feature not built".
 *
 * @param [in, out] d    Decoder cursor.
 * @param [out]     out  Receives the decoded codepoint on the int form.
 *
 * @return  0 on the integer form.
 * @return  NOT_COMPILED_IN for a ~oid / [~oid, params] form.
 * @return  ASN_PARSE_E for a truncated or otherwise malformed item.
 */
static int c509_dec_alg_or_oid(C509Dec* d, sword32* out)
{
    if (d->idx < d->len) {
        int major = (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT);

        if ((major == C509_CBOR_BSTR) || (major == C509_CBOR_ARRAY)) {
            return NOT_COMPILED_IN; /* legal ~oid / [~oid, params] form */
        }
    }
    return (c509_dec_int(d, out) != 0) ? ASN_PARSE_E : 0;
}

/* Read a CBOR byte or text string of the wanted major type; *p points into the
 * input buffer and *pLen is its length.
 *
 * @param [in, out] d          Decoder cursor.
 * @param [in]      wantMajor  Required major type (C509_CBOR_BSTR or
 *                             C509_CBOR_TSTR).
 * @param [out]     p          Receives a pointer to the string bytes within the
 *                             input.
 * @param [out]     pLen       Receives the string length.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a type mismatch or a length that runs past the end of
 *          the input.
 */
static int c509_dec_str(C509Dec* d, int wantMajor, const byte** p, word32* pLen)
{
    int major;
    word32 arg;
    int ret = c509_dec_head(d, &major, &arg, NULL);

    if (ret != 0) {
        return ret;
    }
    if (major != wantMajor) {
        return ASN_PARSE_E;
    }
    if (arg > d->len - d->idx) {
        return ASN_PARSE_E;
    }
    *p = d->buf + d->idx;
    *pLen = arg;
    d->idx += arg;
    return 0;
}

/* Read a CBOR array header into *count (its element count).
 *
 * @param [in, out] d      Decoder cursor.
 * @param [out]     count  Receives the array element count.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E if the next item is not an array.
 */
static int c509_dec_array(C509Dec* d, word32* count)
{
    int major;
    word32 arg;
    int ret = c509_dec_head(d, &major, &arg, NULL);

    if (ret != 0) {
        return ret;
    }
    if (major != C509_CBOR_ARRAY) {
        return ASN_PARSE_E;
    }
    *count = arg;
    return 0;
}

/* Maximum CBOR nesting c509_dec_skip will descend. C509 needs only a few
 * levels (Name / GeneralName, the RSA [modulus, exponent] array, otherName);
 * a small fixed cap stops a malformed input from recursing until the stack is
 * exhausted (which happens before any signature check). */
#define C509_MAX_SKIP_DEPTH 8

/* Skip one CBOR item, recursing through arrays with a bounded depth.
 *
 * @param [in, out] d      Decoder cursor.
 * @param [in]      depth  Current nesting depth (0 at the top level).
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a truncated, unsupported, or too-deeply-nested item.
 */
static int c509_dec_skip_d(C509Dec* d, int depth)
{
    int major;
    word32 arg;
    word32 i;
    int ret;

    if (depth > C509_MAX_SKIP_DEPTH) {
        return ASN_PARSE_E; /* nesting too deep: refuse before recursing */
    }
    ret = c509_dec_head(d, &major, &arg, NULL);
    if (ret != 0) {
        return ret;
    }
    switch (major) {
        case C509_CBOR_UINT:
        case C509_CBOR_NINT:
        case C509_CBOR_SIMPLE:
            /* The head already consumed the value / simple argument. */
            return 0;
        case C509_CBOR_BSTR:
        case C509_CBOR_TSTR:
            if (arg > d->len - d->idx) {
                return ASN_PARSE_E;
            }
            d->idx += arg;
            return 0;
        case C509_CBOR_ARRAY:
            /* Each element is at least one byte, so a count larger than the
             * remaining input is malformed - reject it before iterating (this
             * also bounds the loop). */
            if (arg > d->len - d->idx) {
                return ASN_PARSE_E;
            }
            for (i = 0; i < arg; i++) {
                ret = c509_dec_skip_d(d, depth + 1);
                if (ret != 0) {
                    return ret;
                }
            }
            return 0;
        case C509_CBOR_MAP:
            /* C509 never uses CBOR maps; rejecting them avoids the arg*2
             * element-count overflow and keeps the parser strict. */
            return ASN_PARSE_E;
        case C509_CBOR_TAG:
            /* A tag (e.g. the CBOR tag wrapping a byte-string Name in the
             * C509 encoding) is followed by exactly one data item. */
            return c509_dec_skip_d(d, depth + 1);
        default:
            return ASN_PARSE_E; /* simple / float unused by C509 */
    }
}

/* Skip one CBOR item (recursing through arrays with a bounded depth).
 *
 * @param [in, out] d  Decoder cursor.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a truncated or unsupported item.
 */
static int c509_dec_skip(C509Dec* d)
{
    return c509_dec_skip_d(d, 0);
}

/* ==================================================================== *
 *  DER builder (bounded; overflow flagged in ok)
 * ==================================================================== */

#ifdef C509_NEED_DER_BUILDER
/* A bounded, append-only DER output buffer. pos advances even past cap so an
 * overflow is detectable; ok is cleared on the first overflow so callers can
 * check it once at the end instead of after every write. */
typedef struct DerBuf {
    byte*  buf; /* destination buffer                                   */
    word32 cap; /* capacity of buf in bytes                             */
    word32 pos; /* bytes written so far (may exceed cap on overflow)    */
    int    ok;  /* non-zero while every write has fit within cap        */
} DerBuf;

/* Initialise a DerBuf over the caller's buffer of capacity cap.
 *
 * @param [in, out] b    DerBuf to initialise.
 * @param [out]     buf  Destination buffer.
 * @param [in]      cap  Capacity of buf in bytes.
 */
static void db_init(DerBuf* b, byte* buf, word32 cap)
{
    b->buf = buf;
    b->cap = cap;
    b->pos = 0;
    b->ok = 1;
}

/* Append one byte, or flag overflow (clearing ok) when the buffer is full.
 *
 * @param [in, out] b  Destination DerBuf.
 * @param [in]      v  Byte to append.
 */
static void db_byte(DerBuf* b, byte v)
{
    if (b->buf == NULL) {
        /* Measuring sink (db_init with a NULL buffer): count the byte only,
         * never flag overflow, so a measure pass that runs the same encoders
         * reports the exact length while leaving ok set. */
        b->pos++;
    }
    else if (b->pos < b->cap) {
        b->buf[b->pos] = v;
        b->pos++;
    }
    else {
        b->ok = 0;
        b->pos++;
    }
}

/* Append n raw bytes.
 *
 * @param [in, out] b  Destination DerBuf.
 * @param [in]      d  Source bytes.
 * @param [in]      n  Number of bytes to append.
 */
static void db_raw(DerBuf* b, const byte* d, word32 n)
{
    word32 i;
    for (i = 0; i < n; i++) {
        db_byte(b, d[i]);
    }
}

/* Append a DER definite length (values here are always < 65536).
 *
 * @param [in, out] b  Destination DerBuf.
 * @param [in]      n  Length value to encode.
 */
static void db_len(DerBuf* b, word32 n)
{
    if (n < 0x80) {
        db_byte(b, (byte)n);
    }
    else if (n < 0x100) {
        db_byte(b, (byte)(ASN_LONG_LENGTH | 1)); /* long form, 1 length byte */
        db_byte(b, (byte)n);
    }
    else if (n <= 0xFFFF) {
        db_byte(b, (byte)(ASN_LONG_LENGTH | 2)); /* long form, 2 length bytes */
        db_byte(b, (byte)(n >> 8));
        db_byte(b, (byte)n);
    }
    else {
        /* A DER length of 65536+ cannot occur for a C509 certificate (bounded
         * by WC_C509_MAX_DER). Flag overflow rather than silently truncate the
         * length to two bytes, which would emit structurally wrong DER. The
         * pos still advances so a measure pass and the emit pass agree. */
        b->ok = 0;
        b->pos += 3;
    }
}

/* Append a DER TLV: tag, definite length n, then the n value bytes.
 *
 * @param [in, out] b    Destination DerBuf.
 * @param [in]      tag  DER tag byte.
 * @param [in]      v    Value bytes.
 * @param [in]      n    Number of value bytes.
 */
static void db_tlv(DerBuf* b, byte tag, const byte* v, word32 n)
{
    db_byte(b, tag);
    db_len(b, n);
    db_raw(b, v, n);
}

#ifdef C509_HAVE_ECDSA_VERIFY
/* Wrap a child buffer as tag||length||child. A child that overflowed its own
 * buffer has pos past capacity, so never read it as a length -- propagate the
 * overflow to dst instead. Only the ECDSA verify paths (which stage an
 * ECDSA-Sig-Value / issuer SPKI in a small buffer) still wrap this way; the
 * reconstruction encoders write straight into the output, so this is gated to
 * its callers to avoid an unused-function build in a non-ECC configuration.
 *
 * @param [in, out] dst    Destination DerBuf.
 * @param [in]      tag    DER tag byte to wrap the child with.
 * @param [in]      child  Source DerBuf holding the content.
 */
static void db_wrap(DerBuf* dst, byte tag, const DerBuf* child)
{
    if (!child->ok) {
        dst->ok = 0;
        return;
    }
    db_tlv(dst, tag, child->buf, child->pos);
}
#endif /* C509_HAVE_ECDSA_VERIFY */
#endif /* C509_NEED_DER_BUILDER */

#ifdef WOLFSSL_C509_TYPE3
/* Number of bytes db_len emits for a definite length n (values < 65536): one
 * for a short form, two or three for the long form. Used to precompute nested
 * DER lengths so content can be written directly without a temporary buffer.
 *
 * @param [in] n  Length value that would be encoded.
 *
 * @return  The number of DER length bytes (1, 2 or 3).
 */
static word32 der_len_size(word32 n)
{
    word32 size;

    if (n < 0x80) {
        size = 1;
    }
    else if (n < 0x100) {
        size = 2;
    }
    else {
        size = 3;
    }
    return size;
}

/* TBSCertificate version [0] EXPLICIT INTEGER 2 (X.509 v3), a fixed prefix. */
static const byte DER_VERSION_V3[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
/* C509 extension registry codepoints (draft Section 9.4) handled by
 * der_extensions; a negative codepoint marks the extension critical. */
#define C509_EXT_SKI 1 /* subjectKeyIdentifier   */
#define C509_EXT_KU  2 /* keyUsage               */
#define C509_EXT_SAN 3 /* subjectAltName         */
#define C509_EXT_BC  4 /* basicConstraints       */
#define C509_EXT_AKI 7 /* authorityKeyIdentifier */
#define C509_EXT_EKU 8 /* extKeyUsage            */

/* extension OID prefixes (id-ce.*): OBJECT IDENTIFIER of each extnID. */
static const byte DER_OID_SKI[]   = { 0x06, 0x03, 0x55, 0x1d, 0x0e };
static const byte DER_OID_AKI[]   = { 0x06, 0x03, 0x55, 0x1d, 0x23 };
static const byte DER_OID_KU[]    = { 0x06, 0x03, 0x55, 0x1d, 0x0f };
static const byte DER_OID_BC[]    = { 0x06, 0x03, 0x55, 0x1d, 0x13 };
static const byte DER_OID_EKU[]   = { 0x06, 0x03, 0x55, 0x1d, 0x25 };
/* X.509 extension "critical" BOOLEAN TRUE, emitted before the extnValue for any
 * extension whose C509 codepoint was negative (BasicConstraints, KeyUsage, EKU,
 * SAN, or an OID-form extension). */
static const byte DER_EXT_CRITICAL[] = { 0x01, 0x01, 0xff };
/* BasicConstraints extnValue: OCTET STRING { SEQUENCE { BOOLEAN cA TRUE } }. */
static const byte DER_BC_VALUE[]  = { 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
    0xff };

/* ---- Algorithm / attribute reconstruction tables ------------------------- *
 * Type-3 reconstruction must reproduce the original DER byte-for-byte (its
 * signature is over the original DER TBS), so the algorithm identifiers and
 * attribute OIDs are stored as their exact DER encodings and looked up by the
 * C509 registry codepoint. Every entry below was extracted from the matching
 * draft-ietf-cose-c509-test-vectors certificate. */

/* One row of a codepoint -> fixed-DER lookup table (signatureAlgorithm or
 * SubjectPublicKeyInfo AlgorithmIdentifier). */
typedef struct C509DerAlg {
    sword32     codepoint; /* C509 registry codepoint (sig- or pk-alg)       */
    const byte* der;       /* the complete DER AlgorithmIdentifier bytes      */
    word32      derLen;    /* length of der in bytes                         */
} C509DerAlg;

/* signatureAlgorithm DER (a full SEQUENCE) per C509 signature codepoint. */
static const byte DER_SIGALG_ES256[]  = { 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
static const byte DER_SIGALG_ES384[]  = { 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
static const byte DER_SIGALG_ES512[]  = { 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 };
static const byte DER_SIGALG_SHAKE128[] = { 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x06, 0x20 };
static const byte DER_SIGALG_SHAKE256[] = { 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x06, 0x21 };
/* sha256WithRSAEncryption (SEQUENCE { OID 1.2.840.113549.1.1.11, NULL }). */
static const byte DER_SIGALG_RSA_SHA256[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 };
/* id-Ed25519 (SEQUENCE { OID 1.3.101.112 }); Edwards AlgIds carry no params. */
static const byte DER_SIGALG_ED25519[] = { 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x70 };
/* id-Ed448 (SEQUENCE { OID 1.3.101.113 }). */
static const byte DER_SIGALG_ED448[] = { 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x71 };

/* signatureAlgorithm lookup: C509 signature codepoint -> DER. */
static const C509DerAlg C509_SIGALG_TABLE[] = {
    { C509_SIG_ES256,       DER_SIGALG_ES256,  sizeof(DER_SIGALG_ES256)  },
    { C509_SIG_ES384,       DER_SIGALG_ES384,  sizeof(DER_SIGALG_ES384)  },
    { C509_SIG_ES512,       DER_SIGALG_ES512,  sizeof(DER_SIGALG_ES512)  },
    { C509_SIG_ES_SHAKE128, DER_SIGALG_SHAKE128, sizeof(DER_SIGALG_SHAKE128) },
    { C509_SIG_ES_SHAKE256, DER_SIGALG_SHAKE256, sizeof(DER_SIGALG_SHAKE256) },
    { C509_SIG_RSA_SHA256,  DER_SIGALG_RSA_SHA256,
      sizeof(DER_SIGALG_RSA_SHA256) },
    { C509_SIG_ED25519,     DER_SIGALG_ED25519, sizeof(DER_SIGALG_ED25519) },
    { C509_SIG_ED448,       DER_SIGALG_ED448,   sizeof(DER_SIGALG_ED448)   }
};

/* SubjectPublicKeyInfo AlgorithmIdentifier DER (a full SEQUENCE of
 * id-ecPublicKey + the named-curve OID) per C509 public-key codepoint.
 * Per-algorithm: each curve's DER (and its table entry below) is compiled only
 * when that key type's crypto is enabled, so a C509 whose key type is disabled
 * resolves to NOT_COMPILED_IN (its verify path is likewise gated). */
#ifdef HAVE_ECC
static const byte DER_SPKIALG_P256[]  = { 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07 };
static const byte DER_SPKIALG_P384[]  = { 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const byte DER_SPKIALG_P521[]  = { 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
#ifdef HAVE_ECC_BRAINPOOL
static const byte DER_SPKIALG_BP256[] = { 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02,
    0x08, 0x01, 0x01, 0x07 };
static const byte DER_SPKIALG_BP384[] = { 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02,
    0x08, 0x01, 0x01, 0x0b };
static const byte DER_SPKIALG_BP512[] = { 0x30, 0x14, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02,
    0x08, 0x01, 0x01, 0x0d };
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* HAVE_ECC */
#ifndef NO_RSA
/* rsaEncryption (SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }); the RSA key is
 * reconstructed as an RSAPublicKey with the C509 default exponent 65537.
 * RSA-specific: omitted when RSA is disabled (an RSA-keyed C509 is then an
 * unsupported key type, since the RSA verify path is also NO_RSA-gated). */
static const byte DER_SPKIALG_RSA[]   = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
#endif
#ifdef HAVE_ED25519
/* id-Ed25519 (SEQUENCE { OID 1.3.101.112 }); the raw key is the BIT STRING. */
static const byte DER_SPKIALG_ED25519[] = { 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x70 };
#endif
#ifdef HAVE_ED448
/* id-Ed448 (SEQUENCE { OID 1.3.101.113 }); the raw key is the BIT STRING. */
static const byte DER_SPKIALG_ED448[] = { 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
    0x71 };
#endif

/* SubjectPublicKeyInfo AlgorithmIdentifier lookup: C509 pk codepoint -> DER.
 * The Weierstrass curves take an uncompressed SEC1 point (0x04||X||Y) and
 * Ed25519 a raw key in the BIT STRING; RSA rebuilds an RSAPublicKey from the
 * C509 modulus. */
static const C509DerAlg C509_SPKIALG_TABLE[] = {
#ifdef HAVE_ECC
    { C509_PK_P256,  DER_SPKIALG_P256,  sizeof(DER_SPKIALG_P256)  },
    { C509_PK_P384,  DER_SPKIALG_P384,  sizeof(DER_SPKIALG_P384)  },
    { C509_PK_P521,  DER_SPKIALG_P521,  sizeof(DER_SPKIALG_P521)  },
#ifdef HAVE_ECC_BRAINPOOL
    { C509_PK_BP256, DER_SPKIALG_BP256, sizeof(DER_SPKIALG_BP256) },
    { C509_PK_BP384, DER_SPKIALG_BP384, sizeof(DER_SPKIALG_BP384) },
    { C509_PK_BP512, DER_SPKIALG_BP512, sizeof(DER_SPKIALG_BP512) },
#endif
#endif /* HAVE_ECC */
#ifndef NO_RSA
    { C509_PK_RSA,     DER_SPKIALG_RSA,     sizeof(DER_SPKIALG_RSA)     },
#endif
#ifdef HAVE_ED25519
    { C509_PK_ED25519, DER_SPKIALG_ED25519, sizeof(DER_SPKIALG_ED25519) },
#endif
#ifdef HAVE_ED448
    { C509_PK_ED448,   DER_SPKIALG_ED448,   sizeof(DER_SPKIALG_ED448)   }
#endif
#if !defined(HAVE_ECC) && defined(NO_RSA) && !defined(HAVE_ED25519) && \
    !defined(HAVE_ED448)
    /* No public-key algorithm is compiled in (e.g. a PQ-only cryptonly build).
     * A sentinel keeps the array non-empty - an empty initializer and a
     * zero-length array are invalid in C89/C99 and degenerate for the
     * sizeof(table)/sizeof(table[0]) count. The codepoint is INT32_MIN, which
     * c509_dec_int can never produce (it caps a nint at -(2^31-1)), so it
     * matches no decoded subjectPublicKeyAlgorithm - every GetPubKey/ToDer
     * resolves to NOT_COMPILED_IN. (A plain -1 would wrongly match a cert
     * carrying codepoint -1, CBOR 0x20.) */
    { -0x7FFFFFFF - 1, NULL, 0 }
#endif
};

/* One row mapping a C509 name-attribute codepoint to the DER of its
 * AttributeType OID plus the ASN.1 tag its (text) AttributeValue uses. */
typedef struct C509Attr {
    sword32     codepoint; /* C509 attribute registry codepoint          */
    const byte* oid;       /* DER OBJECT IDENTIFIER of the attribute type */
    word32      oidLen;    /* length of oid in bytes                     */
    byte        strTag;    /* ASN.1 tag of the value (0x0c UTF8String)   */
} C509Attr;

/* AttributeType OIDs (all id-at.*, i.e. 2.5.4.n) for the attributes handled. */
static const byte DER_OID_AT_CN[]        = { 0x06, 0x03, 0x55, 0x04, 0x03 };
static const byte DER_OID_AT_SURNAME[]   = { 0x06, 0x03, 0x55, 0x04, 0x04 };
static const byte DER_OID_AT_COUNTRY[]   = { 0x06, 0x03, 0x55, 0x04, 0x06 };
static const byte DER_OID_AT_TITLE[]     = { 0x06, 0x03, 0x55, 0x04, 0x0c };
static const byte DER_OID_AT_GIVENNAME[] = { 0x06, 0x03, 0x55, 0x04, 0x2a };
static const byte DER_OID_AT_NAME[]      = { 0x06, 0x03, 0x55, 0x04, 0x29 };

/* ASN.1 value-string tags for a name attribute. The C509 compact Name form
 * selects the DER string type by the SIGN of the attribute codepoint: a
 * positive codepoint carries a UTF8String value (the draft's default, used
 * even for countryName in its own type-2 vectors), a negative codepoint the
 * same attribute type (by absolute value) with a PrintableString value. The
 * negative form is how a type-3 (CBOR re-encoded X.509) certificate preserves
 * a PrintableString attribute - countryName is always PrintableString in a
 * real X.509 Name (RFC 5280), and legacy certificates use it for others too -
 * so the original DER can be reconstructed byte-for-byte. */
#define C509_DER_UTF8STRING     0x0c
#define C509_DER_PRINTABLESTRING 0x13

/* Name-attribute lookup: C509 attribute codepoint -> OID + value tag. */
static const C509Attr C509_ATTR_TABLE[] = {
    {  1, DER_OID_AT_CN, sizeof(DER_OID_AT_CN), C509_DER_UTF8STRING },
    {  2, DER_OID_AT_SURNAME, sizeof(DER_OID_AT_SURNAME), C509_DER_UTF8STRING },
    {  4, DER_OID_AT_COUNTRY, sizeof(DER_OID_AT_COUNTRY), C509_DER_UTF8STRING },
    { 10, DER_OID_AT_TITLE, sizeof(DER_OID_AT_TITLE), C509_DER_UTF8STRING },
    { 13, DER_OID_AT_GIVENNAME, sizeof(DER_OID_AT_GIVENNAME),
      C509_DER_UTF8STRING },
    { 25, DER_OID_AT_NAME, sizeof(DER_OID_AT_NAME), C509_DER_UTF8STRING }
};

/* SubjectAltName reconstruction constants. The C509 SubjectAltName value is a
 * CBOR array of (GeneralName type codepoint, value) pairs; the type selects the
 * DER GeneralName [n] tag. The negative codepoints are otherName forms with an
 * implied type-id OID (id-on-*). */
static const byte DER_OID_SAN[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
/* id-on-hardwareModuleName (1.3.6.1.5.5.7.8.4), codepoint -1. */
static const byte DER_ON_HWMODULE[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x08, 0x04 };
/* id-on-SmtpUTF8Mailbox (1.3.6.1.5.5.7.8.9), codepoint -2. */
static const byte DER_ON_SMTPUTF8[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x08, 0x09 };
/* id-on-otherName (1.3.6.1.5.5.7.8.12), codepoint -3 (OCTET STRING value). */
static const byte DER_ON_OTHER812[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x08, 0x0c };

/* KeyPurposeId OIDs for ExtendedKeyUsage, indexed by C509 purpose codepoint. */
static const byte DER_KP_SERVERAUTH[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x03, 0x01 };
static const byte DER_KP_CLIENTAUTH[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x03, 0x02 };

/* ExtendedKeyUsage purpose lookup: C509 codepoint -> KeyPurposeId OID DER. */
static const C509DerAlg C509_EKU_TABLE[] = {
    { 1, DER_KP_SERVERAUTH, sizeof(DER_KP_SERVERAUTH) },
    { 2, DER_KP_CLIENTAUTH, sizeof(DER_KP_CLIENTAUTH) }
};

/* BasicConstraints extnValue for cA:FALSE: OCTET STRING { SEQUENCE {} }. */
static const byte DER_BC_VALUE_FALSE[] = { 0x04, 0x02, 0x30, 0x00 };

/* Look up the fixed DER for a codepoint in a C509DerAlg table.
 *
 * @param [in] table      The C509DerAlg table to search.
 * @param [in] count      Number of entries in table.
 * @param [in] codepoint  C509 registry codepoint to match.
 *
 * @return  The matching entry, or NULL when the codepoint is not in the table.
 */
static const C509DerAlg* c509_der_alg_find(const C509DerAlg* table,
    word32 count, sword32 codepoint)
{
    const C509DerAlg* found = NULL;
    word32 i;

    for (i = 0; i < count; i++) {
        if (table[i].codepoint == codepoint) {
            found = &table[i];
            break;
        }
    }
    return found;
}

/* Look up a name-attribute codepoint in C509_ATTR_TABLE.
 *
 * @param [in] codepoint  C509 attribute registry codepoint to match.
 *
 * @return  The matching entry, or NULL when the attribute type is not
 *          supported.
 */
static const C509Attr* c509_attr_find(sword32 codepoint)
{
    const C509Attr* found = NULL;
    word32 i;
    word32 count = (word32)(sizeof(C509_ATTR_TABLE) /
        sizeof(C509_ATTR_TABLE[0]));

    for (i = 0; i < count; i++) {
        if (C509_ATTR_TABLE[i].codepoint == codepoint) {
            found = &C509_ATTR_TABLE[i];
            break;
        }
    }
    return found;
}

/* Emit one AttributeTypeAndValue as a RelativeDistinguishedName:
 * SET { SEQUENCE { OBJECT type, <valTag> value } }, written directly into out
 * with precomputed lengths (no temporary buffer).
 *
 * @param [in, out] out     Accumulator receiving the RDN.
 * @param [in]      oid     DER OBJECT IDENTIFIER of the attribute type.
 * @param [in]      oidLen  Length of oid.
 * @param [in]      valTag  ASN.1 tag of the value.
 * @param [in]      val     Attribute value bytes.
 * @param [in]      valLen  Length of val.
 */
static void der_attr_atv(DerBuf* out, const byte* oid, word32 oidLen,
    byte valTag, const byte* val, word32 valLen)
{
    word32 seqLen = oidLen + 1u + der_len_size(valLen) + valLen;
    word32 setLen = 1u + der_len_size(seqLen) + seqLen;

    db_byte(out, C509_ASN_SET); /* RelativeDistinguishedName SET */
    db_len(out, setLen);
    db_byte(out, C509_ASN_SEQ); /* AttributeTypeAndValue SEQUENCE */
    db_len(out, seqLen);
    db_raw(out, oid, oidLen);
    db_byte(out, valTag);
    db_len(out, valLen);
    db_raw(out, val, valLen);
}

/* Build a single-commonName Name = SEQUENCE { RDN(commonName, v) } from a
 * contiguous UTF8String value.
 *
 * @param [in, out] out    Accumulator receiving the Name.
 * @param [in]      cn     CommonName UTF8String bytes.
 * @param [in]      cnLen  Length of cn.
 */
static void der_name_cn(DerBuf* out, const byte* cn, word32 cnLen)
{
    word32 seqLen = (word32)sizeof(DER_OID_AT_CN) + 1u +
        der_len_size(cnLen) + cnLen;
    word32 setLen = 1u + der_len_size(seqLen) + seqLen;
    word32 nameLen = 1u + der_len_size(setLen) + setLen;

    db_byte(out, C509_ASN_SEQ); /* Name SEQUENCE */
    db_len(out, nameLen);
    der_attr_atv(out, DER_OID_AT_CN, (word32)sizeof(DER_OID_AT_CN),
        C509_DER_UTF8STRING, cn, cnLen);
}

/* Build a single-commonName Name whose value is the lower-case hex expansion
 * of a C509 byte string (each input byte becomes two hex characters). The hex
 * digits are written directly, so no expansion buffer is needed.
 *
 * @param [in, out] out   Accumulator receiving the Name.
 * @param [in]      s     Source byte string to hex-expand.
 * @param [in]      sLen  Length of s.
 */
static void der_name_cn_hex(DerBuf* out, const byte* s, word32 sLen)
{
    static const char hexd[] = "0123456789abcdef";
    word32 cnLen = sLen * 2u;
    word32 seqLen = (word32)sizeof(DER_OID_AT_CN) + 1u +
        der_len_size(cnLen) + cnLen;
    word32 setLen = 1u + der_len_size(seqLen) + seqLen;
    word32 nameLen = 1u + der_len_size(setLen) + setLen;
    word32 i;

    db_byte(out, C509_ASN_SEQ); /* Name SEQUENCE */
    db_len(out, nameLen);
    db_byte(out, C509_ASN_SET); /* RelativeDistinguishedName SET */
    db_len(out, setLen);
    db_byte(out, C509_ASN_SEQ); /* AttributeTypeAndValue SEQUENCE */
    db_len(out, seqLen);
    db_raw(out, DER_OID_AT_CN, (word32)sizeof(DER_OID_AT_CN));
    db_byte(out, C509_DER_UTF8STRING);
    db_len(out, cnLen);
    for (i = 0; i < sLen; i++) {
        db_byte(out, (byte)hexd[s[i] >> 4]);
        db_byte(out, (byte)hexd[s[i] & 0x0f]);
    }
}

/* Reconstruct one Name RelativeDistinguishedName from the C509 (type, value)
 * pair at d: a registered (int codepoint, UTF8String) attribute, or an OID-form
 * (~oid bytes, DER AttributeValue bytes) attribute. When out is non-NULL the
 * RDN is emitted; its total DER length is always returned via *rdnLen. Advances
 * d past the pair either way, so der_name_multi can size (out == NULL) and then
 * emit (out != NULL) in two walks of the same array.
 *
 * @param [in, out] d       Decoder cursor, positioned at the attribute pair.
 * @param [in, out] out     Accumulator to emit the RDN into, or NULL to only
 *                          measure.
 * @param [out]     rdnLen  Receives the RDN's total DER length.
 *
 * @return  0 on success.
 * @return  NOT_COMPILED_IN for an out-of-profile attribute, or ASN_PARSE_E on a
 *          malformed pair.
 */
static int der_name_attr(C509Dec* d, DerBuf* out, word32* rdnLen)
{
    int ret = 0;
    int major = (d->idx < d->len) ?
        (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) : -1;

    if ((major == C509_CBOR_UINT) || (major == C509_CBOR_NINT)) {
        /* Registered attribute: (int codepoint, text). The codepoint's sign
         * selects the DER value-string type: positive -> UTF8String, negative
         * -> PrintableString of the same attribute (looked up by its absolute
         * value). c509_dec_int caps the magnitude below 2^31, so negating a
         * negative type cannot overflow. */
        sword32 type = 0;
        const byte* val = NULL;
        word32 valLen = 0;
        const C509Attr* attr;
        word32 seqLen;
        word32 setLen;
        byte strTag;

        int vMajor;

        if (c509_dec_int(d, &type) != 0) {
            /* The head byte is an int major but the int does not decode: a
             * truncated multi-byte head or a 64-bit value is malformed. */
            ret = ASN_PARSE_E;
        }
        else if ((attr = c509_attr_find((type < 0) ? -type : type)) == NULL) {
            ret = NOT_COMPILED_IN; /* well-formed but unregistered codepoint */
        }
        else if ((vMajor = ((d->idx < d->len) ?
                (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) : -1)) < 0) {
            /* The codepoint is the last byte: the value is truncated away. */
            ret = ASN_PARSE_E;
        }
        else if (vMajor != C509_CBOR_TSTR) {
            /* Only a text (UTF8String) value is in profile; any other
             * well-formed CBOR major type is out of profile, not malformed. */
            ret = NOT_COMPILED_IN;
        }
        else if (c509_dec_str(d, C509_CBOR_TSTR, &val, &valLen) != 0) {
            /* A text header whose length runs past the buffer is malformed. */
            ret = ASN_PARSE_E;
        }
        else {
            /* A negative codepoint overrides the table's (UTF8String) tag with
             * PrintableString; the value length - and so every DER length
             * below - is identical either way (the tag is one byte). */
            strTag = (type < 0) ? C509_DER_PRINTABLESTRING : attr->strTag;
            seqLen = attr->oidLen + 1u + der_len_size(valLen) + valLen;
            setLen = 1u + der_len_size(seqLen) + seqLen;
            *rdnLen = 1u + der_len_size(setLen) + setLen;
            if (out != NULL) {
                der_attr_atv(out, attr->oid, attr->oidLen, strTag, val,
                    valLen);
            }
        }
    }
    else if (major == C509_CBOR_BSTR) {
        /* OID-form attribute: (~oid bytes, DER AttributeValue bytes). The value
         * byte string is the complete AttributeValue TLV, emitted verbatim. */
        const byte* oid = NULL;
        const byte* val = NULL;
        word32 oidLen = 0;
        word32 valLen = 0;
        word32 seqLen;
        word32 setLen;

        if ((c509_dec_str(d, C509_CBOR_BSTR, &oid, &oidLen) != 0) ||
                (c509_dec_str(d, C509_CBOR_BSTR, &val, &valLen) != 0)) {
            ret = ASN_PARSE_E;
        }
        else {
            seqLen = 1u + der_len_size(oidLen) + oidLen + valLen;
            setLen = 1u + der_len_size(seqLen) + seqLen;
            *rdnLen = 1u + der_len_size(setLen) + setLen;
            if (out != NULL) {
                db_byte(out, C509_ASN_SET); /* RelativeDistinguishedName SET */
                db_len(out, setLen);
                db_byte(out, C509_ASN_SEQ); /* AttributeTypeAndValue SEQUENCE */
                db_len(out, seqLen);
                db_byte(out, ASN_OBJECT_ID); /* AttributeType OID */
                db_len(out, oidLen);
                db_raw(out, oid, oidLen);
                db_raw(out, val, valLen); /* AttributeValue (DER verbatim) */
            }
        }
    }
    else if (major < 0) {
        /* The Name array ended before this attribute pair: malformed. */
        ret = ASN_PARSE_E;
    }
    else {
        ret = NOT_COMPILED_IN; /* well-formed but unsupported attributeType */
    }
    return ret;
}

/* Pass 1 of der_name_multi: walk the count-element C509 name array from the
 * decoder's current position, validate every attribute pair and accumulate the
 * DER Name content length into *content.
 *
 * @param [in, out] d        Decoder cursor, positioned at the first array
 *                           element.
 * @param [in]      count    Number of array elements (an even, non-zero pair
 *                           count).
 * @param [in, out] content  Accumulates the summed Name content length.
 *
 * @return  0 on success.
 * @return  NOT_COMPILED_IN for an out-of-profile attribute.
 */
static int der_name_measure(C509Dec* d, word32 count, word32* content)
{
    int ret = 0;
    word32 i;

    for (i = 0; (ret == 0) && (i < count); i += 2) {
        word32 rdnLen = 0;

        ret = der_name_attr(d, NULL, &rdnLen);
        *content += rdnLen;
    }
    return ret;
}

/* Reconstruct a multi-attribute Name from the C509 array form: array[2*N] of
 * (attributeType, value) pairs, each a registered or OID-form attribute (see
 * der_name_attr) becoming one single-attribute RDN. Emitted as
 * SEQUENCE { RDN, ... } directly into out; two passes size the Name header so
 * no temporary buffer is used.
 *
 * @param [in, out] d    Decoder cursor, positioned at the Name array.
 * @param [in, out] out  Accumulator receiving the DER Name.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed array.
 * @return  NOT_COMPILED_IN for an out-of-profile attribute, or BUFFER_E on
 *          overflow.
 */
static int der_name_multi(C509Dec* d, DerBuf* out)
{
    int ret = 0;
    word32 startIdx = d->idx;
    word32 count = 0;
    word32 content = 0;
    word32 i;

    if (c509_dec_array(d, &count) != 0) {
        ret = ASN_PARSE_E;
    }
    else if ((count == 0) || ((count % 2) != 0)) {
        ret = NOT_COMPILED_IN; /* Name must be a non-empty set of pairs */
    }
    else {
        /* pass 1: validate every attribute and sum the Name content length. */
        ret = der_name_measure(d, count, &content);
    }
    /* pass 2: emit the Name header, then each RDN, re-walking the array. */
    if (ret == 0) {
        db_byte(out, C509_ASN_SEQ); /* Name SEQUENCE */
        db_len(out, content);
        d->idx = startIdx;
        (void)c509_dec_array(d, &count);
        for (i = 0; (ret == 0) && (i < count); i += 2) {
            word32 rdnLen = 0;

            ret = der_name_attr(d, out, &rdnLen);
        }
        if ((ret == 0) && !out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* Reconstruct a Name from a C509 name item. A CBOR null (when nullOk) sets
 * *wasNull and emits nothing; a text string is a verbatim commonName; a byte
 * string is the lower-case-hex commonName form; an array is the multi-attribute
 * form.
 *
 * @param [in, out] d        Decoder cursor, positioned at the Name item.
 * @param [in, out] out      Accumulator receiving the DER Name.
 * @param [in]      nullOk   Non-zero if a CBOR null is accepted (emits
 *                           nothing).
 * @param [out]     wasNull  Optional; set to 1 when a null was consumed (may be
 *                           NULL).
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed item.
 * @return  NOT_COMPILED_IN for an out-of-profile form, or BUFFER_E on overflow.
 */
static int der_name_from_c509(C509Dec* d, DerBuf* out, int nullOk, int* wasNull)
{
    int ret = 0;
    const byte* s;
    word32 sLen;
    int major;

    if (wasNull != NULL) {
        *wasNull = 0;
    }
    if (d->idx >= d->len) {
        ret = ASN_PARSE_E;
    }
    else if (nullOk && (d->buf[d->idx] == 0xf6)) { /* CBOR null */
        d->idx++;
        if (wasNull != NULL) {
            *wasNull = 1;
        }
    }
    else {
        major = (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT);
        if (major == C509_CBOR_TSTR) {
            if (c509_dec_str(d, C509_CBOR_TSTR, &s, &sLen) != 0) {
                ret = ASN_PARSE_E;
            }
            else {
                der_name_cn(out, s, sLen);
                ret = out->ok ? 0 : BUFFER_E;
            }
        }
        else if (major == C509_CBOR_BSTR) {
            if (c509_dec_str(d, C509_CBOR_BSTR, &s, &sLen) != 0) {
                ret = ASN_PARSE_E;
            }
            else {
                der_name_cn_hex(out, s, sLen);
                ret = out->ok ? 0 : BUFFER_E;
            }
        }
        else if (major == C509_CBOR_ARRAY) {
            ret = der_name_multi(d, out);
        }
        else {
            ret = NOT_COMPILED_IN;
        }
    }
    return ret;
}

/* Days-from-epoch to civil y/m/d (Hinnant), then a DER time: a 13-byte UTCTime
 * (two-digit year) for 1950-2049 or a 15-byte GeneralizedTime (four-digit year)
 * otherwise, per RFC 5280 Section 4.1.2.5.
 *
 * @param [in, out] out       Accumulator receiving the UTCTime /
 *                            GeneralizedTime TLV.
 * @param [in]      unixSecs  Time as Unix seconds.
 *
 * @return  0 on success.
 * @return  BUFFER_E on overflow.
 */
static int der_time(DerBuf* out, word32 unixSecs)
{
    byte t[15]; /* GeneralizedTime YYYYMMDDHHMMSSZ (UTCTime uses first 13) */
    sword32 z = (sword32)(unixSecs / 86400);
    word32 secOfDay = unixSecs % 86400;
    sword32 era;
    word32 doe, yoe, y, doy, mp, day, mon;
    word32 hh = secOfDay / 3600;
    word32 mm = (secOfDay / 60) % 60;
    word32 ss = secOfDay % 60;
    word32 i = 0;
    int utc;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (word32)(z - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = (word32)(yoe + (word32)era * 400);
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    day = doy - (153 * mp + 2) / 5 + 1;
    mon = mp < 10 ? mp + 3 : mp - 9;
    y += (mon <= 2);
    utc = (y >= 1950) && (y <= 2049);
    if (utc) {
        t[i++] = (byte)('0' + (y / 10) % 10);
        t[i++] = (byte)('0' + y % 10);
    }
    else {
        t[i++] = (byte)('0' + (y / 1000) % 10);
        t[i++] = (byte)('0' + (y / 100) % 10);
        t[i++] = (byte)('0' + (y / 10) % 10);
        t[i++] = (byte)('0' + y % 10);
    }
    t[i++] = (byte)('0' + mon / 10);
    t[i++] = (byte)('0' + mon % 10);
    t[i++] = (byte)('0' + day / 10);
    t[i++] = (byte)('0' + day % 10);
    t[i++] = (byte)('0' + hh / 10);
    t[i++] = (byte)('0' + hh % 10);
    t[i++] = (byte)('0' + mm / 10);
    t[i++] = (byte)('0' + mm % 10);
    t[i++] = (byte)('0' + ss / 10);
    t[i++] = (byte)('0' + ss % 10);
    t[i++] = 'Z';
    db_tlv(out, utc ? 0x17 : 0x18, t, i);
    return out->ok ? 0 : BUFFER_E;
}

/* Emit the RFC 5280 Section 4.1.2.5 "no well-defined expiration date"
 * GeneralizedTime 99991231235959Z, used to reconstruct a C509 null notAfter.
 *
 * @param [in, out] out  Accumulator receiving the GeneralizedTime TLV.
 */
static void der_time_no_expiry(DerBuf* out)
{
    static const byte t[15] =
        { '9','9','9','9','1','2','3','1','2','3','5','9','5','9','Z' };
    db_tlv(out, 0x18, t, (word32)sizeof(t));
}

/* --- Type-3 extension reconstruction --------------------------------------
 * Each handler parses one C509 extension value from d and appends the DER
 * Extension SEQUENCE { extnID, [critical BOOLEAN TRUE], extnValue } to the
 * accumulator out. The profile currently covers SubjectKeyIdentifier (1),
 * KeyUsage (2), BasicConstraints (4) and ExtendedKeyUsage (8). Handlers whose
 * several scratch buffers add up to a large stack frame use WC_DECLARE_VAR so
 * they move to the heap under WOLFSSL_SMALL_STACK. */

/* SubjectKeyIdentifier (id-ce-subjectKeyIdentifier): the C509 value is the raw
 * key-identifier byte string; extnValue is OCTET STRING { OCTET STRING kid }.
 *
 * @param [in, out] d    Decoder cursor, positioned at the extension value.
 * @param [in, out] out  Accumulator receiving the DER Extension SEQUENCE.
 * @param [in]      crit  Nonzero if the extension was marked critical.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed value (or a critical flag, which this
 *          extension MUST NOT carry).
 * @return  BUFFER_E on overflow.
 */
static int der_ext_ski(C509Dec* d, DerBuf* out, int crit)
{
    int ret = 0;
    const byte* v;
    word32 vLen;

    if (crit) {
        /* RFC 5280 4.2.1.2: subjectKeyIdentifier MUST be non-critical. */
        ret = ASN_PARSE_E;
    }
    else if (c509_dec_str(d, C509_CBOR_BSTR, &v, &vLen) != 0) {
        ret = ASN_PARSE_E;
    }
    else {
        /* Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING } where
         * extnValue wraps a KeyIdentifier OCTET STRING. The nested lengths are
         * precomputed from the inner value so the TLVs are written straight
         * into `out` with no intermediate buffer. */
        word32 kidLen = 1u + der_len_size(vLen) + vLen;
        word32 valLen = 1u + der_len_size(kidLen) + kidLen;
        word32 cLen = (word32)sizeof(DER_OID_SKI) + valLen;

        db_byte(out, C509_ASN_SEQ); /* Extension SEQUENCE */
        db_len(out, cLen);
        db_raw(out, DER_OID_SKI, (word32)sizeof(DER_OID_SKI));
        db_byte(out, ASN_OCTET_STRING); /* extnValue OCTET STRING */
        db_len(out, kidLen);
        db_tlv(out, ASN_OCTET_STRING, v, vLen); /* KeyIdentifier */
        if (!out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* AuthorityKeyIdentifier (id-ce-authorityKeyIdentifier): the C509 value, in the
 * common form every CA-issued leaf carries, is the raw key-identifier byte
 * string. extnValue is OCTET STRING { SEQUENCE { keyIdentifier [0] IMPLICIT
 * OCTET STRING } }. The full [keyId, authorityCertIssuer, serial] array form is
 * out of scope and yields NOT_COMPILED_IN. AKI is non-critical (RFC 5280).
 *
 * @param [in, out] d    Decoder cursor, positioned at the extension value.
 * @param [in, out] out  Accumulator receiving the DER Extension SEQUENCE.
 * @param [in]      crit  Nonzero if the extension was marked critical.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed value (or a critical flag, which this
 *          extension MUST NOT carry).
 * @return  NOT_COMPILED_IN for the unsupported array form.
 * @return  BUFFER_E on overflow.
 */
static int der_ext_aki(C509Dec* d, DerBuf* out, int crit)
{
    int ret = 0;
    const byte* v;
    word32 vLen;
    int major = (d->idx < d->len) ?
        (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) : -1;

    if (crit) {
        /* RFC 5280 4.2.1.1: authorityKeyIdentifier MUST be non-critical. */
        ret = ASN_PARSE_E;
    }
    else if (major != C509_CBOR_BSTR) {
        ret = NOT_COMPILED_IN; /* only the keyIdentifier byte-string form */
    }
    else if (c509_dec_str(d, C509_CBOR_BSTR, &v, &vLen) != 0) {
        ret = ASN_PARSE_E;
    }
    else {
        /* Lengths precomputed from the inner value so the nested TLVs write
         * straight into `out` with no intermediate buffer. */
        word32 kidLen = 1u + der_len_size(vLen) + vLen;     /* [0] keyId     */
        word32 seqLen = 1u + der_len_size(kidLen) + kidLen; /* SEQUENCE      */
        word32 valLen = 1u + der_len_size(seqLen) + seqLen; /* OCTET STRING  */
        word32 cLen = (word32)sizeof(DER_OID_AKI) + valLen;

        db_byte(out, C509_ASN_SEQ); /* Extension SEQUENCE */
        db_len(out, cLen);
        db_raw(out, DER_OID_AKI, (word32)sizeof(DER_OID_AKI));
        db_byte(out, ASN_OCTET_STRING); /* extnValue OCTET STRING */
        db_len(out, seqLen);
        db_byte(out, C509_ASN_SEQ); /* AuthorityKeyIdentifier SEQUENCE */
        db_len(out, kidLen);
        db_byte(out, C509_ASN_CTX(0)); /* keyIdentifier [0] IMPLICIT */
        db_len(out, vLen);
        db_raw(out, v, vLen);
        if (!out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* KeyUsage (id-ce-keyUsage): bits is the usage bit set numbered LSB-first; DER
 * encodes it as a BIT STRING numbered MSB-first, trimmed to the highest set
 * bit. The caller supplies the value and criticality (from the extension type
 * codepoint's sign, or from the compact single-KeyUsage int's sign).
 *
 * @param [in, out] out   Accumulator receiving the DER Extension SEQUENCE.
 * @param [in]      bits  KeyUsage bit set (positive).
 * @param [in]      crit  Non-zero to emit the critical BOOLEAN TRUE.
 *
 * @return  0 on success.
 * @return  NOT_COMPILED_IN for an out-of-range bit set, or BUFFER_E on
 *          overflow.
 */
static int der_ext_ku(DerBuf* out, sword32 bits, int crit)
{
    int ret = 0;
    byte content[2]; /* MSB-first usage bits (up to 9 bits -> 2 bytes) */
    byte bs[3];      /* BIT STRING body: unused-bit count + content    */
    int highBit;
    int k;
    word32 kuLen;
    word32 bsLen;
    word32 bitLen;
    word32 valLen;
    word32 cLen;

    if ((bits <= 0) || (bits > 0x1ff)) {
        ret = NOT_COMPILED_IN;
    }
    else {
        content[0] = 0;
        content[1] = 0;
        highBit = -1;
        for (k = 0; k < 9; k++) {
            if ((bits >> k) & 1) {
                content[k / 8] |= (byte)(0x80 >> (k % 8));
                highBit = k;
            }
        }
        kuLen = (highBit >= 8) ? 2u : 1u;
        bs[0] = (byte)(7 - (highBit % 8)); /* unused bits in the last byte */
        bs[1] = content[0];
        if (kuLen == 2) {
            bs[2] = content[1];
        }
        /* Extension wraps extnValue OCTET STRING { KeyUsage BIT STRING };
         * nested lengths are derived from bsLen so nothing is buffered. */
        bsLen = kuLen + 1u;
        bitLen = 1u + der_len_size(bsLen) + bsLen; /* BIT STRING TLV */
        valLen = 1u + der_len_size(bitLen) + bitLen; /* extnValue OCTET STR */
        cLen = (word32)sizeof(DER_OID_KU) + valLen;
        if (crit) {
            cLen += (word32)sizeof(DER_EXT_CRITICAL);
        }
        db_byte(out, C509_ASN_SEQ); /* Extension SEQUENCE */
        db_len(out, cLen);
        db_raw(out, DER_OID_KU, (word32)sizeof(DER_OID_KU));
        if (crit) {
            db_raw(out, DER_EXT_CRITICAL, (word32)sizeof(DER_EXT_CRITICAL));
        }
        db_byte(out, ASN_OCTET_STRING); /* extnValue OCTET STRING */
        db_len(out, bitLen);
        db_tlv(out, ASN_BIT_STRING, bs, bsLen); /* KeyUsage BIT STRING */
        if (!out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* BasicConstraints (id-ce-basicConstraints): the C509 value is -1 (cA TRUE, no
 * pathLenConstraint), -2 (cA FALSE) or a non-negative pathLenConstraint (cA
 * TRUE with that path length), optionally critical.
 *
 * @param [in, out] d     Decoder cursor, positioned at the extension value.
 * @param [in, out] out   Accumulator receiving the DER Extension SEQUENCE.
 * @param [in]      crit  Non-zero to emit the critical BOOLEAN TRUE.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed value.
 * @return  NOT_COMPILED_IN for a value below -2, or BUFFER_E on overflow.
 */
static int der_ext_bc(C509Dec* d, DerBuf* out, int crit)
{
    int ret = 0;
    sword32 v;

    if (c509_dec_int(d, &v) != 0) {
        ret = ASN_PARSE_E;
    }
    else if (v < -2) {
        ret = NOT_COMPILED_IN; /* out-of-profile BasicConstraints value */
    }
    else {
        /* Extension content = extnID OID [ + critical ] + extnValue. The
         * value is a fixed constant for cA TRUE/FALSE, or (for a path length)
         * an OCTET STRING { SEQUENCE { BOOLEAN TRUE, INTEGER v } }. The content
         * length is precomputed so the TLVs write straight into `out`. */
        byte nb[5]; /* minimal DER INTEGER content bytes (path length) */
        byte tmp[4];
        word32 nlen = 0;
        word32 seqLen = 0;
        word32 cLen = (word32)sizeof(DER_OID_BC);

        if (crit) {
            cLen += (word32)sizeof(DER_EXT_CRITICAL);
        }
        if (v == -1) {
            cLen += (word32)sizeof(DER_BC_VALUE);
        }
        else if (v == -2) {
            cLen += (word32)sizeof(DER_BC_VALUE_FALSE);
        }
        else {
            word32 uv = (word32)v;
            word32 ti = 0;

            if (uv == 0) {
                nb[nlen++] = 0x00;
            }
            else {
                while (uv != 0) {
                    tmp[ti++] = (byte)(uv & 0xffu);
                    uv >>= 8;
                }
                if ((tmp[ti - 1] & 0x80) != 0) {
                    nb[nlen++] = 0x00; /* keep the INTEGER positive */
                }
                while (ti != 0) {
                    nb[nlen++] = tmp[--ti];
                }
            }
            seqLen = 3u + 2u + nlen; /* BOOLEAN TRUE + INTEGER v */
            cLen += 1u + der_len_size(2u + seqLen) + (2u + seqLen);
        }

        db_byte(out, C509_ASN_SEQ); /* Extension SEQUENCE */
        db_len(out, cLen);
        db_raw(out, DER_OID_BC, (word32)sizeof(DER_OID_BC));
        if (crit) {
            db_raw(out, DER_EXT_CRITICAL, (word32)sizeof(DER_EXT_CRITICAL));
        }
        if (v == -1) {
            db_raw(out, DER_BC_VALUE, (word32)sizeof(DER_BC_VALUE));
        }
        else if (v == -2) {
            db_raw(out, DER_BC_VALUE_FALSE, (word32)sizeof(DER_BC_VALUE_FALSE));
        }
        else {
            db_byte(out, ASN_OCTET_STRING); /* extnValue OCTET STRING */
            db_len(out, 2u + seqLen);
            db_byte(out, C509_ASN_SEQ); /* BasicConstraints SEQUENCE */
            db_len(out, seqLen);
            db_byte(out, ASN_BOOLEAN); /* cA BOOLEAN */
            db_byte(out, 0x01);
            db_byte(out, 0xff); /* TRUE */
            db_byte(out, ASN_INTEGER); /* pathLenConstraint INTEGER */
            db_len(out, nlen);
            db_raw(out, nb, nlen);
        }
        if (!out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* Emit the concatenated KeyPurposeId OIDs of an ExtKeyUsage extension,
 * decoding each CBOR purpose from d (no SEQUENCE wrapper). Re-runnable: the
 * caller rewinds d->idx to measure into a null sink then emit into `out`, so
 * the SEQUENCE OF needs no intermediate buffer.
 *
 * @param [in, out] d    CBOR decoder cursor at the purpose value(s).
 * @param [in, out] out  Destination DerBuf for the OID bytes.
 *
 * @return  0 on success; ASN_PARSE_E or NOT_COMPILED_IN on bad input.
 */
static int der_eku_oids(C509Dec* d, DerBuf* out)
{
    int ret = 0;
    word32 count = 0;
    word32 i;
    int isArray;
    word32 ekuN = (word32)(sizeof(C509_EKU_TABLE) / sizeof(C509_EKU_TABLE[0]));

    isArray = ((d->idx < d->len) &&
        ((d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) == C509_CBOR_ARRAY));
    if (isArray && (c509_dec_array(d, &count) != 0)) {
        ret = ASN_PARSE_E;
    }
    else {
        if (!isArray) {
            count = 1; /* a bare int is a single purpose */
        }
        for (i = 0; (ret == 0) && (i < count); i++) {
            sword32 purpose;
            const C509DerAlg* kp;

            if ((ret = c509_dec_alg_or_oid(d, &purpose)) != 0) {
                /* 0 on the int form, else NOT_COMPILED_IN (~oid purpose) or
                 * ASN_PARSE_E (malformed) - the error is already classified. */
            }
            else if ((kp = c509_der_alg_find(C509_EKU_TABLE, ekuN,
                    purpose)) == NULL) {
                ret = NOT_COMPILED_IN; /* unsupported EKU purpose */
            }
            else {
                db_raw(out, kp->der, kp->derLen);
            }
        }
    }
    return ret;
}

/* ExtendedKeyUsage (id-ce-extKeyUsage): the C509 value is a single purpose
 * codepoint or an array of them; each maps through C509_EKU_TABLE to a
 * KeyPurposeId OID. Emitted as SEQUENCE OF KeyPurposeId inside the extnValue
 * OCTET STRING.
 *
 * @param [in, out] d    Decoder cursor, positioned at the extension value.
 * @param [in, out] out  Accumulator receiving the DER Extension SEQUENCE.
 * @param [in]      crit  Nonzero to emit the critical BOOLEAN TRUE.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed value.
 * @return  NOT_COMPILED_IN for an unsupported purpose.
 * @return  BUFFER_E on overflow.
 */
static int der_ext_eku(C509Dec* d, DerBuf* out, int crit)
{
    int ret;
    word32 start = d->idx;
    DerBuf m;
    word32 oidsLen;
    word32 seqLen;
    word32 valLen;
    word32 cLen;

    /* pass 1: measure the SEQUENCE OF KeyPurposeId content into a null sink */
    db_init(&m, NULL, 0);
    ret = der_eku_oids(d, &m);
    if (ret == 0) {
        oidsLen = m.pos;
        seqLen = 1u + der_len_size(oidsLen) + oidsLen; /* SEQUENCE OF */
        valLen = 1u + der_len_size(seqLen) + seqLen;   /* extnValue OCTET STR */
        cLen = (word32)sizeof(DER_OID_EKU) + valLen;
        if (crit) {
            cLen += (word32)sizeof(DER_EXT_CRITICAL);
        }
        /* pass 2: re-decode the OIDs, writing the extension into `out` */
        d->idx = start;
        db_byte(out, C509_ASN_SEQ); /* Extension SEQUENCE */
        db_len(out, cLen);
        db_raw(out, DER_OID_EKU, (word32)sizeof(DER_OID_EKU));
        if (crit) {
            db_raw(out, DER_EXT_CRITICAL, (word32)sizeof(DER_EXT_CRITICAL));
        }
        db_byte(out, ASN_OCTET_STRING); /* extnValue OCTET STRING */
        db_len(out, seqLen);
        db_byte(out, C509_ASN_SEQ); /* SEQUENCE OF KeyPurposeId */
        db_len(out, oidsLen);
        ret = der_eku_oids(d, out);
        if ((ret == 0) && !out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* --- SubjectAltName GeneralName reconstruction ----------------------------
 * A C509 GeneralName is a (type codepoint, value) pair. Positive codepoints map
 * to the DER GeneralName [n] context tag; negative codepoints are otherName
 * forms with an implied id-on-* type-id OID. The helpers below emit one
 * GeneralName into the SubjectAltName accumulator; all lengths are precomputed
 * so no temporary buffer is needed except for the directoryName Name. */

/* C509 GeneralName type codepoints (draft Section 9.5) handled by
 * der_general_name. Positive values are the DER GeneralName [n] context tag;
 * negative values select an id-on-* otherName form. */
#define C509_GN_OTHERNAME  0  /* generic otherName [ OID, valueDER ]        */
#define C509_GN_RFC822     1  /* rfc822Name [1]                             */
#define C509_GN_DNS        2  /* dNSName [2]                                */
#define C509_GN_DIRNAME    4  /* directoryName [4] EXPLICIT Name            */
#define C509_GN_URI        6  /* uniformResourceIdentifier [6]              */
#define C509_GN_IPADDR     7  /* iPAddress [7]                              */
#define C509_GN_REGID      8  /* registeredID [8]                          */
#define C509_GN_HWMODULE  (-1) /* otherName id-on-hardwareModuleName        */
#define C509_GN_SMTPUTF8  (-2) /* otherName id-on-SmtpUTF8Mailbox           */
#define C509_GN_OTHER812  (-3) /* otherName id-on(8.12), OCTET STRING value */

/* Emit an otherName [0] { type-id OID, [0] EXPLICIT { <valTag> value } } for
 * the id-on forms whose value is a single typed string (SmtpUTF8Mailbox as
 * UTF8String, codepoint -3 as OCTET STRING).
 *
 * @param [in, out] out       Accumulator receiving the GeneralName.
 * @param [in]      onOid     DER type-id OID (id-on-*).
 * @param [in]      onOidLen  Length of onOid.
 * @param [in]      valTag    ASN.1 tag of the value.
 * @param [in]      val       Value bytes.
 * @param [in]      valLen    Length of val.
 */
static void der_gn_othername_typed(DerBuf* out, const byte* onOid,
    word32 onOidLen, byte valTag, const byte* val, word32 valLen)
{
    word32 vTlv = 1u + der_len_size(valLen) + valLen;
    word32 expl = 1u + der_len_size(vTlv) + vTlv;
    word32 content = onOidLen + expl;

    db_byte(out, C509_ASN_CONSTR_CTX(0)); /* [0] otherName */
    db_len(out, content);
    db_raw(out, onOid, onOidLen);
    db_byte(out, C509_ASN_CONSTR_CTX(0)); /* [0] EXPLICIT value */
    db_len(out, vTlv);
    db_byte(out, valTag);
    db_len(out, valLen);
    db_raw(out, val, valLen);
}

/* Emit a generic otherName [0] { type-id OID, [0] EXPLICIT { <valDer> } } where
 * the C509 gives the type-id OID content and the already-DER-encoded value.
 *
 * @param [in, out] out        Accumulator receiving the GeneralName.
 * @param [in]      oid        Type-id OBJECT IDENTIFIER content bytes.
 * @param [in]      oidLen     Length of oid.
 * @param [in]      valDer     Already-DER-encoded value.
 * @param [in]      valDerLen  Length of valDer.
 */
static void der_gn_othername_raw(DerBuf* out, const byte* oid, word32 oidLen,
    const byte* valDer, word32 valDerLen)
{
    word32 oidTlv = 1u + der_len_size(oidLen) + oidLen;
    word32 expl = 1u + der_len_size(valDerLen) + valDerLen;
    word32 content = oidTlv + expl;

    db_byte(out, C509_ASN_CONSTR_CTX(0)); /* [0] otherName */
    db_len(out, content);
    db_byte(out, ASN_OBJECT_ID); /* type-id OBJECT IDENTIFIER */
    db_len(out, oidLen);
    db_raw(out, oid, oidLen);
    db_byte(out, C509_ASN_CONSTR_CTX(0)); /* [0] EXPLICIT value */
    db_len(out, valDerLen);
    db_raw(out, valDer, valDerLen);
}

/* Emit an id-on-hardwareModuleName otherName (codepoint -1): [0] { OID(id-on),
 * [0] EXPLICIT { SEQUENCE { hwType OID, hwSerialNum OCTET STRING } } }. The
 * C509 gives the hwType OID content and the serial number octets.
 *
 * @param [in, out] out       Accumulator receiving the GeneralName.
 * @param [in]      hwOid     HwType OBJECT IDENTIFIER content bytes.
 * @param [in]      hwOidLen  Length of hwOid.
 * @param [in]      ser       HwSerialNum octets.
 * @param [in]      serLen    Length of ser.
 */
static void der_gn_hwmodule(DerBuf* out, const byte* hwOid, word32 hwOidLen,
    const byte* ser, word32 serLen)
{
    word32 oidTlv = 1u + der_len_size(hwOidLen) + hwOidLen;
    word32 osTlv = 1u + der_len_size(serLen) + serLen;
    word32 seqContent = oidTlv + osTlv;
    word32 seqTlv = 1u + der_len_size(seqContent) + seqContent;
    word32 expl = 1u + der_len_size(seqTlv) + seqTlv;
    word32 content = (word32)sizeof(DER_ON_HWMODULE) + expl;

    db_byte(out, C509_ASN_CONSTR_CTX(0)); /* [0] otherName */
    db_len(out, content);
    db_raw(out, DER_ON_HWMODULE, (word32)sizeof(DER_ON_HWMODULE));
    db_byte(out, C509_ASN_CONSTR_CTX(0)); /* [0] EXPLICIT value */
    db_len(out, seqTlv);
    db_byte(out, C509_ASN_SEQ); /* HardwareModuleName SEQUENCE */
    db_len(out, seqContent);
    db_byte(out, ASN_OBJECT_ID); /* hwType OBJECT IDENTIFIER */
    db_len(out, hwOidLen);
    db_raw(out, hwOid, hwOidLen);
    db_byte(out, ASN_OCTET_STRING); /* hwSerialNum OCTET STRING */
    db_len(out, serLen);
    db_raw(out, ser, serLen);
}

/* Reconstruct one GeneralName from the C509 (type, value) pair into out.
 * Supports rfc822Name (1), dNSName (2), directoryName (4), URI (6),
 * iPAddress (7), registeredID (8), the generic otherName (0), and the id-on
 * otherName forms hardwareModuleName (-1), SmtpUTF8Mailbox (-2) and the
 * OCTET-STRING otherName (-3).
 *
 * @param [in, out] d    Decoder cursor, positioned at the GeneralName pair.
 * @param [in, out] out  Accumulator receiving the DER GeneralName.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed pair.
 * @return  NOT_COMPILED_IN for an unsupported type.
 * @return  BUFFER_E on overflow.
 */
static int der_general_name(C509Dec* d, DerBuf* out)
{
    int ret = 0;
    sword32 type = 0;
    const byte* v = NULL;
    const byte* oid = NULL;
    word32 vLen = 0;
    word32 oidLen = 0;
    word32 cnt = 0;

    if (c509_dec_int(d, &type) != 0) {
        ret = ASN_PARSE_E;
    }
    else if (type == C509_GN_RFC822) { /* rfc822Name [1] IA5String (implicit) */
        ret = (c509_dec_str(d, C509_CBOR_TSTR, &v, &vLen) == 0) ? 0
            : ASN_PARSE_E;
        if (ret == 0) {
            db_tlv(out, 0x81, v, vLen);
        }
    }
    else if (type == C509_GN_DNS) { /* dNSName [2] */
        ret = (c509_dec_str(d, C509_CBOR_TSTR, &v, &vLen) == 0) ? 0
            : ASN_PARSE_E;
        if (ret == 0) {
            db_tlv(out, 0x82, v, vLen);
        }
    }
    else if (type == C509_GN_URI) { /* uniformResourceIdentifier [6] */
        ret = (c509_dec_str(d, C509_CBOR_TSTR, &v, &vLen) == 0) ? 0
            : ASN_PARSE_E;
        if (ret == 0) {
            db_tlv(out, 0x86, v, vLen);
        }
    }
    else if (type == C509_GN_IPADDR) { /* iPAddress [7] */
        ret = (c509_dec_str(d, C509_CBOR_BSTR, &v, &vLen) == 0) ? 0
            : ASN_PARSE_E;
        if (ret == 0) {
            db_tlv(out, 0x87, v, vLen);
        }
    }
    else if (type == C509_GN_REGID) { /* registeredID [8] (OID content) */
        ret = (c509_dec_str(d, C509_CBOR_BSTR, &v, &vLen) == 0) ? 0
            : ASN_PARSE_E;
        if (ret == 0) {
            db_tlv(out, 0x88, v, vLen);
        }
    }
    else if (type == C509_GN_DIRNAME) { /* directoryName [4] EXPLICIT Name */
        /* [4] wraps the Name: measure it (null sink), write the tag+len, then
         * re-decode it straight into out - no staging buffer. */
        word32 start = d->idx;
        word32 nameLen;
        DerBuf m;

        db_init(&m, NULL, 0);
        ret = der_name_from_c509(d, &m, 0, NULL);
        if (ret == 0) {
            nameLen = m.pos;
            db_byte(out, C509_ASN_CONSTR_CTX(4));
            db_len(out, nameLen);
            d->idx = start;
            ret = der_name_from_c509(d, out, 0, NULL);
        }
    }
    else if (type == C509_GN_OTHERNAME) { /* otherName: [ OID, valueDER ] */
        if ((c509_dec_array(d, &cnt) != 0) || (cnt != 2) ||
                (c509_dec_str(d, C509_CBOR_BSTR, &oid, &oidLen) != 0) ||
                (c509_dec_str(d, C509_CBOR_BSTR, &v, &vLen) != 0)) {
            ret = ASN_PARSE_E;
        }
        else {
            der_gn_othername_raw(out, oid, oidLen, v, vLen);
        }
    }
    else if (type == C509_GN_HWMODULE) { /* otherName hardwareModuleName */
        if ((c509_dec_array(d, &cnt) != 0) || (cnt != 2) ||
                (c509_dec_str(d, C509_CBOR_BSTR, &oid, &oidLen) != 0) ||
                (c509_dec_str(d, C509_CBOR_BSTR, &v, &vLen) != 0)) {
            ret = ASN_PARSE_E;
        }
        else {
            der_gn_hwmodule(out, oid, oidLen, v, vLen);
        }
    }
    else if (type == C509_GN_SMTPUTF8) { /* otherName SmtpUTF8Mailbox: UTF8 */
        ret = (c509_dec_str(d, C509_CBOR_TSTR, &v, &vLen) == 0) ? 0
            : ASN_PARSE_E;
        if (ret == 0) {
            der_gn_othername_typed(out, DER_ON_SMTPUTF8,
                (word32)sizeof(DER_ON_SMTPUTF8), C509_DER_UTF8STRING, v, vLen);
        }
    }
    else if (type == C509_GN_OTHER812) { /* otherName id-on(8.12): OCTET STR */
        ret = (c509_dec_str(d, C509_CBOR_BSTR, &v, &vLen) == 0) ? 0
            : ASN_PARSE_E;
        if (ret == 0) {
            der_gn_othername_typed(out, DER_ON_OTHER812,
                (word32)sizeof(DER_ON_OTHER812), 0x04, v, vLen);
        }
    }
    else {
        ret = NOT_COMPILED_IN; /* unsupported GeneralName type */
    }
    if ((ret == 0) && !out->ok) {
        ret = BUFFER_E;
    }

    return ret;
}

/* Emit the GeneralName entries - the content of the GeneralNames SEQUENCE,
 * without its wrapper - into out, decoding the (array[2N]) from d. Re-runnable
 * from a saved cursor so der_ext_san can measure then encode.
 *
 * @param [in, out] d    Decoder cursor, positioned at the GeneralNames array.
 * @param [in, out] out  Destination DerBuf for the GeneralName entries.
 * @return  0 on success, or a negative wolfCrypt error.
 */
static int der_san_content(C509Dec* d, DerBuf* out)
{
    int ret = 0;
    word32 count = 0;
    word32 i;
    int major = (d->idx < d->len) ?
        (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) : -1;

    if (major == C509_CBOR_TSTR) {
        /* C509 shortcut: a subjectAltName with exactly one dNSName is encoded
         * as a bare text string rather than a [type, value] array. Emit it as
         * a single dNSName [2] IMPLICIT GeneralName. */
        const byte* v;
        word32 vLen;

        if (c509_dec_str(d, C509_CBOR_TSTR, &v, &vLen) != 0) {
            ret = ASN_PARSE_E;
        }
        else {
            db_tlv(out, 0x82, v, vLen); /* dNSName [2] */
        }
    }
    else if ((c509_dec_array(d, &count) != 0) || ((count % 2) != 0)) {
        ret = ASN_PARSE_E;
    }
    else {
        for (i = 0; (ret == 0) && (i < count); i += 2) {
            ret = der_general_name(d, out);
        }
    }
    return ret;
}

/* SubjectAltName (id-ce-subjectAltName): the C509 value is array[2*N] of
 * (GeneralName type, value). Each GeneralName is reconstructed into an
 * accumulator, then wrapped as SEQUENCE inside the extnValue OCTET STRING and
 * emitted as the Extension SEQUENCE.
 *
 * @param [in, out] d    Decoder cursor, positioned at the extension value.
 * @param [in, out] out  Accumulator receiving the DER Extension SEQUENCE.
 * @param [in]      crit  Nonzero to emit the critical BOOLEAN TRUE.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed value.
 * @return  BUFFER_E on overflow.
 */
static int der_ext_san(C509Dec* d, DerBuf* out, int crit)
{
    int ret;
    word32 start = d->idx;
    word32 gnLen;
    word32 sanSeqTlv;
    word32 octTlv;
    word32 extContent;
    DerBuf m;

    /* pass 1: measure the GeneralNames content (null sink, no buffer). */
    db_init(&m, NULL, 0);
    ret = der_san_content(d, &m);
    if (ret == 0) {
        /* Extension SEQUENCE { extnID, [critical BOOLEAN,] extnValue OCTET
         * STRING { GeneralNames SEQUENCE OF GeneralName } }, headers emitted
         * from precomputed lengths, then the content re-decoded into out. */
        gnLen = m.pos;
        sanSeqTlv = 1u + der_len_size(gnLen) + gnLen;
        octTlv = 1u + der_len_size(sanSeqTlv) + sanSeqTlv;
        extContent = (word32)sizeof(DER_OID_SAN) + octTlv;
        if (crit) {
            extContent += (word32)sizeof(DER_EXT_CRITICAL);
        }
        db_byte(out, C509_ASN_SEQ); /* Extension SEQUENCE */
        db_len(out, extContent);
        db_raw(out, DER_OID_SAN, (word32)sizeof(DER_OID_SAN));
        if (crit) {
            db_raw(out, DER_EXT_CRITICAL, (word32)sizeof(DER_EXT_CRITICAL));
        }
        db_byte(out, ASN_OCTET_STRING); /* extnValue OCTET STRING */
        db_len(out, sanSeqTlv);
        db_byte(out, C509_ASN_SEQ); /* GeneralNames SEQUENCE */
        db_len(out, gnLen);
        d->idx = start;
        ret = der_san_content(d, out);
        if ((ret == 0) && !out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* Reconstruct an OID-identified (unregistered) extension whose extnID ~oid has
 * already been read into oid/oidLen. The extensionValue follows as a byte
 * string (non-critical) or a one-element array of a byte string (critical), and
 * carries the DER extnValue verbatim. Emitted as SEQUENCE { extnID OID,
 * [critical BOOLEAN TRUE], extnValue OCTET STRING }.
 *
 * @param [in, out] d       Decoder cursor, positioned at the extensionValue.
 * @param [in]      oid     The extnID OID content bytes (the ~oid byte string).
 * @param [in]      oidLen  Length of oid.
 * @param [in, out] out     Accumulator receiving the DER Extension SEQUENCE.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed value, or BUFFER_E on overflow.
 */
static int der_ext_oid(C509Dec* d, const byte* oid, word32 oidLen, DerBuf* out)
{
    int ret = 0;
    const byte* val = NULL;
    word32 valLen = 0;
    int crit = 0;
    word32 cnt = 0;

    if ((d->idx < d->len) &&
            ((d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) == C509_CBOR_ARRAY)) {
        crit = 1; /* [ bytes ] wraps a critical extension's value */
        if ((c509_dec_array(d, &cnt) != 0) || (cnt != 1u) ||
                (c509_dec_str(d, C509_CBOR_BSTR, &val, &valLen) != 0)) {
            ret = ASN_PARSE_E;
        }
    }
    else if (c509_dec_str(d, C509_CBOR_BSTR, &val, &valLen) != 0) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        word32 oidTlv = 1u + der_len_size(oidLen) + oidLen;
        word32 octTlv = 1u + der_len_size(valLen) + valLen;
        word32 content = oidTlv + octTlv +
            (crit ? (word32)sizeof(DER_EXT_CRITICAL) : 0u);

        db_byte(out, C509_ASN_SEQ); /* Extension SEQUENCE */
        db_len(out, content);
        db_byte(out, ASN_OBJECT_ID); /* extnID OBJECT IDENTIFIER */
        db_len(out, oidLen);
        db_raw(out, oid, oidLen);
        if (crit) {
            /* critical BOOLEAN TRUE */
            db_raw(out, DER_EXT_CRITICAL, (word32)sizeof(DER_EXT_CRITICAL));
        }
        db_byte(out, ASN_OCTET_STRING); /* extnValue OCTET STRING */
        db_len(out, valLen);
        db_raw(out, val, valLen);
        if (!out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

/* Reconstruct one extension entry from the C509 extensions array - a
 * (type, value) pair, or an (~oid, value) pair for an OID-identified
 * (unregistered) extension - appending its DER to acc. A registered type is
 * an int codepoint, negative when the extension is critical.
 *
 * NOTE: the draft lets an extension that HAS a registered int codepoint also
 * be carried in OID form (an unregistered-style (~oid, value) pair). Both
 * rebuild to the same extension DER, so the CA signature verifies either way,
 * but a consumer that scans the raw CBOR for int codepoints would miss an
 * OID-form KU/EKU/BC/... that the reconstructed DER does contain. This is why
 * the only sound way to read a type-3 certificate's extensions is to parse the
 * wc_C509_ToDer output (an ordinary X.509 DER), never the CBOR directly; the
 * public-header dox states this. The library's own verify path is unaffected:
 * it checks the CA signature over the reconstructed DER and never consults the
 * CBOR codepoints for a policy decision.
 *
 * @param [in, out] d    Decoder cursor, positioned at the extension's type.
 * @param [in, out] acc  Accumulator receiving the extension DER.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed entry.
 * @return  NOT_COMPILED_IN for an unsupported extension type.
 */
static int der_extension(C509Dec* d, DerBuf* acc)
{
    int ret = 0;
    sword32 type;
    int crit;
    int major = (d->idx < d->len) ?
        (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) : -1;

    if (major == C509_CBOR_BSTR) {
        /* OID-identified (unregistered) extension: (~oid, value). */
        const byte* oid = NULL;
        word32 oidLen = 0;

        if (c509_dec_str(d, C509_CBOR_BSTR, &oid, &oidLen) != 0) {
            ret = ASN_PARSE_E;
        }
        else {
            ret = der_ext_oid(d, oid, oidLen, acc);
        }
    }
    else if (c509_dec_int(d, &type) != 0) {
        ret = ASN_PARSE_E;
    }
    else {
        crit = (type < 0);
        if (crit) {
            type = -type;
        }
        if (type == C509_EXT_SKI) {
            ret = der_ext_ski(d, acc, crit);
        }
        else if (type == C509_EXT_KU) {
            sword32 bits = 0;

            if (c509_dec_int(d, &bits) != 0) {
                ret = ASN_PARSE_E;
            }
            else {
                ret = der_ext_ku(acc, bits, crit);
            }
        }
        else if (type == C509_EXT_SAN) {
            ret = der_ext_san(d, acc, crit);
        }
        else if (type == C509_EXT_BC) {
            ret = der_ext_bc(d, acc, crit);
        }
        else if (type == C509_EXT_AKI) {
            ret = der_ext_aki(d, acc, crit);
        }
        else if (type == C509_EXT_EKU) {
            ret = der_ext_eku(d, acc, crit);
        }
        else {
            ret = NOT_COMPILED_IN;
        }
    }
    return ret;
}

/* Emit the Extension entries - the content of the Extensions SEQUENCE, without
 * the SEQUENCE / [3] wrapper - into out, decoding them from d. Re-runnable from
 * a saved cursor so der_extensions can measure then encode. Handles the array
 * form (array[2N] of (type, value)) and the compact form (a lone KeyUsage int
 * whose sign marks criticality).
 *
 * @param [in, out] d    Decoder cursor, positioned at the extensions field.
 * @param [in, out] out  Destination DerBuf for the extension entries.
 * @return  0 on success, or a negative wolfCrypt error.
 */
static int der_extensions_content(C509Dec* d, DerBuf* out)
{
    int ret = 0;
    word32 count = 0;
    word32 i;

    if ((d->idx < d->len) &&
            (((d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) == C509_CBOR_UINT) ||
             ((d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) == C509_CBOR_NINT))) {
        /* Compact form: a lone KeyUsage int whose sign encodes criticality. */
        sword32 v = 0;

        if (c509_dec_int(d, &v) != 0) {
            ret = ASN_PARSE_E;
        }
        else {
            int crit = (v < 0);

            ret = der_ext_ku(out, crit ? -v : v, crit);
        }
    }
    else if (c509_dec_array(d, &count) != 0) {
        ret = ASN_PARSE_E;
    }
    else if ((count % 2) != 0) {
        ret = ASN_PARSE_E;
    }
    else {
        for (i = 0; (ret == 0) && (i < count); i += 2) {
            ret = der_extension(d, out);
        }
    }
    return ret;
}

/* Reconstruct the DER Extensions [3] EXPLICIT SEQUENCE from the C509 extensions
 * array (array[2*N] of (type, value); a registered type is an int codepoint,
 * negative when critical, and an unregistered type is the ~oid bytes). Each
 * extension is emitted by its handler into an accumulator, then wrapped as
 * SEQUENCE and [3] EXPLICIT into out.
 *
 * @param [in, out] d    Decoder cursor, positioned at the extensions array.
 * @param [in, out] out  Accumulator receiving the DER Extensions [3] EXPLICIT.
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed array.
 * @return  NOT_COMPILED_IN for an unsupported extension.
 * @return  BUFFER_E on overflow.
 */
static int der_extensions(C509Dec* d, DerBuf* out)
{
    int ret;
    word32 start = d->idx;
    word32 contentLen;
    DerBuf m;

    /* pass 1: measure the Extensions SEQUENCE content into a null sink. */
    db_init(&m, NULL, 0);
    ret = der_extensions_content(d, &m);
    if ((ret == 0) && (m.pos == 0)) {
        /* An empty C509 extensions array means "no extensions". RFC 5280
         * defines Extensions as SEQUENCE SIZE (1..MAX), so a certificate with
         * none omits the [3] field entirely; emitting [3] { SEQUENCE {} } would
         * be invalid DER and never match the signed TBS. The measure pass has
         * already advanced d past the empty array. */
        return 0;
    }
    if (ret == 0) {
        /* [3] EXPLICIT { SEQUENCE OF Extension } written straight into out -
         * no accumulator buffer; the content is re-decoded for the encode. */
        contentLen = m.pos;
        db_byte(out, C509_ASN_CONSTR_CTX(3));
        db_len(out, 1u + der_len_size(contentLen) + contentLen);
        db_byte(out, C509_ASN_SEQ);
        db_len(out, contentLen);
        d->idx = start;
        ret = der_extensions_content(d, out);
        if ((ret == 0) && !out->ok) {
            ret = BUFFER_E;
        }
    }
    return ret;
}

#endif /* WOLFSSL_C509_TYPE3 */

#ifdef C509_NEED_DER_BUILDER
/* Emit an INTEGER from a C509 ~biguint serial (prepend 0x00 if the high bit is
 * set so the value stays positive). Shared by type-3 reconstruction and the
 * type-2 ECDSA verify path.
 *
 * @param [in, out] b  Destination DerBuf.
 * @param [in]      s  Big-endian integer bytes.
 * @param [in]      n  Number of bytes in s.
 */
static void der_serial(DerBuf* b, const byte* s, word32 n)
{
    db_byte(b, ASN_INTEGER);
    if (n == 0) {
        /* A C509 ~biguint strips leading zeros, so serial 0 is the empty
         * string; DER requires a single 0x00 content byte (02 01 00), never a
         * zero-length INTEGER (02 00). der_int_minimal never passes n == 0. */
        db_len(b, 1);
        db_byte(b, 0x00);
    }
    else {
        if (s[0] & 0x80) {
            db_len(b, n + 1);
            db_byte(b, 0x00);
        }
        else {
            db_len(b, n);
        }
        db_raw(b, s, n);
    }
}

/* Emit a minimal DER INTEGER from a fixed-width big-endian value: strip leading
 * zero bytes (keeping at least one), then encode via der_serial (which prepends
 * 0x00 when the top bit is set). ECDSA r/s are carried in C509 as fixed-width
 * halves that may have leading zero bytes; DER requires the minimal form, and a
 * non-minimal INTEGER makes wc_ecc_verify_hash reject the signature.
 *
 * @param [in, out] b  Destination DerBuf.
 * @param [in]      s  Fixed-width big-endian integer bytes.
 * @param [in]      n  Number of bytes in s.
 */
static void der_int_minimal(DerBuf* b, const byte* s, word32 n)
{
    word32 i = 0;
    while ((i + 1 < n) && (s[i] == 0x00)) {
        i++;
    }
    der_serial(b, s + i, n - i);
}
#endif /* C509_NEED_DER_BUILDER */

#ifdef WOLFSSL_C509_TYPE3
/* Encode a raw ECDSA r||s (each half `half` bytes) as the DER signatureValue
 * BIT STRING { SEQUENCE { INTEGER r, INTEGER s } }. The buffers are sized for
 * the largest supported curve (P-521: two ~67-byte INTEGERs).
 *
 * @param [in, out] out   Accumulator receiving the signatureValue BIT STRING.
 * @param [in]      rs    Raw ECDSA signature (r||s).
 * @param [in]      half  Length of each of r and s.
 */
static void der_ecdsa_sig_bitstring(DerBuf* out, const byte* rs, word32 half)
{
    DerBuf m;
    word32 innerLen;
    word32 bitLen;

    /* Measure SEQUENCE { INTEGER r, INTEGER s } into a null sink: der_int_
     * minimal is pure over the raw bytes, so the lengths can be precomputed
     * and the TLVs written straight into `out` with no temporary buffer. */
    db_init(&m, NULL, 0);
    der_int_minimal(&m, rs, half);
    der_int_minimal(&m, rs + half, half);
    innerLen = m.pos;
    /* BIT STRING body = 0x00 unused-bit count + SEQUENCE TLV */
    bitLen = 1u + 1u + der_len_size(innerLen) + innerLen;

    db_byte(out, ASN_BIT_STRING); /* signatureValue BIT STRING */
    db_len(out, bitLen);
    db_byte(out, 0x00); /* 0 unused bits */
    db_byte(out, C509_ASN_SEQ); /* ECDSA-Sig-Value SEQUENCE */
    db_len(out, innerLen);
    der_int_minimal(out, rs, half);
    der_int_minimal(out, rs + half, half);
}

#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
/* Emit a SubjectPublicKeyInfo = SEQUENCE { AlgorithmIdentifier,
 * subjectPublicKey BIT STRING { 0x00 || key } }, where algDer is the fixed
 * AlgorithmIdentifier DER for the curve and key is the C509 uncompressed EC
 * point (0x04||X||Y). Lengths are precomputed so no temporary buffer is used.
 *
 * @param [in, out] out     Accumulator receiving the SubjectPublicKeyInfo.
 * @param [in]      algDer  Fixed AlgorithmIdentifier DER for the curve.
 * @param [in]      algLen  Length of algDer.
 * @param [in]      key     Uncompressed EC point (0x04||X||Y).
 * @param [in]      keyLen  Length of key.
 */
static void der_spki(DerBuf* out, const byte* algDer, word32 algLen,
    const byte* key, word32 keyLen)
{
    word32 bitLen = 1u + keyLen; /* leading 0x00 unused-bit count + key */
    word32 bitTlv = 1u + der_len_size(bitLen) + bitLen;
    word32 content = algLen + bitTlv;

    db_byte(out, C509_ASN_SEQ); /* SubjectPublicKeyInfo SEQUENCE */
    db_len(out, content);
    db_raw(out, algDer, algLen);
    db_byte(out, ASN_BIT_STRING); /* subjectPublicKey BIT STRING */
    db_len(out, bitLen);
    db_byte(out, 0x00); /* 0 unused bits */
    db_raw(out, key, keyLen);
}
#endif /* HAVE_ECC || HAVE_ED25519 || HAVE_ED448 */

#ifndef NO_RSA
/* Emit a SubjectPublicKeyInfo for an RSA key = SEQUENCE { AlgorithmIdentifier,
 * subjectPublicKey BIT STRING { 0x00 || RSAPublicKey } }, where RSAPublicKey is
 * SEQUENCE { INTEGER modulus, INTEGER exponent } rebuilt from the C509 modulus
 * and public exponent (65537 by default, or the value carried alongside the
 * modulus). algDer is the fixed rsaEncryption AlgorithmIdentifier. Lengths are
 * precomputed so no temporary buffer is used.
 *
 * @param [in, out] out     Accumulator receiving the SubjectPublicKeyInfo.
 * @param [in]      algDer  RsaEncryption AlgorithmIdentifier DER.
 * @param [in]      algLen  Length of algDer.
 * @param [in]      mod     RSA modulus (big-endian, as carried in the C509
 *                          key).
 * @param [in]      modLen  Length of mod.
 * @param [in]      exp     RSA public exponent (big-endian, minimal).
 * @param [in]      expLen  Length of exp.
 */
static void der_spki_rsa(DerBuf* out, const byte* algDer, word32 algLen,
    const byte* mod, word32 modLen, const byte* exp, word32 expLen)
{
    word32 modPad = ((modLen > 0) && (mod[0] & 0x80)) ? 1u : 0u;
    word32 expPad = ((expLen > 0) && (exp[0] & 0x80)) ? 1u : 0u;
    word32 modTlv = 1u + der_len_size(modLen + modPad) + modPad + modLen;
    word32 expTlv = 1u + der_len_size(expLen + expPad) + expPad + expLen;
    word32 rpkLen = modTlv + expTlv;               /* RSAPublicKey content    */
    word32 rpkTlv = 1u + der_len_size(rpkLen) + rpkLen;
    word32 bitLen = 1u + rpkTlv;                    /* 0x00 unused + RPK   */
    word32 bitTlv = 1u + der_len_size(bitLen) + bitLen;
    word32 content = algLen + bitTlv;

    db_byte(out, C509_ASN_SEQ); /* SubjectPublicKeyInfo SEQUENCE */
    db_len(out, content);
    db_raw(out, algDer, algLen);
    db_byte(out, ASN_BIT_STRING); /* subjectPublicKey BIT STRING */
    db_len(out, bitLen);
    db_byte(out, 0x00); /* 0 unused bits */
    db_byte(out, C509_ASN_SEQ); /* RSAPublicKey SEQUENCE */
    db_len(out, rpkLen);
    db_byte(out, ASN_INTEGER); /* INTEGER modulus */
    db_len(out, modLen + modPad);
    if (modPad) {
        db_byte(out, 0x00); /* keep the modulus positive */
    }
    db_raw(out, mod, modLen);
    db_byte(out, ASN_INTEGER); /* INTEGER exponent */
    db_len(out, expLen + expPad);
    if (expPad) {
        db_byte(out, 0x00); /* keep the exponent positive */
    }
    db_raw(out, exp, expLen);
}
#endif /* !NO_RSA */

/* Emit a raw signatureValue BIT STRING { 0x00 || sig } for the non-ECDSA
 * signature algorithms (RSA, Ed25519/Ed448), whose C509 signature bytes are the
 * BIT STRING content verbatim.
 *
 * @param [in, out] out     Accumulator receiving the signatureValue BIT STRING.
 * @param [in]      sig     Raw signature bytes.
 * @param [in]      sigLen  Length of sig.
 */
static void der_raw_sig_bitstring(DerBuf* out, const byte* sig, word32 sigLen)
{
    db_byte(out, ASN_BIT_STRING); /* signatureValue BIT STRING */
    db_len(out, 1u + sigLen);
    db_byte(out, 0x00); /* 0 unused bits */
    db_raw(out, sig, sigLen);
}

/* Whether a C509 signature codepoint is an ECDSA algorithm (whose signature is
 * a raw r||s pair re-encoded as a DER ECDSA-Sig-Value); the RSA and Edwards
 * codepoints instead carry the signatureValue BIT STRING content verbatim.
 *
 * @param [in] sigAlg  C509 signature codepoint.
 *
 * @return  Non-zero for an ECDSA/SHAKE codepoint.
 * @return  0 otherwise.
 */
static int c509_sig_is_ecdsa(sword32 sigAlg)
{
    return (sigAlg == C509_SIG_ES256) || (sigAlg == C509_SIG_ES384) ||
           (sigAlg == C509_SIG_ES512) || (sigAlg == C509_SIG_ES_SHAKE128) ||
           (sigAlg == C509_SIG_ES_SHAKE256);
}
#endif /* WOLFSSL_C509_TYPE3 */

#ifdef C509_HAVE_EC_DECOMPRESS
/* Decompress a C509 compressed EC point into the uncompressed SEC1 form
 * 0x04||X||Y. C509 encodes the y-coordinate sign in the leading byte: 0xfe for
 * an even y (SEC1 0x02) or 0xfd for odd (SEC1 0x03), followed by the
 * x-coordinate. Shared by wc_C509_GetPubKey and type-3 reconstruction.
 *
 * @param [in]      comp     C509 compressed point (leading 0xfe/0xfd || X).
 * @param [in]      compLen  Length of comp.
 * @param [in]      curveId  WolfCrypt curve id of the point.
 * @param [out]     out      Buffer receiving the uncompressed point
 *                           (0x04||X||Y).
 * @param [in, out] outLen   In: capacity of out; out: uncompressed length
 *                           written.
 * @param [in]      heap     Heap hint for the scratch key (may be NULL).
 *
 * @return  0 on success.
 * @return  ASN_UNKNOWN_OID_E for a malformed leading byte, or a negative
 *          wolfCrypt error.
 */
static int c509_ec_decompress(const byte* comp, word32 compLen, int curveId,
    byte* out, word32* outLen, void* heap)
{
    byte    sec1[1 + 66]; /* SEC1 compressed point: tag + x (<= P-521 66) */
    int     ret;
    /* Heap-allocate the key under WOLFSSL_SMALL_STACK rather than stacking a
     * multi-KB ecc_key (the whole wolfCrypt convention); with SMALL_STACK off
     * the stock types.h WC_DECLARE_VAR keeps it on the stack. */
    WC_DECLARE_VAR(ecc, ecc_key, 1, heap);

    WC_ALLOC_VAR_EX(ecc, ecc_key, 1, heap, DYNAMIC_TYPE_ECC, (void)0);
    if (!WC_VAR_OK(ecc)) {
        ret = MEMORY_E;
    }
    else if ((compLen < 2u) || (compLen > (word32)sizeof(sec1)) ||
            ((comp[0] != 0xfe) && (comp[0] != 0xfd) &&
             (comp[0] != 0x02) && (comp[0] != 0x03))) {
        ret = ASN_UNKNOWN_OID_E;
    }
    /* EC point decompression is a public-key, local operation, so it is never
     * routed to a crypto-callback device: pass INVALID_DEVID, not the caller's
     * devId (the heap still comes from the caller for static-memory pools). */
    else if ((ret = wc_ecc_init_ex(ecc, heap, INVALID_DEVID)) != 0) {
        /* Pass the init return through rather than flattening to MEMORY_E: it
         * is usually MEMORY_E, but a static-memory pool can report a different
         * code, and the caller's error classes are kept distinct. */
    }
    else {
        /* draft-ietf-cose-cbor-encoded-cert Section 3.2.1: a native C509 key
         * uses the SECG octets 0x02/0x03 directly; 0xfe/0xfd are the type-3
         * markers for an X.509 SPKI that was compressed during CBOR encoding,
         * where 0xfe is even (0x02) and 0xfd is odd (0x03). Pass a SECG octet
         * through unchanged; map the type-3 marker to its SECG octet. */
        if ((comp[0] == 0x02) || (comp[0] == 0x03)) {
            sec1[0] = comp[0];
        }
        else {
            sec1[0] = (comp[0] == 0xfe) ? 0x02 : 0x03; /* even : odd */
        }
        XMEMCPY(sec1 + 1, comp + 1, compLen - 1u);
        ret = wc_ecc_import_x963_ex(sec1, compLen, ecc, curveId);
        if (ret == 0) {
            ret = wc_ecc_export_x963(ecc, out, outLen); /* 0x04||X||Y */
        }
        wc_ecc_free(ecc);
    }
    WC_FREE_VAR_EX(ecc, heap, DYNAMIC_TYPE_ECC);
    return ret;
}
#endif /* C509_HAVE_EC_DECOMPRESS */

#ifdef WOLFSSL_C509_TYPE3
#ifdef C509_HAVE_EC_DECOMPRESS
/* Map a C509 subjectPublicKeyAlgorithm codepoint to its wolfCrypt curve id, for
 * decompressing an EC point during type-3 reconstruction.
 *
 * @param [in]  spkAlg   SubjectPublicKeyAlgorithm codepoint (a C509_PK_*
 *                       value).
 * @param [out] curveId  Receives the wolfCrypt curve id.
 *
 * @return  0 on a supported curve.
 * @return  NOT_COMPILED_IN otherwise.
 */
static int c509_pk_curve(sword32 spkAlg, int* curveId)
{
    int ret = 0;

    switch (spkAlg) {
        case C509_PK_P256:  *curveId = ECC_SECP256R1;       break;
        case C509_PK_P384:  *curveId = ECC_SECP384R1;       break;
        case C509_PK_P521:  *curveId = ECC_SECP521R1;       break;
        case C509_PK_BP256: *curveId = ECC_BRAINPOOLP256R1; break;
        case C509_PK_BP384: *curveId = ECC_BRAINPOOLP384R1; break;
        case C509_PK_BP512: *curveId = ECC_BRAINPOOLP512R1; break;
        default: ret = NOT_COMPILED_IN;
    }
    return ret;
}
#endif /* C509_HAVE_EC_DECOMPRESS */

/* Parse the subjectPublicKeyAlgorithm codepoint and subjectPublicKey byte
 * string from d, look up the SPKI AlgorithmIdentifier DER, and resolve the SEC1
 * point to emit in the reconstruction: an uncompressed point (0x04||X||Y) is
 * used in place, while a C509 compressed point is flagged via compCurveId for
 * der_spki_ecc_compressed to expand straight into the output (needs HAVE_ECC +
 * HAVE_COMP_KEY).
 *
 * @param [in, out] d           Decoder cursor, positioned at
 *                              subjectPublicKeyAlgorithm.
 * @param [out]     compCurveId Receives the wolfCrypt curve id when the key is
 *                              a compressed EC point needing decompression,
 *                              else -1.
 * @param [out]     spkiE       Receives the SPKI AlgorithmIdentifier table
 *                              entry.
 * @param [out]     spkiKey     Receives a pointer to the key bytes to emit (an
 *                              EC point, an Edwards raw key, or an RSA
 *                              modulus).
 * @param [out]     spkiKeyLen  Receives the length of *spkiKey.
 * @param [out]     spkiExp     Receives the RSA public exponent bytes (65537 by
 *                              default, or the value carried in a [modulus,
 *                              exponent] key); unused for non-RSA keys.
 * @param [out]     spkiExpLen  Receives the length of *spkiExp.
 * @param [out]     spkAlgOut   Receives the decoded subjectPublicKeyAlgorithm
 *                              codepoint (a C509_PK_* value; RSA is emitted via
 *                              der_spki_rsa).
 *
 * @return  0 on success.
 * @return  ASN_PARSE_E on a malformed field.
 * @return  NOT_COMPILED_IN for an unsupported curve or point encoding.
 */
static int c509_type3_pubkey(C509Dec* d, int* compCurveId,
    const C509DerAlg** spkiE, const byte** spkiKey, word32* spkiKeyLen,
    const byte** spkiExp, word32* spkiExpLen, sword32* spkAlgOut)
{
#ifndef NO_RSA
    static const byte defExp[] = { 0x01, 0x00, 0x01 }; /* default 65537 */
#endif
    int ret = 0;
    const byte* key = NULL;
    word32 keyLen = 0;
    sword32 spkAlg = 0;
    word32 spkiN = (word32)(sizeof(C509_SPKIALG_TABLE) /
        sizeof(C509_SPKIALG_TABLE[0]));

#ifdef NO_RSA
    /* The RSA exponent outputs are written only by the RSA branches below,
     * which are compiled out when RSA is disabled. */
    (void)spkiExp;
    (void)spkiExpLen;
#endif
#if !defined(HAVE_ECC) && defined(NO_RSA) && !defined(HAVE_ED25519) && \
    !defined(HAVE_ED448)
    /* No PK algorithm: the key out-params are never written (-Werror guard). */
    (void)spkiKey;
    (void)spkiKeyLen;
#endif
    *compCurveId = -1; /* set by the compressed-EC branch when applicable */
    if ((ret = c509_dec_alg_or_oid(d, &spkAlg)) != 0) {
        /* NOT_COMPILED_IN for a ~oid / [~oid, params] subjectPublicKeyAlgorithm
         * (a legal but out-of-profile form), else ASN_PARSE_E (malformed). */
    }
    else if ((*spkiE = c509_der_alg_find(C509_SPKIALG_TABLE, spkiN,
            spkAlg)) == NULL) {
        ret = NOT_COMPILED_IN;
    }
#ifndef NO_RSA
    else if ((spkAlg == C509_PK_RSA) && (d->idx < d->len) &&
            ((d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) == C509_CBOR_ARRAY)) {
        /* RSA with a non-default public exponent: subjectPublicKey is the array
         * [modulus, exponent]. */
        word32 cnt = 0;

        if ((c509_dec_array(d, &cnt) != 0) || (cnt != 2u) ||
                (c509_dec_str(d, C509_CBOR_BSTR, &key, &keyLen) != 0) ||
                (c509_dec_str(d, C509_CBOR_BSTR, spkiExp, spkiExpLen) != 0)) {
            ret = ASN_PARSE_E;
        }
        else {
            *spkiKey = key;
            *spkiKeyLen = keyLen;
        }
    }
#endif /* !NO_RSA */
    else if (c509_dec_str(d, C509_CBOR_BSTR, &key, &keyLen) != 0) {
        ret = ASN_PARSE_E;
    }
#ifndef NO_RSA
    else if (spkAlg == C509_PK_RSA) {
        /* RSA modulus with the default public exponent 65537. */
        *spkiKey = key;
        *spkiKeyLen = keyLen;
        *spkiExp = defExp;
        *spkiExpLen = (word32)sizeof(defExp);
    }
#endif /* !NO_RSA */
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if ((spkAlg == C509_PK_ED25519) || (spkAlg == C509_PK_ED448)) {
        /* Edwards: the raw key is emitted directly in the SPKI BIT STRING. */
        *spkiKey = key;
        *spkiKeyLen = keyLen;
    }
#endif
#ifdef HAVE_ECC
    else if ((keyLen >= 1u) &&
            ((key[0] == 0x04) || (key[0] == 0x02) || (key[0] == 0x03))) {
        /* 0x04 is an uncompressed SEC1 point; draft Section 3.2.1 keeps a SECG
         * compressed point (0x02/0x03) from the original X.509 SPKI verbatim,
         * so both forms are emitted into the reconstructed DER unchanged (only
         * the 0xfe/0xfd markers below mean "the original was uncompressed, C509
         * compressed it" and need decompression). */
        *spkiKey = key;
        *spkiKeyLen = keyLen;
    }
#endif
#ifdef C509_HAVE_EC_DECOMPRESS
    else if ((keyLen >= 2u) && ((key[0] == 0xfe) || (key[0] == 0xfd))) {
        /* Compressed point: keep the C509 bytes and the curve id, and let
         * der_spki_ecc_compressed decompress to the uncompressed SEC1 form the
         * original DER carries (byte-exact) straight into the output buffer. */
        int curveId = 0;

        if (c509_pk_curve(spkAlg, &curveId) != 0) {
            ret = NOT_COMPILED_IN;
        }
        else {
            *spkiKey = key;
            *spkiKeyLen = keyLen;
            *compCurveId = curveId;
        }
    }
#endif
    else {
        ret = NOT_COMPILED_IN; /* unsupported point encoding */
    }
    *spkAlgOut = spkAlg;
    return ret;
}

/* Build the Validity SEQUENCE into vb: notBefore, then notAfter as a time or,
 * when noExpiry is set (a C509 null notAfter), the RFC 5280 no-expiry
 * GeneralizedTime 99991231235959Z. Each bound is a UTCTime or GeneralizedTime
 * chosen by its year (see der_time).
 *
 * @param [in, out] vb         Destination DerBuf (already initialised over its
 *                             buffer).
 * @param [in]      notBefore  Validity start as Unix seconds.
 * @param [in]      notAfter   Validity end as Unix seconds (ignored when
 *                             noExpiry).
 * @param [in]      noExpiry   Non-zero to emit the no-expiry notAfter.
 *
 * @return  0 on success.
 * @return  BUFFER_E on overflow.
 */
static int c509_type3_validity(DerBuf* vb, word32 notBefore, word32 notAfter,
    int noExpiry)
{
    int ret = 0;
    DerBuf m;
    word32 innerLen;

    /* Measure the two time TLVs into a null sink (der_time is pure over the
     * epoch inputs), then emit the Validity SEQUENCE straight into vb. */
    db_init(&m, NULL, 0);
    ret = der_time(&m, notBefore);
    if ((ret == 0) && !noExpiry) {
        ret = der_time(&m, notAfter);
    }
    else if (ret == 0) {
        der_time_no_expiry(&m);
    }
    if (ret == 0) {
        innerLen = m.pos;
        db_byte(vb, C509_ASN_SEQ); /* Validity SEQUENCE */
        db_len(vb, innerLen);
        ret = der_time(vb, notBefore);
        if ((ret == 0) && !noExpiry) {
            ret = der_time(vb, notAfter);
        }
        else if (ret == 0) {
            der_time_no_expiry(vb);
        }
    }
    return ret;
}

#ifdef C509_HAVE_EC_DECOMPRESS
/* Emit an EC SubjectPublicKeyInfo for a C509 compressed point, decompressing
 * the SEC1 point straight into out rather than into a scratch buffer. The
 * uncompressed length is 2*compLen - 1 (a compressed point is prefix||X, an
 * uncompressed point 0x04||X||Y), known before decompression, so the SPKI and
 * BIT STRING lengths are precomputed; a measuring pass (out->buf == NULL)
 * reserves that length without decompressing.
 *
 * @param [in, out] out      Accumulator receiving the SubjectPublicKeyInfo.
 * @param [in]      algDer   Fixed AlgorithmIdentifier DER for the curve.
 * @param [in]      algLen   Length of algDer.
 * @param [in]      comp     C509 compressed point (0xfe/0xfd || X).
 * @param [in]      compLen  Length of comp.
 * @param [in]      curveId  wolfCrypt curve id for the decompression.
 * @param [in]      heap     Heap hint for the decompression key (may be NULL).
 *
 * @return  0 on success, or a negative wolfCrypt error.
 */
static int der_spki_ecc_compressed(DerBuf* out, const byte* algDer,
    word32 algLen, const byte* comp, word32 compLen, int curveId, void* heap)
{
    int ret = 0;
    word32 uncLen = 2u * compLen - 1u; /* 0x04 || X || Y */
    word32 bitLen = 1u + uncLen;       /* 0x00 unused-bit count + point */
    word32 content = algLen + 1u + der_len_size(bitLen) + bitLen;

    db_byte(out, C509_ASN_SEQ); /* SubjectPublicKeyInfo SEQUENCE */
    db_len(out, content);
    db_raw(out, algDer, algLen);
    db_byte(out, ASN_BIT_STRING); /* subjectPublicKey BIT STRING */
    db_len(out, bitLen);
    db_byte(out, 0x00); /* 0 unused bits */
    if (out->buf == NULL) {
        out->pos += uncLen; /* measuring sink: reserve the point length */
    }
    else if (out->ok && (out->pos + uncLen <= out->cap)) {
        word32 dl = uncLen;

        ret = c509_ec_decompress(comp, compLen, curveId, out->buf + out->pos,
            &dl, heap);
        if ((ret == 0) && (dl != uncLen)) {
            ret = ASN_PARSE_E; /* decompressed to an unexpected length */
        }
        if (ret == 0) {
            out->pos += uncLen;
        }
    }
    else {
        out->ok = 0;        /* would overflow the output buffer */
        out->pos += uncLen;
    }
    return ret;
}
#endif /* C509_HAVE_EC_DECOMPRESS */

/* Emit the DER signatureValue for a C509 signature into out: a re-encoded
 * ECDSA-Sig-Value for a raw r||s pair, else the raw signature in a BIT STRING.
 *
 * @param [in, out] out      Destination DerBuf.
 * @param [in]      isEcdsa  Non-zero for a raw ECDSA r||s pair.
 * @param [in]      sig      Raw signature bytes.
 * @param [in]      sigLen   Length of sig.
 */
static void der_sig_value(DerBuf* out, int isEcdsa, const byte* sig,
    word32 sigLen)
{
    if (isEcdsa) {
        der_ecdsa_sig_bitstring(out, sig, sigLen / 2u);
    }
    else {
        der_raw_sig_bitstring(out, sig, sigLen);
    }
}

/* Emit the SubjectPublicKeyInfo for the already-resolved subject public key.
 *
 * @param [in, out] out      Destination DerBuf.
 * @param [in]      spkiE    SPKI AlgorithmIdentifier table entry.
 * @param [in]      spkiAlg  subjectPublicKeyAlgorithm codepoint.
 * @param [in]      key      Key bytes to emit.
 * @param [in]      keyLen   Length of key.
 * @param [in]      exp      RSA public exponent (RSA only).
 * @param [in]      expLen   Length of exp.
 */
static void der_spki_emit(DerBuf* out, const C509DerAlg* spkiE, sword32 spkiAlg,
    const byte* key, word32 keyLen, const byte* exp, word32 expLen)
{
#ifndef NO_RSA
    if (spkiAlg == C509_PK_RSA) {
        der_spki_rsa(out, spkiE->der, spkiE->derLen, key, keyLen, exp, expLen);
    }
    else
#endif
    {
#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
        der_spki(out, spkiE->der, spkiE->derLen, key, keyLen);
#else
        (void)spkiE; (void)key; (void)keyLen;
#endif
        /* else: no non-RSA key type compiled - unreachable, the SPKI lookup
         * already rejected it (NOT_COMPILED_IN). */
    }
    (void)spkiAlg; (void)exp; (void)expLen;
#if defined(NO_RSA) && !defined(HAVE_ECC) && !defined(HAVE_ED25519) && \
    !defined(HAVE_ED448)
    /* No PK algorithm compiled in (a PQ-only build): neither branch above
     * writes to out, so void it to avoid -Werror=unused-parameter. This
     * matches the empty-table sentinel in C509_SPKIALG_TABLE - every lookup
     * resolves to NOT_COMPILED_IN, so der_spki_emit is never actually run. */
    (void)out;
#endif
}

/* Emit the TBSCertificate body (everything inside the TBS SEQUENCE: version,
 * serialNumber, signature, issuer, validity, subject, SPKI and extensions) into
 * out, decoding issuer/subject/SPKI/extensions from d. No component is held in
 * its own buffer - each der_* routine writes straight into out, sizing any
 * nested SEQUENCE with its own internal measure pass. This routine is itself
 * re-runnable from a saved cursor (a pure forward parse), so the caller runs it
 * once into a null sink to learn the body length, then again into the real
 * buffer, keeping only one large buffer (the caller's out) live.
 *
 * d must be positioned at the issuer element (just past serialNumber and
 * signatureAlgorithm, which the caller has already consumed). On return d is
 * positioned at the signatureValue.
 *
 * @param [in, out] d          Decoder cursor (at the issuer element).
 * @param [in, out] out        Destination DerBuf for the TBS body.
 * @param [in]      serial     serialNumber bytes.
 * @param [in]      serialLen  Length of serial.
 * @param [in]      sigAlgE    signature AlgorithmIdentifier table entry.
 * @param [in]      heap       Heap hint for the EC point-decompression key
 *                             (used only for a compressed SPKI; may be NULL).
 * @return  0 on success, or a negative wolfCrypt error.
 */
static int der_tbs_body(C509Dec* d, DerBuf* out, const byte* serial,
    word32 serialLen, const C509DerAlg* sigAlgE, void* heap)
{
    int ret;
    int issuerNull = 0;
    int noExpiry = 0;
    word32 nb = 0;
    word32 na = 0;
    const C509DerAlg* spkiE = NULL;
    const byte* spkiKey = NULL;
    const byte* spkiExp = NULL;
    word32 spkiKeyLen = 0;
    word32 spkiExpLen = 0;
    sword32 spkiAlg = 0;
    int compCurveId = -1; /* >=0 => a compressed EC point to decompress */

    /* heap feeds the EC point decompression only; a build without
     * C509_HAVE_EC_DECOMPRESS never uses it. */
    (void)heap;

    db_raw(out, DER_VERSION_V3, (word32)sizeof(DER_VERSION_V3)); /* [0] v3 */
    der_serial(out, serial, serialLen);                  /* serialNumber     */
    db_raw(out, sigAlgE->der, sigAlgE->derLen);          /* signature AlgId  */

    /* issuer: a CBOR null means self-signed (issuer == subject). The subject
     * element follows the validity bounds, so skip the bounds to decode it as
     * the issuer, then rewind so the shared code below re-reads the bounds and
     * the subject at their own positions. */
    ret = der_name_from_c509(d, out, 1, &issuerNull);
    if ((ret == 0) && issuerNull) {
        word32 afterIssuer = d->idx;
        if ((ret = c509_dec_validity(d, &nb)) != 0) {
            /* classified: NOT_COMPILED_IN (out of profile) or ASN_PARSE_E */
        }
        else if ((d->idx < d->len) && (d->buf[d->idx] == 0xf6)) {
            d->idx++; /* no-expiry notAfter */
        }
        else if ((ret = c509_dec_validity(d, &na)) != 0) {
            /* classified */
        }
        if (ret == 0) {
            ret = der_name_from_c509(d, out, 0, NULL); /* issuer := subject */
        }
        d->idx = afterIssuer;
    }
    /* validity bounds */
    if (ret == 0) {
        if ((ret = c509_dec_validity(d, &nb)) != 0) {
            /* notBefore required; c509_dec_validity classifies the code */
        }
        else if ((d->idx < d->len) && (d->buf[d->idx] == 0xf6)) {
            d->idx++; /* CBOR null notAfter = RFC 5280 no-expiry date */
            noExpiry = 1;
        }
        else if ((ret = c509_dec_validity(d, &na)) != 0) {
            /* classified */
        }
    }
    if (ret == 0) {
        ret = c509_type3_validity(out, nb, na, noExpiry);
    }
    /* subject */
    if (ret == 0) {
        ret = der_name_from_c509(d, out, 0, NULL);
    }
    /* subjectPublicKeyInfo */
    if (ret == 0) {
        ret = c509_type3_pubkey(d, &compCurveId, &spkiE, &spkiKey, &spkiKeyLen,
            &spkiExp, &spkiExpLen, &spkiAlg);
    }
    if (ret == 0) {
#ifdef C509_HAVE_EC_DECOMPRESS
        if (compCurveId >= 0) {
            ret = der_spki_ecc_compressed(out, spkiE->der, spkiE->derLen,
                spkiKey, spkiKeyLen, compCurveId, heap);
        }
        else
#endif
        {
            der_spki_emit(out, spkiE, spkiAlg, spkiKey, spkiKeyLen, spkiExp,
                spkiExpLen);
        }
        if (ret == 0) {
            ret = der_extensions(d, out); /* [3] extensions */
        }
    }
    if ((ret == 0) && !out->ok) {
        ret = BUFFER_E;
    }
    return ret;
}

/* Reconstruct the full DER X.509 certificate from a type-3 C509 into out. The
 * decoder d is positioned just after c509CertificateType (index 1). The
 * reconstruction covers the ECDSA (NIST and brainpool), RSA and Ed25519 / Ed448
 * subject public keys / signature algorithms in C509_SPKIALG_TABLE and
 * C509_SIGALG_TABLE, plus the commonName / multi-attribute name forms, UTCTime
 * / GeneralizedTime (and no-expiry) validity, and the SKI/KeyUsage/
 * BasicConstraints/EKU/SAN extensions; anything else yields NOT_COMPILED_IN.
 * The optional out-params expose pieces the
 * self-contained verify path needs (all may be NULL): sigOut/sigLenOut = the
 * raw signature (points into the C509 input), tbsOff/tbsLenOut = the
 * reconstructed TBSCertificate's offset and length within out, and sigAlgOut =
 * the C509 signature codepoint (so the caller can pick the verify algorithm).
 *
 * @param [in, out] d          Decoder cursor, positioned after
 *                             c509CertificateType.
 * @param [out]     out        Destination certificate buffer.
 * @param [in]      cap        Capacity of out.
 * @param [out]     outLen     Receives the reconstructed certificate length.
 * @param [out]     sigOut     Optional; receives the raw signature (may be
 *                             NULL).
 * @param [out]     sigLenOut  Optional; receives the signature length (may be
 *                             NULL).
 * @param [out]     tbsOff     Optional; receives the TBS offset within out (may
 *                             be NULL).
 * @param [out]     tbsLenOut  Optional; receives the TBS length (may be NULL).
 * @param [out]     sigAlgOut  Optional; receives the signature codepoint (may
 *                             be NULL).
 * @param [in]      heap       Heap hint for the EC point-decompression key
 *                             (used only for a compressed SPKI; may be NULL).
 *
 * @return  0 on success, or a negative wolfCrypt error (ASN_PARSE_E, BUFFER_E,
 *          MEMORY_E, or NOT_COMPILED_IN for an out-of-profile field).
 */
static int c509_type3_build_cert(C509Dec* d, byte* out, word32 cap,
    word32* outLen, const byte** sigOut, word32* sigLenOut, word32* tbsOff,
    word32* tbsLenOut, sword32* sigAlgOut, void* heap)
{
    int ret = 0;
    const byte* serial = NULL;
    const byte* sig = NULL;
    word32 serialLen = 0;
    word32 sigLen = 0;
    sword32 sigAlg = 0;
    int isEcdsa = 0;
    const C509DerAlg* sigAlgE = NULL;
    word32 sigAlgN = (word32)(sizeof(C509_SIGALG_TABLE) /
        sizeof(C509_SIGALG_TABLE[0]));
    word32 bodyStart = 0;
    word32 bodyLen = 0;
    /* ---- serialNumber + signatureAlgorithm (consumed before the body) ----
     * This is the first step, so it runs unconditionally (a bare block, not a
     * redundant `if (ret == 0)`); every later step is guarded on ret. */
    {
        int serMajor = (d->idx < d->len) ?
            (int)(d->buf[d->idx] >> C509_CBOR_MAJOR_SHIFT) : -1;
        if ((serMajor == C509_CBOR_UINT) || (serMajor == C509_CBOR_NINT)) {
            ret = NOT_COMPILED_IN; /* integer-form serial: out of profile */
        }
        else if (c509_dec_str(d, C509_CBOR_BSTR, &serial, &serialLen) != 0) {
            ret = ASN_PARSE_E; /* truncated / ill-formed serialNumber */
        }
        else if ((ret = c509_dec_alg_or_oid(d, &sigAlg)) != 0) {
            /* NOT_COMPILED_IN for a ~oid sigAlg, else ASN_PARSE_E */
        }
        else if ((sigAlgE = c509_der_alg_find(C509_SIGALG_TABLE, sigAlgN,
                sigAlg)) == NULL) {
            ret = NOT_COMPILED_IN;
        }
        else {
            isEcdsa = c509_sig_is_ecdsa(sigAlg);
            if (sigAlgOut != NULL) {
                *sigAlgOut = sigAlg;
            }
        }
    }
    /* ---- pass 1: measure the TBS body (null sink, nothing written) ---- */
    if (ret == 0) {
        DerBuf m;
        bodyStart = d->idx;
        db_init(&m, NULL, 0);
        ret = der_tbs_body(d, &m, serial, serialLen, sigAlgE, heap);
        bodyLen = m.pos;
    }
    /* ---- signatureValue (the cursor is now positioned at it) ---- */
    if (ret == 0) {
        if (c509_dec_str(d, C509_CBOR_BSTR, &sig, &sigLen) != 0) {
            ret = ASN_PARSE_E;
        }
        else if (sigLen == 0u) {
            ret = ASN_PARSE_E; /* a zero-length signature is malformed */
        }
        else if (isEcdsa && ((sigLen % 2u) != 0u)) {
            /* ECDSA raw r||s must be an even length (the der_sig_value split is
             * sigLen / 2u); an odd length is a malformed encoding. */
            ret = ASN_PARSE_E;
        }
    }
    /* ---- pass 2: emit the Certificate, encoding the body straight into out,
     * the only large buffer live for the whole reconstruction ---- */
    if (ret == 0) {
        DerBuf sm;
        DerBuf inner;
        word32 tbsLen, sigValLen, certLen, tbsPos;

        tbsLen = 1u + der_len_size(bodyLen) + bodyLen; /* TBS SEQ + body */
        db_init(&sm, NULL, 0);
        der_sig_value(&sm, isEcdsa, sig, sigLen); /* measure signatureValue */
        sigValLen = sm.pos;
        certLen = tbsLen + sigAlgE->derLen + sigValLen;

        db_init(&inner, out, cap);
        db_byte(&inner, C509_ASN_SEQ);          /* Certificate SEQUENCE */
        db_len(&inner, certLen);
        tbsPos = inner.pos;                      /* TBSCertificate start */
        db_byte(&inner, C509_ASN_SEQ);          /* TBSCertificate SEQUENCE */
        db_len(&inner, bodyLen);
        d->idx = bodyStart;                      /* rewind; encode body */
        ret = der_tbs_body(d, &inner, serial, serialLen, sigAlgE, heap);
        if (ret == 0) {
            db_raw(&inner, sigAlgE->der, sigAlgE->derLen); /* sig AlgId */
            der_sig_value(&inner, isEcdsa, sig, sigLen);   /* signatureValue */
            if (!inner.ok) {
                ret = BUFFER_E;
            }
            else {
                *outLen = inner.pos;
                if (tbsOff != NULL) {
                    *tbsOff = tbsPos;
                }
                if (tbsLenOut != NULL) {
                    *tbsLenOut = tbsLen;
                }
                if (sigOut != NULL) {
                    *sigOut = sig;
                }
                if (sigLenOut != NULL) {
                    *sigLenOut = sigLen;
                }
            }
        }
    }

    return ret;
}
#endif /* WOLFSSL_C509_TYPE3 */

/* ==================================================================== *
 *  Public API
 * ==================================================================== */

#ifdef C509_HAVE_EC_DECOMPRESS
/* Decompress a C509 compressed EC point of the given wc_C509_KeyType into the
 * X||Y coordinate pair written to out.
 *
 * @param [in]      key     C509 compressed point (leading 0xfe/0xfd || X).
 * @param [in]      keyLen  Length of key.
 * @param [in]      ktVal   The wc_C509_KeyType selecting the curve.
 * @param [out]     out     Buffer receiving the X||Y coordinate pair.
 * @param [in, out] outLen  In: capacity of out; out: length written.
 * @param [in]      heap    Heap hint for the decompression key (may be NULL).
 *
 * @return  0 on success.
 * @return  ASN_UNKNOWN_OID_E for an unsupported key type.
 * @return  BUFFER_E if out is too small, or MEMORY_E.
 */
static int c509_ec_pubkey_decompress(const byte* key, word32 keyLen, int ktVal,
    byte* out, word32* outLen, void* heap)
{
    int ret = 0;
    int curveId = 0;
    word32 uncLen = C509_MAX_EC_POINT;
    WC_DECLARE_VAR(uncBuf, byte, C509_MAX_EC_POINT, heap); /* 0x04||X||Y */

    WC_ALLOC_VAR_EX(uncBuf, byte, C509_MAX_EC_POINT, heap,
        DYNAMIC_TYPE_TMP_BUFFER, (void)0);
    if (!WC_VAR_OK(uncBuf)) {
        ret = MEMORY_E;
    }
    else {
        switch (ktVal) {
            case WC_C509_KEY_P256:  curveId = ECC_SECP256R1;       break;
            case WC_C509_KEY_P384:  curveId = ECC_SECP384R1;       break;
            case WC_C509_KEY_P521:  curveId = ECC_SECP521R1;       break;
            case WC_C509_KEY_BP256: curveId = ECC_BRAINPOOLP256R1; break;
            case WC_C509_KEY_BP384: curveId = ECC_BRAINPOOLP384R1; break;
            case WC_C509_KEY_BP512: curveId = ECC_BRAINPOOLP512R1; break;
            default: ret = ASN_UNKNOWN_OID_E;
        }
    }
    if (ret == 0) {
        ret = c509_ec_decompress(key, keyLen, curveId, uncBuf, &uncLen, heap);
    }
    if (ret == 0) {
        if (*outLen < uncLen - 1u) {
            ret = BUFFER_E;
        }
        else {
            XMEMCPY(out, uncBuf + 1, uncLen - 1u);
            *outLen = uncLen - 1u;
        }
    }
    WC_FREE_VAR_EX(uncBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* C509_HAVE_EC_DECOMPRESS */

#ifdef HAVE_ECC
/* Return the raw X||Y coordinate pair from a C509 EC subjectPublicKey. An
 * uncompressed point (0x04||X||Y, pointLen bytes) is returned with the 0x04
 * stripped; a compressed point (SECG 0x02/0x03 or the C509 type-3 marker
 * 0xfe even / 0xfd odd, || X) is decompressed on the key's curve (needs
 * HAVE_ECC + HAVE_COMP_KEY). pointLen is the uncompressed length, ktVal the
 * wc_C509_KeyType to report.
 *
 * @param [out]     out       Buffer receiving the X||Y coordinate pair.
 * @param [in, out] outLen    In: capacity of out; out: length written.
 * @param [out]     keyType   Optional; receives ktVal (may be NULL).
 * @param [in]      key       C509 subjectPublicKey bytes (point).
 * @param [in]      keyLen    Length of key.
 * @param [in]      pointLen  The uncompressed point length for this curve.
 * @param [in]      ktVal     The wc_C509_KeyType to report.
 * @param [in]      heap      Heap hint for point decompression (may be NULL).
 *
 * @return  0 on success.
 * @return  ASN_UNKNOWN_OID_E for an unsupported point form, or BUFFER_E if out
 *          is too small.
 */
static int c509_ec_pubkey(byte* out, word32* outLen, int* keyType,
    const byte* key, word32 keyLen, word32 pointLen, int ktVal, void* heap)
{
    int ret = 0;
    word32 coordLen = (pointLen - 1u) / 2u; /* one coordinate's length */

    /* heap feeds point decompression only; an uncompressed-only build
     * (no C509_HAVE_EC_DECOMPRESS) never uses it. */
    (void)heap;

    if ((keyLen == pointLen) && (key[0] == 0x04)) {
        if (*outLen < pointLen - 1u) {
            ret = BUFFER_E;
        }
        else {
            XMEMCPY(out, key + 1, pointLen - 1u);
            *outLen = pointLen - 1u;
        }
    }
#ifdef C509_HAVE_EC_DECOMPRESS
    /* draft Section 3.2.1: a native C509 key carries a SECG compressed point
     * (0x02 even / 0x03 odd || X); 0xfe/0xfd are the type-3 markers for an
     * uncompressed X.509 point that was compressed during CBOR encoding. Accept
     * all four leading octets so a spec-conformant compressed key is usable. */
    else if ((keyLen == coordLen + 1u) &&
            ((key[0] == 0xfe) || (key[0] == 0xfd) ||
             (key[0] == 0x02) || (key[0] == 0x03))) {
        ret = c509_ec_pubkey_decompress(key, keyLen, ktVal, out, outLen, heap);
    }
#endif
    else {
        ret = ASN_UNKNOWN_OID_E;
    }
    if ((ret == 0) && (keyType != NULL)) {
        *keyType = ktVal;
    }
    (void)coordLen;
    return ret;
}
#endif /* HAVE_ECC */

#if defined(HAVE_ED25519) || defined(HAVE_ED448) || !defined(NO_RSA)
/* Copy a raw (Edwards / RSA-field) public key verbatim.
 *
 * @param [out]     out      Buffer receiving the key.
 * @param [in, out] outLen   In: capacity of out; out: length written.
 * @param [out]     keyType  Optional; receives ktVal (may be NULL).
 * @param [in]      key      Key bytes to copy.
 * @param [in]      keyLen   Length of key.
 * @param [in]      ktVal    The wc_C509_KeyType to report.
 *
 * @return  0 on success.
 * @return  BUFFER_E if out is too small.
 */
static int c509_raw_pubkey(byte* out, word32* outLen, int* keyType,
    const byte* key, word32 keyLen, int ktVal)
{
    if (*outLen < keyLen) {
        return BUFFER_E;
    }
    XMEMCPY(out, key, keyLen);
    *outLen = keyLen;
    if (keyType != NULL) {
        *keyType = ktVal;
    }
    return 0;
}
#endif /* HAVE_ED25519 || HAVE_ED448 || !NO_RSA */

/* Emit subject public key for a decoded subjectPublicKeyAlgorithm codepoint.
 * Edwards keys are raw; Weierstrass EC keys are SECG uncompressed (or C509
 * compressed) points returned as X||Y; the RSA subjectPublicKey field is
 * returned verbatim. Brainpool curves share point sizes with the NIST curves,
 * so the algorithm codepoint - not the length - selects the curve.
 *
 * @param [in]      spkAlg   SubjectPublicKeyAlgorithm codepoint (a C509_PK_*
 *                           value).
 * @param [out]     out      Buffer receiving the raw key (X||Y for EC keys).
 * @param [in, out] outLen   In: capacity of out; out: key length written.
 * @param [out]     keyType  Optional; receives the wc_C509_KeyType (may be
 *                           NULL).
 * @param [in]      key      The C509 subjectPublicKey bytes.
 * @param [in]      keyLen   Length of key.
 * @param [in]      heap     Heap hint for the EC point-decompression key (used
 *                           only for a compressed point; may be NULL).
 *
 * @return  0 on success.
 * @return  BUFFER_E if out is too small.
 * @return  ASN_UNKNOWN_OID_E for an unsupported algorithm or point form.
 */
static int c509_pubkey_by_alg(sword32 spkAlg, byte* out, word32* outLen,
    int* keyType, const byte* key, word32 keyLen, void* heap)
{
    /* heap feeds EC point decompression only; it is unused for raw (Ed/RSA)
     * keys and uncompressed EC points. */
    (void)heap;
#if !defined(HAVE_ECC) && defined(NO_RSA) && !defined(HAVE_ED25519) && \
    !defined(HAVE_ED448)
    /* No public-key algorithm compiled in: every case below is gated out, so
     * the parameters are unused (-Werror guard for a PQ-only build). */
    (void)out; (void)outLen; (void)keyType; (void)key; (void)keyLen;
#endif
    switch (spkAlg) {
#ifdef HAVE_ED25519
        case C509_PK_ED25519:
            return (keyLen == C509_ED25519_PUB)
                ? c509_raw_pubkey(out, outLen, keyType, key, keyLen,
                    WC_C509_KEY_ED25519)
                : ASN_UNKNOWN_OID_E;
#endif
#ifdef HAVE_ED448
        case C509_PK_ED448:
            return (keyLen == C509_ED448_PUB)
                ? c509_raw_pubkey(out, outLen, keyType, key, keyLen,
                    WC_C509_KEY_ED448)
                : ASN_UNKNOWN_OID_E;
#endif
#ifdef HAVE_ECC
        case C509_PK_P256:
            return c509_ec_pubkey(out, outLen, keyType, key, keyLen,
                C509_P256_POINT, WC_C509_KEY_P256, heap);
        case C509_PK_P384:
            return c509_ec_pubkey(out, outLen, keyType, key, keyLen,
                C509_P384_POINT, WC_C509_KEY_P384, heap);
        case C509_PK_P521:
            return c509_ec_pubkey(out, outLen, keyType, key, keyLen,
                C509_P521_POINT, WC_C509_KEY_P521, heap);
#ifdef HAVE_ECC_BRAINPOOL
        case C509_PK_BP256:
            return c509_ec_pubkey(out, outLen, keyType, key, keyLen,
                C509_P256_POINT, WC_C509_KEY_BP256, heap);
        case C509_PK_BP384:
            return c509_ec_pubkey(out, outLen, keyType, key, keyLen,
                C509_P384_POINT, WC_C509_KEY_BP384, heap);
        case C509_PK_BP512:
            return c509_ec_pubkey(out, outLen, keyType, key, keyLen,
                C509_BP512_POINT, WC_C509_KEY_BP512, heap);
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* HAVE_ECC */
#ifndef NO_RSA
        case C509_PK_RSA:
            return c509_raw_pubkey(out, outLen, keyType, key, keyLen,
                WC_C509_KEY_RSA);
#endif
        default:
            return ASN_UNKNOWN_OID_E; /* unsupported subject-public-key alg */
    }
}

/* Extract the subject public key from a C509 certificate as raw bytes and
 * report its wc_C509_KeyType. Public API; see wolfssl/wolfcrypt/c509.h for the
 * full contract.
 *
 * @param [in]      c509     C509 certificate bytes.
 * @param [in]      c509Sz   Length of c509.
 * @param [out]     out      Buffer receiving the raw subject public key.
 * @param [in, out] outLen   In: capacity of out; out: key length written.
 * @param [out]     keyType  Optional; receives the wc_C509_KeyType (may be
 *                           NULL).
 * @param [in]      heap     Heap hint for the EC point-decompression key (used
 *                           only for a compressed point; may be NULL).
 *
 * @return  0 on success, or a negative wolfCrypt error (BAD_FUNC_ARG,
 *          ASN_PARSE_E, BUFFER_E, or ASN_UNKNOWN_OID_E).
 */
static int c509_get_pubkey_core(const byte* c509, word32 c509Sz, byte* out,
    word32* outLen, int* keyType, void* heap)
{
    C509Dec dec;
    const byte* key;
    word32 count;
    word32 keyLen;
    word32 i;
    sword32 spkAlg;

    if ((c509 == NULL) || (c509Sz == 0) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* subjectPublicKeyAlgorithm is index 7, subjectPublicKey index 8; skip the
     * preceding seven fields opaquely. */
    c509_dec_init(&dec, c509, c509Sz);
    /* A C509 certificate is exactly an 11-element array. */
    if ((c509_dec_array(&dec, &count) != 0) || (count != 11)) {
        return ASN_PARSE_E;
    }
    for (i = 0; i < 7; i++) {
        if (c509_dec_skip(&dec) != 0) {
            return ASN_PARSE_E;
        }
    }
    /* The algorithm identifier is an int codepoint. The array form
     * [~oid, params] (and a bare ~oid byte string) is an unregistered,
     * OID-identified algorithm, which is unsupported here (ASN_UNKNOWN_OID_E) -
     * do not treat it as RSA. A truncated/ill-formed head is instead malformed
     * (ASN_PARSE_E): peek the major type to tell the two apart rather than
     * reporting a cut-off certificate as "OID-identified". */
    if (dec.idx < dec.len) {
        int algMajor = (int)(dec.buf[dec.idx] >> C509_CBOR_MAJOR_SHIFT);

        if ((algMajor == C509_CBOR_BSTR) || (algMajor == C509_CBOR_ARRAY)) {
            return ASN_UNKNOWN_OID_E; /* OID-identified (non-codepoint) alg */
        }
    }
    if (c509_dec_int(&dec, &spkAlg) != 0) {
        return ASN_PARSE_E; /* truncated or ill-formed algorithm head */
    }
    /* subjectPublicKey is a byte string, or - for RSA only - the array
     * [modulus, exponent] where the modulus is the reported key. */
#ifndef NO_RSA
    if ((spkAlg == C509_PK_RSA) && (dec.idx < dec.len) &&
            ((dec.buf[dec.idx] >> C509_CBOR_MAJOR_SHIFT) == C509_CBOR_ARRAY)) {
        static const byte e65537[] = { 0x01, 0x00, 0x01 };
        const byte* exp;
        word32 expLen;
        word32 cnt = 0;
        if ((c509_dec_array(&dec, &cnt) != 0) || (cnt != 2u) ||
                (c509_dec_str(&dec, C509_CBOR_BSTR, &key, &keyLen) != 0) ||
                (c509_dec_str(&dec, C509_CBOR_BSTR, &exp, &expLen) != 0)) {
            return ASN_PARSE_E;
        }
        /* The verifier assumes the default exponent 65537; a different one
         * would make a valid signature verify as forged, so report the key as
         * unsupported rather than silently dropping the exponent. */
        if ((expLen != (word32)sizeof(e65537)) ||
                (XMEMCMP(exp, e65537, sizeof(e65537)) != 0)) {
            return NOT_COMPILED_IN;
        }
    }
    else
#endif
    if (c509_dec_str(&dec, C509_CBOR_BSTR, &key, &keyLen) != 0) {
        return ASN_PARSE_E;
    }

    return c509_pubkey_by_alg(spkAlg, out, outLen, keyType, key, keyLen, heap);
}

/* Extract the subject public key from a C509 certificate as raw bytes and
 * report its wc_C509_KeyType. A thin wrapper over the shared core with the
 * default heap. Public API; see wolfssl/wolfcrypt/c509.h for the full contract.
 *
 * @param [in]      c509     C509 certificate bytes.
 * @param [in]      c509Sz   Length of c509.
 * @param [out]     out      Buffer receiving the raw subject public key.
 * @param [in, out] outLen   In: capacity of out; out: key length written.
 * @param [out]     keyType  Optional; receives the wc_C509_KeyType (may be
 *                           NULL).
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG if c509, out or outLen is NULL, or c509Sz is 0.
 * @return  ASN_PARSE_E on a malformed certificate.
 * @return  BUFFER_E if out is too small, ASN_UNKNOWN_OID_E for an unsupported
 *          algorithm / point form, or NOT_COMPILED_IN for a non-65537 RSA
 *          exponent.
 */
int wc_C509_GetPubKey(const byte* c509, word32 c509Sz, byte* out,
    word32* outLen, int* keyType)
{
    return c509_get_pubkey_core(c509, c509Sz, out, outLen, keyType, NULL);
}

/* Like wc_C509_GetPubKey but with a heap hint for the internal EC
 * point-decompression key, so a compressed-point extraction can draw from a
 * static-memory pool. There is no devId: the only crypto here is public-point
 * decompression, which is never routed to a crypto-callback device.
 * wc_C509_GetPubKey is this call with heap == NULL. Public API; see
 * wolfssl/wolfcrypt/c509.h for the full contract.
 *
 * @param [in]      c509     C509 certificate bytes.
 * @param [in]      c509Sz   Length of c509.
 * @param [out]     out      Buffer receiving the raw subject public key.
 * @param [in, out] outLen   In: capacity of out; out: key length written.
 * @param [out]     keyType  Optional; receives the wc_C509_KeyType (may be
 *                           NULL).
 * @param [in]      heap     Heap hint for the decompression key (may be NULL).
 *
 * @return  Same as wc_C509_GetPubKey.
 */
int wc_C509_GetPubKeyEx(const byte* c509, word32 c509Sz, byte* out,
    word32* outLen, int* keyType, void* heap)
{
    return c509_get_pubkey_core(c509, c509Sz, out, outLen, keyType, heap);
}

/* Reconstruct the DER X.509 certificate from a type-3 C509. Public API; see
 * wolfssl/wolfcrypt/c509.h for the full contract.
 *
 * @param [in]      c509    C509 certificate bytes (type 3).
 * @param [in]      c509Sz  Length of c509.
 * @param [out]     out     Buffer receiving the reconstructed DER certificate,
 *                          or NULL to query the required length only.
 * @param [in, out] outLen  When out is non-NULL, in: capacity of out, out: DER
 *                          length written. When out is NULL, out: required DER
 *                          length (and the call returns LENGTH_ONLY_E).
 *
 * @return  0 on success (out non-NULL).
 * @return  LENGTH_ONLY_E when out is NULL, with *outLen set to the required
 *          length (the wolfSSL size-query convention).
 * @return  BAD_FUNC_ARG for a non-type-3 certificate (or NULL c509/outLen,
 *          zero c509Sz), ASN_PARSE_E, BUFFER_E, or NOT_COMPILED_IN - including
 *          when type-3 support is compiled out.
 */
int wc_C509_ToDer(const byte* c509, word32 c509Sz, byte* out, word32* outLen)
{
#ifdef WOLFSSL_C509_TYPE3
    C509Dec dec;
    word32 count;
    sword32 certType;
    word32 derLen = 0;
    int rc;
    /* out == NULL is a length query: build into a counting sink (capacity 0)
     * so *outLen is set to the required length and LENGTH_ONLY_E is returned,
     * matching the other wolfSSL *ToDer size-query APIs. */
    word32 cap;

    if ((c509 == NULL) || (c509Sz == 0) || (outLen == NULL)) {
        /* Clear a valid output buffer here too, so the "on any error the output
         * is cleared and *outLen = 0" contract holds uniformly (out/outLen may
         * be NULL on this path, so guard each). */
        if ((out != NULL) && (outLen != NULL)) {
            XMEMSET(out, 0, *outLen);
        }
        if (outLen != NULL) {
            *outLen = 0;
        }
        return BAD_FUNC_ARG;
    }
    cap = (out != NULL) ? *outLen : 0u;
    c509_dec_init(&dec, c509, c509Sz);
    /* Route every failure - including these early structural rejections -
     * through the single clear-on-error block below, so the documented
     * "output cleared, *outLen = 0 on any error" contract holds uniformly
     * (an early return here used to leave the caller's *outLen untouched). */
    if ((c509_dec_array(&dec, &count) != 0) || (count != 11)) {
        rc = ASN_PARSE_E;
    }
    else if (c509_dec_int(&dec, &certType) != 0) {
        rc = ASN_PARSE_E;
    }
    else if (certType != 3) {
        rc = BAD_FUNC_ARG; /* only type 3 has a DER equivalent */
    }
    else {
        rc = c509_type3_build_cert(&dec, out, cap, &derLen, NULL, NULL,
            NULL, NULL, NULL, NULL);
        /* Reconstruction stops at the signatureValue element; skip it and
         * require the 11-element array to end at the input end (no trailing
         * bytes). */
        if ((rc == 0) &&
                ((c509_dec_skip(&dec) != 0) || (dec.idx != dec.len))) {
            rc = ASN_PARSE_E;
        }
    }
    if (rc != 0) {
        /* Never leave a partially written certificate the caller might mistake
         * for a complete DER: clear the buffer and report zero length. The
         * reconstructed cert is not secret and `out` escapes to the caller, so
         * a plain XMEMSET is correct and (unlike wc_ForceZero) is available in
         * every build, including WOLFSSL_NO_FORCE_ZERO. (A length query passes
         * out == NULL, so there is nothing to clear.) */
        if (out != NULL) {
            XMEMSET(out, 0, cap);
        }
        *outLen = 0;
        return rc;
    }
    *outLen = derLen;
    return (out == NULL) ? LENGTH_ONLY_E : 0;
#else
    (void)c509;
    (void)c509Sz;
    /* Same clear-on-error contract when type-3 is compiled out. */
    if ((out != NULL) && (outLen != NULL)) {
        XMEMSET(out, 0, *outLen);
    }
    if (outLen != NULL) {
        *outLen = 0;
    }
    return NOT_COMPILED_IN; /* type-3 reconstruction compiled out */
#endif
}

#ifdef C509_HAVE_ECDSA_VERIFY
/* Verify a raw ECDSA signature (r||s, xyLen bytes) over a hash with a raw EC
 * public key (X||Y, xyLen bytes) on the given curve. Shared by the type-2 and
 * (capability-less) type-3 verify paths.
 *
 * @param [in] pubXY      Raw EC public key as X||Y.
 * @param [in] xyLen      Length of pubXY (also the expected raw signature
 *                        length).
 * @param [in] rawSig     Raw ECDSA signature (r||s).
 * @param [in] rawSigLen  Length of rawSig.
 * @param [in] hash       Message hash to verify against.
 * @param [in] hashLen    Length of hash.
 * @param [in] curveId    WolfCrypt curve id of the key.
 * @param [in] heap       Heap hint for the verify key (may be NULL).
 * @param [in] devId      Device id for the verify key.
 *
 * @return  0 if valid.
 * @return  ASN_SIG_CONFIRM_E if not, or a negative wolfCrypt error.
 */
static int c509_ecdsa_verify_raw(const byte* pubXY, word32 xyLen,
    const byte* rawSig, word32 rawSigLen, const byte* hash, word32 hashLen,
    int curveId, void* heap, int devId)
{
    DerBuf  sb;
    DerBuf  isb;
    word32  half = xyLen / 2;
    int     ret = 0;
    int     verified = 0;
    int     eccInit = 0;
    WC_DECLARE_VAR(der, byte, C509_ECDSA_SIG_DER, heap);
    WC_DECLARE_VAR(inner, byte, C509_ECDSA_SIG_INNER, heap);
    WC_DECLARE_VAR(ecc, ecc_key, 1, heap);

    WC_ALLOC_VAR_EX(der, byte, C509_ECDSA_SIG_DER, heap,
        DYNAMIC_TYPE_TMP_BUFFER, (void)0);
    WC_ALLOC_VAR_EX(inner, byte, C509_ECDSA_SIG_INNER, heap,
        DYNAMIC_TYPE_TMP_BUFFER, (void)0);
    WC_ALLOC_VAR_EX(ecc, ecc_key, 1, heap, DYNAMIC_TYPE_ECC, (void)0);
    if (!WC_VAR_OK(der) || !WC_VAR_OK(inner) || !WC_VAR_OK(ecc)) {
        ret = MEMORY_E;
    }
    else if (rawSigLen != xyLen) {
        /* draft Section "Encoding of issuerSignatureValue": ECDSA signatures
         * are encoded as in RFC 9053 Section 2.1 - each of r and s padded to
         * the fixed per-curve coordinate width (e.g. 32 bytes for P-256), so a
         * conformant r||s is exactly 2*coordLen = xyLen. A shorter r||s (as the
         * cose-wg demo encoder emits by stripping leading zeros) is NOT spec
         * conformant and is rejected here, both to follow the spec and to fix
         * the r||s encoding (no leading-zero / length variation). Note this
         * does not make ECDSA non-malleable: (r, s) and (r, n-s) both verify,
         * so the signature value is not unique at the algebra level. */
        ret = ASN_PARSE_E;
    }
    else {
        /* r||s -> DER ECDSA-Sig-Value SEQUENCE { INTEGER r, INTEGER s };
         * der_int_minimal restores each minimal DER INTEGER (stripping the
         * fixed-width pad zeros, adding one back when the top bit is set). */
        db_init(&sb, der, C509_ECDSA_SIG_DER);
        db_init(&isb, inner, C509_ECDSA_SIG_INNER);
        der_int_minimal(&isb, rawSig, half);
        der_int_minimal(&isb, rawSig + half, half);
        db_wrap(&sb, C509_ASN_SEQ, &isb);
        if (!sb.ok) {
            ret = BUFFER_E;
        }
        else if ((ret = wc_ecc_init_ex(ecc, heap, devId)) != 0) {
            /* Pass the init return through (a devId crypto-callback device can
             * fail with its own code, not MEMORY_E). */
        }
        else {
            eccInit = 1;
            ret = wc_ecc_import_unsigned(ecc, pubXY, pubXY + half, NULL,
                curveId);
            if (ret == 0) {
                ret = wc_ecc_verify_hash(der, sb.pos, hash, hashLen, &verified,
                    ecc);
            }
        }
    }
    if (eccInit) {
        wc_ecc_free(ecc);
    }
    if (ret == 0) {
        ret = verified ? 0 : ASN_SIG_CONFIRM_E;
    }
    WC_FREE_VAR_EX(ecc, heap, DYNAMIC_TYPE_ECC);
    WC_FREE_VAR_EX(inner, heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(der, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Map a wc_C509_KeyType EC key type to its wolfCrypt curve id and raw X||Y
 * coordinate length. Used whenever the curve must come from the issuer key
 * type rather than the signature codepoint: the ecdsa-with-SHAKE codepoints
 * (hash size fixed by RFC 8692), and the SHA codepoints when the caller gave
 * an explicit EC keyType (so a non-default curve/hash pairing, e.g. a P-384
 * key signing with ES256, verifies).
 *
 * @param [in]  keyType  Issuer wc_C509_KeyType (an EC key type).
 * @param [out] curveId  Receives the wolfCrypt curve id.
 * @param [out] xyLen    Receives the raw X||Y coordinate length.
 *
 * @return  0 on a supported EC key type.
 * @return  NOT_COMPILED_IN otherwise.
 */
static int c509_keytype_curve(int keyType, int* curveId, word32* xyLen)
{
    switch (keyType) {
        case WC_C509_KEY_P256:
            *curveId = ECC_SECP256R1;       *xyLen = C509_P256_XY;  return 0;
        case WC_C509_KEY_BP256:
            *curveId = ECC_BRAINPOOLP256R1; *xyLen = C509_P256_XY;  return 0;
        case WC_C509_KEY_P384:
            *curveId = ECC_SECP384R1;       *xyLen = C509_P384_XY;  return 0;
        case WC_C509_KEY_BP384:
            *curveId = ECC_BRAINPOOLP384R1; *xyLen = C509_P384_XY;  return 0;
        case WC_C509_KEY_P521:
            *curveId = ECC_SECP521R1;       *xyLen = C509_P521_XY;  return 0;
        case WC_C509_KEY_BP512:
            *curveId = ECC_BRAINPOOLP512R1; *xyLen = C509_BP512_XY; return 0;
        default:
            return NOT_COMPILED_IN; /* not a supported EC key type */
    }
}

/* Map an ECDSA C509 signature codepoint plus an (optional) key-type hint to the
 * hash to run (type and digest length) plus the wolfCrypt curve id and the raw
 * X||Y coordinate length. For the SHA codepoints a brainpool key-type overrides
 * the default NIST curve of the same strength (the codepoint fixes only the
 * hash; NIST and brainpool are wire-identical). For the SHAKE codepoints the
 * hash length is fixed by RFC 8692 and the curve comes wholly from the key
 * type.
 *
 * @param [in]  sigAlg    C509 ECDSA signature codepoint.
 * @param [in]  keyType   Issuer wc_C509_KeyType hint (or WC_C509_KEY_UNKNOWN).
 * @param [out] curveId   Receives the wolfCrypt curve id.
 * @param [out] xyLen     Receives the raw X||Y coordinate length.
 * @param [out] hashType  Receives the wc_HashType to run.
 * @param [out] hashLen   Receives the digest length.
 *
 * @return  0 on a supported combination.
 * @return  NOT_COMPILED_IN otherwise.
 */
static int c509_ecdsa_params(sword32 sigAlg, int keyType, int* curveId,
    word32* xyLen, int* hashType, word32* hashLen)
{
    switch (sigAlg) {
    #ifndef NO_SHA256
        case C509_SIG_ES256:
            *hashType = (int)WC_HASH_TYPE_SHA256;
            *hashLen = WC_SHA256_DIGEST_SIZE;
            /* An explicit EC keyType fixes the curve (so a non-default
             * curve/hash pairing verifies); only infer the curve from the
             * codepoint when the key type is UNKNOWN. */
            if (keyType != WC_C509_KEY_UNKNOWN) {
                return c509_keytype_curve(keyType, curveId, xyLen);
            }
            *xyLen = C509_P256_XY;
            *curveId = ECC_SECP256R1;
            return 0;
    #endif
    #ifdef WOLFSSL_SHA384
        case C509_SIG_ES384:
            *hashType = (int)WC_HASH_TYPE_SHA384;
            *hashLen = WC_SHA384_DIGEST_SIZE;
            if (keyType != WC_C509_KEY_UNKNOWN) {
                return c509_keytype_curve(keyType, curveId, xyLen);
            }
            *xyLen = C509_P384_XY;
            *curveId = ECC_SECP384R1;
            return 0;
    #endif
    #ifdef WOLFSSL_SHA512
        case C509_SIG_ES512:
            *hashType = (int)WC_HASH_TYPE_SHA512;
            *hashLen = WC_SHA512_DIGEST_SIZE;
            if (keyType != WC_C509_KEY_UNKNOWN) {
                return c509_keytype_curve(keyType, curveId, xyLen);
            }
            /* UNKNOWN: default to secp521r1 (132-byte X||Y). */
            *xyLen = C509_P521_XY;
            *curveId = ECC_SECP521R1;
            return 0;
    #endif
    #ifdef WOLFSSL_SHAKE128
        case C509_SIG_ES_SHAKE128:
            /* RFC 8692: ecdsa-with-SHAKE128 hashes to 256 bits. The SHAKE
             * codepoints carry no default curve, so an inferred (UNKNOWN) key
             * type cannot name one: refuse with BAD_FUNC_ARG - the same "must
             * call wc_C509_VerifyEx with the key type" signal the inferred-RSA
             * path gives - rather than NOT_COMPILED_IN, which means "SHAKE not
             * built" and would hide the retry-with-VerifyEx remedy. */
            if (keyType == WC_C509_KEY_UNKNOWN) {
                return BAD_FUNC_ARG;
            }
            *hashType = (int)WC_HASH_TYPE_SHAKE128;
            *hashLen = 32;
            return c509_keytype_curve(keyType, curveId, xyLen);
    #endif
    #ifdef WOLFSSL_SHAKE256
        case C509_SIG_ES_SHAKE256:
            /* RFC 8692: ecdsa-with-SHAKE256 hashes to 512 bits. UNKNOWN key
             * type: BAD_FUNC_ARG, as for SHAKE128 above. */
            if (keyType == WC_C509_KEY_UNKNOWN) {
                return BAD_FUNC_ARG;
            }
            *hashType = (int)WC_HASH_TYPE_SHAKE256;
            *hashLen = 64;
            return c509_keytype_curve(keyType, curveId, xyLen);
    #endif
        default:
            return NOT_COMPILED_IN;
    }
}
#endif /* C509_HAVE_ECDSA_VERIFY */

#ifndef NO_RSA
/* The exact bit length of an RSA modulus: its significant-byte length (leading
 * zero octets removed, matching wc_RsaPublicKeyDecodeRaw, which reads with
 * mp_read_unsigned_bin and drops leading zeros) refined to the bit width of the
 * top nonzero byte. The floor WC_C509_RSA_MIN_BITS is specified in bits, so it
 * is enforced on this exact bit count rather than a byte count - a modulus a
 * few bits short of the floor (e.g. a 128-byte modulus whose top byte is 0x01,
 * 1017 bits, against a 1024-bit floor) is rejected, not just one a whole byte
 * short. Stripping leading zeros also stops a zero-padded small modulus (e.g.
 * 64 zero bytes then a 512-bit value) from slipping past the check below.
 *
 * @param [in] mod    Raw RSA modulus bytes.
 * @param [in] modSz  Length of mod.
 *
 * @return  The modulus width in bits (0 for an all-zero / empty modulus).
 */
static word32 c509_rsa_eff_mod_bits(const byte* mod, word32 modSz)
{
    word32 eff = modSz;
    word32 bits;
    byte   top;

    while ((eff > 0u) && (mod[modSz - eff] == 0x00)) {
        eff--;
    }
    if (eff == 0u) {
        return 0u;
    }
    top = mod[modSz - eff];
    bits = (eff - 1u) * 8u;
    while (top != 0u) {
        bits++;
        top = (byte)(top >> 1);
    }
    return bits;
}

/* Verify an RSA C509 signature (PKCS#1 v1.5 for codepoints 23/24/25, RSASSA-PSS
 * with MGF1 and salt length equal to the hash for 26/27/28) over a TBS. The
 * issuer key is the raw RSA modulus as returned by wc_C509_GetPubKey; the
 * public exponent is the C509 default of 65537 (a certificate carrying a
 * non-default exponent is not verifiable from the modulus alone).
 *
 * @param [in] sigAlg  C509 RSA signature codepoint.
 * @param [in] tbs     TBSCertificate bytes to verify.
 * @param [in] tbsLen  Length of tbs.
 * @param [in] sig     RSA signature.
 * @param [in] sigLen  Length of sig.
 * @param [in] mod     Raw RSA modulus (issuer public key).
 * @param [in] modSz   Length of mod.
 * @param [in] heap    Heap hint for the verify key and scratch buffers (may be
 *                     NULL).
 * @param [in] devId   Device id for the verify key.
 *
 * @return  0 on a valid signature.
 * @return  ASN_SIG_CONFIRM_E on a bad one, or a negative wolfCrypt error
 *          (NOT_COMPILED_IN, BUFFER_E, MEMORY_E).
 */
static int c509_verify_rsa(sword32 sigAlg, const byte* tbs, word32 tbsLen,
    const byte* sig, word32 sigLen, const byte* mod, word32 modSz, void* heap,
    int devId)
{
    static const byte e65537[] = { 0x01, 0x00, 0x01 };
    byte   hash[WC_MAX_DIGEST_SIZE];
    word32 hashLen = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int    hashOID = 0;
    int    mgf = 0;
    int    isPss = 0;
    int    ret = 0;
    int    rsaInit = 0;
    WC_DECLARE_VAR(buf, byte, C509_RSA_RECOVER_BUF, heap); /* recovered msg  */
    WC_DECLARE_VAR(enc, byte, C509_DIGESTINFO_BUF, heap);
    WC_DECLARE_VAR(rsa, RsaKey, 1, heap);

    WC_ALLOC_VAR_EX(buf, byte, C509_RSA_RECOVER_BUF, heap,
        DYNAMIC_TYPE_TMP_BUFFER, (void)0);
    WC_ALLOC_VAR_EX(enc, byte, C509_DIGESTINFO_BUF, heap,
        DYNAMIC_TYPE_TMP_BUFFER, (void)0);
    WC_ALLOC_VAR_EX(rsa, RsaKey, 1, heap, DYNAMIC_TYPE_RSA, (void)0);
    if (!WC_VAR_OK(buf) || !WC_VAR_OK(enc) || !WC_VAR_OK(rsa)) {
        ret = MEMORY_E;
    }
    else if (c509_rsa_eff_mod_bits(mod, modSz) < (word32)WC_C509_RSA_MIN_BITS) {
        /* Reject an implausibly small modulus so a non-RSA key (e.g. a 64-byte
         * P-256 or 96-byte P-384 X||Y mistaken for a modulus) cannot be run
         * through RSA verify. The floor is WC_C509_RSA_MIN_BITS (1024 by
         * default - below the keygen RSA_MIN_SIZE of 2048 so a legitimate
         * smaller RSA issuer key is still accepted - raised by a hardened
         * build). It is measured as the exact modulus bit width with leading
         * zero octets stripped (see c509_rsa_eff_mod_bits), so neither a
         * zero-padded small modulus nor one a few bits short of the floor slips
         * past. */
        ret = BAD_FUNC_ARG;
    }
    else {
        switch (sigAlg) {
        #ifndef NO_SHA256
            case C509_SIG_RSA_SHA256:
            case C509_SIG_PSS_SHA256:
                ret = wc_Sha256Hash(tbs, tbsLen, hash);
                hashLen = WC_SHA256_DIGEST_SIZE;
                hashType = WC_HASH_TYPE_SHA256;
                hashOID = SHA256h;
                mgf = WC_MGF1SHA256;
                isPss = (sigAlg == C509_SIG_PSS_SHA256);
                break;
        #endif
        #ifdef WOLFSSL_SHA384
            case C509_SIG_RSA_SHA384:
            case C509_SIG_PSS_SHA384:
                ret = wc_Sha384Hash(tbs, tbsLen, hash);
                hashLen = WC_SHA384_DIGEST_SIZE;
                hashType = WC_HASH_TYPE_SHA384;
                hashOID = SHA384h;
                mgf = WC_MGF1SHA384;
                isPss = (sigAlg == C509_SIG_PSS_SHA384);
                break;
        #endif
        #ifdef WOLFSSL_SHA512
            case C509_SIG_RSA_SHA512:
            case C509_SIG_PSS_SHA512:
                ret = wc_Sha512Hash(tbs, tbsLen, hash);
                hashLen = WC_SHA512_DIGEST_SIZE;
                hashType = WC_HASH_TYPE_SHA512;
                hashOID = SHA512h;
                mgf = WC_MGF1SHA512;
                isPss = (sigAlg == C509_SIG_PSS_SHA512);
                break;
        #endif
            default:
                ret = NOT_COMPILED_IN;
        }
    }

    if (ret == 0) {
        if ((ret = wc_InitRsaKey_ex(rsa, heap, devId)) != 0) {
            /* Pass the init return through (a devId crypto-callback device can
             * fail with its own code, not MEMORY_E). */
        }
        else {
            rsaInit = 1;
            ret = wc_RsaPublicKeyDecodeRaw(mod, modSz, e65537,
                (word32)sizeof(e65537), rsa);
        }
    }
    if ((ret == 0) && isPss) {
    #ifdef WC_RSA_PSS
        /* Bound the signature by the recover buffer (RSA_MAX_SIZE/8) AND by the
         * documented WC_C509_MAX_DER signature cap: both are compile-time
         * constants, so this folds to the tighter one, and a build that lowers
         * WC_C509_MAX_DER to restrict accepted signatures is still honoured. */
        if ((sigLen > (word32)C509_RSA_RECOVER_BUF) ||
                (sigLen > (word32)WC_C509_MAX_DER)) {
            ret = BUFFER_E;
        }
        else {
            ret = wc_RsaPSS_VerifyCheck(sig, sigLen, buf,
                (word32)C509_RSA_RECOVER_BUF, hash, hashLen, hashType, mgf,
                rsa);
            if (ret > 0) {
                ret = 0;
            }
            else if ((ret == WC_NO_ERR_TRACE(SIG_VERIFY_E)) ||
                    (ret == WC_NO_ERR_TRACE(BAD_PADDING_E)) ||
                    (ret == WC_NO_ERR_TRACE(RSA_PAD_E)) ||
                    (ret == WC_NO_ERR_TRACE(PSS_SALTLEN_E))) {
                /* A tampered PSS signature can fail the salt-length check as
                 * well as the padding/verify checks; report every mismatch as
                 * the documented ASN_SIG_CONFIRM_E. */
                ret = ASN_SIG_CONFIRM_E; /* signature mismatch */
            }
            /* else: a resource/other wolfCrypt error passes through as-is */
        }
    #else
        (void)mgf;
        ret = NOT_COMPILED_IN;
    #endif
    }
    else if (ret == 0) {
        /* PKCS#1 v1.5: RSA-recover the DigestInfo and compare it to the
         * DigestInfo built over our own hash (the standard cert-verify idiom
         * -- avoids re-deriving padding). */
        int    decLen;
        word32 encLen;
        byte*  recovered = NULL;
        (void)hashType;
        (void)mgf;
        /* Bounded by the recover buffer and the documented WC_C509_MAX_DER cap
         * (see the PSS path above). */
        if ((sigLen > (word32)C509_RSA_RECOVER_BUF) ||
                (sigLen > (word32)WC_C509_MAX_DER)) {
            ret = BUFFER_E;
        }
        else {
            /* Recover the DigestInfo with the in-place verifier, which exists
             * in every RSA build (the non-inline wc_RsaSSL_Verify is absent
             * under WOLFSSL_RSA_VERIFY_INLINE). The signature is copied into
             * buf first because VerifyInline decrypts in place and points
             * `recovered` at the result within buf. */
            XMEMCPY(buf, sig, sigLen);
            decLen = wc_RsaSSL_VerifyInline(buf, sigLen, &recovered, rsa);
            if (decLen < 0) {
                /* Distinguish a padding/verify mismatch from a resource or
                 * argument error so the latter is not reported as a forgery. */
                if ((decLen == WC_NO_ERR_TRACE(SIG_VERIFY_E)) ||
                        (decLen == WC_NO_ERR_TRACE(BAD_PADDING_E)) ||
                        (decLen == WC_NO_ERR_TRACE(RSA_PAD_E))) {
                    ret = ASN_SIG_CONFIRM_E;
                }
                else {
                    ret = decLen;
                }
            }
            else {
                encLen = wc_EncodeSignature(enc, hash, hashLen, hashOID);
                if ((recovered != NULL) && ((word32)decLen == encLen) &&
                        (XMEMCMP(recovered, enc, encLen) == 0)) {
                    ret = 0;
                }
                else {
                    ret = ASN_SIG_CONFIRM_E;
                }
            }
        }
    }

    if (rsaInit) {
        wc_FreeRsaKey(rsa);
    }
    WC_FREE_VAR_EX(rsa, heap, DYNAMIC_TYPE_RSA);
    WC_FREE_VAR_EX(enc, heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(buf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* NO_RSA */

#ifdef C509_HAVE_ED25519_VERIFY
/* Verify a type-2 Ed25519 signature over the CBOR TBS.
 *
 * @param [in] sig          Ed25519 signature.
 * @param [in] sigLen       Length of sig.
 * @param [in] tbs          CBOR TBSCertificate bytes.
 * @param [in] tbsLen       Length of tbs.
 * @param [in] issuerPub    Raw Ed25519 issuer public key.
 * @param [in] issuerPubSz  Length of issuerPub.
 * @param [in] heap         Heap hint for the verify key (may be NULL).
 * @param [in] devId        Device id for the verify key.
 *
 * @return  0 if valid.
 * @return  ASN_SIG_CONFIRM_E if not, or a negative wolfCrypt error.
 */
static int c509_verify_ed25519(const byte* sig, word32 sigLen, const byte* tbs,
    word32 tbsLen, const byte* issuerPub, word32 issuerPubSz, void* heap,
    int devId)
{
    int ret;
    int verified = 0;
    WC_DECLARE_VAR(ed, ed25519_key, 1, heap);

    WC_ALLOC_VAR_EX(ed, ed25519_key, 1, heap, DYNAMIC_TYPE_ED25519, (void)0);
    if (!WC_VAR_OK(ed)) {
        ret = MEMORY_E;
    }
    else if (issuerPubSz != C509_ED25519_PUB) {
        ret = BAD_FUNC_ARG; /* wrong issuer key length: a caller argument */
    }
    else if (sigLen != C509_ED25519_SIG) {
        /* A wrong signatureValue length is malformed certificate data, not a
         * caller error - report ASN_PARSE_E, as the ECDSA path does. */
        ret = ASN_PARSE_E;
    }
    else if ((ret = wc_ed25519_init_ex(ed, heap, devId)) != 0) {
        /* Pass the init return through (a devId crypto-callback device can
         * fail with its own code, not MEMORY_E). */
    }
    else {
        ret = wc_ed25519_import_public(issuerPub, issuerPubSz, ed);
        if (ret == 0) {
            ret = wc_ed25519_verify_msg(sig, sigLen, tbs, tbsLen, &verified,
                ed);
        }
        wc_ed25519_free(ed);
        /* A signature mismatch surfaces as SIG_VERIFY_E from wolfCrypt; report
         * it as the documented ASN_SIG_CONFIRM_E so the API contract holds for
         * EdDSA as it does for the other algorithms. A real error is kept. */
        if ((ret == 0) || (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E))) {
            ret = verified ? 0 : ASN_SIG_CONFIRM_E;
        }
    }
    WC_FREE_VAR_EX(ed, heap, DYNAMIC_TYPE_ED25519);
    return ret;
}
#endif /* C509_HAVE_ED25519_VERIFY */

#ifdef C509_HAVE_ED448_VERIFY
/* Verify a type-2 Ed448 signature over the CBOR TBS.
 *
 * @param [in] sig          Ed448 signature.
 * @param [in] sigLen       Length of sig.
 * @param [in] tbs          CBOR TBSCertificate bytes.
 * @param [in] tbsLen       Length of tbs.
 * @param [in] issuerPub    Raw Ed448 issuer public key.
 * @param [in] issuerPubSz  Length of issuerPub.
 * @param [in] heap         Heap hint for the verify key (may be NULL).
 * @param [in] devId        Device id for the verify key.
 *
 * @return  0 if valid.
 * @return  ASN_SIG_CONFIRM_E if not, or a negative wolfCrypt error.
 */
static int c509_verify_ed448(const byte* sig, word32 sigLen, const byte* tbs,
    word32 tbsLen, const byte* issuerPub, word32 issuerPubSz, void* heap,
    int devId)
{
    int ret;
    int verified = 0;
    WC_DECLARE_VAR(ed, ed448_key, 1, heap);

    WC_ALLOC_VAR_EX(ed, ed448_key, 1, heap, DYNAMIC_TYPE_ED448, (void)0);
    if (!WC_VAR_OK(ed)) {
        ret = MEMORY_E;
    }
    else if (issuerPubSz != C509_ED448_PUB) {
        ret = BAD_FUNC_ARG; /* wrong issuer key length: a caller argument */
    }
    else if (sigLen != C509_ED448_SIG) {
        /* A wrong signatureValue length is malformed certificate data, not a
         * caller error - report ASN_PARSE_E, as the ECDSA path does. */
        ret = ASN_PARSE_E;
    }
    else if ((ret = wc_ed448_init_ex(ed, heap, devId)) != 0) {
        /* Pass the init return through (a devId crypto-callback device can
         * fail with its own code, not MEMORY_E). */
    }
    else {
        ret = wc_ed448_import_public(issuerPub, issuerPubSz, ed);
        if (ret == 0) {
            ret = wc_ed448_verify_msg(sig, sigLen, tbs, tbsLen, &verified, ed,
                NULL, 0);
        }
        wc_ed448_free(ed);
        /* Map a signature mismatch (SIG_VERIFY_E) to the documented
         * ASN_SIG_CONFIRM_E, as on the Ed25519 path; keep a real error. */
        if ((ret == 0) || (ret == WC_NO_ERR_TRACE(SIG_VERIFY_E))) {
            ret = verified ? 0 : ASN_SIG_CONFIRM_E;
        }
    }
    WC_FREE_VAR_EX(ed, heap, DYNAMIC_TYPE_ED448);
    return ret;
}
#endif /* C509_HAVE_ED448_VERIFY */

#ifdef C509_HAVE_ECDSA_VERIFY
/* Verify a type-2 ECDSA signature over the CBOR TBS. The codepoint fixes the
 * hash (SHA-2 for ES256/384/512, SHAKE per RFC 8692 for the SHAKE codepoints);
 * keyType selects a brainpool curve over the wire-identical NIST curve and, for
 * the SHAKE codepoints, supplies the curve wholly.
 *
 * @param [in] sigAlg       C509 ECDSA signature codepoint.
 * @param [in] keyType      Issuer wc_C509_KeyType hint (or
 *                          WC_C509_KEY_UNKNOWN).
 * @param [in] tbs          CBOR TBSCertificate bytes.
 * @param [in] tbsLen       Length of tbs.
 * @param [in] sig          Raw ECDSA signature (r||s).
 * @param [in] sigLen       Length of sig.
 * @param [in] issuerPub    Raw EC issuer public key (X||Y).
 * @param [in] issuerPubSz  Length of issuerPub.
 * @param [in] heap         Heap hint for the verify key (may be NULL).
 * @param [in] devId        Device id for the verify key.
 *
 * @return  0 if valid.
 * @return  ASN_SIG_CONFIRM_E if not, or a negative wolfCrypt error.
 */
static int c509_verify_ecdsa(sword32 sigAlg, int keyType, const byte* tbs,
    word32 tbsLen, const byte* sig, word32 sigLen, const byte* issuerPub,
    word32 issuerPubSz, void* heap, int devId)
{
    byte   hash[WC_MAX_DIGEST_SIZE];
    int    curveId = 0;
    word32 xyLen = 0;
    int    hashType = 0;
    word32 hashLen = 0;
    int    ret;

    /* Propagate the parameter-resolution code unchanged: NOT_COMPILED_IN for a
     * curve/hash not built, but BAD_FUNC_ARG for a SHAKE codepoint with an
     * inferred (UNKNOWN) key type - the caller must name the key type, the same
     * signal as inferred RSA (do not flatten it to NOT_COMPILED_IN). */
    ret = c509_ecdsa_params(sigAlg, keyType, &curveId, &xyLen, &hashType,
        &hashLen);
    if (ret != 0) {
        return ret;
    }
    if (issuerPubSz != xyLen) {
        return BAD_FUNC_ARG;
    }
#ifdef WOLFSSL_SHA384
    if (hashType == (int)WC_HASH_TYPE_SHA384) {
        ret = wc_Sha384Hash(tbs, tbsLen, hash);
    }
    else
#endif
#ifdef WOLFSSL_SHA512
    if (hashType == (int)WC_HASH_TYPE_SHA512) {
        ret = wc_Sha512Hash(tbs, tbsLen, hash);
    }
    else
#endif
#ifdef WOLFSSL_SHAKE128
    if (hashType == (int)WC_HASH_TYPE_SHAKE128) {
        ret = wc_Shake128Hash(tbs, tbsLen, hash, hashLen);
    }
    else
#endif
#ifdef WOLFSSL_SHAKE256
    if (hashType == (int)WC_HASH_TYPE_SHAKE256) {
        ret = wc_Shake256Hash(tbs, tbsLen, hash, hashLen);
    }
    else
#endif
#ifndef NO_SHA256
    if (hashType == (int)WC_HASH_TYPE_SHA256) {
        ret = wc_Sha256Hash(tbs, tbsLen, hash);
    }
    else
#endif
    {
        return NOT_COMPILED_IN; /* hash not compiled in for codepoint */
    }
    if (ret != 0) {
        return ret;
    }
    return c509_ecdsa_verify_raw(issuerPub, xyLen, sig, sigLen, hash, hashLen,
        curveId, heap, devId);
}
#endif /* C509_HAVE_ECDSA_VERIFY */

/* Signature-algorithm key families, used to bind the caller-supplied issuer
 * key type to the algorithm the (attacker-controlled) certificate names. */
#define C509_SIGFAM_NONE    0
#define C509_SIGFAM_ECDSA   1
#define C509_SIGFAM_ED25519 2
#define C509_SIGFAM_ED448   3
#define C509_SIGFAM_RSA     4

/* Return the key family a C509 signature-algorithm codepoint belongs to.
 *
 * @param [in] sigAlg  C509 issuerSignatureAlgorithm codepoint.
 *
 * @return  A C509_SIGFAM_* value (C509_SIGFAM_NONE for an unknown codepoint).
 */
static int c509_sig_family(sword32 sigAlg)
{
    if ((sigAlg >= C509_SIG_ES256) && (sigAlg <= C509_SIG_ES_SHAKE256)) {
        return C509_SIGFAM_ECDSA;
    }
    if (sigAlg == C509_SIG_ED25519) {
        return C509_SIGFAM_ED25519;
    }
    if (sigAlg == C509_SIG_ED448) {
        return C509_SIGFAM_ED448;
    }
    if ((sigAlg >= C509_SIG_RSA_SHA256) && (sigAlg <= C509_SIG_PSS_SHA512)) {
        return C509_SIGFAM_RSA;
    }
    return C509_SIGFAM_NONE;
}

/* Report whether a caller-supplied keyType is incompatible with the signature
 * algorithm family the certificate names. The certificate must not be able to
 * pick a key family different from the one the caller provided: this closes
 * the confusion where an EC issuer key is used as an RSA modulus (and similar
 * cross-family mixups) just because the certificate claims an RSA codepoint.
 * WC_C509_KEY_UNKNOWN is the inference path and binds nothing here.
 *
 * @param [in] keyType  Caller-supplied wc_C509_KeyType (0 = UNKNOWN).
 * @param [in] sigAlg   C509 issuerSignatureAlgorithm codepoint.
 *
 * @return  Non-zero when keyType is known and does not match the algorithm.
 */
static int c509_keytype_sig_mismatch(int keyType, sword32 sigAlg)
{
    int fam;

    if (keyType == WC_C509_KEY_UNKNOWN) {
        return 0; /* inference path: family resolved from the codepoint */
    }
    fam = c509_sig_family(sigAlg);
    if (fam == C509_SIGFAM_NONE) {
        /* Unknown signature codepoint: there is no family to confuse the key
         * with, and the verify dispatcher rejects it as NOT_COMPILED_IN. Report
         * "no mismatch" so that unsupported result is what the caller sees,
         * matching the inferred-type path, not BAD_FUNC_ARG. */
        return 0;
    }
    switch (keyType) {
        case WC_C509_KEY_ED25519:
            return fam != C509_SIGFAM_ED25519;
        case WC_C509_KEY_ED448:
            return fam != C509_SIGFAM_ED448;
        case WC_C509_KEY_RSA:
            return fam != C509_SIGFAM_RSA;
        case WC_C509_KEY_P256:
        case WC_C509_KEY_P384:
        case WC_C509_KEY_P521:
        case WC_C509_KEY_BP256:
        case WC_C509_KEY_BP384:
        case WC_C509_KEY_BP512:
            return fam != C509_SIGFAM_ECDSA;
        default:
            return 1; /* unknown key type cannot match any algorithm */
    }
}

/* Verify a type-2 (natively signed) C509 signature over its CBOR TBS. The
 * decoder d is positioned just after the array header; tbsStart is the offset
 * of the TBS within the input. keyType (a wc_C509_KeyType, or
 * WC_C509_KEY_UNKNOWN) disambiguates a brainpool issuer key from the wire-
 * identical NIST curve of the same strength.
 *
 * @param [in, out] d            Decoder cursor, positioned after the array
 *                               header.
 * @param [in]      tbsStart     Offset of the CBOR TBS within the input.
 * @param [in]      issuerPub    Raw issuer public key.
 * @param [in]      issuerPubSz  Length of issuerPub.
 * @param [in]      keyType      Issuer wc_C509_KeyType hint (or
 *                               WC_C509_KEY_UNKNOWN).
 * @param [in]      heap         Heap hint for the verify key (may be NULL).
 * @param [in]      devId        Device id for the verify key.
 *
 * @return  0 if valid.
 * @return  ASN_SIG_CONFIRM_E on a bad signature, or a negative wolfCrypt error
 *          (NOT_COMPILED_IN for an unsupported algorithm).
 */
static int c509_verify_type2(C509Dec* d, word32 tbsStart,
    const byte* issuerPub, word32 issuerPubSz, int keyType, void* heap,
    int devId)
{
    const byte* sig;
    const byte* tbs;
    word32 sigLen, tbsLen;
    word32 i;
    sword32 sigAlg;

    if (c509_dec_skip(d) != 0) { /* [1] serialNumber */
        return ASN_PARSE_E;
    }
    { /* [2] signatureAlgorithm: ~oid form -> NOT_COMPILED_IN (out of profile),
       * a truncated/ill-formed head -> ASN_PARSE_E (malformed), not lumped. */
        int algRet = c509_dec_alg_or_oid(d, &sigAlg);
        if (algRet != 0) {
            return algRet;
        }
    }
    /* Bind the caller's issuer key type to the algorithm the certificate
     * names, so a cert cannot steer an EC key into the RSA path (or similar).
     */
    if (c509_keytype_sig_mismatch(keyType, sigAlg)) {
        return BAD_FUNC_ARG;
    }
    /* An RSA codepoint with an inferred (UNKNOWN) key type is refused: the
     * issuer key is an opaque byte string and a size check cannot tell a real
     * modulus from a large EC X||Y (P-521 132 B, brainpoolP512r1 128 B both
     * clear the modulus floor). The caller must assert the key is RSA via
     * wc_C509_VerifyEx(WC_C509_KEY_RSA, ...), as SHAKE already requires. */
    if ((keyType == WC_C509_KEY_UNKNOWN) &&
            (c509_sig_family(sigAlg) == C509_SIGFAM_RSA)) {
        return BAD_FUNC_ARG;
    }
    for (i = 3; i < 10; i++) { /* [3..9] issuer .. extensions */
        if (c509_dec_skip(d) != 0) {
            return ASN_PARSE_E;
        }
    }
    tbs = d->buf + tbsStart;
    tbsLen = d->idx - tbsStart;
    if (c509_dec_str(d, C509_CBOR_BSTR, &sig, &sigLen) != 0) { /* [10] sig */
        return ASN_PARSE_E;
    }
    if (d->idx != d->len) {
        return ASN_PARSE_E; /* unsigned trailing bytes after the signature */
    }

#ifdef C509_HAVE_ED25519_VERIFY
    if (sigAlg == C509_SIG_ED25519) {
        return c509_verify_ed25519(sig, sigLen, tbs, tbsLen, issuerPub,
            issuerPubSz, heap, devId);
    }
#endif
#ifdef C509_HAVE_ED448_VERIFY
    if (sigAlg == C509_SIG_ED448) {
        return c509_verify_ed448(sig, sigLen, tbs, tbsLen, issuerPub,
            issuerPubSz, heap, devId);
    }
#endif
#ifdef C509_HAVE_ECDSA_VERIFY
    if (sigAlg == C509_SIG_ES256 || sigAlg == C509_SIG_ES384 ||
            sigAlg == C509_SIG_ES512 || sigAlg == C509_SIG_ES_SHAKE128 ||
            sigAlg == C509_SIG_ES_SHAKE256) {
        return c509_verify_ecdsa(sigAlg, keyType, tbs, tbsLen, sig, sigLen,
            issuerPub, issuerPubSz, heap, devId);
    }
#endif
#ifndef NO_RSA
    /* RSA PKCS#1 v1.5 (23/24/25) or RSASSA-PSS (26/27/28). The issuer key is
     * the raw RSA modulus; the public exponent is the C509 default 65537. */
    if (sigAlg == C509_SIG_RSA_SHA256 || sigAlg == C509_SIG_RSA_SHA384 ||
            sigAlg == C509_SIG_RSA_SHA512 || sigAlg == C509_SIG_PSS_SHA256 ||
            sigAlg == C509_SIG_PSS_SHA384 || sigAlg == C509_SIG_PSS_SHA512) {
        return c509_verify_rsa(sigAlg, tbs, tbsLen, sig, sigLen, issuerPub,
            issuerPubSz, heap, devId);
    }
#endif
    /* When neither ECDSA nor Ed25519 verification is compiled in, the parsed
     * TBS / signature fields are otherwise unused -- keep the parse (it still
     * validates structure) and avoid -Wunused-but-set-variable. */
    (void)issuerPub;
    (void)issuerPubSz;
    (void)sig;
    (void)sigLen;
    (void)tbs;
    (void)heap;
    (void)devId;
    (void)tbsLen;
    (void)sigAlg;
    (void)keyType;
    return NOT_COMPILED_IN; /* unsupported signature algorithm */
}

#ifdef WOLFSSL_C509_TYPE3
/* Verify a type-3 (CBOR re-encoded X.509) C509: reconstruct the DER certificate
 * and verify the issuer signature over its reconstructed TBSCertificate. ECDSA
 * (any supported curve/hash), RSA and Ed25519 / Ed448 all verify the
 * reconstructed TBS with the shared type-2 verify helpers; keyType selects a
 * brainpool curve or the SHAKE curve exactly as on the type-2 path. dec is
 * positioned just after the array header (before c509CertificateType).
 *
 * @param [in, out] dec          Decoder cursor.
 * @param [in]      issuerPub    Raw issuer public key.
 * @param [in]      issuerPubSz  Length of issuerPub.
 * @param [in]      keyType      Issuer wc_C509_KeyType (WC_C509_KEY_UNKNOWN to
 *                               infer).
 * @param [in]      heap         Heap hint for the verify key (may be NULL).
 * @param [in]      devId        Device id for the verify key.
 *
 * @return  0 on a valid signature.
 * @return  ASN_SIG_CONFIRM_E on a bad one, or another negative wolfCrypt error
 *          (BAD_FUNC_ARG, MEMORY_E, NOT_COMPILED_IN).
 */
static int c509_verify_type3(C509Dec* dec, const byte* issuerPub,
    word32 issuerPubSz, int keyType, void* heap, int devId)
{
#if !defined(NO_RSA) || defined(C509_HAVE_ED25519_VERIFY) || \
    defined(C509_HAVE_ED448_VERIFY) || defined(C509_HAVE_ECDSA_VERIFY)
    int         ret = 0;
    word32      derLen = 0;
    const byte* sig = NULL;
    word32      sigLen = 0;
    word32      tbsOff = 0;
    word32      tbsLen = 0;
    sword32     sigAlg = 0;
#ifdef WOLFSSL_SMALL_STACK
    /* Heap available: size the reconstruction buffer exactly. A first pass
     * with a counting sink (out == NULL) measures the DER length; then exactly
     * that many bytes are allocated for the real pass - so a type-3
     * certificate of any size (a large RSA modulus, a rich extension profile)
     * verifies with no WC_C509_MAX_DER cap. */
    byte*  der = NULL;
    word32 startIdx = dec->idx;
#else
    /* No dynamic allocation: reconstruct into the fixed, compile-time-bounded
     * buffer. WC_C509_MAX_DER is derived from the compiled key sizes (see
     * c509.h); a certificate whose DER exceeds it returns BUFFER_E. */
    byte der[WC_C509_MAX_DER];
#endif

#ifdef WOLFSSL_SMALL_STACK
    ret = c509_type3_build_cert(dec, NULL, 0, &derLen, NULL, NULL, NULL, NULL,
        NULL, heap);
    if (ret == 0) {
        dec->idx = startIdx;              /* rewind for the real emit pass */
        der = (byte*)XMALLOC(derLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        ret = c509_type3_build_cert(dec, der, derLen, &derLen, &sig,
            &sigLen, &tbsOff, &tbsLen, &sigAlg, heap);
    }
#else
    ret = c509_type3_build_cert(dec, der, (word32)WC_C509_MAX_DER, &derLen,
        &sig, &sigLen, &tbsOff, &tbsLen, &sigAlg, heap);
#endif
    /* The reconstruction leaves dec positioned at the signatureValue element;
     * skip it and require the 11-element array to end exactly at the input
     * end, so no unsigned trailing bytes are accepted. */
    if ((ret == 0) &&
            ((c509_dec_skip(dec) != 0) || (dec->idx != dec->len))) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        const byte* tbs = der + tbsOff;

        /* derLen is set by the reconstruction but not needed on the verify
         * path; the other fields are all consumed below (keyType by the
         * mismatch check, tbs/sig/issuerPub by the per-algorithm dispatch,
         * at least one arm of which is always compiled). */
        (void)derLen;
        /* Bind the caller's key type to the certificate's algorithm family,
         * exactly as on the type-2 path (closes EC/RSA confusion). */
        if (c509_keytype_sig_mismatch(keyType, sigAlg)) {
            ret = BAD_FUNC_ARG;
        }
        /* RSA with an inferred (UNKNOWN) key type is refused - see the type-2
         * path; the caller must use wc_C509_VerifyEx(WC_C509_KEY_RSA). */
        else if ((keyType == WC_C509_KEY_UNKNOWN) &&
                (c509_sig_family(sigAlg) == C509_SIGFAM_RSA)) {
            ret = BAD_FUNC_ARG;
        }
        else
#ifndef NO_RSA
        /* Type-3 RSA is sha256WithRSAEncryption only: C509_SIGALG_TABLE has no
         * entry for RSA-SHA384/512 or RSASSA-PSS, so c509_type3_build_cert
         * returns NOT_COMPILED_IN for those codepoints before this point.
         * Dispatching them here would be dead code. */
        if (sigAlg == C509_SIG_RSA_SHA256) {
            ret = c509_verify_rsa(sigAlg, tbs, tbsLen, sig, sigLen, issuerPub,
                issuerPubSz, heap, devId);
        }
        else
#endif
#ifdef C509_HAVE_ED25519_VERIFY
        if (sigAlg == C509_SIG_ED25519) {
            ret = c509_verify_ed25519(sig, sigLen, tbs, tbsLen, issuerPub,
                issuerPubSz, heap, devId);
        }
        else
#endif
#ifdef C509_HAVE_ED448_VERIFY
        if (sigAlg == C509_SIG_ED448) {
            ret = c509_verify_ed448(sig, sigLen, tbs, tbsLen, issuerPub,
                issuerPubSz, heap, devId);
        }
        else
#endif
#ifdef C509_HAVE_ECDSA_VERIFY
        /* ECDSA over the reconstructed DER TBS. keyType selects the curve
         * (NIST / brainpool) and the SHAKE variants through c509_ecdsa_params,
         * the same helper the type-2 path uses, so every supported ES* / curve
         * verifies identically across builds (no CheckCertSignaturePubKey
         * route whose behaviour depended on SMALL_CERT_VERIFY / OPENSSL_EXTRA).
         */
        if (c509_sig_family(sigAlg) == C509_SIGFAM_ECDSA) {
            ret = c509_verify_ecdsa(sigAlg, keyType, tbs, tbsLen, sig, sigLen,
                issuerPub, issuerPubSz, heap, devId);
        }
        else
#endif
        {
            ret = NOT_COMPILED_IN; /* unsupported type-3 signature algorithm */
        }
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(der, heap, DYNAMIC_TYPE_TMP_BUFFER); /* XFREE(NULL) is safe */
#endif
    return ret;
#else
    (void)dec;
    (void)issuerPub;
    (void)issuerPubSz;
    (void)keyType;
    (void)heap;
    (void)devId;
    return NOT_COMPILED_IN; /* no type-3 verify algorithm compiled in */
#endif
}
#endif /* WOLFSSL_C509_TYPE3 */

/* Verify a C509 certificate's issuer signature with the issuer key type
 * supplied (to disambiguate a brainpool key or select a curve for SHAKE).
 * Public API; see wolfssl/wolfcrypt/c509.h for the full contract.
 *
 * @param [in] issuerPub    Raw issuer public key.
 * @param [in] issuerPubSz  Length of issuerPub.
 * @param [in] keyType      Issuer wc_C509_KeyType (or WC_C509_KEY_UNKNOWN to
 *                          infer).
 * @param [in] c509         C509 certificate bytes.
 * @param [in] c509Sz       Length of c509.
 * @param [in] heap         Heap hint for the internal allocations and key
 *                          objects (may be NULL).
 * @param [in] devId        Device id for the signature-verify key object.
 *
 * @return  0 on a valid signature.
 * @return  ASN_SIG_CONFIRM_E on a bad one, or another negative wolfCrypt error.
 */
static int c509_verify_core(const byte* issuerPub, word32 issuerPubSz,
    int keyType, const byte* c509, word32 c509Sz, void* heap, int devId)
{
    C509Dec dec;
    word32 count;
    word32 tbsStart;
    sword32 certType;

    if ((issuerPub == NULL) || (c509 == NULL) || (c509Sz == 0)) {
        return BAD_FUNC_ARG;
    }
    /* keyType must be a wc_C509_KeyType; reject an out-of-range value rather
     * than silently treating it as WC_C509_KEY_UNKNOWN (inference). */
    if ((keyType < WC_C509_KEY_UNKNOWN) || (keyType > WC_C509_KEY_RSA)) {
        return BAD_FUNC_ARG;
    }
    c509_dec_init(&dec, c509, c509Sz);
    /* A C509 certificate is exactly an 11-element array; reject any other
     * count so extra elements cannot ride along outside the signed TBS. */
    if ((c509_dec_array(&dec, &count) != 0) || (count != 11)) {
        return ASN_PARSE_E;
    }
    tbsStart = dec.idx;
    if (c509_dec_int(&dec, &certType) != 0) {
        return ASN_PARSE_E;
    }

    /* Dispatch only on the two defined certificate types; anything else is
     * rejected rather than silently verified as a natively signed cert. */
    if (certType == 2) {
        /* Type 2 (natively signed): verify the CBOR TBS directly. */
        return c509_verify_type2(&dec, tbsStart, issuerPub, issuerPubSz,
            keyType, heap, devId);
    }
    if (certType == 3) {
        /* Reconstruct the DER certificate, then verify its signature. */
#ifdef WOLFSSL_C509_TYPE3
        return c509_verify_type3(&dec, issuerPub, issuerPubSz, keyType, heap,
            devId);
#else
        (void)issuerPubSz;
        (void)heap;
        (void)devId;
        return NOT_COMPILED_IN; /* type-3 support compiled out */
#endif
    }
    return ASN_PARSE_E; /* unknown certificate type */
}

/* Verify a C509 certificate's issuer signature with the issuer key type
 * supplied (to disambiguate a brainpool key, select the curve for a SHAKE
 * signature, or name an RSA issuer). A thin wrapper over the shared core with
 * the default heap and INVALID_DEVID. Public API; see
 * wolfssl/wolfcrypt/c509.h for the full contract.
 *
 * @param [in] issuerPub    Raw issuer public key.
 * @param [in] issuerPubSz  Length of issuerPub.
 * @param [in] keyType      Issuer wc_C509_KeyType (WC_C509_KEY_UNKNOWN to
 *                          infer).
 * @param [in] c509         C509 certificate bytes.
 * @param [in] c509Sz       Length of c509.
 *
 * @return  0 on a valid signature.
 * @return  ASN_SIG_CONFIRM_E on a bad one; BAD_FUNC_ARG on a bad argument or a
 *          keytype/algorithm mismatch; ASN_PARSE_E on a malformed certificate
 *          (including a wrong-length EdDSA signatureValue); BUFFER_E /
 *          NOT_COMPILED_IN / MEMORY_E as documented; or another negative
 *          wolfCrypt error passed through from the key import or signature
 *          check.
 */
int wc_C509_VerifyEx(const byte* issuerPub, word32 issuerPubSz, int keyType,
    const byte* c509, word32 c509Sz)
{
    return c509_verify_core(issuerPub, issuerPubSz, keyType, c509, c509Sz,
        NULL, INVALID_DEVID);
}

/* Like wc_C509_VerifyEx but with a heap hint and device id so the issuer-key
 * import and signature check can run on a crypto-callback device and/or draw
 * from a static-memory pool. devId reaches the signature-verify key objects
 * only (not the EC point-decompression key or the one-shot TBS hash).
 * wc_C509_VerifyEx is this call with heap == NULL and devId == INVALID_DEVID.
 * Public API; see wolfssl/wolfcrypt/c509.h for the full contract.
 *
 * @param [in] issuerPub    Raw issuer public key.
 * @param [in] issuerPubSz  Length of issuerPub.
 * @param [in] keyType      Issuer wc_C509_KeyType (WC_C509_KEY_UNKNOWN to
 *                          infer).
 * @param [in] c509         C509 certificate bytes.
 * @param [in] c509Sz       Length of c509.
 * @param [in] heap         Heap hint for the internal allocations and key
 *                          objects (may be NULL for the default heap).
 * @param [in] devId        Device id for the signature-verify key object
 *                          (INVALID_DEVID for software crypto).
 *
 * @return  Same as wc_C509_VerifyEx.
 */
int wc_C509_VerifyEx2(const byte* issuerPub, word32 issuerPubSz, int keyType,
    const byte* c509, word32 c509Sz, void* heap, int devId)
{
    return c509_verify_core(issuerPub, issuerPubSz, keyType, c509, c509Sz,
        heap, devId);
}

/* Verify a C509 certificate's issuer signature, inferring the issuer key type
 * from the signature-algorithm codepoint. Inference covers only NIST-curve
 * ECDSA (ES256/384/512) and Ed25519 / Ed448; an RSA, SHAKE or brainpool issuer
 * cannot be inferred and must use wc_C509_VerifyEx with the key type. Public
 * API; see wolfssl/wolfcrypt/c509.h for the full contract.
 *
 * @param [in] issuerPub    Raw issuer public key.
 * @param [in] issuerPubSz  Length of issuerPub.
 * @param [in] c509         C509 certificate bytes.
 * @param [in] c509Sz       Length of c509.
 *
 * @return  0 on a valid signature.
 * @return  ASN_SIG_CONFIRM_E on a bad one, or another negative wolfCrypt error.
 */
int wc_C509_Verify(const byte* issuerPub, word32 issuerPubSz, const byte* c509,
    word32 c509Sz)
{
    /* WC_C509_KEY_UNKNOWN: infer the key type from the signature codepoint -
     * a NIST-curve ECDSA codepoint selects the matching P-curve, an Ed25519 /
     * Ed448 codepoint its curve. An RSA or SHAKE codepoint cannot be inferred
     * (c509_verify_type2/type3 return BAD_FUNC_ARG), and a brainpool issuer is
     * wire-identical to the NIST curve of equal strength, so both of those
     * need wc_C509_VerifyEx with the explicit key type. */
    return c509_verify_core(issuerPub, issuerPubSz, WC_C509_KEY_UNKNOWN, c509,
        c509Sz, NULL, INVALID_DEVID);
}

#endif /* WOLFSSL_C509 */
