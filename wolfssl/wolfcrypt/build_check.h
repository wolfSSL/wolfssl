/* build_check.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
    \file wolfssl/wolfcrypt/build_check.h

    Run-time check that an application was compiled with the same wolfSSL
    build configuration as the wolfSSL library it is linked/loaded with.

    The application and the library must be built with the same feature
    defines: they change public struct layouts and which APIs exist, and a
    mismatch compiles cleanly but corrupts memory at run time.  This header
    computes a fingerprint of the configuration seen by whichever translation
    unit includes it:

     - feature words: one bit per ABI-relevant macro (listed, with the rules
       for adding one, in build_check_list.h),
     - the sizes of the public structures applications allocate or read
       fields of: wolfCrypt keys and contexts (Aes, RsaKey, ecc_key, WC_RNG,
       mp_int, ...), certificates (Cert, DecodedCert), wc_PKCS7,
       wc_CryptoInfo, the non-blocking contexts and, with OPENSSL_EXTRA, the
       OpenSSL compatibility structures (EVP_MD_CTX, HMAC_CTX, SHA*_CTX,
       EVP_PKEY, ...); WOLFSSL and WOLFSSL_CTX are opaque to applications and
       not measured,
     - the library version, and
     - WOLFSSL_OPTIONS_HASH, a hash of the generated wolfssl/options.h, when
       the build system provides one (autotools and CMake; not
       user_settings.h builds).

    The library exports its own copy of the fingerprint (computed when the
    library was compiled) through wc_GetBuildConfig(), and compares a
    caller's fingerprint with wc_CompareBuildConfig().  wc_CheckBuildConfig()
    is a header-inline wrapper that fingerprints the caller's compilation and
    compares it in one call:

    \code
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/build_check.h>

    char why[2048];
    if (wc_CheckBuildConfigEx(NULL, why, sizeof(why)) != 0) {
        fprintf(stderr, "wolfSSL build mismatch: %s\n", why);
        exit(1);
    }
    \endcode

    The description names what differs, for example:
    "OPENSSL_EXTRA: app=on lib=off; sizeof(Aes): app=880 lib=848".

    Everything here is available only when HAVE_WC_INTROSPECTION is defined.
    It is on by default with autotools (except lean and reproducible builds),
    with CMake (WOLFSSL_INTROSPECTION, except reproducible builds) and so in
    the Linux kernel module; user_settings.h builds define it themselves.
*/

#ifndef WOLF_CRYPT_BUILD_CHECK_H
#define WOLF_CRYPT_BUILD_CHECK_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/version.h>

#ifdef HAVE_WC_INTROSPECTION

#include <wolfssl/wolfcrypt/error-crypt.h>

/* Headers for the types whose sizes are recorded (see build_check_list.h). */
#ifndef WC_NO_RNG
    #include <wolfssl/wolfcrypt/random.h>
#endif
#ifndef NO_BIG_INT
    #include <wolfssl/wolfcrypt/wolfmath.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_DH
    #include <wolfssl/wolfcrypt/dh.h>
#endif
#ifndef NO_DSA
    #include <wolfssl/wolfcrypt/dsa.h>
#endif
#include <wolfssl/wolfcrypt/hash.h>
#ifndef NO_SHA
    #include <wolfssl/wolfcrypt/sha.h>
#endif
#ifndef NO_MD5
    #include <wolfssl/wolfcrypt/md5.h>
#endif
#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
    #include <wolfssl/wolfcrypt/sha512.h>
#endif
#ifdef WOLFSSL_SHA3
    #include <wolfssl/wolfcrypt/sha3.h>
#endif
#ifndef NO_HMAC
    #include <wolfssl/wolfcrypt/hmac.h>
#endif
#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
#endif
#ifdef WOLFSSL_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif
#ifdef HAVE_CHACHA
    #include <wolfssl/wolfcrypt/chacha.h>
#endif
#ifdef HAVE_POLY1305
    #include <wolfssl/wolfcrypt/poly1305.h>
#endif
#ifdef HAVE_CAMELLIA
    #include <wolfssl/wolfcrypt/camellia.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_CURVE448
    #include <wolfssl/wolfcrypt/curve448.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef WOLFSSL_HAVE_MLKEM
    #include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#ifdef WOLFSSL_HAVE_SLHDSA
    #include <wolfssl/wolfcrypt/wc_slhdsa.h>
#endif
#ifdef WOLFSSL_HAVE_LMS
    #include <wolfssl/wolfcrypt/wc_lms.h>
#endif
#ifdef WOLFSSL_HAVE_XMSS
    #include <wolfssl/wolfcrypt/wc_xmss.h>
#endif
#include <wolfssl/wolfcrypt/asn_public.h>
#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn.h>
#endif
#ifdef HAVE_PKCS7
    #include <wolfssl/wolfcrypt/pkcs7.h>
#endif
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#ifdef HAVE_FALCON
    #include <wolfssl/wolfcrypt/falcon.h>
#endif
#ifdef WOLFSSL_HAVE_FRODOKEM
    #include <wolfssl/wolfcrypt/wc_frodokem.h>
#endif
#ifdef WOLFCRYPT_HAVE_ECCSI
    #include <wolfssl/wolfcrypt/eccsi.h>
#endif
#ifdef WOLFCRYPT_HAVE_SAKKE
    #include <wolfssl/wolfcrypt/sakke.h>
#endif
#ifdef HAVE_ARGON2
    #include <wolfssl/wolfcrypt/argon2.h>
#endif
#ifdef HAVE_ASCON
    #include <wolfssl/wolfcrypt/ascon.h>
#endif
#ifdef HAVE_PKCS11
    #include <wolfssl/wolfcrypt/wc_pkcs11.h>
#endif
#ifdef WOLFSSL_PUF
    #include <wolfssl/wolfcrypt/puf.h>
#endif
#ifdef WOLFSSL_SHE
    #include <wolfssl/wolfcrypt/wc_she.h>
#endif
#ifdef HAVE_WC_RNG_BANK
    #include <wolfssl/wolfcrypt/rng_bank.h>
#endif
#ifndef WOLFCRYPT_ONLY
    /* Defines WOLFSSL_NO_SOCK and WOLFSSL_USER_IO on some platforms; include
     * it so that an application that includes ssl.h sees the same values
     * as the library. */
    #include <wolfssl/wolfio.h>
#endif
#ifndef WOLFCRYPT_ONLY
    /* WOLFSSL_X509_STORE_CTX, read by verify callbacks in every TLS build,
     * and with OPENSSL_EXTRA the compatibility layer structs applications
     * allocate or access directly (ssl.h then pulls in the evp, sha, hmac,
     * md5, bn, rsa and ec compat headers). An application using TLS
     * includes ssl.h anyway, so this adds no names it would not see. */
    #include <wolfssl/ssl.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Layout version of wc_BuildConfig.  The struct is append-only: new fields
 * go at the end and bump this value; existing fields never move. */
#define WC_BUILD_CONFIG_VERSION 1

/* Number of 32-bit feature words and of struct-size slots in version 1.
 * What each bit and slot means is in build_check_list.h.  Both are fixed for
 * version 1: a later version adds fields after sizes[] instead. */
#define WC_BUILD_FEATURE_WORDS  8
#define WC_BUILD_SIZE_COUNT     96

/* Size of the version 1 layout: the smallest wc_BuildConfig that any
 * library accepts or fills.  A later, larger layout keeps this prefix. */
#define WC_BUILD_CONFIG_V1_SZ \
    ((word32)((4 + WC_BUILD_FEATURE_WORDS + WC_BUILD_SIZE_COUNT) * \
              sizeof(word32)))

/* Bits returned through the mismatch argument of wc_CompareBuildConfig(),
 * wc_CheckBuildConfig() and wc_CheckBuildConfigEx(). */
#define WC_BUILD_MISMATCH_VERSION       0x00000001U /* LIBWOLFSSL_VERSION_HEX */
#define WC_BUILD_MISMATCH_FEATURES      0x00000002U /* feature words */
#define WC_BUILD_MISMATCH_SIZES         0x00000004U /* struct sizes */
#define WC_BUILD_MISMATCH_OPTIONS_HASH  0x00000008U /* WOLFSSL_OPTIONS_HASH */

/* Hash of the generated wolfssl/options.h, 0 when unavailable. */
#ifdef WOLFSSL_OPTIONS_HASH
    #define WC_BUILD_OPTIONS_HASH ((word32)(WOLFSSL_OPTIONS_HASH))
#else
    #define WC_BUILD_OPTIONS_HASH ((word32)0)
#endif

typedef struct wc_BuildConfig {
    word32 structSz;      /* bytes of this struct that are filled in: the
                           * filler's sizeof(wc_BuildConfig), or less from
                           * wc_GetBuildConfig() when the caller's is smaller.
                           * Readers use only the fields it covers. */
    word32 cfgVersion;    /* WC_BUILD_CONFIG_VERSION */
    word32 libVersionHex; /* LIBWOLFSSL_VERSION_HEX */
    word32 optionsHash;   /* WC_BUILD_OPTIONS_HASH, 0 = unavailable */
    word32 features[WC_BUILD_FEATURE_WORDS];
    word32 sizes[WC_BUILD_SIZE_COUNT];
} wc_BuildConfig;

#define WC_BUILD_BIT(n) ((word32)1 << (n))

/* Size slot value for a type that exists in the configuration but that the
 * filling translation unit could not see (see WC_BCS_UNKNOWN in
 * build_check_list.h). Comparisons skip such slots. */
#define WC_BUILD_SIZE_UNKNOWN 0xFFFFFFFFU

#ifndef NO_BIG_INT
/* Recorded in a size slot so that the math radix is compared too:
 * sizeof(wc_BuildDigitBits) is DIGIT_BIT. */
typedef char wc_BuildDigitBits[DIGIT_BIT];
#endif

/* Fill cfg with the build configuration visible to the translation unit
 * that compiles this function.  Included in applications, it describes the
 * application's view; inside the library (wc_GetBuildConfig()) it describes
 * the library's view. */
static WC_INLINE WC_MAYBE_UNUSED void wc_BuildConfig_Local(
    wc_BuildConfig* cfg)
{
    XMEMSET(cfg, 0, sizeof(*cfg));
    cfg->structSz      = (word32)sizeof(*cfg);
    cfg->cfgVersion    = WC_BUILD_CONFIG_VERSION;
    cfg->libVersionHex = (word32)LIBWOLFSSL_VERSION_HEX;
    cfg->optionsHash   = WC_BUILD_OPTIONS_HASH;

#define WC_BCF(w, b, n)     cfg->features[w] |= WC_BUILD_BIT(b);
#define WC_BCF_NO(w, b, n)  (void)0;
#define WC_BCS(s, t)        cfg->sizes[s] = (word32)sizeof(t);
#define WC_BCS_NO(s, t)     (void)0;
#define WC_BCS_UNKNOWN(s, t) cfg->sizes[s] = WC_BUILD_SIZE_UNKNOWN;
#include <wolfssl/wolfcrypt/build_check_list.h>
#undef WC_BCF
#undef WC_BCF_NO
#undef WC_BCS
#undef WC_BCS_NO
#undef WC_BCS_UNKNOWN
}

/* Library's own build configuration, as compiled into the library.  Writes
 * at most cfgSz bytes, normally sizeof(*cfg): a newer library fills only the
 * fields an older caller's struct has, and sets structSz to what it wrote.
 * Returns 0, or BAD_FUNC_ARG when cfg is NULL or cfgSz is less than
 * WC_BUILD_CONFIG_V1_SZ. */
WOLFSSL_API int wc_GetBuildConfig(wc_BuildConfig* cfg, word32 cfgSz);

/* Compare cfg (normally the application's view, from wc_BuildConfig_Local())
 * with the library's configuration.  Returns 0 on match,
 * BUILD_CONFIG_MISMATCH_E on mismatch and BAD_FUNC_ARG on bad input.  When
 * mismatch is not NULL it receives a WC_BUILD_MISMATCH_* bitmask. */
WOLFSSL_API int wc_CompareBuildConfig(const wc_BuildConfig* cfg,
    word32* mismatch);

/* Describe how cfg differs from the library's configuration as a
 * NUL-terminated, "; "-separated list in buf, e.g.
 * "OPENSSL_EXTRA: app=on lib=off; sizeof(Aes): app=880 lib=848".  Returns
 * the string length (0 and "" when they match), BUFFER_E when buf was too
 * small (buf then holds the items that fit, ending in "..." if bufSz is at
 * least 4), or BAD_FUNC_ARG.  A mismatch between two quite different builds
 * runs to about 1.5 KB; 2048 bytes is a comfortable size. */
WOLFSSL_API int wc_BuildConfigMismatchString(const wc_BuildConfig* cfg,
    char* buf, word32 bufSz);

/* Name of the macro behind a feature bit, e.g. "WOLFSSL_SHA3", or NULL for an
 * unused or out of range bit. */
WOLFSSL_API const char* wc_BuildConfigFeatureName(word32 word, word32 bit);

/* Type recorded in a size slot, e.g. "Aes", or NULL for an unused or out of
 * range slot. */
WOLFSSL_API const char* wc_BuildConfigSizeName(word32 slot);

/* Fingerprint the calling translation unit and compare it with the loaded
 * library.  Same return values as wc_CompareBuildConfig(). */
static WC_INLINE WC_MAYBE_UNUSED int wc_CheckBuildConfig(word32* mismatch)
{
    wc_BuildConfig cfg;
    wc_BuildConfig_Local(&cfg);
    return wc_CompareBuildConfig(&cfg, mismatch);
}

/* As wc_CheckBuildConfig(), and on a mismatch also describe it in buf (see
 * wc_BuildConfigMismatchString()).  buf may be NULL; on a match it is set to
 * "".  Returns the wc_CompareBuildConfig() result. */
static WC_INLINE WC_MAYBE_UNUSED int wc_CheckBuildConfigEx(word32* mismatch,
    char* buf, word32 bufSz)
{
    wc_BuildConfig cfg;
    int ret;

    wc_BuildConfig_Local(&cfg);
    ret = wc_CompareBuildConfig(&cfg, mismatch);
    if ((buf != NULL) && (bufSz > 0)) {
        buf[0] = '\0';
        if (ret == WC_NO_ERR_TRACE(BUILD_CONFIG_MISMATCH_E)) {
            (void)wc_BuildConfigMismatchString(&cfg, buf, bufSz);
        }
    }
    return ret;
}

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_WC_INTROSPECTION */

#endif /* WOLF_CRYPT_BUILD_CHECK_H */
