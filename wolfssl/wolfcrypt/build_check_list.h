/* build_check_list.h
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

/* The build configuration fingerprint list used by build_check.h.
 *
 * Do not include this file directly. It has no include guard: it is
 * expanded in wc_BuildConfig_Local() to compute the fingerprint, in
 * wolfcrypt/src/logging.c to build the name table behind
 * wc_BuildConfigFeatureName(), wc_BuildConfigSizeName() and
 * wc_BuildConfigMismatchString(), and in tests/api.c to check that no bit
 * or slot is used twice. The includer defines:
 *
 *   WC_BCF(word, bit, NAME)     feature macro NAME is defined
 *   WC_BCF_NO(word, bit, NAME)  feature macro NAME is not defined
 *   WC_BCS(slot, TYPE)          TYPE is available; record sizeof(TYPE)
 *   WC_BCS_NO(slot, TYPE)       TYPE is compiled out; slot stays 0
 *   WC_BCS_UNKNOWN(slot, TYPE)  TYPE exists in this configuration but this
 *                               translation unit cannot see it; record
 *                               WC_BUILD_SIZE_UNKNOWN, which comparisons skip
 *
 * NAME is only ever stringified, never expanded, so it does not matter what
 * value the macro has. TYPE is stringified and, in WC_BCS, used in
 * sizeof(); WC_BCS_NO and WC_BCS_UNKNOWN must not use it, as the type may
 * not be declared.
 *
 * Each guard must match the conditions under which its type is declared in
 * the public headers (build_check.h includes them): broader fails to compile
 * in some configurations, narrower silently reports 0.
 *
 * Rules:
 *  - List a feature macro when it changes a public struct layout, changes
 *    which public APIs exist or their signatures, or selects the math
 *    backend. Macros that only change naming (OPENSSL_COEXIST,
 *    NO_OLD_*_NAMES, ...) are deliberately not listed.
 *  - Each entry gives both branches, so that every bit and slot has a name.
 *  - Bit positions and size slots are append-only: never move or reuse one.
 *    WC_BUILD_FEATURE_WORDS and WC_BUILD_SIZE_COUNT in build_check.h bound
 *    them. Free bits: word 2 bit 14, word 3 bits 24-31 and word 6 bits
 *    28-31. Free size slots: 71-95. Beyond those, more need a
 *    new field at the end of wc_BuildConfig and a WC_BUILD_CONFIG_VERSION
 *    bump.
 *  - CI (.github/scripts/check-build-config-list.py) fails when a public
 *    struct's layout depends on a macro that nothing here covers. Fix it by
 *    sizing the struct (WC_BCS), adding the macro (WC_BCF), or, if
 *    applications never allocate or read the struct, allowlisting it in
 *    that script with the reason. A size slot is not enough for a macro
 *    whose guarded members are all bitfields or single members narrower
 *    than 8 bytes (byte, int, word32, ...), since they can fit into
 *    padding without changing the size while moving the members after
 *    them: such a macro needs a feature bit too.
 *  - A header that defines or undefines a listed macro itself must be
 *    included by build_check.h, so that the library and the application
 *    see the same value whatever else they include. Where that is not
 *    possible (internal.h, sp.h), or build_check.h includes the header only
 *    in some configurations while an application may include it in any
 *    (sp_int.h, aes.h, ...), the entry repeats the header's derivation, or
 *    records the bit only where build_check.h includes the header. The CI
 *    checker enforces this.
 *
 * Included without any of the macros defined, the file expands to nothing,
 * so that it compiles standalone; defining only some of them is an error.
 */

#if defined(WC_BCF) || defined(WC_BCF_NO) || defined(WC_BCS) || \
    defined(WC_BCS_NO) || defined(WC_BCS_UNKNOWN)

#if !defined(WC_BCF) || !defined(WC_BCF_NO) || !defined(WC_BCS) || \
    !defined(WC_BCS_NO) || !defined(WC_BCS_UNKNOWN)
    #error "build_check_list.h: define all of WC_BCF, WC_BCF_NO, WC_BCS, WC_BCS_NO and WC_BCS_UNKNOWN"
#endif


/* ---- Feature word 0: math backend and core library behavior ---- */
#ifdef WOLFSSL_SP_MATH
    WC_BCF(0, 0, WOLFSSL_SP_MATH)
#else
    WC_BCF_NO(0, 0, WOLFSSL_SP_MATH)
#endif
#ifdef WOLFSSL_SP_MATH_ALL
    WC_BCF(0, 1, WOLFSSL_SP_MATH_ALL)
#else
    WC_BCF_NO(0, 1, WOLFSSL_SP_MATH_ALL)
#endif
#ifdef USE_FAST_MATH
    WC_BCF(0, 2, USE_FAST_MATH)
#else
    WC_BCF_NO(0, 2, USE_FAST_MATH)
#endif
#ifdef USE_INTEGER_HEAP_MATH
    WC_BCF(0, 3, USE_INTEGER_HEAP_MATH)
#else
    WC_BCF_NO(0, 3, USE_INTEGER_HEAP_MATH)
#endif
#ifdef NO_BIG_INT
    WC_BCF(0, 4, NO_BIG_INT)
#else
    WC_BCF_NO(0, 4, NO_BIG_INT)
#endif
#ifdef WOLFSSL_HAVE_SP_RSA
    WC_BCF(0, 5, WOLFSSL_HAVE_SP_RSA)
#else
    WC_BCF_NO(0, 5, WOLFSSL_HAVE_SP_RSA)
#endif
#ifdef WOLFSSL_HAVE_SP_DH
    WC_BCF(0, 6, WOLFSSL_HAVE_SP_DH)
#else
    WC_BCF_NO(0, 6, WOLFSSL_HAVE_SP_DH)
#endif
/* sp.h, which no public header includes, undefines WOLFSSL_HAVE_SP_ECC
 * without HAVE_ECC; record the value it leaves, whether or not sp.h was
 * included. */
#if defined(WOLFSSL_HAVE_SP_ECC) && defined(HAVE_ECC)
    WC_BCF(0, 7, WOLFSSL_HAVE_SP_ECC)
#else
    WC_BCF_NO(0, 7, WOLFSSL_HAVE_SP_ECC)
#endif
#ifdef WOLFSSL_SP_384
    WC_BCF(0, 8, WOLFSSL_SP_384)
#else
    WC_BCF_NO(0, 8, WOLFSSL_SP_384)
#endif
#ifdef WOLFSSL_SP_521
    WC_BCF(0, 9, WOLFSSL_SP_521)
#else
    WC_BCF_NO(0, 9, WOLFSSL_SP_521)
#endif
#ifdef WOLFSSL_SP_4096
    WC_BCF(0, 10, WOLFSSL_SP_4096)
#else
    WC_BCF_NO(0, 10, WOLFSSL_SP_4096)
#endif
#ifdef WOLFSSL_PUBLIC_MP
    WC_BCF(0, 11, WOLFSSL_PUBLIC_MP)
#else
    WC_BCF_NO(0, 11, WOLFSSL_PUBLIC_MP)
#endif
#ifdef WOLFSSL_SMALL_STACK
    WC_BCF(0, 12, WOLFSSL_SMALL_STACK)
#else
    WC_BCF_NO(0, 12, WOLFSSL_SMALL_STACK)
#endif
#ifdef WOLFSSL_SMALL_STACK_CACHE
    WC_BCF(0, 13, WOLFSSL_SMALL_STACK_CACHE)
#else
    WC_BCF_NO(0, 13, WOLFSSL_SMALL_STACK_CACHE)
#endif
#ifdef WOLFSSL_STATIC_MEMORY
    WC_BCF(0, 14, WOLFSSL_STATIC_MEMORY)
#else
    WC_BCF_NO(0, 14, WOLFSSL_STATIC_MEMORY)
#endif
#ifdef WOLFSSL_NO_MALLOC
    WC_BCF(0, 15, WOLFSSL_NO_MALLOC)
#else
    WC_BCF_NO(0, 15, WOLFSSL_NO_MALLOC)
#endif
#ifdef SINGLE_THREADED
    WC_BCF(0, 16, SINGLE_THREADED)
#else
    WC_BCF_NO(0, 16, SINGLE_THREADED)
#endif
#ifdef WOLF_CRYPTO_CB
    WC_BCF(0, 17, WOLF_CRYPTO_CB)
#else
    WC_BCF_NO(0, 17, WOLF_CRYPTO_CB)
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_BCF(0, 18, WOLFSSL_ASYNC_CRYPT)
#else
    WC_BCF_NO(0, 18, WOLFSSL_ASYNC_CRYPT)
#endif
#ifdef HAVE_FIPS
    WC_BCF(0, 19, HAVE_FIPS)
#else
    WC_BCF_NO(0, 19, HAVE_FIPS)
#endif
#ifdef WC_RSA_BLINDING
    WC_BCF(0, 20, WC_RSA_BLINDING)
#else
    WC_BCF_NO(0, 20, WC_RSA_BLINDING)
#endif
#ifdef ECC_TIMING_RESISTANT
    WC_BCF(0, 21, ECC_TIMING_RESISTANT)
#else
    WC_BCF_NO(0, 21, ECC_TIMING_RESISTANT)
#endif
#ifdef TFM_TIMING_RESISTANT
    WC_BCF(0, 22, TFM_TIMING_RESISTANT)
#else
    WC_BCF_NO(0, 22, TFM_TIMING_RESISTANT)
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    WC_BCF(0, 23, WOLF_PRIVATE_KEY_ID)
#else
    WC_BCF_NO(0, 23, WOLF_PRIVATE_KEY_ID)
#endif
#ifdef WC_NO_RNG
    WC_BCF(0, 24, WC_NO_RNG)
#else
    WC_BCF_NO(0, 24, WC_NO_RNG)
#endif
#ifdef HAVE_HASHDRBG
    WC_BCF(0, 25, HAVE_HASHDRBG)
#else
    WC_BCF_NO(0, 25, HAVE_HASHDRBG)
#endif
#ifdef WC_RSA_NONBLOCK
    WC_BCF(0, 26, WC_RSA_NONBLOCK)
#else
    WC_BCF_NO(0, 26, WC_RSA_NONBLOCK)
#endif
#ifdef WC_ECC_NONBLOCK
    WC_BCF(0, 27, WC_ECC_NONBLOCK)
#else
    WC_BCF_NO(0, 27, WC_ECC_NONBLOCK)
#endif
#ifdef WOLFSSL_AESNI
    WC_BCF(0, 28, WOLFSSL_AESNI)
#else
    WC_BCF_NO(0, 28, WOLFSSL_AESNI)
#endif
#ifdef WOLFSSL_ARMASM
    WC_BCF(0, 29, WOLFSSL_ARMASM)
#else
    WC_BCF_NO(0, 29, WOLFSSL_ARMASM)
#endif
#ifdef NO_ASN
    WC_BCF(0, 30, NO_ASN)
#else
    WC_BCF_NO(0, 30, NO_ASN)
#endif
#ifdef NO_CODING
    WC_BCF(0, 31, NO_CODING)
#else
    WC_BCF_NO(0, 31, NO_CODING)
#endif

/* ---- Feature word 1: algorithms ---- */
#ifdef NO_RSA
    WC_BCF(1, 0, NO_RSA)
#else
    WC_BCF_NO(1, 0, NO_RSA)
#endif
#ifdef WC_RSA_PSS
    WC_BCF(1, 1, WC_RSA_PSS)
#else
    WC_BCF_NO(1, 1, WC_RSA_PSS)
#endif
#ifdef WOLFSSL_RSA_PUBLIC_ONLY
    WC_BCF(1, 2, WOLFSSL_RSA_PUBLIC_ONLY)
#else
    WC_BCF_NO(1, 2, WOLFSSL_RSA_PUBLIC_ONLY)
#endif
#ifdef NO_DH
    WC_BCF(1, 3, NO_DH)
#else
    WC_BCF_NO(1, 3, NO_DH)
#endif
#ifdef HAVE_ECC
    WC_BCF(1, 4, HAVE_ECC)
#else
    WC_BCF_NO(1, 4, HAVE_ECC)
#endif
#ifdef NO_AES
    WC_BCF(1, 5, NO_AES)
#else
    WC_BCF_NO(1, 5, NO_AES)
#endif
#ifdef HAVE_AESGCM
    WC_BCF(1, 6, HAVE_AESGCM)
#else
    WC_BCF_NO(1, 6, HAVE_AESGCM)
#endif
#ifdef HAVE_AESCCM
    WC_BCF(1, 7, HAVE_AESCCM)
#else
    WC_BCF_NO(1, 7, HAVE_AESCCM)
#endif
#ifdef WOLFSSL_AES_COUNTER
    WC_BCF(1, 8, WOLFSSL_AES_COUNTER)
#else
    WC_BCF_NO(1, 8, WOLFSSL_AES_COUNTER)
#endif
#ifdef WOLFSSL_AES_XTS
    WC_BCF(1, 9, WOLFSSL_AES_XTS)
#else
    WC_BCF_NO(1, 9, WOLFSSL_AES_XTS)
#endif
#ifdef WOLFSSL_AES_DIRECT
    WC_BCF(1, 10, WOLFSSL_AES_DIRECT)
#else
    WC_BCF_NO(1, 10, WOLFSSL_AES_DIRECT)
#endif
#ifdef WOLFSSL_AES_CFB
    WC_BCF(1, 11, WOLFSSL_AES_CFB)
#else
    WC_BCF_NO(1, 11, WOLFSSL_AES_CFB)
#endif
#ifdef WOLFSSL_AES_OFB
    WC_BCF(1, 12, WOLFSSL_AES_OFB)
#else
    WC_BCF_NO(1, 12, WOLFSSL_AES_OFB)
#endif
#ifdef NO_SHA
    WC_BCF(1, 13, NO_SHA)
#else
    WC_BCF_NO(1, 13, NO_SHA)
#endif
#ifdef NO_SHA256
    WC_BCF(1, 14, NO_SHA256)
#else
    WC_BCF_NO(1, 14, NO_SHA256)
#endif
#ifdef WOLFSSL_SHA224
    WC_BCF(1, 15, WOLFSSL_SHA224)
#else
    WC_BCF_NO(1, 15, WOLFSSL_SHA224)
#endif
#ifdef WOLFSSL_SHA384
    WC_BCF(1, 16, WOLFSSL_SHA384)
#else
    WC_BCF_NO(1, 16, WOLFSSL_SHA384)
#endif
#ifdef WOLFSSL_SHA512
    WC_BCF(1, 17, WOLFSSL_SHA512)
#else
    WC_BCF_NO(1, 17, WOLFSSL_SHA512)
#endif
#ifdef WOLFSSL_SHA3
    WC_BCF(1, 18, WOLFSSL_SHA3)
#else
    WC_BCF_NO(1, 18, WOLFSSL_SHA3)
#endif
#ifdef NO_MD5
    WC_BCF(1, 19, NO_MD5)
#else
    WC_BCF_NO(1, 19, NO_MD5)
#endif
#ifdef NO_HMAC
    WC_BCF(1, 20, NO_HMAC)
#else
    WC_BCF_NO(1, 20, NO_HMAC)
#endif
#ifdef NO_DES3
    WC_BCF(1, 21, NO_DES3)
#else
    WC_BCF_NO(1, 21, NO_DES3)
#endif
#ifdef HAVE_CHACHA
    WC_BCF(1, 22, HAVE_CHACHA)
#else
    WC_BCF_NO(1, 22, HAVE_CHACHA)
#endif
#ifdef HAVE_POLY1305
    WC_BCF(1, 23, HAVE_POLY1305)
#else
    WC_BCF_NO(1, 23, HAVE_POLY1305)
#endif
#ifdef HAVE_CURVE25519
    WC_BCF(1, 24, HAVE_CURVE25519)
#else
    WC_BCF_NO(1, 24, HAVE_CURVE25519)
#endif
#ifdef HAVE_ED25519
    WC_BCF(1, 25, HAVE_ED25519)
#else
    WC_BCF_NO(1, 25, HAVE_ED25519)
#endif
#ifdef HAVE_CURVE448
    WC_BCF(1, 26, HAVE_CURVE448)
#else
    WC_BCF_NO(1, 26, HAVE_CURVE448)
#endif
#ifdef HAVE_ED448
    WC_BCF(1, 27, HAVE_ED448)
#else
    WC_BCF_NO(1, 27, HAVE_ED448)
#endif
#ifdef WOLFSSL_HAVE_MLKEM
    WC_BCF(1, 28, WOLFSSL_HAVE_MLKEM)
#else
    WC_BCF_NO(1, 28, WOLFSSL_HAVE_MLKEM)
#endif
#if defined(WOLFSSL_HAVE_MLDSA) || defined(HAVE_DILITHIUM)
    WC_BCF(1, 29, WOLFSSL_HAVE_MLDSA)
#else
    WC_BCF_NO(1, 29, WOLFSSL_HAVE_MLDSA)
#endif
#ifdef WOLFSSL_CMAC
    WC_BCF(1, 30, WOLFSSL_CMAC)
#else
    WC_BCF_NO(1, 30, WOLFSSL_CMAC)
#endif
#ifdef HAVE_HKDF
    WC_BCF(1, 31, HAVE_HKDF)
#else
    WC_BCF_NO(1, 31, HAVE_HKDF)
#endif

/* ---- Feature word 2: TLS library layer ---- */
#ifdef WOLFCRYPT_ONLY
    WC_BCF(2, 0, WOLFCRYPT_ONLY)
#else
    WC_BCF_NO(2, 0, WOLFCRYPT_ONLY)
#endif
#ifdef NO_WOLFSSL_CLIENT
    WC_BCF(2, 1, NO_WOLFSSL_CLIENT)
#else
    WC_BCF_NO(2, 1, NO_WOLFSSL_CLIENT)
#endif
#ifdef NO_WOLFSSL_SERVER
    WC_BCF(2, 2, NO_WOLFSSL_SERVER)
#else
    WC_BCF_NO(2, 2, NO_WOLFSSL_SERVER)
#endif
#ifdef NO_TLS
    WC_BCF(2, 3, NO_TLS)
#else
    WC_BCF_NO(2, 3, NO_TLS)
#endif
#ifdef NO_OLD_TLS
    WC_BCF(2, 4, NO_OLD_TLS)
#else
    WC_BCF_NO(2, 4, NO_OLD_TLS)
#endif
/* Under NO_TLS, ssl.h defines WOLFSSL_NO_TLS12 and undefines WOLFSSL_TLS13
 * for the TLS layer, while the crypto layer keeps the configured values,
 * which decide whether the TLS KDFs are built. Record the crypto-layer
 * values, undoing ssl.h's change through its markers, so that the bits are
 * the same whether or not ssl.h was included first. */
#if defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_NO_TLS12_SET_BY_SSL_H)
    WC_BCF(2, 5, WOLFSSL_NO_TLS12)
#else
    WC_BCF_NO(2, 5, WOLFSSL_NO_TLS12)
#endif
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_TLS13_UNSET_BY_SSL_H)
    WC_BCF(2, 6, WOLFSSL_TLS13)
#else
    WC_BCF_NO(2, 6, WOLFSSL_TLS13)
#endif
#ifdef WOLFSSL_DTLS
    WC_BCF(2, 7, WOLFSSL_DTLS)
#else
    WC_BCF_NO(2, 7, WOLFSSL_DTLS)
#endif
#ifdef WOLFSSL_DTLS13
    WC_BCF(2, 8, WOLFSSL_DTLS13)
#else
    WC_BCF_NO(2, 8, WOLFSSL_DTLS13)
#endif
#ifdef WOLFSSL_DTLS_CID
    WC_BCF(2, 9, WOLFSSL_DTLS_CID)
#else
    WC_BCF_NO(2, 9, WOLFSSL_DTLS_CID)
#endif
#ifdef WOLFSSL_QUIC
    WC_BCF(2, 10, WOLFSSL_QUIC)
#else
    WC_BCF_NO(2, 10, WOLFSSL_QUIC)
#endif
#ifdef OPENSSL_EXTRA
    WC_BCF(2, 11, OPENSSL_EXTRA)
#else
    WC_BCF_NO(2, 11, OPENSSL_EXTRA)
#endif
#ifdef OPENSSL_EXTRA_X509_SMALL
    WC_BCF(2, 12, OPENSSL_EXTRA_X509_SMALL)
#else
    WC_BCF_NO(2, 12, OPENSSL_EXTRA_X509_SMALL)
#endif
#ifdef OPENSSL_ALL
    WC_BCF(2, 13, OPENSSL_ALL)
#else
    WC_BCF_NO(2, 13, OPENSSL_ALL)
#endif
#ifdef HAVE_EX_DATA
    WC_BCF(2, 15, HAVE_EX_DATA)
#else
    WC_BCF_NO(2, 15, HAVE_EX_DATA)
#endif
#ifdef NO_FILESYSTEM
    WC_BCF(2, 16, NO_FILESYSTEM)
#else
    WC_BCF_NO(2, 16, NO_FILESYSTEM)
#endif
#ifdef NO_SESSION_CACHE
    WC_BCF(2, 17, NO_SESSION_CACHE)
#else
    WC_BCF_NO(2, 17, NO_SESSION_CACHE)
#endif
#ifdef HAVE_EXT_CACHE
    WC_BCF(2, 18, HAVE_EXT_CACHE)
#else
    WC_BCF_NO(2, 18, HAVE_EXT_CACHE)
#endif
#ifdef HAVE_PK_CALLBACKS
    WC_BCF(2, 19, HAVE_PK_CALLBACKS)
#else
    WC_BCF_NO(2, 19, HAVE_PK_CALLBACKS)
#endif
#ifdef WOLFSSL_CALLBACKS
    WC_BCF(2, 20, WOLFSSL_CALLBACKS)
#else
    WC_BCF_NO(2, 20, WOLFSSL_CALLBACKS)
#endif
#ifdef HAVE_SECRET_CALLBACK
    WC_BCF(2, 21, HAVE_SECRET_CALLBACK)
#else
    WC_BCF_NO(2, 21, HAVE_SECRET_CALLBACK)
#endif
#ifdef WOLFSSL_CERT_SETUP_CB
    WC_BCF(2, 22, WOLFSSL_CERT_SETUP_CB)
#else
    WC_BCF_NO(2, 22, WOLFSSL_CERT_SETUP_CB)
#endif
#ifdef KEEP_PEER_CERT
    WC_BCF(2, 23, KEEP_PEER_CERT)
#else
    WC_BCF_NO(2, 23, KEEP_PEER_CERT)
#endif
#ifdef SESSION_CERTS
    WC_BCF(2, 24, SESSION_CERTS)
#else
    WC_BCF_NO(2, 24, SESSION_CERTS)
#endif
#ifdef WOLFSSL_SESSION_EXPORT
    WC_BCF(2, 25, WOLFSSL_SESSION_EXPORT)
#else
    WC_BCF_NO(2, 25, WOLFSSL_SESSION_EXPORT)
#endif
#ifdef HAVE_WRITE_DUP
    WC_BCF(2, 26, HAVE_WRITE_DUP)
#else
    WC_BCF_NO(2, 26, HAVE_WRITE_DUP)
#endif
/* wolfio.h defines this and WOLFSSL_NO_SOCK on some platforms, and
 * build_check.h includes wolfio.h only for TLS builds, where they matter. */
#if defined(WOLFSSL_USER_IO) && !defined(WOLFCRYPT_ONLY)
    WC_BCF(2, 27, WOLFSSL_USER_IO)
#else
    WC_BCF_NO(2, 27, WOLFSSL_USER_IO)
#endif
#if defined(WOLFSSL_NO_SOCK) && !defined(WOLFCRYPT_ONLY)
    WC_BCF(2, 28, WOLFSSL_NO_SOCK)
#else
    WC_BCF_NO(2, 28, WOLFSSL_NO_SOCK)
#endif
#ifdef WOLFSSL_SNIFFER
    WC_BCF(2, 29, WOLFSSL_SNIFFER)
#else
    WC_BCF_NO(2, 29, WOLFSSL_SNIFFER)
#endif
#ifdef WOLFSSL_WOLFSENTRY_HOOKS
    WC_BCF(2, 30, WOLFSSL_WOLFSENTRY_HOOKS)
#else
    WC_BCF_NO(2, 30, WOLFSSL_WOLFSENTRY_HOOKS)
#endif

/* Not TLS, but word 2 had room: changes the OpenSSL compat RC4 key layout. */
#ifdef WC_NO_PTR_INT_CAST
    WC_BCF(2, 31, WC_NO_PTR_INT_CAST)
#else
    WC_BCF_NO(2, 31, WC_NO_PTR_INT_CAST)
#endif

/* ---- Feature word 3: TLS extensions and PKI ---- */
#ifdef HAVE_SNI
    WC_BCF(3, 0, HAVE_SNI)
#else
    WC_BCF_NO(3, 0, HAVE_SNI)
#endif
#ifdef HAVE_ALPN
    WC_BCF(3, 1, HAVE_ALPN)
#else
    WC_BCF_NO(3, 1, HAVE_ALPN)
#endif
#ifdef HAVE_MAX_FRAGMENT
    WC_BCF(3, 2, HAVE_MAX_FRAGMENT)
#else
    WC_BCF_NO(3, 2, HAVE_MAX_FRAGMENT)
#endif
#ifdef HAVE_TRUNCATED_HMAC
    WC_BCF(3, 3, HAVE_TRUNCATED_HMAC)
#else
    WC_BCF_NO(3, 3, HAVE_TRUNCATED_HMAC)
#endif
#ifdef HAVE_SUPPORTED_CURVES
    WC_BCF(3, 4, HAVE_SUPPORTED_CURVES)
#else
    WC_BCF_NO(3, 4, HAVE_SUPPORTED_CURVES)
#endif
#ifdef HAVE_SESSION_TICKET
    WC_BCF(3, 5, HAVE_SESSION_TICKET)
#else
    WC_BCF_NO(3, 5, HAVE_SESSION_TICKET)
#endif
#ifdef HAVE_EXTENDED_MASTER
    WC_BCF(3, 6, HAVE_EXTENDED_MASTER)
#else
    WC_BCF_NO(3, 6, HAVE_EXTENDED_MASTER)
#endif
#ifdef HAVE_ENCRYPT_THEN_MAC
    WC_BCF(3, 7, HAVE_ENCRYPT_THEN_MAC)
#else
    WC_BCF_NO(3, 7, HAVE_ENCRYPT_THEN_MAC)
#endif
#ifdef HAVE_SECURE_RENEGOTIATION
    WC_BCF(3, 8, HAVE_SECURE_RENEGOTIATION)
#else
    WC_BCF_NO(3, 8, HAVE_SECURE_RENEGOTIATION)
#endif
#ifdef WOLFSSL_EARLY_DATA
    WC_BCF(3, 9, WOLFSSL_EARLY_DATA)
#else
    WC_BCF_NO(3, 9, WOLFSSL_EARLY_DATA)
#endif
#ifdef WOLFSSL_POST_HANDSHAKE_AUTH
    WC_BCF(3, 10, WOLFSSL_POST_HANDSHAKE_AUTH)
#else
    WC_BCF_NO(3, 10, WOLFSSL_POST_HANDSHAKE_AUTH)
#endif
#ifdef WOLFSSL_SRTP
    WC_BCF(3, 11, WOLFSSL_SRTP)
#else
    WC_BCF_NO(3, 11, WOLFSSL_SRTP)
#endif
#ifdef WOLFSSL_SCTP
    WC_BCF(3, 12, WOLFSSL_SCTP)
#else
    WC_BCF_NO(3, 12, WOLFSSL_SCTP)
#endif
#ifdef HAVE_OCSP
    WC_BCF(3, 13, HAVE_OCSP)
#else
    WC_BCF_NO(3, 13, HAVE_OCSP)
#endif
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
    WC_BCF(3, 14, HAVE_CERTIFICATE_STATUS_REQUEST)
#else
    WC_BCF_NO(3, 14, HAVE_CERTIFICATE_STATUS_REQUEST)
#endif
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    WC_BCF(3, 15, HAVE_CERTIFICATE_STATUS_REQUEST_V2)
#else
    WC_BCF_NO(3, 15, HAVE_CERTIFICATE_STATUS_REQUEST_V2)
#endif
#ifdef HAVE_CRL
    WC_BCF(3, 16, HAVE_CRL)
#else
    WC_BCF_NO(3, 16, HAVE_CRL)
#endif
#ifdef WOLFSSL_KEY_GEN
    WC_BCF(3, 17, WOLFSSL_KEY_GEN)
#else
    WC_BCF_NO(3, 17, WOLFSSL_KEY_GEN)
#endif
#ifdef WOLFSSL_CERT_GEN
    WC_BCF(3, 18, WOLFSSL_CERT_GEN)
#else
    WC_BCF_NO(3, 18, WOLFSSL_CERT_GEN)
#endif
#ifdef WOLFSSL_CERT_REQ
    WC_BCF(3, 19, WOLFSSL_CERT_REQ)
#else
    WC_BCF_NO(3, 19, WOLFSSL_CERT_REQ)
#endif
#ifdef WOLFSSL_CERT_EXT
    WC_BCF(3, 20, WOLFSSL_CERT_EXT)
#else
    WC_BCF_NO(3, 20, WOLFSSL_CERT_EXT)
#endif
#ifdef HAVE_PKCS7
    WC_BCF(3, 21, HAVE_PKCS7)
#else
    WC_BCF_NO(3, 21, HAVE_PKCS7)
#endif
#ifdef HAVE_PKCS12
    WC_BCF(3, 22, HAVE_PKCS12)
#else
    WC_BCF_NO(3, 22, HAVE_PKCS12)
#endif
#ifdef NO_PWDBASED
    WC_BCF(3, 23, NO_PWDBASED)
#else
    WC_BCF_NO(3, 23, NO_PWDBASED)
#endif

/* ---- Feature word 4: more algorithms ---- */
#ifdef HAVE_ARIA
    WC_BCF(4, 0, HAVE_ARIA)
#else
    WC_BCF_NO(4, 0, HAVE_ARIA)
#endif
#ifdef HAVE_CAMELLIA
    WC_BCF(4, 1, HAVE_CAMELLIA)
#else
    WC_BCF_NO(4, 1, HAVE_CAMELLIA)
#endif
#ifdef WOLFSSL_SM2
    WC_BCF(4, 2, WOLFSSL_SM2)
#else
    WC_BCF_NO(4, 2, WOLFSSL_SM2)
#endif
#ifdef WOLFSSL_SM3
    WC_BCF(4, 3, WOLFSSL_SM3)
#else
    WC_BCF_NO(4, 3, WOLFSSL_SM3)
#endif
#ifdef WOLFSSL_SM4
    WC_BCF(4, 4, WOLFSSL_SM4)
#else
    WC_BCF_NO(4, 4, WOLFSSL_SM4)
#endif
#ifdef WOLFSSL_HAVE_SLHDSA
    WC_BCF(4, 5, WOLFSSL_HAVE_SLHDSA)
#else
    WC_BCF_NO(4, 5, WOLFSSL_HAVE_SLHDSA)
#endif
#ifdef WOLFSSL_HAVE_LMS
    WC_BCF(4, 6, WOLFSSL_HAVE_LMS)
#else
    WC_BCF_NO(4, 6, WOLFSSL_HAVE_LMS)
#endif
#ifdef WOLFSSL_HAVE_XMSS
    WC_BCF(4, 7, WOLFSSL_HAVE_XMSS)
#else
    WC_BCF_NO(4, 7, WOLFSSL_HAVE_XMSS)
#endif
#ifdef HAVE_FALCON
    WC_BCF(4, 8, HAVE_FALCON)
#else
    WC_BCF_NO(4, 8, HAVE_FALCON)
#endif
#ifdef WOLFSSL_HAVE_FRODOKEM
    WC_BCF(4, 9, WOLFSSL_HAVE_FRODOKEM)
#else
    WC_BCF_NO(4, 9, WOLFSSL_HAVE_FRODOKEM)
#endif
#ifdef HAVE_BLAKE2B
    WC_BCF(4, 10, HAVE_BLAKE2B)
#else
    WC_BCF_NO(4, 10, HAVE_BLAKE2B)
#endif
#ifdef HAVE_BLAKE2S
    WC_BCF(4, 11, HAVE_BLAKE2S)
#else
    WC_BCF_NO(4, 11, HAVE_BLAKE2S)
#endif
#ifdef WOLFSSL_RIPEMD
    WC_BCF(4, 12, WOLFSSL_RIPEMD)
#else
    WC_BCF_NO(4, 12, WOLFSSL_RIPEMD)
#endif
#ifdef WOLFSSL_SHAKE128
    WC_BCF(4, 13, WOLFSSL_SHAKE128)
#else
    WC_BCF_NO(4, 13, WOLFSSL_SHAKE128)
#endif
#ifdef WOLFSSL_SHAKE256
    WC_BCF(4, 14, WOLFSSL_SHAKE256)
#else
    WC_BCF_NO(4, 14, WOLFSSL_SHAKE256)
#endif
#ifdef HAVE_XCHACHA
    WC_BCF(4, 15, HAVE_XCHACHA)
#else
    WC_BCF_NO(4, 15, HAVE_XCHACHA)
#endif
#ifdef WOLFSSL_AES_SIV
    WC_BCF(4, 16, WOLFSSL_AES_SIV)
#else
    WC_BCF_NO(4, 16, WOLFSSL_AES_SIV)
#endif
#ifdef WOLFSSL_AES_EAX
    WC_BCF(4, 17, WOLFSSL_AES_EAX)
#else
    WC_BCF_NO(4, 17, WOLFSSL_AES_EAX)
#endif
#ifdef HAVE_AES_KEYWRAP
    WC_BCF(4, 18, HAVE_AES_KEYWRAP)
#else
    WC_BCF_NO(4, 18, HAVE_AES_KEYWRAP)
#endif
#ifdef HAVE_AES_ECB
    WC_BCF(4, 19, HAVE_AES_ECB)
#else
    WC_BCF_NO(4, 19, HAVE_AES_ECB)
#endif
#ifdef WOLFSSL_AESGCM_STREAM
    WC_BCF(4, 20, WOLFSSL_AESGCM_STREAM)
#else
    WC_BCF_NO(4, 20, WOLFSSL_AESGCM_STREAM)
#endif
#ifdef NO_DSA
    WC_BCF(4, 21, NO_DSA)
#else
    WC_BCF_NO(4, 21, NO_DSA)
#endif
#ifdef NO_RC4
    WC_BCF(4, 22, NO_RC4)
#else
    WC_BCF_NO(4, 22, NO_RC4)
#endif
#ifdef NO_MD4
    WC_BCF(4, 23, NO_MD4)
#else
    WC_BCF_NO(4, 23, NO_MD4)
#endif
#ifdef WOLFSSL_MD2
    WC_BCF(4, 24, WOLFSSL_MD2)
#else
    WC_BCF_NO(4, 24, WOLFSSL_MD2)
#endif
#ifdef HAVE_ECC_ENCRYPT
    WC_BCF(4, 25, HAVE_ECC_ENCRYPT)
#else
    WC_BCF_NO(4, 25, HAVE_ECC_ENCRYPT)
#endif
#ifdef HAVE_COMP_KEY
    WC_BCF(4, 26, HAVE_COMP_KEY)
#else
    WC_BCF_NO(4, 26, HAVE_COMP_KEY)
#endif
#ifdef WOLFSSL_CUSTOM_CURVES
    WC_BCF(4, 27, WOLFSSL_CUSTOM_CURVES)
#else
    WC_BCF_NO(4, 27, WOLFSSL_CUSTOM_CURVES)
#endif
#ifdef HAVE_X963_KDF
    WC_BCF(4, 28, HAVE_X963_KDF)
#else
    WC_BCF_NO(4, 28, HAVE_X963_KDF)
#endif
#ifdef WC_SRTP_KDF
    WC_BCF(4, 29, WC_SRTP_KDF)
#else
    WC_BCF_NO(4, 29, WC_SRTP_KDF)
#endif
#ifdef WOLFSSL_SIPHASH
    WC_BCF(4, 30, WOLFSSL_SIPHASH)
#else
    WC_BCF_NO(4, 30, WOLFSSL_SIPHASH)
#endif
#ifdef HAVE_HPKE
    WC_BCF(4, 31, HAVE_HPKE)
#else
    WC_BCF_NO(4, 31, HAVE_HPKE)
#endif

/* ---- Feature word 5: more TLS, PKI and platform ---- */
#ifdef HAVE_ECH
    WC_BCF(5, 0, HAVE_ECH)
#else
    WC_BCF_NO(5, 0, HAVE_ECH)
#endif
#ifdef WOLFSSL_DTLS_CH_FRAG
    WC_BCF(5, 1, WOLFSSL_DTLS_CH_FRAG)
#else
    WC_BCF_NO(5, 1, WOLFSSL_DTLS_CH_FRAG)
#endif
#ifdef WOLFSSL_SEND_HRR_COOKIE
    WC_BCF(5, 2, WOLFSSL_SEND_HRR_COOKIE)
#else
    WC_BCF_NO(5, 2, WOLFSSL_SEND_HRR_COOKIE)
#endif
#ifdef HAVE_TRUSTED_CA
    WC_BCF(5, 3, HAVE_TRUSTED_CA)
#else
    WC_BCF_NO(5, 3, HAVE_TRUSTED_CA)
#endif
#ifdef HAVE_RPK
    WC_BCF(5, 4, HAVE_RPK)
#else
    WC_BCF_NO(5, 4, HAVE_RPK)
#endif
#ifdef WOLFSSL_DUAL_ALG_CERTS
    WC_BCF(5, 5, WOLFSSL_DUAL_ALG_CERTS)
#else
    WC_BCF_NO(5, 5, WOLFSSL_DUAL_ALG_CERTS)
#endif
#ifdef WOLFSSL_STATIC_EPHEMERAL
    WC_BCF(5, 6, WOLFSSL_STATIC_EPHEMERAL)
#else
    WC_BCF_NO(5, 6, WOLFSSL_STATIC_EPHEMERAL)
#endif
#ifdef HAVE_FFDHE
    WC_BCF(5, 7, HAVE_FFDHE)
#else
    WC_BCF_NO(5, 7, HAVE_FFDHE)
#endif
#ifdef WOLFSSL_WPAS_SMALL
    WC_BCF(5, 8, WOLFSSL_WPAS_SMALL)
#else
    WC_BCF_NO(5, 8, WOLFSSL_WPAS_SMALL)
#endif
#ifdef HAVE_CURL
    WC_BCF(5, 9, HAVE_CURL)
#else
    WC_BCF_NO(5, 9, HAVE_CURL)
#endif
#ifdef WOLFSSL_ALT_CERT_CHAINS
    WC_BCF(5, 10, WOLFSSL_ALT_CERT_CHAINS)
#else
    WC_BCF_NO(5, 10, WOLFSSL_ALT_CERT_CHAINS)
#endif
#ifdef WOLFSSL_ENCRYPTED_KEYS
    WC_BCF(5, 11, WOLFSSL_ENCRYPTED_KEYS)
#else
    WC_BCF_NO(5, 11, WOLFSSL_ENCRYPTED_KEYS)
#endif
#ifdef WOLFSSL_CERT_NAME_ALL
    WC_BCF(5, 12, WOLFSSL_CERT_NAME_ALL)
#else
    WC_BCF_NO(5, 12, WOLFSSL_CERT_NAME_ALL)
#endif
#ifdef WOLFSSL_CUSTOM_OID
    WC_BCF(5, 13, WOLFSSL_CUSTOM_OID)
#else
    WC_BCF_NO(5, 13, WOLFSSL_CUSTOM_OID)
#endif
#ifdef WOLFSSL_SYS_CA_CERTS
    WC_BCF(5, 14, WOLFSSL_SYS_CA_CERTS)
#else
    WC_BCF_NO(5, 14, WOLFSSL_SYS_CA_CERTS)
#endif
#ifdef HAVE_CRL_IO
    WC_BCF(5, 15, HAVE_CRL_IO)
#else
    WC_BCF_NO(5, 15, HAVE_CRL_IO)
#endif
#ifdef HAVE_PKCS8
    WC_BCF(5, 16, HAVE_PKCS8)
#else
    WC_BCF_NO(5, 16, HAVE_PKCS8)
#endif
/* internal.h defines WOLFSSL_TICKET_HAVE_ID itself with early data and
 * session tickets; record the value it leaves, whether or not internal.h
 * was included. */
#if defined(WOLFSSL_TICKET_HAVE_ID) || \
    (defined(WOLFSSL_EARLY_DATA) && defined(HAVE_SESSION_TICKET))
    WC_BCF(5, 17, WOLFSSL_TICKET_HAVE_ID)
#else
    WC_BCF_NO(5, 17, WOLFSSL_TICKET_HAVE_ID)
#endif
#ifdef HAVE_OCSP_RESPONDER
    WC_BCF(5, 18, HAVE_OCSP_RESPONDER)
#else
    WC_BCF_NO(5, 18, HAVE_OCSP_RESPONDER)
#endif
#ifdef WOLFSSL_MULTICAST
    WC_BCF(5, 19, WOLFSSL_MULTICAST)
#else
    WC_BCF_NO(5, 19, WOLFSSL_MULTICAST)
#endif
/* ssl.h defines it with OPENSSL_ALL and DTLS. */
#if defined(WOLFSSL_DTLS_MTU) || \
    (defined(OPENSSL_ALL) && defined(WOLFSSL_DTLS))
    WC_BCF(5, 20, WOLFSSL_DTLS_MTU)
#else
    WC_BCF_NO(5, 20, WOLFSSL_DTLS_MTU)
#endif
#ifdef NO_CERTS
    WC_BCF(5, 21, NO_CERTS)
#else
    WC_BCF_NO(5, 21, NO_CERTS)
#endif
#ifdef NO_PSK
    WC_BCF(5, 22, NO_PSK)
#else
    WC_BCF_NO(5, 22, NO_PSK)
#endif
#ifdef WOLFSSL_ACERT
    WC_BCF(5, 23, WOLFSSL_ACERT)
#else
    WC_BCF_NO(5, 23, WOLFSSL_ACERT)
#endif
#ifdef HAVE_KEYING_MATERIAL
    WC_BCF(5, 24, HAVE_KEYING_MATERIAL)
#else
    WC_BCF_NO(5, 24, HAVE_KEYING_MATERIAL)
#endif
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    WC_BCF(5, 25, WOLFSSL_HAVE_TLS_UNIQUE)
#else
    WC_BCF_NO(5, 25, WOLFSSL_HAVE_TLS_UNIQUE)
#endif
#ifdef HAVE_PKCS11
    WC_BCF(5, 26, HAVE_PKCS11)
#else
    WC_BCF_NO(5, 26, HAVE_PKCS11)
#endif
#ifdef WOLFSSL_EITHER_SIDE
    WC_BCF(5, 27, WOLFSSL_EITHER_SIDE)
#else
    WC_BCF_NO(5, 27, WOLFSSL_EITHER_SIDE)
#endif
#ifdef WOLFSSL_ATOMIC_OPS
    WC_BCF(5, 28, WOLFSSL_ATOMIC_OPS)
#else
    WC_BCF_NO(5, 28, WOLFSSL_ATOMIC_OPS)
#endif
#ifdef HAVE_THREAD_LS
    WC_BCF(5, 29, HAVE_THREAD_LS)
#else
    WC_BCF_NO(5, 29, HAVE_THREAD_LS)
#endif
#ifdef WC_RNG_SEED_CB
    WC_BCF(5, 30, WC_RNG_SEED_CB)
#else
    WC_BCF_NO(5, 30, WC_RNG_SEED_CB)
#endif
#ifdef WOLFSSL_TSP
    WC_BCF(5, 31, WOLFSSL_TSP)
#else
    WC_BCF_NO(5, 31, WOLFSSL_TSP)
#endif

/* ---- Feature word 6: macros that guard only bitfields or single bytes in
 * sized structs. Such a member can fit into existing padding, so the
 * struct's size does not change and only a feature bit tells the builds
 * apart. ---- */
#ifdef IGNORE_NAME_CONSTRAINTS
    WC_BCF(6, 0, IGNORE_NAME_CONSTRAINTS)
#else
    WC_BCF_NO(6, 0, IGNORE_NAME_CONSTRAINTS)
#endif
#ifdef IGNORE_NETSCAPE_CERT_TYPE
    WC_BCF(6, 1, IGNORE_NETSCAPE_CERT_TYPE)
#else
    WC_BCF_NO(6, 1, IGNORE_NETSCAPE_CERT_TYPE)
#endif
#ifdef USE_INTEL_SPEEDUP
    WC_BCF(6, 2, USE_INTEL_SPEEDUP)
#else
    WC_BCF_NO(6, 2, USE_INTEL_SPEEDUP)
#endif
#ifdef WC_SLHDSA_NEED_SHA512
    WC_BCF(6, 3, WC_SLHDSA_NEED_SHA512)
#else
    WC_BCF_NO(6, 3, WC_SLHDSA_NEED_SHA512)
#endif
#ifdef WOLFSSL_AKID_NAME
    WC_BCF(6, 4, WOLFSSL_AKID_NAME)
#else
    WC_BCF_NO(6, 4, WOLFSSL_AKID_NAME)
#endif
#ifdef WOLFSSL_ALLOW_ENCODING_CA_FALSE
    WC_BCF(6, 5, WOLFSSL_ALLOW_ENCODING_CA_FALSE)
#else
    WC_BCF_NO(6, 5, WOLFSSL_ALLOW_ENCODING_CA_FALSE)
#endif
#ifdef WOLFSSL_ALT_NAMES
    WC_BCF(6, 6, WOLFSSL_ALT_NAMES)
#else
    WC_BCF_NO(6, 6, WOLFSSL_ALT_NAMES)
#endif
/* aes.h derives it; build_check.h includes aes.h only without NO_AES. */
#if defined(WOLFSSL_ARM32_AES_HW_FLAGS) || \
    (defined(WOLFSSL_ARMASM) && !defined(__aarch64__) && \
     !defined(WOLFSSL_ARMASM_THUMB2) && \
     !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO) && \
     !defined(WOLFSSL_ARMASM_NO_BASE_IMPL))
    WC_BCF(6, 7, WOLFSSL_ARM32_AES_HW_FLAGS)
#else
    WC_BCF_NO(6, 7, WOLFSSL_ARM32_AES_HW_FLAGS)
#endif
#ifdef WOLFSSL_ARMASM_NO_HW_CRYPTO
    WC_BCF(6, 8, WOLFSSL_ARMASM_NO_HW_CRYPTO)
#else
    WC_BCF_NO(6, 8, WOLFSSL_ARMASM_NO_HW_CRYPTO)
#endif
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED
    WC_BCF(6, 9, WOLFSSL_CHACHA20_POLY1305_FUSED)
#else
    WC_BCF_NO(6, 9, WOLFSSL_CHACHA20_POLY1305_FUSED)
#endif
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    WC_BCF(6, 10, WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA)
#else
    WC_BCF_NO(6, 10, WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA)
#endif
#ifdef WOLFSSL_LMS_NO_SIG_CACHE
    WC_BCF(6, 11, WOLFSSL_LMS_NO_SIG_CACHE)
#else
    WC_BCF_NO(6, 11, WOLFSSL_LMS_NO_SIG_CACHE)
#endif
#ifdef WOLFSSL_LMS_VERIFY_ONLY
    WC_BCF(6, 12, WOLFSSL_LMS_VERIFY_ONLY)
#else
    WC_BCF_NO(6, 12, WOLFSSL_LMS_VERIFY_ONLY)
#endif
#ifdef WOLFSSL_MICROCHIP_TA100
    WC_BCF(6, 13, WOLFSSL_MICROCHIP_TA100)
#else
    WC_BCF_NO(6, 13, WOLFSSL_MICROCHIP_TA100)
#endif
#if defined(WOLFSSL_MLDSA_ASSIGN_KEY) || \
    (!defined(WOLFSSL_NO_DILITHIUM_LEGACY_GATES) && \
     defined(WOLFSSL_DILITHIUM_ASSIGN_KEY))
    WC_BCF(6, 14, WOLFSSL_MLDSA_ASSIGN_KEY)
#else
    WC_BCF_NO(6, 14, WOLFSSL_MLDSA_ASSIGN_KEY)
#endif
/* dilithium.h maps the legacy WOLFSSL_DILITHIUM_* names. */
#if defined(WOLFSSL_MLDSA_DYNAMIC_KEYS) || \
    (!defined(WOLFSSL_NO_DILITHIUM_LEGACY_GATES) && \
     defined(WOLFSSL_DILITHIUM_DYNAMIC_KEYS))
    WC_BCF(6, 15, WOLFSSL_MLDSA_DYNAMIC_KEYS)
#else
    WC_BCF_NO(6, 15, WOLFSSL_MLDSA_DYNAMIC_KEYS)
#endif
#ifdef WOLFSSL_RENESAS_FSPSM_TLS
    WC_BCF(6, 16, WOLFSSL_RENESAS_FSPSM_TLS)
#else
    WC_BCF_NO(6, 16, WOLFSSL_RENESAS_FSPSM_TLS)
#endif
#ifdef WOLFSSL_RENESAS_TSIP
    WC_BCF(6, 17, WOLFSSL_RENESAS_TSIP)
#else
    WC_BCF_NO(6, 17, WOLFSSL_RENESAS_TSIP)
#endif
#ifdef WOLFSSL_RSA_VERIFY_INLINE
    WC_BCF(6, 18, WOLFSSL_RSA_VERIFY_INLINE)
#else
    WC_BCF_NO(6, 18, WOLFSSL_RSA_VERIFY_INLINE)
#endif
#ifdef WOLFSSL_RSA_VERIFY_ONLY
    WC_BCF(6, 19, WOLFSSL_RSA_VERIFY_ONLY)
#else
    WC_BCF_NO(6, 19, WOLFSSL_RSA_VERIFY_ONLY)
#endif
#ifdef WOLFSSL_SE050
    WC_BCF(6, 20, WOLFSSL_SE050)
#else
    WC_BCF_NO(6, 20, WOLFSSL_SE050)
#endif
#ifdef WOLFSSL_SEP
    WC_BCF(6, 21, WOLFSSL_SEP)
#else
    WC_BCF_NO(6, 21, WOLFSSL_SEP)
#endif
#ifdef WOLFSSL_SM4_CCM
    WC_BCF(6, 22, WOLFSSL_SM4_CCM)
#else
    WC_BCF_NO(6, 22, WOLFSSL_SM4_CCM)
#endif
#ifdef WOLFSSL_SM4_GCM
    WC_BCF(6, 23, WOLFSSL_SM4_GCM)
#else
    WC_BCF_NO(6, 23, WOLFSSL_SM4_GCM)
#endif
#ifdef WOLFSSL_SUBJ_DIR_ATTR
    WC_BCF(6, 24, WOLFSSL_SUBJ_DIR_ATTR)
#else
    WC_BCF_NO(6, 24, WOLFSSL_SUBJ_DIR_ATTR)
#endif
#ifdef WOLFSSL_SUBJ_INFO_ACC
    WC_BCF(6, 25, WOLFSSL_SUBJ_INFO_ACC)
#else
    WC_BCF_NO(6, 25, WOLFSSL_SUBJ_INFO_ACC)
#endif
#ifdef WOLFSSL_WOLFSSH
    WC_BCF(6, 26, WOLFSSL_WOLFSSH)
#else
    WC_BCF_NO(6, 26, WOLFSSL_WOLFSSH)
#endif

/* ---- Word 7 (and word 6 bit 27): macros guarding members narrower than
 * 8 bytes (int, word32, ...), which can sit in padding before an
 * 8-byte-aligned member without changing sizeof() but move the members
 * after them. Alphabetical. */
#ifdef ALT_ECC_SIZE
    WC_BCF(7, 0, ALT_ECC_SIZE)
#else
    WC_BCF_NO(7, 0, ALT_ECC_SIZE)
#endif
#ifdef HAVE_CAVIUM_OCTEON_SYNC
    WC_BCF(7, 1, HAVE_CAVIUM_OCTEON_SYNC)
#else
    WC_BCF_NO(7, 1, HAVE_CAVIUM_OCTEON_SYNC)
#endif
#ifdef HAVE_GETPID
    WC_BCF(7, 2, HAVE_GETPID)
#else
    WC_BCF_NO(7, 2, HAVE_GETPID)
#endif
#ifdef HAVE_WOLF_BIGINT
    WC_BCF(7, 3, HAVE_WOLF_BIGINT)
#else
    WC_BCF_NO(7, 3, HAVE_WOLF_BIGINT)
#endif
#ifdef WC_ASN_NO_HEAP
    WC_BCF(7, 4, WC_ASN_NO_HEAP)
#else
    WC_BCF_NO(7, 4, WC_ASN_NO_HEAP)
#endif
#ifdef WC_RNG_BANK_HAVE_INST_OP_GATE
    WC_BCF(7, 5, WC_RNG_BANK_HAVE_INST_OP_GATE)
#else
    WC_BCF_NO(7, 5, WC_RNG_BANK_HAVE_INST_OP_GATE)
#endif
#ifdef WC_RNG_DEBUG_STATS
    WC_BCF(7, 6, WC_RNG_DEBUG_STATS)
#else
    WC_BCF_NO(7, 6, WC_RNG_DEBUG_STATS)
#endif
#ifdef WC_RNG_HAVE_AUTO_LOCK
    WC_BCF(7, 7, WC_RNG_HAVE_AUTO_LOCK)
#else
    WC_BCF_NO(7, 7, WC_RNG_HAVE_AUTO_LOCK)
#endif
#ifdef WC_RNG_HAVE_ENTROPY_EPOCH
    WC_BCF(7, 8, WC_RNG_HAVE_ENTROPY_EPOCH)
#else
    WC_BCF_NO(7, 8, WC_RNG_HAVE_ENTROPY_EPOCH)
#endif
#ifdef WC_RNG_HAVE_LOCK
    WC_BCF(7, 9, WC_RNG_HAVE_LOCK)
#else
    WC_BCF_NO(7, 9, WC_RNG_HAVE_LOCK)
#endif
#ifdef WC_RNG_HAVE_LOCK_FULL_MUTEX
    WC_BCF(7, 10, WC_RNG_HAVE_LOCK_FULL_MUTEX)
#else
    WC_BCF_NO(7, 10, WC_RNG_HAVE_LOCK_FULL_MUTEX)
#endif
#ifdef WC_RNG_HAVE_NEXT_SEED
    WC_BCF(7, 11, WC_RNG_HAVE_NEXT_SEED)
#else
    WC_BCF_NO(7, 11, WC_RNG_HAVE_NEXT_SEED)
#endif
#ifdef WC_RNG_HAVE_RBGC
    WC_BCF(7, 12, WC_RNG_HAVE_RBGC)
#else
    WC_BCF_NO(7, 12, WC_RNG_HAVE_RBGC)
#endif
#ifdef WC_RNG_LOCK_ATFORK
    WC_BCF(7, 13, WC_RNG_LOCK_ATFORK)
#else
    WC_BCF_NO(7, 13, WC_RNG_LOCK_ATFORK)
#endif
#ifdef WC_RSA_NONBLOCK_TIME
    WC_BCF(7, 14, WC_RSA_NONBLOCK_TIME)
#else
    WC_BCF_NO(7, 14, WC_RSA_NONBLOCK_TIME)
#endif
#ifdef WOLFSSL_AES_CTS
    WC_BCF(7, 15, WOLFSSL_AES_CTS)
#else
    WC_BCF_NO(7, 15, WOLFSSL_AES_CTS)
#endif
#ifdef WOLFSSL_AFALG_XILINX_RSA
    WC_BCF(7, 16, WOLFSSL_AFALG_XILINX_RSA)
#else
    WC_BCF_NO(7, 16, WOLFSSL_AFALG_XILINX_RSA)
#endif
#ifdef WOLFSSL_APACHE_HTTPD
    WC_BCF(7, 17, WOLFSSL_APACHE_HTTPD)
#else
    WC_BCF_NO(7, 17, WOLFSSL_APACHE_HTTPD)
#endif
#ifdef WOLFSSL_CAAM
    WC_BCF(7, 18, WOLFSSL_CAAM)
#else
    WC_BCF_NO(7, 18, WOLFSSL_CAAM)
#endif
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    WC_BCF(7, 19, WOLFSSL_ECDSA_DETERMINISTIC_K)
#else
    WC_BCF_NO(7, 19, WOLFSSL_ECDSA_DETERMINISTIC_K)
#endif
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT
    WC_BCF(7, 20, WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
#else
    WC_BCF_NO(7, 20, WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
#endif
#ifdef WOLFSSL_FPKI
    WC_BCF(7, 21, WOLFSSL_FPKI)
#else
    WC_BCF_NO(7, 21, WOLFSSL_FPKI)
#endif
#ifdef WOLFSSL_HASH_FLAGS
    WC_BCF(7, 22, WOLFSSL_HASH_FLAGS)
#else
    WC_BCF_NO(7, 22, WOLFSSL_HASH_FLAGS)
#endif
#ifdef WOLFSSL_MAXQ10XX_TLS
    WC_BCF(7, 23, WOLFSSL_MAXQ10XX_TLS)
#else
    WC_BCF_NO(7, 23, WOLFSSL_MAXQ10XX_TLS)
#endif
#ifdef WOLFSSL_MLKEM_DYNAMIC_KEYS
    WC_BCF(7, 24, WOLFSSL_MLKEM_DYNAMIC_KEYS)
#else
    WC_BCF_NO(7, 24, WOLFSSL_MLKEM_DYNAMIC_KEYS)
#endif
#ifdef WOLFSSL_NO_GETPID
    WC_BCF(7, 25, WOLFSSL_NO_GETPID)
#else
    WC_BCF_NO(7, 25, WOLFSSL_NO_GETPID)
#endif
#ifdef WOLFSSL_PUF_TEST
    WC_BCF(7, 26, WOLFSSL_PUF_TEST)
#else
    WC_BCF_NO(7, 26, WOLFSSL_PUF_TEST)
#endif
#ifdef WOLFSSL_SHA512_HASHTYPE
    WC_BCF(7, 27, WOLFSSL_SHA512_HASHTYPE)
#else
    WC_BCF_NO(7, 27, WOLFSSL_SHA512_HASHTYPE)
#endif
#ifdef WOLFSSL_SP_FAST_MODEXP
    WC_BCF(7, 28, WOLFSSL_SP_FAST_MODEXP)
#else
    WC_BCF_NO(7, 28, WOLFSSL_SP_FAST_MODEXP)
#endif
/* sp_int.h defines it with OPENSSL_EXTRA and ASN, but build_check.h only
 * reaches sp_int.h in SP math builds. */
#if defined(WOLFSSL_SP_INT_NEGATIVE) || \
    (defined(OPENSSL_EXTRA) && !defined(NO_ASN))
    WC_BCF(7, 29, WOLFSSL_SP_INT_NEGATIVE)
#else
    WC_BCF_NO(7, 29, WOLFSSL_SP_INT_NEGATIVE)
#endif
#ifdef WOLFSSL_SP_NONBLOCK
    WC_BCF(7, 30, WOLFSSL_SP_NONBLOCK)
#else
    WC_BCF_NO(7, 30, WOLFSSL_SP_NONBLOCK)
#endif
#ifdef WOLFSSL_SP_SMALL
    WC_BCF(7, 31, WOLFSSL_SP_SMALL)
#else
    WC_BCF_NO(7, 31, WOLFSSL_SP_SMALL)
#endif
#ifdef WOLF_CRYPTO_CB_SHAKE_XOF
    WC_BCF(6, 27, WOLF_CRYPTO_CB_SHAKE_XOF)
#else
    WC_BCF_NO(6, 27, WOLF_CRYPTO_CB_SHAKE_XOF)
#endif

/* ---- Struct sizes ----
 * Slots 0-15: platform basics and wolfCrypt. Slots 16-31: OpenSSL
 * compatibility layer (only with OPENSSL_EXTRA and the TLS library, except
 * slot 25, WOLFSSL_X509_STORE_CTX, recorded in every TLS build).
 * Slots 32-47: more wolfCrypt.
 * Slots 48-63: structs applications allocate or read fields of, found by
 * .github/scripts/check-build-config-list.py (certificates, PKCS#7, crypto
 * callback info, non-blocking contexts, ...).
 * Slots 64-67: driver contexts applications allocate and hand to an init
 * function (PKCS#11 device, PUF, SHE, RNG bank).
 * Slots 68-70: DNS_entry (alt-name list node apps walk), mp_digit and
 * DIGIT_BIT (the math radix, which heap-math mp_int sizes do not show).
 * The library's WOLFSSL and WOLFSSL_CTX are opaque to applications (only
 * defined in internal.h) and so are not part of this check. */
    WC_BCS(0, void*)
    WC_BCS(1, long)
    WC_BCS(2, size_t)
#ifndef WC_NO_RNG
    WC_BCS(3, WC_RNG)
#else
    WC_BCS_NO(3, WC_RNG)
#endif
#ifndef NO_BIG_INT
    WC_BCS(4, mp_int)
#else
    WC_BCS_NO(4, mp_int)
#endif
#ifndef NO_AES
    WC_BCS(5, Aes)
#else
    WC_BCS_NO(5, Aes)
#endif
#ifndef NO_RSA
    WC_BCS(6, RsaKey)
#else
    WC_BCS_NO(6, RsaKey)
#endif
#ifdef HAVE_ECC
    WC_BCS(7, ecc_key)
#else
    WC_BCS_NO(7, ecc_key)
#endif
#ifndef NO_DH
    WC_BCS(8, DhKey)
#else
    WC_BCS_NO(8, DhKey)
#endif
#ifndef NO_SHA256
    WC_BCS(9, wc_Sha256)
#else
    WC_BCS_NO(9, wc_Sha256)
#endif
#if (defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384))
    WC_BCS(10, wc_Sha512)
#else
    WC_BCS_NO(10, wc_Sha512)
#endif
#ifndef NO_HMAC
    WC_BCS(11, Hmac)
#else
    WC_BCS_NO(11, Hmac)
#endif
#ifdef HAVE_CURVE25519
    WC_BCS(12, curve25519_key)
#else
    WC_BCS_NO(12, curve25519_key)
#endif
#ifdef HAVE_ED25519
    WC_BCS(13, ed25519_key)
#else
    WC_BCS_NO(13, ed25519_key)
#endif
#ifdef WOLFSSL_HAVE_MLKEM
    WC_BCS(14, MlKemKey)
#else
    WC_BCS_NO(14, MlKemKey)
#endif
#ifdef WOLFSSL_SHA3
    WC_BCS(15, wc_Sha3)
#else
    WC_BCS_NO(15, wc_Sha3)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    WC_BCS(16, struct WOLFSSL_EVP_MD_CTX)
#else
    WC_BCS_NO(16, struct WOLFSSL_EVP_MD_CTX)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    WC_BCS(17, struct WOLFSSL_EVP_CIPHER_CTX)
#else
    WC_BCS_NO(17, struct WOLFSSL_EVP_CIPHER_CTX)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY) && !defined(NO_HMAC)
    WC_BCS(18, struct WOLFSSL_HMAC_CTX)
#else
    WC_BCS_NO(18, struct WOLFSSL_HMAC_CTX)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY) && !defined(NO_SHA)
    WC_BCS(19, struct WOLFSSL_SHA_CTX)
#else
    WC_BCS_NO(19, struct WOLFSSL_SHA_CTX)
#endif
#if defined(OPENSSL_EXTRA) && \
    !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_SHA224)
    WC_BCS(20, struct WOLFSSL_SHA224_CTX)
#else
    WC_BCS_NO(20, struct WOLFSSL_SHA224_CTX)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY) && !defined(NO_SHA256)
    WC_BCS(21, struct WOLFSSL_SHA256_CTX)
#else
    WC_BCS_NO(21, struct WOLFSSL_SHA256_CTX)
#endif
#if defined(OPENSSL_EXTRA) && \
    !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_SHA512)
    WC_BCS(22, struct WOLFSSL_SHA512_CTX)
#else
    WC_BCS_NO(22, struct WOLFSSL_SHA512_CTX)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY) && defined(WOLFSSL_SHA3)
    WC_BCS(23, struct WOLFSSL_SHA3_CTX)
#else
    WC_BCS_NO(23, struct WOLFSSL_SHA3_CTX)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY) && !defined(NO_MD5)
    WC_BCS(24, struct WOLFSSL_MD5_CTX)
#else
    WC_BCS_NO(24, struct WOLFSSL_MD5_CTX)
#endif
#ifndef WOLFCRYPT_ONLY
    /* Not compat-only: verify callbacks read it in every TLS build. */
    WC_BCS(25, struct WOLFSSL_X509_STORE_CTX)
#else
    WC_BCS_NO(25, struct WOLFSSL_X509_STORE_CTX)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    WC_BCS(26, struct WOLFSSL_EVP_PKEY)
#else
    WC_BCS_NO(26, struct WOLFSSL_EVP_PKEY)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    WC_BCS(27, struct WOLFSSL_ASN1_STRING)
#else
    WC_BCS_NO(27, struct WOLFSSL_ASN1_STRING)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    WC_BCS(28, struct WOLFSSL_ASN1_OBJECT)
#else
    WC_BCS_NO(28, struct WOLFSSL_ASN1_OBJECT)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
    WC_BCS(29, struct WOLFSSL_BIGNUM)
#else
    WC_BCS_NO(29, struct WOLFSSL_BIGNUM)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY) && !defined(NO_RSA)
    WC_BCS(30, struct WOLFSSL_RSA)
#else
    WC_BCS_NO(30, struct WOLFSSL_RSA)
#endif
#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY) && defined(HAVE_ECC)
    WC_BCS(31, struct WOLFSSL_EC_KEY)
#else
    WC_BCS_NO(31, struct WOLFSSL_EC_KEY)
#endif
#ifndef NO_SHA
    WC_BCS(32, wc_Sha)
#else
    WC_BCS_NO(32, wc_Sha)
#endif
#ifndef NO_MD5
    WC_BCS(33, wc_Md5)
#else
    WC_BCS_NO(33, wc_Md5)
#endif
#ifndef NO_DES3
    WC_BCS(34, Des3)
#else
    WC_BCS_NO(34, Des3)
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && \
    (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    WC_BCS(35, Cmac)
#else
    WC_BCS_NO(35, Cmac)
#endif
#ifdef HAVE_CHACHA
    WC_BCS(36, ChaCha)
#else
    WC_BCS_NO(36, ChaCha)
#endif
#ifdef HAVE_POLY1305
    WC_BCS(37, Poly1305)
#else
    WC_BCS_NO(37, Poly1305)
#endif
#if defined(HAVE_AESGCM) && !defined(NO_AES) && \
    (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    WC_BCS(38, Gmac)
#else
    WC_BCS_NO(38, Gmac)
#endif
#ifndef NO_DSA
    WC_BCS(39, DsaKey)
#else
    WC_BCS_NO(39, DsaKey)
#endif
#ifdef HAVE_ED448
    WC_BCS(40, ed448_key)
#else
    WC_BCS_NO(40, ed448_key)
#endif
#ifdef HAVE_CURVE448
    WC_BCS(41, curve448_key)
#else
    WC_BCS_NO(41, curve448_key)
#endif
#ifdef WOLFSSL_HAVE_MLDSA
    WC_BCS(42, struct wc_MlDsaKey)
#else
    WC_BCS_NO(42, struct wc_MlDsaKey)
#endif
#ifdef WOLFSSL_HAVE_SLHDSA
    WC_BCS(43, SlhDsaKey)
#else
    WC_BCS_NO(43, SlhDsaKey)
#endif
#ifdef WOLFSSL_HAVE_LMS
    WC_BCS(44, LmsKey)
#else
    WC_BCS_NO(44, LmsKey)
#endif
#ifdef WOLFSSL_HAVE_XMSS
    WC_BCS(45, XmssKey)
#else
    WC_BCS_NO(45, XmssKey)
#endif
#ifndef NO_HASH_WRAPPER
    WC_BCS(46, wc_HashAlg)
#else
    WC_BCS_NO(46, wc_HashAlg)
#endif
/* The struct tag: the Camellia typedef does not exist with OPENSSL_COEXIST. */
#ifdef HAVE_CAMELLIA
    WC_BCS(47, struct wc_Camellia)
#else
    WC_BCS_NO(47, struct wc_Camellia)
#endif
    WC_BCS(48, Cert)
/* An application that includes openssl/obj_mac.h before anything else that
 * pulls in asn.h gets only asn.h's SN_* names, and can then never see
 * DecodedCert: record "unknown" rather than a size that would not match. */
#if !defined(NO_ASN) && defined(WC_DECODEDCERT_DEFINED)
    WC_BCS(49, DecodedCert)
#elif !defined(NO_ASN)
    WC_BCS_UNKNOWN(49, DecodedCert)
#else
    WC_BCS_NO(49, DecodedCert)
#endif
#if !defined(NO_ASN) && defined(WOLFSSL_ACERT) && \
    defined(WC_DECODEDCERT_DEFINED)
    WC_BCS(50, DecodedAcert)
#elif !defined(NO_ASN) && defined(WOLFSSL_ACERT)
    WC_BCS_UNKNOWN(50, DecodedAcert)
#else
    WC_BCS_NO(50, DecodedAcert)
#endif
#ifdef HAVE_PKCS7
    WC_BCS(51, wc_PKCS7)
#else
    WC_BCS_NO(51, wc_PKCS7)
#endif
#ifdef WOLF_CRYPTO_CB
    WC_BCS(52, wc_CryptoInfo)
#else
    WC_BCS_NO(52, wc_CryptoInfo)
#endif
#ifndef NO_DH
    WC_BCS(53, DhParams)
#else
    WC_BCS_NO(53, DhParams)
#endif
#if !defined(NO_RSA) && defined(WC_RSA_NONBLOCK) && \
    (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    WC_BCS(54, RsaNb)
#else
    WC_BCS_NO(54, RsaNb)
#endif
#if !defined(NO_DH) && defined(WC_DH_NONBLOCK)
    WC_BCS(55, DhNb)
#else
    WC_BCS_NO(55, DhNb)
#endif
#if defined(HAVE_ECC) && defined(WC_ECC_NONBLOCK)
    WC_BCS(56, ecc_nb_ctx_t)
#else
    WC_BCS_NO(56, ecc_nb_ctx_t)
#endif
#ifdef HAVE_FALCON
    WC_BCS(57, falcon_key)
#else
    WC_BCS_NO(57, falcon_key)
#endif
#ifdef WOLFSSL_HAVE_FRODOKEM
    WC_BCS(58, FrodoKemKey)
#else
    WC_BCS_NO(58, FrodoKemKey)
#endif
#ifdef WOLFCRYPT_HAVE_ECCSI
    WC_BCS(59, EccsiKey)
#else
    WC_BCS_NO(59, EccsiKey)
#endif
#ifdef WOLFCRYPT_HAVE_SAKKE
    WC_BCS(60, SakkeKey)
#else
    WC_BCS_NO(60, SakkeKey)
#endif
#ifdef HAVE_ARGON2
    WC_BCS(61, Argon2Ctx)
#else
    WC_BCS_NO(61, Argon2Ctx)
#endif
#ifdef HAVE_ASCON
    WC_BCS(62, wc_AsconAEAD128)
#else
    WC_BCS_NO(62, wc_AsconAEAD128)
#endif
#if !defined(NO_AES) && defined(WOLFSSL_AES_XTS) && \
    (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    WC_BCS(63, XtsAes)
#else
    WC_BCS_NO(63, XtsAes)
#endif
#ifdef HAVE_PKCS11
    WC_BCS(64, Pkcs11Dev)
#else
    WC_BCS_NO(64, Pkcs11Dev)
#endif
#ifdef WOLFSSL_PUF
    WC_BCS(65, wc_PufCtx)
#else
    WC_BCS_NO(65, wc_PufCtx)
#endif
#ifdef WOLFSSL_SHE
    WC_BCS(66, wc_SHE)
#else
    WC_BCS_NO(66, wc_SHE)
#endif
#ifdef HAVE_WC_RNG_BANK
    WC_BCS(67, struct wc_rng_bank)
#else
    WC_BCS_NO(67, struct wc_rng_bank)
#endif
#ifndef NO_ASN
    WC_BCS(68, DNS_entry)
#else
    WC_BCS_NO(68, DNS_entry)
#endif
#ifndef NO_BIG_INT
    /* The digit type and radix: mp_int holds only a pointer to its digits
     * in heap math, so its size does not show them. */
    WC_BCS(69, mp_digit)
    WC_BCS(70, wc_BuildDigitBits)
#else
    WC_BCS_NO(69, mp_digit)
    WC_BCS_NO(70, wc_BuildDigitBits)
#endif

#endif /* WC_BCF || WC_BCF_NO || WC_BCS || WC_BCS_NO || WC_BCS_UNKNOWN */
