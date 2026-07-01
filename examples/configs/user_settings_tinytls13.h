/* user_settings_tinytls13.h
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

/* Tiny TLS 1.3 footprint profile.
 *
 * A TLS 1.3-only build that strips to a PSK + ECDHE floor (no X.509), with
 * X.509 cert verify, mTLS, server role, zero-heap, and PQC as opt-in adders.
 * The WOLFSSL_TINY_TLS13 umbrella in settings.h expands these into the
 * underlying wolfSSL macros; this file just selects the profile and options.
 *
 * Smallest footprint comes from a dead-code-eliminated, LTO link of a single
 * client/server:
 *   cp ./examples/configs/user_settings_tinytls13.h user_settings.h
 *   ./configure --enable-usersettings --enable-static --disable-shared \
 *               --disable-examples --disable-crypttests
 *   make
 *   # link your app: -Os -flto -ffunction-sections -fdata-sections \
 *   #                -Wl,--gc-sections  (use gcc-ar/gcc-ranlib for LTO archives)
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ===== PROFILE ========================================================== */
#if 1   /* Profile A: PSK + ECDHE floor, no X.509 (smallest) */
    #define WOLFSSL_TINY_TLS13
#endif
#if 0   /* Profile B: + minimal X.509 cert verify (ECDSA P-256). Implies core.
         * Reduced-security verify: no name constraints, relaxed ASN, no CRL.
         * For a known or pinned CA, not general public-internet PKI. */
    #define WOLFSSL_TINY_TLS13_CERT
#endif

/* ===== ROLE / AUTH ADDERS =============================================== */
#if 0   /* add TLS 1.3 server role (default is client only) */
    #define WOLFSSL_TINY_TLS13_SERVER
#endif
#if 0   /* mutual TLS (X.509 client auth, adds ECDSA sign). Implies cert. */
    #define WOLFSSL_TINY_TLS13_MUTUAL_AUTH
#endif
#if 0   /* add RSA-PSS cert verify (cert profile is ECDSA-only by default) */
    #define WOLFSSL_TINY_TLS13_RSA_VERIFY
#endif

/* ===== MEMORY MODEL ===================================================== */
#if 0   /* static memory pool for TLS allocations (deterministic RAM, no
         * fragmentation). App provides the pool via
         * wolfSSL_CTX_load_static_memory(). Keeps the malloc fallback. */
    #define WOLFSSL_TINY_TLS13_STATIC_MEM
#endif
#if 0   /* true zero-heap: forbid all system malloc. Opt-in because it removes
         * the allocator the standard test suite relies on. Pair with the
         * static memory pool above. */
    #define WOLFSSL_NO_MALLOC
#endif
#if 0   /* Static-memory pool buckets for a tinytls13 PSK handshake, measured with
         * wolfSSL's memory-bucket-optimizer. The distribution sets the minimum
         * pool size (~320 KB for client+server, ~half a single role), so enable
         * these only once your buffer matches; re-run the optimizer for your own
         * role/adders. Left out of the floor because forcing a large distribution
         * breaks consumers that load a smaller buffer. */
    #define WOLFMEM_BUCKETS     64,96,160,288,816,3408,5088,6176,10784
    #define WOLFMEM_DIST        92,34,36,421,63,20,3,1,2
    #define WOLFMEM_DEF_BUCKETS 9
#endif

/* ===== SPEED ============================================================ */
#if 0   /* tiny+fast: assembly crypto instead of small-C (size up, speed up) */
    #define WOLFSSL_TINY_TLS13_ASM
#endif

/* ===== CURVE (Profile A) =============================================== */
/* Default curve is X25519. For P-256 ECDHE instead, enable the next block.
 * (Profile B uses P-256 automatically for both ECDHE and ECDSA verify.) */
#if 0
    #define HAVE_ECC
    #define ECC_USER_CURVES
#endif

/* ===== AEAD / HASH ADDERS (floor is AES-128-GCM + SHA-256) ============= */
#if 0   /* ChaCha20-Poly1305 */
    #define HAVE_CHACHA
    #define HAVE_POLY1305
#endif
#if 0   /* AES-256-GCM (floor is AES-128 only) */
    #undef  NO_AES_256
    #define WOLFSSL_AES_256
#endif
#if 0   /* SHA-384 (for AES-256-GCM-SHA384 etc.) */
    #define WOLFSSL_SHA384
#endif

/* ===== PQC ADDERS (valid on either profile; SHA-3/SHAKE pulled in auto) = */
#if 0   /* ML-DSA-44 verify-only. Use with the cert profile (Profile B) for TLS
         * auth: the PSK floor has no certificate to verify, so on Profile A
         * this only confirms the umbrella builds. ML-DSA-44 is the right tier
         * for a tiny stack paired with X25519/P-256 + AES-128; higher levels
         * add no security against that classical floor. */
    #define WOLFSSL_HAVE_MLDSA
    #define WOLFSSL_MLDSA_VERIFY_ONLY
    #define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
    #ifndef WOLFSSL_TINY_TLS13_CERT
        /* PSK floor never parses a cert; the cert profile needs ML-DSA ASN.1
         * to decode and verify ML-DSA certificates, so keep it there. */
        #define WOLFSSL_MLDSA_NO_ASN1
    #endif
    #define WOLFSSL_NO_ML_DSA_65
    #define WOLFSSL_NO_ML_DSA_87
#endif
#if 0   /* ML-KEM-768 + X25519MLKEM768 hybrid (768 is the widely-adopted tier;
         * disable 512/1024) */
    #define WOLFSSL_HAVE_MLKEM
    #define WOLFSSL_NO_ML_KEM_512
    #define WOLFSSL_NO_ML_KEM_1024
    #define WOLFSSL_MLKEM_DYNAMIC_KEYS
#endif

/* ===== PLATFORM (bare-metal defaults; adjust for your target) ========== */
#if 1
    #define WOLFSSL_USER_IO     /* provide your own send/recv callbacks */
    #define NO_FILESYSTEM
    #define WOLFSSL_NO_SOCK
    #define NO_WRITEV
    #define WOLFSSL_NO_GETPID
#endif
/* Provide a hardware RNG seed for bare metal:
 * #define CUSTOM_RAND_GENERATE_SEED my_hw_seed   (int f(byte*, word32)) */

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
