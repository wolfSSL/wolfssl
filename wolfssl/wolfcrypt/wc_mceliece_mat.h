/* wc_mceliece_mat.h
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
    \file wolfssl/wolfcrypt/wc_mceliece_mat.h
*/

/* Internal declarations shared by wc_mceliece.c (KEM / API glue) and
 * wc_mceliece_mat.c (field, polynomial, matrix and code machinery). This
 * header is not installed for application use. */

#ifndef WOLF_CRYPT_WC_MCELIECE_MAT_H
#define WOLF_CRYPT_WC_MCELIECE_MAT_H

#include <wolfssl/wolfcrypt/wc_mceliece.h>

#ifdef WOLFSSL_HAVE_MCELIECE

#ifdef __cplusplus
    extern "C" {
#endif

/* Run-time parameters for a Classic McEliece parameter set. All derived byte
 * lengths are precomputed so the KEM glue never recomputes CEILING() values. */
struct McElieceParams {
    /* Full key type including the MCELIECE_F / MCELIECE_PC modifier bits. */
    int type;
    /* Code length n (number of support elements). */
    word16 n;
    /* Error weight t (also the Goppa polynomial degree). */
    word16 t;
    /* FixedWeight samples drawn per attempt: t when n == q, else 2t. */
    word16 tau;
    /* m * t (number of parity-check rows). */
    word16 mt;
    /* Code dimension k = n - mt. */
    word16 k;
    /* Non-zero when plaintext confirmation (pc) is used. */
    byte pc;
    /* Non-zero when semi-systematic (f) MatGen is used. */
    byte f;
    /* Encoded public key length in bytes. */
    word32 pubSz;
    /* Encoded private key length in bytes. */
    word32 privSz;
    /* Ciphertext length in bytes (accounts for pc). */
    word32 ctSz;
    /* Syndrome length CEILING(mt / 8) (the non-pc ciphertext body). */
    word32 syndBytes;
    /* Error-vector length CEILING(n / 8). */
    word32 sBytes;
    /* Goppa polynomial length t * CEILING(m / 8). */
    word32 irrBytes;
};


/* Generate a key pair from a 32-byte delta seed (SeededKeyGen, draft section
 * 8.3). On success the encoded public key T is written to pk (params->pubSz
 * bytes) and the encoded private key to sk (params->privSz bytes). Internal
 * retries (field ordering / irreducible / MatGen failure) are SHAKE-derived
 * and consume no further external randomness. Returns 0 on success. */
/* Return the scratch size (bytes) each operation needs. The caller allocates
 * one buffer of this size and passes it in; mat.c allocates nothing itself. */
WOLFSSL_LOCAL word32 wc_mceliece_keygen_scratch_sz(const McElieceParams* p);
WOLFSSL_LOCAL word32 wc_mceliece_encap_scratch_sz(const McElieceParams* p);
WOLFSSL_LOCAL word32 wc_mceliece_decode_scratch_sz(const McElieceParams* p);
/* Public-key buffer size needed during key generation: MatGen runs in place in
 * the pk buffer, so it must hold the full mt x n matrix (shrunk to pubSz after
 * keygen). */
WOLFSSL_LOCAL word32 wc_mceliece_keygen_pk_sz(const McElieceParams* p);

/* One-time initialization: retrieve the CPU feature flags for asm dispatch. */
WOLFSSL_LOCAL void mceliece_init(void);

WOLFSSL_LOCAL int wc_mceliece_keypair(const McElieceParams* p, wc_Shake* shake,
    const byte* delta, byte* pk, byte* sk, byte* scratch);

/* Encapsulation code path (draft section 8.5, Encode): draw a fixed-weight-t
 * error vector e from rand (FixedWeight, draft section 8.4, consuming rand in
 * 2*tau-byte attempts with rejection) and compute the syndrome C0 = He. The
 * weight-t error vector is written to e (params->sBytes bytes) for the caller
 * to hash, and C0 to c0 (params->syndBytes bytes). Returns 0 on success, or
 * MCELIECE_RAND_DEPLETED when rand is exhausted before success. */
WOLFSSL_LOCAL int wc_mceliece_encap(const McElieceParams* p, const byte* pk,
    const byte* rand, word32 randLen, byte* e, byte* c0, byte* scratch);

/* Decapsulation code path (draft section 8.6, Decode): recover the weight-t
 * error vector e from syndrome C0 using the private key sk. On success e holds
 * the decoded error (params->sBytes bytes) and 0 is returned. A decoding
 * failure (no weight-t solution) returns MCELIECE_DECODE_FAIL so the caller can
 * apply implicit rejection; other negative values are hard errors. */
WOLFSSL_LOCAL int wc_mceliece_decode(const McElieceParams* p, const byte* sk,
    const byte* c0, byte* e, byte* scratch);

/* Sentinel from wc_mceliece_decode for a genuine decoding failure (drives
 * constant-time implicit rejection in the caller). */
#define MCELIECE_DECODE_FAIL   1

/* Sentinel from wc_mceliece_encap when the supplied randomness runs out
 * before a weight-t error vector is found (the caller supplies more and retries
 * for the RNG path, or fails for the WithRandom path). */
#define MCELIECE_RAND_DEPLETED 2

/* Number of bytes of randomness FixedWeight consumes per attempt: 16 * tau bits
 * = 2 * tau bytes. tau = t when n == q (mceliece8192128), else 2t - see
 * MCELIECE_TAU / McElieceParams.tau. Pass the parameter set's tau. */
#define MCELIECE_FIXEDWEIGHT_ATTEMPT_SZ(tau)  (2 * (tau))


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_MCELIECE */

#endif /* WOLF_CRYPT_WC_MCELIECE_MAT_H */
