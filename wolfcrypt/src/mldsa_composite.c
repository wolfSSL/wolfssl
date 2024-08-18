/* mldsa_composite.c
 */

/* Based on dilithium.c and Reworked for Composite by Dr. Pala.
 */

/* Possible Composite options:
 *
 * HAVE_MLDSA_COMPOSITE                                       Default: OFF
 *   Enables the code in this file to be compiled.
 * WOLFSSL_NO_MLDSA44_P256                                    Default: OFF
 *   Does not compile in parameter set ML-DSA-44 and any code specific to that
 *   parameter set.
 * WOLFSSL_NO_MLDSA44_X25519                                  Default: OFF
 *   Does not compile in parameter set ML-DSA-44 and any code specific to that
 *   parameter set.
 * WOLFSSL_MLDSA_COMPOSITE_VERIFY_ONLY                        Default: OFF
 *   Compiles in only the verification and public key operations.
 * WOLFSSL_MLDSA_COMPOSITE_ASSIGN_KEY                         Default: OFF
 *   Key data is assigned into Composite key rather than copied.
 *   Life of key data passed in is tightly coupled to life of Compsite key.
 *   Cannot be used when make key is enabled.
 *
 * WOLFSSL_MLDSA_COMPOSITE_NO_ASN1                            Default: OFF
 *   Disables any ASN.1 encoding or decoding code.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_PQC there */
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1
#include <wolfssl/wolfcrypt/asn.h>
#endif

#if defined(HAVE_MLDSA_COMPOSITE)
dddsfd
#include <wolfssl/wolfcrypt/mldsa_composite.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_WC_MLDSA_COMPOSITE


/******************************************************************************
 * Encode/Decode operations
 ******************************************************************************/

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY

/* Make a key from a random seed.
 *
 * xi is seed passed in.
 * FIPS 204. 5: Algorithm 1 ML-DSA.KeyGen()
 *   ...
 *   2: (rho, rho', K) E {0,1}256 x {0,1}512 x {0,1}256 <- H(xi, 1024)
 *   3: A_circum <- ExpandA(rho)
 *   4: (s1,s2) <- ExpandS(rho')
 *   5: t <- NTT-1(A_circum o NTT(s1)) + s2
 *   6: (t1, t0) <- Power2Round(t, d)
 *   7: pk <- pkEncode(rho, t1)
 *   8: tr <- H(BytesToBits(pk), 512)
 *   9: sk <- skEncode(rho, K, tr, s1, s2, t0)
 *  10: return (pk, sk)
 *
 * FIPS 204. 8.2: Algorithm 16 pkEncode(rho, t1)
 *   1: pk <- BitsToBytes(rho)
 *   2: for i from 0 to l - 1 do
 *   3:     pk <- pk || SimpleBitPack(t1[i], 2^(bitlen(q-1)-d) - 1)
 *   4: end for
 *   5: return pk
 *
 * FIPS 204. 8.2: Algorithm 18 skEncode(rho, K, tr, s, s2, t0)
 *   1: sk <- BitsToBytes(rho) || BitsToBytes(K) || BitsToBytes(tr)
 *   2: for i from 0 to l - 1 do
 *   3:     sk <- sk || BitPack(s1[i], eta, eta)
 *   4: end for
 *   5: for i from 0 to k - 1 do
 *   6:     sk <- sk || BitPack(s2[i], eta, eta)
 *   7: end for
 *   8: for i from 0 to k - 1 do
 *   9:     sk <- sk || BitPack(t0[i], 2^(d-1)-1, 2^(d-1))
 *  10: end for
 *  11: return sk
 *
 * Public and private key store in key.
 *
 * @param [in, out] key   Dilithium key.
 * @param [in]      seed  Seed to hash to generate values.
 * @return  0 on success.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int mldsa_composite_make_key_from_seed(mldsa_composite_key* key, const byte* seed)
{
#ifndef WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t = NULL;
    byte* pub_seed = key->k;

    /* Allocate memory for large intermediates. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if (key->a == NULL) {
        key->a = (sword32*)XMALLOC(params->aSz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->a == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        a = key->a;
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->s1 == NULL)) {
        key->s1 = (sword32*)XMALLOC(params->aSz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            key->s2 = key->s1  + params->s1Sz / sizeof(*s1);
            key->t0 = key->s2  + params->s2Sz / sizeof(*s2);
        }
    }
#endif
    if (ret == 0) {
        s1 = key->s1;
        s2 = key->s2;
        t  = key->t0;
    }
#else
    if (ret == 0) {
        unsigned int allocSz;

        allocSz = params->s1Sz + params->s2Sz + params->s2Sz;
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
        allocSz += params->aSz;
#endif

        /* s1, s2, t, a */
        s1 = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            s2 = s1 + params->s1Sz / sizeof(*s1);
            t  = s2 + params->s2Sz / sizeof(*s2);
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
            a  = t  + params->s2Sz / sizeof(*t);
#endif
        }
    }
#endif

    if (ret == 0) {
        /* Step 2: Create public seed, private seed and K from seed.
         * Step 9; Alg 18, Step 1: Public seed is placed into private key. */
        ret = dilithium_shake256(&key->shake, seed, DILITHIUM_SEED_SZ, pub_seed,
            DILITHIUM_SEEDS_SZ);
    }
    if (ret == 0) {
        /* Step 7; Alg 16 Step 1: Copy public seed into public key. */
        XMEMCPY(key->p, pub_seed, DILITHIUM_PUB_SEED_SZ);

        /* Step 3: Expand public seed into a matrix of polynomials. */
        ret = dilithium_expand_a(&key->shake, pub_seed, params->k, params->l,
            a, key->heap);
    }
    if (ret == 0) {
        byte* priv_seed = key->k + DILITHIUM_PUB_SEED_SZ;

        /* Step 4: Expand private seed into to vectors of polynomials. */
        ret = dilithium_expand_s(&key->shake, priv_seed, params->eta, s1,
            params->l, s2, params->k);
    }
    if (ret == 0) {
        byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
        byte* tr = k + DILITHIUM_K_SZ;
        byte* s1p = tr + DILITHIUM_TR_SZ;
        byte* s2p = s1p + params->s1EncSz;
        byte* t0 = s2p + params->s2EncSz;
        byte* t1 = key->p + DILITHIUM_PUB_SEED_SZ;

        /* Step 9: Move k down to after public seed. */
        XMEMCPY(k, k + DILITHIUM_PRIV_SEED_SZ, DILITHIUM_K_SZ);
        /* Step 9. Alg 18 Steps 2-4: Encode s1 into private key. */
        dilthium_vec_encode_eta_bits(s1, params->l, params->eta, s1p);
        /* Step 9. Alg 18 Steps 5-7: Encode s2 into private key. */
        dilthium_vec_encode_eta_bits(s2, params->k, params->eta, s2p);

        /* Step 5: t <- NTT-1(A_circum o NTT(s1)) + s2 */
        dilithium_vec_ntt_small(s1, params->l);
        dilithium_matrix_mul(t, a, s1, params->k, params->l);
        dilithium_vec_invntt(t, params->k);
        dilithium_vec_add(t, s2, params->k);

        /* Make positive for decomposing. */
        dilithium_vec_make_pos(t, params->k);
        /* Step 6, Step 7, Step 9. Alg 16 Steps 2-4, Alg 18 Steps 8-10.
         * Decompose t in t0 and t1 and encode into public and private key.
         */
        dilithium_vec_encode_t0_t1(t, params->k, t0, t1);
        /* Step 8. Alg 18, Step 1: Hash public key into private key. */
        ret = dilithium_shake256(&key->shake, key->p, params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if (ret == 0) {
        /* Public key and private key are available. */
        key->prvKeySet = 1;
        key->pubKeySet = 1;
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Matrix A is available. */
        key->aSet = 1;
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
        /* Private vectors are not available as they were overwritten. */
        key->privVecsSet = 0;
#endif
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
        /* Public vector, t1, is not available as it was not created. */
        key->pubVecSet = 0;
#endif
    }

#ifndef WC_DILITHIUM_CACHE_PRIV_VECTORS
    XFREE(s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
#endif
    return ret;
#else
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t = NULL;
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    sword64* t64 = NULL;
#endif
    byte* h = NULL;
    byte* pub_seed = key->k;
    unsigned int r;
    unsigned int s;

    /* Allocate memory for large intermediates. */
    if (ret == 0) {
        unsigned int allocSz;

        /* s1-l, s2-k, t-k, a-1 */
        allocSz  = params->s1Sz + params->s2Sz + params->s2Sz +
            DILITHIUM_REJ_NTT_POLY_H_SIZE + DILITHIUM_POLY_SIZE;
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        /* t64 */
        allocSz += DILITHIUM_POLY_SIZE * 2;
    #endif
        s1 = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            s2 = s1 + params->s1Sz / sizeof(*s1);
            t  = s2 + params->s2Sz / sizeof(*s2);
            h  = (byte*)(t  + params->s2Sz / sizeof(*t));
            a  = (sword32*)(h + DILITHIUM_REJ_NTT_POLY_H_SIZE);
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64 = (sword64*)(a + DILITHIUM_N);
        #endif
        }
    }

    if (ret == 0) {
        /* Step 2: Create public seed, private seed and K from seed.
         * Step 9; Alg 18, Step 1: Public seed is placed into private key. */
        ret = dilithium_shake256(&key->shake, seed, DILITHIUM_SEED_SZ, pub_seed,
            DILITHIUM_SEEDS_SZ);
    }
    if (ret == 0) {
        byte* priv_seed = key->k + DILITHIUM_PUB_SEED_SZ;

        /* Step 7; Alg 16 Step 1: Copy public seed into public key. */
        XMEMCPY(key->p, pub_seed, DILITHIUM_PUB_SEED_SZ);

        /* Step 4: Expand private seed into to vectors of polynomials. */
        ret = dilithium_expand_s(&key->shake, priv_seed, params->eta, s1,
            params->l, s2, params->k);
    }
    if (ret == 0) {
        byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
        byte* tr = k + DILITHIUM_K_SZ;
        byte* s1p = tr + DILITHIUM_TR_SZ;
        byte* s2p = s1p + params->s1EncSz;
        byte* t0 = s2p + params->s2EncSz;
        byte* t1 = key->p + DILITHIUM_PUB_SEED_SZ;
        byte aseed[DILITHIUM_GEN_A_SEED_SZ];
        sword32* s2t = s2;
        sword32* tt = t;

        /* Step 9: Move k down to after public seed. */
        XMEMCPY(k, k + DILITHIUM_PRIV_SEED_SZ, DILITHIUM_K_SZ);
        /* Step 9. Alg 18 Steps 2-4: Encode s1 into private key. */
        dilthium_vec_encode_eta_bits(s1, params->l, params->eta, s1p);
        /* Step 9. Alg 18 Steps 5-7: Encode s2 into private key. */
        dilthium_vec_encode_eta_bits(s2, params->k, params->eta, s2p);

        /* Step 5: NTT(s1) */
        dilithium_vec_ntt_small(s1, params->l);
        /* Step 5: t <- NTT-1(A_circum o NTT(s1)) + s2 */
        XMEMCPY(aseed, pub_seed, DILITHIUM_PUB_SEED_SZ);
        for (r = 0; (ret == 0) && (r < params->k); r++) {
            sword32* s1t = s1;
            unsigned int e;

            /* Put r/i into buffer to be hashed. */
            aseed[DILITHIUM_PUB_SEED_SZ + 1] = r;
            for (s = 0; (ret == 0) && (s < params->l); s++) {

                /* Put s into buffer to be hashed. */
                aseed[DILITHIUM_PUB_SEED_SZ + 0] = s;
                /* Step 3: Expand public seed into a matrix of polynomials. */
                ret = dilithium_rej_ntt_poly_ex(&key->shake, aseed, a, h);
                if (ret != 0) {
                    break;
                }
                /* Matrix multiply. */
            #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
                if (s == 0) {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        tt[e] = dilithium_mont_red((sword64)a[e] * s1t[e]);
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        tt[e+0] = dilithium_mont_red((sword64)a[e+0]*s1t[e+0]);
                        tt[e+1] = dilithium_mont_red((sword64)a[e+1]*s1t[e+1]);
                        tt[e+2] = dilithium_mont_red((sword64)a[e+2]*s1t[e+2]);
                        tt[e+3] = dilithium_mont_red((sword64)a[e+3]*s1t[e+3]);
                        tt[e+4] = dilithium_mont_red((sword64)a[e+4]*s1t[e+4]);
                        tt[e+5] = dilithium_mont_red((sword64)a[e+5]*s1t[e+5]);
                        tt[e+6] = dilithium_mont_red((sword64)a[e+6]*s1t[e+6]);
                        tt[e+7] = dilithium_mont_red((sword64)a[e+7]*s1t[e+7]);
                    }
                #endif
                }
                else {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        tt[e] += dilithium_mont_red((sword64)a[e] * s1t[e]);
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        tt[e+0] += dilithium_mont_red((sword64)a[e+0]*s1t[e+0]);
                        tt[e+1] += dilithium_mont_red((sword64)a[e+1]*s1t[e+1]);
                        tt[e+2] += dilithium_mont_red((sword64)a[e+2]*s1t[e+2]);
                        tt[e+3] += dilithium_mont_red((sword64)a[e+3]*s1t[e+3]);
                        tt[e+4] += dilithium_mont_red((sword64)a[e+4]*s1t[e+4]);
                        tt[e+5] += dilithium_mont_red((sword64)a[e+5]*s1t[e+5]);
                        tt[e+6] += dilithium_mont_red((sword64)a[e+6]*s1t[e+6]);
                        tt[e+7] += dilithium_mont_red((sword64)a[e+7]*s1t[e+7]);
                    }
                #endif
                }
            #else
                if (s == 0) {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        t64[e] = (sword64)a[e] * s1t[e];
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        t64[e+0] = (sword64)a[e+0] * s1t[e+0];
                        t64[e+1] = (sword64)a[e+1] * s1t[e+1];
                        t64[e+2] = (sword64)a[e+2] * s1t[e+2];
                        t64[e+3] = (sword64)a[e+3] * s1t[e+3];
                        t64[e+4] = (sword64)a[e+4] * s1t[e+4];
                        t64[e+5] = (sword64)a[e+5] * s1t[e+5];
                        t64[e+6] = (sword64)a[e+6] * s1t[e+6];
                        t64[e+7] = (sword64)a[e+7] * s1t[e+7];
                    }
                #endif
                }
                else {
                #ifdef WOLFSSL_DILITHIUM_SMALL
                    for (e = 0; e < DILITHIUM_N; e++) {
                        t64[e] += (sword64)a[e] * s1t[e];
                    }
                #else
                    for (e = 0; e < DILITHIUM_N; e += 8) {
                        t64[e+0] += (sword64)a[e+0] * s1t[e+0];
                        t64[e+1] += (sword64)a[e+1] * s1t[e+1];
                        t64[e+2] += (sword64)a[e+2] * s1t[e+2];
                        t64[e+3] += (sword64)a[e+3] * s1t[e+3];
                        t64[e+4] += (sword64)a[e+4] * s1t[e+4];
                        t64[e+5] += (sword64)a[e+5] * s1t[e+5];
                        t64[e+6] += (sword64)a[e+6] * s1t[e+6];
                        t64[e+7] += (sword64)a[e+7] * s1t[e+7];
                    }
                #endif
                }
            #endif
                /* Next polynomial. */
                s1t += DILITHIUM_N;
            }
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            for (e = 0; e < DILITHIUM_N; e++) {
                tt[e] = dilithium_mont_red(t64[e]);
            }
        #endif
            dilithium_invntt(tt);
            dilithium_add(tt, s2t);
            /* Make positive for decomposing. */
            dilithium_make_pos(tt);

            tt += DILITHIUM_N;
            s2t += DILITHIUM_N;
        }

        /* Step 6, Step 7, Step 9. Alg 16 Steps 2-4, Alg 18 Steps 8-10.
         * Decompose t in t0 and t1 and encode into public and private key.
         */
        dilithium_vec_encode_t0_t1(t, params->k, t0, t1);
        /* Step 8. Alg 18, Step 1: Hash public key into private key. */
        ret = dilithium_shake256(&key->shake, key->p, params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if (ret == 0) {
        /* Public key and private key are available. */
        key->prvKeySet = 1;
        key->pubKeySet = 1;
    }

    XFREE(s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#endif
}

/* Make a key from a random seed.
 *
 * FIPS 204. 5: Algorithm 1 ML-DSA.KeyGen()
 *   1: xi <- {0,1}256  [Choose random seed]
 *   ...
 *
 * @param [in, out] key  Dilithium key.
 * @param [in]      rng  Random number generator.
 * @return  0 on success.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int mldsa_composite_make_key(mldsa_composite_key* key, WC_RNG* rng)
{
    int ret;
    byte seed[DILITHIUM_SEED_SZ];

    /* Generate a 256-bit random seed. */
    ret = wc_RNG_GenerateBlock(rng, seed, DILITHIUM_SEED_SZ);
    if (ret == 0) {
        /* Make key with random seed. */
        ret = wc_dilithium_make_key_from_seed(key, seed);
    }

    return ret;
}
#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_SIGN

/* Sign a message with the key and a seed.
 *
 * FIPS 204. 6: Algorithm 2 MD-DSA.Sign(sk, M)
 *   1: (rho, K, tr, s1, s2, t0) <- skDecode(sk)
 *   2: s1_circum <- NTT(s1)
 *   3: s2_circum <- NTT(s2)
 *   4: t0_circum <- NTT(t0)
 *   5: A_circum <- ExpandA(rho)
 *   6: mu <- H(tr||M, 512)
 *   7: rnd <- {0,1}256
 *   8: rho' <- H(K||rnd||mu, 512)
 *   9: kappa <- 0
 *  10: (z, h) <- falsam
 *  11: while (z, h) = falsam do
 *  12:    y <- ExpandMask(rho', kappa)
 *  13:    w <- NTT-1(A_circum o NTT(y))
 *  14:    w1 <- HighBits(w)
 *  15:    c_tilde E {0,1}2*lambda <- H(mu|w1Encode(w1), 2 * lambda)
 *  16:    (c1_tilde, c2_tilde) E {0,1}256 x {0,1}2*lambda-256 <- c_tilde
 *  17:     c < SampleInBall(c1_tilde)
 *  18:     c_circum <- NTT(c)
 *  19:     <<cs1>> <- NTT-1(c_circum o s1_circum)
 *  20:     <<cs2>> <- NTT-1(c_circum o s2_circum)
 *  21:     z <- y + <<cs1>>
 *  22:     r0 <- LowBits(w - <<cs2>>
 *  23:     if ||z||inf >= GAMMA1 - BETA or ||r0||inf GAMMA2 - BETA then
 *                                                             (z, h) <- falsam
 *  24:     else
 *  25:         <<ct0>> <- NTT-1(c_circum o t0_circum)
 *  26:         h < MakeHint(-<<ct0>>, w - <<sc2>> + <<ct0>>)
 *  27:         if (||<<ct>>||inf >= GAMMMA1 or
 *                 the number of 1's in h is greater than OMEGA, then
 *                                                             (z, h) <- falsam
 *  28:         end if
 *  29:     end if
 *  30:     kappa <- kappa + l
 *  31: end while
 *  32: sigma <- sigEncode(c_tilde, z mod +/- q, h)
 *  33: return sigma
 *
 * @param [in, out] key     Dilithium key.
 * @param [in, out] seed    Random seed.
 * @param [in]      msg     Message data to sign.
 * @param [in]      msgLen  Length of message data in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int mldsa_composite_sign_msg_with_seed(mldsa_composite_key* key, const byte* seed,
    const byte* msg, word32 msgLen, byte* sig, word32 *sigLen)
{
#ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t0 = NULL;
    sword32* y = NULL;
    sword32* w0 = NULL;
    sword32* w1 = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* ct0 = NULL;
    byte data[DILITHIUM_RND_SZ + DILITHIUM_MU_SZ];
    byte* mu = data + DILITHIUM_RND_SZ;
    byte priv_rand_seed[DILITHIUM_Y_SEED_SZ];
    byte* h = sig + params->lambda * 2 + params->zEncSz;

    /* Check the signature buffer isn't too small. */
    if ((ret == 0) && (*sigLen < params->sigSz)) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Return the size of the signature. */
        *sigLen = params->sigSz;
    }

    /* Allocate memory for large intermediates. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->a == NULL)) {
        a = (sword32*)XMALLOC(params->aSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (a == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        a = key->a;
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->s1 == NULL)) {
        key->s1 = (sword32*)XMALLOC(params->aSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (key->s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            key->s2 = key->s1  + params->s1Sz / sizeof(*s1);
            key->t0 = key->s2  + params->s2Sz / sizeof(*s2);
        }
    }
#endif
    if (ret == 0) {
        s1 = key->s1;
        s2 = key->s2;
        t0 = key->t0;
    }
#endif
    if (ret == 0) {
        unsigned int allocSz;

        /* y-l, w0-k, w1-k, c-1, z-l, ct0-k */
        allocSz = params->s1Sz + params->s2Sz + params->s2Sz +
            DILITHIUM_POLY_SIZE + params->s1Sz + params->s2Sz;
#ifndef WC_DILITHIUM_CACHE_PRIV_VECTORS
        /* s1-l, s2-k, t0-k */
        allocSz += params->s1Sz + params->s2Sz + params->s2Sz;
#endif
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
        /* A */
        allocSz += params->aSz;
#endif
        y = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (y == NULL) {
            ret = MEMORY_E;
        }
        else {
            w0  = y   + params->s1Sz / sizeof(*y);
            w1  = w0  + params->s2Sz / sizeof(*w0);
            c   = w1  + params->s2Sz / sizeof(*w1);
            z   = c   + DILITHIUM_N;
            ct0 = z   + params->s1Sz / sizeof(*z);
#ifndef WC_DILITHIUM_CACHE_PRIV_VECTORS
            s1  = ct0 + params->s2Sz / sizeof(*ct0);
            s2  = s1  + params->s1Sz / sizeof(*s1);
            t0  = s2  + params->s2Sz / sizeof(*s2);
#endif
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
            a   = t0  + params->s2Sz / sizeof(*s2);
#endif
        }
    }

    if (ret == 0) {
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
        /* Check that we haven't already cached the private vectors. */
        if (!key->privVecsSet)
#endif
        {
            /* Steps 1-4: Decode and NTT vectors s1, s2, and t0. */
            dilithium_make_priv_vecs(key, s1, s2, t0);
        }

#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Check that we haven't already cached the matrix A. */
        if (!key->aSet)
#endif
        {
            /* Step 5: Create the matrix A from the public seed. */
            ret = dilithium_expand_a(&key->shake, pub_seed, params->k,
                params->l, a, key->heap);
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
            key->aSet = (ret == 0);
#endif
        }
    }
    if (ret == 0) {
        /* Step 6: Compute the hash of tr, public key hash, and message. */
        ret = dilithium_hash256(&key->shake, tr, DILITHIUM_TR_SZ, msg, msgLen,
            mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        /* Step 7: Copy random into buffer for hashing. */
        XMEMCPY(data, seed, DILITHIUM_RND_SZ);
    }
    if (ret == 0) {
        /* Step 9: Compute private random using hash. */
        ret = dilithium_hash256(&key->shake, k, DILITHIUM_K_SZ, data,
            DILITHIUM_RND_SZ + DILITHIUM_MU_SZ, priv_rand_seed,
            DILITHIUM_PRIV_RAND_SEED_SZ);
    }
    if (ret == 0) {
        word16 kappa = 0;
        int valid = 0;

        /* Step 11: Start rejection sampling loop */
        do {
            byte w1e[DILITHIUM_MAX_W1_ENC_SZ];
            sword32* w = w1;
            sword32* y_ntt = z;
            sword32* cs2 = ct0;
            byte* commit = sig;

            /* Step 12: Compute vector y from private random seed and kappa. */
            dilithium_vec_expand_mask(&key->shake, priv_rand_seed, kappa,
                params->gamma1_bits, y, params->l);
        #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_Y
            valid = dilithium_vec_check_low(y, params->l,
                (1 << params->gamma1_bits) - params->beta);
            if (valid)
        #endif
            {
                /* Step 13: NTT-1(A o NTT(y)) */
                XMEMCPY(y_ntt, y, params->s1Sz);
                dilithium_vec_ntt(y_ntt, params->l);
                dilithium_matrix_mul(w, a, y_ntt, params->k, params->l);
                dilithium_vec_invntt(w, params->k);
                /* Step 14, Step 22: Make values positive and decompose. */
                dilithium_vec_make_pos(w, params->k);
                dilithium_vec_decompose(w, params->k, params->gamma2, w0, w1);
        #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_W0
                valid = dilithium_vec_check_low(w0, params->k,
                    params->gamma2 - params->beta);
            }
            if (valid) {
        #endif
                /* Step 15: Encode w1. */
                dilithium_vec_encode_w1(w1, params->k, params->gamma2, w1e);
                /* Step 15: Hash mu and encoded w1.
                 * Step 32: Hash is stored in signature. */
                ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ,
                    w1e, params->w1EncSz, commit, 2 * params->lambda);
                if (ret == 0) {
                    /* Step 17: Compute c from first 256 bits of commit. */
                    ret = dilithium_sample_in_ball(&key->shake, commit,
                        params->tau, c, key->heap);
                }
                if (ret == 0) {
                    sword32 hi;

                    /* Step 18: NTT(c). */
                    dilithium_ntt_small(c);
                    /* Step 20: cs2 = NTT-1(c o s2) */
                    dilithium_vec_mul(cs2, c, s2, params->k);
                    dilithium_vec_invntt(cs2, params->k);
                    /* Step 22: w0 - cs2 */
                    dilithium_vec_sub(w0, cs2, params->k);
                    dilithium_vec_red(w0, params->k);
                    /* Step 23: Check w0 - cs2 has low enough values. */
                    hi = params->gamma2 - params->beta;
                    valid = dilithium_vec_check_low(w0, params->k, hi);
                    if (valid) {
                        /* Step 19: cs1 = NTT-1(c o s1) */
                        dilithium_vec_mul(z, c, s1, params->l);
                        dilithium_vec_invntt(z, params->l);
                        /* Step 21: z = y + cs1 */
                        dilithium_vec_add(z, y, params->l);
                        dilithium_vec_red(z, params->l);
                        /* Step 23: Check z has low enough values. */
                        hi = (1 << params->gamma1_bits) - params->beta;
                        valid = dilithium_vec_check_low(z, params->l, hi);
                    }
                    if (valid) {
                        /* Step 25: ct0 = NTT-1(c o t0) */
                        dilithium_vec_mul(ct0, c, t0, params->k);
                        dilithium_vec_invntt(ct0, params->k);
                        /* Step 27: Check ct0 has low enough values. */
                        hi = params->gamma2;
                        valid = dilithium_vec_check_low(ct0, params->k, hi);
                    }
                    if (valid) {
                        /* Step 26: ct0 = ct0 + w0 */
                        dilithium_vec_add(ct0, w0, params->k);
                        dilithium_vec_red(ct0, params->k);
                        /* Step 26, 27: Make hint from ct0 and w1 and check
                         * number of hints is valid.
                         * Step 32: h is encoded into signature.
                         */
                        valid = (dilithium_make_hint(ct0, w1, params->k,
                            params->gamma2, params->omega, h) >= 0);
                    }
                }
            }

            if (!valid) {
                /* Too many attempts - something wrong with implementation. */
                if ((kappa > (word16)(kappa + params->l))) {
                    ret = BAD_COND_E;
                }

                /* Step 30: increment value to append to seed to unique value.
                 */
                kappa += params->l;
            }
        }
        /* Step 11: Check we have a valid signature. */
        while ((ret == 0) && (!valid));
    }
    if (ret == 0) {
        byte* ze = sig + params->lambda * 2;
        /* Step 32: Encode z into signature.
         * Commit (c) and h already encoded into signature. */
        dilithium_vec_encode_gamma1(z, params->l, params->gamma1_bits, ze);
    }

    XFREE(y, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#else
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->k;
    const byte* k = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* tr = k + DILITHIUM_K_SZ;
    const byte* s1p = tr + DILITHIUM_TR_SZ;
    const byte* s2p = s1p + params->s1EncSz;
    const byte* t0p = s2p + params->s2EncSz;
    sword32* a = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t0 = NULL;
    sword32* y = NULL;
    sword32* y_ntt = NULL;
    sword32* w0 = NULL;
    sword32* w1 = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* ct0 = NULL;
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    sword64* t64 = NULL;
#endif
    byte* blocks = NULL;
    byte data[DILITHIUM_RND_SZ + DILITHIUM_MU_SZ];
    byte* mu = data + DILITHIUM_RND_SZ;
    byte priv_rand_seed[DILITHIUM_Y_SEED_SZ];
    byte* h = sig + params->lambda * 2 + params->zEncSz;
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
    byte maxK = (byte)min(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A,
        params->k);
#endif

    /* Check the signature buffer isn't too small. */
    if ((ret == 0) && (*sigLen < params->sigSz)) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Return the size of the signature. */
        *sigLen = params->sigSz;
    }

    /* Allocate memory for large intermediates. */
    if (ret == 0) {
        unsigned int allocSz;

        /* y-l, w0-k, w1-k, blocks, c-1, z-1, A-1 */
        allocSz  = params->s1Sz + params->s2Sz + params->s2Sz +
            DILITHIUM_REJ_NTT_POLY_H_SIZE +
            DILITHIUM_POLY_SIZE +  DILITHIUM_POLY_SIZE + DILITHIUM_POLY_SIZE;
    #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
        allocSz += params->s1Sz + params->s2Sz + params->s2Sz;
    #elif defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A)
        allocSz += maxK * params->l * DILITHIUM_POLY_SIZE;
    #endif
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        allocSz += DILITHIUM_POLY_SIZE * 2;
    #endif
        y = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (y == NULL) {
            ret = MEMORY_E;
        }
        else {
            w0     = y  + params->s1Sz / sizeof(*y_ntt);
            w1     = w0 + params->s2Sz / sizeof(*w0);
            blocks = (byte*)(w1 + params->s2Sz / sizeof(*w1));
            c      = (sword32*)(blocks + DILITHIUM_REJ_NTT_POLY_H_SIZE);
            z      = c  + DILITHIUM_N;
            a      = z  + DILITHIUM_N;
            ct0    = z;
    #if defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A)
            y_ntt  = w0;
            s1     = z;
            s2     = z;
            t0     = z;
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64    = (sword64*)(a + (1 + maxK * params->l) * DILITHIUM_N);
        #endif
    #elif defined(WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC)
            y_ntt  = z;
            s1     = a  + DILITHIUM_N;
            s2     = s1 + params->s1Sz / sizeof(*s1);
            t0     = s2 + params->s2Sz / sizeof(*s2);
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64    = (sword64*)(t0 + params->s2Sz / sizeof(*t0));
        #endif
    #else
            y_ntt  = z;
            s1     = z;
            s2     = z;
            t0     = z;
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64    = (sword64*)(a + DILITHIUM_N);
        #endif
    #endif
        }
    }

    if (ret == 0) {
        /* Step 7: Copy random into buffer for hashing. */
        XMEMCPY(data, seed, DILITHIUM_RND_SZ);

        /* Step 6: Compute the hash of tr, public key hash, and message. */
        ret = dilithium_hash256(&key->shake, tr, DILITHIUM_TR_SZ, msg, msgLen,
            mu, DILITHIUM_MU_SZ);
    }
    if (ret == 0) {
        /* Step 9: Compute private random using hash. */
        ret = dilithium_hash256(&key->shake, k, DILITHIUM_K_SZ, data,
            DILITHIUM_RND_SZ + DILITHIUM_MU_SZ, priv_rand_seed,
            DILITHIUM_PRIV_RAND_SEED_SZ);
    }
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
    if (ret == 0) {
        dilithium_make_priv_vecs(key, s1, s2, t0);
    }
#endif
#ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
    if (ret == 0) {
        /* Step 5: Create the matrix A from the public seed. */
        ret = dilithium_expand_a(&key->shake, pub_seed, maxK, params->l, a,
            key->heap);
    }
#endif
    if (ret == 0) {
        word16 kappa = 0;
        int valid;

        /* Step 11: Start rejection sampling loop */
        do {
            byte aseed[DILITHIUM_GEN_A_SEED_SZ];
            byte w1e[DILITHIUM_MAX_W1_ENC_SZ];
            sword32* w = w1;
            byte* commit = sig;
            byte r;
            byte s;
            sword32 hi;
            sword32* wt = w;
            sword32* w0t = w0;
            sword32* w1t = w1;
            sword32* at = a;

        #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
            w0t += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * DILITHIUM_N;
            w1t += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * DILITHIUM_N;
            wt += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * DILITHIUM_N;
            at += WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A * params->l *
                DILITHIUM_N;
        #endif

            valid = 1;
            /* Step 12: Compute vector y from private random seed and kappa. */
            dilithium_vec_expand_mask(&key->shake, priv_rand_seed, kappa,
                params->gamma1_bits, y, params->l);
        #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_Y
            valid = dilithium_vec_check_low(y, params->l,
                (1 << params->gamma1_bits) - params->beta);
        #endif

        #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
            /* Step 13: NTT-1(A o NTT(y)) */
            XMEMCPY(y_ntt, y, params->s1Sz);
            dilithium_vec_ntt(y_ntt, params->l);
            dilithium_matrix_mul(w, a, y_ntt, maxK, params->l);
            dilithium_vec_invntt(w, maxK);
            /* Step 14, Step 22: Make values positive and decompose. */
            dilithium_vec_make_pos(w, maxK);
            dilithium_vec_decompose(w, maxK, params->gamma2, w0, w1);
        #endif
            /* Step 5: Create the matrix A from the public seed. */
            /* Copy the seed into a buffer that has space for s and r. */
            XMEMCPY(aseed, pub_seed, DILITHIUM_PUB_SEED_SZ);
        #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
            r = WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A;
        #else
            r = 0;
        #endif
            /* Alg 26. Step 1: Loop over first dimension of matrix. */
            for (; (ret == 0) && valid && (r < params->k); r++) {
                unsigned int e;
                sword32* yt = y;
            #ifdef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC_A
                sword32* y_ntt_t = z;
            #else
                sword32* y_ntt_t = y_ntt;
            #endif

                /* Put r/i into buffer to be hashed. */
                aseed[DILITHIUM_PUB_SEED_SZ + 1] = r;
                /* Alg 26. Step 2: Loop over second dimension of matrix. */
                for (s = 0; (ret == 0) && (s < params->l); s++) {
                    /* Put s into buffer to be hashed. */
                    aseed[DILITHIUM_PUB_SEED_SZ + 0] = s;
                    /* Alg 26. Step 3: Create polynomial from hashing seed. */
                    ret = dilithium_rej_ntt_poly_ex(&key->shake, aseed, at,
                        blocks);
                    if (ret != 0) {
                        break;
                    }
                    XMEMCPY(y_ntt_t, yt, DILITHIUM_POLY_SIZE);
                    dilithium_ntt(y_ntt_t);
                    /* Matrix multiply. */
                #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
                    if (s == 0) {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            wt[e] = dilithium_mont_red((sword64)at[e] *
                                y_ntt_t[e]);
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            wt[e + 0] = dilithium_mont_red((sword64)at[e + 0] *
                                y_ntt_t[e + 0]);
                            wt[e + 1] = dilithium_mont_red((sword64)at[e + 1] *
                                y_ntt_t[e + 1]);
                            wt[e + 2] = dilithium_mont_red((sword64)at[e + 2] *
                                y_ntt_t[e + 2]);
                            wt[e + 3] = dilithium_mont_red((sword64)at[e + 3] *
                                y_ntt_t[e + 3]);
                            wt[e + 4] = dilithium_mont_red((sword64)at[e + 4] *
                                y_ntt_t[e + 4]);
                            wt[e + 5] = dilithium_mont_red((sword64)at[e + 5] *
                                y_ntt_t[e + 5]);
                            wt[e + 6] = dilithium_mont_red((sword64)at[e + 6] *
                                y_ntt_t[e + 6]);
                            wt[e + 7] = dilithium_mont_red((sword64)at[e + 7] *
                                y_ntt_t[e + 7]);
                        }
                    #endif
                    }
                    else {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            wt[e] += dilithium_mont_red((sword64)at[e] *
                                y_ntt_t[e]);
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            wt[e + 0] += dilithium_mont_red((sword64)at[e + 0] *
                                y_ntt_t[e + 0]);
                            wt[e + 1] += dilithium_mont_red((sword64)at[e + 1] *
                                y_ntt_t[e + 1]);
                            wt[e + 2] += dilithium_mont_red((sword64)at[e + 2] *
                                y_ntt_t[e + 2]);
                            wt[e + 3] += dilithium_mont_red((sword64)at[e + 3] *
                                y_ntt_t[e + 3]);
                            wt[e + 4] += dilithium_mont_red((sword64)at[e + 4] *
                                y_ntt_t[e + 4]);
                            wt[e + 5] += dilithium_mont_red((sword64)at[e + 5] *
                                y_ntt_t[e + 5]);
                            wt[e + 6] += dilithium_mont_red((sword64)at[e + 6] *
                                y_ntt_t[e + 6]);
                            wt[e + 7] += dilithium_mont_red((sword64)at[e + 7] *
                                y_ntt_t[e + 7]);
                        }
                    #endif
                    }
                #else
                    if (s == 0) {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            t64[e] = (sword64)at[e] * y_ntt_t[e];
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            t64[e+0] = (sword64)at[e+0] * y_ntt_t[e+0];
                            t64[e+1] = (sword64)at[e+1] * y_ntt_t[e+1];
                            t64[e+2] = (sword64)at[e+2] * y_ntt_t[e+2];
                            t64[e+3] = (sword64)at[e+3] * y_ntt_t[e+3];
                            t64[e+4] = (sword64)at[e+4] * y_ntt_t[e+4];
                            t64[e+5] = (sword64)at[e+5] * y_ntt_t[e+5];
                            t64[e+6] = (sword64)at[e+6] * y_ntt_t[e+6];
                            t64[e+7] = (sword64)at[e+7] * y_ntt_t[e+7];
                        }
                    #endif
                    }
                    else {
                    #ifdef WOLFSSL_DILITHIUM_SMALL
                        for (e = 0; e < DILITHIUM_N; e++) {
                            t64[e] += (sword64)at[e] * y_ntt_t[e];
                        }
                    #else
                        for (e = 0; e < DILITHIUM_N; e += 8) {
                            t64[e+0] += (sword64)at[e+0] * y_ntt_t[e+0];
                            t64[e+1] += (sword64)at[e+1] * y_ntt_t[e+1];
                            t64[e+2] += (sword64)at[e+2] * y_ntt_t[e+2];
                            t64[e+3] += (sword64)at[e+3] * y_ntt_t[e+3];
                            t64[e+4] += (sword64)at[e+4] * y_ntt_t[e+4];
                            t64[e+5] += (sword64)at[e+5] * y_ntt_t[e+5];
                            t64[e+6] += (sword64)at[e+6] * y_ntt_t[e+6];
                            t64[e+7] += (sword64)at[e+7] * y_ntt_t[e+7];
                        }
                    #endif
                    }
                #endif
                    /* Next polynomial. */
                    yt += DILITHIUM_N;
                }
            #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
                for (e = 0; e < DILITHIUM_N; e++) {
                    wt[e] = dilithium_mont_red(t64[e]);
                }
            #endif
                dilithium_invntt(wt);
                /* Step 14, Step 22: Make values positive and decompose. */
                dilithium_make_pos(wt);
            #ifndef WOLFSSL_NO_ML_DSA_44
                if (params->gamma2 == DILITHIUM_Q_LOW_88) {
                    /* For each value of polynomial. */
                    for (e = 0; e < DILITHIUM_N; e++) {
                        /* Decompose value into two vectors. */
                        dilithium_decompose_q88(wt[e], &w0t[e], &w1t[e]);
                    }
                }
            #endif
            #if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
                if (params->gamma2 == DILITHIUM_Q_LOW_32) {
                    /* For each value of polynomial. */
                    for (e = 0; e < DILITHIUM_N; e++) {
                        /* Decompose value into two vectors. */
                        dilithium_decompose_q32(wt[e], &w0t[e], &w1t[e]);
                    }
                }
            #endif
            #ifdef WOLFSSL_DILITHIUM_SIGN_CHECK_W0
                valid = dilithium_vec_check_low(w0t,
                    params->gamma2 - params->beta);
            #endif
                wt  += DILITHIUM_N;
                w0t += DILITHIUM_N;
                w1t += DILITHIUM_N;
            }
            if ((ret == 0) && valid) {
                sword32* yt = y;
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                const byte* s1pt = s1p;
            #endif
                byte* ze = sig + params->lambda * 2;

                /* Step 15: Encode w1. */
                dilithium_vec_encode_w1(w1, params->k, params->gamma2, w1e);
                /* Step 15: Hash mu and encoded w1.
                 * Step 32: Hash is stored in signature. */
                ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ,
                    w1e, params->w1EncSz, commit, 2 * params->lambda);
                if (ret == 0) {
                    /* Step 17: Compute c from first 256 bits of commit. */
                    ret = dilithium_sample_in_ball_ex(&key->shake, commit,
                        params->tau, c, blocks);
                }
                if (ret == 0) {
                    /* Step 18: NTT(c). */
                    dilithium_ntt_small(c);
                }

                for (s = 0; (ret == 0) && valid && (s < params->l); s++) {
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                #if !defined(WOLFSSL_NO_ML_DSA_44) || \
                    !defined(WOLFSSL_NO_ML_DSA_87)
                    /* -2..2 */
                    if (params->eta == DILITHIUM_ETA_2) {
                        dilithium_decode_eta_2_bits(s1pt, s1);
                        s1pt += DILITHIUM_ETA_2_BITS * DILITHIUM_N / 8;
                    }
                #endif
                #ifndef WOLFSSL_NO_ML_DSA_65
                    /* -4..4 */
                    if (params->eta == DILITHIUM_ETA_4) {
                        dilithium_decode_eta_4_bits(s1pt, s1);
                        s1pt += DILITHIUM_N / 2;
                    }
                #endif
                    dilithium_ntt_small(s1);
                    dilithium_mul(z, c, s1);
            #else
                    dilithium_mul(z, c, s1 + s * DILITHIUM_N);
            #endif
                    /* Step 19: cs1 = NTT-1(c o s1) */
                    dilithium_invntt(z);
                    /* Step 21: z = y + cs1 */
                    dilithium_add(z, yt);
                    dilithium_poly_red(z);
                    /* Step 23: Check z has low enough values. */
                    hi = (1 << params->gamma1_bits) - params->beta;
                    valid = dilithium_check_low(z, hi);
                    if (valid) {
                        /* Step 32: Encode z into signature.
                         * Commit (c) and h already encoded into signature. */
                    #if !defined(WOLFSSL_NO_ML_DSA_44)
                        if (params->gamma1_bits == DILITHIUM_GAMMA1_BITS_17) {
                            dilithium_encode_gamma1_17_bits(z, ze);
                            /* Move to next place to encode to. */
                            ze += DILITHIUM_GAMMA1_17_ENC_BITS / 2 *
                                  DILITHIUM_N / 4;
                        }
                        else
                    #endif
                    #if !defined(WOLFSSL_NO_ML_DSA_65) || \
                        !defined(WOLFSSL_NO_ML_DSA_87)
                        if (params->gamma1_bits == DILITHIUM_GAMMA1_BITS_19) {
                            dilithium_encode_gamma1_19_bits(z, ze);
                            /* Move to next place to encode to. */
                            ze += DILITHIUM_GAMMA1_19_ENC_BITS / 2 *
                                  DILITHIUM_N / 4;
                        }
                    #endif
                    }

                    yt += DILITHIUM_N;
                }
            }
            if ((ret == 0) && valid) {
                const byte* t0pt = t0p;
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                const byte* s2pt = s2p;
            #endif
                sword32* cs2 = ct0;
                w0t = w0;
                w1t = w1;
                byte idx = 0;

                for (r = 0; valid && (r < params->k); r++) {
            #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                #if !defined(WOLFSSL_NO_ML_DSA_44) || \
                    !defined(WOLFSSL_NO_ML_DSA_87)
                    /* -2..2 */
                    if (params->eta == DILITHIUM_ETA_2) {
                        dilithium_decode_eta_2_bits(s2pt, s2);
                        s2pt += DILITHIUM_ETA_2_BITS * DILITHIUM_N / 8;
                    }
                #endif
                #ifndef WOLFSSL_NO_ML_DSA_65
                    /* -4..4 */
                    if (params->eta == DILITHIUM_ETA_4) {
                        dilithium_decode_eta_4_bits(s2pt, s2);
                        s2pt += DILITHIUM_N / 2;
                    }
                #endif
                    dilithium_ntt_small(s2);
                    /* Step 20: cs2 = NTT-1(c o s2) */
                    dilithium_mul(cs2, c, s2);
            #else
                    /* Step 20: cs2 = NTT-1(c o s2) */
                    dilithium_mul(cs2, c, s2 + r * DILITHIUM_N);
            #endif
                    dilithium_invntt(cs2);
                    /* Step 22: w0 - cs2 */
                    dilithium_sub(w0t, cs2);
                    dilithium_poly_red(w0t);
                    /* Step 23: Check w0 - cs2 has low enough values. */
                    hi = params->gamma2 - params->beta;
                    valid = dilithium_check_low(w0t, hi);
                    if (valid) {
                    #ifndef WOLFSSL_DILITHIUM_SIGN_SMALL_MEM_PRECALC
                        dilithium_decode_t0(t0pt, t0);
                        dilithium_ntt(t0);

                        /* Step 25: ct0 = NTT-1(c o t0) */
                        dilithium_mul(ct0, c, t0);
                    #else
                        /* Step 25: ct0 = NTT-1(c o t0) */
                        dilithium_mul(ct0, c, t0 + r * DILITHIUM_N);
                    #endif
                        dilithium_invntt(ct0);
                        /* Step 27: Check ct0 has low enough values. */
                        valid = dilithium_check_low(ct0, params->gamma2);
                    }
                    if (valid) {
                        /* Step 26: ct0 = ct0 + w0 */
                        dilithium_add(ct0, w0t);
                        dilithium_poly_red(ct0);

                        /* Step 26, 27: Make hint from ct0 and w1 and check
                         * number of hints is valid.
                         * Step 32: h is encoded into signature.
                         */
                    #ifndef WOLFSSL_NO_ML_DSA_44
                        if (params->gamma2 == DILITHIUM_Q_LOW_88) {
                            valid = (dilithium_make_hint_88(ct0, w1t, h,
                                &idx) == 0);
                            /* Alg 14, Step 10: Store count of hints for
                             *                  polynomial at end of list. */
                            h[PARAMS_ML_DSA_44_OMEGA + r] = idx;
                        }
                    #endif
                    #if !defined(WOLFSSL_NO_ML_DSA_65) || \
                        !defined(WOLFSSL_NO_ML_DSA_87)
                        if (params->gamma2 == DILITHIUM_Q_LOW_32) {
                            valid = (dilithium_make_hint_32(ct0, w1t,
                                params->omega, h, &idx) == 0);
                            /* Alg 14, Step 10: Store count of hints for
                             *                  polynomial at end of list. */
                            h[params->omega + r] = idx;
                        }
                    #endif
                    }

                    t0pt += DILITHIUM_D * DILITHIUM_N / 8;
                    w0t += DILITHIUM_N;
                    w1t += DILITHIUM_N;
                }
                /* Set remaining hints to zero. */
                XMEMSET(h + idx, 0, params->omega - idx);
            }

            if (!valid) {
                /* Too many attempts - something wrong with implementation. */
                if ((kappa > (word16)(kappa + params->l))) {
                    ret = BAD_COND_E;
                }

                /* Step 30: increment value to append to seed to unique value.
                 */
                kappa += params->l;
            }
        }
        /* Step 11: Check we have a valid signature. */
        while ((ret == 0) && (!valid));
    }

    XFREE(y, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#endif
}

/* Sign a message with the key and a random number generator.
 *
 * FIPS 204. 6: Algorithm 2 MD-DSA.Sign(sk, M)
 *   ...
 *   7: rnd <- {0,1}256  [Randomly generated.]
 *   ...
 *
 * @param [in, out] key     Dilithium key.
 * @param [in, out] rng     Random number generator.
 * @param [in]      msg     Message data to sign.
 * @param [in]      msgLen  Length of message data in bytes.
 * @param [out]     sig     Buffer to hold signature.
 * @param [in, out] sigLen  On in, length of buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  0 on success.
 * @return  BUFFER_E when the signature buffer is too small.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int mldsa_composite_sign_msg(mldsa_composite_key* key, WC_RNG* rng, const byte* msg,
    word32 msgLen, byte* sig, word32 *sigLen)
{
    int ret = 0;
    byte rnd[DILITHIUM_RND_SZ];

    /* Must have a random number generator. */
    if (rng == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Step 7: Generate random seed. */
        ret = wc_RNG_GenerateBlock(rng, rnd, DILITHIUM_RND_SZ);
    }
    if (ret == 0) {
        /* Sign with random seed. */
        ret = dilithium_sign_msg_with_seed(key, rnd, msg, msgLen, sig,
            sigLen);
    }

    return ret;
}

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_SIGN */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY

/* Verify signature of message using public key.
 *
 * FIPS 204. 6: Algorithm 3 ML-DSA.Verify(pk, M, sigma)
 *  1: (rho, t1) <- pkDecode(pk)
 *  2: (c_tilde, z, h) <- sigDecode(sigma)
 *  3: if h = falsam then return false
 *  4: end if
 *  5: A_circum <- ExpandS(rho)
 *  6: tr <- H(BytesToBits(pk), 512)
 *  7: mu <- H(tr||M, 512)
 *  8: (c1_tilde, c2_tilde) E {0,1}256 x {0,1)2*lambda-256 <- c_tilde
 *  9: c <- SampleInBall(c1_tilde)
 * 10: w'approx <- NTT-1(A_circum o NTT(z) - NTT(c) o NTT(t1.s^d))
 * 11: w1' <- UseHint(h, w'approx)
 * 12: c'_tilde < H(mu||w1Encode(w1'), 2*lambda)
 * 13: return [[ ||z||inf < GAMMA1 - BETA]] and [[c_tilde = c'_tilde]] and
 *             [[number of 1's in h is <= OMEGA
 *
 * @param [in, out] key     Dilithium key.
 * @param [in]      msg     Message to verify.
 * @param [in]      msgLen  Length of message in bytes.
 * @param [in]      sig     Signature to verify message.
 * @param [in]      sigLen  Length of message in bytes.
 * @param [out]     res     Result of verification.
 * @return  0 on success.
 * @return  SIG_VERIFY_E when hint is malformed.
 * @return  BUFFER_E when the length of the signature does not match
 *          parameters.
 * @return  MEMORY_E when memory allocation fails.
 * @return  Other negative when an error occurs.
 */
static int mldsa_composite_verify_msg(mldsa_composite_key* key, const byte* msg,
    word32 msgLen, const byte* sig, word32 sigLen, int* res)
{
#ifndef WOLFSSL_MLDSA_COMPOSITE_VERIFY_SMALL_MEM
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->p;
    const byte* commit = sig;
    const byte* ze = sig + params->lambda * 2;
    const byte* h = ze + params->zEncSz;
    sword32* a = NULL;
    sword32* t1 = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* w = NULL;
    sword32* t1c = NULL;
    byte tr[DILITHIUM_TR_SZ];
    byte* mu = tr;
    byte* w1e = NULL;
    byte* commit_calc = tr;
    int valid = 0;
    sword32 hi;

    /* Ensure the signature is the right size for the parameters. */
    if (sigLen != params->sigSz) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Step 13: Verify the hint is well-formed. */
        ret = dilithium_check_hint(h, params->k, params->omega);
    }

    /* Allocate memory for large intermediates. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->a == NULL)) {
        key->a = (sword32*)XMALLOC(params->aSz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->a == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        a = key->a;
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->t1 == NULL)) {
        key->t1 = (sword32*)XMALLOC(params->s2Sz, key->heap,
            DYNAMIC_TYPE_DILITHIUM);
        if (key->t1 == NULL) {
            ret = MEMORY_E;
        }
    }
#endif
    if (ret == 0) {
        t1 = key->t1;
    }
#endif
    if (ret == 0) {
        unsigned int allocSz;

        /* z, c, w, t1/t1c */
        allocSz = DILITHIUM_POLY_SIZE + params->s1Sz + params->s2Sz +
            params->s2Sz;
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
        /* a */
        allocSz += params->aSz;
#endif

        z = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (z == NULL) {
            ret = MEMORY_E;
        }
        else {
            c   = z  + params->s1Sz / sizeof(*z);
            w   = c  + DILITHIUM_N;
#ifndef WC_DILITHIUM_CACHE_PUB_VECTORS
            t1  = w  + params->s2Sz / sizeof(*w);
            t1c = t1;
#else
            t1c = w  + params->s2Sz / sizeof(*w);
#endif
#ifndef WC_DILITHIUM_CACHE_MATRIX_A
            a   = t1 + params->s2Sz / sizeof(*t1);
#endif
            w1e = (byte*)c;
        }
    }

    if (ret == 0) {
        /* Step 2: Decode z from signature. */
        dilithium_vec_decode_gamma1(ze, params->l, params->gamma1_bits, z);
        /* Step 13: Check z is valid - values are low enough. */
        hi = (1 << params->gamma1_bits) - params->beta;
        valid = dilithium_vec_check_low(z, params->l, hi);
    }
    if ((ret == 0) && valid) {
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
        /* Check that we haven't already cached the public vector. */
        if (!key->pubVecSet)
#endif
        {
            /* Step 1: Decode and NTT vector t1. */
            dilithium_make_pub_vec(key, t1);
        }

#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Check that we haven't already cached the matrix A. */
        if (!key->aSet)
#endif
        {
            /* Step 5: Expand pub seed to compute matrix A. */
            ret = dilithium_expand_a(&key->shake, pub_seed, params->k,
                params->l, a, key->heap);
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
            /* Whether we have cached A is dependent on success of operation. */
            key->aSet = (ret == 0);
#endif
        }
    }
    if ((ret == 0) && valid) {
        /* Step 6: Hash public key. */
        ret = dilithium_shake256(&key->shake, key->p, params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if ((ret == 0) && valid) {
        /* Step 7: Hash hash of public key and message. */
        ret = dilithium_hash256(&key->shake, tr, DILITHIUM_TR_SZ, msg, msgLen,
            mu, DILITHIUM_MU_SZ);
    }
    if ((ret == 0) && valid) {
        /* Step 9: Compute c from first 256 bits of commit. */
        ret = dilithium_sample_in_ball(&key->shake, commit, params->tau, c,
            key->heap);
    }
    if ((ret == 0) && valid) {
        /* Step 10: w = NTT-1(A o NTT(z) - NTT(c) o NTT(t1)) */
        dilithium_vec_ntt(z, params->l);
        dilithium_matrix_mul(w, a, z, params->k, params->l);
        dilithium_ntt_small(c);
        dilithium_vec_mul(t1c, c, t1, params->k);
        dilithium_vec_sub(w, t1c, params->k);
        dilithium_vec_invntt(w, params->k);
        /* Step 11: Use hint to give full w1. */
        dilithium_vec_use_hint(w, params->k, params->gamma2, params->omega, h);
        /* Step 12: Encode w1. */
        dilithium_vec_encode_w1(w, params->k, params->gamma2, w1e);
        /* Step 12: Hash mu and encoded w1. */
        ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ, w1e,
            params->w1EncSz, commit_calc, 2 * params->lambda);
    }
    if ((ret == 0) && valid) {
        /* Step 13: Compare commit. */
        valid = (XMEMCMP(commit, commit_calc, 2 * params->lambda) == 0);
    }

    *res = valid;
    XFREE(z, key->heap, DYNAMIC_TYPE_DILITHIUM);
    return ret;
#else
    int ret = 0;
    const wc_dilithium_params* params = key->params;
    const byte* pub_seed = key->p;
    const byte* t1p = pub_seed + DILITHIUM_PUB_SEED_SZ;
    const byte* commit = sig;
    const byte* ze = sig + params->lambda * 2;
    const byte* h = ze + params->zEncSz;
    sword32* t1 = NULL;
    sword32* a = NULL;
    sword32* c = NULL;
    sword32* z = NULL;
    sword32* w = NULL;
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    sword64* t64 = NULL;
#endif
#ifndef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
    byte*    block = NULL;
#endif
    byte tr[DILITHIUM_TR_SZ];
    byte* mu = tr;
    byte* w1e = NULL;
    byte* commit_calc = tr;
    int valid = 0;
    sword32 hi;
    unsigned int r;
    byte o;
    byte* encW1;
    byte* seed = tr;

    /* Ensure the signature is the right size for the parameters. */
    if (sigLen != params->sigSz) {
        ret = BUFFER_E;
    }
    if (ret == 0) {
        /* Step 13: Verify the hint is well-formed. */
        ret = dilithium_check_hint(h, params->k, params->omega);
    }

#ifndef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
    /* Allocate memory for large intermediates. */
    if (ret == 0) {
        /* z, c, w, t1, w1e. */
        unsigned int allocSz;

        allocSz  = params->s1Sz + 3 * DILITHIUM_POLY_SIZE +
            DILITHIUM_REJ_NTT_POLY_H_SIZE + params->w1EncSz;
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        allocSz += DILITHIUM_POLY_SIZE * 2;
    #endif
        z = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (z == NULL) {
            ret = MEMORY_E;
        }
        else {
            c     = z + params->s1Sz / sizeof(*t1);
            w     = c + DILITHIUM_N;
            t1    = w + DILITHIUM_N;
            block = (byte*)(t1 + DILITHIUM_N);
            w1e   = block + DILITHIUM_REJ_NTT_POLY_H_SIZE;
            a     = t1;
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            t64   = (sword64*)(w1e + params->w1EncSz);
        #endif
        }
    }
#else
    if (ret == 0) {
        z = key->z;
        c = key->c;
        w = key->w;
        t1 = key->t1;
        w1e = key->w1e;
        a = t1;
    #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        t64 = key->t64;
    #endif
    }
#endif

    if (ret == 0) {
        /* Step 2: Decode z from signature. */
        dilithium_vec_decode_gamma1(ze, params->l, params->gamma1_bits, z);
        /* Step 13: Check z is valid - values are low enough. */
        hi = (1 << params->gamma1_bits) - params->beta;
        valid = dilithium_vec_check_low(z, params->l, hi);
    }
    if ((ret == 0) && valid) {
        /* Step 10: NTT(z) */
        dilithium_vec_ntt(z, params->l);

         /* Step 9: Compute c from first 256 bits of commit. */
#ifdef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
         ret = dilithium_sample_in_ball_ex(&key->shake, commit, params->tau, c,
             key->block);
#else
         ret = dilithium_sample_in_ball_ex(&key->shake, commit, params->tau, c,
             block);
#endif
    }
    if ((ret == 0) && valid) {
        dilithium_ntt_small(c);

        o = 0;
        encW1 = w1e;

        /* Copy the seed into a buffer that has space for s and r. */
        XMEMCPY(seed, pub_seed, DILITHIUM_PUB_SEED_SZ);
        /* Step 1: Loop over first dimension of matrix. */
        for (r = 0; (ret == 0) && (r < params->k); r++) {
            unsigned int s;
            unsigned int e;
            const sword32* zt = z;

            /* Step 1: Decode and NTT vector t1. */
            dilithium_decode_t1(t1p, w);
            /* Next polynomial. */
            t1p += DILITHIUM_U * DILITHIUM_N / 8;

            /* Step 10: - NTT(c) o NTT(t1)) */
            dilithium_ntt(w);
    #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
        #ifdef WOLFSSL_DILITHIUM_SMALL
            for (e = 0; e < DILITHIUM_N; e++) {
                w[e] = -dilithium_mont_red((sword64)c[e] * w[e]);
            }
        #else
            for (e = 0; e < DILITHIUM_N; e += 8) {
                w[e+0] = -dilithium_mont_red((sword64)c[e+0] * w[e+0]);
                w[e+1] = -dilithium_mont_red((sword64)c[e+1] * w[e+1]);
                w[e+2] = -dilithium_mont_red((sword64)c[e+2] * w[e+2]);
                w[e+3] = -dilithium_mont_red((sword64)c[e+3] * w[e+3]);
                w[e+4] = -dilithium_mont_red((sword64)c[e+4] * w[e+4]);
                w[e+5] = -dilithium_mont_red((sword64)c[e+5] * w[e+5]);
                w[e+6] = -dilithium_mont_red((sword64)c[e+6] * w[e+6]);
                w[e+7] = -dilithium_mont_red((sword64)c[e+7] * w[e+7]);
            }
        #endif
    #else
        #ifdef WOLFSSL_DILITHIUM_SMALL
            for (e = 0; e < DILITHIUM_N; e++) {
                t64[e] = -(sword64)c[e] * w[e];
            }
        #else
            for (e = 0; e < DILITHIUM_N; e += 8) {
                t64[e+0] = -(sword64)c[e+0] * w[e+0];
                t64[e+1] = -(sword64)c[e+1] * w[e+1];
                t64[e+2] = -(sword64)c[e+2] * w[e+2];
                t64[e+3] = -(sword64)c[e+3] * w[e+3];
                t64[e+4] = -(sword64)c[e+4] * w[e+4];
                t64[e+5] = -(sword64)c[e+5] * w[e+5];
                t64[e+6] = -(sword64)c[e+6] * w[e+6];
                t64[e+7] = -(sword64)c[e+7] * w[e+7];
            }
        #endif
    #endif

            /* Step 5: Expand pub seed to compute matrix A. */
            /* Put r into buffer to be hashed. */
            seed[DILITHIUM_PUB_SEED_SZ + 1] = r;
            for (s = 0; (ret == 0) && (s < params->l); s++) {
                /* Put s into buffer to be hashed. */
                seed[DILITHIUM_PUB_SEED_SZ + 0] = s;
                /* Step 3: Create polynomial from hashing seed. */
            #ifdef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
                ret = dilithium_rej_ntt_poly_ex(&key->shake, seed, a, key->h);
            #else
                ret = dilithium_rej_ntt_poly_ex(&key->shake, seed, a, block);
            #endif

                /* Step 10: w = A o NTT(z) - NTT(c) o NTT(t1) */
        #ifndef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            #ifdef WOLFSSL_DILITHIUM_SMALL
                for (e = 0; e < DILITHIUM_N; e++) {
                    w[e] += dilithium_mont_red((sword64)a[e] * zt[e]);
                }
            #else
                for (e = 0; e < DILITHIUM_N; e += 8) {
                    w[e+0] += dilithium_mont_red((sword64)a[e+0] * zt[e+0]);
                    w[e+1] += dilithium_mont_red((sword64)a[e+1] * zt[e+1]);
                    w[e+2] += dilithium_mont_red((sword64)a[e+2] * zt[e+2]);
                    w[e+3] += dilithium_mont_red((sword64)a[e+3] * zt[e+3]);
                    w[e+4] += dilithium_mont_red((sword64)a[e+4] * zt[e+4]);
                    w[e+5] += dilithium_mont_red((sword64)a[e+5] * zt[e+5]);
                    w[e+6] += dilithium_mont_red((sword64)a[e+6] * zt[e+6]);
                    w[e+7] += dilithium_mont_red((sword64)a[e+7] * zt[e+7]);
                }
            #endif
        #else
            #ifdef WOLFSSL_DILITHIUM_SMALL
                for (e = 0; e < DILITHIUM_N; e++) {
                    t64[e] += (sword64)a[e] * zt[e];
                }
            #else
                for (e = 0; e < DILITHIUM_N; e += 8) {
                    t64[e+0] += (sword64)a[e+0] * zt[e+0];
                    t64[e+1] += (sword64)a[e+1] * zt[e+1];
                    t64[e+2] += (sword64)a[e+2] * zt[e+2];
                    t64[e+3] += (sword64)a[e+3] * zt[e+3];
                    t64[e+4] += (sword64)a[e+4] * zt[e+4];
                    t64[e+5] += (sword64)a[e+5] * zt[e+5];
                    t64[e+6] += (sword64)a[e+6] * zt[e+6];
                    t64[e+7] += (sword64)a[e+7] * zt[e+7];
                }
            #endif
        #endif
                /* Next polynomial. */
                zt += DILITHIUM_N;
            }
        #ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
            for (e = 0; e < DILITHIUM_N; e++) {
                w[e] = dilithium_mont_red(t64[e]);
            }
        #endif

            /* Step 10: w = NTT-1(A o NTT(z) - NTT(c) o NTT(t1)) */
            dilithium_invntt(w);

        #ifndef WOLFSSL_NO_ML_DSA_44
            if (params->gamma2 == DILITHIUM_Q_LOW_88) {
                /* Step 11: Use hint to give full w1. */
                dilithium_use_hint_88(w, h, r, &o);
                /* Step 12: Encode w1. */
                dilithium_encode_w1_88(w, encW1);
                encW1 += DILITHIUM_Q_HI_88_ENC_BITS * 2 * DILITHIUM_N / 16;
            }
            else
        #endif
        #if !defined(WOLFSSL_NO_ML_DSA_65) || !defined(WOLFSSL_NO_ML_DSA_87)
            if (params->gamma2 == DILITHIUM_Q_LOW_32) {
                /* Step 11: Use hint to give full w1. */
                dilithium_use_hint_32(w, h, params->omega, r, &o);
                /* Step 12: Encode w1. */
                dilithium_encode_w1_32(w, encW1);
                encW1 += DILITHIUM_Q_HI_32_ENC_BITS * 2 * DILITHIUM_N / 16;
            }
            else
        #endif
            {
            }
        }
    }
    if ((ret == 0) && valid) {
        /* Step 6: Hash public key. */
        ret = dilithium_shake256(&key->shake, key->p, params->pkSz, tr,
            DILITHIUM_TR_SZ);
    }
    if ((ret == 0) && valid) {
        /* Step 7: Hash hash of public key and message. */
        ret = dilithium_hash256(&key->shake, tr, DILITHIUM_TR_SZ, msg, msgLen,
            mu, DILITHIUM_MU_SZ);
    }
    if ((ret == 0) && valid) {
        /* Step 12: Hash mu and encoded w1. */
        ret = dilithium_hash256(&key->shake, mu, DILITHIUM_MU_SZ, w1e,
            params->w1EncSz, commit_calc, 2 * params->lambda);
    }
    if ((ret == 0) && valid) {
        /* Step 13: Compare commit. */
        valid = (XMEMCMP(commit, commit_calc, 2 * params->lambda) == 0);
    }

    *res = valid;
#ifndef WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC
    XFREE(z, key->heap, DYNAMIC_TYPE_DILITHIUM);
#endif
    return ret;
#endif /* !WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM */
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY */

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY
int wc_mldsa_composite_make_key(mldsa_composite_key* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
    #ifndef WOLF_CRYPTO_CB_FIND
        if (key->devId != INVALID_DEVID)
    #endif
        {
            ret = wc_CryptoCb_MakePqcSignatureKey(rng,
                WC_PQC_SIG_TYPE_DILITHIUM, key->level, key);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return ret;
            /* fall-through when unavailable */
            ret = 0;
        }
    }
#endif

    if (ret == 0) {
#ifdef WOLFSSL_WC_MLDSA_COMPOSITE
        /* Check the level or parameters have been set. */
        if (key->params == NULL) {
            ret = BAD_STATE_E;
        }
        else {
            /* Make the key. */
            ret = mldsa_composite_make_key(key, rng);
        }
#endif
    }

    return ret;
}

int wc_mldsa_composite_make_key_from_seed(mldsa_composite_key* key, const byte* seed)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (seed == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
#ifdef WOLFSSL_WC_MLDSA_COMPOSITE
        /* Check the level or parameters have been set. */
        if (key->params == NULL) {
            ret = BAD_STATE_E;
        }
        else {
            /* Make the key. */
            ret = mldsa_composite_make_key_from_seed(key, seed);
        }
#endif
    }

    return ret;
}
#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_MAKE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_SIGN
/* Sign the message using the dilithium private key.
 *
 *  msg         [in]      Message to sign.
 *  msgLen      [in]      Length of the message in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL or public key not set,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_mldsa_composite_sign_msg(const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen, mldsa_composite* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((msg == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
    #ifndef WOLF_CRYPTO_CB_FIND
        if (key->devId != INVALID_DEVID)
    #endif
        {
            ret = wc_CryptoCb_PqcSign(msg, msgLen, sig, sigLen, rng,
                WC_PQC_SIG_TYPE_DILITHIUM, key);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return ret;
            /* fall-through when unavailable */
            ret = 0;
        }
    }
#endif

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_MLDSA_COMPOSITE
        ret = mldsa_composite_sign_msg(key, rng, msg, msgLen, sig, sigLen);
    #endif
    }

    return ret;
}

/* Sign the message using the dilithium private key.
 *
 *  msg         [in]      Message to sign.
 *  msgLen      [in]      Length of the message in bytes.
 *  sig         [out]     Buffer to write signature into.
 *  sigLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Dilithium key to use when signing
 *  returns BAD_FUNC_ARG when a parameter is NULL or public key not set,
 *          BUFFER_E when outLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_mldsa_composite_sign_msg_with_seed(const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen, mldsa_composite* key, byte* seed)
{
    int ret = 0;

    /* Validate parameters. */
    if ((msg == NULL) || (sig == NULL) || (sigLen == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Sign message. */
    #ifdef WOLFSSL_WC_DILITHIUM
        ret = mldsa_composite_sign_msg_with_seed(key, seed, msg, msgLen, sig, sigLen);
    #elif defined(HAVE_LIBOQS)
        ret = NOT_COMPILED_IN;
        (void)msgLen;
        (void)seed;
    #endif
    }

    return ret;
}
#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_SIGN */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY
/* Verify the message using the dilithium public key.
 *
 *  sig         [in]  Signature to verify.
 *  sigLen      [in]  Size of signature in bytes.
 *  msg         [in]  Message to verify.
 *  msgLen      [in]  Length of the message in bytes.
 *  res         [out] *res is set to 1 on successful verification.
 *  key         [in]  Dilithium key to use to verify.
 *  returns BAD_FUNC_ARG when a parameter is NULL or contextLen is zero when and
 *          BUFFER_E when sigLen is less than DILITHIUM_LEVEL2_SIG_SIZE,
 *          0 otherwise.
 */
int wc_mldsa_composite_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, mldsa_composite_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (msg == NULL) || (res == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    #ifdef WOLF_CRYPTO_CB
    if (ret == 0) {
        #ifndef WOLF_CRYPTO_CB_FIND
        if (key->devId != INVALID_DEVID)
        #endif
        {
            ret = wc_CryptoCb_PqcVerify(sig, sigLen, msg, msgLen, res,
                WC_PQC_SIG_TYPE_DILITHIUM, key);
            if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
                return ret;
            /* fall-through when unavailable */
            ret = 0;
        }
    }
    #endif

    if (ret == 0) {
        /* Verify message with signature. */
    #ifdef WOLFSSL_WC_MLDSA_COMPOSITE
        ret = dilithium_verify_msg(key, msg, msgLen, sig, sigLen, res);
    #endif
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY */

/* Initialize the MlDsaComposite private/public key.
 *
 * key  [in]  mldsa_composite key.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_mldsa_composite_init(mldsa_composite_key* key)
{
    return wc_mldsa_composite_init_ex(key, NULL, INVALID_DEVID);
}

/* Initialize the MlDsaComposite private/public key.
 *
 * key  [in]  MlDsaComposite key.
 * heap [in]  Heap hint.
 * devId[in]  Device ID.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_mldsa_composite_init_ex(mldsa_composite_key* key, void* heap, int devId)
{
    int ret = 0;

    (void)devId;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Init the MLDSA Key */
    ret = wc_dilithium_init_ex(&key->mldsa_key, heap, devId);

    /* Initialize the traditional key */
    //
    // MISSING CODE
    //
    return ret;
}

#ifdef WOLF_PRIVATE_KEY_ID
int wc_mldsa_composite_init_id(mldsa_composite_key* key, const unsigned char* id, int len,
    void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && ((len < 0) || (len > DILITHIUM_MAX_ID_LEN))) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ret = wc_dilithium_init_ex(key, heap, devId);
    }
    if ((ret == 0) && (id != NULL) && (len != 0)) {
        XMEMCPY(key->id, id, (size_t)len);
        key->idLen = len;
    }

    /* Set the maximum level here */
    wc_dilithium_set_level(key->mldsa_key, WC_ML_DSA_87);

    return ret;
}

int wc_mldsa_composite_init_label(mldsa_composite_key* key, const char* label, void* heap,
    int devId)
{
    int ret = 0;
    int labelLen = 0;

    if ((key == NULL) || (label == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        labelLen = (int)XSTRLEN(label);
        if ((labelLen == 0) || (labelLen > MLDSA_COMPOISTE_MAX_LABEL_LEN)) {
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        ret = wc_mldsa_composite_init_ex(key, heap, devId);
    }
    if (ret == 0) {
        XMEMCPY(key->label, label, (size_t)labelLen);
        key->labelLen = labelLen;
    }

    /* Set the maximum level here */
    wc_dilithium_set_level(key, WC_ML_DSA_87);


    return ret;
}
#endif

/* Set the level of the MlDsaComposite private/public key.
 *
 * key   [out]  MlDsaComposite key.
 * level [in]   Either 2,3 or 5.
 * returns BAD_FUNC_ARG when key is NULL or level is a bad values.
 */
int wc_mldsa_composite_set_level(mldsa_composite_key* key, byte level)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (level != WC_ML_DSA_44) && (level != WC_ML_DSA_65) &&
            (level != WC_ML_DSA_87)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
#ifdef WOLFSSL_WC_DILITHIUM
        /* Get the parameters for level into key. */
        ret = dilithium_get_params(level, &key->params);
    }
    if (ret == 0) {
        /* Clear any cached items. */
#ifndef WC_DILITHIUM_FIXED_ARRAY
    #ifdef WC_DILITHIUM_CACHE_MATRIX_A
        XFREE(key->a, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->a = NULL;
        key->aSet = 0;
    #endif
    #ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
        XFREE(key->s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->s1 = NULL;
        key->s2 = NULL;
        key->t0 = NULL;
        key->privVecsSet = 0;
    #endif
    #ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
        XFREE(key->t1, key->heap, DYNAMIC_TYPE_DILITHIUM);
        key->t1 = NULL;
        key->pubVecSet = 0;
    #endif
#endif
#endif /* WOLFSSL_WC_DILITHIUM */

        /* Store level and indicate public and private key are not set. */
        key->level = level;
        key->pubKeySet = 0;
        key->prvKeySet = 0;
    }

    return ret;
}

/* Get the level of the MlDsaComposite private/public key.
 *
 * key   [in]  MlDsaComposite key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_mldsa_composite_get_level(mldsa_composite_key* key, byte* level)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (level == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (key->level != WC_ML_DSA_44) &&
            (key->level != WC_ML_DSA_65) && (key->level != WC_ML_DSA_87)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Return level. */
        *level = key->level;
    }

    return ret;
}

/* Clears the MlDsaComposite key data
 *
 * key  [in]  MlDsaComposite key.
 */
void wc_mldsa_composite_free(mldsa_composite_key* key)
{
    if (key != NULL) {
#ifdef WOLFSSL_WC_MLDSA_COMPOSITE

        /* Ensure all private data is zeroized. */
        ForceZero(key, sizeof(*key));
    }
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY
/* Returns the size of a MlDsaComposite private key.
 *
 * @param [in] key  Dilithium private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->level == WC_ML_DSA_44) {
            ret = DILITHIUM_LEVEL2_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = DILITHIUM_LEVEL3_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = DILITHIUM_LEVEL5_KEY_SIZE;
        }
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Private key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_priv_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->level == WC_ML_DSA_44) {
            ret = DILITHIUM_LEVEL2_PRV_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = DILITHIUM_LEVEL3_PRV_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = DILITHIUM_LEVEL5_PRV_KEY_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a MlDsaComposite private plus public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Private key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaCompositeKey_GetPrivLen(MlDsaCompositeKey* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_priv_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */
#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Public key size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_pub_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->level == WC_ML_DSA_44) {
            ret = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a MlDsaComposite public key.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Public key size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaComposite_GetPubLen(MlDsaComposite* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_pub_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_SIGN) || !defined(WOLFSSL_MLDSA_COMPOSITE_NO_VERIFY)
/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  Signature size on success for set level.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_mldsa_composite_sig_size(mldsa_composite_key* key)
{
    int ret = BAD_FUNC_ARG;

    if (key != NULL) {
        if (key->level == WC_ML_DSA_44) {
            ret = DILITHIUM_LEVEL2_SIG_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = DILITHIUM_LEVEL3_SIG_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = DILITHIUM_LEVEL5_SIG_SIZE;
        }
    }

    return ret;
}

/* Returns the size of a MlDsaComposite signature.
 *
 * @param [in]  key  MlDsaComposite private/public key.
 * @param [out] len  Signature size for set level.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or level not set,
 */
int wc_MlDsaComposite_GetSigLen(MlDsaComposite* key, int* len)
{
    int ret = 0;

    *len = wc_mldsa_composite_sig_size(key);
    if (*len < 0) {
        ret = *len;
    }

    return ret;
}
#endif

#ifdef WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY
/* Check the public key of the MlDsaComposite key matches the private key.
 *
 * @param [in] key  MlDsaComposite private/public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL or no private key available,
 * @return  PUBLIC_KEY_E when the public key is not set or doesn't match,
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wc_mldsa_composite_check_key(mldsa_composite_key* key)
{
    int ret = 0;
#ifdef WOLFSSL_WC_MLDSA_COMPOSITE
    const wc_mldsa_composite_params* params;
    sword32* a  = NULL;
    sword32* s1 = NULL;
    sword32* s2 = NULL;
    sword32* t  = NULL;
    sword32* t0 = NULL;
    sword32* t1 = NULL;

    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = PUBLIC_KEY_E;
    }

    /* Any value in public key are valid.
     * Public seed is hashed to generate matrix A.
     * t1 is the top 10 bits of a number in range of 0..(Q-1).
     * Q >> 13 = 0x3ff so all encoded values are valid.
     */

    if (ret == 0) {
        params = key->params;
        unsigned int allocSz;

        /* s1-L, s2-K, t0-K, t-K, t1-K */
        allocSz = params->s1Sz + 4 * params->s2Sz;
#if !defined(WC_DILITHIUM_CACHE_MATRIX_A)
        /* A-KxL */
        allocSz += params->aSz;
#endif

        /* Allocate memory for large intermediates. */
        s1 = (sword32*)XMALLOC(allocSz, key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (s1 == NULL) {
            ret = MEMORY_E;
        }
        else {
            s2 = s1 + params->s1Sz / sizeof(*s1);
            t0 = s2 + params->s2Sz / sizeof(*s2);
            t  = t0 + params->s2Sz / sizeof(*t0);
            t1 = t  + params->s2Sz / sizeof(*t);
#if !defined(WC_DILITHIUM_CACHE_MATRIX_A)
            a  = t1 + params->s2Sz / sizeof(*t1);
#else
            a = key->a;
#endif
        }
    }

    if (ret == 0) {
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
        /* Check that we haven't already cached the matrix A. */
        if (!key->aSet)
#endif
        {
            const byte* pub_seed = key->p;

            ret = dilithium_expand_a(&key->shake, pub_seed, params->k,
                params->l, a, key->heap);
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
            key->aSet = (ret == 0);
#endif
        }
    }
    if (ret == 0) {
        const byte* s1p = key->k + DILITHIUM_PUB_SEED_SZ + DILITHIUM_K_SZ +
                                   DILITHIUM_TR_SZ;
        const byte* s2p = s1p + params->s1EncSz;
        const byte* t0p = s2p + params->s2EncSz;
        const byte* t1p = key->p + DILITHIUM_PUB_SEED_SZ;
        sword32* tt = t;
        unsigned int i;
        unsigned int j;
        sword32 x = 0;

        /* Get s1, s2 and t0 from private key. */
        dilithium_vec_decode_eta_bits(s1p, params->eta, s1, params->l);
        dilithium_vec_decode_eta_bits(s2p, params->eta, s2, params->k);
        dilithium_vec_decode_t0(t0p, params->k, t0);

        /* Get t1 from public key. */
        dilithium_vec_decode_t1(t1p, params->k, t1);

        /* Calcaluate t = NTT-1(A o NTT(s1)) + s2 */
        dilithium_vec_ntt_small(s1, params->l);
        dilithium_matrix_mul(t, a, s1, params->k, params->l);
        dilithium_vec_invntt(t, params->k);
        dilithium_vec_add(t, s2, params->k);
        /* Subtract t0 from t. */
        dilithium_vec_sub(t, t0, params->k);
        /* Make t positive to match t1. */
        dilithium_vec_make_pos(t, params->k);

        /* Check t - t0 and t1 are the same. */
        for (i = 0; i < params->k; i++) {
            for (j = 0; j < DILITHIUM_N; j++) {
                x |= tt[j] ^ t1[j];
            }
            tt += DILITHIUM_N;
            t1 += DILITHIUM_N;
        }
        /* Check the public seed is the same in private and public key. */
        for (i = 0; i < DILITHIUM_PUB_SEED_SZ; i++) {
            x |= key->p[i] ^ key->k[i];
        }

        if ((ret == 0) && (x != 0)) {
            ret = PUBLIC_KEY_E;
        }
    }

    if (key != NULL) {
        /* Dispose of allocated memory. */
        XFREE(s1, key->heap, DYNAMIC_TYPE_DILITHIUM);
    }
#else
    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = PUBLIC_KEY_E;
    }

    if (ret == 0) {
        int i;
        sword32 x = 0;

        /* Check the public seed is the same in private and public key. */
        for (i = 0; i < 32; i++) {
            x |= key->p[i] ^ key->k[i];
        }

        if (x != 0) {
            ret = PUBLIC_KEY_E;
        }
    }
#endif /* WOLFSSL_WC_DILITHIUM */
    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_CHECK_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY

/* Export the MlDsaComposite public key.
 *
 * @param [in]      key     MlDsaComposite public key.
 * @param [out]     out     Array to hold public key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_PUB_KEY_SIZE.
 */
int wc_mldsa_composite_export_public(mldsa_composite_key* key, byte* out, word32* outLen)
{
    int ret = 0;
    word32 inLen;

    /* Validate parameters */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Get length passed in for checking. */
        inLen = *outLen;
        if (key->level == WC_ML_DSA_44) {
            /* Set out length. */
            *outLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < DILITHIUM_LEVEL2_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else if (key->level == WC_ML_DSA_65) {
            /* Set out length. */
            *outLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < DILITHIUM_LEVEL3_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else if (key->level == WC_ML_DSA_87) {
            /* Set out length. */
            *outLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
            /* Validate length passed in. */
            if (inLen < DILITHIUM_LEVEL5_PUB_KEY_SIZE) {
                ret = BUFFER_E;
            }
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    /* Check public key available. */
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy public key out. */
        XMEMCPY(out, key->p, *outLen);
    }

    return ret;
}

/* Import a MlDsaComposite public key from a byte array.
 *
 * Public key encoded in big-endian.
 *
 * @param [in]      in     Array holding public key.
 * @param [in]      inLen  Number of bytes of data in array.
 * @param [in, out] key    MlDsaComposite public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when in or key is NULL or key format is not supported.
 */
int wc_mldsa_composite_import_public(const byte* in, word32 inLen, mldsa_composite_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((in == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        if (key->level == WC_ML_DSA_44) {
            /* Check length. */
            if (inLen != DILITHIUM_LEVEL2_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else if (key->level == WC_ML_DSA_65) {
            /* Check length. */
            if (inLen != DILITHIUM_LEVEL3_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else if (key->level == WC_ML_DSA_87) {
            /* Check length. */
            if (inLen != DILITHIUM_LEVEL5_PUB_KEY_SIZE) {
                ret = BAD_FUNC_ARG;
            }
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Copy the private key data in or copy pointer. */
    #ifndef WOLFSSL_DILITHIUM_ASSIGN_KEY
        XMEMCPY(key->p, in, inLen);
    #else
        key->p = in;
    #endif

#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
    #ifndef WC_DILITHIUM_FIXED_ARRAY
        /* Allocate t1 if required. */
        if (key->t1 == NULL) {
            key->t1 = (sword32*)XMALLOC(key->params->s2Sz, key->heap,
                DYNAMIC_TYPE_DILITHIUM);
            if (key->t1 == NULL) {
                ret = MEMORY_E;
            }
        }
    #endif
    }
    if (ret == 0) {
        /* Compute t1 from public key data. */
        dilithium_make_pub_vec(key, key->t1);
#endif
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
    #ifndef WC_DILITHIUM_FIXED_ARRAY
        /* Allocate matrix a if required. */
        if (key->a == NULL) {
            key->a = (sword32*)XMALLOC(key->params->aSz, key->heap,
                DYNAMIC_TYPE_DILITHIUM);
            if (key->a == NULL) {
                ret = MEMORY_E;
            }
        }
    #endif
    }
    if (ret == 0) {
        /* Compute matrix a from public key data. */
        ret = dilithium_expand_a(&key->shake, key->p, key->params->k,
            key->params->l, key->a, key->heap);
        if (ret == 0) {
            key->aSet = 1;
        }
    }
    if (ret == 0) {
#endif
        /* Public key is set. */
        key->pubKeySet = 1;
    }

    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY

/* Set the private key data into key.
 *
 * @param [in]     priv    Private key data.
 * @param [in]     privSz  Size of private key data in bytes.
 * @param in, out] key     mldsa_composite key to set into.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when private key size is invalid.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative on hash error.
 */
static int mldsa_composite_set_priv_key(const byte* priv, word32 privSz,
    mldsa_composite_key* key)
{
    int ret = 0;
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
    const wc_dilithium_params* params = key->params;
#endif

    /* Validate parameters. */
    if ((privSz != DILITHIUM_LEVEL2_KEY_SIZE) &&
            (privSz != DILITHIUM_LEVEL3_KEY_SIZE) &&
            (privSz != DILITHIUM_LEVEL5_KEY_SIZE)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Copy the private key data in or copy pointer. */
    #ifndef WOLFSSL_DILITHIUM_ASSIGN_KEY
        XMEMCPY(key->k, priv, privSz);
    #else
        key->k = priv;
    #endif
    }

        /* Allocate and create cached values. */
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if (ret == 0) {
        /* Allocate matrix a if required. */
        if (key->a == NULL) {
            key->a = (sword32*)XMALLOC(params->aSz, key->heap,
                DYNAMIC_TYPE_DILITHIUM);
            if (key->a == NULL) {
                ret = MEMORY_E;
            }
        }
    }
#endif
    if (ret == 0) {
        /* Compute matrix a from private key data. */
        ret = dilithium_expand_a(&key->shake, key->k, params->k, params->l,
            key->a, key->heap);
        if (ret == 0) {
            key->aSet = 1;
        }
    }
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
#ifndef WC_DILITHIUM_FIXED_ARRAY
    if ((ret == 0) && (key->s1 == NULL)) {
        /* Allocate L vector s1, K vector s2 and K vector t0 if required. */
        key->s1 = (sword32*)XMALLOC(params->s1Sz + params->s2Sz + params->s2Sz,
            key->heap, DYNAMIC_TYPE_DILITHIUM);
        if (key->s1 == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0) {
            /* Set pointers into allocated memory. */
            key->s2 = key->s1 + params->s1Sz / sizeof(*key->s1);
            key->t0 = key->s2 + params->s2Sz / sizeof(*key->s2);
        }
    }
#endif
    if (ret == 0) {
        /* Compute vectors from private key. */
        dilithium_make_priv_vecs(key, key->s1, key->s2, key->t0);
    }
#endif
    if (ret == 0) {
        /* Private key is set. */
        key->prvKeySet = 1;
    }

    return ret;
}

/* Import a mldsa_composite private key from a byte array.
 *
 * @param [in]      priv    Array holding private key.
 * @param [in]      privSz  Number of bytes of data in array.
 * @param [in, out] key     mldsa_composite private key.
 * @return  0 otherwise.
 * @return  BAD_FUNC_ARG when a parameter is NULL or privSz is less than size
 *          required for level,
 */
int wc_mldsa_composite_import_private(const byte* priv, word32 privSz,
    mldsa_composite_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (key->level != WC_ML_DSA_44) &&
            (key->level != WC_ML_DSA_65) && (key->level != WC_ML_DSA_87)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set the private key data. */
        ret = dilithium_set_priv_key(priv, privSz, key);
    }

    return ret;
}

#if defined(WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY)
/* Import a mldsa_composite private and public keys from byte array(s).
 *
 * @param [in] priv    Array holding private key or private+public keys
 * @param [in] privSz  Number of bytes of data in private key array.
 * @param [in] pub     Array holding public key (or NULL).
 * @param [in] pubSz   Number of bytes of data in public key array (or 0).
 * @param [in] key     mldsa_composite private/public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required parameter is NULL an invalid
 *          combination of keys/lengths is supplied.
 */
int wc_mldsa_composite_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, mldsa_composite_key* key)
{
    int ret = 0;

    /* Validate parameters. */
    if ((priv == NULL) || (key == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((pub == NULL) && (pubSz != 0)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (key->level != WC_ML_DSA_44) &&
            (key->level != WC_ML_DSA_65) && (key->level != WC_ML_DSA_87)) {
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && (pub != NULL)) {
        /* Import public key. */
        ret = wc_dilithium_import_public(pub, pubSz, key);
    }
    if (ret == 0) {
        ret = dilithium_set_priv_key(priv, privSz, key);
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

/* Export the mldsa_composite private key.
 *
 * @param [in]      key     mldsa_composite private key.
 * @param [out]     out     Array to hold private key.
 * @param [in, out] outLen  On in, the number of bytes in array.
 *                          On out, the number bytes put into array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 * @return  BUFFER_E when outLen is less than DILITHIUM_LEVEL2_KEY_SIZE.
 */
int wc_mldsa_composite_export_private(mldsa_composite_key* key, byte* out,
    word32* outLen)
{
    int ret = 0;
    word32 inLen;

    /* Validate parameters. */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Check private key available. */
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        inLen = *outLen;
        /* check and set up out length */
        if (key->level == WC_ML_DSA_44) {
            *outLen = DILITHIUM_LEVEL2_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            *outLen = DILITHIUM_LEVEL3_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            *outLen = DILITHIUM_LEVEL5_KEY_SIZE;
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    /* Check array length. */
    if ((ret == 0) && (inLen < *outLen)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Copy private key out key. */
        XMEMCPY(out, key->k, *outLen);
    }

    return ret;
}

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Export the mldsa_composite private and public key.
 *
 * @param [in]      key     mldsa_composite private/public key.
 * @param [out]     priv    Array to hold private key.
 * @param [in, out] privSz  On in, the number of bytes in private key array.
 *                          On out, the number bytes put into private key.
 * @param [out]     pub     Array to hold  public key.
 * @param [in, out] pubSz   On in, the number of bytes in public key array.
 *                          On out, the number bytes put into public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a key, priv, privSz, pub or pubSz is NULL.
 * @return  BUFFER_E when privSz or pubSz is less than required size.
 */
int wc_mldsa_composite_export_key(mldsa_composite_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz)
{
    int ret;

    /* Export private key only. */
    ret = wc_mldsa_composite_export_private(key, priv, privSz);
    if (ret == 0) {
        /* Export public key. */
        ret = wc_mldsa_composite_export_public(key, pub, pubSz);
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#if defined(WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY)

/* Decode the DER encoded mldsa_composite key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       mldsa_composite key to store key.
 * @param [in]      inSz      Total size of data in array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  BAD_FUNC_ARG when level not set.
 * @return  Other negative on parse error.
 */
int wc_MlDsaComposite_PrivateKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz)
{
    int ret = 0;
    const byte* privKey = NULL;
    const byte* pubKey = NULL;
    word32 privKeyLen = 0;
    word32 pubKeyLen = 0;
    int keytype = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Get OID sum for level. */
        if (key->level == WC_ML_DSA_44) {
            keytype = DILITHIUM_LEVEL2k;
        }
        else if (key->level == WC_ML_DSA_65) {
            keytype = DILITHIUM_LEVEL3k;
        }
        else if (key->level == WC_ML_DSA_87) {
            keytype = DILITHIUM_LEVEL5k;
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        /* Decode the asymmetric key and get out private and public key data. */
        ret = DecodeAsymKey_Assign(input, inOutIdx, inSz, &privKey, &privKeyLen,
            &pubKey, &pubKeyLen, keytype);
    }
    if ((ret == 0) && (pubKey == NULL) && (pubKeyLen == 0)) {
        /* Check if the public key is included in the private key. */
        if ((key->level == WC_ML_DSA_44) &&
            (privKeyLen == DILITHIUM_LEVEL2_PRV_KEY_SIZE)) {
            pubKey = privKey + DILITHIUM_LEVEL2_KEY_SIZE;
            pubKeyLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
            privKeyLen -= DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        }
        else if ((key->level == WC_ML_DSA_65) &&
                 (privKeyLen == DILITHIUM_LEVEL3_PRV_KEY_SIZE)) {
            pubKey = privKey + DILITHIUM_LEVEL3_KEY_SIZE;
            pubKeyLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
            privKeyLen -= DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        }
        else if ((key->level == WC_ML_DSA_87) &&
                 (privKeyLen == DILITHIUM_LEVEL5_PRV_KEY_SIZE)) {
            pubKey = privKey + DILITHIUM_LEVEL5_KEY_SIZE;
            pubKeyLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
            privKeyLen -= DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        }
    }

    if (ret == 0) {
        /* Check whether public key data was found. */
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        if (pubKeyLen == 0)
#endif
        {
            /* No public key data, only import private key data. */
            ret = wc_dilithium_import_private(privKey, privKeyLen, key);
        }
#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
        else {
            /* Import private and public key data. */
            ret = wc_dilithium_import_key(privKey, privKeyLen, pubKey,
                pubKeyLen, key);
        }
#endif
    }

    (void)pubKey;
    (void)pubKeyLen;

    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

static int mldsa_composite_get_der_length(const byte* input, word32* inOutIdx,
    int *length, word32 inSz)
{
    int ret = 0;
    word32 idx = *inOutIdx;
    word32 len = 0;

    if (idx >= inSz) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] < 0x80) {
        len = input[idx];
        idx++;
    }
    else if ((input[idx] == 0x80) || (input[idx] >= 0x83)) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] == 0x81) {
        if (idx + 1 >= inSz) {
            ret = ASN_PARSE_E;
        }
        else if (input[idx + 1] < 0x80) {
            ret = ASN_PARSE_E;
        }
        else {
            len = input[idx + 1];
            idx += 2;
        }
    }
    else if (input[idx] == 0x82) {
        if (idx + 2 >= inSz) {
            ret = ASN_PARSE_E;
        }
        else {
            len = ((word16)input[idx + 1] << 8) + input[idx + 2];
            idx += 3;
            if (len < 0x100) {
                ret = ASN_PARSE_E;
            }
        }
    }

    if ((ret == 0) && ((idx + len) > inSz)) {
        ret = ASN_PARSE_E;
    }

    *length = (int)len;
    *inOutIdx = idx;
    return ret;
}

static int mldsa_composite_check_type(const byte* input, word32* inOutIdx, byte type,
    word32 inSz)
{
    int ret = 0;
    word32 idx = *inOutIdx;

    if (idx >= inSz) {
        ret = ASN_PARSE_E;
    }
    else if (input[idx] != type){
        ret = ASN_PARSE_E;
    }
    else {
        idx++;
    }

    *inOutIdx = idx;
    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

/* Decode the DER encoded mldsa_composite public key.
 *
 * @param [in]      input     Array holding DER encoded data.
 * @param [in, out] inOutIdx  On in, index into array of start of DER encoding.
 *                            On out, index into array after DER encoding.
 * @param [in, out] key       mldsa_composite key to store key.
 * @param [in]      inSz      Total size of data in array.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when input, inOutIdx or key is NULL or inSz is 0.
 * @return  BAD_FUNC_ARG when level not set.
 * @return  Other negative on parse error.
 */
int wc_MlDsaComposite_PublicKeyDecode(const byte* input, word32* inOutIdx,
    mldsa_composite_key* key, word32 inSz)
{
    int ret = 0;
    const byte* pubKey;
    word32 pubKeyLen = 0;

    /* Validate parameters. */
    if ((input == NULL) || (inOutIdx == NULL) || (key == NULL) || (inSz == 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Try to import the key directly. */
        ret = wc_mldsa_composite_import_public(input, inSz, key);
        if (ret != 0) {
        #if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_ASN1)
            int keytype = 0;
        #else
            int length;
            unsigned char* oid;
            int oidLen;
            word32 idx = 0;
        #endif

            /* Start again. */
            ret = 0;

    #if !defined(WOLFSSL_MLDSA_COMPOSITE_NO_ASN1)
            /* Get OID sum for level. */
            if (key->level == WC_ML_DSA_44) {
                keytype = DILITHIUM_LEVEL2k;
            }
            else if (key->level == WC_ML_DSA_65) {
                keytype = DILITHIUM_LEVEL3k;
            }
            else if (key->level == WC_ML_DSA_87) {
                keytype = DILITHIUM_LEVEL5k;
            }
            else {
                /* Level not set. */
                ret = BAD_FUNC_ARG;
            }
            if (ret == 0) {
                /* Decode the asymmetric key and get out public key data. */
                ret = DecodeAsymKeyPublic_Assign(input, inOutIdx, inSz, &pubKey,
                    &pubKeyLen, keytype);
            }
    #else
            /* Get OID sum for level. */
        #ifndef WOLFSSL_NO_ML_DSA_44
            if (key->level == WC_ML_DSA_44) {
                oid = dilithium_oid_44;
                oidLen = (int)sizeof(dilithium_oid_44);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_65
            if (key->level == WC_ML_DSA_65) {
                oid = dilithium_oid_65;
                oidLen = (int)sizeof(dilithium_oid_65);
            }
            else
        #endif
        #ifndef WOLFSSL_NO_ML_DSA_87
            if (key->level == WC_ML_DSA_87) {
                oid = dilithium_oid_87;
                oidLen = (int)sizeof(dilithium_oid_87);
            }
            else
        #endif
            {
                /* Level not set. */
                ret = BAD_FUNC_ARG;
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x30, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x30, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x06, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                if ((length != oidLen) ||
                        (XMEMCMP(input + idx, oid, oidLen) != 0)) {
                    ret = ASN_PARSE_E;
                }
                idx += oidLen;
            }
            if (ret == 0) {
                ret = dilithium_check_type(input, &idx, 0x03, inSz);
            }
            if (ret == 0) {
                ret = dilitihium_get_der_length(input, &idx, &length, inSz);
            }
            if (ret == 0) {
                if (input[idx] != 0) {
                    ret = ASN_PARSE_E;
                }
                idx++;
                length--;
            }
            if (ret == 0) {
                /* This is the raw point data compressed or uncompressed. */
                pubKeyLen = (word32)length;
                pubKey = input + idx;
            }
    #endif
            if (ret == 0) {
                /* Import public key data. */
                ret = wc_dilithium_import_public(pubKey, pubKeyLen, key);
            }
        }
    }
    return ret;
}

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
/* Encode the public part of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key      mldsa_composite key object.
 * @param [out] output   Buffer to put encoded data in.
 * @param [in]  len      Size of buffer in bytes.
 * @param [in]  withAlg  Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_MlDsaComposite_PublicKeyToDer(mldsa_composite_key* key, byte* output, word32 len,
    int withAlg)
{
    int ret = 0;
    int keytype = 0;
    int pubKeyLen = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check we have a public key to encode. */
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Get OID and length for level. */
        if (key->level == WC_ML_DSA_44) {
            keytype = DILITHIUM_LEVEL2k;
            pubKeyLen = DILITHIUM_LEVEL2_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_65) {
            keytype = DILITHIUM_LEVEL3k;
            pubKeyLen = DILITHIUM_LEVEL3_PUB_KEY_SIZE;
        }
        else if (key->level == WC_ML_DSA_87) {
            keytype = DILITHIUM_LEVEL5k;
            pubKeyLen = DILITHIUM_LEVEL5_PUB_KEY_SIZE;
        }
        else {
            /* Level not set. */
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        ret = SetAsymKeyDerPublic(key->p, pubKeyLen, output, len, keytype,
            withAlg);
    }

    return ret;
}
#endif /* WC_ENABLE_ASYM_KEY_EXPORT */

#endif /* !WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

#ifdef WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY

#ifndef WOLFSSL_MLDSA_COMPOSITE_NO_ASN1

#ifdef WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY
/* Encode the private and public data of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     mldsa_composite key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wcMlDsaComposite_KeyToDer(mldsa_composite_key* key, byte* output, word32 len)
{
    int ret = BAD_FUNC_ARG;

    /* Validate parameters and check public and private key set. */
    if ((key != NULL) && key->prvKeySet && key->pubKeySet) {
        /* Create DER for level. */
        if (key->level == WC_ML_DSA_44) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL2_KEY_SIZE, key->p,
                DILITHIUM_LEVEL2_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL2k);
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL3_KEY_SIZE, key->p,
                DILITHIUM_LEVEL3_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL3k);
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL5_KEY_SIZE, key->p,
                DILITHIUM_LEVEL5_PUB_KEY_SIZE, output, len, DILITHIUM_LEVEL5k);
        }
    }

    return ret;
}
#endif /* WOLFSSL_MLDSA_COMPOSITE_PUBLIC_KEY */

//////////////////////////////////////////////////////////////////////////
// Resume From Here vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
//////////////////////////////////////////////////////////////////////////




/* Encode the private data of a mldsa_composite key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key     mldsa_composite key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  len     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_MlDsaComposite_PrivateKeyToDer(mldsa_composite_key* key, byte* output, word32 len)
{
    int ret = BAD_FUNC_ARG;

    /* Validate parameters and check private key set. */
    if ((key != NULL) && key->prvKeySet) {
        /* Create DER for level. */
        if (key->level == WC_ML_DSA_44) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL2_KEY_SIZE, NULL, 0,
                output, len, DILITHIUM_LEVEL2k);
        }
        else if (key->level == WC_ML_DSA_65) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL3_KEY_SIZE, NULL, 0,
                output, len, DILITHIUM_LEVEL3k);
        }
        else if (key->level == WC_ML_DSA_87) {
            ret = SetAsymKeyDer(key->k, DILITHIUM_LEVEL5_KEY_SIZE, NULL, 0,
                output, len, DILITHIUM_LEVEL5k);
        }
    }

    return ret;
}

#endif /* WOLFSSL_MLDSA_COMPOSITE_NO_ASN1 */

#endif /* WOLFSSL_MLDSA_COMPOSITE_PRIVATE_KEY */

#endif /* HAVE_MLDSA_COMPOSITE */
