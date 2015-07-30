/* srp.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFCRYPT_HAVE_SRP

#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static int SrpHashInit(SrpHash* hash, int type)
{
    hash->type = type;

    switch (type) {
    #ifndef NO_SHA
        case SRP_TYPE_SHA:
            return wc_InitSha(&hash->data.sha);
    #endif

    #ifndef NO_SHA256
        case SRP_TYPE_SHA256:
            return wc_InitSha256(&hash->data.sha256);
    #endif

    #ifdef WOLFSSL_SHA384
        case SRP_TYPE_SHA384:
            return wc_InitSha384(&hash->data.sha384);
    #endif

    #ifdef WOLFSSL_SHA512
        case SRP_TYPE_SHA512:
            return wc_InitSha512(&hash->data.sha512);
    #endif

        default:
            return BAD_FUNC_ARG;
    }
}

static int SrpHashUpdate(SrpHash* hash, const byte* data, word32 size)
{
    switch (hash->type) {
    #ifndef NO_SHA
        case SRP_TYPE_SHA:
            return wc_ShaUpdate(&hash->data.sha, data, size);
    #endif

    #ifndef NO_SHA256
        case SRP_TYPE_SHA256:
            return wc_Sha256Update(&hash->data.sha256, data, size);
    #endif

    #ifdef WOLFSSL_SHA384
        case SRP_TYPE_SHA384:
            return wc_Sha384Update(&hash->data.sha384, data, size);
    #endif

    #ifdef WOLFSSL_SHA512
        case SRP_TYPE_SHA512:
            return wc_Sha512Update(&hash->data.sha512, data, size);
    #endif

        default:
            return BAD_FUNC_ARG;
    }
}

static int SrpHashFinal(SrpHash* hash, byte* digest)
{
    switch (hash->type) {
    #ifndef NO_SHA
        case SRP_TYPE_SHA:
            return wc_ShaFinal(&hash->data.sha, digest);
    #endif

    #ifndef NO_SHA256
        case SRP_TYPE_SHA256:
            return wc_Sha256Final(&hash->data.sha256, digest);
    #endif

    #ifdef WOLFSSL_SHA384
        case SRP_TYPE_SHA384:
            return wc_Sha384Final(&hash->data.sha384, digest);
    #endif

    #ifdef WOLFSSL_SHA512
        case SRP_TYPE_SHA512:
            return wc_Sha512Final(&hash->data.sha512, digest);
    #endif

        default:
            return BAD_FUNC_ARG;
    }
}

static word32 SrpHashSize(byte type)
{
    switch (type) {
    #ifndef NO_SHA
        case SRP_TYPE_SHA:
            return SHA_DIGEST_SIZE;
    #endif

    #ifndef NO_SHA256
        case SRP_TYPE_SHA256:
            return SHA256_DIGEST_SIZE;
    #endif

    #ifdef WOLFSSL_SHA384
        case SRP_TYPE_SHA384:
            return SHA384_DIGEST_SIZE;
    #endif

    #ifdef WOLFSSL_SHA512
        case SRP_TYPE_SHA512:
            return SHA512_DIGEST_SIZE;
    #endif

        default:
            return 0;
    }
}

int wc_SrpInit(Srp* srp, byte type, byte side)
{
    int r;

    /* validating params */

    if (!srp)
        return BAD_FUNC_ARG;

    if (side != SRP_CLIENT_SIDE && side != SRP_SERVER_SIDE)
        return BAD_FUNC_ARG;

    if (type != SRP_TYPE_SHA    && type != SRP_TYPE_SHA256 &&
        type != SRP_TYPE_SHA384 && type != SRP_TYPE_SHA512)
        return BAD_FUNC_ARG;

    /* initializing variables */

    XMEMSET(srp, 0, sizeof(Srp));

    if ((r = SrpHashInit(&srp->client_proof, type)) != 0)
        return r;

    if ((r = SrpHashInit(&srp->server_proof, type)) != 0)
        return r;

    if ((r = mp_init_multi(&srp->N,    &srp->g, &srp->auth,
                           &srp->priv, &srp->u, 0)) != 0)
        return r;

    srp->side = side;    srp->type   = type;
    srp->salt = NULL;    srp->saltSz = 0;
    srp->user = NULL;    srp->userSz = 0;

    return 0;
}

void wc_SrpTerm(Srp* srp)
{
    if (srp) {
        mp_clear(&srp->N);    mp_clear(&srp->g);
        mp_clear(&srp->auth); mp_clear(&srp->priv);
        mp_clear(&srp->u);

        XMEMSET(srp->salt, 0, srp->saltSz);
        XFREE(srp->salt, NULL, DYNAMIC_TYPE_SRP);
        XMEMSET(srp->user, 0, srp->userSz);
        XFREE(srp->user, NULL, DYNAMIC_TYPE_SRP);

        XMEMSET(srp, 0, sizeof(Srp));
    }
}

int wc_SrpSetUsername(Srp* srp, const byte* username, word32 size)
{
    if (!srp || !username)
        return BAD_FUNC_ARG;

    srp->user = (byte*)XMALLOC(size, NULL, DYNAMIC_TYPE_SRP);
    if (srp->user == NULL)
        return MEMORY_E;

    srp->userSz = size;
    XMEMCPY(srp->user, username, srp->userSz);

    return 0;
}

int wc_SrpSetParams(Srp* srp, const byte* N,    word32 nSz,
                              const byte* g,    word32 gSz,
                              const byte* salt, word32 saltSz)
{
    SrpHash hash;
    byte digest1[SRP_MAX_DIGEST_SIZE];
    byte digest2[SRP_MAX_DIGEST_SIZE];
    byte pad = 0;
    int i, j, r;

    if (!srp || !N || !g || !salt || nSz < gSz)
        return BAD_FUNC_ARG;

    if (!srp->user)
        return SRP_CALL_ORDER_E;

    /* Set N */
    if (mp_read_unsigned_bin(&srp->N, N, nSz) != MP_OKAY)
        return MP_READ_E;

    /* Set g */
    if (mp_read_unsigned_bin(&srp->g, g, gSz) != MP_OKAY)
        return MP_READ_E;

    /* Set salt */
    if (srp->salt) {
        XMEMSET(srp->salt, 0, srp->saltSz);
        XFREE(srp->salt, NULL, DYNAMIC_TYPE_SRP);
    }

    srp->salt = (byte*)XMALLOC(saltSz, NULL, DYNAMIC_TYPE_SRP);
    if (srp->salt == NULL)
        return MEMORY_E;

    XMEMCPY(srp->salt, salt, saltSz);
    srp->saltSz = saltSz;

    /* Set k = H(N, g) */
            r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, (byte*) N, nSz);
    for (i = 0; (word32)i < nSz - gSz; i++)
        SrpHashUpdate(&hash, &pad, 1);
    if (!r) r = SrpHashUpdate(&hash, (byte*) g, gSz);
    if (!r) r = SrpHashFinal(&hash, srp->k);

    /* Update client proof */

    /* digest1 = H(N) */
    if (!r) r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, (byte*) N, nSz);
    if (!r) r = SrpHashFinal(&hash, digest1);

    /* digest2 = H(g) */
    if (!r) r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, (byte*) g, gSz);
    if (!r) r = SrpHashFinal(&hash, digest2);

    /* digest1 = H(N) ^ H(g) */
    for (i = 0, j = SrpHashSize(srp->type); i < j; i++)
        digest1[i] ^= digest2[i];

    /* digest2 = H(user) */
    if (!r) r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, srp->user, srp->userSz);
    if (!r) r = SrpHashFinal(&hash, digest2);

    /* Client proof = H( H(N) ^ H(g) | H(user) | salt) */
    if (!r) r = SrpHashUpdate(&srp->client_proof, digest1, j);
    if (!r) r = SrpHashUpdate(&srp->client_proof, digest2, j);
    if (!r) r = SrpHashUpdate(&srp->client_proof, salt, saltSz);

    return r;
}

int wc_SrpSetPassword(Srp* srp, const byte* password, word32 size)
{
    SrpHash hash;
    byte digest[SRP_MAX_DIGEST_SIZE];
    word32 digestSz;
    int r;

    if (!srp || !password || srp->side != SRP_CLIENT_SIDE)
        return BAD_FUNC_ARG;

    if (!srp->salt)
        return SRP_CALL_ORDER_E;

    digestSz = SrpHashSize(srp->type);

    /* digest = H(username | ':' | password) */
            r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, srp->user, srp->userSz);
    if (!r) r = SrpHashUpdate(&hash, (const byte*) ":", 1);
    if (!r) r = SrpHashUpdate(&hash, password, size);
    if (!r) r = SrpHashFinal(&hash, digest);

    /* digest = H(salt | H(username | ':' | password)) */
    if (!r) r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, srp->salt, srp->saltSz);
    if (!r) r = SrpHashUpdate(&hash, digest, digestSz);
    if (!r) r = SrpHashFinal(&hash, digest);

    /* Set x (private key) */
    if (!r) r = mp_read_unsigned_bin(&srp->auth, digest, digestSz);

    XMEMSET(digest, 0, SRP_MAX_DIGEST_SIZE);

    return r;
}

int wc_SrpGetVerifier(Srp* srp, byte* verifier, word32* size)
{
    mp_int v;
    int r;

    if (!srp || !verifier || !size || srp->side != SRP_CLIENT_SIDE)
        return BAD_FUNC_ARG;

    if (mp_iszero(&srp->auth))
        return SRP_CALL_ORDER_E;

    r = mp_init(&v);

    /* v = g ^ x % N */
    if (!r) r = mp_exptmod(&srp->g, &srp->auth, &srp->N, &v);
    if (!r) r = *size < (word32)mp_unsigned_bin_size(&v) ? BUFFER_E : MP_OKAY;
    if (!r) r = mp_to_unsigned_bin(&v, verifier);
    if (!r) *size = mp_unsigned_bin_size(&v);

    mp_clear(&v);

    return r;
}

int wc_SrpSetVerifier(Srp* srp, const byte* verifier, word32 size)
{
    if (!srp || !verifier || srp->side != SRP_SERVER_SIDE)
        return BAD_FUNC_ARG;

    return mp_read_unsigned_bin(&srp->auth, verifier, size);
}

int wc_SrpSetPrivate(Srp* srp, const byte* private, word32 size)
{
    if (!srp || !private || !size)
        return BAD_FUNC_ARG;

    if (mp_iszero(&srp->auth))
        return SRP_CALL_ORDER_E;

    return mp_read_unsigned_bin(&srp->priv, private, size);
}

static int wc_SrpGenPrivate(Srp* srp, byte* private, word32 size)
{
    RNG rng;
    int r = wc_InitRng(&rng);

    if (!r) r = wc_RNG_GenerateBlock(&rng, private, size);
    if (!r) r = wc_SrpSetPrivate(srp, private, size);
    if (!r) wc_FreeRng(&rng);

    return r;
}

int wc_SrpGetPublic(Srp* srp, byte* public, word32* size)
{
    mp_int pubkey;
    word32 modulusSz;
    int r = mp_init(&pubkey);

    if (r != 0)
        return r;

    if (!srp || !public || !size)
        return BAD_FUNC_ARG;

    if (mp_iszero(&srp->auth))
        return SRP_CALL_ORDER_E;

    modulusSz = mp_unsigned_bin_size(&srp->N);
    if (*size < modulusSz)
        return BUFFER_E;

    /* priv = random() */
    if (mp_iszero(&srp->priv))
        r = wc_SrpGenPrivate(srp, public, modulusSz);

    /* client side: A = g ^ a % N */
    if (srp->side == SRP_CLIENT_SIDE) {
        if (!r) r = mp_exptmod(&srp->g, &srp->priv, &srp->N, &pubkey);

    /* server side: B = (k * v + (g ^ b % N)) % N */
    } else {
        mp_int i, j;

        if (mp_init_multi(&i, &j, 0, 0, 0, 0) == MP_OKAY) {
            if (!r) r = mp_read_unsigned_bin(&i, srp->k,SrpHashSize(srp->type));
            if (!r) r = mp_exptmod(&srp->g, &srp->priv, &srp->N, &pubkey);
            if (!r) r = mp_mulmod(&i, &srp->auth, &srp->N, &j);
            if (!r) r = mp_add(&j, &pubkey, &i);
            if (!r) r = mp_mod(&i, &srp->N, &pubkey);

            mp_clear(&i); mp_clear(&j);
        }
    }

    /* extract public key to buffer */
    XMEMSET(public, 0, modulusSz);
    if (!r) r = mp_to_unsigned_bin(&pubkey, public);
    if (!r) *size = mp_unsigned_bin_size(&pubkey);
    mp_clear(&pubkey);

    return r;
}

static int wc_SrpSetU(Srp* srp, byte* clientPubKey, word32 clientPubKeySz,
                                byte* serverPubKey, word32 serverPubKeySz)
{
    SrpHash hash;
    byte    digest[SRP_MAX_DIGEST_SIZE];
    word32  modulusSz = mp_unsigned_bin_size(&srp->N);
    byte    pad = 0;
    word32  i;
    int     r = SrpHashInit(&hash, srp->type);

    /* H(A) */
    for (i = 0; !r && i < modulusSz - clientPubKeySz; i++)
        r = SrpHashUpdate(&hash, &pad, 1);
    if (!r) r = SrpHashUpdate(&hash, clientPubKey, clientPubKeySz);

    /* H(A | B) */
    for (i = 0; !r && i < modulusSz - serverPubKeySz; i++)
        r = SrpHashUpdate(&hash, &pad, 1);
    if (!r) r = SrpHashUpdate(&hash, serverPubKey, serverPubKeySz);

    /* client proof = H( H(N) ^ H(g) | H(user) | salt | A | B) */
    if (!r) r = SrpHashUpdate(&srp->client_proof, clientPubKey, clientPubKeySz);
    if (!r) r = SrpHashUpdate(&srp->client_proof, serverPubKey, serverPubKeySz);

    /* server proof = H(A) */
    if (!r) r = SrpHashUpdate(&srp->server_proof, clientPubKey, clientPubKeySz);

    /* set u */
    if (!r) r = SrpHashFinal(&hash, digest);
    if (!r) r = mp_read_unsigned_bin(&srp->u, digest, SrpHashSize(srp->type));

    return r;
}

static int wc_SrpSetK(Srp* srp, byte* secret, word32 size)
{
    SrpHash hash;
    byte digest[SRP_MAX_DIGEST_SIZE];
    word32 digestSz = SrpHashSize(srp->type);
    int r;
    word32 i = 0;
    word32 pos = 0;
    byte cnt[4];

    for (i = 0; pos < digestSz * 2; i++) {
        cnt[0] = (i >> 24) & 0xFF;
        cnt[1] = (i >> 16) & 0xFF;
        cnt[2] = (i >>  8) & 0xFF;
        cnt[3] =  i        & 0xFF;

        r = SrpHashInit(&hash, srp->type);
        if (!r) r = SrpHashUpdate(&hash, secret, size);
        if (!r) r = SrpHashUpdate(&hash, cnt, 4);

        if(pos + digestSz > digestSz * 2) {
            if (!r) r = SrpHashFinal(&hash, digest);
            XMEMCPY(srp->key + pos, digest, digestSz * 2 - pos);
            pos = digestSz * 2;
        }
        else {
            if (!r) r = SrpHashFinal(&hash, srp->key + pos);
            pos += digestSz;
        }
    }

    XMEMSET(digest, 0, sizeof(digest));
    XMEMSET(&hash, 0, sizeof(SrpHash));

    return r;
}

int wc_SrpComputeKey(Srp* srp, byte* clientPubKey, word32 clientPubKeySz,
                               byte* serverPubKey, word32 serverPubKeySz)
{
    byte* secret;
    word32 digestSz;
    word32 secretSz;
    mp_int i, j, s;
    int r;

    if (!srp || !clientPubKey || clientPubKeySz == 0
             || !serverPubKey || serverPubKeySz == 0)
        return BAD_FUNC_ARG;

    if (mp_iszero(&srp->priv))
        return SRP_CALL_ORDER_E;

    if ((r = mp_init_multi(&i, &j, &s, 0, 0, 0)) != MP_OKAY)
        return r;

    secretSz = mp_unsigned_bin_size(&srp->N);
    secret = (byte*)XMALLOC(secretSz, NULL, DYNAMIC_TYPE_SRP);
    if (secret == NULL) {
        mp_clear(&i); mp_clear(&j); mp_clear(&s);
        return MEMORY_E;
    }

    digestSz = SrpHashSize(srp->type);

    r = wc_SrpSetU(srp, clientPubKey, clientPubKeySz,
                        serverPubKey, serverPubKeySz);

    if (!r && srp->side == SRP_CLIENT_SIDE) {
        /* i = B - k * v */
        r = mp_read_unsigned_bin(&i, srp->k, digestSz);
        if (!r) r = mp_exptmod(&srp->g, &srp->auth, &srp->N, &j);
        if (!r) r = mp_mulmod(&i, &j, &srp->N, &s);
        if (!r) r = mp_read_unsigned_bin(&j, serverPubKey, serverPubKeySz);
        if (!r) r = mp_sub(&j, &s, &i);

        /* j = a + u * x */
        if (!r) r = mp_mulmod(&srp->u, &srp->auth, &srp->N, &s);
        if (!r) r = mp_add(&srp->priv, &s, &j);

        /* secret = i ^ j % N */
        if (!r) r = mp_exptmod(&i, &j, &srp->N, &s);

    } else if (!r && srp->side == SRP_SERVER_SIDE) {
        /* i = v ^ u % N */
        r = mp_exptmod(&srp->auth, &srp->u, &srp->N, &i);

        /* j = A * i % N */
        if (!r) r = mp_read_unsigned_bin(&s, clientPubKey, clientPubKeySz);
        if (!r) r = mp_mulmod(&s, &i, &srp->N, &j);

        /* secret = j * b % N */
        if (!r) r = mp_exptmod(&j, &srp->priv, &srp->N, &s);
    }

    if (!r) r = mp_to_unsigned_bin(&s, secret);
    if (!r) r = wc_SrpSetK(srp, secret, mp_unsigned_bin_size(&s));

    /* client proof = H( H(N) ^ H(g) | H(user) | salt | A | B | K) */
    if (!r) r = SrpHashUpdate(&srp->client_proof, srp->key, digestSz * 2);

    XFREE(secret, NULL, DYNAMIC_TYPE_SRP);
    mp_clear(&i); mp_clear(&j); mp_clear(&s);

    return r;
}

int wc_SrpGetProof(Srp* srp, byte* proof, word32* size)
{
    int r;

    if (!srp || !proof || !size)
        return BAD_FUNC_ARG;

    if (*size < SrpHashSize(srp->type))
        return BUFFER_E;

    if ((r = SrpHashFinal(srp->side == SRP_CLIENT_SIDE
                          ? &srp->client_proof
                          : &srp->server_proof, proof)) != 0)
        return r;

    *size = SrpHashSize(srp->type);

    if (srp->side == SRP_CLIENT_SIDE) {
        /* server proof = H( A | client proof | K) */
        if (!r) r = SrpHashUpdate(&srp->server_proof, proof, *size);
        if (!r) r = SrpHashUpdate(&srp->server_proof, srp->key, (*size) * 2);
    }

    return r;
}

int wc_SrpVerifyPeersProof(Srp* srp, byte* proof, word32 size)
{
    byte digest[SRP_MAX_DIGEST_SIZE];
    int r;

    if (!srp || !proof)
        return BAD_FUNC_ARG;

    if (size != SrpHashSize(srp->type))
        return BUFFER_E;

    r = SrpHashFinal(srp->side == SRP_CLIENT_SIDE ? &srp->server_proof
                                                  : &srp->client_proof, digest);

    if (srp->side == SRP_SERVER_SIDE) {
        /* server proof = H( A | client proof | K) */
        if (!r) r = SrpHashUpdate(&srp->server_proof, proof, size);
        if (!r) r = SrpHashUpdate(&srp->server_proof, srp->key, size * 2);
    }

    if (!r && XMEMCMP(proof, digest, size) != 0)
        r = SRP_VERIFY_E;

    return r;
}

#endif /* WOLFCRYPT_HAVE_SRP */
