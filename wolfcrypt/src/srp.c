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

    /* initializing common data */
    srp->side = side;    srp->type   = type;
    srp->salt = NULL;    srp->saltSz = 0;
    srp->user = NULL;    srp->userSz = 0;

    if (mp_init_multi(&srp->N, &srp->g, &srp->s, &srp->u, 0, 0) != MP_OKAY)
        return MP_INIT_E;

            r = SrpHashInit(&srp->client_proof, type);
    if (!r) r = SrpHashInit(&srp->server_proof, type);

    /* initializing client specific data */
    if (!r && srp->side == SRP_CLIENT_SIDE)
        r = mp_init_multi(&srp->specific.client.a, &srp->specific.client.A,
                          &srp->specific.client.B, &srp->specific.client.x,0,0);

    /* initializing server specific data */
    if (!r && srp->side == SRP_SERVER_SIDE)
        r = mp_init_multi(&srp->specific.server.b, &srp->specific.server.B,
                          &srp->specific.server.A, &srp->specific.server.v,0,0);

    /* undo initializations on error */
    if (r != 0) {
        mp_clear(&srp->N); mp_clear(&srp->g);
        mp_clear(&srp->s); mp_clear(&srp->u);
    }

    return r;
}

void wc_SrpTerm(Srp* srp)
{
    if (srp) {
        mp_clear(&srp->N); mp_clear(&srp->g);
        mp_clear(&srp->s); mp_clear(&srp->u);

        XMEMSET(srp->salt, 0, srp->saltSz);
        XFREE(srp->salt, NULL, DYNAMIC_TYPE_SRP);
        XMEMSET(srp->user, 0, srp->userSz);
        XFREE(srp->user, NULL, DYNAMIC_TYPE_SRP);

        if (srp->side == SRP_CLIENT_SIDE) {
            mp_clear(&srp->specific.client.a);
            mp_clear(&srp->specific.client.A);
            mp_clear(&srp->specific.client.B);
            mp_clear(&srp->specific.client.x);
        }

        if (srp->side == SRP_SERVER_SIDE) {
            mp_clear(&srp->specific.server.b);
            mp_clear(&srp->specific.server.B);
            mp_clear(&srp->specific.server.A);
            mp_clear(&srp->specific.server.v);
        }

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
    int r;

    if (!srp || !password || srp->side != SRP_CLIENT_SIDE)
        return BAD_FUNC_ARG;

    if (!srp->salt)
        return SRP_CALL_ORDER_E;

    /* digest = H(username | ':' | password) */
            r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, srp->user, srp->userSz);
    if (!r) r = SrpHashUpdate(&hash, (const byte*) ":", 1);
    if (!r) r = SrpHashUpdate(&hash, password, size);
    if (!r) r = SrpHashFinal(&hash, digest);

    /* digest = H(salt | H(username | ':' | password)) */
    if (!r) r = SrpHashInit(&hash, srp->type);
    if (!r) r = SrpHashUpdate(&hash, srp->salt, srp->saltSz);
    if (!r) r = SrpHashUpdate(&hash, digest, SrpHashSize(srp->type));
    if (!r) r = SrpHashFinal(&hash, digest);

    /* Set x (private key) */
    if (!r && mp_read_unsigned_bin(&srp->specific.client.x, digest,
                                             SrpHashSize(srp->type)) != MP_OKAY)
            r = MP_READ_E;

    XMEMSET(digest, 0, SRP_MAX_DIGEST_SIZE);

    return r;
}

int wc_SrpGetVerifier(Srp* srp, byte* verifier, word32* size)
{
    mp_int v;
    int r;

    if (!srp || !verifier || !size || srp->side != SRP_CLIENT_SIDE)
        return BAD_FUNC_ARG;

    if (mp_iszero(&srp->specific.client.x))
        return SRP_CALL_ORDER_E;

    r = mp_init(&v);

    /* v = g ^ x % N */
    if (!r) r = mp_exptmod(&srp->g, &srp->specific.client.x, &srp->N, &v);
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

    if (mp_read_unsigned_bin(&srp->specific.server.v, verifier, size)
                                                                     != MP_OKAY)
        return MP_READ_E;

    return 0;
}

int wc_SrpSetPrivate(Srp* srp, const byte* private, word32 size) {
    if (!srp || !private || !size)
        return BAD_FUNC_ARG;

    return mp_read_unsigned_bin(srp->type == SRP_CLIENT_SIDE
                                ? &srp->specific.client.a
                                : &srp->specific.server.b, private, size);
}

static int wc_SrpGenPrivate(Srp* srp, byte* private, word32 size) {
    RNG rng;
    int r = wc_InitRng(&rng);

    if (!r) r = wc_RNG_GenerateBlock(&rng, private, size);
    if (!r) r = wc_SrpSetPrivate(srp, private, size);
    if (!r) wc_FreeRng(&rng);

    return r;
}

int wc_SrpGenPublic(Srp* srp, byte* public, word32* size)
{
    byte* buf;
    word32 len;
    int r = 0;

    if (!srp || (!public && size) || (public && !size))
        return BAD_FUNC_ARG;

    if (srp->side == SRP_CLIENT_SIDE && mp_iszero(&srp->N))
        return SRP_CALL_ORDER_E;

    if (srp->side == SRP_SERVER_SIDE && (mp_iszero(&srp->N) ||
                                         mp_iszero(&srp->specific.server.v)))
        return SRP_CALL_ORDER_E;

    len = mp_unsigned_bin_size(&srp->N);
    if (size && *size < len)
        return BUFFER_E;

    buf = public ? public : (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_SRP);
    if (!buf)
        return MEMORY_E;

    if (srp->side == SRP_CLIENT_SIDE) {
        /* a = random() */
        if (mp_iszero(&srp->specific.client.a))
            r = wc_SrpGenPrivate(srp, buf, len);

        /* A = g ^ a % N */
        if (!r) r = mp_exptmod(&srp->g, &srp->specific.client.a,
                               &srp->N, &srp->specific.client.A);

        /* extract public key to buffer */
        XMEMSET(buf, 0, len);
        if (!r) r   = mp_to_unsigned_bin(&srp->specific.client.A, buf);
        if (!r) len = mp_unsigned_bin_size(&srp->specific.client.A);

        /* Client proof = H( H(N) ^ H(g) | H(user) | salt | A) */
        if (!r) r = SrpHashUpdate(&srp->client_proof, buf, len);

        /* Server proof = H(A) */
        if (!r) r = SrpHashUpdate(&srp->server_proof, buf, len);

    } else {
        mp_int i, j;

        if (mp_init_multi(&i, &j, 0, 0, 0, 0) == MP_OKAY) {
            /* b = random() */
            if (mp_iszero(&srp->specific.server.b))
                r = wc_SrpGenPrivate(srp, buf, len);

            /* B = (k * v + (g ^ b % N)) % N */
            if (!r) r = mp_read_unsigned_bin(&i, srp->k,SrpHashSize(srp->type));
            if (!r) r = mp_exptmod(&srp->g, &srp->specific.server.b,
                                   &srp->N, &srp->specific.server.B);
            if (!r) r = mp_mul(&i, &srp->specific.server.v, &j);
            if (!r) r = mp_add(&j, &srp->specific.server.B, &i);
            if (!r) r = mp_mod(&i, &srp->N, &srp->specific.server.B);

            /* extract public key to buffer */
            XMEMSET(buf, 0, len);
            if (!r) r   = mp_to_unsigned_bin(&srp->specific.server.B, buf);
            if (!r) len = mp_unsigned_bin_size(&srp->specific.server.B);

            /* Client proof = H( H(N) ^ H(g) | H(user) | salt | A) */
            if (!r) r = SrpHashUpdate(&srp->client_proof, buf, len);

            /* Server proof = H(A) */
            if (!r) r = SrpHashUpdate(&srp->server_proof, buf, len);

            mp_clear(&i); mp_clear(&j);
        }
    }

    if (public)
        *size = len;
    else
        XFREE(buf, NULL, DYNAMIC_TYPE_SRP);

    return r;
}

#endif /* WOLFCRYPT_HAVE_SRP */
