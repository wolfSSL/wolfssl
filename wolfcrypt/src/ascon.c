/* ascon.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef HAVE_ASCON

#include <wolfssl/wolfcrypt/ascon.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/*
 * Implementation of the ASCON AEAD and HASH algorithms. Based on the NIST
 * Initial Public Draft "NIST SP 800-232 ipd" and reference implementation found
 * at https://github.com/ascon/ascon-c.
 */

/*
 * TODO
 * - Add support for big-endian systems
 * - Add support for 32-bit and smaller systems */

#ifndef WORD64_AVAILABLE
    #error "Ascon implementation requires a 64-bit word"
#endif

/* Data block size in bytes */
#define ASCON_HASH256_RATE                              8
#define ASCON_HASH256_ROUNDS                           12
#define ASCON_HASH256_IV            0x0000080100CC0002ULL

#define ASCON_AEAD128_ROUNDS_PA                        12
#define ASCON_AEAD128_ROUNDS_PB                         8
#define ASCON_AEAD128_IV            0x00001000808C0001ULL
#define ASCON_AEAD128_RATE                             16

#define MAX_ROUNDS 12

#ifndef WOLFSSL_ASCON_UNROLL

/* Table 5 */
static const byte round_constants[MAX_ROUNDS] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

static byte start_index(byte rounds)
{
    switch (rounds) {
        case 8:
            return 4;
        case 12:
            return 0;
        default:
            WOLFSSL_MSG("Something went wrong in wolfCrypt logic. Wrong ASCON "
                        "rounds value.");
            return MAX_ROUNDS;
    }
}

static WC_INLINE void ascon_round(AsconState* a, byte round)
{
    word64 tmp0, tmp1, tmp2, tmp3, tmp4;
    /* 3.2 Constant-Addition Layer */
    a->s64[2] ^= round_constants[round];
    /* 3.3 Substitution Layer */
    a->s64[0] ^= a->s64[4];
    a->s64[4] ^= a->s64[3];
    a->s64[2] ^= a->s64[1];
    tmp0 = a->s64[0] ^ (~a->s64[1] & a->s64[2]);
    tmp2 = a->s64[2] ^ (~a->s64[3] & a->s64[4]);
    tmp4 = a->s64[4] ^ (~a->s64[0] & a->s64[1]);
    tmp1 = a->s64[1] ^ (~a->s64[2] & a->s64[3]);
    tmp3 = a->s64[3] ^ (~a->s64[4] & a->s64[0]);
    tmp1 ^= tmp0;
    tmp3 ^= tmp2;
    tmp0 ^= tmp4;
    tmp2 = ~tmp2;
    /* 3.4 Linear Diffusion Layer */
    a->s64[4] = tmp4 ^ rotrFixed64(tmp4,  7) ^ rotrFixed64(tmp4, 41);
    a->s64[1] = tmp1 ^ rotrFixed64(tmp1, 61) ^ rotrFixed64(tmp1, 39);
    a->s64[3] = tmp3 ^ rotrFixed64(tmp3, 10) ^ rotrFixed64(tmp3, 17);
    a->s64[0] = tmp0 ^ rotrFixed64(tmp0, 19) ^ rotrFixed64(tmp0, 28);
    a->s64[2] = tmp2 ^ rotrFixed64(tmp2,  1) ^ rotrFixed64(tmp2,  6);
}

static void permutation(AsconState* a, byte rounds)
{
    byte i = start_index(rounds);
    for (; i < MAX_ROUNDS; i++) {
        ascon_round(a, i);
    }
}

#else

#define p(a, c) do {                                                           \
    word64 tmp0, tmp1, tmp2, tmp3, tmp4;                                       \
    /* 3.2 Constant-Addition Layer */                                          \
    (a)->s64[2] ^= c;                                                          \
    /* 3.3 Substitution Layer */                                               \
    (a)->s64[0] ^= (a)->s64[4];                                                \
    (a)->s64[4] ^= (a)->s64[3];                                                \
    (a)->s64[2] ^= (a)->s64[1];                                                \
    tmp0 = (a)->s64[0] ^ (~(a)->s64[1] & (a)->s64[2]);                         \
    tmp2 = (a)->s64[2] ^ (~(a)->s64[3] & (a)->s64[4]);                         \
    tmp4 = (a)->s64[4] ^ (~(a)->s64[0] & (a)->s64[1]);                         \
    tmp1 = (a)->s64[1] ^ (~(a)->s64[2] & (a)->s64[3]);                         \
    tmp3 = (a)->s64[3] ^ (~(a)->s64[4] & (a)->s64[0]);                         \
    tmp1 ^= tmp0;                                                              \
    tmp3 ^= tmp2;                                                              \
    tmp0 ^= tmp4;                                                              \
    tmp2 = ~tmp2;                                                              \
    /* 3.4 Linear Diffusion Layer */                                           \
    (a)->s64[4] = tmp4 ^ rotrFixed64(tmp4,  7) ^ rotrFixed64(tmp4, 41);        \
    (a)->s64[1] = tmp1 ^ rotrFixed64(tmp1, 61) ^ rotrFixed64(tmp1, 39);        \
    (a)->s64[3] = tmp3 ^ rotrFixed64(tmp3, 10) ^ rotrFixed64(tmp3, 17);        \
    (a)->s64[0] = tmp0 ^ rotrFixed64(tmp0, 19) ^ rotrFixed64(tmp0, 28);        \
    (a)->s64[2] = tmp2 ^ rotrFixed64(tmp2,  1) ^ rotrFixed64(tmp2,  6);        \
} while (0)

#define p8(a) \
    p(a, 0xb4); \
    p(a, 0xa5); \
    p(a, 0x96); \
    p(a, 0x87); \
    p(a, 0x78); \
    p(a, 0x69); \
    p(a, 0x5a); \
    p(a, 0x4b)

#define p12(a) \
    p(a, 0xf0); \
    p(a, 0xe1); \
    p(a, 0xd2); \
    p(a, 0xc3); \
    p8(a)

/* Needed layer to evaluate the macro values */
#define _permutation(a, rounds) \
    p ## rounds(a)

#define permutation(a, rounds) \
    _permutation(a, rounds)

#endif

/* AsconHash API */

wc_AsconHash256* wc_AsconHash256_New(void)
{
    wc_AsconHash256* ret = (wc_AsconHash256*)XMALLOC(sizeof(wc_AsconHash256),
            NULL, DYNAMIC_TYPE_ASCON);
    if (ret != NULL) {
        if (wc_AsconHash256_Init(ret) != 0) {
            wc_AsconHash256_Free(ret);
            ret = NULL;
        }
    }
    return ret;
}

void wc_AsconHash256_Free(wc_AsconHash256* a)
{
    if (a != NULL) {
        wc_AsconHash256_Clear(a);
        XFREE(a, NULL, DYNAMIC_TYPE_ASCON);
    }
}

int wc_AsconHash256_Init(wc_AsconHash256* a)
{
    if (a == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(a, 0, sizeof(*a));

    a->state.s64[0] = ASCON_HASH256_IV;
    permutation(&a->state, ASCON_HASH256_ROUNDS);

    return 0;
}

void wc_AsconHash256_Clear(wc_AsconHash256* a)
{
    if (a != NULL) {
        ForceZero(a, sizeof(*a));
    }
}

int wc_AsconHash256_Update(wc_AsconHash256* a, const byte* data, word32 dataSz)
{
    if (a == NULL || (data == NULL && dataSz != 0))
        return BAD_FUNC_ARG;

    if (dataSz == 0)
        return 0;

    /* Process leftover block */
    if (a->lastBlkSz != 0) {
        word32 toProcess = min(ASCON_HASH256_RATE - a->lastBlkSz, dataSz);
        xorbuf(a->state.s8 + a->lastBlkSz, data, toProcess);
        data += toProcess;
        dataSz -= toProcess;
        a->lastBlkSz += toProcess;

        if (a->lastBlkSz < ASCON_HASH256_RATE)
            return 0;

        permutation(&a->state, ASCON_HASH256_ROUNDS);
        /* Reset the counter */
        a->lastBlkSz = 0;
    }

    while (dataSz >= ASCON_HASH256_RATE) {
        /* Read in input as little endian numbers */
        xorbuf(a->state.s64, data, ASCON_HASH256_RATE);
        permutation(&a->state, ASCON_HASH256_ROUNDS);
        data += ASCON_HASH256_RATE;
        dataSz -= ASCON_HASH256_RATE;
    }

    xorbuf(a->state.s64, data, dataSz);
    a->lastBlkSz = dataSz;

    return 0;
}

int wc_AsconHash256_Final(wc_AsconHash256* a, byte* hash)
{
    byte i;

    if (a == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Process last block */
    a->state.s8[a->lastBlkSz] ^= 1;

    for (i = 0; i < ASCON_HASH256_SZ; i += ASCON_HASH256_RATE) {
        permutation(&a->state, ASCON_HASH256_ROUNDS);
        XMEMCPY(hash, a->state.s64, ASCON_HASH256_RATE);
        hash += ASCON_HASH256_RATE;
    }

    /* Clear state as soon as possible */
    wc_AsconHash256_Clear(a);
    return 0;
}

/* AsconAEAD API */

wc_AsconAEAD128* wc_AsconAEAD128_New(void)
{
    wc_AsconAEAD128 *ret = (wc_AsconAEAD128*) XMALLOC(sizeof(wc_AsconAEAD128),
            NULL, DYNAMIC_TYPE_ASCON);
    if (ret != NULL) {
        if (wc_AsconAEAD128_Init(ret) != 0) {
            wc_AsconAEAD128_Free(ret);
            ret = NULL;
        }
    }
    return ret;
}

void wc_AsconAEAD128_Free(wc_AsconAEAD128 *a)
{
    if (a != NULL) {
        wc_AsconAEAD128_Clear(a);
        XFREE(a, NULL, DYNAMIC_TYPE_ASCON);
    }
}

int wc_AsconAEAD128_Init(wc_AsconAEAD128 *a)
{
    if (a == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(a, 0, sizeof(*a));
    a->state.s64[0] = ASCON_AEAD128_IV;

    return 0;
}

void wc_AsconAEAD128_Clear(wc_AsconAEAD128 *a)
{
    if (a != NULL) {
        ForceZero(a, sizeof(*a));
    }
}

int wc_AsconAEAD128_SetKey(wc_AsconAEAD128* a, const byte* key)
{
    if (a == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (a->keySet)
        return BAD_STATE_E;

    XMEMCPY(a->key, key, ASCON_AEAD128_KEY_SZ);
    a->state.s64[1] = a->key[0];
    a->state.s64[2] = a->key[1];
    a->keySet = 1;

    return 0;
}

int wc_AsconAEAD128_SetNonce(wc_AsconAEAD128* a, const byte* nonce)
{
    if (a == NULL || nonce == NULL)
        return BAD_FUNC_ARG;
    if (a->nonceSet)
        return BAD_STATE_E;

    XMEMCPY(&a->state.s64[3], nonce, ASCON_AEAD128_NONCE_SZ);
    a->nonceSet = 1;

    return 0;
}

int wc_AsconAEAD128_SetAD(wc_AsconAEAD128* a, const byte* ad,
                                      word32 adSz)
{
    if (a == NULL || (ad == NULL && adSz > 0))
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet) /* key and nonce must be set before */
        return BAD_STATE_E;

    permutation(&a->state, ASCON_AEAD128_ROUNDS_PA);
    a->state.s64[3] ^= a->key[0];
    a->state.s64[4] ^= a->key[1];

    if (adSz > 0) {
        while (adSz >= ASCON_AEAD128_RATE) {
            xorbuf(a->state.s64, ad, ASCON_AEAD128_RATE);
            permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
            ad += ASCON_AEAD128_RATE;
            adSz -= ASCON_AEAD128_RATE;
        }
        xorbuf(a->state.s64, ad, adSz);
        /* Pad the last block */
        a->state.s8[adSz] ^= 1;
        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
    }
    a->state.s64[4] ^= 1ULL << 63;

    a->adSet = 1;
    return 0;
}

int wc_AsconAEAD128_EncryptUpdate(wc_AsconAEAD128* a, byte* out,
                                  const byte* in, word32 inSz)
{
    if (a == NULL || (in == NULL && inSz > 0))
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op == ASCON_AEAD128_NOTSET)
        a->op = ASCON_AEAD128_ENCRYPT;
    else if (a->op != ASCON_AEAD128_ENCRYPT)
        return BAD_STATE_E;

    /* Process leftover from last block */
    if (a->lastBlkSz != 0) {
        word32 toProcess = min(ASCON_AEAD128_RATE - a->lastBlkSz, inSz);
        xorbuf(&a->state.s8[a->lastBlkSz], in, toProcess);
        XMEMCPY(out, &a->state.s8[a->lastBlkSz], toProcess);
        a->lastBlkSz += toProcess;
        in += toProcess;
        out += toProcess;
        inSz -= toProcess;

        if (a->lastBlkSz < ASCON_AEAD128_RATE)
            return 0;

        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        a->lastBlkSz = 0;
    }

    while (inSz >= ASCON_AEAD128_RATE) {
        xorbuf(a->state.s64, in, ASCON_AEAD128_RATE);
        XMEMCPY(out, a->state.s64, ASCON_AEAD128_RATE);
        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        inSz -= ASCON_AEAD128_RATE;
    }
    /* Store leftover */
    xorbuf(a->state.s64, in, inSz);
    XMEMCPY(out, a->state.s64, inSz);
    a->lastBlkSz = inSz;

    return 0;
}


int wc_AsconAEAD128_EncryptFinal(wc_AsconAEAD128* a, byte* tag)
{
    if (a == NULL || tag == NULL)
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op != ASCON_AEAD128_ENCRYPT)
        return BAD_STATE_E;

    /* Process leftover from last block */
    a->state.s8[a->lastBlkSz] ^= 1;

    a->state.s64[2] ^= a->key[0];
    a->state.s64[3] ^= a->key[1];
    permutation(&a->state, ASCON_AEAD128_ROUNDS_PA);
    a->state.s64[3] ^= a->key[0];
    a->state.s64[4] ^= a->key[1];

    XMEMCPY(tag, &a->state.s64[3], ASCON_AEAD128_TAG_SZ);

    /* Clear state as soon as possible */
    wc_AsconAEAD128_Clear(a);

    return 0;

}


int wc_AsconAEAD128_DecryptUpdate(wc_AsconAEAD128* a, byte* out,
                                  const byte* in, word32 inSz)
{
    if (a == NULL || (in == NULL && inSz > 0))
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op == ASCON_AEAD128_NOTSET)
        a->op = ASCON_AEAD128_DECRYPT;
    else if (a->op != ASCON_AEAD128_DECRYPT)
        return BAD_STATE_E;

    /* Process leftover block */
    if (a->lastBlkSz != 0) {
        word32 toProcess = min(ASCON_AEAD128_RATE - a->lastBlkSz, inSz);
        xorbufout(out, a->state.s8 + a->lastBlkSz, in, toProcess);
        XMEMCPY(a->state.s8 + a->lastBlkSz, in, toProcess);
        in += toProcess;
        out += toProcess;
        inSz -= toProcess;
        a->lastBlkSz += toProcess;

        if (a->lastBlkSz < ASCON_AEAD128_RATE)
            return 0;

        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        a->lastBlkSz = 0;
    }

    while (inSz >= ASCON_AEAD128_RATE) {
        xorbufout(out, a->state.s64, in, ASCON_AEAD128_RATE);
        XMEMCPY(a->state.s64, in, ASCON_AEAD128_RATE);
        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        inSz -= ASCON_AEAD128_RATE;
    }
    /* Store leftover */
    xorbufout(out, a->state.s64, in, inSz);
    XMEMCPY(a->state.s64, in, inSz);
    a->lastBlkSz = inSz;

    return 0;
}

int wc_AsconAEAD128_DecryptFinal(wc_AsconAEAD128* a, const byte* tag)
{
    if (a == NULL || tag == NULL)
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op != ASCON_AEAD128_DECRYPT)
        return BAD_STATE_E;

    /* Pad last block */
    a->state.s8[a->lastBlkSz] ^= 1;

    a->state.s64[2] ^= a->key[0];
    a->state.s64[3] ^= a->key[1];
    permutation(&a->state, ASCON_AEAD128_ROUNDS_PA);
    a->state.s64[3] ^= a->key[0];
    a->state.s64[4] ^= a->key[1];

    if (ConstantCompare(tag, (const byte*)&a->state.s64[3],
                        ASCON_AEAD128_TAG_SZ) != 0)
        return ASCON_AUTH_E;

    /* Clear state as soon as possible */
    wc_AsconAEAD128_Clear(a);

    return 0;
}

#endif /* HAVE_ASCON */
