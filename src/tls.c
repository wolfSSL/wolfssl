/* tls.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFCRYPT_ONLY

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/hmac.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef HAVE_NTRU
    #include "libntruencrypt/ntru_crypto.h"
    #include <wolfssl/wolfcrypt/random.h>
#endif
#ifdef HAVE_QSH
    static int TLSX_AddQSHKey(QSHKey** list, QSHKey* key);
    static byte* TLSX_QSHKeyFind_Pub(QSHKey* qsh, word16* pubLen, word16 name);
    static int TLSX_CreateNtruKey(WOLFSSL* ssl, int type);
#endif


#ifndef NO_TLS


#ifndef WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MIN

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* WOLFSSL_HAVE_MIN */


#ifdef WOLFSSL_SHA384
    #define P_HASH_MAX_SIZE SHA384_DIGEST_SIZE
#else
    #define P_HASH_MAX_SIZE SHA256_DIGEST_SIZE
#endif

/* compute p_hash for MD5, SHA-1, SHA-256, or SHA-384 for TLSv1 PRF */
static int p_hash(byte* result, word32 resLen, const byte* secret,
                   word32 secLen, const byte* seed, word32 seedLen, int hash)
{
    word32 len = P_HASH_MAX_SIZE;
    word32 times;
    word32 lastLen;
    word32 lastTime;
    word32 i;
    word32 idx = 0;
    int    ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte*  previous;
    byte*  current;
    Hmac*  hmac;
#else
    byte   previous[P_HASH_MAX_SIZE];  /* max size */
    byte   current[P_HASH_MAX_SIZE];   /* max size */
    Hmac   hmac[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    previous = (byte*)XMALLOC(P_HASH_MAX_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    current  = (byte*)XMALLOC(P_HASH_MAX_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    hmac     = (Hmac*)XMALLOC(sizeof(Hmac),    NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (previous == NULL || current == NULL || hmac == NULL) {
        if (previous) XFREE(previous, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (current)  XFREE(current,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (hmac)     XFREE(hmac,     NULL, DYNAMIC_TYPE_TMP_BUFFER);

        return MEMORY_E;
    }
#endif

    switch (hash) {
        #ifndef NO_MD5
            case md5_mac:
                hash = MD5;
                len  = MD5_DIGEST_SIZE;
            break;
        #endif

        #ifndef NO_SHA256
            case sha256_mac:
                hash = SHA256;
                len  = SHA256_DIGEST_SIZE;
            break;
        #endif

        #ifdef WOLFSSL_SHA384
            case sha384_mac:
                hash = SHA384;
                len  = SHA384_DIGEST_SIZE;
            break;
        #endif

        #ifndef NO_SHA
            case sha_mac:
            default:
                hash = SHA;
                len  = SHA_DIGEST_SIZE;
            break;
        #endif
    }

    times   = resLen / len;
    lastLen = resLen % len;

    if (lastLen)
        times += 1;

    lastTime = times - 1;

    if ((ret = wc_HmacSetKey(hmac, hash, secret, secLen)) == 0) {
        if ((ret = wc_HmacUpdate(hmac, seed, seedLen)) == 0) { /* A0 = seed */
            if ((ret = wc_HmacFinal(hmac, previous)) == 0) {   /* A1 */
                for (i = 0; i < times; i++) {
                    ret = wc_HmacUpdate(hmac, previous, len);
                    if (ret != 0)
                        break;
                    ret = wc_HmacUpdate(hmac, seed, seedLen);
                    if (ret != 0)
                        break;
                    ret = wc_HmacFinal(hmac, current);
                    if (ret != 0)
                        break;

                    if ((i == lastTime) && lastLen)
                        XMEMCPY(&result[idx], current,
                                                 min(lastLen, P_HASH_MAX_SIZE));
                    else {
                        XMEMCPY(&result[idx], current, len);
                        idx += len;
                        ret = wc_HmacUpdate(hmac, previous, len);
                        if (ret != 0)
                            break;
                        ret = wc_HmacFinal(hmac, previous);
                        if (ret != 0)
                            break;
                    }
                }
            }
        }
    }

    ForceZero(previous,  P_HASH_MAX_SIZE);
    ForceZero(current,   P_HASH_MAX_SIZE);
    ForceZero(hmac,      sizeof(Hmac));

#ifdef WOLFSSL_SMALL_STACK
    XFREE(previous, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(current,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(hmac,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#undef P_HASH_MAX_SIZE


#ifndef NO_OLD_TLS

/* calculate XOR for TLSv1 PRF */
static INLINE void get_xor(byte *digest, word32 digLen, byte* md5, byte* sha)
{
    word32 i;

    for (i = 0; i < digLen; i++)
        digest[i] = md5[i] ^ sha[i];
}


/* compute TLSv1 PRF (pseudo random function using HMAC) */
static int doPRF(byte* digest, word32 digLen, const byte* secret,word32 secLen,
                 const byte* label, word32 labLen, const byte* seed,
                 word32 seedLen)
{
    int    ret  = 0;
    word32 half = (secLen + 1) / 2;

#ifdef WOLFSSL_SMALL_STACK
    byte* md5_half;
    byte* sha_half;
    byte* labelSeed;
    byte* md5_result;
    byte* sha_result;
#else
    byte  md5_half[MAX_PRF_HALF];     /* half is real size */
    byte  sha_half[MAX_PRF_HALF];     /* half is real size */
    byte  labelSeed[MAX_PRF_LABSEED]; /* labLen + seedLen is real size */
    byte  md5_result[MAX_PRF_DIG];    /* digLen is real size */
    byte  sha_result[MAX_PRF_DIG];    /* digLen is real size */
#endif

    if (half > MAX_PRF_HALF)
        return BUFFER_E;
    if (labLen + seedLen > MAX_PRF_LABSEED)
        return BUFFER_E;
    if (digLen > MAX_PRF_DIG)
        return BUFFER_E;

#ifdef WOLFSSL_SMALL_STACK
    md5_half   = (byte*)XMALLOC(MAX_PRF_HALF,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sha_half   = (byte*)XMALLOC(MAX_PRF_HALF,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    labelSeed  = (byte*)XMALLOC(MAX_PRF_LABSEED, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    md5_result = (byte*)XMALLOC(MAX_PRF_DIG,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sha_result = (byte*)XMALLOC(MAX_PRF_DIG,     NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (md5_half == NULL || sha_half == NULL || labelSeed == NULL ||
                                     md5_result == NULL || sha_result == NULL) {
        if (md5_half)   XFREE(md5_half,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sha_half)   XFREE(sha_half,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (labelSeed)  XFREE(labelSeed,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (md5_result) XFREE(md5_result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sha_result) XFREE(sha_result, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        return MEMORY_E;
    }
#endif

    XMEMSET(md5_result, 0, digLen);
    XMEMSET(sha_result, 0, digLen);

    XMEMCPY(md5_half, secret, half);
    XMEMCPY(sha_half, secret + half - secLen % 2, half);

    XMEMCPY(labelSeed, label, labLen);
    XMEMCPY(labelSeed + labLen, seed, seedLen);

    if ((ret = p_hash(md5_result, digLen, md5_half, half, labelSeed,
                                             labLen + seedLen, md5_mac)) == 0) {
        if ((ret = p_hash(sha_result, digLen, sha_half, half, labelSeed,
                                             labLen + seedLen, sha_mac)) == 0) {
            get_xor(digest, digLen, md5_result, sha_result);
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(md5_half,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sha_half,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(labelSeed,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(md5_result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sha_result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif


/* Wrapper to call straight thru to p_hash in TSL 1.2 cases to remove stack
   use */
static int PRF(byte* digest, word32 digLen, const byte* secret, word32 secLen,
            const byte* label, word32 labLen, const byte* seed, word32 seedLen,
            int useAtLeastSha256, int hash_type)
{
    int ret = 0;

    if (useAtLeastSha256) {
#ifdef WOLFSSL_SMALL_STACK
        byte* labelSeed;
#else
        byte labelSeed[MAX_PRF_LABSEED]; /* labLen + seedLen is real size */
#endif

        if (labLen + seedLen > MAX_PRF_LABSEED)
            return BUFFER_E;

#ifdef WOLFSSL_SMALL_STACK
        labelSeed = (byte*)XMALLOC(MAX_PRF_LABSEED, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (labelSeed == NULL)
           return MEMORY_E;
#endif

        XMEMCPY(labelSeed, label, labLen);
        XMEMCPY(labelSeed + labLen, seed, seedLen);

        /* If a cipher suite wants an algorithm better than sha256, it
         * should use better. */
        if (hash_type < sha256_mac || hash_type == blake2b_mac)
            hash_type = sha256_mac;
        ret = p_hash(digest, digLen, secret, secLen, labelSeed,
                     labLen + seedLen, hash_type);

#ifdef WOLFSSL_SMALL_STACK
        XFREE(labelSeed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    }
#ifndef NO_OLD_TLS
    else {
        ret = doPRF(digest, digLen, secret, secLen, label, labLen, seed,
                    seedLen);
    }
#endif

    return ret;
}


#ifdef WOLFSSL_SHA384
    #define HSHASH_SZ SHA384_DIGEST_SIZE
#else
    #define HSHASH_SZ FINISHED_SZ
#endif


int BuildTlsHandshakeHash(WOLFSSL* ssl, byte* hash, word32* hashLen)
{
    word32 hashSz = FINISHED_SZ;

    if (ssl == NULL || hash == NULL || hashLen == NULL || *hashLen < HSHASH_SZ)
        return BAD_FUNC_ARG;

#ifndef NO_OLD_TLS
    wc_Md5GetHash(&ssl->hsHashes->hashMd5, hash);
    wc_ShaGetHash(&ssl->hsHashes->hashSha, &hash[MD5_DIGEST_SIZE]);
#endif

    if (IsAtLeastTLSv1_2(ssl)) {
#ifndef NO_SHA256
        if (ssl->specs.mac_algorithm <= sha256_mac ||
            ssl->specs.mac_algorithm == blake2b_mac) {
            int ret = wc_Sha256GetHash(&ssl->hsHashes->hashSha256, hash);

            if (ret != 0)
                return ret;

            hashSz = SHA256_DIGEST_SIZE;
        }
#endif
#ifdef WOLFSSL_SHA384
        if (ssl->specs.mac_algorithm == sha384_mac) {
            int ret = wc_Sha384GetHash(&ssl->hsHashes->hashSha384, hash);

            if (ret != 0)
                return ret;

            hashSz = SHA384_DIGEST_SIZE;
        }
#endif
    }

    *hashLen = hashSz;

    return 0;
}


int BuildTlsFinished(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int         ret;
    const byte* side;
    byte        handshake_hash[HSHASH_SZ];
    word32      hashSz = HSHASH_SZ;

    ret = BuildTlsHandshakeHash(ssl, handshake_hash, &hashSz);
    if (ret < 0)
        return ret;

    if ( XSTRNCMP((const char*)sender, (const char*)client, SIZEOF_SENDER) == 0)
        side = tls_client;
    else
        side = tls_server;

    return PRF((byte*)hashes, TLS_FINISHED_SZ, ssl->arrays->masterSecret,
               SECRET_LEN, side, FINISHED_LABEL_SZ, handshake_hash, hashSz,
               IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
}


#ifndef NO_OLD_TLS

ProtocolVersion MakeTLSv1(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_MINOR;

    return pv;
}


ProtocolVersion MakeTLSv1_1(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_1_MINOR;

    return pv;
}

#endif


ProtocolVersion MakeTLSv1_2(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_2_MINOR;

    return pv;
}


#ifdef HAVE_EXTENDED_MASTER
static const byte ext_master_label[EXT_MASTER_LABEL_SZ + 1] =
                                                      "extended master secret";
#endif
static const byte master_label[MASTER_LABEL_SZ + 1] = "master secret";
static const byte key_label   [KEY_LABEL_SZ + 1]    = "key expansion";


/* External facing wrapper so user can call as well, 0 on success */
int wolfSSL_DeriveTlsKeys(byte* key_data, word32 keyLen,
                         const byte* ms, word32 msLen,
                         const byte* sr, const byte* cr,
                         int tls1_2, int hash_type)
{
    byte  seed[SEED_LEN];

    XMEMCPY(seed,           sr, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, cr, RAN_LEN);

    return PRF(key_data, keyLen, ms, msLen, key_label, KEY_LABEL_SZ,
               seed, SEED_LEN, tls1_2, hash_type);
}


int DeriveTlsKeys(WOLFSSL* ssl)
{
    int   ret;
    int   length = 2 * ssl->specs.hash_size +
                   2 * ssl->specs.key_size  +
                   2 * ssl->specs.iv_size;
#ifdef WOLFSSL_SMALL_STACK
    byte* key_data;
#else
    byte  key_data[MAX_PRF_DIG];
#endif

#ifdef WOLFSSL_SMALL_STACK
    key_data = (byte*)XMALLOC(MAX_PRF_DIG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key_data == NULL) {
        return MEMORY_E;
    }
#endif

    ret = wolfSSL_DeriveTlsKeys(key_data, length,
                           ssl->arrays->masterSecret, SECRET_LEN,
                           ssl->arrays->serverRandom, ssl->arrays->clientRandom,
                           IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    if (ret == 0)
        ret = StoreKeys(ssl, key_data);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(key_data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/* External facing wrapper so user can call as well, 0 on success */
int wolfSSL_MakeTlsMasterSecret(byte* ms, word32 msLen,
                               const byte* pms, word32 pmsLen,
                               const byte* cr, const byte* sr,
                               int tls1_2, int hash_type)
{
    byte  seed[SEED_LEN];

    XMEMCPY(seed,           cr, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, sr, RAN_LEN);

    return PRF(ms, msLen, pms, pmsLen, master_label, MASTER_LABEL_SZ,
               seed, SEED_LEN, tls1_2, hash_type);
}


#ifdef HAVE_EXTENDED_MASTER

/* External facing wrapper so user can call as well, 0 on success */
int wolfSSL_MakeTlsExtendedMasterSecret(byte* ms, word32 msLen,
                                        const byte* pms, word32 pmsLen,
                                        const byte* sHash, word32 sHashLen,
                                        int tls1_2, int hash_type)
{
    return PRF(ms, msLen, pms, pmsLen, ext_master_label, EXT_MASTER_LABEL_SZ,
               sHash, sHashLen, tls1_2, hash_type);
}

#endif /* HAVE_EXTENDED_MASTER */


int MakeTlsMasterSecret(WOLFSSL* ssl)
{
    int    ret;
#ifdef HAVE_EXTENDED_MASTER
    byte   handshake_hash[HSHASH_SZ];
    word32 hashSz = HSHASH_SZ;

    if (ssl->options.haveEMS) {

        ret = BuildTlsHandshakeHash(ssl, handshake_hash, &hashSz);
        if (ret < 0)
            return ret;

        ret = wolfSSL_MakeTlsExtendedMasterSecret(
                ssl->arrays->masterSecret, SECRET_LEN,
                ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
                handshake_hash, hashSz,
                IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    } else
#endif
    ret = wolfSSL_MakeTlsMasterSecret(ssl->arrays->masterSecret, SECRET_LEN,
              ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
              ssl->arrays->clientRandom, ssl->arrays->serverRandom,
              IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);

    if (ret == 0) {
    #ifdef SHOW_SECRETS
        int i;

        printf("master secret: ");
        for (i = 0; i < SECRET_LEN; i++)
            printf("%02x", ssl->arrays->masterSecret[i]);
        printf("\n");
    #endif

        ret = DeriveTlsKeys(ssl);
    }

    return ret;
}


/* Used by EAP-TLS and EAP-TTLS to derive keying material from
 * the master_secret. */
int wolfSSL_make_eap_keys(WOLFSSL* ssl, void* msk, unsigned int len,
                                                              const char* label)
{
    int   ret;
#ifdef WOLFSSL_SMALL_STACK
    byte* seed;
#else
    byte  seed[SEED_LEN];
#endif

#ifdef WOLFSSL_SMALL_STACK
    seed = (byte*)XMALLOC(SEED_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (seed == NULL)
        return MEMORY_E;
#endif

    /*
     * As per RFC-5281, the order of the client and server randoms is reversed
     * from that used by the TLS protocol to derive keys.
     */
    XMEMCPY(seed,           ssl->arrays->clientRandom, RAN_LEN);
    XMEMCPY(seed + RAN_LEN, ssl->arrays->serverRandom, RAN_LEN);

    ret = PRF((byte*)msk, len, ssl->arrays->masterSecret, SECRET_LEN,
              (const byte *)label, (word32)XSTRLEN(label), seed, SEED_LEN,
              IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(seed, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/*** next for static INLINE s copied internal.c ***/

/* convert 16 bit integer to opaque */
static INLINE void c16toa(word16 u16, byte* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}

#ifdef HAVE_TLS_EXTENSIONS
/* convert opaque to 16 bit integer */
static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}

#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_SERVER)
/* convert a 24 bit integer into a 32 bit one */
static INLINE void c24to32(const word24 u24, word32* u32)
{
    *u32 = (u24[0] << 16) | (u24[1] << 8) | u24[2];
}
#endif
#endif

/* convert 32 bit integer to opaque */
static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}


static INLINE word32 GetSEQIncrement(WOLFSSL* ssl, int verify)
{
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        if (verify)
            return ssl->keys.dtls_state.curSeq; /* explicit from peer */
        else
            return ssl->keys.dtls_sequence_number - 1; /* already incremented */
    }
#endif
    if (verify)
        return ssl->keys.peer_sequence_number++;
    else
        return ssl->keys.sequence_number++;
}


#ifdef WOLFSSL_DTLS

static INLINE word32 GetEpoch(WOLFSSL* ssl, int verify)
{
    if (verify)
        return ssl->keys.dtls_state.curEpoch;
    else
        return ssl->keys.dtls_epoch;
}

#endif /* WOLFSSL_DTLS */


/*** end copy ***/


/* return HMAC digest type in wolfSSL format */
int wolfSSL_GetHmacType(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    switch (ssl->specs.mac_algorithm) {
        #ifndef NO_MD5
        case md5_mac:
        {
            return MD5;
        }
        #endif
        #ifndef NO_SHA256
        case sha256_mac:
        {
            return SHA256;
        }
        #endif
        #ifdef WOLFSSL_SHA384
        case sha384_mac:
        {
            return SHA384;
        }

        #endif
        #ifndef NO_SHA
        case sha_mac:
        {
            return SHA;
        }
        #endif
        #ifdef HAVE_BLAKE2
        case blake2b_mac:
        {
            return BLAKE2B_ID;
        }
        #endif
        default:
        {
            return SSL_FATAL_ERROR;
        }
    }
}


int wolfSSL_SetTlsHmacInner(WOLFSSL* ssl, byte* inner, word32 sz, int content,
                           int verify)
{
    if (ssl == NULL || inner == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(inner, 0, WOLFSSL_TLS_HMAC_INNER_SZ);

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls)
        c16toa((word16)GetEpoch(ssl, verify), inner);
#endif
    c32toa(GetSEQIncrement(ssl, verify), &inner[sizeof(word32)]);
    inner[SEQ_SZ] = (byte)content;
    inner[SEQ_SZ + ENUM_LEN]            = ssl->version.major;
    inner[SEQ_SZ + ENUM_LEN + ENUM_LEN] = ssl->version.minor;
    c16toa((word16)sz, inner + SEQ_SZ + ENUM_LEN + VERSION_SZ);

    return 0;
}


/* TLS type HMAC */
int TLS_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz,
              int content, int verify)
{
    Hmac hmac;
    int  ret;
    byte myInner[WOLFSSL_TLS_HMAC_INNER_SZ];

    if (ssl == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_FUZZER
    if (ssl->fuzzerCb)
        ssl->fuzzerCb(ssl, in, sz, FUZZ_HMAC, ssl->fuzzerCtx);
#endif

    wolfSSL_SetTlsHmacInner(ssl, myInner, sz, content, verify);

    ret = wc_HmacSetKey(&hmac, wolfSSL_GetHmacType(ssl),
                     wolfSSL_GetMacSecret(ssl, verify), ssl->specs.hash_size);
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, myInner, sizeof(myInner));
    if (ret != 0)
        return ret;
    ret = wc_HmacUpdate(&hmac, in, sz);                                /* content */
    if (ret != 0)
        return ret;
    ret = wc_HmacFinal(&hmac, digest);
    if (ret != 0)
        return ret;

    return 0;
}

#ifdef HAVE_TLS_EXTENSIONS

/**
 * The TLSX semaphore is used to calculate the size of the extensions to be sent
 * from one peer to another.
 */

/** Supports up to 64 flags. Increase as needed. */
#define SEMAPHORE_SIZE 8

/**
 * Converts the extension type (id) to an index in the semaphore.
 *
 * Oficial reference for TLS extension types:
 *   http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml
 *
 * Motivation:
 *   Previously, we used the extension type itself as the index of that
 *   extension in the semaphore as the extension types were declared
 *   sequentially, but maintain a semaphore as big as the number of available
 *   extensions is no longer an option since the release of renegotiation_info.
 *
 * How to update:
 *   Assign extension types that extrapolate the number of available semaphores
 *   to the first available index going backwards in the semaphore array.
 *   When adding a new extension type that don't extrapolate the number of
 *   available semaphores, check for a possible collision with with a
 *   'remapped' extension type.
 */
static INLINE word16 TLSX_ToSemaphore(word16 type)
{
    switch (type) {

        case TLSX_RENEGOTIATION_INFO: /* 0xFF01 */
            return 63;

        default:
            if (type > 62) {
                /* This message SHOULD only happens during the adding of
                   new TLS extensions in which its IANA number overflows
                   the current semaphore's range, or if its number already
                   is assigned to be used by another extension.
                   Use this check value for the new extension and decrement
                   the check value by one. */
                WOLFSSL_MSG("### TLSX semaphore colision or overflow detected!");
            }
    }

    return type;
}

/** Checks if a specific light (tls extension) is not set in the semaphore. */
#define IS_OFF(semaphore, light) \
    ((semaphore)[(light) / 8] ^  (byte) (0x01 << ((light) % 8)))

/** Turn on a specific light (tls extension) in the semaphore. */
#define TURN_ON(semaphore, light) \
    ((semaphore)[(light) / 8] |= (byte) (0x01 << ((light) % 8)))

/** Creates a new extension. */
static TLSX* TLSX_New(TLSX_Type type, void* data, void* heap)
{
    TLSX* extension = (TLSX*)XMALLOC(sizeof(TLSX), heap, DYNAMIC_TYPE_TLSX);

    if (extension) {
        extension->type = type;
        extension->data = data;
        extension->resp = 0;
        extension->next = NULL;
    }

    return extension;
}

/**
 * Creates a new extension and pushes it to the provided list.
 * Checks for duplicate extensions, keeps the newest.
 */
static int TLSX_Push(TLSX** list, TLSX_Type type, void* data, void* heap)
{
    TLSX* extension = TLSX_New(type, data, heap);

    if (extension == NULL)
        return MEMORY_E;

    /* pushes the new extension on the list. */
    extension->next = *list;
    *list = extension;

    /* remove duplicate extensions, there should be only one of each type. */
    do {
        if (extension->next && extension->next->type == type) {
            TLSX *next = extension->next;

            extension->next = next->next;
            next->next = NULL;

            TLSX_FreeAll(next, heap);

            /* there is no way to occur more than */
            /* two extensions of the same type.   */
            break;
        }
    } while ((extension = extension->next));

    return 0;
}

#ifndef NO_WOLFSSL_SERVER

/** Mark an extension to be sent back to the client. */
void TLSX_SetResponse(WOLFSSL* ssl, TLSX_Type type);

void TLSX_SetResponse(WOLFSSL* ssl, TLSX_Type type)
{
    TLSX *ext = TLSX_Find(ssl->extensions, type);

    if (ext)
        ext->resp = 1;
}

#endif

/******************************************************************************/
/* Application-Layer Protocol Negotiation                                     */
/******************************************************************************/

#ifdef HAVE_ALPN
/** Creates a new ALPN object, providing protocol name to use. */
static ALPN* TLSX_ALPN_New(char *protocol_name, word16 protocol_nameSz,
                                                                     void* heap)
{
    ALPN *alpn;

    WOLFSSL_ENTER("TLSX_ALPN_New");

    if (protocol_name == NULL ||
        protocol_nameSz > WOLFSSL_MAX_ALPN_PROTO_NAME_LEN) {
        WOLFSSL_MSG("Invalid arguments");
        return NULL;
    }

    alpn = (ALPN*)XMALLOC(sizeof(ALPN), heap, DYNAMIC_TYPE_TLSX);
    if (alpn == NULL) {
        WOLFSSL_MSG("Memory failure");
        return NULL;
    }

    alpn->next = NULL;
    alpn->negotiated = 0;
    alpn->options = 0;

    alpn->protocol_name = (char*)XMALLOC(protocol_nameSz + 1,
                                         heap, DYNAMIC_TYPE_TLSX);
    if (alpn->protocol_name == NULL) {
        WOLFSSL_MSG("Memory failure");
        XFREE(alpn, heap, DYNAMIC_TYPE_TLSX);
        return NULL;
    }

    XMEMCPY(alpn->protocol_name, protocol_name, protocol_nameSz);
    alpn->protocol_name[protocol_nameSz] = 0;

    return alpn;
}

/** Releases an ALPN object. */
static void TLSX_ALPN_Free(ALPN *alpn, void* heap)
{
    (void)heap;

    if (alpn == NULL)
        return;

    XFREE(alpn->protocol_name, heap, DYNAMIC_TYPE_TLSX);
    XFREE(alpn, heap, DYNAMIC_TYPE_TLSX);
}

/** Releases all ALPN objects in the provided list. */
static void TLSX_ALPN_FreeAll(ALPN *list, void* heap)
{
    ALPN* alpn;

    while ((alpn = list)) {
        list = alpn->next;
        TLSX_ALPN_Free(alpn, heap);
    }
}

/** Tells the buffered size of the ALPN objects in a list. */
static word16 TLSX_ALPN_GetSize(ALPN *list)
{
    ALPN* alpn;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((alpn = list)) {
        list = alpn->next;

        length++; /* protocol name length is on one byte */
        length += (word16)XSTRLEN(alpn->protocol_name);
    }

    return length;
}

/** Writes the ALPN objects of a list in a buffer. */
static word16 TLSX_ALPN_Write(ALPN *list, byte *output)
{
    ALPN* alpn;
    word16 length = 0;
    word16 offset = OPAQUE16_LEN; /* list length offset */

    while ((alpn = list)) {
        list = alpn->next;

        length = (word16)XSTRLEN(alpn->protocol_name);

        /* protocol name length */
        output[offset++] = (byte)length;

        /* protocol name value */
        XMEMCPY(output + offset, alpn->protocol_name, length);

        offset += length;
    }

    /* writing list length */
    c16toa(offset - OPAQUE16_LEN, output);

    return offset;
}

/** Finds a protocol name in the provided ALPN list */
static ALPN* TLSX_ALPN_Find(ALPN *list, char *protocol_name, word16 size)
{
    ALPN *alpn;

    if (list == NULL || protocol_name == NULL)
        return NULL;

    alpn = list;
    while (alpn != NULL && (
           (word16)XSTRLEN(alpn->protocol_name) != size ||
           XSTRNCMP(alpn->protocol_name, protocol_name, size)))
        alpn = alpn->next;

    return alpn;
}

/** Set the ALPN matching client and server requirements */
static int TLSX_SetALPN(TLSX** extensions, const void* data, word16 size,
                                                                     void* heap)
{
    ALPN *alpn;
    int  ret;

    if (extensions == NULL || data == NULL)
        return BAD_FUNC_ARG;

    alpn = TLSX_ALPN_New((char *)data, size, heap);
    if (alpn == NULL) {
        WOLFSSL_MSG("Memory failure");
        return MEMORY_E;
    }

    alpn->negotiated = 1;

    ret = TLSX_Push(extensions, TLSX_APPLICATION_LAYER_PROTOCOL, (void*)alpn,
                                                                          heap);
    if (ret != 0) {
        TLSX_ALPN_Free(alpn, heap);
        return ret;
    }

    return SSL_SUCCESS;
}

/** Parses a buffer of ALPN extensions and set the first one matching
 * client and server requirements */
static int TLSX_ALPN_ParseAndSet(WOLFSSL *ssl, byte *input, word16 length,
                                 byte isRequest)
{
    word16  size = 0, offset = 0, idx = 0;
    int     r = BUFFER_ERROR;
    byte    match = 0;
    TLSX    *extension;
    ALPN    *alpn = NULL, *list;

    extension = TLSX_Find(ssl->extensions, TLSX_APPLICATION_LAYER_PROTOCOL);
    if (extension == NULL)
        extension = TLSX_Find(ssl->ctx->extensions,
                                               TLSX_APPLICATION_LAYER_PROTOCOL);

    if (extension == NULL || extension->data == NULL) {
        WOLFSSL_MSG("No ALPN extensions not used or bad");
        return isRequest ? 0             /* not using ALPN */
                         : BUFFER_ERROR; /* unexpected ALPN response */
    }

    if (OPAQUE16_LEN > length)
        return BUFFER_ERROR;

    ato16(input, &size);
    offset += OPAQUE16_LEN;

    /* validating alpn list length */
    if (length != OPAQUE16_LEN + size)
        return BUFFER_ERROR;

    list = (ALPN*)extension->data;

    /* keep the list sent by client */
    if (isRequest) {
        if (ssl->alpn_client_list != NULL)
            XFREE(ssl->alpn_client_list, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

        ssl->alpn_client_list = (char *)XMALLOC(size, ssl->heap,
                                                DYNAMIC_TYPE_TMP_BUFFER);
        if (ssl->alpn_client_list == NULL)
            return MEMORY_ERROR;
    }

    for (size = 0; offset < length; offset += size) {

        size = input[offset++];
        if (offset + size > length)
            return BUFFER_ERROR;

        if (isRequest) {
            XMEMCPY(ssl->alpn_client_list+idx, (char*)input + offset, size);
            idx += size;
            ssl->alpn_client_list[idx++] = ',';
        }

        if (!match) {
            alpn = TLSX_ALPN_Find(list, (char*)input + offset, size);
            if (alpn != NULL) {
                WOLFSSL_MSG("ALPN protocol match");
                match = 1;

                /* skip reading other values if not required */
                if (!isRequest)
                    break;
            }
        }
    }

    if (isRequest)
        ssl->alpn_client_list[idx-1] = 0;

    if (!match) {
        WOLFSSL_MSG("No ALPN protocol match");

        /* do nothing if no protocol match between client and server and option
         is set to continue (like OpenSSL) */
        if (list->options & WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) {
            WOLFSSL_MSG("Continue on mismatch");
            return 0;
        }

        SendAlert(ssl, alert_fatal, no_application_protocol);
        return UNKNOWN_ALPN_PROTOCOL_NAME_E;
    }

    /* set the matching negotiated protocol */
    r = TLSX_SetALPN(&ssl->extensions,
                     alpn->protocol_name,
                     (word16)XSTRLEN(alpn->protocol_name),
                     ssl->heap);
    if (r != SSL_SUCCESS) {
        WOLFSSL_MSG("TLSX_UseALPN failed");
        return BUFFER_ERROR;
    }

    /* reply to ALPN extension sent from client */
    if (isRequest) {
#ifndef NO_WOLFSSL_SERVER
        TLSX_SetResponse(ssl, TLSX_APPLICATION_LAYER_PROTOCOL);
#endif
    }

    return 0;
}

/** Add a protocol name to the list of accepted usable ones */
int TLSX_UseALPN(TLSX** extensions, const void* data, word16 size, byte options,
                                                                     void* heap)
{
    ALPN *alpn;
    TLSX *extension;
    int  ret;

    if (extensions == NULL || data == NULL)
        return BAD_FUNC_ARG;

    alpn = TLSX_ALPN_New((char *)data, size, heap);
    if (alpn == NULL) {
        WOLFSSL_MSG("Memory failure");
        return MEMORY_E;
    }

    /* Set Options of ALPN */
    alpn->options = options;

    extension = TLSX_Find(*extensions, TLSX_APPLICATION_LAYER_PROTOCOL);
    if (extension == NULL) {
        ret = TLSX_Push(extensions, TLSX_APPLICATION_LAYER_PROTOCOL,
                                                             (void*)alpn, heap);
        if (ret != 0) {
            TLSX_ALPN_Free(alpn, heap);
            return ret;
        }
    }
    else {
        /* push new ALPN object to extension data. */
        alpn->next = (ALPN*)extension->data;
        extension->data = (void*)alpn;
    }

    return SSL_SUCCESS;
}

/** Get the protocol name set by the server */
int TLSX_ALPN_GetRequest(TLSX* extensions, void** data, word16 *dataSz)
{
    TLSX *extension;
    ALPN *alpn;

    if (extensions == NULL || data == NULL || dataSz == NULL)
        return BAD_FUNC_ARG;

    extension = TLSX_Find(extensions, TLSX_APPLICATION_LAYER_PROTOCOL);
    if (extension == NULL) {
        WOLFSSL_MSG("TLS extension not found");
        return SSL_ALPN_NOT_FOUND;
    }

    alpn = (ALPN *)extension->data;
    if (alpn == NULL) {
        WOLFSSL_MSG("ALPN extension not found");
        *data = NULL;
        *dataSz = 0;
        return SSL_FATAL_ERROR;
    }

    if (alpn->negotiated != 1) {

        /* consider as an error */
        if (alpn->options & WOLFSSL_ALPN_FAILED_ON_MISMATCH) {
            WOLFSSL_MSG("No protocol match with peer -> Failed");
            return SSL_FATAL_ERROR;
        }

        /* continue without negotiated protocol */
        WOLFSSL_MSG("No protocol match with peer -> Continue");
        return SSL_ALPN_NOT_FOUND;
    }

    if (alpn->next != NULL) {
        WOLFSSL_MSG("Only one protocol name must be accepted");
        return SSL_FATAL_ERROR;
    }

    *data = alpn->protocol_name;
    *dataSz = (word16)XSTRLEN((char*)*data);

    return SSL_SUCCESS;
}

#define ALPN_FREE_ALL     TLSX_ALPN_FreeAll
#define ALPN_GET_SIZE     TLSX_ALPN_GetSize
#define ALPN_WRITE        TLSX_ALPN_Write
#define ALPN_PARSE        TLSX_ALPN_ParseAndSet

#else /* HAVE_ALPN */

#define ALPN_FREE_ALL(list, heap)
#define ALPN_GET_SIZE(list)     0
#define ALPN_WRITE(a, b)        0
#define ALPN_PARSE(a, b, c, d)  0

#endif /* HAVE_ALPN */

/******************************************************************************/
/* Server Name Indication                                                     */
/******************************************************************************/

#ifdef HAVE_SNI

/** Creates a new SNI object. */
static SNI* TLSX_SNI_New(byte type, const void* data, word16 size, void* heap)
{
    SNI* sni = (SNI*)XMALLOC(sizeof(SNI), heap, DYNAMIC_TYPE_TLSX);

    if (sni) {
        sni->type = type;
        sni->next = NULL;

    #ifndef NO_WOLFSSL_SERVER
        sni->options = 0;
        sni->status  = WOLFSSL_SNI_NO_MATCH;
    #endif

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                sni->data.host_name = (char*)XMALLOC(size + 1, heap,
                                                     DYNAMIC_TYPE_TLSX);
                if (sni->data.host_name) {
                    XSTRNCPY(sni->data.host_name, (const char*)data, size);
                    sni->data.host_name[size] = 0;
                } else {
                    XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
                    sni = NULL;
                }
            break;

            default: /* invalid type */
                XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
                sni = NULL;
        }
    }

    return sni;
}

/** Releases a SNI object. */
static void TLSX_SNI_Free(SNI* sni, void* heap)
{
    if (sni) {
        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                XFREE(sni->data.host_name, heap, DYNAMIC_TYPE_TLSX);
            break;
        }

        XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

/** Releases all SNI objects in the provided list. */
static void TLSX_SNI_FreeAll(SNI* list, void* heap)
{
    SNI* sni;

    while ((sni = list)) {
        list = sni->next;
        TLSX_SNI_Free(sni, heap);
    }
}

/** Tells the buffered size of the SNI objects in a list. */
static word16 TLSX_SNI_GetSize(SNI* list)
{
    SNI* sni;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((sni = list)) {
        list = sni->next;

        length += ENUM_LEN + OPAQUE16_LEN; /* sni type + sni length */

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                length += XSTRLEN((char*)sni->data.host_name);
            break;
        }
    }

    return length;
}

/** Writes the SNI objects of a list in a buffer. */
static word16 TLSX_SNI_Write(SNI* list, byte* output)
{
    SNI* sni;
    word16 length = 0;
    word16 offset = OPAQUE16_LEN; /* list length offset */

    while ((sni = list)) {
        list = sni->next;

        output[offset++] = sni->type; /* sni type */

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                length = XSTRLEN((char*)sni->data.host_name);

                c16toa(length, output + offset); /* sni length */
                offset += OPAQUE16_LEN;

                XMEMCPY(output + offset, sni->data.host_name, length);

                offset += length;
            break;
        }
    }

    c16toa(offset - OPAQUE16_LEN, output); /* writing list length */

    return offset;
}

#ifndef NO_WOLFSSL_SERVER

/** Finds a SNI object in the provided list. */
static SNI* TLSX_SNI_Find(SNI *list, byte type)
{
    SNI *sni = list;

    while (sni && sni->type != type)
        sni = sni->next;

    return sni;
}


/** Sets the status of a SNI object. */
static void TLSX_SNI_SetStatus(TLSX* extensions, byte type, byte status)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        sni->status = status;
}

/** Gets the status of a SNI object. */
byte TLSX_SNI_Status(TLSX* extensions, byte type)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        return sni->status;

    return 0;
}

#endif /* NO_WOLFSSL_SERVER */

/** Parses a buffer of SNI extensions. */
static int TLSX_SNI_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
#ifndef NO_WOLFSSL_SERVER
    word16 size = 0;
    word16 offset = 0;
    int cacheOnly = 0;
#endif

    TLSX *extension = TLSX_Find(ssl->extensions, TLSX_SERVER_NAME);

    if (!extension)
        extension = TLSX_Find(ssl->ctx->extensions, TLSX_SERVER_NAME);

    (void)isRequest;
    (void)input;

    if (!extension || !extension->data) {
#if defined(WOLFSSL_ALWAYS_KEEP_SNI) && !defined(NO_WOLFSSL_SERVER)
        /* This will keep SNI even though TLSX_UseSNI has not been called.
         * Enable it so that the received sni is available to functions
         * that use a custom callback when SNI is received */
        cacheOnly = 1;
        WOLFSSL_MSG("Forcing SSL object to store SNI parameter");
#else
        return isRequest ? 0             /* not using SNI.           */
                         : BUFFER_ERROR; /* unexpected SNI response. */
#endif
    }

    if (!isRequest)
        return length ? BUFFER_ERROR /* SNI response MUST be empty. */
                      : 0;           /* nothing else to do.         */

#ifndef NO_WOLFSSL_SERVER

    if (OPAQUE16_LEN > length)
        return BUFFER_ERROR;

    ato16(input, &size);
    offset += OPAQUE16_LEN;

    /* validating sni list length */
    if (length != OPAQUE16_LEN + size)
        return BUFFER_ERROR;

    for (size = 0; offset < length; offset += size) {
        SNI *sni = NULL;
        byte type = input[offset++];

        if (offset + OPAQUE16_LEN > length)
            return BUFFER_ERROR;

        ato16(input + offset, &size);
        offset += OPAQUE16_LEN;

        if (offset + size > length)
            return BUFFER_ERROR;

        if (!cacheOnly && !(sni = TLSX_SNI_Find((SNI*)extension->data, type)))
            continue; /* not using this type of SNI. */

        switch(type) {
            case WOLFSSL_SNI_HOST_NAME: {
                int matchStat;
                byte matched = cacheOnly ||
                            ((XSTRLEN(sni->data.host_name) == size)
                            && (XSTRNCMP(sni->data.host_name,
                                       (const char*)input + offset, size) == 0));

                if (matched || sni->options & WOLFSSL_SNI_ANSWER_ON_MISMATCH) {
                    int r = TLSX_UseSNI(&ssl->extensions,
                                         type, input + offset, size, ssl->heap);

                    if (r != SSL_SUCCESS)
                        return r; /* throws error. */

                    if(cacheOnly) {
                        WOLFSSL_MSG("Forcing storage of SNI, Fake match");
                        matchStat = WOLFSSL_SNI_FORCE_KEEP;
                    } else if(matched) {
                        WOLFSSL_MSG("SNI did match!");
                        matchStat = WOLFSSL_SNI_REAL_MATCH;
                    } else {
                        WOLFSSL_MSG("fake SNI match from ANSWER_ON_MISMATCH");
                        matchStat = WOLFSSL_SNI_FAKE_MATCH;
                    }

                    TLSX_SNI_SetStatus(ssl->extensions, type, matchStat);

                    if(!cacheOnly)
                        TLSX_SetResponse(ssl, TLSX_SERVER_NAME);

                } else if (!(sni->options & WOLFSSL_SNI_CONTINUE_ON_MISMATCH)) {
                    SendAlert(ssl, alert_fatal, unrecognized_name);

                    return UNKNOWN_SNI_HOST_NAME_E;
                }
                break;
            }
        }
    }

#endif

    return 0;
}

static int TLSX_SNI_VerifyParse(WOLFSSL* ssl,  byte isRequest)
{
    (void)ssl;

    if (isRequest) {
    #ifndef NO_WOLFSSL_SERVER
        TLSX* ctx_ext = TLSX_Find(ssl->ctx->extensions, TLSX_SERVER_NAME);
        TLSX* ssl_ext = TLSX_Find(ssl->extensions,      TLSX_SERVER_NAME);
        SNI* ctx_sni = ctx_ext ? (SNI*)ctx_ext->data : NULL;
        SNI* ssl_sni = ssl_ext ? (SNI*)ssl_ext->data : NULL;
        SNI* sni = NULL;

        for (; ctx_sni; ctx_sni = ctx_sni->next) {
            if (ctx_sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) {
                sni = TLSX_SNI_Find(ssl_sni, ctx_sni->type);

                if (sni) {
                    if (sni->status != WOLFSSL_SNI_NO_MATCH)
                        continue;

                    /* if ssl level overrides ctx level, it is ok. */
                    if ((sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) == 0)
                        continue;
                }

                SendAlert(ssl, alert_fatal, handshake_failure);
                return SNI_ABSENT_ERROR;
            }
        }

        for (; ssl_sni; ssl_sni = ssl_sni->next) {
            if (ssl_sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) {
                if (ssl_sni->status != WOLFSSL_SNI_NO_MATCH)
                    continue;

                SendAlert(ssl, alert_fatal, handshake_failure);
                return SNI_ABSENT_ERROR;
            }
        }
    #endif /* NO_WOLFSSL_SERVER */
    }

    return 0;
}

int TLSX_UseSNI(TLSX** extensions, byte type, const void* data, word16 size,
                                                                     void* heap)
{
    TLSX* extension = TLSX_Find(*extensions, TLSX_SERVER_NAME);
    SNI*  sni       = NULL;

    if (extensions == NULL || data == NULL)
        return BAD_FUNC_ARG;

    if ((sni = TLSX_SNI_New(type, data, size, heap)) == NULL)
        return MEMORY_E;

    if (!extension) {
        int ret = TLSX_Push(extensions, TLSX_SERVER_NAME, (void*)sni, heap);
        if (ret != 0) {
            TLSX_SNI_Free(sni, heap);
            return ret;
        }
    }
    else {
        /* push new SNI object to extension data. */
        sni->next = (SNI*)extension->data;
        extension->data = (void*)sni;

        /* remove duplicate SNI, there should be only one of each type. */
        do {
            if (sni->next && sni->next->type == type) {
                SNI *next = sni->next;

                sni->next = next->next;
                TLSX_SNI_Free(next, heap);

                /* there is no way to occur more than */
                /* two SNIs of the same type.         */
                break;
            }
        } while ((sni = sni->next));
    }

    return SSL_SUCCESS;
}

#ifndef NO_WOLFSSL_SERVER

/** Tells the SNI requested by the client. */
word16 TLSX_SNI_GetRequest(TLSX* extensions, byte type, void** data)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni && sni->status != WOLFSSL_SNI_NO_MATCH) {
        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                *data = sni->data.host_name;
                return XSTRLEN((char*)*data);
        }
    }

    return 0;
}

/** Sets the options for a SNI object. */
void TLSX_SNI_SetOptions(TLSX* extensions, byte type, byte options)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        sni->options = options;
}

/** Retrieves a SNI request from a client hello buffer. */
int TLSX_SNI_GetFromBuffer(const byte* clientHello, word32 helloSz,
                           byte type, byte* sni, word32* inOutSz)
{
    word32 offset = 0;
    word32 len32  = 0;
    word16 len16  = 0;

    if (helloSz < RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + CLIENT_HELLO_FIRST)
        return INCOMPLETE_DATA;

    /* TLS record header */
    if ((enum ContentType) clientHello[offset++] != handshake) {

        /* checking for SSLv2.0 client hello according to: */
        /* http://tools.ietf.org/html/rfc4346#appendix-E.1 */
        if ((enum HandShakeType) clientHello[++offset] == client_hello) {
            offset += ENUM_LEN + VERSION_SZ; /* skip version */

            ato16(clientHello + offset, &len16);
            offset += OPAQUE16_LEN;

            if (len16 % 3) /* cipher_spec_length must be multiple of 3 */
                return BUFFER_ERROR;

            ato16(clientHello + offset, &len16);
            /* Returning SNI_UNSUPPORTED do not increment offset here */

            if (len16 != 0) /* session_id_length must be 0 */
                return BUFFER_ERROR;

            return SNI_UNSUPPORTED;
        }

        return BUFFER_ERROR;
    }

    if (clientHello[offset++] != SSLv3_MAJOR)
        return BUFFER_ERROR;

    if (clientHello[offset++] < TLSv1_MINOR)
        return SNI_UNSUPPORTED;

    ato16(clientHello + offset, &len16);
    offset += OPAQUE16_LEN;

    if (offset + len16 > helloSz)
        return INCOMPLETE_DATA;

    /* Handshake header */
    if ((enum HandShakeType) clientHello[offset] != client_hello)
        return BUFFER_ERROR;

    c24to32(clientHello + offset + 1, &len32);
    offset += HANDSHAKE_HEADER_SZ;

    if (offset + len32 > helloSz)
        return BUFFER_ERROR;

    /* client hello */
    offset += VERSION_SZ + RAN_LEN; /* version, random */

    if (helloSz < offset + clientHello[offset])
        return BUFFER_ERROR;

    offset += ENUM_LEN + clientHello[offset]; /* skip session id */

    /* cypher suites */
    if (helloSz < offset + OPAQUE16_LEN)
        return BUFFER_ERROR;

    ato16(clientHello + offset, &len16);
    offset += OPAQUE16_LEN;

    if (helloSz < offset + len16)
        return BUFFER_ERROR;

    offset += len16; /* skip cypher suites */

    /* compression methods */
    if (helloSz < offset + 1)
        return BUFFER_ERROR;

    if (helloSz < offset + clientHello[offset])
        return BUFFER_ERROR;

    offset += ENUM_LEN + clientHello[offset]; /* skip compression methods */

    /* extensions */
    if (helloSz < offset + OPAQUE16_LEN)
        return 0; /* no extensions in client hello. */

    ato16(clientHello + offset, &len16);
    offset += OPAQUE16_LEN;

    if (helloSz < offset + len16)
        return BUFFER_ERROR;

    while (len16 >= OPAQUE16_LEN + OPAQUE16_LEN) {
        word16 extType;
        word16 extLen;

        ato16(clientHello + offset, &extType);
        offset += OPAQUE16_LEN;

        ato16(clientHello + offset, &extLen);
        offset += OPAQUE16_LEN;

        if (helloSz < offset + extLen)
            return BUFFER_ERROR;

        if (extType != TLSX_SERVER_NAME) {
            offset += extLen; /* skip extension */
        } else {
            word16 listLen;

            ato16(clientHello + offset, &listLen);
            offset += OPAQUE16_LEN;

            if (helloSz < offset + listLen)
                return BUFFER_ERROR;

            while (listLen > ENUM_LEN + OPAQUE16_LEN) {
                byte   sniType = clientHello[offset++];
                word16 sniLen;

                ato16(clientHello + offset, &sniLen);
                offset += OPAQUE16_LEN;

                if (helloSz < offset + sniLen)
                    return BUFFER_ERROR;

                if (sniType != type) {
                    offset  += sniLen;
                    listLen -= min(ENUM_LEN + OPAQUE16_LEN + sniLen, listLen);
                    continue;
                }

                *inOutSz = min(sniLen, *inOutSz);
                XMEMCPY(sni, clientHello + offset, *inOutSz);

                return SSL_SUCCESS;
            }
        }

        len16 -= min(2 * OPAQUE16_LEN + extLen, len16);
    }

    return len16 ? BUFFER_ERROR : 0;
}

#endif

#define SNI_FREE_ALL     TLSX_SNI_FreeAll
#define SNI_GET_SIZE     TLSX_SNI_GetSize
#define SNI_WRITE        TLSX_SNI_Write
#define SNI_PARSE        TLSX_SNI_Parse
#define SNI_VERIFY_PARSE TLSX_SNI_VerifyParse

#else

#define SNI_FREE_ALL(list, heap)
#define SNI_GET_SIZE(list)     0
#define SNI_WRITE(a, b)        0
#define SNI_PARSE(a, b, c, d)  0
#define SNI_VERIFY_PARSE(a, b) 0

#endif /* HAVE_SNI */

/******************************************************************************/
/* Max Fragment Length Negotiation                                            */
/******************************************************************************/

#ifdef HAVE_MAX_FRAGMENT

static word16 TLSX_MFL_Write(byte* data, byte* output)
{
    output[0] = data[0];

    return ENUM_LEN;
}

static int TLSX_MFL_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
    (void)isRequest;

    if (length != ENUM_LEN)
        return BUFFER_ERROR;

    switch (*input) {
        case WOLFSSL_MFL_2_9 : ssl->max_fragment =  512; break;
        case WOLFSSL_MFL_2_10: ssl->max_fragment = 1024; break;
        case WOLFSSL_MFL_2_11: ssl->max_fragment = 2048; break;
        case WOLFSSL_MFL_2_12: ssl->max_fragment = 4096; break;
        case WOLFSSL_MFL_2_13: ssl->max_fragment = 8192; break;

        default:
            SendAlert(ssl, alert_fatal, illegal_parameter);

            return UNKNOWN_MAX_FRAG_LEN_E;
    }

#ifndef NO_WOLFSSL_SERVER
    if (isRequest) {
        int r = TLSX_UseMaxFragment(&ssl->extensions, *input, ssl->heap);

        if (r != SSL_SUCCESS) return r; /* throw error */

        TLSX_SetResponse(ssl, TLSX_MAX_FRAGMENT_LENGTH);
    }
#endif

    return 0;
}

int TLSX_UseMaxFragment(TLSX** extensions, byte mfl, void* heap)
{
    byte* data = NULL;
    int   ret  = 0;

    if (extensions == NULL)
        return BAD_FUNC_ARG;

    if (mfl < WOLFSSL_MFL_2_9 || WOLFSSL_MFL_2_13 < mfl)
        return BAD_FUNC_ARG;

    if ((data = (byte*)XMALLOC(ENUM_LEN, heap, DYNAMIC_TYPE_TLSX)) == NULL)
        return MEMORY_E;

    data[0] = mfl;

    /* push new MFL extension. */
    if ((ret = TLSX_Push(extensions, TLSX_MAX_FRAGMENT_LENGTH, data, heap))
                                                                         != 0) {
        XFREE(data, heap, DYNAMIC_TYPE_TLSX);
        return ret;
    }

    return SSL_SUCCESS;
}


#define MFL_FREE_ALL(data, heap) XFREE(data, (heap), DYNAMIC_TYPE_TLSX)
#define MFL_GET_SIZE(data) ENUM_LEN
#define MFL_WRITE          TLSX_MFL_Write
#define MFL_PARSE          TLSX_MFL_Parse

#else

#define MFL_FREE_ALL(a, b)
#define MFL_GET_SIZE(a)       0
#define MFL_WRITE(a, b)       0
#define MFL_PARSE(a, b, c, d) 0

#endif /* HAVE_MAX_FRAGMENT */

/******************************************************************************/
/* Truncated HMAC                                                             */
/******************************************************************************/

#ifdef HAVE_TRUNCATED_HMAC

static int TLSX_THM_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
    (void)isRequest;

    if (length != 0 || input == NULL)
        return BUFFER_ERROR;

#ifndef NO_WOLFSSL_SERVER
    if (isRequest) {
        int r = TLSX_UseTruncatedHMAC(&ssl->extensions, ssl->heap);

        if (r != SSL_SUCCESS)
            return r; /* throw error */

        TLSX_SetResponse(ssl, TLSX_TRUNCATED_HMAC);
    }
#endif

    ssl->truncated_hmac = 1;

    return 0;
}

int TLSX_UseTruncatedHMAC(TLSX** extensions, void* heap)
{
    int ret = 0;

    if (extensions == NULL)
        return BAD_FUNC_ARG;

    if ((ret = TLSX_Push(extensions, TLSX_TRUNCATED_HMAC, NULL, heap)) != 0)
        return ret;

    return SSL_SUCCESS;
}

#define THM_PARSE TLSX_THM_Parse

#else

#define THM_PARSE(a, b, c, d) 0

#endif /* HAVE_TRUNCATED_HMAC */

/******************************************************************************/
/* Certificate Status Request                                                 */
/******************************************************************************/

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST

static void TLSX_CSR_Free(CertificateStatusRequest* csr, void* heap)
{
    switch (csr->status_type) {
        case WOLFSSL_CSR_OCSP:
            FreeOcspRequest(&csr->request.ocsp);
        break;
    }

    XFREE(csr, heap, DYNAMIC_TYPE_TLSX);
    (void)heap;
}

static word16 TLSX_CSR_GetSize(CertificateStatusRequest* csr, byte isRequest)
{
    word16 size = 0;

    /* shut up compiler warnings */
    (void) csr; (void) isRequest;

#ifndef NO_WOLFSSL_CLIENT
    if (isRequest) {
        switch (csr->status_type) {
            case WOLFSSL_CSR_OCSP:
                size += ENUM_LEN + 2 * OPAQUE16_LEN;

                if (csr->request.ocsp.nonceSz)
                    size += OCSP_NONCE_EXT_SZ;
            break;
        }
    }
#endif

    return size;
}

static word16 TLSX_CSR_Write(CertificateStatusRequest* csr, byte* output,
                                                                 byte isRequest)
{
    /* shut up compiler warnings */
    (void) csr; (void) output; (void) isRequest;

#ifndef NO_WOLFSSL_CLIENT
    if (isRequest) {
        word16 offset = 0;
        word16 length = 0;

        /* type */
        output[offset++] = csr->status_type;

        switch (csr->status_type) {
            case WOLFSSL_CSR_OCSP:
                /* responder id list */
                c16toa(0, output + offset);
                offset += OPAQUE16_LEN;

                /* request extensions */
                if (csr->request.ocsp.nonceSz)
                    length = EncodeOcspRequestExtensions(
                                                 &csr->request.ocsp,
                                                 output + offset + OPAQUE16_LEN,
                                                 OCSP_NONCE_EXT_SZ);

                c16toa(length, output + offset);
                offset += OPAQUE16_LEN + length;

            break;
        }

        return offset;
    }
#endif

    return 0;
}

static int TLSX_CSR_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
    int ret;

    /* shut up compiler warnings */
    (void) ssl; (void) input;

    if (!isRequest) {
#ifndef NO_WOLFSSL_CLIENT
        TLSX* extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST);
        CertificateStatusRequest* csr = extension ? extension->data : NULL;

        if (!csr) {
            /* look at context level */

            extension = TLSX_Find(ssl->ctx->extensions, TLSX_STATUS_REQUEST);
            csr = extension ? extension->data : NULL;

            if (!csr)
                return BUFFER_ERROR; /* unexpected extension */

            /* enable extension at ssl level */
            ret = TLSX_UseCertificateStatusRequest(&ssl->extensions,
                                     csr->status_type, csr->options, ssl->heap);
            if (ret != SSL_SUCCESS)
                return ret;

            switch (csr->status_type) {
                case WOLFSSL_CSR_OCSP:
                    /* propagate nonce */
                    if (csr->request.ocsp.nonceSz) {
                        OcspRequest* request =
                                           TLSX_CSR_GetRequest(ssl->extensions);

                        if (request) {
                            XMEMCPY(request->nonce, csr->request.ocsp.nonce,
                                                    csr->request.ocsp.nonceSz);
                            request->nonceSz = csr->request.ocsp.nonceSz;
                        }
                    }
                break;
            }
        }

        ssl->status_request = 1;

        return length ? BUFFER_ERROR : 0; /* extension_data MUST be empty. */
#endif
    }
    else {
#ifndef NO_WOLFSSL_SERVER
        byte   status_type;
        word16 offset = 0;
        word16 size = 0;

        if (length < ENUM_LEN)
            return BUFFER_ERROR;

        status_type = input[offset++];

        switch (status_type) {
            case WOLFSSL_CSR_OCSP: {

                /* skip responder_id_list */
                if (length - offset < OPAQUE16_LEN)
                    return BUFFER_ERROR;

                ato16(input + offset, &size);
                offset += OPAQUE16_LEN + size;

                /* skip request_extensions */
                if (length - offset < OPAQUE16_LEN)
                    return BUFFER_ERROR;

                ato16(input + offset, &size);
                offset += OPAQUE16_LEN + size;

                if (offset > length)
                    return BUFFER_ERROR;

                /* is able to send OCSP response? */
                if (ssl->ctx->cm == NULL || !ssl->ctx->cm->ocspStaplingEnabled)
                    return 0;
            }
            break;
        }

        /* if using status_request and already sending it, skip this one */
        #ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
        if (ssl->status_request_v2)
            return 0;
        #endif

        /* accept the first good status_type and return */
        ret = TLSX_UseCertificateStatusRequest(&ssl->extensions, status_type,
                                                                  0, ssl->heap);
        if (ret != SSL_SUCCESS)
            return ret; /* throw error */

        TLSX_SetResponse(ssl, TLSX_STATUS_REQUEST);
        ssl->status_request = status_type;

#endif
    }

    return 0;
}

int TLSX_CSR_InitRequest(TLSX* extensions, DecodedCert* cert, void* heap)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_STATUS_REQUEST);
    CertificateStatusRequest* csr = extension ? extension->data : NULL;
    int ret = 0;

    if (csr) {
        switch (csr->status_type) {
            case WOLFSSL_CSR_OCSP: {
                byte nonce[MAX_OCSP_NONCE_SZ];
                int  nonceSz = csr->request.ocsp.nonceSz;

                /* preserve nonce */
                XMEMCPY(nonce, csr->request.ocsp.nonce, nonceSz);

                if ((ret = InitOcspRequest(&csr->request.ocsp, cert, 0, heap))
                                                                           != 0)
                    return ret;

                /* restore nonce */
                XMEMCPY(csr->request.ocsp.nonce, nonce, nonceSz);
                csr->request.ocsp.nonceSz = nonceSz;
            }
            break;
        }
    }

    return ret;
}

void* TLSX_CSR_GetRequest(TLSX* extensions)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_STATUS_REQUEST);
    CertificateStatusRequest* csr = extension ? extension->data : NULL;

    if (csr) {
        switch (csr->status_type) {
            case WOLFSSL_CSR_OCSP:
                return &csr->request.ocsp;
            break;
        }
    }

    return NULL;
}

int TLSX_CSR_ForceRequest(WOLFSSL* ssl)
{
    TLSX* extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST);
    CertificateStatusRequest* csr = extension ? extension->data : NULL;

    if (csr) {
        switch (csr->status_type) {
            case WOLFSSL_CSR_OCSP:
                if (ssl->ctx->cm->ocspEnabled)
                    return CheckOcspRequest(ssl->ctx->cm->ocsp,
                                                      &csr->request.ocsp, NULL);
                else
                    return OCSP_LOOKUP_FAIL;
        }
    }

    return 0;
}

int TLSX_UseCertificateStatusRequest(TLSX** extensions, byte status_type,
                                                       byte options, void* heap)
{
    CertificateStatusRequest* csr = NULL;
    int ret = 0;

    if (!extensions || status_type != WOLFSSL_CSR_OCSP)
        return BAD_FUNC_ARG;

    csr = (CertificateStatusRequest*)
             XMALLOC(sizeof(CertificateStatusRequest), heap, DYNAMIC_TYPE_TLSX);
    if (!csr)
        return MEMORY_E;

    ForceZero(csr, sizeof(CertificateStatusRequest));

    csr->status_type = status_type;
    csr->options     = options;

    switch (csr->status_type) {
        case WOLFSSL_CSR_OCSP:
            if (options & WOLFSSL_CSR_OCSP_USE_NONCE) {
                WC_RNG rng;

#ifdef WOLFSSL_STATIC_MEMORY
                if (wc_InitRng_ex(&rng, heap) == 0) {
#else
                if (wc_InitRng(&rng) == 0) {
#endif
                    if (wc_RNG_GenerateBlock(&rng, csr->request.ocsp.nonce,
                                                        MAX_OCSP_NONCE_SZ) == 0)
                        csr->request.ocsp.nonceSz = MAX_OCSP_NONCE_SZ;

                    wc_FreeRng(&rng);
                }
            }
        break;
    }

    if ((ret = TLSX_Push(extensions, TLSX_STATUS_REQUEST, csr, heap)) != 0) {
        XFREE(csr, heap, DYNAMIC_TYPE_TLSX);
        return ret;
    }

    return SSL_SUCCESS;
}

#define CSR_FREE_ALL TLSX_CSR_Free
#define CSR_GET_SIZE TLSX_CSR_GetSize
#define CSR_WRITE    TLSX_CSR_Write
#define CSR_PARSE    TLSX_CSR_Parse

#else

#define CSR_FREE_ALL(data, heap)
#define CSR_GET_SIZE(a, b)    0
#define CSR_WRITE(a, b, c)    0
#define CSR_PARSE(a, b, c, d) 0

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST */

/******************************************************************************/
/* Certificate Status Request v2                                              */
/******************************************************************************/

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2

static void TLSX_CSR2_FreeAll(CertificateStatusRequestItemV2* csr2, void* heap)
{
    CertificateStatusRequestItemV2* next;

    for (; csr2; csr2 = next) {
        next = csr2->next;

        switch (csr2->status_type) {
            case WOLFSSL_CSR2_OCSP:
            case WOLFSSL_CSR2_OCSP_MULTI:
                while(csr2->requests--)
                    FreeOcspRequest(&csr2->request.ocsp[csr2->requests]);
            break;
        }

        XFREE(csr2, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

static word16 TLSX_CSR2_GetSize(CertificateStatusRequestItemV2* csr2,
                                                                 byte isRequest)
{
    word16 size = 0;

    /* shut up compiler warnings */
    (void) csr2; (void) isRequest;

#ifndef NO_WOLFSSL_CLIENT
    if (isRequest) {
        CertificateStatusRequestItemV2* next;

        for (size = OPAQUE16_LEN; csr2; csr2 = next) {
            next = csr2->next;

            switch (csr2->status_type) {
                case WOLFSSL_CSR2_OCSP:
                case WOLFSSL_CSR2_OCSP_MULTI:
                    size += ENUM_LEN + 3 * OPAQUE16_LEN;

                    if (csr2->request.ocsp[0].nonceSz)
                        size += OCSP_NONCE_EXT_SZ;
                break;
            }
        }
    }
#endif

    return size;
}

static word16 TLSX_CSR2_Write(CertificateStatusRequestItemV2* csr2,
                                                   byte* output, byte isRequest)
{
    /* shut up compiler warnings */
    (void) csr2; (void) output; (void) isRequest;

#ifndef NO_WOLFSSL_CLIENT
    if (isRequest) {
        word16 offset;
        word16 length;

        for (offset = OPAQUE16_LEN; csr2 != NULL; csr2 = csr2->next) {
            /* status_type */
            output[offset++] = csr2->status_type;

            /* request */
            switch (csr2->status_type) {
                case WOLFSSL_CSR2_OCSP:
                case WOLFSSL_CSR2_OCSP_MULTI:
                    /* request_length */
                    length = 2 * OPAQUE16_LEN;

                    if (csr2->request.ocsp[0].nonceSz)
                        length += OCSP_NONCE_EXT_SZ;

                    c16toa(length, output + offset);
                    offset += OPAQUE16_LEN;

                    /* responder id list */
                    c16toa(0, output + offset);
                    offset += OPAQUE16_LEN;

                    /* request extensions */
                    length = 0;

                    if (csr2->request.ocsp[0].nonceSz)
                        length = EncodeOcspRequestExtensions(
                                                 &csr2->request.ocsp[0],
                                                 output + offset + OPAQUE16_LEN,
                                                 OCSP_NONCE_EXT_SZ);

                    c16toa(length, output + offset);
                    offset += OPAQUE16_LEN + length;
                break;
            }
        }

        /* list size */
        c16toa(offset - OPAQUE16_LEN, output);

        return offset;
    }
#endif

    return 0;
}

static int TLSX_CSR2_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
    int ret;

    /* shut up compiler warnings */
    (void) ssl; (void) input;

    if (!isRequest) {
#ifndef NO_WOLFSSL_CLIENT
        TLSX* extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST_V2);
        CertificateStatusRequestItemV2* csr2 = extension ? extension->data
                                                         : NULL;

        if (!csr2) {
            /* look at context level */

            extension = TLSX_Find(ssl->ctx->extensions, TLSX_STATUS_REQUEST_V2);
            csr2 = extension ? extension->data : NULL;

            if (!csr2)
                return BUFFER_ERROR; /* unexpected extension */

            /* enable extension at ssl level */
            for (; csr2; csr2 = csr2->next) {
                ret = TLSX_UseCertificateStatusRequestV2(&ssl->extensions,
                                   csr2->status_type, csr2->options, ssl->heap);
                if (ret != SSL_SUCCESS)
                    return ret;

                switch (csr2->status_type) {
                    case WOLFSSL_CSR2_OCSP:
                        /* followed by */
                    case WOLFSSL_CSR2_OCSP_MULTI:
                        /* propagate nonce */
                        if (csr2->request.ocsp[0].nonceSz) {
                            OcspRequest* request =
                                        TLSX_CSR2_GetRequest(ssl->extensions,
                                                          csr2->status_type, 0);

                            if (request) {
                                XMEMCPY(request->nonce,
                                        csr2->request.ocsp[0].nonce,
                                        csr2->request.ocsp[0].nonceSz);

                                request->nonceSz =
                                                  csr2->request.ocsp[0].nonceSz;
                            }
                        }
                    break;
                }
            }

        }

        ssl->status_request_v2 = 1;

        return length ? BUFFER_ERROR : 0; /* extension_data MUST be empty. */
#endif
    }
    else {
#ifndef NO_WOLFSSL_SERVER
        byte   status_type;
        word16 request_length;
        word16 offset = 0;
        word16 size = 0;

        /* list size */
        ato16(input + offset, &request_length);
        offset += OPAQUE16_LEN;

        if (length - OPAQUE16_LEN != request_length)
            return BUFFER_ERROR;

        while (length > offset) {
            if (length - offset < ENUM_LEN + OPAQUE16_LEN)
                return BUFFER_ERROR;

            status_type = input[offset++];

            ato16(input + offset, &request_length);
            offset += OPAQUE16_LEN;

            if (length - offset < request_length)
                return BUFFER_ERROR;

            switch (status_type) {
                case WOLFSSL_CSR2_OCSP:
                case WOLFSSL_CSR2_OCSP_MULTI:
                    /* skip responder_id_list */
                    if (length - offset < OPAQUE16_LEN)
                        return BUFFER_ERROR;

                    ato16(input + offset, &size);
                    offset += OPAQUE16_LEN + size;

                    /* skip request_extensions */
                    if (length - offset < OPAQUE16_LEN)
                        return BUFFER_ERROR;

                    ato16(input + offset, &size);
                    offset += OPAQUE16_LEN + size;

                    if (offset > length)
                        return BUFFER_ERROR;

                    /* is able to send OCSP response? */
                    if (ssl->ctx->cm == NULL
                    || !ssl->ctx->cm->ocspStaplingEnabled)
                        continue;
                break;

                default:
                    /* unknown status type, skipping! */
                    offset += request_length;
                    continue;
            }

            /* if using status_request and already sending it, skip this one */
            #ifdef HAVE_CERTIFICATE_STATUS_REQUEST
            if (ssl->status_request)
                return 0;
            #endif

            /* accept the first good status_type and return */
            ret = TLSX_UseCertificateStatusRequestV2(&ssl->extensions,
                                                     status_type, 0, ssl->heap);
            if (ret != SSL_SUCCESS)
                return ret; /* throw error */

            TLSX_SetResponse(ssl, TLSX_STATUS_REQUEST_V2);
            ssl->status_request_v2 = status_type;

            return 0;
        }
#endif
    }

    return 0;
}

int TLSX_CSR2_InitRequests(TLSX* extensions, DecodedCert* cert, byte isPeer,
                                                                     void* heap)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_STATUS_REQUEST_V2);
    CertificateStatusRequestItemV2* csr2 = extension ? extension->data : NULL;
    int ret = 0;

    for (; csr2; csr2 = csr2->next) {
        switch (csr2->status_type) {
            case WOLFSSL_CSR2_OCSP:
                if (!isPeer || csr2->requests != 0)
                    break;

                /* followed by */

            case WOLFSSL_CSR2_OCSP_MULTI: {
                if (csr2->requests < 1 + MAX_CHAIN_DEPTH) {
                    byte nonce[MAX_OCSP_NONCE_SZ];
                    int  nonceSz = csr2->request.ocsp[0].nonceSz;

                    /* preserve nonce, replicating nonce of ocsp[0] */
                    XMEMCPY(nonce, csr2->request.ocsp[0].nonce, nonceSz);

                    if ((ret = InitOcspRequest(
                                      &csr2->request.ocsp[csr2->requests], cert,
                                                                 0, heap)) != 0)
                        return ret;

                    /* restore nonce */
                    XMEMCPY(csr2->request.ocsp[csr2->requests].nonce,
                                                                nonce, nonceSz);
                    csr2->request.ocsp[csr2->requests].nonceSz = nonceSz;
                    csr2->requests++;
                }
            }
            break;
        }
    }

    return ret;
}

void* TLSX_CSR2_GetRequest(TLSX* extensions, byte status_type, byte index)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_STATUS_REQUEST_V2);
    CertificateStatusRequestItemV2* csr2 = extension ? extension->data : NULL;

    for (; csr2; csr2 = csr2->next) {
        if (csr2->status_type == status_type) {
            switch (csr2->status_type) {
                case WOLFSSL_CSR2_OCSP:
                    /* followed by */

                case WOLFSSL_CSR2_OCSP_MULTI:
                    /* requests are initialized in the reverse order */
                    return index < csr2->requests
                         ? &csr2->request.ocsp[csr2->requests - index - 1]
                         : NULL;
                break;
            }
        }
    }

    return NULL;
}

int TLSX_CSR2_ForceRequest(WOLFSSL* ssl)
{
    TLSX* extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST_V2);
    CertificateStatusRequestItemV2* csr2 = extension ? extension->data : NULL;

    /* forces only the first one */
    if (csr2) {
        switch (csr2->status_type) {
            case WOLFSSL_CSR2_OCSP:
                /* followed by */

            case WOLFSSL_CSR2_OCSP_MULTI:
                if (ssl->ctx->cm->ocspEnabled)
                    return CheckOcspRequest(ssl->ctx->cm->ocsp,
                                                  &csr2->request.ocsp[0], NULL);
                else
                    return OCSP_LOOKUP_FAIL;
        }
    }

    return 0;
}

int TLSX_UseCertificateStatusRequestV2(TLSX** extensions, byte status_type,
                                                       byte options, void* heap)
{
    TLSX* extension = NULL;
    CertificateStatusRequestItemV2* csr2 = NULL;
    int ret = 0;

    if (!extensions)
        return BAD_FUNC_ARG;

    if (status_type != WOLFSSL_CSR2_OCSP
    &&  status_type != WOLFSSL_CSR2_OCSP_MULTI)
        return BAD_FUNC_ARG;

    csr2 = (CertificateStatusRequestItemV2*)
       XMALLOC(sizeof(CertificateStatusRequestItemV2), heap, DYNAMIC_TYPE_TLSX);
    if (!csr2)
        return MEMORY_E;

    ForceZero(csr2, sizeof(CertificateStatusRequestItemV2));

    csr2->status_type = status_type;
    csr2->options     = options;
    csr2->next        = NULL;

    switch (csr2->status_type) {
        case WOLFSSL_CSR2_OCSP:
        case WOLFSSL_CSR2_OCSP_MULTI:
            if (options & WOLFSSL_CSR2_OCSP_USE_NONCE) {
                WC_RNG rng;

#ifdef WOLFSSL_STATIC_MEMORY
                if (wc_InitRng_ex(&rng, heap) == 0) {
#else
                if (wc_InitRng(&rng) == 0) {
#endif
                    if (wc_RNG_GenerateBlock(&rng, csr2->request.ocsp[0].nonce,
                                                        MAX_OCSP_NONCE_SZ) == 0)
                        csr2->request.ocsp[0].nonceSz = MAX_OCSP_NONCE_SZ;

                    wc_FreeRng(&rng);
                }
            }
        break;
    }

    /* append new item */
    if ((extension = TLSX_Find(*extensions, TLSX_STATUS_REQUEST_V2))) {
        CertificateStatusRequestItemV2* last =
                               (CertificateStatusRequestItemV2*)extension->data;

        for (; last->next; last = last->next);

        last->next = csr2;
    }
    else if ((ret = TLSX_Push(extensions, TLSX_STATUS_REQUEST_V2, csr2,heap))) {
        XFREE(csr2, heap, DYNAMIC_TYPE_TLSX);
        return ret;
    }

    return SSL_SUCCESS;
}

#define CSR2_FREE_ALL TLSX_CSR2_FreeAll
#define CSR2_GET_SIZE TLSX_CSR2_GetSize
#define CSR2_WRITE    TLSX_CSR2_Write
#define CSR2_PARSE    TLSX_CSR2_Parse

#else

#define CSR2_FREE_ALL(data, heap)
#define CSR2_GET_SIZE(a, b)    0
#define CSR2_WRITE(a, b, c)    0
#define CSR2_PARSE(a, b, c, d) 0

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

/******************************************************************************/
/* Supported Elliptic Curves                                                  */
/******************************************************************************/

#ifdef HAVE_SUPPORTED_CURVES

#ifndef HAVE_ECC
#error Elliptic Curves Extension requires Elliptic Curve Cryptography. \
       Use --enable-ecc in the configure script or define HAVE_ECC.
#endif

static void TLSX_EllipticCurve_FreeAll(EllipticCurve* list, void* heap)
{
    EllipticCurve* curve;

    while ((curve = list)) {
        list = curve->next;
        XFREE(curve, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

static int TLSX_EllipticCurve_Append(EllipticCurve** list, word16 name,
                                                                     void* heap)
{
    EllipticCurve* curve = NULL;

    if (list == NULL)
        return BAD_FUNC_ARG;

    curve = (EllipticCurve*)XMALLOC(sizeof(EllipticCurve), heap,
                                                             DYNAMIC_TYPE_TLSX);
    if (curve == NULL)
        return MEMORY_E;

    curve->name = name;
    curve->next = *list;

    *list = curve;

    return 0;
}

#ifndef NO_WOLFSSL_CLIENT

static void TLSX_EllipticCurve_ValidateRequest(WOLFSSL* ssl, byte* semaphore)
{
    int i;

    for (i = 0; i < ssl->suites->suiteSz; i+= 2)
        if (ssl->suites->suites[i] == ECC_BYTE ||
                                          ssl->suites->suites[i] == CHACHA_BYTE)
            return;

    /* turns semaphore on to avoid sending this extension. */
    TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_SUPPORTED_GROUPS));
}

static word16 TLSX_EllipticCurve_GetSize(EllipticCurve* list)
{
    EllipticCurve* curve;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((curve = list)) {
        list = curve->next;
        length += OPAQUE16_LEN; /* curve length */
    }

    return length;
}

static word16 TLSX_EllipticCurve_WriteR(EllipticCurve* curve, byte* output);
static word16 TLSX_EllipticCurve_WriteR(EllipticCurve* curve, byte* output)
{
    word16 offset = 0;

    if (!curve)
        return offset;

    offset = TLSX_EllipticCurve_WriteR(curve->next, output);
    c16toa(curve->name, output + offset);

    return OPAQUE16_LEN + offset;
}

static word16 TLSX_EllipticCurve_Write(EllipticCurve* list, byte* output)
{
    word16 length = TLSX_EllipticCurve_WriteR(list, output + OPAQUE16_LEN);

    c16toa(length, output); /* writing list length */

    return OPAQUE16_LEN + length;
}

#endif /* NO_WOLFSSL_CLIENT */
#ifndef NO_WOLFSSL_SERVER

static int TLSX_EllipticCurve_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
    word16 offset;
    word16 name;
    int r;

    (void) isRequest; /* shut up compiler! */

    if (OPAQUE16_LEN > length || length % OPAQUE16_LEN)
        return BUFFER_ERROR;

    ato16(input, &offset);

    /* validating curve list length */
    if (length != OPAQUE16_LEN + offset)
        return BUFFER_ERROR;

    while (offset) {
        ato16(input + offset, &name);
        offset -= OPAQUE16_LEN;

        r = TLSX_UseSupportedCurve(&ssl->extensions, name, ssl->heap);

        if (r != SSL_SUCCESS) return r; /* throw error */
    }

    return 0;
}

int TLSX_ValidateEllipticCurves(WOLFSSL* ssl, byte first, byte second) {
    TLSX*          extension = (first == ECC_BYTE || first == CHACHA_BYTE)
                             ? TLSX_Find(ssl->extensions, TLSX_SUPPORTED_GROUPS)
                             : NULL;
    EllipticCurve* curve     = NULL;
    word32         oid       = 0;
    word16         octets    = 0; /* according to 'ecc_set_type ecc_sets[];' */
    int            sig       = 0; /* validate signature */
    int            key       = 0; /* validate key       */

    (void)oid;
    (void)octets;

    if (!extension)
        return 1; /* no suite restriction */

    for (curve = (EllipticCurve*)extension->data;
         curve && !(sig && key);
         curve = curve->next) {

        /* find supported curve */
        switch (curve->name) {
    #if defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP160R1: oid = ECC_SECP160R1_OID; octets = 20; break;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_SECPR2
            case WOLFSSL_ECC_SECP160R2: oid = ECC_SECP160R2_OID; octets = 20; break;
        #endif /* HAVE_ECC_SECPR2 */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP160K1: oid = ECC_SECP160K1_OID; octets = 20; break;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP192R1: oid = ECC_SECP192R1_OID; octets = 24; break;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP192K1: oid = ECC_SECP192K1_OID; octets = 24; break;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP224R1: oid = ECC_SECP224R1_OID; octets = 28; break;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP224K1: oid = ECC_SECP224K1_OID; octets = 28; break;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if !defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP256R1: oid = ECC_SECP256R1_OID; octets = 32; break;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP256K1: oid = ECC_SECP256K1_OID; octets = 32; break;
        #endif /* HAVE_ECC_KOBLITZ */
        #ifdef HAVE_ECC_BRAINPOOL
            case WOLFSSL_ECC_BRAINPOOLP256R1: oid = ECC_BRAINPOOLP256R1_OID; octets = 32; break;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP384R1: oid = ECC_SECP384R1_OID; octets = 48; break;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_BRAINPOOL
            case WOLFSSL_ECC_BRAINPOOLP384R1: oid = ECC_BRAINPOOLP384R1_OID; octets = 48; break;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)
        #ifdef HAVE_ECC_BRAINPOOL
            case WOLFSSL_ECC_BRAINPOOLP512R1: oid = ECC_BRAINPOOLP512R1_OID; octets = 64; break;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP521R1: oid = ECC_SECP521R1_OID; octets = 66; break;
        #endif /* !NO_ECC_SECP */
    #endif
            default: continue; /* unsupported curve */
        }

        if (first == ECC_BYTE) {
        switch (second) {
            /* ECDHE_ECDSA */
            case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
            case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
            case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
            case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
            case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
            case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
            case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
                sig |= ssl->pkCurveOID == oid;
                key |= ssl->eccTempKeySz == octets;
            break;

#ifdef WOLFSSL_STATIC_DH
            /* ECDH_ECDSA */
            case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
            case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
            case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
            case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
            case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
            case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
            case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
            case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
                sig |= ssl->pkCurveOID == oid;
                key |= ssl->pkCurveOID == oid;
            break;
#endif /* WOLFSSL_STATIC_DH */
#ifndef NO_RSA
            /* ECDHE_RSA */
            case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
            case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            case TLS_ECDHE_RSA_WITH_RC4_128_SHA:
            case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
            case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                sig = 1;
                key |= ssl->eccTempKeySz == octets;
            break;

#ifdef WOLFSSL_STATIC_DH
            /* ECDH_RSA */
            case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
            case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
            case TLS_ECDH_RSA_WITH_RC4_128_SHA:
            case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
            case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
            case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
            case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
            case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
                sig = 1;
                key |= ssl->pkCurveOID == oid;
            break;
#endif /* WOLFSSL_STATIC_DH */
#endif
            default:
                sig = 1;
                key = 1;
            break;
        }
        }

        /* ChaCha20-Poly1305 ECC cipher suites */
        if (first == CHACHA_BYTE) {
        switch (second) {
            /* ECDHE_ECDSA */
            case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :
            case TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                sig |= ssl->pkCurveOID == oid;
                key |= ssl->eccTempKeySz == octets;
            break;
#ifndef NO_RSA
            /* ECDHE_RSA */
            case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
            case TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                sig = 1;
                key |= ssl->eccTempKeySz == octets;
            break;
#endif
            default:
                sig = 1;
                key = 1;
            break;
        }
        }
    }

    return sig && key;
}

#endif /* NO_WOLFSSL_SERVER */

int TLSX_UseSupportedCurve(TLSX** extensions, word16 name, void* heap)
{
    TLSX*          extension = TLSX_Find(*extensions, TLSX_SUPPORTED_GROUPS);
    EllipticCurve* curve     = NULL;
    int            ret       = 0;

    if (extensions == NULL)
        return BAD_FUNC_ARG;

    if ((ret = TLSX_EllipticCurve_Append(&curve, name, heap)) != 0)
        return ret;

    if (!extension) {
        if ((ret = TLSX_Push(extensions, TLSX_SUPPORTED_GROUPS, curve, heap))
                                                                         != 0) {
            XFREE(curve, heap, DYNAMIC_TYPE_TLSX);
            return ret;
        }
    }
    else {
        /* push new EllipticCurve object to extension data. */
        curve->next = (EllipticCurve*)extension->data;
        extension->data = (void*)curve;

        /* look for another curve of the same name to remove (replacement) */
        do {
            if (curve->next && curve->next->name == name) {
                EllipticCurve *next = curve->next;

                curve->next = next->next;
                XFREE(next, heap, DYNAMIC_TYPE_TLSX);

                break;
            }
        } while ((curve = curve->next));
    }

    return SSL_SUCCESS;
}

#define EC_FREE_ALL         TLSX_EllipticCurve_FreeAll
#define EC_VALIDATE_REQUEST TLSX_EllipticCurve_ValidateRequest

#ifndef NO_WOLFSSL_CLIENT
#define EC_GET_SIZE TLSX_EllipticCurve_GetSize
#define EC_WRITE    TLSX_EllipticCurve_Write
#else
#define EC_GET_SIZE(list)         0
#define EC_WRITE(a, b)            0
#endif

#ifndef NO_WOLFSSL_SERVER
#define EC_PARSE TLSX_EllipticCurve_Parse
#else
#define EC_PARSE(a, b, c, d)      0
#endif

#else

#define EC_FREE_ALL(list, heap)
#define EC_GET_SIZE(list)         0
#define EC_WRITE(a, b)            0
#define EC_PARSE(a, b, c, d)      0
#define EC_VALIDATE_REQUEST(a, b)

#endif /* HAVE_SUPPORTED_CURVES */

/******************************************************************************/
/* Renegotiation Indication                                                   */
/******************************************************************************/

#ifdef HAVE_SECURE_RENEGOTIATION

static byte TLSX_SecureRenegotiation_GetSize(SecureRenegotiation* data,
                                                                  int isRequest)
{
    byte length = OPAQUE8_LEN; /* empty info length */

    if (data->enabled) {
        /* client sends client_verify_data only */
        length += TLS_FINISHED_SZ;

        /* server also sends server_verify_data */
        if (!isRequest)
            length += TLS_FINISHED_SZ;
    }

    return length;
}

static word16 TLSX_SecureRenegotiation_Write(SecureRenegotiation* data,
                                                    byte* output, int isRequest)
{
    word16 offset = OPAQUE8_LEN; /* RenegotiationInfo length */

    if (data->enabled) {
        /* client sends client_verify_data only */
        XMEMCPY(output + offset, data->client_verify_data, TLS_FINISHED_SZ);
        offset += TLS_FINISHED_SZ;

        /* server also sends server_verify_data */
        if (!isRequest) {
            XMEMCPY(output + offset, data->server_verify_data, TLS_FINISHED_SZ);
            offset += TLS_FINISHED_SZ;
        }
    }

    output[0] = offset - 1;  /* info length - self */

    return offset;
}

static int TLSX_SecureRenegotiation_Parse(WOLFSSL* ssl, byte* input,
                                                  word16 length, byte isRequest)
{
    int ret = SECURE_RENEGOTIATION_E;

    if (length >= OPAQUE8_LEN) {
        if (ssl->secure_renegotiation == NULL) {
        #ifndef NO_WOLFSSL_SERVER
            if (isRequest && *input == 0) {
                ret = 0;  /* don't reply, user didn't enable */
            }
        #endif
        }
        else if (isRequest) {
        #ifndef NO_WOLFSSL_SERVER
            if (*input == TLS_FINISHED_SZ) {
                /* TODO compare client_verify_data */
                ret = 0;
            }
        #endif
        }
        else {
        #ifndef NO_WOLFSSL_CLIENT
            if (!ssl->secure_renegotiation->enabled) {
                if (*input == 0) {
                    ssl->secure_renegotiation->enabled = 1;
                    ret = 0;
                }
            }
            else if (*input == 2 * TLS_FINISHED_SZ) {
                /* TODO compare client_verify_data and server_verify_data */
                ret = 0;
            }
        #endif
        }
    }

    if (ret != 0) {
        /* TODO: turn on fatal error at ssl level too */
        SendAlert(ssl, alert_fatal, handshake_failure);
    }

    return ret;
}

int TLSX_UseSecureRenegotiation(TLSX** extensions, void* heap)
{
    int ret = 0;
    SecureRenegotiation* data = NULL;

    data = (SecureRenegotiation*)XMALLOC(sizeof(SecureRenegotiation), heap,
                                                             DYNAMIC_TYPE_TLSX);
    if (data == NULL)
        return MEMORY_E;

    XMEMSET(data, 0, sizeof(SecureRenegotiation));

    ret = TLSX_Push(extensions, TLSX_RENEGOTIATION_INFO, data, heap);
    if (ret != 0) {
        XFREE(data, heap, DYNAMIC_TYPE_TLSX);
        return ret;
    }

    return SSL_SUCCESS;
}


#define SCR_FREE_ALL(data, heap) XFREE(data, (heap), DYNAMIC_TYPE_TLSX)
#define SCR_GET_SIZE       TLSX_SecureRenegotiation_GetSize
#define SCR_WRITE          TLSX_SecureRenegotiation_Write
#define SCR_PARSE          TLSX_SecureRenegotiation_Parse

#else

#define SCR_FREE_ALL(a, heap)
#define SCR_GET_SIZE(a, b)    0
#define SCR_WRITE(a, b, c)    0
#define SCR_PARSE(a, b, c, d) 0

#endif /* HAVE_SECURE_RENEGOTIATION */

/******************************************************************************/
/* Session Tickets                                                            */
/******************************************************************************/

#ifdef HAVE_SESSION_TICKET

static void TLSX_SessionTicket_ValidateRequest(WOLFSSL* ssl)
{
    TLSX*          extension = TLSX_Find(ssl->extensions, TLSX_SESSION_TICKET);
    SessionTicket* ticket    = extension ? extension->data : NULL;

    if (ticket) {
        /* TODO validate ticket timeout here! */
        if (ticket->lifetime == 0xfffffff) {
            /* send empty ticket on timeout */
            TLSX_UseSessionTicket(&ssl->extensions, NULL, ssl->heap);
        }
    }
}


static word16 TLSX_SessionTicket_GetSize(SessionTicket* ticket, int isRequest)
{
    (void)isRequest;
    return ticket ? ticket->size : 0;
}

static word16 TLSX_SessionTicket_Write(SessionTicket* ticket, byte* output,
                                                                  int isRequest)
{
    word16 offset = 0; /* empty ticket */

    if (isRequest && ticket) {
        XMEMCPY(output + offset, ticket->data, ticket->size);
        offset += ticket->size;
    }

    return offset;
}


static int TLSX_SessionTicket_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
    int ret = 0;

    (void) input; /* avoid unused parameter if NO_WOLFSSL_SERVER defined */

    if (!isRequest) {
        /* client side */
        if (length != 0)
            return BUFFER_ERROR;

        ssl->expect_session_ticket = 1;
    }
#ifndef NO_WOLFSSL_SERVER
    else {
        /* server side */
        if (ssl->ctx->ticketEncCb == NULL) {
            WOLFSSL_MSG("Client sent session ticket, server has no callback");
            return 0;
        }

        if (length == 0) {
            /* blank ticket */
            ret = TLSX_UseSessionTicket(&ssl->extensions, NULL, ssl->heap);
            if (ret == SSL_SUCCESS) {
                ret = 0;
                TLSX_SetResponse(ssl, TLSX_SESSION_TICKET);  /* send blank ticket */
                ssl->options.createTicket = 1;  /* will send ticket msg */
                ssl->options.useTicket    = 1;
                ssl->options.resuming     = 0;  /* no standard resumption */
                ssl->arrays->sessionIDSz  = 0;  /* no echo on blank ticket */
            }
        } else {
            /* got actual ticket from client */
            ret = DoClientTicket(ssl, input, length);
            if (ret == WOLFSSL_TICKET_RET_OK) {    /* use ticket to resume */
                WOLFSSL_MSG("Using exisitng client ticket");
                ssl->options.useTicket = 1;
                ssl->options.resuming  = 1;
            } else if (ret == WOLFSSL_TICKET_RET_CREATE) {
                WOLFSSL_MSG("Using existing client ticket, creating new one");
                ret = TLSX_UseSessionTicket(&ssl->extensions, NULL, ssl->heap);
                if (ret == SSL_SUCCESS) {
                    ret = 0;
                    TLSX_SetResponse(ssl, TLSX_SESSION_TICKET);
                                                    /* send blank ticket */
                    ssl->options.createTicket = 1;  /* will send ticket msg */
                    ssl->options.useTicket    = 1;
                    ssl->options.resuming     = 1;
                }
            } else if (ret == WOLFSSL_TICKET_RET_REJECT) {
                WOLFSSL_MSG("Process client ticket rejected, not using");
                ssl->options.rejectTicket = 1;
                ret = 0;  /* not fatal */
            } else if (ret == WOLFSSL_TICKET_RET_FATAL || ret < 0) {
                WOLFSSL_MSG("Process client ticket fatal error, not using");
            }
        }
    }
#endif /* NO_WOLFSSL_SERVER */

    return ret;
}

WOLFSSL_LOCAL SessionTicket* TLSX_SessionTicket_Create(word32 lifetime,
                                            byte* data, word16 size, void* heap)
{
    SessionTicket* ticket = (SessionTicket*)XMALLOC(sizeof(SessionTicket),
                                                       heap, DYNAMIC_TYPE_TLSX);
    if (ticket) {
        ticket->data = (byte*)XMALLOC(size, heap, DYNAMIC_TYPE_TLSX);
        if (ticket->data == NULL) {
            XFREE(ticket, heap, DYNAMIC_TYPE_TLSX);
            return NULL;
        }

        XMEMCPY(ticket->data, data, size);
        ticket->size     = size;
        ticket->lifetime = lifetime;
    }

    return ticket;
}
WOLFSSL_LOCAL void TLSX_SessionTicket_Free(SessionTicket* ticket, void* heap)
{
    if (ticket) {
        XFREE(ticket->data, heap, DYNAMIC_TYPE_TLSX);
        XFREE(ticket,       heap, DYNAMIC_TYPE_TLSX);
    }

    (void)heap;
}

int TLSX_UseSessionTicket(TLSX** extensions, SessionTicket* ticket, void* heap)
{
    int ret = 0;

    if (extensions == NULL)
        return BAD_FUNC_ARG;

    /* If the ticket is NULL, the client will request a new ticket from the
       server. Otherwise, the client will use it in the next client hello. */
    if ((ret = TLSX_Push(extensions, TLSX_SESSION_TICKET, (void*)ticket, heap))
                                                                           != 0)
        return ret;

    return SSL_SUCCESS;
}

#define STK_VALIDATE_REQUEST TLSX_SessionTicket_ValidateRequest
#define STK_GET_SIZE         TLSX_SessionTicket_GetSize
#define STK_WRITE            TLSX_SessionTicket_Write
#define STK_PARSE            TLSX_SessionTicket_Parse
#define STK_FREE(stk, heap)  TLSX_SessionTicket_Free((SessionTicket*)stk,(heap))

#else

#define STK_FREE(a, b)
#define STK_VALIDATE_REQUEST(a)
#define STK_GET_SIZE(a, b)      0
#define STK_WRITE(a, b, c)      0
#define STK_PARSE(a, b, c, d)   0

#endif /* HAVE_SESSION_TICKET */

/******************************************************************************/
/* Quantum-Safe-Hybrid                                                        */
/******************************************************************************/

#ifdef HAVE_QSH
static WC_RNG* rng;
static wolfSSL_Mutex* rngMutex;

static void TLSX_QSH_FreeAll(QSHScheme* list, void* heap)
{
    QSHScheme* current;

    while ((current = list)) {
        list = current->next;
        XFREE(current, heap, DYNAMIC_TYPE_TLSX);
    }

    (void)heap;
}

static int TLSX_QSH_Append(QSHScheme** list, word16 name, byte* pub,
                                                                  word16 pubLen)
{
    QSHScheme* temp;

    if (list == NULL)
        return BAD_FUNC_ARG;

    if ((temp = (QSHScheme*)XMALLOC(sizeof(QSHScheme), NULL,
                                                    DYNAMIC_TYPE_TLSX)) == NULL)
        return MEMORY_E;

    temp->name  = name;
    temp->PK    = pub;
    temp->PKLen = pubLen;
    temp->next  = *list;

    *list = temp;

    return 0;
}


/* request for server's public key : 02 indicates 0-2 requested */
static byte TLSX_QSH_SerPKReq(byte* output, byte isRequest)
{
    if (isRequest) {
        /* only request one public key from the server */
        output[0] = 0x01;

        return OPAQUE8_LEN;
    }
    else {
        return 0;
    }
}

#ifndef NO_WOLFSSL_CLIENT

/* check for TLS_QSH suite */
static void TLSX_QSH_ValidateRequest(WOLFSSL* ssl, byte* semaphore)
{
    int i;

    for (i = 0; i < ssl->suites->suiteSz; i+= 2)
        if (ssl->suites->suites[i] == QSH_BYTE)
            return;

    /* No QSH suite found */
    TURN_ON(semaphore, TLSX_ToSemaphore(TLSX_QUANTUM_SAFE_HYBRID));
}


/* return the size of the QSH hello extension
   list      the list of QSHScheme structs containing id and key
   isRequest if 1 then is being sent to the server
 */
word16 TLSX_QSH_GetSize(QSHScheme* list, byte isRequest)
{
    QSHScheme* temp = list;
    word16 length = 0;

    /* account for size of scheme list and public key list */
    if (isRequest)
        length = OPAQUE16_LEN;
    length += OPAQUE24_LEN;

    /* for each non null element in list add size */
    while ((temp)) {
        /* add public key info Scheme | Key Length | Key */
        length += OPAQUE16_LEN;
        length += OPAQUE16_LEN;
        length += temp->PKLen;

        /* if client add name size for scheme list
           advance to next QSHScheme struct in list */
        if (isRequest)
            length += OPAQUE16_LEN;
        temp = temp->next;
    }

    /* add length for request server public keys */
    if (isRequest)
        length += OPAQUE8_LEN;

    return length;
}


/* write out a list of QSHScheme IDs */
static word16 TLSX_QSH_Write(QSHScheme* list, byte* output)
{
    QSHScheme* current = list;
    word16 length      = 0;

    length += OPAQUE16_LEN;

    while (current) {
        c16toa(current->name, output + length);
        length += OPAQUE16_LEN;
        current = (QSHScheme*)current->next;
    }

    c16toa(length - OPAQUE16_LEN, output); /* writing list length */

    return length;
}


/* write public key list in extension */
static word16 TLSX_QSHPK_WriteR(QSHScheme* format, byte* output);
static word16 TLSX_QSHPK_WriteR(QSHScheme* format, byte* output)
{
    word32 offset = 0;
    word16 public_len = 0;

    if (!format)
        return offset;

    /* write scheme ID */
    c16toa(format->name, output + offset);
    offset += OPAQUE16_LEN;

    /* write public key matching scheme */
    public_len = format->PKLen;
    c16toa(public_len, output + offset);
    offset += OPAQUE16_LEN;
    if (format->PK) {
        XMEMCPY(output+offset, format->PK, public_len);
    }

    return public_len + offset;
}

word16 TLSX_QSHPK_Write(QSHScheme* list, byte* output)
{
    QSHScheme* current = list;
    word32 length = 0;
    word24 toWire;

    length += OPAQUE24_LEN;

    while (current) {
        length += TLSX_QSHPK_WriteR(current, output + length);
        current = (QSHScheme*)current->next;
    }
    /* length of public keys sent */
    c32to24(length - OPAQUE24_LEN, toWire);
    output[0] = toWire[0];
    output[1] = toWire[1];
    output[2] = toWire[2];

    return length;
}

#endif /* NO_WOLFSSL_CLIENT */
#ifndef NO_WOLFSSL_SERVER

static void TLSX_QSHAgreement(TLSX** extensions, void* heap)
{
    TLSX* extension = TLSX_Find(*extensions, TLSX_QUANTUM_SAFE_HYBRID);
    QSHScheme* format = NULL;
    QSHScheme* del    = NULL;
    QSHScheme* prev   = NULL;

    if (extension == NULL)
        return;

    format = (QSHScheme*)extension->data;
    while (format) {
        if (format->PKLen == 0) {
            /* case of head */
            if (format == extension->data) {
                extension->data = format->next;
            }
            if (prev)
                prev->next = format->next;
            del = format;
            format = format->next;
            XFREE(del, heap, DYNAMIC_TYPE_TMP_BUFFER);
            del = NULL;
        } else {
            prev   = format;
            format = format->next;
        }
    }

    (void)heap;
}


/* Parse in hello extension
   input     the byte stream to process
   length    length of total extension found
   isRequest set to 1 if being sent to the server
 */
static int TLSX_QSH_Parse(WOLFSSL* ssl, byte* input, word16 length,
                                                                 byte isRequest)
{
    byte   numKeys    = 0;
    word16 offset     = 0;
    word16 schemSz    = 0;
    word16 offset_len = 0;
    word32 offset_pk  = 0;
    word16 name  = 0;
    word16 PKLen = 0;
    byte*  PK = NULL;
    int r;


    if (OPAQUE16_LEN > length)
        return BUFFER_ERROR;

    if (isRequest) {
        ato16(input, &schemSz);

        /* list of public keys available for QSH schemes */
        offset_len = schemSz + OPAQUE16_LEN;
    }

    offset_pk = ((input[offset_len] << 16)   & 0xFF00000) |
                (((input[offset_len + 1]) << 8) & 0xFF00) |
                (input[offset_len + 2] & 0xFF);
    offset_len += OPAQUE24_LEN;

    /* check buffer size */
    if (offset_pk > length)
        return BUFFER_ERROR;

    /* set maximum number of keys the client will accept */
    if (!isRequest)
        numKeys = (ssl->maxRequest < 1)? 1 : ssl->maxRequest;

    /* hello extension read list of scheme ids */
    if (isRequest) {

        /* read in request for public keys */
        ssl->minRequest = (input[length -1] >> 4) & 0xFF;
        ssl->maxRequest = input[length -1] & 0x0F;

        /* choose the min between min requested by client and 1 */
        numKeys = (ssl->minRequest > 1) ? ssl->minRequest : 1;

        if (ssl->minRequest > ssl->maxRequest)
            return BAD_FUNC_ARG;

        offset  += OPAQUE16_LEN;
        schemSz += offset;

        /* check buffer size */
        if (schemSz > length)
            return BUFFER_ERROR;

        while ((offset < schemSz) && numKeys) {
            /* Scheme ID list */
            ato16(input + offset, &name);
            offset += OPAQUE16_LEN;

            /* validate we have scheme id */
            if (ssl->user_set_QSHSchemes &&
                    !TLSX_ValidateQSHScheme(&ssl->extensions, name)) {
                continue;
            }

            /* server create keys on demand */
            if ((r = TLSX_CreateNtruKey(ssl, name)) != 0) {
                WOLFSSL_MSG("Error creating ntru keys");
                return r;
            }

            /* peer sent an agreed upon scheme */
            r = TLSX_UseQSHScheme(&ssl->extensions, name, NULL, 0, ssl->heap);

            if (r != SSL_SUCCESS) return r; /* throw error */

            numKeys--;
        }

        /* choose the min between min requested by client and 1 */
        numKeys = (ssl->minRequest > 1) ? ssl->minRequest : 1;
    }

    /* QSHPK struct */
    offset_pk += offset_len;
    while ((offset_len < offset_pk) && numKeys) {
        QSHKey * temp;

        if ((temp = (QSHKey*)XMALLOC(sizeof(QSHKey), ssl->heap,
                                                    DYNAMIC_TYPE_TLSX)) == NULL)
            return MEMORY_E;

        /* initialize */
        temp->next = NULL;
        temp->pub.buffer = NULL;
        temp->pub.length = 0;
        temp->pri.buffer = NULL;
        temp->pri.length = 0;

        /* scheme id */
        ato16(input + offset_len, &(temp->name));
        offset_len += OPAQUE16_LEN;

        /* public key length */
        ato16(input + offset_len, &PKLen);
        temp->pub.length = PKLen;
        offset_len += OPAQUE16_LEN;


        if (isRequest) {
            /* validate we have scheme id */
            if (ssl->user_set_QSHSchemes &&
                    (!TLSX_ValidateQSHScheme(&ssl->extensions, temp->name))) {
                offset_len += PKLen;
                XFREE(temp, ssl->heap, DYNAMIC_TYPE_TLSX);
                continue;
            }
        }

        /* read in public key */
        if (PKLen > 0) {
            temp->pub.buffer = (byte*)XMALLOC(temp->pub.length,
                                            ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
            XMEMCPY(temp->pub.buffer, input + offset_len, temp->pub.length);
            offset_len += PKLen;
        }
        else {
            PK = NULL;
        }

        /* use own key when adding to extensions list for sending reply */
        PKLen = 0;
        PK = TLSX_QSHKeyFind_Pub(ssl->QSH_Key, &PKLen, temp->name);
        r  = TLSX_UseQSHScheme(&ssl->extensions, temp->name, PK, PKLen,
                                                                     ssl->heap);

        /* store peers key */
        ssl->peerQSHKeyPresent = 1;
        if (TLSX_AddQSHKey(&ssl->peerQSHKey, temp) != 0)
            return MEMORY_E;

        if (temp->pub.length == 0) {
            XFREE(temp, ssl->heap, DYNAMIC_TYPE_TLSX);
        }

        if (r != SSL_SUCCESS) {return r;} /* throw error */

        numKeys--;
    }

    /* reply to a QSH extension sent from client */
    if (isRequest) {
        TLSX_SetResponse(ssl, TLSX_QUANTUM_SAFE_HYBRID);
        /* only use schemes we have key generated for -- free the rest */
        TLSX_QSHAgreement(&ssl->extensions, ssl->heap);
    }

    return 0;
}


/* Used for parsing in QSHCipher structs on Key Exchange */
int TLSX_QSHCipher_Parse(WOLFSSL* ssl, const byte* input, word16 length,
                                                                  byte isServer)
{
    QSHKey* key;
    word16 Max_Secret_Len = 48;
    word16 offset     = 0;
    word16 offset_len = 0;
    word32 offset_pk  = 0;
    word16 name       = 0;
    word16 secretLen  = 0;
    byte*  secret     = NULL;
    word16 buffLen    = 0;
    byte buff[145]; /* size enough for 3 secrets */
    buffer* buf;

    /* pointer to location where secret should be stored */
    if (isServer) {
        buf = ssl->QSH_secret->CliSi;
    }
    else {
        buf = ssl->QSH_secret->SerSi;
    }

    offset_pk = ((input[offset_len] << 16)    & 0xFF0000) |
                (((input[offset_len + 1]) << 8) & 0xFF00) |
                (input[offset_len + 2] & 0xFF);
    offset_len += OPAQUE24_LEN;

    /* validating extension list length -- check if trying to read over edge
       of buffer */
    if (length < (offset_pk + OPAQUE24_LEN)) {
        return BUFFER_ERROR;
    }

    /* QSHCipherList struct */
    offset_pk += offset_len;
    while (offset_len < offset_pk) {

        /* scheme id */
        ato16(input + offset_len, &name);
        offset_len += OPAQUE16_LEN;

        /* public key length */
        ato16(input + offset_len, &secretLen);
        offset_len += OPAQUE16_LEN;

        /* read in public key */
        if (secretLen > 0) {
            secret = (byte*)(input + offset_len);
            offset_len += secretLen;
        }
        else {
            secret = NULL;
        }

        /* no secret sent */
        if (secret == NULL)
            continue;

        /* find corresponding key */
        key = ssl->QSH_Key;
        while (key) {
            if (key->name == name)
                break;
            else
                key = (QSHKey*)key->next;
        }

        /* if we do not have the key than there was a big issue negotiation */
        if (key == NULL) {
            WOLFSSL_MSG("key was null for decryption!!!\n");
            return MEMORY_E;
        }

        /* Decrypt sent secret */
        buffLen = Max_Secret_Len;
        QSH_Decrypt(key, secret, secretLen, buff + offset, &buffLen);
        offset += buffLen;
    }

    /* allocate memory for buffer */
    buf->length = offset;
    buf->buffer = (byte*)XMALLOC(offset, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf->buffer == NULL)
        return MEMORY_E;

    /* store secrets */
    XMEMCPY(buf->buffer, buff, offset);
    ForceZero(buff, offset);

    return offset_len;
}


/* return 1 on success */
int TLSX_ValidateQSHScheme(TLSX** extensions, word16 theirs) {
    TLSX* extension = TLSX_Find(*extensions, TLSX_QUANTUM_SAFE_HYBRID);
    QSHScheme* format    = NULL;

    /* if no extension is sent then do not use QSH */
    if (!extension) {
        WOLFSSL_MSG("No QSH Extension");
        return 0;
    }

    for (format = (QSHScheme*)extension->data; format; format = format->next) {
        if (format->name == theirs) {
	        WOLFSSL_MSG("Found Matching QSH Scheme");
            return 1; /* have QSH */
        }
    }

    return 0;
}
#endif /* NO_WOLFSSL_SERVER */

/* test if the QSH Scheme is implemented
   return 1 if yes 0 if no */
static int TLSX_HaveQSHScheme(word16 name)
{
    switch(name) {
        #ifdef HAVE_NTRU
            case WOLFSSL_NTRU_EESS439:
            case WOLFSSL_NTRU_EESS593:
            case WOLFSSL_NTRU_EESS743:
                    return 1;
        #endif
            case WOLFSSL_LWE_XXX:
            case WOLFSSL_HFE_XXX:
                    return 0; /* not supported yet */

        default:
            return 0;
    }
}


/* Add a QSHScheme struct to list of usable ones */
int TLSX_UseQSHScheme(TLSX** extensions, word16 name, byte* pKey, word16 pkeySz,
                                                                     void* heap)
{
    TLSX*      extension = TLSX_Find(*extensions, TLSX_QUANTUM_SAFE_HYBRID);
    QSHScheme* format    = NULL;
    int        ret       = 0;

    /* sanity check */
    if (extensions == NULL || (pKey == NULL && pkeySz != 0))
        return BAD_FUNC_ARG;

    /* if scheme is implemented than add */
    if (TLSX_HaveQSHScheme(name)) {
	    if ((ret = TLSX_QSH_Append(&format, name, pKey, pkeySz)) != 0)
	        return ret;

	    if (!extension) {
	        if ((ret = TLSX_Push(extensions, TLSX_QUANTUM_SAFE_HYBRID, format,
                                                                  heap)) != 0) {
	            XFREE(format, 0, DYNAMIC_TYPE_TLSX);
	            return ret;
	        }
	    }
	    else {
	        /* push new QSH object to extension data. */
	        format->next = (QSHScheme*)extension->data;
	        extension->data = (void*)format;

	        /* look for another format of the same name to remove (replacement) */
	        do {
	            if (format->next && (format->next->name == name)) {
	                QSHScheme* next = format->next;

	                format->next = next->next;
	                XFREE(next, 0, DYNAMIC_TYPE_TLSX);

	                break;
	            }
	        } while ((format = format->next));
	    }
    }
    return SSL_SUCCESS;
}

#define QSH_FREE_ALL         TLSX_QSH_FreeAll
#define QSH_VALIDATE_REQUEST TLSX_QSH_ValidateRequest

#ifndef NO_WOLFSSL_CLIENT
#define QSH_GET_SIZE TLSX_QSH_GetSize
#define QSH_WRITE    TLSX_QSH_Write
#else
#define QSH_GET_SIZE(list)         0
#define QSH_WRITE(a, b)            0
#endif

#ifndef NO_WOLFSSL_SERVER
#define QSH_PARSE TLSX_QSH_Parse
#else
#define QSH_PARSE(a, b, c, d)      0
#endif

#define QSHPK_WRITE TLSX_QSHPK_Write
#define QSH_SERREQ TLSX_QSH_SerPKReq
#else

#define QSH_FREE_ALL(list, heap)
#define QSH_GET_SIZE(list, a)      0
#define QSH_WRITE(a, b)            0
#define QSH_PARSE(a, b, c, d)      0
#define QSHPK_WRITE(a, b)          0
#define QSH_SERREQ(a, b)           0
#define QSH_VALIDATE_REQUEST(a, b)

#endif /* HAVE_QSH */

/******************************************************************************/
/* TLS Extensions Framework                                                   */
/******************************************************************************/

/** Finds an extension in the provided list. */
TLSX* TLSX_Find(TLSX* list, TLSX_Type type)
{
    TLSX* extension = list;

    while (extension && extension->type != type)
        extension = extension->next;

    return extension;
}

/** Releases all extensions in the provided list. */
void TLSX_FreeAll(TLSX* list, void* heap)
{
    TLSX* extension;

    while ((extension = list)) {
        list = extension->next;

        switch (extension->type) {

            case TLSX_SERVER_NAME:
                SNI_FREE_ALL((SNI*)extension->data, heap);
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                MFL_FREE_ALL(extension->data, heap);
                break;

            case TLSX_TRUNCATED_HMAC:
                /* Nothing to do. */
                break;

            case TLSX_SUPPORTED_GROUPS:
                EC_FREE_ALL((EllipticCurve*)extension->data, heap);
                break;

            case TLSX_STATUS_REQUEST:
                CSR_FREE_ALL(extension->data, heap);
                break;

            case TLSX_STATUS_REQUEST_V2:
                CSR2_FREE_ALL(extension->data, heap);
                break;

            case TLSX_RENEGOTIATION_INFO:
                SCR_FREE_ALL(extension->data, heap);
                break;

            case TLSX_SESSION_TICKET:
                STK_FREE(extension->data, heap);
                break;

            case TLSX_QUANTUM_SAFE_HYBRID:
                QSH_FREE_ALL((QSHScheme*)extension->data, heap);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                ALPN_FREE_ALL((ALPN*)extension->data, heap);
                break;
        }

        XFREE(extension, heap, DYNAMIC_TYPE_TLSX);
    }

    (void)heap;
}

/** Checks if the tls extensions are supported based on the protocol version. */
int TLSX_SupportExtensions(WOLFSSL* ssl) {
    return ssl && (IsTLS(ssl) || ssl->version.major == DTLS_MAJOR);
}

/** Tells the buffered size of the extensions in a list. */
static word16 TLSX_GetSize(TLSX* list, byte* semaphore, byte isRequest)
{
    TLSX* extension;
    word16 length = 0;

    while ((extension = list)) {
        list = extension->next;

        /* only extensions marked as response are sent back to the client. */
        if (!isRequest && !extension->resp)
            continue; /* skip! */

        /* ssl level extensions are expected to override ctx level ones. */
        if (!IS_OFF(semaphore, TLSX_ToSemaphore(extension->type)))
            continue; /* skip! */

        /* extension type + extension data length. */
        length += HELLO_EXT_TYPE_SZ + OPAQUE16_LEN;


        switch (extension->type) {

            case TLSX_SERVER_NAME:
                /* SNI only sends the name on the request. */
                if (isRequest)
                    length += SNI_GET_SIZE((SNI*)extension->data);
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                length += MFL_GET_SIZE(extension->data);
                break;

            case TLSX_TRUNCATED_HMAC:
                /* always empty. */
                break;

            case TLSX_SUPPORTED_GROUPS:
                length += EC_GET_SIZE((EllipticCurve*)extension->data);
                break;

            case TLSX_STATUS_REQUEST:
                length += CSR_GET_SIZE(extension->data, isRequest);
                break;

            case TLSX_STATUS_REQUEST_V2:
                length += CSR2_GET_SIZE(extension->data, isRequest);
                break;

            case TLSX_RENEGOTIATION_INFO:
                length += SCR_GET_SIZE(extension->data, isRequest);
                break;

            case TLSX_SESSION_TICKET:
                length += STK_GET_SIZE(extension->data, isRequest);
                break;

            case TLSX_QUANTUM_SAFE_HYBRID:
                length += QSH_GET_SIZE((QSHScheme*)extension->data, isRequest);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                length += ALPN_GET_SIZE((ALPN*)extension->data);
                break;

        }

        /* marks the extension as processed so ctx level */
        /* extensions don't overlap with ssl level ones. */
        TURN_ON(semaphore, TLSX_ToSemaphore(extension->type));
    }

    return length;
}

/** Writes the extensions of a list in a buffer. */
static word16 TLSX_Write(TLSX* list, byte* output, byte* semaphore,
                                                                 byte isRequest)
{
    TLSX* extension;
    word16 offset = 0;
    word16 length_offset = 0;

    while ((extension = list)) {
        list = extension->next;

        /* only extensions marked as response are written in a response. */
        if (!isRequest && !extension->resp)
            continue; /* skip! */

        /* ssl level extensions are expected to override ctx level ones. */
        if (!IS_OFF(semaphore, TLSX_ToSemaphore(extension->type)))
            continue; /* skip! */

        /* writes extension type. */
        c16toa(extension->type, output + offset);
        offset += HELLO_EXT_TYPE_SZ + OPAQUE16_LEN;
        length_offset = offset;

        /* extension data should be written internally. */
        switch (extension->type) {
            case TLSX_SERVER_NAME:
                if (isRequest)
                    offset += SNI_WRITE((SNI*)extension->data, output + offset);
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                offset += MFL_WRITE((byte*)extension->data, output + offset);
                break;

            case TLSX_TRUNCATED_HMAC:
                /* always empty. */
                break;

            case TLSX_SUPPORTED_GROUPS:
                offset += EC_WRITE((EllipticCurve*)extension->data,
                                    output + offset);
                break;

            case TLSX_STATUS_REQUEST:
                offset += CSR_WRITE(extension->data, output + offset,
                                                                     isRequest);
                break;

            case TLSX_STATUS_REQUEST_V2:
                offset += CSR2_WRITE(extension->data, output + offset,
                                                                     isRequest);
                break;

            case TLSX_RENEGOTIATION_INFO:
                offset += SCR_WRITE(extension->data, output + offset,
                                                                     isRequest);
                break;

            case TLSX_SESSION_TICKET:
                offset += STK_WRITE(extension->data, output + offset,
                                                                     isRequest);
                break;

            case TLSX_QUANTUM_SAFE_HYBRID:
                if (isRequest) {
                    offset += QSH_WRITE((QSHScheme*)extension->data, output + offset);
                }
                offset += QSHPK_WRITE((QSHScheme*)extension->data, output + offset);
                offset += QSH_SERREQ(output + offset, isRequest);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                offset += ALPN_WRITE((ALPN*)extension->data, output + offset);
                break;
        }

        /* writes extension data length. */
        c16toa(offset - length_offset, output + length_offset - OPAQUE16_LEN);

        /* marks the extension as processed so ctx level */
        /* extensions don't overlap with ssl level ones. */
        TURN_ON(semaphore, TLSX_ToSemaphore(extension->type));
    }

    return offset;
}


#ifdef HAVE_NTRU

static word32 GetEntropy(unsigned char* out, word32 num_bytes)
{
    int ret = 0;

    if (rng == NULL) {
        if ((rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL,
                                                    DYNAMIC_TYPE_TLSX)) == NULL)
            return DRBG_OUT_OF_MEMORY;
        wc_InitRng(rng);
    }

    if (rngMutex == NULL) {
        if ((rngMutex = (wolfSSL_Mutex*)XMALLOC(sizeof(wolfSSL_Mutex), NULL,
                                                    DYNAMIC_TYPE_TLSX)) == NULL)
            return DRBG_OUT_OF_MEMORY;
        InitMutex(rngMutex);
    }

    ret |= LockMutex(rngMutex);
    ret |= wc_RNG_GenerateBlock(rng, out, num_bytes);
    ret |= UnLockMutex(rngMutex);

    if (ret != 0)
        return DRBG_ENTROPY_FAIL;

    return DRBG_OK;
}
#endif


#ifdef HAVE_QSH
static int TLSX_CreateQSHKey(WOLFSSL* ssl, int type)
{
    int ret;

    switch (type) {
#ifdef HAVE_NTRU
        case WOLFSSL_NTRU_EESS439:
        case WOLFSSL_NTRU_EESS593:
        case WOLFSSL_NTRU_EESS743:
            ret = TLSX_CreateNtruKey(ssl, type);
            break;
#endif
        default:
            WOLFSSL_MSG("Unknown type for creating NTRU key");
            return -1;
    }

    return ret;
}


static int TLSX_AddQSHKey(QSHKey** list, QSHKey* key)
{
    QSHKey* current;

    if (key == NULL)
        return BAD_FUNC_ARG;

    /* if no public key stored in key then do not add */
    if (key->pub.length == 0 || key->pub.buffer == NULL)
        return 0;

    /* first element to be added to the list */
    current = *list;
    if (current == NULL) {
        *list = key;
        return 0;
    }

    while (current->next) {
        /* can only have one of the key in the list */
        if (current->name == key->name)
            return -1;
        current = (QSHKey*)current->next;
    }

    current->next = (struct QSHKey*)key;

    return 0;
}


#ifdef HAVE_NTRU
int TLSX_CreateNtruKey(WOLFSSL* ssl, int type)
{
    int ret;
    int ntruType;

    /* variable declarations for NTRU*/
    QSHKey* temp = NULL;
    byte   public_key[1027];
    word16 public_key_len = sizeof(public_key);
    byte   private_key[1120];
    word16 private_key_len = sizeof(private_key);
    DRBG_HANDLE drbg;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case WOLFSSL_NTRU_EESS439:
            ntruType = NTRU_EES439EP1;
            break;
        case WOLFSSL_NTRU_EESS593:
            ntruType = NTRU_EES593EP1;
            break;
        case WOLFSSL_NTRU_EESS743:
            ntruType = NTRU_EES743EP1;
            break;
        default:
            WOLFSSL_MSG("Unknown type for creating NTRU key");
            return -1;
    }
    ret = ntru_crypto_drbg_external_instantiate(GetEntropy, &drbg);
    if (ret != DRBG_OK) {
        WOLFSSL_MSG("NTRU drbg instantiate failed\n");
        return ret;
    }

    if ((ret = ntru_crypto_ntru_encrypt_keygen(drbg, ntruType,
                     &public_key_len, NULL, &private_key_len, NULL)) != NTRU_OK)
        return ret;

    if ((ret = ntru_crypto_ntru_encrypt_keygen(drbg, ntruType,
        &public_key_len, public_key, &private_key_len, private_key)) != NTRU_OK)
        return ret;

    ret = ntru_crypto_drbg_uninstantiate(drbg);
    if (ret != NTRU_OK) {
        WOLFSSL_MSG("NTRU drbg uninstantiate failed\n");
        return ret;
    }

    if ((temp = (QSHKey*)XMALLOC(sizeof(QSHKey), ssl->heap,
                                                    DYNAMIC_TYPE_TLSX)) == NULL)
        return MEMORY_E;
    temp->name = type;
    temp->pub.length = public_key_len;
    temp->pub.buffer = (byte*)XMALLOC(public_key_len, ssl->heap,
                                DYNAMIC_TYPE_PUBLIC_KEY);
    XMEMCPY(temp->pub.buffer, public_key, public_key_len);
    temp->pri.length = private_key_len;
    temp->pri.buffer = (byte*)XMALLOC(private_key_len, ssl->heap,
                                DYNAMIC_TYPE_ARRAYS);
    XMEMCPY(temp->pri.buffer, private_key, private_key_len);
    temp->next = NULL;

    TLSX_AddQSHKey(&ssl->QSH_Key, temp);

    return ret;
}
#endif


/*
    Used to find a public key from the list of keys
    pubLen length of array
    name   input the name of the scheme looking for ie WOLFSSL_NTRU_ESSXXX

    returns a pointer to public key byte* or NULL if not found
 */
static byte* TLSX_QSHKeyFind_Pub(QSHKey* qsh, word16* pubLen, word16 name)
{
    QSHKey* current = qsh;

    if (qsh == NULL || pubLen == NULL)
        return NULL;

    *pubLen = 0;

    while(current) {
        if (current->name == name) {
            *pubLen = current->pub.length;
            return current->pub.buffer;
        }
        current = (QSHKey*)current->next;
    }

    return NULL;
}
#endif /* HAVE_QSH */


int TLSX_PopulateExtensions(WOLFSSL* ssl, byte isServer)
{
    byte* public_key      = NULL;
    word16 public_key_len = 0;
    #ifdef HAVE_QSH
        TLSX* extension;
        QSHScheme* qsh;
        QSHScheme* next;
    #endif
    int ret = 0;

    #ifdef HAVE_QSH
        /* add supported QSHSchemes */
        WOLFSSL_MSG("Adding supported QSH Schemes");

        /* server will add extension depending on whats parsed from client */
        if (!isServer) {

            /* test if user has set a specific scheme already */
            if (!ssl->user_set_QSHSchemes) {
                if (ssl->sendQSHKeys && ssl->QSH_Key == NULL) {
                    if ((ret = TLSX_CreateQSHKey(ssl, WOLFSSL_NTRU_EESS743)) != 0) {
                        WOLFSSL_MSG("Error creating ntru keys");
                        return ret;
                    }
                    if ((ret = TLSX_CreateQSHKey(ssl, WOLFSSL_NTRU_EESS593)) != 0) {
                        WOLFSSL_MSG("Error creating ntru keys");
                        return ret;
                    }
                    if ((ret = TLSX_CreateQSHKey(ssl, WOLFSSL_NTRU_EESS439)) != 0) {
                        WOLFSSL_MSG("Error creating ntru keys");
                        return ret;
                    }

                /* add NTRU 256 */
                public_key = TLSX_QSHKeyFind_Pub(ssl->QSH_Key,
                        &public_key_len, WOLFSSL_NTRU_EESS743);
                }
                if (TLSX_UseQSHScheme(&ssl->extensions, WOLFSSL_NTRU_EESS743,
                                      public_key, public_key_len, ssl->heap)
                                      != SSL_SUCCESS)
                    ret = -1;

                /* add NTRU 196 */
                if (ssl->sendQSHKeys) {
                    public_key = TLSX_QSHKeyFind_Pub(ssl->QSH_Key,
                        &public_key_len, WOLFSSL_NTRU_EESS593);
                }
                if (TLSX_UseQSHScheme(&ssl->extensions, WOLFSSL_NTRU_EESS593,
                                      public_key, public_key_len, ssl->heap)
                                      != SSL_SUCCESS)
                    ret = -1;

                /* add NTRU 128 */
                if (ssl->sendQSHKeys) {
                    public_key = TLSX_QSHKeyFind_Pub(ssl->QSH_Key,
                        &public_key_len, WOLFSSL_NTRU_EESS439);
                }
                if (TLSX_UseQSHScheme(&ssl->extensions, WOLFSSL_NTRU_EESS439,
                                      public_key, public_key_len, ssl->heap)
                                      != SSL_SUCCESS)
                    ret = -1;
            }
            else if (ssl->sendQSHKeys && ssl->QSH_Key == NULL) {
                /* for each scheme make a client key */
                extension = TLSX_Find(ssl->extensions, TLSX_QUANTUM_SAFE_HYBRID);
                if (extension) {
                    qsh = (QSHScheme*)extension->data;

                    while (qsh) {
                        if ((ret = TLSX_CreateQSHKey(ssl, qsh->name)) != 0)
                            return ret;

                        /* get next now because qsh could be freed */
                        next = qsh->next;

                        /* find the public key created and add to extension*/
                        public_key = TLSX_QSHKeyFind_Pub(ssl->QSH_Key,
                                 &public_key_len, qsh->name);
                        if (TLSX_UseQSHScheme(&ssl->extensions, qsh->name,
                                              public_key, public_key_len,
                                              ssl->heap) != SSL_SUCCESS)
                            ret = -1;
                        qsh = next;
                    }
                }
            }
         } /* is not server */
    #endif

    (void)isServer;
    (void)public_key;
    (void)public_key_len;
    (void)ssl;

    return ret;
}


#ifndef NO_WOLFSSL_CLIENT

/** Tells the buffered size of extensions to be sent into the client hello. */
word16 TLSX_GetRequestSize(WOLFSSL* ssl)
{
    word16 length = 0;

    if (TLSX_SupportExtensions(ssl)) {
        byte semaphore[SEMAPHORE_SIZE] = {0};

        EC_VALIDATE_REQUEST(ssl, semaphore);
        QSH_VALIDATE_REQUEST(ssl, semaphore);
        STK_VALIDATE_REQUEST(ssl);

        if (ssl->extensions)
            length += TLSX_GetSize(ssl->extensions, semaphore, 1);

        if (ssl->ctx && ssl->ctx->extensions)
            length += TLSX_GetSize(ssl->ctx->extensions, semaphore, 1);

        if (IsAtLeastTLSv1_2(ssl) && ssl->suites->hashSigAlgoSz)
            length += HELLO_EXT_SZ + HELLO_EXT_SIGALGO_SZ
                   + ssl->suites->hashSigAlgoSz;

#ifdef HAVE_EXTENDED_MASTER
        if (ssl->options.haveEMS)
            length += HELLO_EXT_SZ;
#endif
    }

    if (length)
        length += OPAQUE16_LEN; /* for total length storage. */

    return length;
}

/** Writes the extensions to be sent into the client hello. */
word16 TLSX_WriteRequest(WOLFSSL* ssl, byte* output)
{
    word16 offset = 0;

    if (TLSX_SupportExtensions(ssl) && output) {
        byte semaphore[SEMAPHORE_SIZE] = {0};

        offset += OPAQUE16_LEN; /* extensions length */

        EC_VALIDATE_REQUEST(ssl, semaphore);
        STK_VALIDATE_REQUEST(ssl);
        QSH_VALIDATE_REQUEST(ssl, semaphore);

        if (ssl->extensions)
            offset += TLSX_Write(ssl->extensions, output + offset,
                                                                  semaphore, 1);

        if (ssl->ctx && ssl->ctx->extensions)
            offset += TLSX_Write(ssl->ctx->extensions, output + offset,
                                                                  semaphore, 1);

        if (IsAtLeastTLSv1_2(ssl) && ssl->suites->hashSigAlgoSz) {
            int i;
            /* extension type */
            c16toa(HELLO_EXT_SIG_ALGO, output + offset);
            offset += HELLO_EXT_TYPE_SZ;

            /* extension data length */
            c16toa(OPAQUE16_LEN + ssl->suites->hashSigAlgoSz,
                   output + offset);
            offset += OPAQUE16_LEN;

            /* sig algos length */
            c16toa(ssl->suites->hashSigAlgoSz, output + offset);
            offset += OPAQUE16_LEN;

            /* sig algos */
            for (i = 0; i < ssl->suites->hashSigAlgoSz; i++, offset++)
                output[offset] = ssl->suites->hashSigAlgo[i];
        }

#ifdef HAVE_EXTENDED_MASTER
        if (ssl->options.haveEMS) {
            c16toa(HELLO_EXT_EXTMS, output + offset);
            offset += HELLO_EXT_TYPE_SZ;
            c16toa(0, output + offset);
            offset += HELLO_EXT_SZ_SZ;
        }
#endif

        if (offset > OPAQUE16_LEN)
            c16toa(offset - OPAQUE16_LEN, output); /* extensions length */
    }

    return offset;
}

#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER

/** Tells the buffered size of extensions to be sent into the server hello. */
word16 TLSX_GetResponseSize(WOLFSSL* ssl)
{
    word16 length = 0;
    byte semaphore[SEMAPHORE_SIZE] = {0};

    #ifdef HAVE_QSH
        /* change response if not using TLS_QSH */
        if (!ssl->options.haveQSH) {
            TLSX* ext = TLSX_Find(ssl->extensions, TLSX_QUANTUM_SAFE_HYBRID);
            if (ext)
                ext->resp = 0;
        }
    #endif

#ifdef HAVE_EXTENDED_MASTER
    if (ssl->options.haveEMS)
        length += HELLO_EXT_SZ;
#endif

    if (TLSX_SupportExtensions(ssl))
        length += TLSX_GetSize(ssl->extensions, semaphore, 0);

    /* All the response data is set at the ssl object only, so no ctx here. */

    if (length)
        length += OPAQUE16_LEN; /* for total length storage. */

    return length;
}

/** Writes the server hello extensions into a buffer. */
word16 TLSX_WriteResponse(WOLFSSL *ssl, byte* output)
{
    word16 offset = 0;

    if (TLSX_SupportExtensions(ssl) && output) {
        byte semaphore[SEMAPHORE_SIZE] = {0};

        offset += OPAQUE16_LEN; /* extensions length */

        offset += TLSX_Write(ssl->extensions, output + offset, semaphore, 0);

#ifdef HAVE_EXTENDED_MASTER
        if (ssl->options.haveEMS) {
            c16toa(HELLO_EXT_EXTMS, output + offset);
            offset += HELLO_EXT_TYPE_SZ;
            c16toa(0, output + offset);
            offset += HELLO_EXT_SZ_SZ;
        }
#endif

        if (offset > OPAQUE16_LEN)
            c16toa(offset - OPAQUE16_LEN, output); /* extensions length */
    }

    return offset;
}

#endif /* NO_WOLFSSL_SERVER */

/** Parses a buffer of TLS extensions. */
int TLSX_Parse(WOLFSSL* ssl, byte* input, word16 length, byte isRequest,
                                                                 Suites *suites)
{
    int ret = 0;
    word16 offset = 0;
#ifdef HAVE_EXTENDED_MASTER
    byte pendingEMS = 0;
#endif

    if (!ssl || !input || (isRequest && !suites))
        return BAD_FUNC_ARG;

    while (ret == 0 && offset < length) {
        word16 type;
        word16 size;

        if (length - offset < HELLO_EXT_TYPE_SZ + OPAQUE16_LEN)
            return BUFFER_ERROR;

        ato16(input + offset, &type);
        offset += HELLO_EXT_TYPE_SZ;

        ato16(input + offset, &size);
        offset += OPAQUE16_LEN;

        if (offset + size > length)
            return BUFFER_ERROR;

        switch (type) {
            case TLSX_SERVER_NAME:
                WOLFSSL_MSG("SNI extension received");

                ret = SNI_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_MAX_FRAGMENT_LENGTH:
                WOLFSSL_MSG("Max Fragment Length extension received");

                ret = MFL_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_TRUNCATED_HMAC:
                WOLFSSL_MSG("Truncated HMAC extension received");

                ret = THM_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_SUPPORTED_GROUPS:
                WOLFSSL_MSG("Elliptic Curves extension received");

                ret = EC_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_STATUS_REQUEST:
                WOLFSSL_MSG("Certificate Status Request extension received");

                ret = CSR_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_STATUS_REQUEST_V2:
                WOLFSSL_MSG("Certificate Status Request v2 extension received");

                ret = CSR2_PARSE(ssl, input + offset, size, isRequest);
                break;

#ifdef HAVE_EXTENDED_MASTER
            case HELLO_EXT_EXTMS:
                WOLFSSL_MSG("Extended Master Secret extension received");

#ifndef NO_WOLFSSL_SERVER
                if (isRequest)
                    ssl->options.haveEMS = 1;
#endif
                pendingEMS = 1;
                break;
#endif

            case TLSX_RENEGOTIATION_INFO:
                WOLFSSL_MSG("Secure Renegotiation extension received");

                ret = SCR_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_SESSION_TICKET:
                WOLFSSL_MSG("Session Ticket extension received");

                ret = STK_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_QUANTUM_SAFE_HYBRID:
                WOLFSSL_MSG("Quantum-Safe-Hybrid extension received");

                ret = QSH_PARSE(ssl, input + offset, size, isRequest);
                break;

            case TLSX_APPLICATION_LAYER_PROTOCOL:
                WOLFSSL_MSG("ALPN extension received");

                ret = ALPN_PARSE(ssl, input + offset, size, isRequest);
                break;

            case HELLO_EXT_SIG_ALGO:
                if (isRequest) {
                    /* do not mess with offset inside the switch! */
                    if (IsAtLeastTLSv1_2(ssl)) {
                        ato16(input + offset, &suites->hashSigAlgoSz);

                        if (suites->hashSigAlgoSz > size - OPAQUE16_LEN)
                            return BUFFER_ERROR;

                        XMEMCPY(suites->hashSigAlgo,
                                input + offset + OPAQUE16_LEN,
                                min(suites->hashSigAlgoSz,
                                                        HELLO_EXT_SIGALGO_MAX));
                    }
                } else {
                    WOLFSSL_MSG("Servers MUST NOT send SIG ALGO extension.");
                }

                break;
        }

        /* offset should be updated here! */
        offset += size;
    }

#ifdef HAVE_EXTENDED_MASTER
    if (!isRequest && ssl->options.haveEMS && !pendingEMS)
        ssl->options.haveEMS = 0;
#endif

    if (ret == 0)
        ret = SNI_VERIFY_PARSE(ssl, isRequest);

    return ret;
}

/* undefining semaphore macros */
#undef IS_OFF
#undef TURN_ON
#undef SEMAPHORE_SIZE

#endif /* HAVE_TLS_EXTENSIONS */

#ifndef NO_WOLFSSL_CLIENT

#ifndef NO_OLD_TLS

    WOLFSSL_METHOD* wolfTLSv1_client_method(void)
    {
        return wolfTLSv1_client_method_ex(NULL);
    }


    WOLFSSL_METHOD* wolfTLSv1_1_client_method(void)
    {
        return wolfTLSv1_1_client_method_ex(NULL);
    }

    WOLFSSL_METHOD* wolfTLSv1_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                             (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        if (method)
            InitSSL_Method(method, MakeTLSv1());
        return method;
    }


    WOLFSSL_METHOD* wolfTLSv1_1_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        if (method)
            InitSSL_Method(method, MakeTLSv1_1());
        return method;
    }

#endif /* !NO_OLD_TLS */

#ifndef NO_SHA256   /* can't use without SHA256 */

    WOLFSSL_METHOD* wolfTLSv1_2_client_method(void)
    {
        return wolfTLSv1_2_client_method_ex(NULL);
    }

    WOLFSSL_METHOD* wolfTLSv1_2_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        if (method)
            InitSSL_Method(method, MakeTLSv1_2());
        return method;
    }
#endif


    WOLFSSL_METHOD* wolfSSLv23_client_method(void)
    {
        return wolfSSLv23_client_method_ex(NULL);
    }


    WOLFSSL_METHOD* wolfSSLv23_client_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        if (method) {
#ifndef NO_SHA256         /* 1.2 requires SHA256 */
            InitSSL_Method(method, MakeTLSv1_2());
#else
            InitSSL_Method(method, MakeTLSv1_1());
#endif
#ifndef NO_OLD_TLS
            method->downgrade = 1;
#endif
        }
        return method;
    }

#endif /* NO_WOLFSSL_CLIENT */



#ifndef NO_WOLFSSL_SERVER

#ifndef NO_OLD_TLS

    WOLFSSL_METHOD* wolfTLSv1_server_method(void)
    {
        return wolfTLSv1_server_method_ex(NULL);
    }


    WOLFSSL_METHOD* wolfTLSv1_1_server_method(void)
    {
        return wolfTLSv1_1_server_method_ex(NULL);
    }

    WOLFSSL_METHOD* wolfTLSv1_server_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        if (method) {
            InitSSL_Method(method, MakeTLSv1());
            method->side = WOLFSSL_SERVER_END;
        }
        return method;
    }


    WOLFSSL_METHOD* wolfTLSv1_1_server_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        if (method) {
            InitSSL_Method(method, MakeTLSv1_1());
            method->side = WOLFSSL_SERVER_END;
        }
        return method;
    }
#endif /* !NO_OLD_TLS */

#ifndef NO_SHA256   /* can't use without SHA256 */

    WOLFSSL_METHOD* wolfTLSv1_2_server_method(void)
    {
        return wolfTLSv1_2_server_method_ex(NULL);
    }

    WOLFSSL_METHOD* wolfTLSv1_2_server_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD), 
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        if (method) {
            InitSSL_Method(method, MakeTLSv1_2());
            method->side = WOLFSSL_SERVER_END;
        }
        return method;
    }

#endif


    WOLFSSL_METHOD* wolfSSLv23_server_method(void)
    {
        return wolfSSLv23_server_method_ex(NULL);
    }

    WOLFSSL_METHOD* wolfSSLv23_server_method_ex(void* heap)
    {
        WOLFSSL_METHOD* method =
                              (WOLFSSL_METHOD*) XMALLOC(sizeof(WOLFSSL_METHOD),
                                                     heap, DYNAMIC_TYPE_METHOD);
        (void)heap;
        if (method) {
#ifndef NO_SHA256         /* 1.2 requires SHA256 */
            InitSSL_Method(method, MakeTLSv1_2());
#else
            InitSSL_Method(method, MakeTLSv1_1());
#endif
            method->side      = WOLFSSL_SERVER_END;
#ifndef NO_OLD_TLS
            method->downgrade = 1;
#endif /* !NO_OLD_TLS */
        }
        return method;
    }


#endif /* NO_WOLFSSL_SERVER */
#endif /* NO_TLS */
#endif /* WOLFCRYPT_ONLY */
