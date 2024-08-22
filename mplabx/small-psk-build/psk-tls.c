/* psk-tls.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


/* combining all TLS 1.2 components needed for a bare static psk connection */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFCRYPT_ONLY

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_RENESAS_TSIP_TLS)
    #include <wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h>
#endif

#include <wolfssl/wolfcrypt/hpke.h>

#ifndef NO_TLS

#ifndef WOLFSSL_NO_TLS12

#ifdef WOLFSSL_SHA384
    #define HSHASH_SZ WC_SHA384_DIGEST_SIZE
#else
    #define HSHASH_SZ FINISHED_SZ
#endif

int BuildTlsHandshakeHash(WOLFSSL* ssl, byte* hash, word32* hashLen)
{
    int ret = 0;
    word32 hashSz = FINISHED_SZ;

    if (ssl == NULL || hash == NULL || hashLen == NULL || *hashLen < (word32)HSHASH_SZ)
        return BAD_FUNC_ARG;

    /* for constant timing perform these even if error */
#ifndef NO_OLD_TLS
    ret |= wc_Md5GetHash(&ssl->hsHashes->hashMd5, hash);
    ret |= wc_ShaGetHash(&ssl->hsHashes->hashSha, &hash[WC_MD5_DIGEST_SIZE]);
#endif
    if (IsAtLeastTLSv1_2(ssl)) {
#ifndef NO_SHA256
        if (ssl->specs.mac_algorithm <= (byte)sha256_mac ||
            ssl->specs.mac_algorithm == (byte)blake2b_mac) {
#ifdef WOLFSSL_NO_HASH_COPY
            ret |= wc_Sha256Final(&ssl->hsHashes->hashSha256, hash);
#else
            ret |= wc_Sha256GetHash(&ssl->hsHashes->hashSha256, hash);
#endif
            hashSz = WC_SHA256_DIGEST_SIZE;
        }
#endif
#ifdef WOLFSSL_SHA384
        if (ssl->specs.mac_algorithm == sha384_mac) {
            ret |= wc_Sha384GetHash(&ssl->hsHashes->hashSha384, hash);
            hashSz = WC_SHA384_DIGEST_SIZE;
        }
#endif
#ifdef WOLFSSL_SM3
        if (ssl->specs.mac_algorithm == sm3_mac) {
            ret |= wc_Sm3GetHash(&ssl->hsHashes->hashSm3, hash);
            hashSz = WC_SM3_DIGEST_SIZE;
        }
#endif
    }

    *hashLen = hashSz;
#ifdef WOLFSSL_CHECK_MEM_ZERO
     wc_MemZero_Add("TLS handshake hash", hash, hashSz);
#endif
     
    if (ret != 0) {
        ret = BUILD_MSG_ERROR;
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    return ret;
}


int BuildTlsFinished(WOLFSSL* ssl, Hashes* hashes, byte srvr)
{
    const byte kTlsClientFinStr[FINISHED_LABEL_SZ + 1] = "client finished";
    const byte kTlsServerFinStr[FINISHED_LABEL_SZ + 1] = "server finished";
    int ret;
    const byte* side = NULL;
    word32 hashSz = HSHASH_SZ;
#if !defined(WOLFSSL_ASYNC_CRYPT) || defined(WC_ASYNC_NO_HASH)
    byte handshake_hash[HSHASH_SZ];
#else
    WC_DECLARE_VAR(handshake_hash, byte, HSHASH_SZ, ssl->heap);
    WC_ALLOC_VAR(handshake_hash, byte, HSHASH_SZ, ssl->heap);
    if (handshake_hash == NULL)
        return MEMORY_E;
#endif

    XMEMSET(handshake_hash, 0, HSHASH_SZ);
    

    ret = BuildTlsHandshakeHash(ssl, handshake_hash, &hashSz);
    if (ret == 0) {
        if (srvr == 0u) {
            side = kTlsClientFinStr;
        }
        else if (srvr == 1u) {
            side = kTlsServerFinStr;
        }
        else {
            ret = BAD_FUNC_ARG;
            WOLFSSL_MSG("Unexpected sender value");
        }
    }
    
    if (ret == 0) {
#ifdef WOLFSSL_HAVE_PRF
        {
            PRIVATE_KEY_UNLOCK();
            ret = wc_PRF_TLS((byte*)hashes, TLS_FINISHED_SZ,
                      ssl->arrays->masterSecret, SECRET_LEN, side,
                      FINISHED_LABEL_SZ, handshake_hash, hashSz,
                      IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm,
                      ssl->heap,
                      INVALID_DEVID);
            PRIVATE_KEY_LOCK();
        }
#ifndef WOLFSSL_NO_FORCE_ZERO
        ForceZero(handshake_hash, hashSz);
#endif
#else
        /* Pseudo random function must be enabled in the configuration. */
        ret = PRF_MISSING;
        WOLFSSL_ERROR_VERBOSE(ret);
        WOLFSSL_MSG("Pseudo-random function is not enabled");

        (void)side;
        (void)hashes;
#endif
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WC_ASYNC_NO_HASH)
    WC_FREE_VAR(handshake_hash, ssl->heap);
#elif defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(handshake_hash, HSHASH_SZ);
#endif

    return ret;
}

#endif /* !WOLFSSL_NO_TLS12 */

#ifndef WOLFSSL_NO_TLS12

ProtocolVersion MakeTLSv1_2(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_2_MINOR;

    return pv;
}

#endif /* !WOLFSSL_NO_TLS12 */

#ifdef WOLFSSL_TLS13
/* The TLS v1.3 protocol version.
 *
 * returns the protocol version data for TLS v1.3.
 */
ProtocolVersion MakeTLSv1_3(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = TLSv1_3_MINOR;

    return pv;
}
#endif


#ifndef WOLFSSL_NO_TLS12

#ifdef HAVE_EXTENDED_MASTER
static const byte ext_master_label[EXT_MASTER_LABEL_SZ + 1] =
                                                      "extended master secret";
#endif

#ifdef HAVE_EXTENDED_MASTER

static int _MakeTlsExtendedMasterSecret(byte* ms, word32 msLen,
                                        const byte* pms, word32 pmsLen,
                                        const byte* sHash, word32 sHashLen,
                                        int tls1_2, int hash_type,
                                        void* heap, int devId)
{
    int ret;

#ifdef WOLFSSL_HAVE_PRF
    PRIVATE_KEY_UNLOCK();
    ret = wc_PRF_TLS(ms, msLen, pms, pmsLen, ext_master_label, EXT_MASTER_LABEL_SZ,
               sHash, sHashLen, tls1_2, hash_type, heap, devId);
    PRIVATE_KEY_LOCK();
#else
    /* Pseudo random function must be enabled in the configuration. */
    ret = PRF_MISSING;
    WOLFSSL_MSG("Pseudo-random function is not enabled");

    (void)ms;
    (void)msLen;
    (void)pms;
    (void)pmsLen;
    (void)sHash;
    (void)sHashLen;
    (void)tls1_2;
    (void)hash_type;
    (void)heap;
    (void)devId;
#endif
    return ret;
}

/* External facing wrapper so user can call as well, 0 on success */
int wolfSSL_MakeTlsExtendedMasterSecret(byte* ms, word32 msLen,
                                        const byte* pms, word32 pmsLen,
                                        const byte* sHash, word32 sHashLen,
                                        int tls1_2, int hash_type)
{
    return _MakeTlsExtendedMasterSecret(ms, msLen, pms, pmsLen, sHash, sHashLen,
        tls1_2, hash_type, NULL, INVALID_DEVID);
}

#endif /* HAVE_EXTENDED_MASTER */


int wolfSSL_SetTlsHmacInner(WOLFSSL* ssl, byte* inner, word32 sz, int content,
                           int verify)
{
    if (ssl == NULL || inner == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(inner, 0, WOLFSSL_TLS_HMAC_INNER_SZ);

    WriteSEQ(ssl, verify, inner);
    inner[SEQ_SZ] = (byte)content;
    inner[SEQ_SZ + ENUM_LEN]            = ssl->version.major;
    inner[SEQ_SZ + ENUM_LEN + ENUM_LEN] = ssl->version.minor;
    c16toa((word16)sz, inner + SEQ_SZ + ENUM_LEN + VERSION_SZ);

    return 0;
}


#ifndef WOLFSSL_AEAD_ONLY
#if !defined(WOLFSSL_NO_HASH_RAW) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)


#ifdef NO_HASH_WRAPPER
/* SHA256 only small code build without HASH wrappers.
 * Finalize the HMAC by performing outer hash.
 *
 * hmac  HMAC object.
 * mac   MAC result.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_OuterHash(Hmac* hmac, unsigned char* mac)
{
    int ret = BAD_FUNC_ARG;
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha256 *hash = NULL;
#else
    wc_Sha256 hash[1];
#endif
    enum wc_HashType hashType = (enum wc_HashType)hmac->macType;
    word32 digestSz = WC_SHA256_DIGEST_SIZE;
    word32 blockSz = WC_SHA256_BLOCK_SIZE;

    if (hashType != WC_HASH_TYPE_SHA256) {
        return BAD_FUNC_ARG;
    }
    
#ifdef WOLFSSL_SMALL_STACK
    hash = (wc_Sha256*)XMALLOC(sizeof(wc_Sha256), NULL, DYNAMIC_TYPE_HASH_TMP);
    if (hash == NULL) {
        return MEMORY_E;
    }
#endif
    
    if ((digestSz >= 0u) && (blockSz >= 0u)) {
        ret = wc_InitSha256(hash);
    }
    if (ret == 0) {
        ret = wc_Sha256Update(hash, (byte*)hmac->opad,
            blockSz);
        if (ret == 0)
            ret = wc_Sha256Update(hash, (byte*)hmac->innerHash,
                digestSz);
        if (ret == 0)
            ret = wc_Sha256Final(hash, mac);
        wc_Sha256Free(hash);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(hash, NULL, DYNAMIC_TYPE_HASH_TMP);
#endif
    return ret;
}
#else
/* Finalize the HMAC by performing outer hash.
 *
 * hmac  HMAC object.
 * mac   MAC result.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_OuterHash(Hmac* hmac, unsigned char* mac)
{
    int ret = BAD_FUNC_ARG;
#ifdef WOLFSSL_SMALL_STACK
    wc_HashAlg *hash = NULL;
#else
    wc_HashAlg hash[1];
#endif
    enum wc_HashType hashType = (enum wc_HashType)hmac->macType;
    int digestSz = wc_HashGetDigestSize(hashType);
    int blockSz = wc_HashGetBlockSize(hashType);

#ifdef WOLFSSL_SMALL_STACK
    hash = (wc_HashAlg*)XMALLOC(sizeof(wc_HashAlg), NULL, DYNAMIC_TYPE_HASH_TMP);
    if (hash == NULL) {
        return MEMORY_E;
    }
#endif
    
    if ((digestSz >= 0) && (blockSz >= 0)) {
        ret = wc_HashInit(hash, hashType);
    }
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, hashType, (byte*)hmac->opad,
            (word32)blockSz);
        if (ret == 0)
            ret = wc_HashUpdate(&hash, hashType, (byte*)hmac->innerHash,
                (word32)digestSz);
        if (ret == 0)
            ret = wc_HashFinal(hash, hashType, mac);
        wc_HashFree(hash, hashType);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(hash, NULL, DYNAMIC_TYPE_HASH_TMP);
#endif
    return ret;
}
#endif

/* Calculate the HMAC of the header + message data.
 * Constant time implementation using wc_Sha*FinalRaw().
 *
 * hmac    HMAC object.
 * digest  MAC result.
 * in      Message data.
 * sz      Size of the message data.
 * header  Constructed record header with length of handshake data.
 * returns 0 on success, otherwise failure.
 */
static int Hmac_UpdateFinal_CT(Hmac* hmac, byte* digest, const byte* in,
                               word32 sz, int macLen, byte* header)
{
    byte         lenBytes[8];
    int          i, j;
    unsigned int k;
    int          blockBits, blockMask;
    int          lastBlockLen, extraLen, eocIndex;
    int          blocks, safeBlocks, lenBlock, eocBlock;
    unsigned int maxLen;
    int          blockSz, padSz;
    int          ret;
    word32       realLen;
    byte         extraBlock;

    switch (hmac->macType) {
    #ifndef NO_SHA
        case WC_SHA:
            blockSz = WC_SHA_BLOCK_SIZE;
            blockBits = 6;
            padSz = WC_SHA_BLOCK_SIZE - WC_SHA_PAD_SIZE + 1;
            break;
    #endif /* !NO_SHA */

    #ifndef NO_SHA256
        case WC_SHA256:
            blockSz = WC_SHA256_BLOCK_SIZE;
            blockBits = 6;
            padSz = WC_SHA256_BLOCK_SIZE - WC_SHA256_PAD_SIZE + 1;
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            blockSz = WC_SHA384_BLOCK_SIZE;
            blockBits = 7;
            padSz = WC_SHA384_BLOCK_SIZE - WC_SHA384_PAD_SIZE + 1;
            break;
    #endif /* WOLFSSL_SHA384 */

    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
            blockSz = WC_SHA512_BLOCK_SIZE;
            blockBits = 7;
            padSz = WC_SHA512_BLOCK_SIZE - WC_SHA512_PAD_SIZE + 1;
            break;
    #endif /* WOLFSSL_SHA512 */

    #ifdef WOLFSSL_SM3
        case WC_SM3:
            blockSz = WC_SM3_BLOCK_SIZE;
            blockBits = 6;
            padSz = WC_SM3_BLOCK_SIZE - WC_SM3_PAD_SIZE + 1;
            break;
    #endif /* WOLFSSL_SM3 */

        default:
            return BAD_FUNC_ARG;
    }
    blockMask = blockSz - 1;

    /* Size of data to HMAC if padding length byte is zero. */
    maxLen = WOLFSSL_TLS_HMAC_INNER_SZ + sz - 1 - (unsigned int)macLen;
    /* Complete data (including padding) has block for EOC and/or length. */
    extraBlock = (byte)ctSetLTE((maxLen + (unsigned int)padSz) & blockMask, padSz);
    /* Total number of blocks for data including padding. */
    blocks = ((maxLen + blockSz - 1) >> blockBits) + extraBlock;
    /* Up to last 6 blocks can be hashed safely. */
    safeBlocks = blocks - 6;

    if (sz < 1u)
        return BAD_FUNC_ARG;

    /* Length of message data. */
    realLen = maxLen - in[sz - 1];
    /* Number of message bytes in last block. */
    lastBlockLen = realLen & blockMask;
    /* Number of padding bytes in last block. */
    extraLen = ((blockSz * 2 - padSz - lastBlockLen) & blockMask) + 1;
    /* Number of blocks to create for hash. */
    lenBlock = (realLen + extraLen) >> blockBits;
    /* Block containing EOC byte. */
    eocBlock = realLen >> blockBits;
    /* Index of EOC byte in block. */
    eocIndex = realLen & blockMask;

    /* Add length of hmac's ipad to total length. */
    realLen += blockSz;
    /* Length as bits - 8 bytes bigendian. */
    c32toa(realLen >> ((sizeof(word32) * 8) - 3), lenBytes);
    c32toa(realLen << 3, lenBytes + sizeof(word32));

    ret = wc_Sha256Update(&hmac->hash.sha256, (unsigned char*)hmac->ipad, (word32)blockSz);
    if (ret != 0)
        return ret;

    XMEMSET(hmac->innerHash, 0, macLen);

    if (safeBlocks > 0) {
        ret = wc_Sha256Update(&hmac->hash.sha256, header, WOLFSSL_TLS_HMAC_INNER_SZ);
        if (ret != 0)
            return ret;
        ret = wc_Sha256Update(&hmac->hash.sha256, in, safeBlocks * blockSz -
                                                     WOLFSSL_TLS_HMAC_INNER_SZ);
        if (ret != 0)
            return ret;
    }
    else
        safeBlocks = 0;

    XMEMSET(digest, 0, macLen);
    k = (unsigned int)(safeBlocks * blockSz);
    for (i = safeBlocks; i < blocks; i++) {
#ifdef WOLFSSL_SMALL_STACK
        unsigned char* hashBlock;
#else
        unsigned char hashBlock[WC_MAX_BLOCK_SIZE];
#endif
        unsigned char isEocBlock = ctMaskEq(i, eocBlock);
        unsigned char isOutBlock = ctMaskEq(i, lenBlock);

#ifdef WOLFSSL_SMALL_STACK
        hashBlock = (unsigned char*)XMALLOC(WC_MAX_BLOCK_SIZE, NULL, DYNAMIC_TYPE_HMAC);
        if (hashBlock == NULL)
            return MEMORY_E;
#endif
        
        for (j = 0; j < blockSz; j++) {
            unsigned char atEoc = ctMaskEq(j, eocIndex) & isEocBlock;
            unsigned char pastEoc = ctMaskGT(j, eocIndex) & isEocBlock;
            unsigned char b = 0;

            if (k < (unsigned int)WOLFSSL_TLS_HMAC_INNER_SZ)
                b = header[k];
            else if (k < maxLen)
                b = in[k - WOLFSSL_TLS_HMAC_INNER_SZ];
            k++;

            b = ctMaskSel(atEoc, 0x80, b);
            b &= (unsigned char)~(word32)pastEoc;
            b &= ((unsigned char)~(word32)isOutBlock) | isEocBlock;

            if (j >= blockSz - 8) {
                b = ctMaskSel(isOutBlock, lenBytes[j - (blockSz - 8)], b);
            }

            hashBlock[j] = b;
        }

        ret = wc_Sha256Update(&hmac->hash.sha256, hashBlock, (word32)blockSz);
        if (ret != 0)
            return ret;
        ret = wc_Sha256FinalRaw(&hmac->hash.sha256, hashBlock);
        if (ret != 0)
            return ret;
        for (j = 0; j < macLen; j++)
            ((unsigned char*)hmac->innerHash)[j] |= hashBlock[j] & isOutBlock;
#ifdef WOLFSSL_SMALL_STACK
        XFREE(hashBlock, NULL, DYNAMIC_TYPE_HMAC);
#endif
    }

    ret = Hmac_OuterHash(hmac, digest);

    return ret;
}

#endif

int TLS_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz, int padSz,
             int content, int verify, int epochOrder)
{
#ifdef WOLFSSL_SMALL_STACK
    Hmac*  hmac = NULL;
    byte   myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
#else
    Hmac   hmac[1];
    byte   myInner[WOLFSSL_TLS_HMAC_INNER_SZ];
#endif
    int    ret = 0;
    const byte* macSecret = NULL;
#ifdef WOLFSSL_LEANPSK_STATIC
    byte hashSz = 0;
#else
    word32 hashSz = 0;
#endif

    if (ssl == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    hmac = (Hmac*)XMALLOC(sizeof(Hmac), NULL, DYNAMIC_TYPE_HMAC);
    if (hmac == NULL)
        return MEMORY_E;
#endif
    
#ifdef HAVE_TRUNCATED_HMAC
    hashSz = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                        : ssl->specs.hash_size;
#else
    hashSz = ssl->specs.hash_size;
#endif

    wolfSSL_SetTlsHmacInner(ssl, myInner, sz, content, verify);
    ret = wc_HmacInit(hmac, ssl->heap,INVALID_DEVID);
    if (ret != 0)
        return ret;


#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls)
        macSecret = wolfSSL_GetDtlsMacSecret(ssl, verify, epochOrder);
    else
        macSecret = wolfSSL_GetMacSecret(ssl, verify);
#elif defined(WOLFSSL_LEANPSK) && defined(NO_WOLFSSL_SERVER)
    if (verify) {
        macSecret = (const byte*)(ssl->keys->keys + WC_MAX_DIGEST_SIZE);
    }
    else
    {
        macSecret = (const byte*)ssl->keys->keys;
    }
#else
    macSecret = wolfSSL_GetMacSecret(ssl, verify);
#endif
    ret = wc_HmacSetKey(hmac, WC_SHA256, macSecret, ssl->specs.hash_size

            );

    if (ret == 0) {
        /* Constant time verification required. */
        if (verify && padSz >= 0) {
#if !defined(WOLFSSL_NO_HASH_RAW) && !defined(HAVE_FIPS) && \
    !defined(HAVE_SELFTEST)
            {
                ret = Hmac_UpdateFinal_CT(hmac, digest, in,
                                      sz + hashSz + padSz + 1, hashSz, myInner);
            }
#else
            ret = Hmac_UpdateFinal(hmac, digest, in, sz + hashSz + padSz + 1,
                                                                       myInner);
#endif
        }
        else {
            ret = wc_HmacUpdate (hmac, myInner, WOLFSSL_TLS_HMAC_INNER_SZ);
            if (ret == 0)
                ret = wc_HmacUpdate(hmac, in, sz);                /* content */
            if (ret == 0)
                ret = wc_HmacFinal(hmac, digest);
        }
    }

    wc_HmacFree(hmac);

#ifdef WOLFSSL_SMALL_STACK
        //XFREE(myInner, NULL, DYNAMIC_TYPE_HMAC);
    XFREE(hmac, NULL, DYNAMIC_TYPE_HMAC);
#endif
    return ret;
}
#endif /* WOLFSSL_AEAD_ONLY */

#endif /* !WOLFSSL_NO_TLS12 */

#ifndef NO_WOLFSSL_CLIENT

#ifndef WOLFSSL_NO_TLS12
    WOLFSSL_ABI
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
        WOLFSSL_ENTER("TLSv1_2_client_method_ex");
        if (method)
            InitSSL_Method(method, MakeTLSv1_2());
        return method;
    }
#endif /* WOLFSSL_NO_TLS12 */

#endif /* NO_WOLFSSL_CLIENT */

#endif /* NO_TLS */

#endif /* WOLFCRYPT_ONLY */

 
int SetCipherSpecs(WOLFSSL* ssl)
{
    int ret = GetCipherSpec(ssl->options.side, ssl->options.cipherSuite0,
                                ssl->options.cipherSuite, &ssl->specs,
                                &ssl->options);
    if (ret == 0) {
        /* set TLS if it hasn't been turned off */
        if (ssl->version.major == SSLv3_MAJOR &&
                ssl->version.minor >= TLSv1_MINOR) {
    #ifndef NO_TLS
            ssl->options.tls = 1;
            if (ssl->version.minor >= TLSv1_1_MINOR) {
                ssl->options.tls1_1 = 1;
                if (ssl->version.minor >= TLSv1_3_MINOR)
                    ssl->options.tls1_3 = 1;
            }
    #endif
        }

    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (IsAtLeastTLSv1_3(ssl->version) || ssl->specs.cipher_type != block)
           ssl->options.encThenMac = 0;
    #endif

    }
    return ret;
}

/**
 * Populate specs with the specification of the chosen ciphersuite. If opts is
 * not NULL then the appropriate options will also be set.
 *
 * @param side         [in] WOLFSSL_SERVER_END or WOLFSSL_CLIENT_END
 * @param cipherSuite0 [in]
 * @param cipherSuite  [in]
 * @param specs        [out] CipherSpecs
 * @param opts         [in/out] Options can be NULL
 * @return
 */
int GetCipherSpec(word16 side, byte cipherSuite0, byte cipherSuite,
                      CipherSpecs* specs, Options* opts)
{
    word16 havePSK = 0;
    (void)havePSK;
    (void)side;
#if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
    if (opts != NULL)
        havePSK = opts->havePSK;
#endif
    if (cipherSuite != TLS_PSK_WITH_AES_128_CBC_SHA256)
        return UNSUPPORTED_SUITE;

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->block_size            = AES_BLOCK_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
#endif

    if (specs->sig_algo == anonymous_sa_algo && opts != NULL) {
        /* CLIENT/SERVER: No peer authentication to be performed. */
        opts->peerAuthGood = 1;
    }

    return 0;
}


enum KeyStuff {
    MASTER_ROUNDS = 3,
    PREFIX        = 3,     /* up to three letters for master prefix */
    KEY_PREFIX    = 9      /* up to 9 prefix letters for key rounds */


};


/* Master wrapper, doesn't use SSL stack space in TLS mode */
int LeanPSKMakeMasterSecret(WOLFSSL* ssl, byte* keyLabel)
{
    /* append secret to premaster : premaster | SerSi | CliSi */
    int ret = 0;
    {
        byte master_label[MASTER_LABEL_SZ + 1] = "master secret";
        PRIVATE_KEY_UNLOCK();
        ret = wc_PRF_TLS(ssl->arrays->masterSecret, SECRET_LEN,
                ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
                master_label, MASTER_LABEL_SZ, ssl->arrays->csRandom, SEED_LEN,
                1, ssl->specs.mac_algorithm, ssl->heap, INVALID_DEVID);
        PRIVATE_KEY_LOCK();
    }

    if (ret == 0) {
        int   key_dig_len = 2 * ssl->specs.hash_size +
                            2 * AES_128_KEY_SIZE  +
                            2 * AES_IV_SIZE;
        byte seed[SEED_LEN];
        
        XMEMCPY(seed,           ssl->arrays->csRandom + RAN_LEN, RAN_LEN);
        XMEMCPY(seed + RAN_LEN, ssl->arrays->csRandom, RAN_LEN);

        PRIVATE_KEY_UNLOCK();
        ret = wc_PRF_TLS(ssl->keys->keys, key_dig_len,
                ssl->arrays->masterSecret, SECRET_LEN, keyLabel,
                KEY_LABEL_SZ, (const byte*)seed, SEED_LEN,
                IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm, ssl->heap,
                INVALID_DEVID);
        PRIVATE_KEY_LOCK();
    }

    return ret;
}


#ifndef NO_KDF


#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#ifdef WC_SRTP_KDF
#include <wolfssl/wolfcrypt/aes.h>
#endif

#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC)

/* Wrapper for TLS 1.2 and TLSv1 cases to calculate PRF */
/* In TLS 1.2 case call straight thru to wc_PRF */
int wc_PRF_TLS(byte* digest, word32 digLen, const byte* secret, word32 secLen,
            const byte* label, word32 labLen, const byte* seed, word32 seedLen,
            int useAtLeastSha256, int hash_type, void* heap, int devId)
{
    int ret = 0;
    byte times;
    byte lastLen;
    byte lastTime;
    
#ifdef WOLFSSL_SMALL_STACK
    byte*  current;
    byte   previous[WC_SHA256_DIGEST_SIZE];  /* max size */
    Hmac*  hmac;
#else
    byte   previous[P_HASH_MAX_SIZE];  /* max size */
    byte   current[P_HASH_MAX_SIZE];   /* max size */
    Hmac   hmac[1];
#endif

    if (useAtLeastSha256) {
    #ifdef WOLFSSL_SMALL_STACK
        byte* labelSeed;
    #else
        byte  labelSeed[MAX_PRF_LABSEED];
    #endif

        if (labLen + seedLen > (word32)MAX_PRF_LABSEED) {
            return BUFFER_E;
        }

    #ifdef WOLFSSL_SMALL_STACK
        labelSeed = (byte*)XMALLOC(MAX_PRF_LABSEED, NULL, DYNAMIC_TYPE_DIGEST);
        if (labelSeed == NULL) {
            return MEMORY_E;
        }
    #endif

        XMEMCPY(labelSeed, label, labLen);
        XMEMCPY(labelSeed + labLen, seed, seedLen);

        /* If a cipher suite wants an algorithm better than sha256, it
         * should use better. */
        if (hash_type < sha256_mac || hash_type == blake2b_mac) {
            hash_type = sha256_mac;
        }

        times   = digLen / WC_SHA256_DIGEST_SIZE;
        lastLen = digLen % WC_SHA256_DIGEST_SIZE;

        if (lastLen)
            times += 1;


        /* times == 0 if resLen == 0, but times == 0 abides clang static analyzer
           while resLen == 0 doesn't */
        if (times == 0u)
            return BAD_FUNC_ARG;

        lastTime = times - 1U;

    #ifdef WOLFSSL_SMALL_STACK
        current  = (byte*)XMALLOC(WC_SHA256_DIGEST_SIZE, heap, DYNAMIC_TYPE_DIGEST);
        hmac     = (Hmac*)XMALLOC(sizeof(Hmac),    heap, DYNAMIC_TYPE_HMAC);
        if (hmac == NULL || current == NULL) {
            if (current)  XFREE(current,  heap, DYNAMIC_TYPE_DIGEST);
            if (hmac)     XFREE(hmac,     heap, DYNAMIC_TYPE_HMAC);
            return MEMORY_E;
        }
    #endif
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        XMEMSET(previous, 0xff, P_HASH_MAX_SIZE);
        wc_MemZero_Add("wc_PRF previous", previous, P_HASH_MAX_SIZE);
        wc_MemZero_Add("wc_PRF current", current, P_HASH_MAX_SIZE);
        wc_MemZero_Add("wc_PRF hmac", hmac, sizeof(Hmac));
    #endif

        ret = wc_HmacInit(hmac, heap, devId);
        if (ret == 0) {
            ret = wc_HmacSetKey(hmac, WC_SHA256, secret, secLen);
            if (ret == 0) {
                ret = wc_HmacUpdate(hmac, labelSeed, labLen + seedLen); /* A0 = seed */
            }
            if (ret == 0) {
                ret = wc_HmacFinal(hmac, previous);       /* A1 */
            }
            if (ret == 0) {
                byte i;
                word32 idx = 0;

                for (i = 0; i < times; i++) {
                    ret = wc_HmacUpdate(hmac, previous, WC_SHA256_DIGEST_SIZE);
                    if (ret != 0)
                        break;
                    ret = wc_HmacUpdate(hmac, labelSeed, labLen + seedLen);
                    if (ret != 0)
                        break;
                    ret = wc_HmacFinal(hmac, current);
                    if (ret != 0)
                        break;

                    if ((i == lastTime) && lastLen)
                        XMEMCPY(&digest[idx], current,
                                                 min(lastLen, WC_SHA256_DIGEST_SIZE));
                    else {
                        XMEMCPY(&digest[idx], current, WC_SHA256_DIGEST_SIZE);
                        idx += WC_SHA256_DIGEST_SIZE;
                        ret = wc_HmacUpdate(hmac, previous, WC_SHA256_DIGEST_SIZE);
                        if (ret != 0)
                            break;
                        ret = wc_HmacFinal(hmac, previous);
                        if (ret != 0)
                            break;
                    }
                }
            }
            wc_HmacFree(hmac);
        }


    #ifndef WOLFSSL_NO_FORCE_ZERO
        ForceZero(previous,  P_HASH_MAX_SIZE);
        ForceZero(current,   P_HASH_MAX_SIZE);
        ForceZero(hmac,      sizeof(Hmac));

    #if defined(WOLFSSL_CHECK_MEM_ZERO)
        wc_MemZero_Check(previous, P_HASH_MAX_SIZE);
        wc_MemZero_Check(current,  P_HASH_MAX_SIZE);
        wc_MemZero_Check(hmac,     sizeof(Hmac));
    #endif
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(current,  heap, DYNAMIC_TYPE_DIGEST);
        XFREE(hmac,     heap, DYNAMIC_TYPE_HMAC);
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(labelSeed, NULL, DYNAMIC_TYPE_DIGEST);
    #endif
#define WOLFSSL_SMALL_STACK
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    return ret;
}
#endif /* WOLFSSL_HAVE_PRF && !NO_HMAC */

#endif /* NO_KDF */

