/* kdf.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifndef NO_KDF

#if FIPS_VERSION3_GE(5,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

    #ifdef USE_WINDOWS_API
        #pragma code_seg(".fipsA$h")
        #pragma const_seg(".fipsB$h")
    #endif
#endif


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

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_kdf_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000009 };
    int wolfCrypt_FIPS_KDF_sanity(void)
    {
        return 0;
    }
#endif

#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC)

#ifdef WOLFSSL_SHA512
    #define P_HASH_MAX_SIZE WC_SHA512_DIGEST_SIZE
#elif defined(WOLFSSL_SHA384)
    #define P_HASH_MAX_SIZE WC_SHA384_DIGEST_SIZE
#else
    #define P_HASH_MAX_SIZE WC_SHA256_DIGEST_SIZE
#endif

/* Pseudo Random Function for MD5, SHA-1, SHA-256, SHA-384, or SHA-512 */
int wc_PRF(byte* result, word32 resLen, const byte* secret,
                  word32 secLen, const byte* seed, word32 seedLen, int hash,
                  void* heap, int devId)
{
    word32 len = P_HASH_MAX_SIZE;
    word32 times;
    word32 lastLen;
    word32 lastTime;
    int    ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte*  current;
    Hmac*  hmac;
#else
    byte   current[P_HASH_MAX_SIZE];   /* max size */
    Hmac   hmac[1];
#endif

    switch (hash) {
    #ifndef NO_MD5
        case md5_mac:
            hash = WC_MD5;
            len  = WC_MD5_DIGEST_SIZE;
        break;
    #endif

    #ifndef NO_SHA256
        case sha256_mac:
            hash = WC_SHA256;
            len  = WC_SHA256_DIGEST_SIZE;
        break;
    #endif

    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            hash = WC_SHA384;
            len  = WC_SHA384_DIGEST_SIZE;
        break;
    #endif

    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            hash = WC_SHA512;
            len  = WC_SHA512_DIGEST_SIZE;
        break;
    #endif

    #ifdef WOLFSSL_SM3
        case sm3_mac:
            hash = WC_SM3;
            len  = WC_SM3_DIGEST_SIZE;
        break;
    #endif

    #ifndef NO_SHA
        case sha_mac:
            hash = WC_SHA;
            len  = WC_SHA_DIGEST_SIZE;
        break;
    #endif
        default:
            return HASH_TYPE_E;
    }

    times   = resLen / len;
    lastLen = resLen % len;

    if (lastLen)
        times += 1;

    /* times == 0 if resLen == 0, but times == 0 abides clang static analyzer
       while resLen == 0 doesn't */
    if (times == 0)
        return BAD_FUNC_ARG;

    lastTime = times - 1;

#ifdef WOLFSSL_SMALL_STACK
    current = (byte*)XMALLOC(P_HASH_MAX_SIZE, heap, DYNAMIC_TYPE_DIGEST);
    hmac    = (Hmac*)XMALLOC(sizeof(Hmac),    heap, DYNAMIC_TYPE_HMAC);
    if (current == NULL || hmac == NULL) {
        XFREE(current, heap, DYNAMIC_TYPE_DIGEST);
        XFREE(hmac, heap, DYNAMIC_TYPE_HMAC);
        return MEMORY_E;
    }
#endif
#ifdef WOLFSSL_CHECK_MEM_ZERO
    XMEMSET(current, 0xff, P_HASH_MAX_SIZE);
    wc_MemZero_Add("wc_PRF current", current, P_HASH_MAX_SIZE);
    wc_MemZero_Add("wc_PRF hmac", hmac, sizeof(Hmac));
#endif

    ret = wc_HmacInit(hmac, heap, devId);
    if (ret == 0) {
        ret = wc_HmacSetKey(hmac, hash, secret, secLen);
        if (ret == 0)
            ret = wc_HmacUpdate(hmac, seed, seedLen); /* A0 = seed */
        if (ret == 0)
            ret = wc_HmacFinal(hmac, current);        /* A1 */
        if (ret == 0) {
            word32 i;
            word32 idx = 0;

            for (i = 0; i < times; i++) {
                ret = wc_HmacUpdate(hmac, current, len);
                if (ret != 0)
                    break;
                ret = wc_HmacUpdate(hmac, seed, seedLen);
                if (ret != 0)
                    break;
                if ((i != lastTime) || !lastLen) {
                    ret = wc_HmacFinal(hmac, &result[idx]);
                    if (ret != 0)
                        break;
                    idx += len;

                    ret = wc_HmacUpdate(hmac, current, len);
                    if (ret != 0)
                        break;
                    ret = wc_HmacFinal(hmac, current);
                    if (ret != 0)
                        break;
                }
                else {
                    ret = wc_HmacFinal(hmac, current);
                    if (ret != 0)
                        break;
                    XMEMCPY(&result[idx], current,
                                             min(lastLen, P_HASH_MAX_SIZE));
                }
            }
        }
        wc_HmacFree(hmac);
    }

    ForceZero(current, P_HASH_MAX_SIZE);
    ForceZero(hmac,    sizeof(Hmac));

#if defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(current, P_HASH_MAX_SIZE);
    wc_MemZero_Check(hmac,    sizeof(Hmac));
#endif

#ifdef WOLFSSL_SMALL_STACK
    XFREE(current, heap, DYNAMIC_TYPE_DIGEST);
    XFREE(hmac,     heap, DYNAMIC_TYPE_HMAC);
#endif

    return ret;
}
#undef P_HASH_MAX_SIZE

/* compute PRF (pseudo random function) using SHA1 and MD5 for TLSv1 */
int wc_PRF_TLSv1(byte* digest, word32 digLen, const byte* secret,
           word32 secLen, const byte* label, word32 labLen,
           const byte* seed, word32 seedLen, void* heap, int devId)
{
    int         ret  = 0;
    word32      half = (secLen + 1) / 2;
    const byte* md5_half;
    const byte* sha_half;
    byte*      md5_result;
#ifdef WOLFSSL_SMALL_STACK
    byte*      sha_result;
    byte*      labelSeed;
#else
    byte       sha_result[MAX_PRF_DIG];    /* digLen is real size */
    byte       labelSeed[MAX_PRF_LABSEED];
#endif

    if (half > MAX_PRF_HALF ||
        labLen + seedLen > MAX_PRF_LABSEED ||
        digLen > MAX_PRF_DIG)
    {
        return BUFFER_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    sha_result = (byte*)XMALLOC(MAX_PRF_DIG, heap, DYNAMIC_TYPE_DIGEST);
    labelSeed = (byte*)XMALLOC(MAX_PRF_LABSEED, heap, DYNAMIC_TYPE_DIGEST);
    if (sha_result == NULL || labelSeed == NULL) {
        XFREE(sha_result, heap, DYNAMIC_TYPE_DIGEST);
        XFREE(labelSeed, heap, DYNAMIC_TYPE_DIGEST);
        return MEMORY_E;
    }
#endif

    md5_half = secret;
    sha_half = secret + half - secLen % 2;
    md5_result = digest;

    XMEMCPY(labelSeed, label, labLen);
    XMEMCPY(labelSeed + labLen, seed, seedLen);

    if ((ret = wc_PRF(md5_result, digLen, md5_half, half, labelSeed,
                                labLen + seedLen, md5_mac, heap, devId)) == 0) {
        if ((ret = wc_PRF(sha_result, digLen, sha_half, half, labelSeed,
                                labLen + seedLen, sha_mac, heap, devId)) == 0) {
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Add("wc_PRF_TLSv1 sha_result", sha_result, digLen);
        #endif
            /* calculate XOR for TLSv1 PRF */
            /* md5 result is placed directly in digest */
            xorbuf(digest, sha_result, digLen);
            ForceZero(sha_result, digLen);
        }
    }

#if defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(sha_result, MAX_PRF_DIG);
#endif

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha_result, heap, DYNAMIC_TYPE_DIGEST);
    XFREE(labelSeed, heap, DYNAMIC_TYPE_DIGEST);
#endif

    return ret;
}

/* Wrapper for TLS 1.2 and TLSv1 cases to calculate PRF */
/* In TLS 1.2 case call straight thru to wc_PRF */
int wc_PRF_TLS(byte* digest, word32 digLen, const byte* secret, word32 secLen,
            const byte* label, word32 labLen, const byte* seed, word32 seedLen,
            int useAtLeastSha256, int hash_type, void* heap, int devId)
{
    int ret = 0;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("  secret");
    WOLFSSL_BUFFER(secret, secLen);
    WOLFSSL_MSG("  label");
    WOLFSSL_BUFFER(label, labLen);
    WOLFSSL_MSG("  seed");
    WOLFSSL_BUFFER(seed, seedLen);
#endif


    if (useAtLeastSha256) {
    #ifdef WOLFSSL_SMALL_STACK
        byte* labelSeed;
    #else
        byte  labelSeed[MAX_PRF_LABSEED];
    #endif

        if (labLen + seedLen > MAX_PRF_LABSEED) {
            return BUFFER_E;
        }

    #ifdef WOLFSSL_SMALL_STACK
        labelSeed = (byte*)XMALLOC(MAX_PRF_LABSEED, heap, DYNAMIC_TYPE_DIGEST);
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
        /* compute PRF for MD5, SHA-1, SHA-256, or SHA-384 for TLSv1.2 PRF */
        ret = wc_PRF(digest, digLen, secret, secLen, labelSeed,
                     labLen + seedLen, hash_type, heap, devId);

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(labelSeed, heap, DYNAMIC_TYPE_DIGEST);
    #endif
    }
    else {
#ifndef NO_OLD_TLS
        /* compute TLSv1 PRF (pseudo random function using HMAC) */
        ret = wc_PRF_TLSv1(digest, digLen, secret, secLen, label, labLen, seed,
                          seedLen, heap, devId);
#else
        ret = BAD_FUNC_ARG;
#endif
    }

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("  digest");
    WOLFSSL_BUFFER(digest, digLen);
    WOLFSSL_MSG_EX("hash_type %d", hash_type);
#endif

    return ret;
}
#endif /* WOLFSSL_HAVE_PRF && !NO_HMAC */


#if defined(HAVE_HKDF) && !defined(NO_HMAC)

    /* Extract data using HMAC, salt and input.
     * RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
     */
    int wc_Tls13_HKDF_Extract_ex(byte* prk, const byte* salt, word32 saltLen,
        byte* ikm, word32 ikmLen, int digest, void* heap, int devId)
    {
        int ret;
        word32 len = 0;

        switch (digest) {
            #ifndef NO_SHA256
            case WC_SHA256:
                len = WC_SHA256_DIGEST_SIZE;
                break;
            #endif

            #ifdef WOLFSSL_SHA384
            case WC_SHA384:
                len = WC_SHA384_DIGEST_SIZE;
                break;
            #endif

            #ifdef WOLFSSL_TLS13_SHA512
            case WC_SHA512:
                len = WC_SHA512_DIGEST_SIZE;
                break;
            #endif

            #ifdef WOLFSSL_SM3
            case WC_SM3:
                len = WC_SM3_DIGEST_SIZE;
                break;
            #endif

            default:
                return BAD_FUNC_ARG;
        }

        /* When length is 0 then use zeroed data of digest length. */
        if (ikmLen == 0) {
            ikmLen = len;
            XMEMSET(ikm, 0, len);
        }

#ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("  Salt");
        WOLFSSL_BUFFER(salt, saltLen);
        WOLFSSL_MSG("  IKM");
        WOLFSSL_BUFFER(ikm, ikmLen);
#endif

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        ret = wc_HKDF_Extract_ex(digest, salt, saltLen, ikm, ikmLen, prk, heap,
            devId);
#else
        ret = wc_HKDF_Extract(digest, salt, saltLen, ikm, ikmLen, prk);
        (void)heap;
        (void)devId;
#endif

#ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("  PRK");
        WOLFSSL_BUFFER(prk, len);
#endif

        return ret;
    }

    int wc_Tls13_HKDF_Extract(byte* prk, const byte* salt, word32 saltLen,
                                 byte* ikm, word32 ikmLen, int digest)
    {
        return wc_Tls13_HKDF_Extract_ex(prk, salt, saltLen, ikm, ikmLen, digest,
            NULL, INVALID_DEVID);
    }

    /* Expand data using HMAC, salt and label and info.
     * TLS v1.3 defines this function. */
    int wc_Tls13_HKDF_Expand_Label_ex(byte* okm, word32 okmLen,
                                 const byte* prk, word32 prkLen,
                                 const byte* protocol, word32 protocolLen,
                                 const byte* label, word32 labelLen,
                                 const byte* info, word32 infoLen,
                                 int digest, void* heap, int devId)
    {
        int    ret = 0;
        word32 idx = 0;
    #ifdef WOLFSSL_SMALL_STACK
        byte*  data;
    #else
        byte   data[MAX_TLS13_HKDF_LABEL_SZ];
    #endif

        /* okmLen (2) + protocol|label len (1) + info len(1) + protocollen +
         * labellen + infolen */
        idx = 4 + protocolLen + labelLen + infoLen;
        if (idx > MAX_TLS13_HKDF_LABEL_SZ) {
            return BUFFER_E;
        }

    #ifdef WOLFSSL_SMALL_STACK
        data = (byte*)XMALLOC(idx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (data == NULL) {
            return MEMORY_E;
        }
    #endif
        idx = 0;

        /* Output length. */
        data[idx++] = (byte)(okmLen >> 8);
        data[idx++] = (byte)okmLen;
        /* Length of protocol | label. */
        data[idx++] = (byte)(protocolLen + labelLen);
        if (protocolLen > 0) {
            /* Protocol */
            XMEMCPY(&data[idx], protocol, protocolLen);
            idx += protocolLen;
        }
        if (labelLen > 0) {
            /* Label */
            XMEMCPY(&data[idx], label, labelLen);
            idx += labelLen;
        }
        /* Length of hash of messages */
        data[idx++] = (byte)infoLen;
        if (infoLen > 0) {
            /* Hash of messages */
            XMEMCPY(&data[idx], info, infoLen);
            idx += infoLen;
        }

    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("wc_Tls13_HKDF_Expand_Label data", data, idx);
    #endif

#ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("  PRK");
        WOLFSSL_BUFFER(prk, prkLen);
        WOLFSSL_MSG("  Info");
        WOLFSSL_BUFFER(data, idx);
        WOLFSSL_MSG_EX("  Digest %d", digest);
#endif

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        ret = wc_HKDF_Expand_ex(digest, prk, prkLen, data, idx, okm, okmLen,
            heap, devId);
#else
        ret = wc_HKDF_Expand(digest, prk, prkLen, data, idx, okm, okmLen);
        (void)heap;
        (void)devId;
#endif

#ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("  OKM");
        WOLFSSL_BUFFER(okm, okmLen);
#endif

        ForceZero(data, idx);

    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(data, idx);
    #endif
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }

    int wc_Tls13_HKDF_Expand_Label(byte* okm, word32 okmLen,
                                 const byte* prk, word32 prkLen,
                                 const byte* protocol, word32 protocolLen,
                                 const byte* label, word32 labelLen,
                                 const byte* info, word32 infoLen,
                                 int digest)
    {
        return wc_Tls13_HKDF_Expand_Label_ex(okm, okmLen, prk, prkLen, protocol,
            protocolLen, label, labelLen, info, infoLen, digest,
            NULL, INVALID_DEVID);
    }

#if defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                                    \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    /* Expand data using HMAC, salt and label and info.
     * TLS v1.3 defines this function. */
    int wc_Tls13_HKDF_Expand_Label_Alloc(byte* okm, word32 okmLen,
        const byte* prk, word32 prkLen, const byte* protocol,
        word32 protocolLen, const byte* label, word32 labelLen,
        const byte* info, word32 infoLen, int digest, void* heap)
    {
        int    ret = 0;
        word32 idx = 0;
        size_t len;
        byte   *data;

        (void)heap;
        /* okmLen (2) + protocol|label len (1) + info len(1) + protocollen +
         * labellen + infolen */
        len = 4U + protocolLen + labelLen + infoLen;

        data = (byte*)XMALLOC(len, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (data == NULL)
            return BUFFER_E;

        /* Output length. */
        data[idx++] = (byte)(okmLen >> 8);
        data[idx++] = (byte)okmLen;
        /* Length of protocol | label. */
        data[idx++] = (byte)(protocolLen + labelLen);
        /* Protocol */
        XMEMCPY(&data[idx], protocol, protocolLen);
        idx += protocolLen;
        /* Label */
        XMEMCPY(&data[idx], label, labelLen);
        idx += labelLen;
        /* Length of hash of messages */
        data[idx++] = (byte)infoLen;
        /* Hash of messages */
        XMEMCPY(&data[idx], info, infoLen);
        idx += infoLen;

    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("wc_Tls13_HKDF_Expand_Label data", data, idx);
    #endif

#ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("  PRK");
        WOLFSSL_BUFFER(prk, prkLen);
        WOLFSSL_MSG("  Info");
        WOLFSSL_BUFFER(data, idx);
        WOLFSSL_MSG_EX("  Digest %d", digest);
#endif

        ret = wc_HKDF_Expand(digest, prk, prkLen, data, idx, okm, okmLen);

#ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("  OKM");
        WOLFSSL_BUFFER(okm, okmLen);
#endif

        ForceZero(data, idx);

    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(data, len);
    #endif
        XFREE(data, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

#endif
/* defined(WOLFSSL_TICKET_NONCE_MALLOC) && (!defined(HAVE_FIPS) ||
 *  FIPS_VERSION_GE(5,3)) */

#endif /* HAVE_HKDF && !NO_HMAC */


#ifdef WOLFSSL_WOLFSSH

/* hash union */
typedef union {
#ifndef NO_MD5
    wc_Md5 md5;
#endif
#ifndef NO_SHA
    wc_Sha sha;
#endif
#ifdef WOLFSSL_SHA224
    wc_Sha224 sha224;
#endif
#ifndef NO_SHA256
    wc_Sha256 sha256;
#endif
#ifdef WOLFSSL_SHA384
    wc_Sha384 sha384;
#endif
#ifdef WOLFSSL_SHA512
    wc_Sha512 sha512;
#endif
#ifdef WOLFSSL_SHA3
    wc_Sha3 sha3;
#endif
} _hash;

static
int _HashInit(byte hashId, _hash* hash)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    switch (hashId) {
    #ifndef NO_SHA
        case WC_SHA:
            ret = wc_InitSha(&hash->sha);
            break;
    #endif /* !NO_SHA */

    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_InitSha256(&hash->sha256);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_InitSha384(&hash->sha384);
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
            ret = wc_InitSha512(&hash->sha512);
            break;
    #endif /* WOLFSSL_SHA512 */
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

static
int _HashUpdate(byte hashId, _hash* hash,
        const byte* data, word32 dataSz)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    switch (hashId) {
    #ifndef NO_SHA
        case WC_SHA:
            ret = wc_ShaUpdate(&hash->sha, data, dataSz);
            break;
    #endif /* !NO_SHA */

    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_Sha256Update(&hash->sha256, data, dataSz);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_Sha384Update(&hash->sha384, data, dataSz);
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
            ret = wc_Sha512Update(&hash->sha512, data, dataSz);
            break;
    #endif /* WOLFSSL_SHA512 */
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

static
int _HashFinal(byte hashId, _hash* hash, byte* digest)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

    switch (hashId) {
    #ifndef NO_SHA
        case WC_SHA:
            ret = wc_ShaFinal(&hash->sha, digest);
            break;
    #endif /* !NO_SHA */

    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_Sha256Final(&hash->sha256, digest);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_Sha384Final(&hash->sha384, digest);
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
            ret = wc_Sha512Final(&hash->sha512, digest);
            break;
    #endif /* WOLFSSL_SHA512 */
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

static
void _HashFree(byte hashId, _hash* hash)
{
    switch (hashId) {
    #ifndef NO_SHA
        case WC_SHA:
            wc_ShaFree(&hash->sha);
            break;
    #endif /* !NO_SHA */

    #ifndef NO_SHA256
        case WC_SHA256:
            wc_Sha256Free(&hash->sha256);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            wc_Sha384Free(&hash->sha384);
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
            wc_Sha512Free(&hash->sha512);
            break;
    #endif /* WOLFSSL_SHA512 */
    }
}


#define LENGTH_SZ 4

int wc_SSH_KDF(byte hashId, byte keyId, byte* key, word32 keySz,
        const byte* k, word32 kSz, const byte* h, word32 hSz,
        const byte* sessionId, word32 sessionIdSz)
{
    word32 blocks, remainder;
    _hash hash;
    enum wc_HashType enmhashId = (enum wc_HashType)hashId;
    byte kPad = 0;
    byte pad = 0;
    byte kSzFlat[LENGTH_SZ];
    word32 digestSz;
    int ret;

    if (key == NULL || keySz == 0 ||
        k == NULL || kSz == 0 ||
        h == NULL || hSz == 0 ||
        sessionId == NULL || sessionIdSz == 0) {

        return BAD_FUNC_ARG;
    }

    ret = wc_HmacSizeByType(enmhashId);
    if (ret <= 0) {
        return BAD_FUNC_ARG;
    }
    digestSz = (word32)ret;

    if (k[0] & 0x80) kPad = 1;
    c32toa(kSz + kPad, kSzFlat);

    blocks = keySz / digestSz;
    remainder = keySz % digestSz;

    ret = _HashInit(enmhashId, &hash);
    if (ret == 0)
        ret = _HashUpdate(enmhashId, &hash, kSzFlat, LENGTH_SZ);
    if (ret == 0 && kPad)
        ret = _HashUpdate(enmhashId, &hash, &pad, 1);
    if (ret == 0)
        ret = _HashUpdate(enmhashId, &hash, k, kSz);
    if (ret == 0)
        ret = _HashUpdate(enmhashId, &hash, h, hSz);
    if (ret == 0)
        ret = _HashUpdate(enmhashId, &hash, &keyId, sizeof(keyId));
    if (ret == 0)
        ret = _HashUpdate(enmhashId, &hash, sessionId, sessionIdSz);

    if (ret == 0) {
        if (blocks == 0) {
            if (remainder > 0) {
                byte lastBlock[WC_MAX_DIGEST_SIZE];
                ret = _HashFinal(enmhashId, &hash, lastBlock);
                if (ret == 0)
                    XMEMCPY(key, lastBlock, remainder);
            }
        }
        else {
            word32 runningKeySz, curBlock;

            runningKeySz = digestSz;
            ret = _HashFinal(enmhashId, &hash, key);

            for (curBlock = 1; curBlock < blocks; curBlock++) {
                ret = _HashInit(enmhashId, &hash);
                if (ret != 0) break;
                ret = _HashUpdate(enmhashId, &hash, kSzFlat, LENGTH_SZ);
                if (ret != 0) break;
                if (kPad)
                    ret = _HashUpdate(enmhashId, &hash, &pad, 1);
                if (ret != 0) break;
                ret = _HashUpdate(enmhashId, &hash, k, kSz);
                if (ret != 0) break;
                ret = _HashUpdate(enmhashId, &hash, h, hSz);
                if (ret != 0) break;
                ret = _HashUpdate(enmhashId, &hash, key, runningKeySz);
                if (ret != 0) break;
                ret = _HashFinal(enmhashId, &hash, key + runningKeySz);
                if (ret != 0) break;
                runningKeySz += digestSz;
            }

            if (remainder > 0) {
                byte lastBlock[WC_MAX_DIGEST_SIZE];
                if (ret == 0)
                    ret = _HashInit(enmhashId, &hash);
                if (ret == 0)
                    ret = _HashUpdate(enmhashId, &hash, kSzFlat, LENGTH_SZ);
                if (ret == 0 && kPad)
                    ret = _HashUpdate(enmhashId, &hash, &pad, 1);
                if (ret == 0)
                    ret = _HashUpdate(enmhashId, &hash, k, kSz);
                if (ret == 0)
                    ret = _HashUpdate(enmhashId, &hash, h, hSz);
                if (ret == 0)
                    ret = _HashUpdate(enmhashId, &hash, key, runningKeySz);
                if (ret == 0)
                    ret = _HashFinal(enmhashId, &hash, lastBlock);
                if (ret == 0)
                    XMEMCPY(key + runningKeySz, lastBlock, remainder);
            }
        }
    }

    _HashFree(enmhashId, &hash);

    return ret;
}

#endif /* WOLFSSL_WOLFSSH */

#ifdef WC_SRTP_KDF
/* Calculate first block to encrypt.
 *
 * @param [in]  salt     Random value to XOR in.
 * @param [in]  saltSz   Size of random value in bytes.
 * @param [in]  kdrIdx   Key derivation rate. kdr = 0 when -1, otherwise
 *                       kdr = 2^kdrIdx.
 * @param [in]  index    Index value to XOR in.
 * @param [in]  indexSz  Size of index value in bytes.
 * @param [out] block    First block to encrypt.
 */
static void wc_srtp_kdf_first_block(const byte* salt, word32 saltSz, int kdrIdx,
        const byte* index, int indexSz, unsigned char* block)
{
    int i;

    /* XOR salt into zeroized buffer. */
    for (i = 0; i < WC_SRTP_MAX_SALT - (int)saltSz; i++) {
        block[i] = 0;
    }
    XMEMCPY(block + WC_SRTP_MAX_SALT - saltSz, salt, saltSz);
    block[WC_SRTP_MAX_SALT] = 0;
    /* block[15] is counter. */

    /* When kdrIdx is -1, don't XOR in index. */
    if (kdrIdx >= 0) {
        /* Get the number of bits to shift index by. */
        word32 bits = kdrIdx & 0x7;
        /* Reduce index size by number of bytes to remove. */
        indexSz -= kdrIdx >> 3;

        if ((kdrIdx & 0x7) == 0) {
            /* Just XOR in as no bit shifting. */
            for (i = 0; i < indexSz; i++) {
                block[i + WC_SRTP_MAX_SALT - indexSz] ^= index[i];
            }
        }
        else {
            /* XOR in as bit shifted index. */
            block[WC_SRTP_MAX_SALT - indexSz] ^= index[0] >> bits;
            for (i = 1; i < indexSz; i++) {
                block[i + WC_SRTP_MAX_SALT - indexSz] ^=
                    (index[i-1] << (8 - bits)) |
                    (index[i+0] >>      bits );
            }
        }
    }
}

/* Derive a key given the first block.
 *
 * @param [in, out] block    First block to encrypt. Need label XORed in.
 * @param [in]      indexSz  Size of index in bytes to calculate where label is
 *                           XORed into.
 * @param [in]      label    Label byte that differs for each key.
 * @param [out]     key      Derived key.
 * @param [in]      keySz    Size of key to derive in bytes.
 * @param [in]      aes      AES object to encrypt with.
 * @return  0 on success.
 */
static int wc_srtp_kdf_derive_key(byte* block, int indexSz, byte label,
        byte* key, word32 keySz, Aes* aes)
{
    int i;
    int ret = 0;
    /* Calculate the number of full blocks needed for derived key. */
    int blocks = (int)(keySz / AES_BLOCK_SIZE);

    /* XOR in label. */
    block[WC_SRTP_MAX_SALT - indexSz - 1] ^= label;
    for (i = 0; (ret == 0) && (i < blocks); i++) {
        /* Set counter. */
        block[15] = (byte)i;
        /* Encrypt block into key buffer. */
        ret = wc_AesEcbEncrypt(aes, key, block, AES_BLOCK_SIZE);
        /* Reposition for more derived key. */
        key += AES_BLOCK_SIZE;
        /* Reduce the count of key bytes required. */
        keySz -= AES_BLOCK_SIZE;
    }
    /* Do any partial blocks. */
    if ((ret == 0) && (keySz > 0)) {
        byte enc[AES_BLOCK_SIZE];
        /* Set counter. */
        block[15] = (byte)i;
        /* Encrypt block into temporary. */
        ret = wc_AesEcbEncrypt(aes, enc, block, AES_BLOCK_SIZE);
        if (ret == 0) {
            /* Copy into key required amount. */
            XMEMCPY(key, enc, keySz);
        }
    }
    /* XOR out label. */
    block[WC_SRTP_MAX_SALT - indexSz - 1] ^= label;

    return ret;
}

/* Derive keys using SRTP KDF algorithm.
 *
 * SP 800-135 (RFC 3711).
 *
 * @param [in]  key      Key to use with encryption.
 * @param [in]  keySz    Size of key in bytes.
 * @param [in]  salt     Random non-secret value.
 * @param [in]  saltSz   Size of random in bytes.
 * @param [in]  kdrIdx   Key derivation rate. kdr = 0 when -1, otherwise
 *                       kdr = 2^kdrIdx.
 * @param [in]  index    Index value to XOR in.
 * @param [out] key1     First key. Label value of 0x00.
 * @param [in]  key1Sz   Size of first key in bytes.
 * @param [out] key2     Second key. Label value of 0x01.
 * @param [in]  key2Sz   Size of second key in bytes.
 * @param [out] key3     Third key. Label value of 0x02.
 * @param [in]  key3Sz   Size of third key in bytes.
 * @return  BAD_FUNC_ARG when key or salt is NULL.
 * @return  BAD_FUNC_ARG when key length is not 16, 24 or 32.
 * @return  BAD_FUNC_ARG when saltSz is larger than 14.
 * @return  BAD_FUNC_ARG when kdrIdx is less than -1 or larger than 24.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  0 on success.
 */
int wc_SRTP_KDF(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
        int kdrIdx, const byte* index, byte* key1, word32 key1Sz, byte* key2,
        word32 key2Sz, byte* key3, word32 key3Sz)
{
    int ret = 0;
    byte block[AES_BLOCK_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes = NULL;
#else
    Aes aes[1];
#endif
    int aes_inited = 0;

    /* Validate parameters. */
    if ((key == NULL) || (keySz > AES_256_KEY_SIZE) || (salt == NULL) ||
            (saltSz > WC_SRTP_MAX_SALT) || (kdrIdx < -1) || (kdrIdx > 24)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_CIPHER);
        if (aes == NULL) {
            ret = MEMORY_E;
        }
    }
    if (aes != NULL)
#endif
    {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    /* Setup AES object. */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        aes_inited = 1;
        ret = wc_AesSetKey(aes, key, keySz, NULL, AES_ENCRYPTION);
    }

    /* Calculate first block that can be used in each derivation. */
    if (ret == 0) {
        wc_srtp_kdf_first_block(salt, saltSz, kdrIdx, index, WC_SRTP_INDEX_LEN,
            block);
    }

    /* Calculate first key if required. */
    if ((ret == 0) && (key1 != NULL)) {
        ret = wc_srtp_kdf_derive_key(block, WC_SRTP_INDEX_LEN,
            WC_SRTP_LABEL_ENCRYPTION, key1, key1Sz, aes);
    }
    /* Calculate second key if required. */
    if ((ret == 0) && (key2 != NULL)) {
        ret = wc_srtp_kdf_derive_key(block, WC_SRTP_INDEX_LEN,
            WC_SRTP_LABEL_MSG_AUTH, key2, key2Sz, aes);
    }
    /* Calculate third key if required. */
    if ((ret == 0) && (key3 != NULL)) {
        ret = wc_srtp_kdf_derive_key(block, WC_SRTP_INDEX_LEN,
            WC_SRTP_LABEL_SALT, key3, key3Sz, aes);
    }

    if (aes_inited)
        wc_AesFree(aes);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes, NULL, DYNAMIC_TYPE_CIPHER);
#endif
    return ret;
}

/* Derive keys using SRTCP KDF algorithm.
 *
 * SP 800-135 (RFC 3711).
 *
 * @param [in]  key      Key to use with encryption.
 * @param [in]  keySz    Size of key in bytes.
 * @param [in]  salt     Random non-secret value.
 * @param [in]  saltSz   Size of random in bytes.
 * @param [in]  kdrIdx   Key derivation rate index. kdr = 0 when -1, otherwise
 *                       kdr = 2^kdrIdx. See wc_SRTP_KDF_kdr_to_idx()
 * @param [in]  index    Index value to XOR in.
 * @param [out] key1     First key. Label value of 0x03.
 * @param [in]  key1Sz   Size of first key in bytes.
 * @param [out] key2     Second key. Label value of 0x04.
 * @param [in]  key2Sz   Size of second key in bytes.
 * @param [out] key3     Third key. Label value of 0x05.
 * @param [in]  key3Sz   Size of third key in bytes.
 * @return  BAD_FUNC_ARG when key or salt is NULL.
 * @return  BAD_FUNC_ARG when key length is not 16, 24 or 32.
 * @return  BAD_FUNC_ARG when saltSz is larger than 14.
 * @return  BAD_FUNC_ARG when kdrIdx is less than -1 or larger than 24.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  0 on success.
 */
int wc_SRTCP_KDF_ex(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
        int kdrIdx, const byte* index, byte* key1, word32 key1Sz, byte* key2,
        word32 key2Sz, byte* key3, word32 key3Sz, int idxLenIndicator)
{
    int ret = 0;
    byte block[AES_BLOCK_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes = NULL;
#else
    Aes aes[1];
#endif
    int aes_inited = 0;
    int idxLen;

    if (idxLenIndicator == WC_SRTCP_32BIT_IDX) {
        idxLen = WC_SRTCP_INDEX_LEN;
    } else if (idxLenIndicator == WC_SRTCP_48BIT_IDX) {
        idxLen = WC_SRTP_INDEX_LEN;
    } else {
        return BAD_FUNC_ARG; /* bad or invalid idxLenIndicator */
    }

    /* Validate parameters. */
    if ((key == NULL) || (keySz > AES_256_KEY_SIZE) || (salt == NULL) ||
            (saltSz > WC_SRTP_MAX_SALT) || (kdrIdx < -1) || (kdrIdx > 24)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_CIPHER);
        if (aes == NULL) {
            ret = MEMORY_E;
        }
    }
    if (aes != NULL)
#endif
    {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    /* Setup AES object. */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        aes_inited = 1;
        ret = wc_AesSetKey(aes, key, keySz, NULL, AES_ENCRYPTION);
    }

    /* Calculate first block that can be used in each derivation. */
    if (ret == 0) {
        wc_srtp_kdf_first_block(salt, saltSz, kdrIdx, index, idxLen, block);
    }

    /* Calculate first key if required. */
    if ((ret == 0) && (key1 != NULL)) {
        ret = wc_srtp_kdf_derive_key(block, idxLen,
            WC_SRTCP_LABEL_ENCRYPTION, key1, key1Sz, aes);
    }
    /* Calculate second key if required. */
    if ((ret == 0) && (key2 != NULL)) {
        ret = wc_srtp_kdf_derive_key(block, idxLen,
            WC_SRTCP_LABEL_MSG_AUTH, key2, key2Sz, aes);
    }
    /* Calculate third key if required. */
    if ((ret == 0) && (key3 != NULL)) {
        ret = wc_srtp_kdf_derive_key(block, idxLen,
            WC_SRTCP_LABEL_SALT, key3, key3Sz, aes);
    }

    if (aes_inited)
        wc_AesFree(aes);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes, NULL, DYNAMIC_TYPE_CIPHER);
#endif
    return ret;
}

int wc_SRTCP_KDF(const byte* key, word32 keySz, const byte* salt, word32 saltSz,
        int kdrIdx, const byte* index, byte* key1, word32 key1Sz, byte* key2,
        word32 key2Sz, byte* key3, word32 key3Sz)
{
    /* The default 32-bit IDX expected by many implementations */
    return wc_SRTCP_KDF_ex(key, keySz, salt, saltSz, kdrIdx, index,
                           key1, key1Sz, key2, key2Sz, key3, key3Sz,
                           WC_SRTCP_32BIT_IDX);
}
/* Derive key with label using SRTP KDF algorithm.
 *
 * SP 800-135 (RFC 3711).
 *
 * @param [in]  key       Key to use with encryption.
 * @param [in]  keySz     Size of key in bytes.
 * @param [in]  salt      Random non-secret value.
 * @param [in]  saltSz    Size of random in bytes.
 * @param [in]  kdrIdx    Key derivation rate index. kdr = 0 when -1, otherwise
 *                        kdr = 2^kdrIdx. See wc_SRTP_KDF_kdr_to_idx()
 * @param [in]  index     Index value to XOR in.
 * @param [in]  label     Label to use when deriving key.
 * @param [out] outKey    Derived key.
 * @param [in]  outKeySz  Size of derived key in bytes.
 * @return  BAD_FUNC_ARG when key, salt or outKey is NULL.
 * @return  BAD_FUNC_ARG when key length is not 16, 24 or 32.
 * @return  BAD_FUNC_ARG when saltSz is larger than 14.
 * @return  BAD_FUNC_ARG when kdrIdx is less than -1 or larger than 24.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  0 on success.
 */
int wc_SRTP_KDF_label(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* index, byte label, byte* outKey,
        word32 outKeySz)
{
    int ret = 0;
    byte block[AES_BLOCK_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes = NULL;
#else
    Aes aes[1];
#endif
    int aes_inited = 0;

    /* Validate parameters. */
    if ((key == NULL) || (keySz > AES_256_KEY_SIZE) || (salt == NULL) ||
            (saltSz > WC_SRTP_MAX_SALT) || (kdrIdx < -1) || (kdrIdx > 24) ||
            (outKey == NULL)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_CIPHER);
        if (aes == NULL) {
            ret = MEMORY_E;
        }
    }
    if (aes != NULL)
#endif
    {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    /* Setup AES object. */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        aes_inited = 1;
        ret = wc_AesSetKey(aes, key, keySz, NULL, AES_ENCRYPTION);
    }

    /* Calculate first block that can be used in each derivation. */
    if (ret == 0) {
        wc_srtp_kdf_first_block(salt, saltSz, kdrIdx, index, WC_SRTP_INDEX_LEN,
            block);
    }
    if (ret == 0) {
        /* Calculate key. */
        ret = wc_srtp_kdf_derive_key(block, WC_SRTP_INDEX_LEN, label, outKey,
            outKeySz, aes);
    }

    if (aes_inited)
        wc_AesFree(aes);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes, NULL, DYNAMIC_TYPE_CIPHER);
#endif
    return ret;

}

/* Derive key with label using SRTCP KDF algorithm.
 *
 * SP 800-135 (RFC 3711).
 *
 * @param [in]  key       Key to use with encryption.
 * @param [in]  keySz     Size of key in bytes.
 * @param [in]  salt      Random non-secret value.
 * @param [in]  saltSz    Size of random in bytes.
 * @param [in]  kdrIdx    Key derivation rate index. kdr = 0 when -1, otherwise
 *                        kdr = 2^kdrIdx. See wc_SRTP_KDF_kdr_to_idx()
 * @param [in]  index     Index value to XOR in.
 * @param [in]  label     Label to use when deriving key.
 * @param [out] outKey    Derived key.
 * @param [in]  outKeySz  Size of derived key in bytes.
 * @return  BAD_FUNC_ARG when key, salt or outKey is NULL.
 * @return  BAD_FUNC_ARG when key length is not 16, 24 or 32.
 * @return  BAD_FUNC_ARG when saltSz is larger than 14.
 * @return  BAD_FUNC_ARG when kdrIdx is less than -1 or larger than 24.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  0 on success.
 */
int wc_SRTCP_KDF_label(const byte* key, word32 keySz, const byte* salt,
        word32 saltSz, int kdrIdx, const byte* index, byte label, byte* outKey,
        word32 outKeySz)
{
    int ret = 0;
    byte block[AES_BLOCK_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes = NULL;
#else
    Aes aes[1];
#endif
    int aes_inited = 0;

    /* Validate parameters. */
    if ((key == NULL) || (keySz > AES_256_KEY_SIZE) || (salt == NULL) ||
            (saltSz > WC_SRTP_MAX_SALT) || (kdrIdx < -1) || (kdrIdx > 24) ||
            (outKey == NULL)) {
        ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        aes = (Aes*)XMALLOC(sizeof(Aes), NULL, DYNAMIC_TYPE_CIPHER);
        if (aes == NULL) {
            ret = MEMORY_E;
        }
    }
    if (aes != NULL)
#endif
    {
        XMEMSET(aes, 0, sizeof(Aes));
    }

    /* Setup AES object. */
    if (ret == 0) {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    }
    if (ret == 0) {
        aes_inited = 1;
        ret = wc_AesSetKey(aes, key, keySz, NULL, AES_ENCRYPTION);
    }

    /* Calculate first block that can be used in each derivation. */
    if (ret == 0) {
        wc_srtp_kdf_first_block(salt, saltSz, kdrIdx, index, WC_SRTCP_INDEX_LEN,
            block);
    }
    if (ret == 0) {
        /* Calculate key. */
        ret = wc_srtp_kdf_derive_key(block, WC_SRTCP_INDEX_LEN, label, outKey,
            outKeySz, aes);
    }

    if (aes_inited)
        wc_AesFree(aes);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes, NULL, DYNAMIC_TYPE_CIPHER);
#endif
    return ret;

}

/* Converts a kdr value to an index to use in SRTP/SRTCP KDF API.
 *
 * @param [in] kdr  Key derivation rate to convert.
 * @return  Key derivation rate as an index.
 */
int wc_SRTP_KDF_kdr_to_idx(word32 kdr)
{
    int idx = -1;

    /* Keep shifting value down and incrementing index until top bit is gone. */
    while (kdr != 0) {
        kdr >>= 1;
        idx++;
    }

    /* Index of top bit set. */
    return idx;
}
#endif /* WC_SRTP_KDF */

#ifdef WC_KDF_NIST_SP_800_56C
static int wc_KDA_KDF_iteration(const byte* z, word32 zSz, word32 counter,
    const byte* fixedInfo, word32 fixedInfoSz, enum wc_HashType hashType,
    byte* output)
{
    byte counterBuf[4];
    wc_HashAlg hash;
    int ret;

    ret = wc_HashInit(&hash, hashType);
    if (ret != 0)
        return ret;
    c32toa(counter, counterBuf);
    ret = wc_HashUpdate(&hash, hashType, counterBuf, 4);
    if (ret == 0) {
        ret = wc_HashUpdate(&hash, hashType, z, zSz);
    }
    if (ret == 0 && fixedInfoSz > 0) {
        ret = wc_HashUpdate(&hash, hashType, fixedInfo, fixedInfoSz);
    }
    if (ret == 0) {
        ret = wc_HashFinal(&hash, hashType, output);
    }
    wc_HashFree(&hash, hashType);
    return ret;
}

/**
 * \brief Performs the single-step key derivation function (KDF) as specified in
 * SP800-56C option 1.
 *
 * \param [in] z The input keying material.
 * \param [in] zSz The size of the input keying material.
 * \param [in] fixedInfo The fixed information to be included in the KDF.
 * \param [in] fixedInfoSz The size of the fixed information.
 * \param [in] derivedSecretSz The desired size of the derived secret.
 * \param [in] hashType The hash algorithm to be used in the KDF.
 * \param [out] output The buffer to store the derived secret.
 * \param [in] outputSz The size of the output buffer.
 *
 * \return 0 if the KDF operation is successful.
 * \return BAD_FUNC_ARG if the input parameters are invalid.
 * \return negative error code if the KDF operation fails.
 */
int wc_KDA_KDF_onestep(const byte* z, word32 zSz, const byte* fixedInfo,
    word32 fixedInfoSz, word32 derivedSecretSz, enum wc_HashType hashType,
    byte* output, word32 outputSz)
{
    byte hashTempBuf[WC_MAX_DIGEST_SIZE];
    word32 counter, outIdx;
    int hashOutSz;
    int ret;

    if (output == NULL || outputSz < derivedSecretSz)
        return BAD_FUNC_ARG;
    if (z == NULL || zSz == 0 || (fixedInfoSz > 0 && fixedInfo == NULL))
        return BAD_FUNC_ARG;
    if (derivedSecretSz == 0)
        return BAD_FUNC_ARG;

    hashOutSz = wc_HashGetDigestSize(hashType);
    if (hashOutSz == WC_NO_ERR_TRACE(HASH_TYPE_E))
        return BAD_FUNC_ARG;

    /* According to SP800_56C, table 1, the max input size (max_H_inputBits)
     * depends on the HASH algo. The smaller value in the table is (2**64-1)/8.
     * This is larger than the possible length using word32 integers. */

    counter = 1;
    outIdx = 0;
    ret = 0;

    /* According to SP800_56C the number of iterations shall not be greater than
     * 2**32-1. This is not possible using word32 integers.*/
    while (outIdx + hashOutSz <= derivedSecretSz) {
        ret = wc_KDA_KDF_iteration(z, zSz, counter, fixedInfo, fixedInfoSz,
            hashType, output + outIdx);
        if (ret != 0)
            break;
        counter++;
        outIdx += hashOutSz;
    }

    if (ret == 0 && outIdx < derivedSecretSz) {
        ret = wc_KDA_KDF_iteration(z, zSz, counter, fixedInfo, fixedInfoSz,
            hashType, hashTempBuf);
        if (ret == 0) {
            XMEMCPY(output + outIdx, hashTempBuf, derivedSecretSz - outIdx);
        }
        ForceZero(hashTempBuf, hashOutSz);
    }

    if (ret != 0) {
        ForceZero(output, derivedSecretSz);
    }

    return ret;
}
#endif /* WC_KDF_NIST_SP_800_56C */

#endif /* NO_KDF */
