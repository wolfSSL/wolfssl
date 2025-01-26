/* aes.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/*!
    \file wolfssl/wolfcrypt/aes.h
*/
/*

DESCRIPTION
This library provides the interfaces to the Advanced Encryption Standard (AES)
for encrypting and decrypting data. AES is the standard known for a symmetric
block cipher mechanism that uses n-bit binary string parameter key with 128-bits,
192-bits, and 256-bits of key sizes.

*/
#ifndef WOLF_CRYPT_AES_H
#define WOLF_CRYPT_AES_H

#include <wolfssl/wolfcrypt/types.h>

#if !defined(NO_AES) || defined(WOLFSSL_SM4)
typedef struct Gcm {
    ALIGN16 byte H[16];
#ifdef OPENSSL_EXTRA
    word32 aadH[4]; /* additional authenticated data GHASH */
    word32 aadLen;  /* additional authenticated data len */
#endif
#ifdef GCM_TABLE
    /* key-based fast multiplication table. */
    ALIGN16 byte M0[256][16];
#elif defined(GCM_TABLE_4BIT)
    #if defined(BIG_ENDIAN_ORDER) || defined(WC_16BIT_CPU)
        ALIGN16 byte M0[16][16];
    #else
        ALIGN16 byte M0[32][16];
    #endif
#endif /* GCM_TABLE */
} Gcm;

#if FIPS_VERSION3_GE(6,0,0)
    extern const unsigned int wolfCrypt_FIPS_aes_ro_sanity[2];
    WOLFSSL_LOCAL int wolfCrypt_FIPS_AES_sanity(void);
#endif

WOLFSSL_LOCAL void GenerateM0(Gcm* gcm);
#if !defined(__aarch64__) && defined(WOLFSSL_ARMASM)
WOLFSSL_LOCAL void GMULT(byte* X, byte* Y);
#endif
WOLFSSL_LOCAL void GHASH(Gcm* gcm, const byte* a, word32 aSz, const byte* c,
                         word32 cSz, byte* s, word32 sSz);
#endif

#ifndef NO_AES

#if defined(HAVE_FIPS) && \
    defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
    #include <wolfssl/wolfcrypt/fips.h>
#endif /* HAVE_FIPS_VERSION >= 2 */

#ifndef WC_NO_RNG
    #include <wolfssl/wolfcrypt/random.h>
#endif
#ifdef STM32_CRYPTO
    #include <wolfssl/wolfcrypt/port/st/stm32.h>
#endif

#ifdef WOLFSSL_IMXRT_DCP
    #include "fsl_dcp.h"
#endif

#ifdef WOLFSSL_XILINX_CRYPT
#ifdef WOLFSSL_XILINX_CRYPT_VERSAL
#include <wolfssl/wolfcrypt/port/xilinx/xil-versal-glue.h>
#include <xsecure_aesclient.h>
#if !defined(WOLFSSL_XILINX_AES_KEY_SRC)
    #define WOLFSSL_XILINX_AES_KEY_SRC XSECURE_AES_USER_KEY_0
#endif
#else /* versal */
#include <xsecure_aes.h>
#if !defined(WOLFSSL_XILINX_AES_KEY_SRC)
    #define WOLFSSL_XILINX_AES_KEY_SRC XSECURE_CSU_AES_KEY_SRC_KUP
#endif
#endif /* !versal */
#endif /* WOLFSSL_XILINX_CRYPT */

#if defined(WOLFSSL_XILINX_CRYPT) || defined(WOLFSSL_AFALG_XILINX_AES)
#if !defined(WOLFSSL_XILINX_AES_KEY_SRC)
#define WOLFSSL_XILINX_AES_KEY_SRC 0
#endif /* !defined(WOLFSSL_XILINX_AES_KEY_SRC) */
#endif /* all Xilinx crypto */

#ifdef WOLFSSL_SE050
    #include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#endif

#if defined(WOLFSSL_AFALG) || defined(WOLFSSL_AFALG_XILINX_AES)
/* included for struct msghdr */
#include <wolfssl/wolfcrypt/port/af_alg/wc_afalg.h>
#endif

#if defined(WOLFSSL_KCAPI_AES)
#include <wolfssl/wolfcrypt/port/kcapi/wc_kcapi.h>
#endif

#if defined(WOLFSSL_DEVCRYPTO_AES) || defined(WOLFSSL_DEVCRYPTO_CBC)
#include <wolfssl/wolfcrypt/port/devcrypto/wc_devcrypto.h>
#endif

#ifdef WOLFSSL_SILABS_SE_ACCEL
    #include <wolfssl/wolfcrypt/port/silabs/silabs_aes.h>
#endif


#if defined(HAVE_AESGCM) && !defined(WC_NO_RNG)
    #include <wolfssl/wolfcrypt/random.h>
#endif

#if defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_AES)
#include <psa/crypto.h>
#endif

#if defined(WOLFSSL_CRYPTOCELL)
    #include <wolfssl/wolfcrypt/port/arm/cryptoCell.h>
#endif

#if (defined(WOLFSSL_RENESAS_TSIP_TLS) && \
    defined(WOLFSSL_RENESAS_TSIP_TLS_AES_CRYPT)) ||\
    defined(WOLFSSL_RENESAS_TSIP_CRYPTONLY)
    #include <wolfssl/wolfcrypt/port/Renesas/renesas_tsip_types.h>
#endif

#if defined(WOLFSSL_RENESAS_FSPSM)
    #include <wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-crypt.h>
#endif

#ifdef WOLFSSL_MAXQ10XX_CRYPTO
    #include <wolfssl/wolfcrypt/port/maxim/maxq10xx.h>
#endif


#ifdef __cplusplus
    extern "C" {
#endif

#ifndef WOLFSSL_AES_KEY_SIZE_ENUM
#define WOLFSSL_AES_KEY_SIZE_ENUM
/* these are required for FIPS and non-FIPS */
enum {
    AES_128_KEY_SIZE    = 16,  /* for 128 bit             */
    AES_192_KEY_SIZE    = 24,  /* for 192 bit             */
    AES_256_KEY_SIZE    = 32,  /* for 256 bit             */

    AES_IV_SIZE         = 16  /* always block size       */
};
#endif

/* avoid redefinition of structs */
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

enum {
    AES_ENC_TYPE   = WC_CIPHER_AES,   /* cipher unique type */
    AES_ENCRYPTION = 0,
    AES_DECRYPTION = 1,
#ifdef WC_AES_XTS_SUPPORT_SIMULTANEOUS_ENC_AND_DEC_KEYS
    AES_ENCRYPTION_AND_DECRYPTION = 2,
#endif

    WC_AES_BLOCK_SIZE      = 16,
#ifdef OPENSSL_COEXIST
    /* allow OPENSSL_COEXIST applications to detect absence of AES_BLOCK_SIZE
     * and presence of WC_AES_BLOCK_SIZE.
     *
     * if WC_NO_COMPAT_AES_BLOCK_SIZE is defined, WC_AES_BLOCK_SIZE is
     * available, otherwise AES_BLOCK_SIZE is available.
     */
    #define WC_NO_COMPAT_AES_BLOCK_SIZE
#else
    #define AES_BLOCK_SIZE WC_AES_BLOCK_SIZE
#endif

    KEYWRAP_BLOCK_SIZE  = 8,

    GCM_NONCE_MAX_SZ = 16, /* wolfCrypt's maximum nonce size allowed. */
    GCM_NONCE_MID_SZ = 12, /* The default nonce size for AES-GCM. */
    GCM_NONCE_MIN_SZ = 8,  /* wolfCrypt's minimum nonce size allowed. */
    CCM_NONCE_MIN_SZ = 7,
    CCM_NONCE_MAX_SZ = 13,
    CTR_SZ   = 4,
    AES_IV_FIXED_SZ = 4,
#ifdef WOLFSSL_AES_CFB
    AES_CFB_MODE = 1,
#endif
#ifdef WOLFSSL_AES_OFB
    AES_OFB_MODE = 2,
#endif
#ifdef WOLFSSL_AES_XTS
    AES_XTS_MODE = 3,
#endif

#ifdef WOLF_PRIVATE_KEY_ID
    AES_MAX_ID_LEN      = 32,
    AES_MAX_LABEL_LEN   = 32,
#endif

    WOLF_ENUM_DUMMY_LAST_ELEMENT(AES)
};

#ifdef WC_AES_BITSLICED
    #ifdef WC_AES_BS_WORD_SIZE
        #define BS_WORD_SIZE        WC_AES_BS_WORD_SIZE
    #elif defined(NO_64BIT)
        #define BS_WORD_SIZE        32
    #else
        #define BS_WORD_SIZE        64
    #endif

    /* Number of bits to a block. */
    #define AES_BLOCK_BITS      (WC_AES_BLOCK_SIZE * 8)
    /* Number of bytes of input that can be processed in one call. */
    #define BS_BLOCK_SIZE       (WC_AES_BLOCK_SIZE * BS_WORD_SIZE)
    /* Number of words in a block.  */
    #define BS_BLOCK_WORDS      (AES_BLOCK_BITS / BS_WORD_SIZE)

    #if BS_WORD_SIZE == 64
        typedef word64          bs_word;
        #define BS_WORD_SHIFT   6
        #define bs_bswap(x)     ByteReverseWord64(x)
    #elif BS_WORD_SIZE == 32
        typedef word32          bs_word;
        #define BS_WORD_SHIFT   5
        #define bs_bswap(x)     ByteReverseWord32(x)
    #elif BS_WORD_SIZE == 16
        typedef word16          bs_word;
        #define BS_WORD_SHIFT   4
        #define bs_bswap(x)     ByteReverseWord16(x)
    #elif BS_WORD_SIZE == 8
        typedef word8           bs_word;
        #define BS_WORD_SHIFT   3
        #define bs_bswap(x)     (x)
    #else
        #error "Word size not supported"
    #endif
#endif

struct Aes {
    ALIGN16 word32 key[60];
#ifdef WC_AES_BITSLICED
    /* Extra key schedule space required for bit-slicing technique. */
    ALIGN16 bs_word bs_key[15 * WC_AES_BLOCK_SIZE * BS_WORD_SIZE];
#endif
    word32  rounds;
#ifdef WC_C_DYNAMIC_FALLBACK
    word32 key_C_fallback[60];
#endif
    int     keylen;

    ALIGN16 word32 reg[WC_AES_BLOCK_SIZE / sizeof(word32)];      /* for CBC mode */
    ALIGN16 word32 tmp[WC_AES_BLOCK_SIZE / sizeof(word32)];      /* same         */

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    word32 invokeCtr[2];
    word32 nonceSz;
#endif
#ifdef HAVE_AESGCM
    Gcm gcm;

#ifdef WOLFSSL_SE050
    sss_symmetric_t aes_ctx; /* used as the function context */
    int ctxInitDone;
    word32 keyId;
    byte   keyIdSet;
    byte   useSWCrypt; /* Use SW crypt instead of SE050, before SCP03 auth */
#endif
#ifdef HAVE_CAVIUM_OCTEON_SYNC
    word32 y0;
#endif
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_CAAM
    int blackKey; /* black key / hsm key id */
#endif
#ifdef WOLFSSL_AESNI
    byte use_aesni;
#endif /* WOLFSSL_AESNI */
#if defined(__aarch64__) && defined(WOLFSSL_ARMASM) && \
    !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)
    byte use_aes_hw_crypto;
#ifdef HAVE_AESGCM
    byte use_pmull_hw_crypto;
    byte use_sha3_hw_crypto;
#endif
#endif /* __aarch64__ && WOLFSSL_ARMASM && !WOLFSSL_ARMASM_NO_HW_CRYPTO */
#ifdef WOLF_CRYPTO_CB
    int    devId;
    void*  devCtx;
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    byte id[AES_MAX_ID_LEN];
    int  idLen;
    char label[AES_MAX_LABEL_LEN];
    int  labelLen;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif /* WOLFSSL_ASYNC_CRYPT */
#if defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_CFB) || \
    defined(WOLFSSL_AES_OFB) || defined(WOLFSSL_AES_XTS)
    word32  left;            /* unused bytes left from last call */
#endif
#ifdef WOLFSSL_XILINX_CRYPT
#ifdef WOLFSSL_XILINX_CRYPT_VERSAL
    wc_Xsecure          xSec;
    XSecure_AesKeySize  xKeySize;
    int                 aadStyle;
    byte                keyInit[WOLFSSL_XSECURE_AES_KEY_SIZE] ALIGN64;
#else
    XSecure_Aes xilAes;
    XCsuDma     dma;
    word32      keyInit[8];
#endif
    word32      kup;
#endif
#if defined(WOLFSSL_AFALG) || defined(WOLFSSL_AFALG_XILINX_AES)
    int alFd; /* server socket to bind to */
    int rdFd; /* socket to read from */
    struct msghdr msg;
    int dir;  /* flag for encrypt or decrypt */
#ifdef WOLFSSL_AFALG_XILINX_AES
    word32 msgBuf[CMSG_SPACE(4) + CMSG_SPACE(sizeof(struct af_alg_iv) +
                  GCM_NONCE_MID_SZ)];
#endif
#endif
#if defined(WOLFSSL_KCAPI_AES)
    struct kcapi_handle* handle;
    int                  init;
#endif
#if defined(WOLF_CRYPTO_CB) || (defined(WOLFSSL_DEVCRYPTO) && \
    (defined(WOLFSSL_DEVCRYPTO_AES) || defined(WOLFSSL_DEVCRYPTO_CBC))) || \
    (defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_AES)) || \
    defined(WOLFSSL_KCAPI_AES)
    word32 devKey[AES_MAX_KEY_SIZE/WOLFSSL_BIT_SIZE/sizeof(word32)]; /* raw key */
#ifdef HAVE_CAVIUM_OCTEON_SYNC
    int    keySet;
#endif
#endif
#if defined(WOLFSSL_DEVCRYPTO) && \
    (defined(WOLFSSL_DEVCRYPTO_AES) || defined(WOLFSSL_DEVCRYPTO_CBC))
    WC_CRYPTODEV ctx;
#endif
#if defined(WOLFSSL_CRYPTOCELL)
    aes_context_t ctx;
#endif
#if (defined(WOLFSSL_RENESAS_TSIP_TLS) && \
    defined(WOLFSSL_RENESAS_TSIP_TLS_AES_CRYPT)) ||\
    defined(WOLFSSL_RENESAS_TSIP_CRYPTONLY)
    TSIP_AES_CTX ctx;
#endif
#if defined(WOLFSSL_RENESAS_FSPSM)
    FSPSM_AES_CTX ctx;
#endif
#if defined(WOLFSSL_IMXRT_DCP)
    dcp_handle_t handle;
#endif
#if defined(WOLFSSL_SILABS_SE_ACCEL)
    silabs_aes_t ctx;
#endif
#ifdef WOLFSSL_MAXQ10XX_CRYPTO
    maxq_aes_t maxq_ctx;
#endif
#if defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_AES)
    psa_key_id_t key_id;
    psa_cipher_operation_t psa_ctx;
    int ctx_initialized;
    int key_need_importing;
#endif
    void*  heap; /* memory hint to use */
#ifdef WOLFSSL_AESGCM_STREAM
#if !defined(WOLFSSL_SMALL_STACK) || defined(WOLFSSL_AESNI)
    ALIGN16 byte streamData[5 * WC_AES_BLOCK_SIZE];
#else
    byte*        streamData;
    word32       streamData_sz;
#endif
    word32       aSz;
    word32       cSz;
    byte         over;
    byte         aOver;
    byte         cOver;
    WC_BITFIELD  gcmKeySet:1;
    WC_BITFIELD  nonceSet:1;
    WC_BITFIELD  ctrSet:1;
#endif
#ifdef WC_DEBUG_CIPHER_LIFECYCLE
    void *CipherLifecycleTag; /* used for dummy allocation and initialization,
                               * trackable by sanitizers.
                               */
#endif
};

#ifndef WC_AES_TYPE_DEFINED
    typedef struct Aes Aes;
    #define WC_AES_TYPE_DEFINED
#endif

#ifdef WOLFSSL_AES_XTS
    #if FIPS_VERSION3_GE(6,0,0)
        /* SP800-38E - Restrict data unit to 2^20 blocks per key. A block is
         * WC_AES_BLOCK_SIZE or 16-bytes (128-bits). So each key may only be used to
         * protect up to 1,048,576 blocks of WC_AES_BLOCK_SIZE (16,777,216 bytes)
         */
        #define FIPS_AES_XTS_MAX_BYTES_PER_TWEAK 16777216
    #endif
    struct XtsAes {
        Aes aes;
    #ifdef WC_AES_XTS_SUPPORT_SIMULTANEOUS_ENC_AND_DEC_KEYS
        Aes aes_decrypt;
    #endif
        Aes tweak;
    };

    #ifdef WOLFSSL_AESXTS_STREAM
        struct XtsAesStreamData {
            byte tweak_block[WC_AES_BLOCK_SIZE];
            word32 bytes_crypted_with_this_tweak;
        };
    #endif

    #ifndef WC_AESXTS_TYPE_DEFINED
        typedef struct XtsAes XtsAes;
        typedef struct XtsAesStreamData XtsAesStreamData;
        #define WC_AESXTS_TYPE_DEFINED
    #endif

#endif


#if (!defined(WC_AESFREE_IS_MANDATORY)) &&                              \
    (defined(WC_DEBUG_CIPHER_LIFECYCLE) ||                              \
     (defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_AES)) ||  \
     defined(WOLFSSL_AFALG) || defined(WOLFSSL_AFALG_XILINX_AES) ||     \
     defined(WOLFSSL_KCAPI_AES) ||                                      \
     (defined(WOLFSSL_DEVCRYPTO) &&                                     \
      (defined(WOLFSSL_DEVCRYPTO_AES) ||                                \
       defined(WOLFSSL_DEVCRYPTO_CBC))) ||                              \
     defined(WOLFSSL_IMXRT_DCP) ||                                      \
     (defined(WOLFSSL_AESGCM_STREAM) && defined(WOLFSSL_SMALL_STACK) && \
      !defined(WOLFSSL_AESNI)) ||                                       \
     (defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_CRYPT)) ||        \
     (defined(WOLFSSL_HAVE_PSA) && !defined(WOLFSSL_PSA_NO_AES)) ||     \
     defined(WOLFSSL_MAXQ10XX_CRYPTO) ||                                \
     ((defined(WOLFSSL_RENESAS_FSPSM_TLS) ||                            \
       defined(WOLFSSL_RENESAS_FSPSM_CRYPTONLY)) &&                     \
      !defined(NO_WOLFSSL_RENESAS_FSPSM_AES)))
#define WC_AESFREE_IS_MANDATORY
#endif

#ifdef HAVE_AESGCM
struct Gmac {
    Aes aes;
};

#ifndef WC_AESGCM_TYPE_DEFINED
    typedef struct Gmac Gmac;
    #define WC_AESGCM_TYPE_DEFINED
#endif

#endif /* HAVE_AESGCM */
#endif /* HAVE_FIPS */


/* Authenticate cipher function prototypes */
typedef int (*wc_AesAuthEncryptFunc)(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
typedef int (*wc_AesAuthDecryptFunc)(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/* AES-CBC */
WOLFSSL_API int  wc_AesSetKey(Aes* aes, const byte* key, word32 len,
                              const byte* iv, int dir);
WOLFSSL_API int  wc_AesSetIV(Aes* aes, const byte* iv);

#ifdef HAVE_AES_CBC
WOLFSSL_API int  wc_AesCbcEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);
WOLFSSL_API int  wc_AesCbcDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);
#endif

#ifdef WOLFSSL_AES_CFB
WOLFSSL_API int wc_AesCfbEncrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
WOLFSSL_API int wc_AesCfb1Encrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
WOLFSSL_API int wc_AesCfb8Encrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
#ifdef HAVE_AES_DECRYPT
WOLFSSL_API int wc_AesCfbDecrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
WOLFSSL_API int wc_AesCfb1Decrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
WOLFSSL_API int wc_AesCfb8Decrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_CFB */

#ifdef WOLFSSL_AES_OFB
WOLFSSL_API int wc_AesOfbEncrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
#ifdef HAVE_AES_DECRYPT
WOLFSSL_API int wc_AesOfbDecrypt(Aes* aes, byte* out,
                                    const byte* in, word32 sz);
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_OFB */

#ifdef HAVE_AES_ECB
WOLFSSL_API int wc_AesEcbEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);
WOLFSSL_API int wc_AesEcbDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);
#endif

/* AES-CTR */
#ifdef WOLFSSL_AES_COUNTER
 WOLFSSL_API int wc_AesCtrEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz);
 WOLFSSL_API int wc_AesCtrSetKey(Aes* aes, const byte* key, word32 len,
                                        const byte* iv, int dir);

#endif
/* AES-DIRECT */
#if defined(WOLFSSL_AES_DIRECT)
#if defined(BUILDING_WOLFSSL)
 WOLFSSL_API WARN_UNUSED_RESULT int wc_AesEncryptDirect(Aes* aes, byte* out,
                                                        const byte* in);
 WOLFSSL_API WARN_UNUSED_RESULT int wc_AesDecryptDirect(Aes* aes, byte* out,
                                                        const byte* in);
 WOLFSSL_API WARN_UNUSED_RESULT int wc_AesSetKeyDirect(Aes* aes,
                                                       const byte* key,
                                                       word32 len,
                                const byte* iv, int dir);
#else
 WOLFSSL_API int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in);
 WOLFSSL_API int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in);
 WOLFSSL_API int wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
                                const byte* iv, int dir);
#endif
#endif

#ifdef HAVE_AESGCM
#ifdef WOLFSSL_XILINX_CRYPT
 WOLFSSL_API int  wc_AesGcmSetKey_ex(Aes* aes, const byte* key, word32 len,
         word32 kup);
#elif defined(WOLFSSL_AFALG_XILINX_AES)
 WOLFSSL_LOCAL int  wc_AesGcmSetKey_ex(Aes* aes, const byte* key, word32 len,
         word32 kup);
#endif
 WOLFSSL_API int  wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len);
 WOLFSSL_API int  wc_AesGcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
 WOLFSSL_API int  wc_AesGcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
#ifdef WOLFSSL_AESGCM_STREAM
WOLFSSL_API int wc_AesGcmInit(Aes* aes, const byte* key, word32 len,
        const byte* iv, word32 ivSz);

WOLFSSL_API int wc_AesGcmEncryptInit(Aes* aes, const byte* key, word32 len,
        const byte* iv, word32 ivSz);
WOLFSSL_API int wc_AesGcmEncryptInit_ex(Aes* aes, const byte* key, word32 len,
        byte* ivOut, word32 ivOutSz);
WOLFSSL_API int wc_AesGcmEncryptUpdate(Aes* aes, byte* out, const byte* in,
        word32 sz, const byte* authIn, word32 authInSz);
WOLFSSL_API int wc_AesGcmEncryptFinal(Aes* aes, byte* authTag,
        word32 authTagSz);

WOLFSSL_API int wc_AesGcmDecryptInit(Aes* aes, const byte* key, word32 len,
        const byte* iv, word32 ivSz);
WOLFSSL_API int wc_AesGcmDecryptUpdate(Aes* aes, byte* out, const byte* in,
        word32 sz, const byte* authIn, word32 authInSz);
WOLFSSL_API int wc_AesGcmDecryptFinal(Aes* aes, const byte* authTag,
        word32 authTagSz);
#endif

#ifndef WC_NO_RNG
 WOLFSSL_API int  wc_AesGcmSetExtIV(Aes* aes, const byte* iv, word32 ivSz);
 WOLFSSL_API int  wc_AesGcmSetIV(Aes* aes, word32 ivSz,
                                   const byte* ivFixed, word32 ivFixedSz,
                                   WC_RNG* rng);
 WOLFSSL_API int  wc_AesGcmEncrypt_ex(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   byte* ivOut, word32 ivOutSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
#endif /* WC_NO_RNG */

 WOLFSSL_API int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len);
 WOLFSSL_API int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                               const byte* authIn, word32 authInSz,
                               byte* authTag, word32 authTagSz);
#ifndef WC_NO_RNG
 WOLFSSL_API int wc_Gmac(const byte* key, word32 keySz, byte* iv, word32 ivSz,
                               const byte* authIn, word32 authInSz,
                               byte* authTag, word32 authTagSz, WC_RNG* rng);
 WOLFSSL_API int wc_GmacVerify(const byte* key, word32 keySz,
                               const byte* iv, word32 ivSz,
                               const byte* authIn, word32 authInSz,
                               const byte* authTag, word32 authTagSz);
#endif /* WC_NO_RNG */
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
 WOLFSSL_LOCAL int wc_AesCcmCheckTagSize(int sz);
 WOLFSSL_API int  wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz);
 WOLFSSL_API int  wc_AesCcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
 WOLFSSL_API int  wc_AesCcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
 WOLFSSL_API int  wc_AesCcmSetNonce(Aes* aes,
                                   const byte* nonce, word32 nonceSz);
 WOLFSSL_API int  wc_AesCcmEncrypt_ex(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   byte* ivOut, word32 ivOutSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
#endif /* HAVE_AESCCM */

#ifdef HAVE_AES_KEYWRAP
 WOLFSSL_API int  wc_AesKeyWrap(const byte* key, word32 keySz,
                                const byte* in, word32 inSz,
                                byte* out, word32 outSz,
                                const byte* iv);
 WOLFSSL_API int  wc_AesKeyWrap_ex(Aes *aes,
                                const byte* in, word32 inSz,
                                byte* out, word32 outSz,
                                const byte* iv);
 WOLFSSL_API int  wc_AesKeyUnWrap(const byte* key, word32 keySz,
                                const byte* in, word32 inSz,
                                byte* out, word32 outSz,
                                const byte* iv);
 WOLFSSL_API int  wc_AesKeyUnWrap_ex(Aes *aes,
                                const byte* in, word32 inSz,
                                byte* out, word32 outSz,
                                const byte* iv);
#endif /* HAVE_AES_KEYWRAP */

#ifdef WOLFSSL_AES_XTS

WOLFSSL_API int wc_AesXtsInit(XtsAes* aes, void* heap, int devId);

WOLFSSL_API int wc_AesXtsSetKeyNoInit(XtsAes* aes, const byte* key,
         word32 len, int dir);

WOLFSSL_API int wc_AesXtsSetKey(XtsAes* aes, const byte* key,
         word32 len, int dir, void* heap, int devId);

WOLFSSL_API int wc_AesXtsEncryptSector(XtsAes* aes, byte* out,
         const byte* in, word32 sz, word64 sector);

WOLFSSL_API int wc_AesXtsDecryptSector(XtsAes* aes, byte* out,
         const byte* in, word32 sz, word64 sector);

WOLFSSL_API int wc_AesXtsEncrypt(XtsAes* aes, byte* out,
         const byte* in, word32 sz, const byte* i, word32 iSz);

WOLFSSL_API int wc_AesXtsDecrypt(XtsAes* aes, byte* out,
        const byte* in, word32 sz, const byte* i, word32 iSz);

WOLFSSL_API int wc_AesXtsEncryptConsecutiveSectors(XtsAes* aes,
        byte* out, const byte* in, word32 sz, word64 sector,
        word32 sectorSz);

WOLFSSL_API int wc_AesXtsDecryptConsecutiveSectors(XtsAes* aes,
        byte* out, const byte* in, word32 sz, word64 sector,
        word32 sectorSz);

#ifdef WOLFSSL_AESXTS_STREAM

WOLFSSL_API int wc_AesXtsEncryptInit(XtsAes* aes, const byte* i, word32 iSz,
         struct XtsAesStreamData *stream);

WOLFSSL_API int wc_AesXtsDecryptInit(XtsAes* aes, const byte* i, word32 iSz,
         struct XtsAesStreamData *stream);

WOLFSSL_API int wc_AesXtsEncryptUpdate(XtsAes* aes, byte* out,
         const byte* in, word32 sz, struct XtsAesStreamData *stream);

WOLFSSL_API int wc_AesXtsDecryptUpdate(XtsAes* aes, byte* out,
         const byte* in, word32 sz, struct XtsAesStreamData *stream);

WOLFSSL_API int wc_AesXtsEncryptFinal(XtsAes* aes, byte* out,
         const byte* in, word32 sz, struct XtsAesStreamData *stream);

WOLFSSL_API int wc_AesXtsDecryptFinal(XtsAes* aes, byte* out,
         const byte* in, word32 sz, struct XtsAesStreamData *stream);

#endif /* WOLFSSL_AESXTS_STREAM */

WOLFSSL_API int wc_AesXtsFree(XtsAes* aes);
#endif

WOLFSSL_API int wc_AesGetKeySize(Aes* aes, word32* keySize);

WOLFSSL_API int  wc_AesInit(Aes* aes, void* heap, int devId);
#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API int  wc_AesInit_Id(Aes* aes, unsigned char* id, int len, void* heap,
        int devId);
WOLFSSL_API int  wc_AesInit_Label(Aes* aes, const char* label, void* heap,
        int devId);
#endif
WOLFSSL_API void wc_AesFree(Aes* aes);
#ifndef WC_NO_CONSTRUCTORS
WOLFSSL_API Aes* wc_AesNew(void* heap, int devId, int *result_code);
WOLFSSL_API int wc_AesDelete(Aes* aes, Aes** aes_p);
#endif

#ifdef WOLFSSL_AES_SIV
typedef struct AesSivAssoc {
    const byte* assoc;
    word32 assocSz;
} AesSivAssoc;

WOLFSSL_API
int wc_AesSivEncrypt(const byte* key, word32 keySz, const byte* assoc,
                     word32 assocSz, const byte* nonce, word32 nonceSz,
                     const byte* in, word32 inSz, byte* siv, byte* out);
WOLFSSL_API
int wc_AesSivDecrypt(const byte* key, word32 keySz, const byte* assoc,
                     word32 assocSz, const byte* nonce, word32 nonceSz,
                     const byte* in, word32 inSz, byte* siv, byte* out);

WOLFSSL_API
int wc_AesSivEncrypt_ex(const byte* key, word32 keySz, const AesSivAssoc* assoc,
                        word32 numAssoc, const byte* nonce, word32 nonceSz,
                        const byte* in, word32 inSz, byte* siv, byte* out);
WOLFSSL_API
int wc_AesSivDecrypt_ex(const byte* key, word32 keySz, const AesSivAssoc* assoc,
                        word32 numAssoc, const byte* nonce, word32 nonceSz,
                        const byte* in, word32 inSz, byte* siv, byte* out);
#endif

#ifdef WOLFSSL_AES_EAX

/* Because of the circular dependency between AES and CMAC, we need to prevent
 * inclusion of AES EAX from CMAC to avoid a recursive inclusion */
#ifndef WOLF_CRYPT_CMAC_H
#include <wolfssl/wolfcrypt/cmac.h>
struct AesEax {
    Aes  aes;
    Cmac nonceCmac;
    Cmac aadCmac;
    Cmac ciphertextCmac;
    byte nonceCmacFinal[WC_AES_BLOCK_SIZE];
    byte aadCmacFinal[WC_AES_BLOCK_SIZE];
    byte ciphertextCmacFinal[WC_AES_BLOCK_SIZE];
    byte prefixBuf[WC_AES_BLOCK_SIZE];
};
#endif /* !defined(WOLF_CRYPT_CMAC_H) */

typedef struct AesEax AesEax;

/* One-shot API */
WOLFSSL_API int  wc_AesEaxEncryptAuth(const byte* key, word32 keySz, byte* out,
                                      const byte* in, word32 inSz,
                                      const byte* nonce, word32 nonceSz,
                                      /* output computed auth tag */
                                      byte* authTag, word32 authTagSz,
                                      /* input data to authenticate (header) */
                                      const byte* authIn, word32 authInSz);

WOLFSSL_API int  wc_AesEaxDecryptAuth(const byte* key, word32 keySz, byte* out,
                                      const byte* in, word32 inSz,
                                      const byte* nonce, word32 nonceSz,
                                      /* auth tag to verify against */
                                      const byte* authTag, word32 authTagSz,
                                      /* input data to authenticate (header) */
                                      const byte* authIn, word32 authInSz);

/* Incremental API */
WOLFSSL_API int  wc_AesEaxInit(AesEax* eax,
                               const byte* key, word32 keySz,
                               const byte* nonce, word32 nonceSz,
                               const byte* authIn, word32 authInSz);

WOLFSSL_API int  wc_AesEaxEncryptUpdate(AesEax* eax, byte* out,
                                        const byte* in, word32 inSz,
                                        const byte* authIn, word32 authInSz);

WOLFSSL_API int  wc_AesEaxDecryptUpdate(AesEax* eax, byte* out,
                                        const byte* in, word32 inSz,
                                        const byte* authIn, word32 authInSz);

WOLFSSL_API int  wc_AesEaxAuthDataUpdate(AesEax* eax,
                                       const byte* authIn, word32 authInSz);

WOLFSSL_API int wc_AesEaxEncryptFinal(AesEax* eax,
                                      byte* authTag, word32 authTagSz);

WOLFSSL_API int wc_AesEaxDecryptFinal(AesEax* eax,
                                      const byte* authIn, word32 authInSz);

WOLFSSL_API int wc_AesEaxFree(AesEax* eax);

#endif /* WOLFSSL_AES_EAX */

#if defined(__aarch64__) && defined(WOLFSSL_ARMASM) && \
    !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)

/* GHASH one block of data.
 *
 * XOR block into tag and GMULT with H.
 *
 * @param [in, out] aes    AES GCM object.
 * @param [in]      block  Block of AAD or cipher text.
 */
#define GHASH_ONE_BLOCK_AARCH64(aes, block)             \
    do {                                                \
        xorbuf(AES_TAG(aes), block, WC_AES_BLOCK_SIZE); \
        GMULT_AARCH64(AES_TAG(aes), aes->gcm.H);        \
    }                                                   \
    while (0)

WOLFSSL_LOCAL int AES_set_key_AARCH64(const unsigned char *userKey,
    const int keylen, Aes* aes, int dir);
WOLFSSL_LOCAL void AES_encrypt_AARCH64(const byte* inBlock, byte* outBlock,
    byte* key, int nr);
WOLFSSL_LOCAL void AES_decrypt_AARCH64(const byte* inBlock, byte* outBlock,
    byte* key, int nr);
WOLFSSL_LOCAL void AES_CBC_encrypt_AARCH64(const byte* in, byte* out, word32 sz,
    byte* reg, byte* key, int rounds);
WOLFSSL_LOCAL void AES_CBC_decrypt_AARCH64(const byte* in, byte* out, word32 sz,
    byte* reg, byte* key, int rounds);
WOLFSSL_LOCAL void AES_CTR_encrypt_AARCH64(Aes* aes, byte* out, const byte* in,
    word32 sz);
WOLFSSL_LOCAL void GMULT_AARCH64(byte* X, byte* Y);
#ifdef WOLFSSL_AESGCM_STREAM
WOLFSSL_LOCAL void GHASH_UPDATE_AARCH64(Aes* aes, const byte* a, word32 aSz,
    const byte* c, word32 cSz);
WOLFSSL_LOCAL void AES_GCM_init_AARCH64(Aes* aes, const byte* iv, word32 ivSz);
WOLFSSL_LOCAL void AES_GCM_crypt_update_AARCH64(Aes* aes, byte* out,
    const byte* in, word32 sz);
WOLFSSL_LOCAL void AES_GCM_final_AARCH64(Aes* aes, byte* authTag,
    word32 authTagSz);
#endif
WOLFSSL_LOCAL void AES_GCM_set_key_AARCH64(Aes* aes, byte* iv);
WOLFSSL_LOCAL void AES_GCM_encrypt_AARCH64(Aes* aes, byte* out, const byte* in,
    word32 sz, const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz);
WOLFSSL_LOCAL int AES_GCM_decrypt_AARCH64(Aes* aes, byte* out, const byte* in,
    word32 sz, const byte* iv, word32 ivSz, const byte* authTag,
    word32 authTagSz, const byte* authIn, word32 authInSz);

#ifdef WOLFSSL_AES_XTS
WOLFSSL_LOCAL void AES_XTS_encrypt_AARCH64(XtsAes* xaes, byte* out,
    const byte* in, word32 sz, const byte* i);
WOLFSSL_LOCAL void AES_XTS_decrypt_AARCH64(XtsAes* xaes, byte* out,
    const byte* in, word32 sz, const byte* i);
#endif /* WOLFSSL_AES_XTS */
#endif /* __aarch64__ && WOLFSSL_ARMASM && !WOLFSSL_ARMASM_NO_HW_CRYPTO */

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* NO_AES */
#endif /* WOLF_CRYPT_AES_H */
