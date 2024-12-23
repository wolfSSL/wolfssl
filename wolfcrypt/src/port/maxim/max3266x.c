/* max3266x.c
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

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_MAX3266X) || defined(WOLFSSL_MAX3266X_OLD)

#include <stdint.h>
#include <stdarg.h>

#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/maxim/max3266x.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/port/maxim/max3266x-cryptocb.h>
#endif

#if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH)
    #error  MXC Not Compatible with Fast Math or Heap Math
    #include <wolfssl/wolfcrypt/tfm.h>
    #define MXC_WORD_SIZE               DIGIT_BIT
#elif defined(WOLFSSL_SP_MATH_ALL)
    #include <wolfssl/wolfcrypt/sp_int.h>
    #define MXC_WORD_SIZE               SP_WORD_SIZE
#else
    #error MXC HW port needs #define WOLFSSL_SP_MATH_ALL
#endif

/* Max size MAA can handle */
#define MXC_MAA_MAX_SIZE (2048 / MXC_WORD_SIZE)

int wc_MXC_TPU_Init(void)
{
    /* Initialize the TPU device */
    if (MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TRNG) != 0) {
        MAX3266X_MSG("Device did not initialize");
        return RNG_FAILURE_E;
    }
    return 0;
}

int wc_MXC_TPU_Shutdown(void)
{
    /* Shutdown the TPU device */
#if defined(WOLFSSL_MAX3266X_OLD)
    MXC_TPU_Shutdown(); /* Is a void return in older SDK */
#else
    if (MXC_TPU_Shutdown(MXC_SYS_PERIPH_CLOCK_TRNG) != 0) {
        MAX3266X_MSG("Device did not shutdown");
        return RNG_FAILURE_E;
    }
#endif
    MAX3266X_MSG("TPU Hardware Shutdown");
    return 0;
}


#ifdef WOLF_CRYPTO_CB
int wc_MxcAesCryptoCb(wc_CryptoInfo* info)
{
    switch (info->cipher.type) {
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            if (info->cipher.enc == 1) {
                return wc_MxcCb_AesCbcEncrypt(info->cipher.aescbc.aes,
                                                info->cipher.aescbc.out,
                                                info->cipher.aescbc.in,
                                                info->cipher.aescbc.sz);
            }
            #ifdef HAVE_AES_DECRYPT
            else if (info->cipher.enc == 0) {
                return wc_MxcCb_AesCbcDecrypt(info->cipher.aescbc.aes,
                                                info->cipher.aescbc.out,
                                                info->cipher.aescbc.in,
                                                info->cipher.aescbc.sz);
                }
            #endif
            break; /* Break out and return error */
#endif
#ifdef HAVE_AES_ECB
        case WC_CIPHER_AES_ECB:
            if (info->cipher.enc == 1) {
                return wc_MxcCb_AesEcbEncrypt(info->cipher.aesecb.aes,
                                                info->cipher.aesecb.out,
                                                info->cipher.aesecb.in,
                                                info->cipher.aesecb.sz);
            }
            #ifdef HAVE_AES_DECRYPT
            else if (info->cipher.enc == 0) {
                return wc_MxcCb_AesEcbDecrypt(info->cipher.aesecb.aes,
                                                info->cipher.aesecb.out,
                                                info->cipher.aesecb.in,
                                                info->cipher.aesecb.sz);
                }
            #endif
            break; /* Break out and return error */
#endif
        default:
            /* Is not ECB/CBC/GCM */
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* Just in case code breaks of switch statement return error */
    return BAD_FUNC_ARG;
}

#ifdef MAX3266X_SHA_CB

int wc_MxcShaCryptoCb(wc_CryptoInfo* info)
{
    switch (info->hash.type) {
    #ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            MAX3266X_MSG("SHA-1 CB:");
            /* Update Case */
            if (info->hash.in != NULL && info->hash.digest == NULL) {
                MAX3266X_MSG("Update CB");
                return wc_MXC_TPU_SHA_Update(&(info->hash.sha1->mxcCtx),
                                            info->hash.in, info->hash.inSz);
            }
            /* Sha 1 Final Case */
            if (info->hash.in == NULL && info->hash.digest != NULL) {
                MAX3266X_MSG("Final CB");
                return wc_MXC_TPU_SHA_Final(&(info->hash.sha1->mxcCtx),
                                                info->hash.digest,
                                                MXC_TPU_HASH_SHA1);
            }
            break; /* Break Out and Return Error */
    #endif
    #ifdef WOLFSSL_SHA224
        case WC_HASH_TYPE_SHA224:
            MAX3266X_MSG("SHA-224 CB:");
            /* Update Case */
            if (info->hash.in != NULL && info->hash.digest == NULL) {
                MAX3266X_MSG("Update CB");
                return wc_MXC_TPU_SHA_Update(&(info->hash.sha224->mxcCtx),
                                            info->hash.in, info->hash.inSz);
            }
            /* Sha 256 Final Case */
            if (info->hash.in == NULL && info->hash.digest != NULL) {
                MAX3266X_MSG("Final CB");
                return wc_MXC_TPU_SHA_Final(&(info->hash.sha224->mxcCtx),
                                                info->hash.digest,
                                                MXC_TPU_HASH_SHA224);
            }
            break; /* Break Out and Return Error */
    #endif
    #ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            MAX3266X_MSG("SHA-256 CB:");
            /* Update Case */
            if (info->hash.in != NULL && info->hash.digest == NULL) {
                MAX3266X_MSG("Update CB");
                return wc_MXC_TPU_SHA_Update(&(info->hash.sha256->mxcCtx),
                                            info->hash.in, info->hash.inSz);
            }
            /* Sha 256 Final Case */
            if (info->hash.in == NULL && info->hash.digest != NULL) {
                MAX3266X_MSG("Final CB");
                return wc_MXC_TPU_SHA_Final(&(info->hash.sha256->mxcCtx),
                                                info->hash.digest,
                                                MXC_TPU_HASH_SHA256);
            }
            break; /* Break Out and Return Error */
    #endif
    #ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            MAX3266X_MSG("SHA-384 CB:");
            /* Update Case */
            if (info->hash.in != NULL && info->hash.digest == NULL) {
                MAX3266X_MSG("Update CB");
                return wc_MXC_TPU_SHA_Update(&(info->hash.sha384->mxcCtx),
                                            info->hash.in, info->hash.inSz);
            }
            /* Sha 384 Final Case */
            if (info->hash.in == NULL && info->hash.digest != NULL) {
                MAX3266X_MSG("Final CB");
                return wc_MXC_TPU_SHA_Final(&(info->hash.sha384->mxcCtx),
                                                info->hash.digest,
                                                MXC_TPU_HASH_SHA384);
            }
            break; /* Break Out and Return Error */
    #endif
    #ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            MAX3266X_MSG("SHA-512 CB:");
            /* Update Case */
            if (info->hash.in != NULL && info->hash.digest == NULL) {
                MAX3266X_MSG("Update CB");
                return wc_MXC_TPU_SHA_Update(&(info->hash.sha512->mxcCtx),
                                            info->hash.in, info->hash.inSz);
            }
            /* Sha 512 Final Case */
            if (info->hash.in == NULL && info->hash.digest != NULL) {
                MAX3266X_MSG("Final CB");
                return wc_MXC_TPU_SHA_Final(&(info->hash.sha512->mxcCtx),
                                                info->hash.digest,
                                                MXC_TPU_HASH_SHA512);
            }
            break; /* Break Out and Return Error */
    #endif
        default:
            /* Hash type not supported */
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (info->hash.inSz == 0) {
        return 0; /* Dont need to Update when Size is Zero */
    }
    return BAD_FUNC_ARG;
}
#endif /* MAX3266X_SHA_CB */

/* Determines AES Type for Callback */
/* General Callback Function to determine ALGO Type */
int wc_MxcCryptoCb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    int ret;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef DEBUG_CRYPTOCB
    wc_CryptoCb_InfoString(info);
#endif

    switch (info->algo_type) {
        case WC_ALGO_TYPE_CIPHER:
            MAX3266X_MSG("Using MXC AES HW Callback:");
            ret = wc_MxcAesCryptoCb(info); /* Determine AES HW or SW */
            break;
#ifdef MAX3266X_SHA_CB
        case WC_ALGO_TYPE_HASH:
            MAX3266X_MSG("Using MXC SHA HW Callback:");
            ret = wc_MxcShaCryptoCb(info); /* Determine SHA HW or SW */
            break;
#endif /* MAX3266X_SHA_CB */
        default:
            MAX3266X_MSG("Callback not support with MXC, using SW");
            /* return this to bypass HW and use SW */
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return ret;
}
#endif

/* Convert Error Codes Correctly and Report HW error when */
/* using #define MAX3266X_VERBOSE */
int wc_MXC_error(int *ret)
{
    if (ret == NULL) {
        /* In case somehow pointer to the return code is NULL */
        return BAD_FUNC_ARG;
    }
    switch (*ret) {
        case E_SUCCESS:
            return 0;

        case E_INVALID: /* Process Failed */
            MAX3266X_MSG("HW Reported: E_INVALID Error");
            *ret = WC_HW_E;
            break;

        case E_NULL_PTR:
            MAX3266X_MSG("HW Reported: E_NULL_PTR Error");
            *ret = BAD_FUNC_ARG;
            break;

        case E_BAD_PARAM:
            MAX3266X_MSG("HW Reported: E_BAD_PARAM Error");
            *ret = BAD_FUNC_ARG;
            break;

        case E_BAD_STATE:
            MAX3266X_MSG("HW Reported: E_BAD_STATE Error");
            *ret = WC_HW_E;
            break;

        default:
            MAX3266X_MSG("HW Reported an Unknown Error");
            *ret = WC_HW_E; /* If something else return HW Error */
            break;
    }
    return *ret;
}


#if defined(MAX3266X_RNG)
/* Simple call to SDK's TRNG HW */
int wc_MXC_TRNG_Random(unsigned char* output, unsigned int sz)
{
    int status;
    if (output == NULL) {
        return BAD_FUNC_ARG;
    }
    status = wolfSSL_HwRngMutexLock(); /* Lock Mutex needed since */
                                         /* calling TPU init */
    if (status != 0) {
        return status;
    }
    status = MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TRNG);
    if (status == 0) {
        /* void return function */
        MXC_TPU_TRNG_Read(MXC_TRNG, output, sz);
        MAX3266X_MSG("TRNG Hardware Used");
    }
    else {
        MAX3266X_MSG("TRNG Device did not initialize");
        status = RNG_FAILURE_E;
    }
    wolfSSL_HwRngMutexUnLock(); /* Unlock Mutex no matter status value */
    return status;
}
#endif /* MAX3266X_RNG */

#if defined(MAX3266X_AES)
/* Generic call to the SDK's AES 1 shot Encrypt based on inputs given */
int wc_MXC_TPU_AesEncrypt(const unsigned char* in, const unsigned char* iv,
                            const unsigned char* enc_key,
                            MXC_TPU_MODE_TYPE mode, unsigned int data_size,
                            unsigned char* out, unsigned int keySize)
{
    int status;
    if (in == NULL || iv == NULL || enc_key == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    status = wolfSSL_HwAesMutexLock();
    MAX3266X_MSG("AES HW Encryption");
    if (status != 0) {
        MAX3266X_MSG("Hardware Mutex Failure");
        return status;
    }
    switch (keySize) {
        case MXC_AES_KEY_128_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES128);
            status = MXC_TPU_Cipher_AES_Encrypt((const char*)in,
                        (const char*)iv, (const char*)enc_key,
                        MXC_TPU_CIPHER_AES128, mode, data_size, (char*)out);
            MAX3266X_MSG("AES HW Acceleration Used: 128 Bit");
            break;
        case MXC_AES_KEY_192_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES192);
            status = MXC_TPU_Cipher_AES_Encrypt((const char*)in,
                        (const char*)iv, (const char*)enc_key,
                        MXC_TPU_CIPHER_AES192, mode, data_size, (char*)out);
            MAX3266X_MSG("AES HW Acceleration Used: 192 Bit");
            break;
        case MXC_AES_KEY_256_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES256);
            status = MXC_TPU_Cipher_AES_Encrypt((const char*)in,
                        (const char*)iv, (const char*)enc_key,
                        MXC_TPU_CIPHER_AES256, mode, data_size, (char*)out);
            MAX3266X_MSG("AES HW Acceleration Used: 256 Bit");
            break;
        default:
            MAX3266X_MSG("AES HW ERROR: Length Not Supported");
            wolfSSL_HwAesMutexUnLock();
            return BAD_FUNC_ARG;
    }
    wolfSSL_HwAesMutexUnLock();
    if (status != 0) {
        MAX3266X_MSG("AES HW Acceleration Error Occurred");
        return WC_HW_E;
    }
    return status;
}


/* Encrypt AES Crypto Callbacks*/
#if defined(WOLF_CRYPTO_CB)

#ifdef HAVE_AES_ECB
int wc_MxcCb_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int status;
    word32 keySize;

    if ((in == NULL) || (out == NULL) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    status = wc_AesGetKeySize(aes, &keySize);
    if (status != 0) {
        return status;
    }

    status = wc_MXC_TPU_AesEncrypt(in, (byte*)aes->reg, (byte*)aes->devKey,
                                        MXC_TPU_MODE_ECB, sz, out, keySize);

    return status;
}
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
int wc_MxcCb_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 keySize;
    int status;
    byte *iv;

    if ((in == NULL) || (out == NULL) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* Always enforce a length check */
    if (sz % WC_AES_BLOCK_SIZE) {
    #ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
        return BAD_LENGTH_E;
    #else
        return BAD_FUNC_ARG;
    #endif
    }
    if (sz == 0) {
        return 0;
    }

    iv = (byte*)aes->reg;
    status = wc_AesGetKeySize(aes, &keySize);
    if (status != 0) {
        return status;
    }

    status = wc_MXC_TPU_AesEncrypt(in, iv, (byte*)aes->devKey,
                                    MXC_TPU_MODE_CBC, sz, out,
                                    (unsigned int)keySize);
    /* store iv for next call */
    if (status == 0) {
        XMEMCPY(iv, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }
    return (status == 0) ? 0 : -1;
}
#endif /* HAVE_AES_CBC */
#endif /* WOLF_CRYPTO_CB */

#ifdef HAVE_AES_DECRYPT
/* Generic call to the SDK's AES 1 shot decrypt based on inputs given */
int wc_MXC_TPU_AesDecrypt(const unsigned char* in, const unsigned char* iv,
                            const unsigned char* dec_key,
                            MXC_TPU_MODE_TYPE mode, unsigned int data_size,
                            unsigned char* out, unsigned int keySize)
{
    int status;
    if (in == NULL || iv == NULL || dec_key == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    status = wolfSSL_HwAesMutexLock();
    if (status != 0) {
        return status;
    }
    switch (keySize) {
        case MXC_AES_KEY_128_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES128);
            status = MXC_TPU_Cipher_AES_Decrypt((const char*)in,
                        (const char*)iv, (const char*)dec_key,
                        MXC_TPU_CIPHER_AES128, mode, data_size, (char*)out);
            MAX3266X_MSG("AES HW Acceleration Used: 128 Bit");
            break;
        case MXC_AES_KEY_192_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES192);
            status = MXC_TPU_Cipher_AES_Decrypt((const char*)in,
                        (const char*)iv, (const char*)dec_key,
                        MXC_TPU_CIPHER_AES192, mode, data_size, (char*)out);
            MAX3266X_MSG("AES HW Acceleration Used: 192 Bit");
            break;
        case MXC_AES_KEY_256_LEN:
            MXC_TPU_Cipher_Config(mode, MXC_TPU_CIPHER_AES256);
            status = MXC_TPU_Cipher_AES_Decrypt((const char*)in,
                        (const char*)iv, (const char*)dec_key,
                        MXC_TPU_CIPHER_AES256, mode, data_size, (char*)out);
            MAX3266X_MSG("AES HW Acceleration Used: 256 Bit");
            break;
        default:
            MAX3266X_MSG("AES HW ERROR: Length Not Supported");
            wolfSSL_HwAesMutexUnLock();
            return BAD_FUNC_ARG;
    }
    wolfSSL_HwAesMutexUnLock();
    if (status != 0) {
        MAX3266X_MSG("AES HW Acceleration Error Occurred");
        return WC_HW_E;
    }
    return status;
}

/* Decrypt Aes Crypto Callbacks*/
#if defined(WOLF_CRYPTO_CB)

#ifdef HAVE_AES_ECB
int wc_MxcCb_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int status;
    word32 keySize;

    if ((in == NULL) || (out == NULL) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    status = wc_AesGetKeySize(aes, &keySize);
    if (status != 0) {
        return status;
    }

    status = wc_MXC_TPU_AesDecrypt(in, (byte*)aes->reg, (byte*)aes->devKey,
                                        MXC_TPU_MODE_ECB, sz, out, keySize);

    return status;
}
#endif /* HAVE_AES_ECB */

#ifdef HAVE_AES_CBC
int wc_MxcCb_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    word32 keySize;
    int status;
    byte *iv;
    byte temp_block[WC_AES_BLOCK_SIZE];

    if ((in == NULL) || (out == NULL) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* Always enforce a length check */
    if (sz % WC_AES_BLOCK_SIZE) {
    #ifdef WOLFSSL_AES_CBC_LENGTH_CHECKS
        return BAD_LENGTH_E;
    #else
        return BAD_FUNC_ARG;
    #endif
    }
    if (sz == 0) {
        return 0;
    }

    iv = (byte*)aes->reg;
    status = wc_AesGetKeySize(aes, &keySize);
    if (status != 0) {
        return status;
    }

    /* get IV for next call */
    XMEMCPY(temp_block, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    status = wc_MXC_TPU_AesDecrypt(in, iv, (byte*)aes->devKey,
                                    MXC_TPU_MODE_CBC, sz, out,
                                    keySize);

    /* store iv for next call */
    if (status == 0) {
        XMEMCPY(iv, temp_block, WC_AES_BLOCK_SIZE);
    }
    return (status == 0) ? 0 : -1;
}
#endif /* HAVE_AES_CBC */
#endif /* WOLF_CRYPTO_CB */
#endif /* HAVE_AES_DECRYPT */
#endif /* MAX3266X_AES */

#if defined(MAX3266X_SHA) || defined(MAX3266X_SHA_CB)

int wc_MXC_TPU_SHA_Init(wc_MXC_Sha *hash)
{
    if (hash == NULL) {
        return BAD_FUNC_ARG; /* Appropriate error handling for null argument */
    }
    hash->msg = NULL;
    hash->used = 0;
    hash->size = 0;
    return 0;
}

/* Used to update the msg. Currently the SDK only supports 1 shots, so the */
/* hash->msg buffer needs to be updated and resized. hash->msg will keep the */
/* unhashed msg and produce a digest when wc_MXC_TPU_SHA_Final or */
/* wc_MXC_TPU_SHA_GetHash is called */
int wc_MXC_TPU_SHA_Update(wc_MXC_Sha *hash, const unsigned char* data,
                            unsigned int size)
{
    void *p;
    /* Only update if size is not 0 */
    if (size == 0) {
        return 0;
    }
    /* Check for NULL pointers After Size Check */
    if (hash == NULL || data == NULL) {
        return BAD_FUNC_ARG;
    }
    if (hash->size < hash->used+size) {
        if (hash->msg == NULL) {
            p = XMALLOC(hash->used+size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            #ifdef WOLFSSL_NO_REALLOC
            p = XMALLOC(hash->used + size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (p != NULL) {
                XMEMCPY(p, hash->msg, hash->used);
                XFREE(hash->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
            #else
            p = XREALLOC(hash->msg, hash->used+size, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
            #endif
        }
        if (p == NULL) {
            return MEMORY_E;
        }
        hash->msg = p;
        hash->size = hash->used+size;
    }
    XMEMCPY(hash->msg+hash->used, data, size);
    hash->used += size;
    if (hash->msg == NULL) {
        return BAD_FUNC_ARG;
    }
    return 0;
}

int wc_MXC_TPU_SHA_GetHash(wc_MXC_Sha *hash, unsigned char* digest,
                                MXC_TPU_HASH_TYPE algo)
{
    int status;
    if (hash == NULL || digest == NULL) {
        return BAD_FUNC_ARG;
    }
    status = wc_MXC_TPU_SHA_GetDigest(hash, digest, algo);
    /* True Case that msg is an empty string */
    if (status == 1) {
        /* Hardware cannot handle the case of an empty string */
        /* so in the case of this we will provide the hash via software */
        return 0;
    }
    /* False Case where msg needs to be processed */
    else if (status == 0) {
        status = wolfSSL_HwHashMutexLock(); /* Set Mutex */
        if (status != 0) { /* Mutex Call Check */
            return status;
        }
        MXC_TPU_Init(MXC_SYS_PERIPH_CLOCK_TPU);
        MXC_TPU_Hash_Config(algo);
        status = MXC_TPU_Hash_SHA((const char *)hash->msg, algo, hash->size,
                                         (char *)digest);
        MAX3266X_MSG("SHA HW Acceleration Used");
        wolfSSL_HwHashMutexUnLock(); /* Release Mutex */
        if (wc_MXC_error(&status) != 0) {
            MAX3266X_MSG("SHA HW Error Occurred");
            return status;
        }
    }
    /* Error Occurred */
    return status;
}

/* Calls GetHash to determine the digest and then reinitialize the hash */
/* struct */
int wc_MXC_TPU_SHA_Final(wc_MXC_Sha *hash, unsigned char* digest,
                                    MXC_TPU_HASH_TYPE algo)
{
    int status;
    if (hash == NULL || digest == NULL) {
        return BAD_FUNC_ARG;
    }
    status = wc_MXC_TPU_SHA_GetHash(hash, digest, algo);
    /* Free hash->msg no matter result */
    XFREE(hash->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (status != 0) {
        return status;
    }
    status = wc_MXC_TPU_SHA_Init(hash);
    if (status != 0) {
        return status;
    }
    return status;
}

/* Copies Struct values from SRC struct to DST struct */
int wc_MXC_TPU_SHA_Copy(wc_MXC_Sha* src, wc_MXC_Sha* dst)
{
    if (src == NULL || dst == NULL) {
        return BAD_FUNC_ARG;
    }
    dst->used = src->used;
    dst->size = src->size;
    if (dst->msg == src->msg && src->msg != 0) {
        /* Allocate new memory for dst->msg if it points to the same location */
        /* as src->msg */
        dst->msg = (unsigned char*)XMALLOC(src->size, NULL,
                                            DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL) {
            return MEMORY_E; /* Handle memory allocation failure */
        }
    }
    XMEMCPY(dst->msg, src->msg, src->size);
    return 0;
}

/* Free the given struct's msg buffer and then reinitialize the struct to 0 */
/* returns void to match other wc_Sha*Free api */
void wc_MXC_TPU_SHA_Free(wc_MXC_Sha* hash)
{
    if (hash == NULL) {
        return; /* Hash Struct is Null already, dont edit potentially */
                /* undefined memory */
    }
    XFREE(hash->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_MXC_TPU_SHA_Init(hash); /* sets hash->msg to null + zero's attributes */
    return;
}

/* Acts as a True/False if true it will provide the stored digest */
/* for the edge case of an empty string */
int wc_MXC_TPU_SHA_GetDigest(wc_MXC_Sha *hash, unsigned char* digest,
                                        MXC_TPU_HASH_TYPE algo)
{
    if (hash == NULL || digest == NULL) {
        return BAD_FUNC_ARG;
    }
    if (hash->msg == 0 && hash->size == 0) {
        switch (algo) {
            #ifndef NO_SHA
            case MXC_TPU_HASH_SHA1:
                XMEMCPY(digest, MXC_EMPTY_DIGEST_SHA1, WC_SHA_DIGEST_SIZE);
                break;
            #endif /* NO_SHA */
            #ifdef WOLFSSL_SHA224
            case MXC_TPU_HASH_SHA224:
                XMEMCPY(digest, MXC_EMPTY_DIGEST_SHA224, WC_SHA224_DIGEST_SIZE);
                break;
            #endif /* WOLFSSL_SHA224 */
            #ifndef NO_SHA256
            case MXC_TPU_HASH_SHA256:
                XMEMCPY(digest, MXC_EMPTY_DIGEST_SHA256, WC_SHA256_DIGEST_SIZE);
                break;
            #endif /* NO_SHA256 */
            #ifdef WOLFSSL_SHA384
            case MXC_TPU_HASH_SHA384:
                XMEMCPY(digest, MXC_EMPTY_DIGEST_SHA384, WC_SHA384_DIGEST_SIZE);
                break;
            #endif /* WOLFSSL_SHA384 */
            #ifdef WOLFSSL_SHA512
            case MXC_TPU_HASH_SHA512:
                XMEMCPY(digest, MXC_EMPTY_DIGEST_SHA512, WC_SHA512_DIGEST_SIZE);
                break;
            #endif /* WOLFSSL_SHA512 */
            default:
                return BAD_FUNC_ARG;
        }
        return 1; /* True */
    }
    return 0; /* False */
}

#ifndef MAX3266X_SHA_CB
#if !defined(NO_SHA)

WOLFSSL_API int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId)
{
    if (sha == NULL) {
        return BAD_FUNC_ARG;
    }
    (void)heap;
    (void)devId;
    return wc_MXC_TPU_SHA_Init(&(sha->mxcCtx));
}

WOLFSSL_API int wc_ShaUpdate(wc_Sha* sha, const unsigned char* data,
                                        unsigned int len)
{
    return wc_MXC_TPU_SHA_Update(&(sha->mxcCtx), data, len);
}

WOLFSSL_API int wc_ShaFinal(wc_Sha* sha, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_Final(&(sha->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA1);
}

WOLFSSL_API int wc_ShaGetHash(wc_Sha* sha, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_GetHash(&(sha->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA1);
}

WOLFSSL_API int wc_ShaCopy(wc_Sha* src, wc_Sha* dst)
{
    return wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
}

WOLFSSL_API void wc_ShaFree(wc_Sha* sha)
{
    wc_MXC_TPU_SHA_Free(&(sha->mxcCtx));
    return;
}

#endif /* NO_SHA */

#if defined(WOLFSSL_SHA224)

WOLFSSL_API int wc_InitSha224_ex(wc_Sha224* sha224, void* heap, int devId)
{
    if (sha224 == NULL) {
        return BAD_FUNC_ARG;
    }
    (void)heap;
    (void)devId;
    return wc_MXC_TPU_SHA_Init(&(sha224->mxcCtx));
}

WOLFSSL_API int wc_InitSha224(wc_Sha224* sha224)
{
    return wc_InitSha224_ex(sha224, NULL, INVALID_DEVID);
}

WOLFSSL_API int wc_Sha224Update(wc_Sha224* sha224, const unsigned char* data,
                                        unsigned int len)
{
    return wc_MXC_TPU_SHA_Update(&(sha224->mxcCtx), data, len);
}

WOLFSSL_API int wc_Sha224Final(wc_Sha224* sha224, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_Final(&(sha224->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA224);
}

WOLFSSL_API int wc_Sha224GetHash(wc_Sha224* sha224, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_GetHash(&(sha224->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA224);
}

WOLFSSL_API int wc_Sha224Copy(wc_Sha224* src, wc_Sha224* dst)
{
    return wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
}

WOLFSSL_API void wc_Sha224Free(wc_Sha224* sha224)
{
    wc_MXC_TPU_SHA_Free(&(sha224->mxcCtx));
    return;
}

#endif /* WOLFSSL_SHA224 */

#if !defined(NO_SHA256)

WOLFSSL_API int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    if (sha256 == NULL) {
        return BAD_FUNC_ARG;
    }
    (void)heap;
    (void)devId;
    return wc_MXC_TPU_SHA_Init(&(sha256->mxcCtx));
}

WOLFSSL_API int wc_InitSha256(wc_Sha256* sha256)
{
    return wc_InitSha256_ex(sha256, NULL, INVALID_DEVID);
}

WOLFSSL_API int wc_Sha256Update(wc_Sha256* sha256, const unsigned char* data,
                                        unsigned int len)
{
    return wc_MXC_TPU_SHA_Update(&(sha256->mxcCtx), data, len);
}

WOLFSSL_API int wc_Sha256Final(wc_Sha256* sha256, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_Final(&(sha256->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA256);
}

WOLFSSL_API int wc_Sha256GetHash(wc_Sha256* sha256, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_GetHash(&(sha256->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA256);
}

WOLFSSL_API int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    return wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
}

WOLFSSL_API void wc_Sha256Free(wc_Sha256* sha256)
{
    wc_MXC_TPU_SHA_Free(&(sha256->mxcCtx));
    return;
}

#endif /* NO_SHA256 */

#if defined(WOLFSSL_SHA384)

WOLFSSL_API int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
{
    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }
    (void)heap;
    (void)devId;
    return wc_MXC_TPU_SHA_Init(&(sha384->mxcCtx));
}

WOLFSSL_API int wc_InitSha384(wc_Sha384* sha384)
{
    return wc_InitSha384_ex(sha384, NULL, INVALID_DEVID);
}

WOLFSSL_API int wc_Sha384Update(wc_Sha384* sha384, const unsigned char* data,
                                        unsigned int len)
{
    return wc_MXC_TPU_SHA_Update(&(sha384->mxcCtx), data, len);
}

WOLFSSL_API int wc_Sha384Final(wc_Sha384* sha384, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_Final(&(sha384->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA384);
}

WOLFSSL_API int wc_Sha384GetHash(wc_Sha384* sha384, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_GetHash(&(sha384->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA384);
}

WOLFSSL_API int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst)
{
    return wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
}

WOLFSSL_API void wc_Sha384Free(wc_Sha384* sha384)
{
    wc_MXC_TPU_SHA_Free(&(sha384->mxcCtx));
    return;
}

#endif /* WOLFSSL_SHA384 */

#if defined(WOLFSSL_SHA512)

WOLFSSL_API int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
{
    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }
    (void)heap;
    (void)devId;
    return wc_MXC_TPU_SHA_Init(&(sha512->mxcCtx));
}

WOLFSSL_API int wc_InitSha512(wc_Sha512* sha512)
{
    return wc_InitSha512_ex(sha512, NULL, INVALID_DEVID);
}

WOLFSSL_API int wc_Sha512Update(wc_Sha512* sha512, const unsigned char* data,
                                        unsigned int len)
{
    return wc_MXC_TPU_SHA_Update(&(sha512->mxcCtx), data, len);
}

WOLFSSL_API int wc_Sha512Final(wc_Sha512* sha512, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_Final(&(sha512->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA512);
}

WOLFSSL_API int wc_Sha512GetHash(wc_Sha512* sha512, unsigned char* hash)
{
    return wc_MXC_TPU_SHA_GetHash(&(sha512->mxcCtx), hash,
                                        MXC_TPU_HASH_SHA512);
}

WOLFSSL_API int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    return wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
}

WOLFSSL_API void wc_Sha512Free(wc_Sha512* sha512)
{
    wc_MXC_TPU_SHA_Free(&(sha512->mxcCtx));
    return;
}

#endif /* WOLFSSL_SHA512 */
#endif /* !MAX3266X_SHA_CB*/
#endif /* MAX3266X_SHA || MAX3266X_SHA_CB */

#if defined(MAX3266X_MATH)

/* Sets mutex and initializes hardware according to needed operation size */
int wc_MXC_MAA_init(unsigned int len)
{
    int status;
    MAX3266X_MSG("Setting Hardware Mutex and Starting MAA");
    status = wolfSSL_HwPkMutexLock();
    if (status == 0) {
        status = MXC_TPU_MAA_Init(len);
    }
    return wc_MXC_error(&status); /* Return Status of Init */
}

/* Unlocks mutex and performs graceful shutdown of hardware */
int wc_MXC_MAA_Shutdown(void)
{
    int status;
    MAX3266X_MSG("Unlocking Hardware Mutex and Shutting Down MAA");
    status = MXC_TPU_MAA_Shutdown();
    if (status == E_BAD_PARAM) { /* Miss leading, Send WC_HW_ERROR */
                                /* This is returned when MAA cannot stop */
        status = WC_HW_E;
    }
    wolfSSL_HwPkMutexUnLock(); /* Always call Unlock in shutdown */
    return wc_MXC_error(&status);
}

/* Update used number for mp_int struct for results */
int wc_MXC_MAA_adjustUsed(unsigned int *array, unsigned int length)
{
    int i, lastNonZeroIndex;
    lastNonZeroIndex = -1; /* Track the last non-zero index */
    for (i = 0; i < length; i++) {
        if (array[i] != 0) {
            lastNonZeroIndex = i;
        }
    }
    return (lastNonZeroIndex + 1);
}

/* Determines the size of operation that needs to happen */
unsigned int wc_MXC_MAA_Largest(unsigned int count, ...)
{
    va_list args;
    int i;
    unsigned int largest, num;
    va_start(args, count);
    largest = va_arg(args, unsigned int);
    for (i = 1; i < count; i++) {
        num = va_arg(args, unsigned int);
        if (num > largest) {
            largest = num;
        }
    }
    va_end(args);
    return largest;
}

/* Determines if we need to fallback to Software */
int wc_MXC_MAA_Fallback(unsigned int count, ...)
{
    va_list args;
    int num, i;
    va_start(args, count);
    for (i = 0; i < count; i++) {
        num = va_arg(args, unsigned int);
        if (num > MXC_MAA_MAX_SIZE) {
            MAX3266X_MSG("HW Falling Back to Software");
            return 1;
        }
    }
    va_end(args);
    MAX3266X_MSG("HW Can Handle Input");
    return 0;
}

/* Have to zero pad the entire data array up to 256 bytes(2048 bits) */
/* If length > 256 bytes then error */
int wc_MXC_MAA_zeroPad(mp_int* multiplier, mp_int* multiplicand,
                            mp_int* exp, mp_int* mod, mp_int* result,
                            MXC_TPU_MAA_TYPE clc, unsigned int length)
{
    mp_digit* zero_tmp;
    MAX3266X_MSG("Zero Padding Buffers for Hardware");
    if (length > MXC_MAA_MAX_SIZE) {
        MAX3266X_MSG("Hardware cannot exceed 2048 bit input");
        return BAD_FUNC_ARG;
    }
    if ((result == NULL) || (multiplier == NULL) || (multiplicand == NULL) ||
            ((exp == NULL) && (clc == MXC_TPU_MAA_EXP)) || (mod == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* Create an array to compare values to to check edge for error edge case */
    zero_tmp = (mp_digit*)XMALLOC(multiplier->size*sizeof(mp_digit), NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (zero_tmp == NULL) {
        MAX3266X_MSG("NULL pointer found after XMALLOC call");
        return MEMORY_E;
    }
    XMEMSET(zero_tmp, 0x00, multiplier->size*sizeof(mp_digit));

    /* Check for invalid arguments before padding */
    switch ((char)clc) {
        case MXC_TPU_MAA_EXP:
            /* Cannot be 0 for a^e mod m operation */
            if (XMEMCMP(zero_tmp, exp, (exp->used*sizeof(mp_digit))) == 0) {
                XFREE(zero_tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                MAX3266X_MSG("Cannot use Value 0 for Exp");
                return BAD_FUNC_ARG;
            }

            /* Pad out rest of data if used != length to ensure no */
            /* garbage is used in calculation */
            if ((exp != NULL) && (clc == MXC_TPU_MAA_EXP)) {
                if ((exp->dp != NULL) && (exp->used < length)) {
                    MAX3266X_MSG("Zero Padding Exp Buffer");
                    XMEMSET(exp->dp + exp->used, 0x00,
                            sizeof(int) *(length - exp->used));
                }
            }

        /* Fall through to check mod is not 0 */
        case MXC_TPU_MAA_SQ:
        case MXC_TPU_MAA_MUL:
        case MXC_TPU_MAA_SQMUL:
        case MXC_TPU_MAA_ADD:
        case MXC_TPU_MAA_SUB:
            /* Cannot be 0 for mod m value */
            if (XMEMCMP(zero_tmp, mod, (exp->used*sizeof(mp_digit))) == 0) {
                XFREE(zero_tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                MAX3266X_MSG("Cannot use Value 0 for Exp");
                return BAD_FUNC_ARG;
            }

            /* Pad out rest of data if used != length to ensure no */
            /* garbage is used in calculation */
            if ((multiplier->dp != NULL) && (multiplier->used < length)) {
                MAX3266X_MSG("Zero Padding Multiplier Buffer");
                XMEMSET(multiplier->dp + multiplier->used, 0x00,
                    sizeof(int) * (length - multiplier->used));
            }
            if ((multiplicand->dp != NULL) && (multiplicand->used < length)) {
                MAX3266X_MSG("Zero Padding Multiplicand Buffer");
                XMEMSET(multiplicand->dp + multiplicand->used, 0x00,
                    sizeof(int) * (length - multiplicand->used));
            }
            if ((mod->dp != NULL) && (mod->used < length)) {
                MAX3266X_MSG("Zero Padding Mod Buffer");
                XMEMSET(mod->dp + mod->used, 0x00,
                            sizeof(int) *(length - mod->used));
            }
            break;
        default:
            /* Free the zero array used to check values */
            XFREE(zero_tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return BAD_FUNC_ARG; /* Invalid clc given */
    }
    /* Free the zero array used to check values */
    XFREE(zero_tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Make sure result is 0 padded */
    if (result->dp != NULL) {
        ForceZero(result->dp, sizeof(int)*(length));
        result->used = length;
    }
    else if (result == NULL) {
        return BAD_FUNC_ARG; /* Cannot be null */
    }
    return 0;
}



/* General Control Over MAA Hardware to handle all needed Cases */
int wc_MXC_MAA_math(mp_int* multiplier, mp_int* multiplicand, mp_int* exp,
                                mp_int* mod, mp_int* result,
                                MXC_TPU_MAA_TYPE clc)
{
    int ret;
    int length;
    mp_int* result_tmp_ptr;
    mp_int result_tmp;
    if (multiplier == NULL || multiplicand == NULL || mod == NULL ||
            (exp == NULL && clc == MXC_TPU_MAA_EXP) || result == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Check if result shares struct pointer */
    if ((multiplier == result) || (multiplicand == result) || (exp == result) ||
            (mod == result)) {
            MAX3266X_MSG("Creating Temp Result Buffer for Hardware");
            result_tmp_ptr = &result_tmp; /* Assign point to temp struct */
    }
    else {
        result_tmp_ptr = result; /* No Shared Point to directly assign */
    }
    if (result_tmp_ptr == NULL) {
        MAX3266X_MSG("tmp ptr is null");
        return MP_VAL;
    }

    if (clc == MXC_TPU_MAA_EXP) {
        length = wc_MXC_MAA_Largest(5, multiplier->used, multiplicand->used,
                                           exp->used, mod->used, result->used);
    }
    else {
        length = wc_MXC_MAA_Largest(4, multiplier->used, multiplicand->used,
                                        mod->used, result->used);
    }

    /* Zero Pad everything if needed */
    ret = wc_MXC_MAA_zeroPad(multiplier, multiplicand, exp, mod, result_tmp_ptr,
                                clc, length);
    if (ret != 0) {
        MAX3266X_MSG("Zero Padding Failed");
        return ret;
    }

    /* Init MAA HW */
    ret = wc_MXC_MAA_init(length*sizeof(mp_digit)*8);
    if (ret != 0) {
        MAX3266X_MSG("HW Init Failed");
        wolfSSL_HwPkMutexUnLock();
        return ret;
    }

    /* Start Math And Cast to expect types for SDK */
    MAX3266X_MSG("Starting Computation in MAA");
    ret = MXC_TPU_MAA_Compute(clc, (char *)(multiplier->dp),
                                    (char *)(multiplicand->dp),
                                    (char *)(exp->dp), (char *)(mod->dp),
                                    (int *)(result_tmp_ptr->dp),
                                    (length*sizeof(mp_digit)));
    MAX3266X_MSG("MAA Finished Computation");
    if (wc_MXC_error(&ret) != 0) {
        MAX3266X_MSG("HW Computation Error");
        wolfSSL_HwPkMutexUnLock();
        return ret;
    }

    ret = wc_MXC_MAA_Shutdown();
    if (ret != 0) {
        MAX3266X_MSG("HW Shutdown Failure");
        /* Shutdown will always call wolfSSL_HwPkMutexUnLock(); */
        /* before returning */
        return ret;
    }

    /* Copy tmp result if needed */
    if ((multiplier == result) || (multiplicand == result) || (exp == result) ||
            (mod == result)) {
        mp_copy(result_tmp_ptr, result);
        ForceZero(result_tmp_ptr, sizeof(result_tmp_ptr)); /* force zero */
    }

    result->used = wc_MXC_MAA_adjustUsed(result->dp, length);
    return ret;
}



int wc_MXC_MAA_expmod(mp_int* base, mp_int* exp, mp_int* mod,
                            mp_int* result)
{
    mp_int multiplicand;
    if (base == NULL || exp == NULL || mod == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&multiplicand, 0, sizeof(mp_int));
    multiplicand.dp[0] = 0x01;
    multiplicand.used = mod->used;
    MAX3266X_MSG("Preparing exptmod MAA HW Call");
    return wc_MXC_MAA_math(base, &multiplicand, exp, mod, result,
                            MXC_TPU_MAA_EXP);
}

int wc_MXC_MAA_sqrmod(mp_int* multiplier, mp_int* mod, mp_int* result)
{
    mp_int multiplicand;
    if (multiplier == NULL || mod == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET(&multiplicand, 0, sizeof(mp_int));
    multiplicand.dp[0] = 0x01;
    multiplicand.used = mod->used;
    MAX3266X_MSG("Preparing sqrmod MAA HW Call");
    return wc_MXC_MAA_math(multiplier, &multiplicand, NULL, mod, result,
                            MXC_TPU_MAA_SQ);
}

int wc_MXC_MAA_mulmod(mp_int* multiplier, mp_int* multiplicand, mp_int* mod,
                            mp_int* result)
{
    if (multiplier == NULL || multiplicand == NULL || mod == NULL ||
            result == NULL) {
        return BAD_FUNC_ARG;
    }
    MAX3266X_MSG("Preparing mulmod MAA HW Call");
    return wc_MXC_MAA_math(multiplier, multiplicand, NULL, mod, result,
                            MXC_TPU_MAA_MUL);
}

int wc_MXC_MAA_sqrmulmod(mp_int* multiplier, mp_int* multiplicand,
                            mp_int* exp, mp_int* mod, mp_int* result)
{
    if (multiplier == NULL || multiplicand == NULL || exp == NULL ||
            mod == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }
    MAX3266X_MSG("Preparing sqrmulmod MAA HW Call");
    return wc_MXC_MAA_math(multiplier, multiplicand, NULL, mod, result,
                            MXC_TPU_MAA_SQMUL);
}

int wc_MXC_MAA_addmod(mp_int* multiplier, mp_int* multiplicand, mp_int* mod,
                            mp_int* result)
{
    if (multiplier == NULL || multiplicand == NULL || mod == NULL ||
            result == NULL) {
        return BAD_FUNC_ARG;
    }
    MAX3266X_MSG("Preparing addmod MAA HW Call");
    return wc_MXC_MAA_math(multiplier, multiplicand, NULL, mod, result,
                            MXC_TPU_MAA_ADD);
}

int wc_MXC_MAA_submod(mp_int* multiplier, mp_int* multiplicand, mp_int* mod,
                            mp_int* result)
{
    if (multiplier == NULL || multiplicand == NULL || mod == NULL ||
            result == NULL) {
        return BAD_FUNC_ARG;
    }
    MAX3266X_MSG("Preparing submod MAA HW Call");
    if ((mod->used < multiplier->used) || (mod->used < multiplicand->used)) {
            MAX3266X_MSG("HW Limitation: Defaulting back to software");
            return mxc_submod(multiplier, multiplicand, mod, result);
    }
    else {
        return wc_MXC_MAA_math(multiplier, multiplicand, NULL, mod, result,
                             MXC_TPU_MAA_SUB);
    }
}

/* General Function to call hardware control */
int hw_mulmod(mp_int* multiplier, mp_int* multiplicand, mp_int* mod,
                    mp_int* result)
{
    if (multiplier == NULL || multiplicand == NULL || mod == NULL ||
            result == NULL) {
        return MP_VAL;
    }
    if ((multiplier->used == 0) || (multiplicand->used == 0)) {
        mp_zero(result);
        return 0;
    }
    else {
        if (wc_MXC_MAA_Fallback(3, multiplier->used, mod->used,
                                multiplicand->used) != 0) {
                return mxc_mulmod(multiplier, multiplicand, mod, result);
        }
        else {
            return wc_MXC_MAA_mulmod(multiplier, multiplicand, mod, result);
        }
    }
}

int hw_addmod(mp_int* a, mp_int* b, mp_int* mod, mp_int* result)
{
    int err = MP_OKAY;
    /* Validate parameters. */
    if ((a == NULL) || (b == NULL) || (mod == NULL) || (result == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        if (wc_MXC_MAA_Fallback(3, a->used, b->used, mod->used) != 0) {
            err = mxc_addmod(a, b, mod, result);
        }
        else {
            err = wc_MXC_MAA_addmod(a, b, mod, result);
        }
    }
    return err;
}


int hw_submod(mp_int* a, mp_int* b, mp_int* mod, mp_int* result)
{
    int err = MP_OKAY;
    /* Validate parameters. */
    if ((a == NULL) || (b == NULL) || (mod == NULL) || (result == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        if (wc_MXC_MAA_Fallback(3, a->used, b->used, mod->used) != 0) {
            err = mxc_submod(a, b, mod, result);
        }
        else{
            err = wc_MXC_MAA_submod(a, b, mod, result);
        }
    }
    return err;
}

int hw_exptmod(mp_int* base, mp_int* exp, mp_int* mod, mp_int* result)
{
    int err = MP_OKAY;
    /* Validate parameters. */
    if ((base == NULL) || (exp == NULL) || (mod == NULL) || (result == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        if ((mod->used < exp->used) || (mod->used < base->used)) {
            err = mxc_exptmod(base, exp, mod, result);
        }
        else if (wc_MXC_MAA_Fallback(3, base->used, exp->used, mod->used)
                    != 0) {
            return mxc_exptmod(base, exp, mod, result);
        }
        else{
            err = wc_MXC_MAA_expmod(base, exp, mod, result);
        }
    }
    return err;
}


/* No mod function available with hardware, however perform a submod    */
/* (a - 0) mod m will essentially perform the same operation as a mod m */
int hw_mod(mp_int* a, mp_int* mod, mp_int* result)
{
    mp_int b;
    if (a == NULL || mod == NULL || result == NULL) {
        return MP_VAL;
    }
    if (wc_MXC_MAA_Fallback(2, a->used, mod->used) != 0) {
        return mxc_mod(a, mod, result);
    }
    XMEMSET(&b, 0, sizeof(mp_int));
    b.used = mod->used; /* assume mod is determining size */
    return hw_submod(a, &b, mod, result);
}

int hw_sqrmod(mp_int* base, mp_int* mod, mp_int* result)
{
    if (base == NULL || mod == NULL || result == NULL) {
        return MP_VAL;
    }
    if (base->used == 0) {
        mp_zero(result);
        return 0;
    }
    return wc_MXC_MAA_sqrmod(base, mod, result);
}

#endif /* MAX3266X_MATH */

#if defined(MAX3266X_RTC)
/* Initialize the RTC */
int wc_MXC_RTC_Init(void)
{
    /* RTC Init for benchmark */
    if (MXC_RTC_Init(0, 0) != E_NO_ERROR) {
        return WC_HW_E;
    }
    /* Disable the Interrupt */
    if (MXC_RTC_DisableInt(MXC_RTC_INT_EN_LONG) == E_BUSY) {
        return WC_HW_E;
    }
    /* Start Clock for RTC */
    if (MXC_RTC_SquareWaveStart(MXC_RTC_F_512HZ) == E_BUSY) {
        return E_BUSY;
    }
    /* Begin RTC count */
    if (MXC_RTC_Start() != E_NO_ERROR) {
        return WC_HW_E;
    }
    return 0;
}

/* Reset the RTC */
int wc_MXC_RTC_Reset(void)
{
    /* Stops Counts */
    if (MXC_RTC_Stop() != E_NO_ERROR) {
        return WC_HW_E;
    }
    /* Restart RTC via Init */
    if (wc_MXC_RTC_Init() != E_NO_ERROR) {
        return WC_HW_E;
    }
    return 0;
}

/* Function to handle RTC read retries */
void wc_MXC_RTC_GetRTCValue(int32_t (*rtcGetFunction)(uint32_t*),
                                uint32_t* outValue, int32_t* err)
{
    *err = rtcGetFunction(outValue);  /* Initial attempt to get the value */
    while (*err != E_NO_ERROR) {
        *err = rtcGetFunction(outValue);  /* Retry if the error persists */
    }
}

/* Function to provide the current time as a double */
/* Returns seconds and millisecond */
double wc_MXC_RTC_Time(void)
{
    int32_t err;
    uint32_t rtc_seconds, rtc_subseconds;

    /* Retrieve sub-seconds from RTC */
    wc_MXC_RTC_GetRTCValue((int32_t (*)(uint32_t*))MXC_RTC_GetSubSeconds,
                                    &rtc_subseconds, &err);
    if (err != E_NO_ERROR) {
        return (double)err;
    }
    /* Retrieve seconds from RTC */
    wc_MXC_RTC_GetRTCValue((int32_t (*)(uint32_t*))MXC_RTC_GetSeconds,
                                &rtc_seconds, &err);
    if (err != E_NO_ERROR) {
        return (double)err;
    }
    /* Per the device documentation, subsecond register holds up to 1 second */
    /* subsecond register is size 2^12, so divide by 4096 to get milliseconds */
    return ((double)rtc_seconds + ((double)rtc_subseconds / 4096));
}

#endif /* MAX3266X_RTC */

#endif /* WOLFSSL_MAX32665 || WOLFSSL_MAX32666 */
