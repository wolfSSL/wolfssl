/* renesas_sce_ra6m3g.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

/* wolfSSL and wolfCrypt */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/port/Renesas/renesas_sce_ra6m3g.h>
/* Renesas RA SCE */
#include "common/hw_sce_common.h"
#include "hw_sce_private.h"
#include "hw_sce_trng_private.h"
#include "hw_sce_hash_private.h"
#include "hw_sce_aes_private.h"
#include "hw_sce_ecc_private.h"
#include "hw_sce_rsa_private.h"
/* Standard */
#include <stdio.h>

#define AES_BLOCK_WORDS (AES_BLOCK_SIZE / sizeof(word32))
#define AES128_KEYSIZE (16)
#define AES256_KEYSIZE (32)

#define ECC256_KEYSIZE (32)
#define ECC384_KEYSIZE (48)

#define RSA_1024_KEYSIZE (128)
#define RSA_2048_KEYSIZE (256)
#define RSA_MAX_PARAMS_SIZE (RSA_2048_KEYSIZE*5/2)
#define RSA_GENKEY_TRIES 10000

/*
   Initialize Renesas RA Secure Crypt Engine Hardware
   Hardware is Little Endian mode.

   return  FSP_SUCCESS:     HW initialized successfully
                     *:     Error
*/
int wc_Renesas_SCE_init(void) {
    fsp_err_t ret;

    HW_SCE_PowerOn();
    HW_SCE_SoftReset();

    ret = HW_SCE_Initialization1();
    if (FSP_SUCCESS == ret) {
        ret = HW_SCE_Initialization2();
    }
    if (FSP_SUCCESS == ret) {
        ret = HW_SCE_secureBoot();
        HW_SCE_EndianSetLittle();
    }
    return (int)ret;
}

/*
   TRNG
   Generate true random number with length "sz" using Renesas RA Hardware

   Inputs:
        sz      size(bytes) of output and amount of random number to generate.
   Outputs:
        output  byte buffer to store random number

   return  0:               HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not generate seed.
*/
int wc_Renesas_GenerateSeed(byte* output, word32 sz) {
    int ret = FSP_SUCCESS;
    uint32_t tmpOut[4] = {0};

    WOLFSSL_ENTER("wc_Renesas_GenerateSeed");
    if (output == NULL)
        ret = BAD_FUNC_ARG;

    /* Fill output with multiples of 128-bit random numbers */
    while (sz >= sizeof(tmpOut) && ret == FSP_SUCCESS) {
        ret = HW_SCE_RNG_Read((uint32_t*) output);
        output += sizeof(tmpOut);
        sz -= sizeof(tmpOut);
    }

    /* Truncate random number when sz is less than 128-bits */
    if (sz > 0 && ret == FSP_SUCCESS) {
        ret = HW_SCE_RNG_Read(tmpOut);
        XMEMCPY(output, tmpOut, sz);
    }

    if (ret == FSP_SUCCESS) {
        ret = 0;
    } else {
        if (ret != BAD_FUNC_ARG)
            ret = WC_HW_E;
    }

    return ret;
}

/*
   SHA-256 with Renesas RA Hardware

   Inputs:
        sha256  sha256->buffer is the buffer to transform.
        data    Unused. For compatibility or future use.
   Outputs:
        sha256  sha256->digest is where the transform output is stored.

   return  FSP_SUCCESS:     HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not hash message
*/
int wc_Renesas_Sha256Transform(wc_Sha256* sha256, const byte* data) {
    int ret = 0;
    (void) data;

    WOLFSSL_ENTER("wc_Renesas_Sha256Transform");
    if (sha256 == NULL)
        ret = BAD_FUNC_ARG;

    if (ret != BAD_FUNC_ARG && wolfSSL_CryptHwMutexLock() == 0) {
        HW_SCE_EndianSetBig();
        ret = HW_SCE_SHA256_UpdateHash((const uint32_t*) data,
                            (uint32_t) WC_SHA256_BLOCK_SIZE  / sizeof(word32),
                            (uint32_t*) sha256->digest);
        wolfSSL_CryptHwMutexUnLock();
        HW_SCE_EndianSetLittle();
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG) {
        WOLFSSL_MSG("Hardware error.");
        ret = WC_HW_E;
    }
    return ret;
}

/*
   AES-CBC Encrypt/Decrypt with Renesas RA Hardware

   Inputs:
        aes Contains AES key and parameters for stream re-use
        in  Plaintext to encrypt
        sz  Size of plaintext
        op  AES_SCE_ENCRYPT or AES_SCE_DECRYPT for desired operation
   Outputs:
        out Ciphertext message

   return  FSP_SUCCESS:     HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not encrypt message.
*/
int wc_Renesas_AesCbc(Aes* aes, byte* out, const byte* in, word32 sz, int op)
{
    word32 keySize = 0;
    uint32_t num_words = 0;
    int ret = 0;

    WOLFSSL_ENTER("wc_Renesas_AesCbcEncrypt");
    /* Only accept input with size that is a multiple AES_BLOCK_SIZE */
    if (sz % AES_BLOCK_SIZE != 0 ||
            aes == NULL || out == NULL || in == NULL)
        ret = BAD_FUNC_ARG;

    if (ret != BAD_FUNC_ARG && wolfSSL_CryptHwMutexLock() == 0)
    {
        wc_AesGetKeySize(aes, &keySize);
        num_words = (sz / sizeof(word32));

        if (op == AES_SCE_ENCRYPT && keySize == AES128_KEYSIZE)
            ret =  HW_SCE_AES_128CbcEncrypt((const uint32_t*) aes->key,
                                            (const uint32_t*) aes->reg,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*)       out,
                                            (uint32_t*)       aes->reg);
        else if (op == AES_SCE_ENCRYPT && keySize == AES256_KEYSIZE)
            ret =  HW_SCE_AES_256CbcEncrypt((const uint32_t*) aes->key,
                                            (const uint32_t*) aes->reg,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*)       out,
                                            (uint32_t*)       aes->reg);
#ifdef HAVE_AES_DECRYPT
        else if (op == AES_SCE_DECRYPT && keySize == AES128_KEYSIZE)
            ret =  HW_SCE_AES_128CbcDecrypt((const uint32_t*) aes->key,
                                            (const uint32_t*) aes->reg,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*)       out,
                                            (uint32_t*)       aes->reg);
        else if (op == AES_SCE_DECRYPT && keySize == AES256_KEYSIZE)
            ret =  HW_SCE_AES_256CbcDecrypt((const uint32_t*) aes->key,
                                            (const uint32_t*) aes->reg,
                                            (const uint32_t)  num_words,
                                            (const uint32_t*) in,
                                            (uint32_t*)       out,
                                            (uint32_t*)       aes->reg);
#endif
        else
            ret = BAD_FUNC_ARG;
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG) {
        WOLFSSL_MSG("Hardware error.");
        ret = WC_HW_E;
    }
    return ret;
}

/*
   AES-ECB Encrypt/Decrypt with Renesas RA Hardware

   Inputs:
        aes Contains AES key and parameters for stream re-use
        in  Plaintext to encrypt
        sz  Size of plaintext
        op  AES_SCE_ENCRYPT or AES_SCE_DECRYPT for desired operation
   Outputs:
        out Ciphertext message

   return  FSP_SUCCESS:     HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not encrypt message.
*/
int wc_Renesas_AesEcb(Aes* aes, byte* out, const byte* in, word32 sz, int op)
{
    word32 keySize = 0;
    uint32_t num_words = 0;
    int ret = 0;

    WOLFSSL_ENTER("wc_Renesas_AesEcbEncrypt");
    /* Only accept input with size that is a multiple AES_BLOCK_SIZE */
    if (sz % AES_BLOCK_SIZE != 0 ||
            aes == NULL || out == NULL || in == NULL)
        ret = BAD_FUNC_ARG;

    if (ret != BAD_FUNC_ARG && wolfSSL_CryptHwMutexLock() == 0)
    {
        wc_AesGetKeySize(aes, &keySize);
        num_words = (sz / sizeof(word32));

        if (op == AES_SCE_ENCRYPT && keySize == AES128_KEYSIZE)
            ret = HW_SCE_AES_128EcbEncrypt((const uint32_t*) aes->key,
                                           (const uint32_t)  num_words,
                                           (const uint32_t*) in,
                                           (uint32_t*)       out);
        else if (op == AES_SCE_ENCRYPT && keySize == AES256_KEYSIZE)
            ret = HW_SCE_AES_256EcbEncrypt((const uint32_t*) aes->key,
                                           (const uint32_t)  num_words,
                                           (const uint32_t*) in,
                                           (uint32_t*)       out);
#ifdef HAVE_AES_DECRYPT
        else if (op == AES_SCE_DECRYPT && keySize == AES128_KEYSIZE)
            ret = HW_SCE_AES_128EcbDecrypt((const uint32_t*) aes->key,
                                           (const uint32_t)  num_words,
                                           (const uint32_t*) in,
                                           (uint32_t*)       out);
        else if (op == AES_SCE_DECRYPT && keySize == AES256_KEYSIZE)
            ret = HW_SCE_AES_256EcbDecrypt((const uint32_t*) aes->key,
                                           (const uint32_t)  num_words,
                                           (const uint32_t*) in,
                                           (uint32_t*)       out);
#endif
        else
            ret = BAD_FUNC_ARG;
        wolfSSL_CryptHwMutexUnLock();
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG) {
        WOLFSSL_MSG("Hardware error.");
        ret = WC_HW_E;
    }
    return ret;
}

/*
   AES-CTR Encrypt with Renesas RA Hardware

   Inputs:
        aes Contains AES key and parameters for stream re-use
        in  Plaintext to encrypt
        sz  Size of plaintext
   Outputs:
        out Ciphertext message

   return  FSP_SUCCESS:     HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not encrypt message.
*/
int wc_Renesas_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz) {
    word32 keySize = 0;
    int ret = 0;
    const byte* tmp;
    uint32_t* outTmp;
    byte inTmp[AES_BLOCK_SIZE] = {0};

    WOLFSSL_ENTER("wc_Renesas_AesCtrEncrypt");

    if (aes == NULL || out == NULL || in == NULL)
        ret = BAD_FUNC_ARG;

    wc_AesGetKeySize(aes, &keySize);
    if (!(keySize == AES128_KEYSIZE || keySize == AES256_KEYSIZE))
        ret = BAD_FUNC_ARG;

    /* Use remaining AES stream from previous non-AES_BLOCK_SIZE operation */
    tmp = (byte*)aes->tmp + AES_BLOCK_SIZE - aes->left;
    while (aes->left && sz && ret != BAD_FUNC_ARG) {
       *(out++) = *(in++) ^ *(tmp++);
       aes->left--;
       sz--;
    }

    while (sz) {
        tmp = in;
        outTmp = (uint32_t*) out;

        if (sz < AES_BLOCK_SIZE) {
            /* Copy remaining bytes into AES_BLOCK_SIZE buffer */
            XMEMCPY(inTmp, in, sz);
            tmp = inTmp;
            /* Set output to aes->tmp for future stream re-use */
            outTmp = (uint32_t*) aes->tmp;
        }

        if (wolfSSL_CryptHwMutexLock() != 0)
            break;

        if (keySize == AES128_KEYSIZE)
            ret = HW_SCE_AES_128CtrEncrypt((const uint32_t*) aes->key,
                                           (const uint32_t*) aes->reg,
                                           (const uint32_t)  AES_BLOCK_WORDS,
                                           (const uint32_t*) tmp,
                                           (uint32_t*)       outTmp,
                                           (uint32_t*)       aes->reg);
        else if (keySize == AES256_KEYSIZE)
            ret = HW_SCE_AES_256CtrEncrypt((const uint32_t*) aes->key,
                                           (const uint32_t*) aes->reg,
                                           (const uint32_t)  AES_BLOCK_WORDS,
                                           (const uint32_t*) tmp,
                                           (uint32_t*)       outTmp,
                                           (uint32_t*)       aes->reg);
        else
            ret = BAD_FUNC_ARG;

        wolfSSL_CryptHwMutexUnLock();
        if (ret != FSP_SUCCESS)
            break;

        if (sz < AES_BLOCK_SIZE) {
            /* Finished remaining bytes.
             * Bookkeeping for future stream re-use.
             */
            XMEMCPY(out, aes->tmp, sz);
            aes->left = AES_BLOCK_SIZE - sz;
            break;
        } else {
            out += AES_BLOCK_SIZE;
            in  += AES_BLOCK_SIZE;
            sz  -= AES_BLOCK_SIZE;
            aes->left = 0;
        }
    }

    if (ret != FSP_SUCCESS && ret != BAD_FUNC_ARG) {
        WOLFSSL_MSG("Hardware error.")
        ret = WC_HW_E;
    }
    return ret;
}

#if defined(HAVE_ECC) && !defined(NO_RSA)
/*
   Helper function for Renesas ECC hardware functions.
   Formats ECC domain and other parameters to be consumed by hardware.
   This isn't expected to be called by user.

   Inputs:
       key  ECC key containing parameters to populate domain and gxy
       domain[4*ECC384_KEYSIZE] = {0};
       gxy[2*ECC384_KEYSIZE]    = {0};
   Outputs:
       domain = (Af || Bf || prime || order)
       gxy    = (Gx || Gy)

   return  MP_OKAY:         domain and gxy populated from ECC key
           BAD_FUNC_ARG:    Invalid Argument
*/
#define _ECC_PARAMS 6 /* (Af || Bf || prime || order || Gx || Gy) */
static int Renesas_EccFormatArgs(ecc_key* key, byte* domain, byte* gxy) {
    word32 keySz = 0;
    int i;
    int ret;

    mp_int tmp_mp[1];
    const char* paramStrs[_ECC_PARAMS] = {0};
    byte* domainPtrs[_ECC_PARAMS] = {0};

    if (key != NULL && key->dp != NULL  &&
            domain != NULL && gxy != NULL) {
        keySz = (word32)wc_ecc_size(key);
    }

    if (keySz == ECC256_KEYSIZE || keySz == ECC384_KEYSIZE)
    {
        /* Convert ECC parameters into format expected by hardware */
        /* Create array of pointers, used in for loop iterations */
        paramStrs[0] = key->dp->Af;
        paramStrs[1] = key->dp->Bf;
        paramStrs[2] = key->dp->prime;
        paramStrs[3] = key->dp->order;
        paramStrs[4] = key->dp->Gx;
        paramStrs[5] = key->dp->Gy;
        /* (Af || Bf || prime || order) */
        domainPtrs[0] = &domain[0];
        domainPtrs[1] = &domain[1*keySz];
        domainPtrs[2] = &domain[2*keySz];
        domainPtrs[3] = &domain[3*keySz];
        /* (Gx || Gy) */
        domainPtrs[4] = &gxy[0];
        domainPtrs[5] = &gxy[keySz];

        /* convert Hex string -> mp_int -> byte array */
        ret = mp_init(tmp_mp);
        for (i = 0; i < _ECC_PARAMS; i++) {
            if (ret != MP_OKAY)
                break;
            ret = mp_read_radix(tmp_mp, paramStrs[i], MP_RADIX_HEX);
            if (ret != MP_OKAY)
                break;
            ret = mp_to_unsigned_bin(tmp_mp, domainPtrs[i]);
            if (ret != MP_OKAY)
                break;
        }
        mp_clear(tmp_mp);
    } else {
        ret = BAD_FUNC_ARG;
    }
    if (ret != MP_OKAY) {
        WOLFSSL_MSG("Unable to format ECC parameters for hardware.");
    }
    return ret;
}

/*
   Generate an ECC Key using Renesas RA Hardware
   Supported Curves: ECC_SECP256R1, ECC_SECP256K1, ECC_SECP384R1

   Outputs:
       key  Generated key is populated within here.
            Caller must pass in initialized ecc_key*

   return  MP_OKAY:         HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           ECC_CURVE_OID_E: Unsupported curve
           WC_HW_E:         Hardware could not generate key
*/
int wc_Renesas_EccGenerateKey(ecc_key* key)
{
    word32 keySz = 0;
    word32 pubSz = 0;
    int ret = MP_OKAY;

    /* ECC parameters for hardware consumption. Size up to 384-bit key. */
    byte priv[ECC384_KEYSIZE]     = {0};  /* HW Output: Stored in key */
    byte gxy[2*ECC384_KEYSIZE]    = {0};  /* (Gx || Gy) */
    byte pub[2*ECC384_KEYSIZE+1]  = {0};  /* HW Output: (0x04 || Px || Py) */
    byte domain[4*ECC384_KEYSIZE] = {0};  /* (Af || Bf || prime || order) */

    WOLFSSL_ENTER("wc_Renesas_EccGenerateKey");
    if (key == NULL || key->dp == NULL)
        ret = BAD_FUNC_ARG;

    if (ret == MP_OKAY) {
        keySz = (word32)wc_ecc_size(key);
        /* Size for Px and Py with + 1 for 0x04 at pub[0] */
        pubSz = 2*keySz + 1;
        /* Build up key parameters into format expected by hardware */
        /* MP_OKAY if successful */
        ret = Renesas_EccFormatArgs(key, domain, gxy);
    }

    /* Perform Hardware Key Generation */
    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        switch (key->dp->id) {
        case ECC_SECP256R1:
        case ECC_SECP256K1:
            ret = (int) HW_SCE_ECC_256GenerateKey((const uint32_t*) domain,
                                                  (const uint32_t*) gxy,
                                                  (uint32_t*)       priv,
                                                  (uint32_t*)       &pub[1]);
            break;
        case ECC_SECP384R1:
            ret = (int) HW_SCE_ECC_384GenerateKey((const uint32_t*) domain,
                                                  (const uint32_t*) gxy,
                                                  (uint32_t*)       priv,
                                                  (uint32_t*)       &pub[1]);
            break;
        default:
            ret = ECC_CURVE_OID_E; /* Unsupported Curve */
            break;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret == FSP_SUCCESS) {
            pub[0] = 0x04; /* point type needed by wc_ecc_import_x963_ex */
            /* import returns MP_OKAY if successful */
            ret = wc_ecc_import_private_key((const byte*) priv, keySz,
                                            (const byte*) pub,  pubSz, key);
        } else {
            /* Error from Hardware */
            if (ret != ECC_CURVE_OID_E)
                ret = WC_HW_E;
        }
    }
    return ret;
}

/*
   Generate an ECC signature using Renesas RA Hardware
   Supported Curves: ECC_SECP256R1, ECC_SECP256K1, ECC_SECP384R1

   Inputs:
       key     ECC key
       hash    The message digest to sign. Cannot be all 0's.
       hashlen The length of the hash (bytes). Must be same size as key.
   Outputs:
       r       The signature R component
       s       The signature S component

   return      MP_OKAY:         Sign generated successfully
               BAD_FUNC_ARG:    Invalid Argument
               ECC_CURVE_OID_E: Unsupported curve
               WC_HW_E:         Hardware could not generate sign
*/
int wc_Renesas_EccGenerateSign(ecc_key* key, const byte* hash,
                               const word32 hashlen, mp_int* r, mp_int* s)
{
    word32 keySz = 0;
    int ret = MP_OKAY;

    /* ECC parameters for hardware consumption */
    byte priv[ECC384_KEYSIZE]     = {0};  /* Raw Private Key */
    byte gxy[2*ECC384_KEYSIZE]    = {0};  /* (Gx || Gy) */
    byte sigRS[2*ECC384_KEYSIZE]  = {0};  /* (r || s) */
    byte domain[4*ECC384_KEYSIZE] = {0};  /* (Af || Bf || prime || order) */

    WOLFSSL_ENTER("wc_Renesas_EccGenerateSign");
    if (key == NULL || key->dp == NULL ||
            r == NULL || s == NULL || hash == NULL) {
        WOLFSSL_MSG("NULL input.\n");
        ret = BAD_FUNC_ARG;
    }

    keySz = (word32)wc_ecc_size(key);
    if (hashlen != keySz) {
        WOLFSSL_MSG("Hash length does not match key size.");
        ret = BAD_FUNC_ARG;
    }

    /* Build up key parameters into format expected by hardware */
    /* MP_OKAY if successful */
    if (ret == MP_OKAY)
    {
        ret = Renesas_EccFormatArgs(key, domain, gxy);
        /* Convert Private Key from mp_int to raw binary */
        if (ret == MP_OKAY) {
            ret = mp_to_unsigned_bin(&key->k, priv);
        }
    }

    /* Perform Hardware Key Generation */
    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        switch (key->dp->id) {
        case ECC_SECP256R1:
        case ECC_SECP256K1:
            ret = (int) HW_SCE_ECC_256GenerateSign((const uint32_t*) domain,
                                                   (const uint32_t*) gxy,
                                                   (const uint32_t*) priv,
                                                   (const uint32_t*) hash,
                                                   (uint32_t*) &sigRS[0],
                                                   (uint32_t*) &sigRS[keySz]);
            break;
        case ECC_SECP384R1:
            ret = (int) HW_SCE_ECC_384GenerateSign((const uint32_t*) domain,
                                                   (const uint32_t*) gxy,
                                                   (const uint32_t*) priv,
                                                   (const uint32_t*) hash,
                                                   (uint32_t*) &sigRS[0],
                                                   (uint32_t*) &sigRS[keySz]);
            break;
        default:
            WOLFSSL_MSG("Unsupported ECC Curve.");
            ret = ECC_CURVE_OID_E;
            break;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret == FSP_SUCCESS) {
            ret = mp_read_unsigned_bin(r, &sigRS[0], (int) keySz);
            if (ret == MP_OKAY)
                mp_read_unsigned_bin(s, &sigRS[keySz], (int) keySz);
        } else {
            WOLFSSL_MSG("ECC Sign failed.");
            if (ret != ECC_CURVE_OID_E)
                ret = WC_HW_E;
        }
    }
    return ret;
}

/*
   Verify an ECC signature using Renesas RA Hardware
   Supported Curves: ECC_SECP256R1, ECC_SECP256K1, ECC_SECP384R1

   Inputs:
       key         The corresponding public ECC key
       r           The signature R component to verify
       s           The signature S component to verify
       hash        The message digest that was signed
       hashlen     The length of the hash (bytes)
   Outputs:
       res         Result of signature, 1==valid, 0==invalid
                   res is expected to be set to 0 prior to call.

   return  MP_OKAY:         HW completed successfully (res = 0 or res = 1)
           BAD_FUNC_ARG:    Invalid Argument  (res = 0)
           ECC_CURVE_OID_E: Unsupported curve (res = 0)
*/
int wc_Renesas_EccVerifySign(ecc_key* key, mp_int* r, mp_int* s,
                             const byte* hash, const word32 hashlen, int* res)
{
    word32 keySz = 0;
    int ret = MP_OKAY;

    /* ECC parameters for hardware consumption */
    byte gxy[2*ECC384_KEYSIZE]    = {0};  /* (Gx || Gy) */
    byte pub[2*ECC384_KEYSIZE]    = {0};  /* (Px || Py) */
    byte sigRS[2*ECC384_KEYSIZE]  = {0};  /* ( r || s ) */
    byte domain[4*ECC384_KEYSIZE] = {0};  /* (Af || Bf || prime || order) */

    WOLFSSL_ENTER("wc_Renesas_EccVerifySign");
    if (key == NULL || key->dp == NULL ||
            s == NULL || hash == NULL || r == NULL) {
        WOLFSSL_MSG("NULL input.");
        ret = BAD_FUNC_ARG;
    }

    /* Input hash must be exactly the key size and cannot be all 0's */
    keySz = (word32)wc_ecc_size(key);
    if (hashlen != keySz || keySz > ECC384_KEYSIZE ||
            XMEMCMP(hash, sigRS, keySz) == 0) {
        WOLFSSL_MSG("Invalid Hash or Hash length.");
        ret = BAD_FUNC_ARG;
    }

    /* Build up key parameters into format expected by hardware */
    /* MP_OKAY if successful */
    if (ret == MP_OKAY) {
        ret = Renesas_EccFormatArgs(key, domain, gxy);
        /* Concatenate r and s */
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(r, &sigRS[0]);
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(s, &sigRS[keySz]);
        /* Concatenate Px and Py */
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(key->pubkey.x, &pub[0]);
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(key->pubkey.y, &pub[keySz]);
    }

    /* Perform Hardware Key Generation */
    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        switch (key->dp->id) {
        case ECC_SECP256R1:
        case ECC_SECP256K1:
            ret = (int) HW_SCE_ECC_256VerifySign((const uint32_t*) domain,
                                                 (const uint32_t*) gxy,
                                                 (const uint32_t*) pub,
                                                 (const uint32_t*) hash,
                                                 (const uint32_t*) &sigRS[0],
                                                 (const uint32_t*) &sigRS[keySz]);
            break;
        case ECC_SECP384R1:
            ret = (int) HW_SCE_ECC_384VerifySign((const uint32_t*) domain,
                                                 (const uint32_t*) gxy,
                                                 (const uint32_t*) pub,
                                                 (const uint32_t*) hash,
                                                 (const uint32_t*) &sigRS[0],
                                                 (const uint32_t*) &sigRS[keySz]);
            break;
        default:
            WOLFSSL_MSG("Unsupported ECC Curve.");
            ret = ECC_CURVE_OID_E;
            break;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret == FSP_SUCCESS) {
            *res = 1;
            ret = MP_OKAY;
        } else {
            /* invalid signature, result should already be 0 */
            if (ret == FSP_ERR_CRYPTO_SCE_VERIFY_FAIL) {
                WOLFSSL_MSG("Verify failed.");
                ret = MP_OKAY;
            }
        }

    }
    return ret;
}

/*
   ECC Scalar Multiplication using Renesas RA Hardware
   Supported Curves: ECC_SECP256R1, ECC_SECP256K1, ECC_SECP384R1

   Acts as a HW replacement to wc_ecc_mulmod_ex
   Note: The hardware performance is worse than using wolfSSL software
         mulmod with WOLFSSL_HAVE_SP_ECC and WOLFSSL_SP_ARM_CORTEX_M_ASM.

   Inputs:
       k        The multiplicand
       G        Base point to multiply
       a        ECC curve parameter a
       b        ECC curve parameter b
       modulus  prime / modulus for the curve
       map      [boolean] If non-zero maps the point back to affine coordinates,
                 otherwise it's left in jacobian-montgomery form

   Outputs:
       R        Destination of product

   return  MP_OKAY:         HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           ECC_CURVE_OID_E: Unsupported curve
*/
int wc_Renesas_EccMulmod(mp_int* k, ecc_point *G, ecc_point *R,
                            mp_int* a, mp_int* b, mp_int* modulus, int map) {

    word32 keySize = 0;
    int ret = MP_OKAY;
    uint8_t k_bin[ECC384_KEYSIZE]    = {0};
    uint8_t g_bin[2*ECC384_KEYSIZE]  = {0}; /* HW In:  (Gx || Gy) / (Px || Py) */
    uint8_t r_bin[2*ECC384_KEYSIZE]  = {0}; /* HW Out: (Rx || Ry) */
    uint8_t domain[3*ECC384_KEYSIZE] = {0}; /* (a || b || modulus) */

    WOLFSSL_ENTER("wc_Renesas_Ecc256Mulmod");
    if (k == NULL || G == NULL || R == NULL ||
            a == NULL || b == NULL || modulus == NULL)
    {
        WOLFSSL_MSG("NULL Input.");
        ret = BAD_FUNC_ARG;
    }

    if (k->dp == NULL || G->x == NULL || G->y == NULL
            || R->x == NULL || R->y == NULL ||
            (k->used != G->x->used) ||
            (k->used != modulus->used) ||
            (k->used != a->used) ||
            (k->used != b->used))
    {
        WOLFSSL_MSG("Invalid input sizes.");
        ret = BAD_FUNC_ARG;
    }

    /* Build up key parameters into format expected by hardware */
    /* MP_OKAY if successful */
    if (ret == MP_OKAY) {
        keySize = (word32) k->used * 4;
        /* mp_int k to raw binary */
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(k, k_bin);
        /* Build domain == (a || b || modulus) */
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(a, &domain[0]);
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(b, &domain[1*keySize]);
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(modulus, &domain[2*keySize]);
        /* Build g_bin = (Gx || Gy) */
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(G->x, &g_bin[0]);
        if (ret == MP_OKAY)
            ret = mp_to_unsigned_bin(G->y, &g_bin[keySize]);
    }

    /* Perform Hardware Multiplication */
    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        switch (keySize) {
         case ECC256_KEYSIZE:
            ret = (int) HW_SCE_ECC_256ScalarMultiplication(
                                                       (const uint32_t*) domain,
                                                       (const uint32_t*) k_bin,
                                                       (const uint32_t*) g_bin,
                                                       (uint32_t*)       r_bin);
             break;
         case ECC384_KEYSIZE:
            ret = (int) HW_SCE_ECC_384ScalarMultiplication(
                                                       (const uint32_t*) domain,
                                                       (const uint32_t*) k_bin,
                                                       (const uint32_t*) g_bin,
                                                       (uint32_t*)       r_bin);
             break;
         default:
             WOLFSSL_MSG("Unsupported ECC Curve.");
             ret = ECC_CURVE_OID_E;
             break;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret == FSP_SUCCESS) {
            ret = mp_read_unsigned_bin(R->x, &r_bin[0], (int) keySize);
            if (ret == MP_OKAY)
                mp_read_unsigned_bin(R->y, &r_bin[keySize], (int) keySize);
            if (map == 1)
                ret = mp_copy(G->z, R->z);
        } else {
            WOLFSSL_MSG("ECC Sign failed.");
            if (ret != ECC_CURVE_OID_E)
                ret = WC_HW_E;
        }
    }
    return ret;
}
#endif /* HAVE_ECC && !NO_RSA */

#if !defined(NO_RSA)
/* RSA */
/*
   Generate an RSA Key using Renesas RA Hardware
   Supported Key Sizes: 1024 and 2048

   Inputs:
      e     public modulus
      size  key size (bits)
   Outputs:
      rsa  key is populated with HW generated parameters

   return  MP_OKAY:         HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not generate key
*/
int wc_Renesas_RsaGenerateKey(RsaKey* rsa, long e, int size)
{
    int ret = MP_OKAY;
    /* Individual param size (bytes) */
    const int paramSz = (size / (WOLFSSL_BIT_SIZE*2));
    byte priv[RSA_2048_KEYSIZE]      = {0};
    byte n[RSA_2048_KEYSIZE]         = {0};
    byte domain[RSA_MAX_PARAMS_SIZE] = {0};/* HW Out: (dQ || q || dP || p || u) */

    WOLFSSL_ENTER("wc_Renesas_RsaGenerateKey");
    if (rsa == NULL)
        ret = BAD_FUNC_ARG;

    /* Perform Hardware Key Generation */
    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        /* convert size bits to bytes */
        size /= 8;
        /* Hardware Key Generation */
        switch (size) {
        case RSA_1024_KEYSIZE:
            ret = (int) HW_SCE_RSA_1024KeyGenerate((uint32_t)  RSA_GENKEY_TRIES,
                                                   (uint32_t*) priv,
                                                   (uint32_t*) n,
                                                   (uint32_t*) domain);
            break;
        case RSA_2048_KEYSIZE:
            ret = (int) HW_SCE_RSA_2048KeyGenerate((uint32_t)  RSA_GENKEY_TRIES,
                                                   (uint32_t*) priv,
                                                   (uint32_t*) n,
                                                   (uint32_t*) domain);
            break;
        default:
            ret = BAD_FUNC_ARG; /* Unsupported RSA Key Size */
            break;
        }
        wolfSSL_CryptHwMutexUnLock();

        /* Set Generated Key into RsaKey */
        if (ret == FSP_SUCCESS) {
            /* Setup RsaKey buffers */
            if (ret == MP_OKAY)
                ret = mp_init_multi(&rsa->n, &rsa->e, &rsa->d,
                                    &rsa->p, &rsa->q, NULL);
            /* Set n and e */
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&rsa->n, n, size);
            if (ret == MP_OKAY)
                ret = mp_set_int(&rsa->e, (mp_digit)e);
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
            /* Set Private Key Parameters */
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&rsa->d, priv, size);
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&rsa->p,&domain[3*paramSz],paramSz);
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&rsa->q,&domain[1*paramSz],paramSz);
            rsa->type = RSA_PRIVATE;
#else
            rsa->type = RSA_PUBLIC;
#endif

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
            if (ret == MP_OKAY)
                ret = mp_init_multi(&rsa->dP, &rsa->dQ, &rsa->u,NULL,NULL,NULL);
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&rsa->dQ,&domain[0],paramSz);
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&rsa->dP,&domain[2*paramSz],paramSz);
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&rsa->u,&domain[4*paramSz],paramSz);
#endif
        } else {
            /* Error from Hardware */
            if (ret != BAD_FUNC_ARG)
                ret = WC_HW_E;
        }
    }
    return ret;
}

/*
   RSA Functionality Interface for Renesas RA Hardware
   Supported Key Sizes: 1024 and 2048

   Serves as a replacement for wc_RsaFunction()

   Inputs:
      in        plain/cipher text padded to key size (if not already key size)
      inLen     Must be multiples of key size (bytes)
      key       Contains public/private RSA key
      rng       Only used in software fallback (wc_RsaFunction)
      rsa_type  RSA_PUBLIC_ENCRYPT or RSA_PRIVATE_DECRYPT
      pad_value RSA_BLOCK_TYPE1 or RSA_BLOCK_TYPE2 depending on rsa_type
   Outputs:
      out       cipher/plain text
      outLen    The amount of bytes encrypted/decrypted.

   return  MP_OKAY:         HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not complete operation
*/

int wc_Renesas_RsaFunction(const byte* in, word32 inLen, byte* out, word32* outLen,
                           int rsa_type, RsaKey* key, WC_RNG* rng, byte pad_value)
{
    int ret;
    (void) pad_value; /* unused in wc_RsaFunction */
    (void) rng;       /* used only in wc_RsaFunction */
    if (rsa_type == RSA_PUBLIC_ENCRYPT && pad_value == RSA_BLOCK_TYPE_2) {
        ret = wc_Renesas_RsaPublicEncrypt(in, inLen, out, outLen, key);
    } else if (rsa_type == RSA_PRIVATE_DECRYPT && pad_value == RSA_BLOCK_TYPE_2) {
    #if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
        ret = wc_Renesas_RsaPrivateCrtDecrypt(in, inLen, out, outLen, key);
    #else
        ret = wc_Renesas_RsaPrivateDecrypt(in, inLen, out, outLen, key);
    #endif
    } else { /* Resort to software */
        ret = wc_RsaFunction(out, inLen, out, outLen, rsa_type, key, rng);
    }
    return ret;
}

/*
   RSA Public Encrypt using Renesas RA Hardware
   Supported Key Sizes: 1024 and 2048

   Inputs:
      in        plain text padded to key size (if not already key size)
      inLen     Must be multiples of key size (bytes)
      key       Contains private RSA key
   Outputs:
      out       Cipher text
      outLen    The amount of bytes encrypted.

   return  MP_OKAY:         HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not complete operation
*/
int wc_Renesas_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                word32* outLen, RsaKey* key)
{
    word32 i, keySz;
    int ret = MP_OKAY;
    uint8_t n[RSA_2048_KEYSIZE] = {0};
    uint32_t e;

    WOLFSSL_ENTER("wc_Renesas_RsaPublicEncrypt");
    if (in == NULL || out == NULL || key == NULL ||
            outLen == NULL)
        ret = BAD_FUNC_ARG;

    keySz = (word32) wc_RsaEncryptSize(key);

    /* Make sure inLen is a multiple of key size */
    if ((inLen % keySz) != 0 || *outLen < inLen)
        ret = BAD_FUNC_ARG;

    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->n, n);
    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->e, (uint8_t*)&e);
    if (ret == MP_OKAY) /*TODO: implement ByteReverseWords without NO_INLINE */
        ByteReverseWords((word32*)&e, (word32*)&e, sizeof(word32));

    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        for (i = 0; i < inLen; i += keySz)
        {
            switch (keySz) {
            case RSA_1024_KEYSIZE:
                ret = (int) HW_SCE_RSA_1024PublicKeyEncrypt(
                                                       (const uint32_t*) &in[i],
                                                       (const uint32_t*) &e,
                                                       (const uint32_t*) n,
                                                       (uint32_t*) &out[i]);
                break;
            case RSA_2048_KEYSIZE:
                ret = (int) HW_SCE_RSA_2048PublicKeyEncrypt(
                                                       (const uint32_t*) &in[i],
                                                       (const uint32_t*) &e,
                                                       (const uint32_t*) n,
                                                       (uint32_t*) &out[i]);
                break;
            default:
                ret = BAD_FUNC_ARG; /* Unsupported RSA Key Size */
                break;
            }
            if (ret != FSP_SUCCESS) /* Exit loop on error */
                break;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret == FSP_SUCCESS) {
            ret = (int) i;
            *outLen = i;
        } else if (ret != BAD_FUNC_ARG) {
            /* Error from Hardware */
            ret = WC_HW_E;
        }
    }
    return ret;
}

/*
   RSA Private Decrypt using Renesas RA Hardware
   Supported Key Sizes: 1024 and 2048

   Inputs:
      in        cipher text
      inLen     Must be multiples of key size (bytes)
      key       Contains private RSA key
   Outputs:
      out       Plain text w/ padding
      outLen    The amount of bytes decrypted.

   return  MP_OKAY:         HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not complete operation
*/
int wc_Renesas_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                 word32* outLen, RsaKey* key)
{
    word32 i, keySz;
    int ret = MP_OKAY;
    uint8_t d[RSA_2048_KEYSIZE] = {0};
    uint8_t n[RSA_2048_KEYSIZE] = {0};

    WOLFSSL_ENTER("wc_Renesas_RsaPrivateDecrypt");
    if (in == NULL || out == NULL || key == NULL ||
            outLen == NULL)
        ret = BAD_FUNC_ARG;

    keySz = (word32) wc_RsaEncryptSize(key);

    /* Make sure inLen is a multiple of key size */
    if ((inLen % keySz) != 0 || *outLen < inLen)
        ret = BAD_FUNC_ARG;

    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->d, d);
    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->n, n);

    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        for (i = 0; i < inLen; i += keySz)
        {
            switch (keySz) {
            case RSA_1024_KEYSIZE:
                ret = (int) HW_SCE_RSA_1024PrivateKeyDecrypt(
                                                       (const uint32_t*) &in[i],
                                                       (const uint32_t*) d,
                                                       (const uint32_t*) n,
                                                       (uint32_t*) &out[i]);
                break;
            case RSA_2048_KEYSIZE:
                ret = (int) HW_SCE_RSA_2048PrivateKeyDecrypt(
                                                       (const uint32_t*) &in[i],
                                                       (const uint32_t*) d,
                                                       (const uint32_t*) n,
                                                       (uint32_t*) &out[i]);
                break;
            default:
                ret = BAD_FUNC_ARG; /* Unsupported RSA Key Size */
                break;
            }
            if (ret != FSP_SUCCESS) /* Exit loop on error */
                break;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret == FSP_SUCCESS) {
            ret = (int) i;
            *outLen = i;
        } else {
            /* Error from Hardware */
            if (ret != BAD_FUNC_ARG)
                ret = WC_HW_E;
        }
    }
    return ret;
}
/*
   RSA Private Decrypt w/ Chinese Remainder Theorem
   using Renesas RA Hardware
   Supported Key Sizes: 1024 and 2048

   Inputs:
      in        cipher text
      inLen     Must be multiples of key size (bytes)
      key       Contains: dQ, q, dP, p, u
   Outputs:
      out       Plain text w/ padding
      outLen    The amount of bytes decrypted.

   return  MP_OKAY:         HW completed successfully
           BAD_FUNC_ARG:    Invalid Argument
           WC_HW_E:         Hardware could not complete operation
*/
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
int wc_Renesas_RsaPrivateCrtDecrypt(const byte* in, word32 inLen, byte* out,
                                    word32* outLen, RsaKey* key)
{
    word32 i, keySz;
    word32 paramSz; /* Individual param size (bytes) */
    int ret = MP_OKAY;
    byte domain[RSA_MAX_PARAMS_SIZE] = {0};/* HW In: (dQ || q || dP || p || u) */

    WOLFSSL_ENTER("wc_Renesas_RsaPrivateCrtDecrypt");
    if (in == NULL || out == NULL || key == NULL ||
            outLen == NULL)
        ret = BAD_FUNC_ARG;

    keySz = (word32) wc_RsaEncryptSize(key);
    paramSz = (keySz / 2);

    /* Make sure inLen is a multiple of key size */
    if ((inLen % keySz) != 0 || *outLen < inLen)
        ret = BAD_FUNC_ARG;

    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->dQ, &domain[0]);
    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->q, &domain[1*paramSz]);
    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->dP, &domain[2*paramSz]);
    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->p, &domain[3*paramSz]);
    if (ret == MP_OKAY)
        ret = mp_to_unsigned_bin(&key->u, &domain[4*paramSz]);

    if (ret == MP_OKAY && wolfSSL_CryptHwMutexLock() == 0)
    {
        for (i = 0; i < inLen; i += keySz)
        {
            switch (keySz) {
            case RSA_1024_KEYSIZE:
                ret = (int) HW_SCE_RSA_1024PrivateCrtKeyDecrypt(
                                                       (const uint32_t*) &in[i],
                                                       (const uint32_t*) domain,
                                                       (uint32_t*) &out[i]);
                break;
            case RSA_2048_KEYSIZE:
                ret = (int) HW_SCE_RSA_2048PrivateCrtKeyDecrypt(
                                                       (const uint32_t*) &in[i],
                                                       (const uint32_t*) domain,
                                                       (uint32_t*) &out[i]);
                break;
            default:
                ret = BAD_FUNC_ARG; /* Unsupported RSA Key Size */
                break;
            }
            if (ret != FSP_SUCCESS) /* Exit loop on error */
                break;
        }
        wolfSSL_CryptHwMutexUnLock();

        if (ret == FSP_SUCCESS) {
            ret = (int) i;
            *outLen = i;
        } else {
            /* Error from Hardware */
            if (ret != BAD_FUNC_ARG)
                ret = WC_HW_E;
        }
    }
    return ret;
}
#endif /* HAVE_ECC && !NO_RSA */
#endif /* !No_RSA */
