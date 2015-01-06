/* settings_comp.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef CTAO_CRYPT_SETTINGS_C_H
#define CTAO_CRYPT_SETTINGS_C_H

/* Macro redefinitions for compatibility */
#ifdef WOLFSSL_SHA512
    #define CYASSL_SHA512 WOLFSSL_SHA512
#endif
#ifdef WOLFSSL_SHA384
    #define CYASSL_SHA384 WOLFSSL_SHA384
#endif

/* These are compatibility from fips protected headers
 * When using non-fips mode and including old headers this allows for
 * using old function calls
 */
#ifndef HAVE_FIPS
    /* for random.h compatibility */
    #include <wolfssl/wolfcrypt/random.h>
    #define InitRng           wc_InitRng
    #define RNG_GenerateBlock wc_RNG_GenerateBlock
    #define RNG_GenerateByte  wc_RNG_GenerateByte

#if defined(HAVE_HASHDRBG) || defined(NO_RC4)
    #define FreeRng        wc_FreeRng
    #define RNG_HealthTest wc_RNG_HealthTest
#endif /* HAVE_HASHDRBG || NO_RC4 */

    #ifndef NO_AES
        #include <wolfssl/wolfcrypt/aes.h>
        #define AesSetKey            wc_AesSetKey
        #define AesSetIV             wc_AesSetIV
        #define AesCbcEncrypt        wc_AesCbcEncrypt
        #define AesCbcDecrypt        wc_AesCbcDecrypt
        #define AesCbcDecryptWithKey wc_AesCbcDecryptWithKey

        /* AES-CTR */
        #ifdef WOLFSSL_AES_COUNTER
            #define AesCtrEncrypt wc_AesCtrEncrypt
        #endif
        /* AES-DIRECT */
        #if defined(WOLFSSL_AES_DIRECT)
            #define AesEncryptDirect wc_AesEncryptDirect
            #define AesDecryptDirect wc_AesDecryptDirect
            #define AesSetKeyDirect  wc_AesSetKeyDirect
        #endif
        #ifdef HAVE_AESGCM
            #define AesGcmSetKey  wc_AesGcmSetKey
            #define AesGcmEncrypt wc_AesGcmEncrypt
            #define AesGcmDecrypt wc_AesGcmDecrypt
            #define GmacSetKey    wc_GmacSetKey
            #define GmacUpdate    wc_GmacUpdate
        #endif /* HAVE_AESGCM */
        #ifdef HAVE_AESCCM
            #define AesCcmSetKey  wc_AesCcmSetKey
            #define AesCcmEncrypt wc_AesCcmEncrypt
            #define AesCcmDecrypt wc_AesCcmDecrypt
        #endif /* HAVE_AESCCM */

        #ifdef HAVE_CAVIUM
            #define AesInitCavium wc_AesInitCavium
            #define AesFreeCavium wc_AesFreeCavium
        #endif
    #endif /* NO_AES */

#ifndef NO_RSA
        #include <wolfssl/wolfcrypt/rsa.h>
    #define InitRsaKey              wc_InitRsaKey
    #define FreeRsaKey              wc_FreeRsaKey
    #define RsaPublicEncrypt        wc_RsaPublicEncrypt
    #define RsaPrivateDecryptInline wc_RsaPrivateDecryptInline
    #define RsaPrivateDecrypt     wc_RsaPrivateDecrypt
    #define RsaSSL_Sign           wc_RsaSSL_Sign
    #define RsaSSL_VerifyInline   wc_RsaSSL_VerifyInline
    #define RsaSSL_Verify         wc_RsaSSL_Verify
    #define RsaEncryptSize        wc_RsaEncryptSize
    #define RsaPrivateKeyDecode   wc_RsaPrivateKeyDecode
    #define RsaPublicKeyDecode    wc_RsaPublicKeyDecode
    #define RsaPublicKeyDecodeRaw wc_RsaPublicKeyDecodeRaw
    #define RsaFlattenPublicKey   wc_RsaFlattenPublicKey

	#ifdef WOLFSSL_KEY_GEN
	    #define MakeRsaKey  wc_MakeRsaKey
	    #define RsaKeyToDer wc_RsaKeyToDer
	#endif

	#ifdef HAVE_CAVIUM
	    #define RsaInitCavium wc_RsaInitCavium
	    #define RsaFreeCavium wc_RsaFreeCavium
	#endif
#endif /* NO_RSA */

#ifndef NO_HMAC
        #include <wolfssl/wolfcrypt/hmac.h>
    #define HmacSetKey wc_HmacSetKey
    #define HmacUpdate wc_HmacUpdate
    #define HmacFinal  wc_HmacFinal
    #ifdef HAVE_CAVIUM
        #define HmacInitCavium wc_HmacInitCavium
        #define HmacFreeCavium wc_HmacFreeCavium
    #endif
    #define wolfSSL_GetHmacMaxSize wc_wolfSSL_GetHmacMaxSize
    #ifdef HAVE_HKDF
        #define HKDF wc_HKDF
    #endif /* HAVE_HKDF */
    #endif /* NO_HMAC */

#ifndef NO_DES3
        #include <wolfssl/wolfcrypt/des3.h>
    #define Des_SetKey     wc_Des_SetKey
    #define Des_SetIV      wc_Des_SetIV
    #define Des_CbcEncrypt wc_Des_CbcEncrypt
    #define Des_CbcDecrypt wc_Des_CbcDecrypt
    #define Des_EcbEncrypt wc_Des_EcbEncrypt
    #define Des_CbcDecryptWithKey  wc_Des_CbcDecryptWithKey
    #define Des3_SetKey            wc_Des3_SetKey
    #define Des3_SetIV             wc_Des3_SetIV
    #define Des3_CbcEncrypt        wc_Des3_CbcEncrypt
    #define Des3_CbcDecrypt        wc_Des3_CbcDecrypt
    #define Des3_CbcDecryptWithKey wc_Des3_CbcDecryptWithKey
    #ifdef HAVE_CAVIUM
        #define Des3_InitCavium wc_Des3_InitCavium
        #define Des3_FreeCavium wc_Des3_FreeCavium
    #endif
#endif /* NO_DES3 */

#ifndef NO_SHA
        #include <wolfssl/wolfcrypt/sha.h>
    #define InitSha   wc_InitSha
    #define ShaUpdate wc_ShaUpdate
    #define ShaFinal  wc_ShaFinal
    #define ShaHash   wc_ShaHash
#endif /* NO_SHA */

#ifndef NO_SHA256
        #include <wolfssl/wolfcrypt/sha256.h>
    #define InitSha256   wc_InitSha256
    #define Sha256Update wc_Sha256Update
    #define Sha256Final  wc_Sha256Final
    #define Sha256Hash   wc_Sha256Hash
#endif /* NO_SHA256 */

#ifdef WOLFSSL_SHA512
        #include <wolfssl/wolfcrypt/sha512.h>
    #define InitSha512 wc_InitSha512
    #define Sha512Update wc_Sha512Update
    #define Sha512Final wc_Sha512Final
    #define Sha512Hash wc_Sha512Hash

	#if defined(WOLFSSL_SHA384) || defined(HAVE_AESGCM)
	    #define InitSha384 wc_InitSha384
	    #define Sha384Update wc_Sha384Update
	    #define Sha384Final wc_Sha384Final
	    #define Sha384Hash wc_Sha384Hash
	#endif /* WOLFSSL_SHA384 */
#endif /* WOLFSSL_SHA512 */
#endif /* HAVE_FIPS */

#endif /* CTAO_CRYPT_SETTINGS_C_H */

