/* crypto.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/* Implements Microchip CRYPTO API layer */



#include "crypto.h"

#include <cyassl/ctaocrypt/md5.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/sha256.h>
#include <cyassl/ctaocrypt/sha512.h>
#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/compress.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/ecc.h>


/* Initialize MD5 */
int CRYPT_MD5_Initialize(CRYPT_MD5_CTX* md5)
{
    typedef char md5_test[sizeof(CRYPT_MD5_CTX) >= sizeof(Md5) ? 1 : -1];
    (void)sizeof(md5_test);

    InitMd5((Md5*)md5);

    return 0;
}


/* Add data to MD5 */
int CRYPT_MD5_DataAdd(CRYPT_MD5_CTX* md5, const unsigned char* input,
                      unsigned int sz)
{
    Md5Update((Md5*)md5, input, sz);

    return 0;
}


/* Get MD5 Final into digest */
int CRYPT_MD5_Finalize(CRYPT_MD5_CTX* md5, unsigned char* digest)
{
    Md5Final((Md5*)md5, digest);

    return 0;
}


/* Initialize SHA */
int CRYPT_SHA_Initialize(CRYPT_SHA_CTX* sha)
{
    typedef char sha_test[sizeof(CRYPT_SHA_CTX) >= sizeof(Sha) ? 1 : -1];
    (void)sizeof(sha_test);

    InitSha((Sha*)sha);

    return 0;
}


/* Add data to SHA */
int CRYPT_SHA_DataAdd(CRYPT_SHA_CTX* sha, const unsigned char* input,
                       unsigned int sz)
{
    ShaUpdate((Sha*)sha, input, sz);

    return 0;
}


/* Get SHA Final into digest */
int CRYPT_SHA_Finalize(CRYPT_SHA_CTX* sha, unsigned char* digest)
{
    ShaFinal((Sha*)sha, digest);

    return 0;
}


/* Initialize SHA-256 */
int CRYPT_SHA256_Initialize(CRYPT_SHA256_CTX* sha256)
{
    typedef char sha_test[sizeof(CRYPT_SHA256_CTX) >= sizeof(Sha256) ? 1 : -1];
    (void)sizeof(sha_test);

    InitSha256((Sha256*)sha256);

    return 0;
}


/* Add data to SHA-256 */
int CRYPT_SHA256_DataAdd(CRYPT_SHA256_CTX* sha256, const unsigned char* input,
                         unsigned int sz)
{
    Sha256Update((Sha256*)sha256, input, sz);

    return 0;
}


/* Get SHA-256 Final into digest */
int CRYPT_SHA256_Finalize(CRYPT_SHA256_CTX* sha256, unsigned char* digest)
{
    Sha256Final((Sha256*)sha256, digest);

    return 0;
}


/* Initialize SHA-384 */
int CRYPT_SHA384_Initialize(CRYPT_SHA384_CTX* sha384)
{
    typedef char sha_test[sizeof(CRYPT_SHA384_CTX) >= sizeof(Sha384) ? 1 : -1];
    (void)sizeof(sha_test);

    InitSha384((Sha384*)sha384);

    return 0;
}


/* Add data to SHA-384 */
int CRYPT_SHA384_DataAdd(CRYPT_SHA384_CTX* sha384, const unsigned char* input,
                         unsigned int sz)
{
    Sha384Update((Sha384*)sha384, input, sz);

    return 0;
}


/* Get SHA-384 Final into digest */
int CRYPT_SHA384_Finalize(CRYPT_SHA384_CTX* sha384, unsigned char* digest)
{
    Sha384Final((Sha384*)sha384, digest);

    return 0;
}


/* Initialize SHA-512 */
int CRYPT_SHA512_Initialize(CRYPT_SHA512_CTX* sha512)
{
    typedef char sha_test[sizeof(CRYPT_SHA512_CTX) >= sizeof(Sha512) ? 1 : -1];
    (void)sizeof(sha_test);

    InitSha512((Sha512*)sha512);

    return 0;
}


/* Add data to SHA-512 */
int CRYPT_SHA512_DataAdd(CRYPT_SHA512_CTX* sha512, const unsigned char* input,
                         unsigned int sz)
{
    Sha512Update((Sha512*)sha512, input, sz);

    return 0;
}


/* Get SHA-512 Final into digest */
int CRYPT_SHA512_Finalize(CRYPT_SHA512_CTX* sha512, unsigned char* digest)
{
    Sha512Final((Sha512*)sha512, digest);

    return 0;
}


/* Set HMAC key with type */
int CRYPT_HMAC_SetKey(CRYPT_HMAC_CTX* hmac, int type, const unsigned char* key,
                      unsigned int sz)
{
    typedef char hmac_test[sizeof(CRYPT_HMAC_CTX) >= sizeof(Hmac) ? 1 : -1];
    (void)sizeof(hmac_test);

    if (type != CRYPT_HMAC_SHA && type != CRYPT_HMAC_SHA256 &&
        type != CRYPT_HMAC_SHA384 && type != CRYPT_HMAC_SHA512) {
        return -1;  /* bad hmac type */
    }

    HmacSetKey((Hmac*)hmac, type, key, sz);

    return 0;
}


int CRYPT_HMAC_DataAdd(CRYPT_HMAC_CTX* hmac, const unsigned char* input,
                       unsigned int sz)
{
    HmacUpdate((Hmac*)hmac, input, sz);

    return 0;
}


/* Get HMAC Final into digest */
int CRYPT_HMAC_Finalize(CRYPT_HMAC_CTX* hmac, unsigned char* digest)
{
    HmacFinal((Hmac*)hmac, digest);

    return 0;
}


/* Huffman Compression, set flag to do static, otherwise dynamic */
/* return compressed size, otherwise < 0 for error */
int CRYPT_HUFFMAN_Compress(unsigned char* out, unsigned int outSz,
                           const unsigned char* in, unsigned int inSz,
                           unsigned int flags)
{
    return Compress(out, outSz, in, inSz, flags);
}


/* Huffman DeCompression, self determines type */
/* return decompressed size, otherwise < 0 for error */
int CRYPT_HUFFMAN_DeCompress(unsigned char* out, unsigned int outSz,
                             const unsigned char* in, unsigned int inSz)
{
    return DeCompress(out, outSz, in, inSz);
}


/* RNG Initialize, < 0 on error */
int CRYPT_RNG_Initialize(CRYPT_RNG_CTX* rng)
{
    typedef char rng_test[sizeof(CRYPT_RNG_CTX) >= sizeof(RNG) ? 1 : -1];
    (void)sizeof(rng_test);

    return InitRng((RNG*)rng);
}


/* RNG Get single bytes, < 0 on error */
int CRYPT_RNG_Get(CRYPT_RNG_CTX* rng, unsigned char* b)
{
    *b = RNG_GenerateByte((RNG*)rng);

    return 0;
}


/* RNG Block Generation of sz bytes, < 0 on error */
int CRYPT_RNG_BlockGenerate(CRYPT_RNG_CTX* rng, unsigned char* b,
                            unsigned int sz)
{
    RNG_GenerateBlock((RNG*)rng, b, sz);

    return 0;
}


/* Triple DES Key Set, may have iv, will have direction */
int CRYPT_TDES_KeySet(CRYPT_TDES_CTX* tdes, const unsigned char* key,
                      const unsigned char* iv, int dir)
{
    typedef char tdes_test[sizeof(CRYPT_TDES_CTX) >= sizeof(Des3) ? 1 : -1];
    (void)sizeof(tdes_test);

    Des3_SetKey((Des3*)tdes, key, iv, dir);

    return 0;
}


/* Triple DES Iv Set, sometimes added later */
int CRYPT_TDES_IvSet(CRYPT_TDES_CTX* tdes, const unsigned char* iv)
{
    Des3_SetIV((Des3*)tdes, iv);

    return 0;
}


/* Triple DES CBC Encrypt */
int CRYPT_TDES_CBC_Encrypt(CRYPT_TDES_CTX* tdes, unsigned char* out,
                           const unsigned char* in, unsigned int inSz)
{
    Des3_CbcEncrypt((Des3*)tdes, out, in, inSz);

    return 0;
}


/* Triple DES CBC Decrypt */
int CRYPT_TDES_CBC_Decrypt(CRYPT_TDES_CTX* tdes, unsigned char* out,
                           const unsigned char* in, unsigned int inSz)
{
    Des3_CbcDecrypt((Des3*)tdes, out, in, inSz);

    return 0;
}


/* AES Key Set, may have iv, will have direction */
int CRYPT_AES_KeySet(CRYPT_AES_CTX* aes, const unsigned char* key,
                     unsigned int keyLen, const unsigned char* iv, int dir)
{
    typedef char aes_test[sizeof(CRYPT_AES_CTX) >= sizeof(Aes) ? 1 : -1];
    (void)sizeof(aes_test);

    return AesSetKey((Aes*)aes, key, keyLen, iv, dir);
}


/* AES Iv Set, sometimes added later */
int CRYPT_AES_IvSet(CRYPT_AES_CTX* aes, const unsigned char* iv)
{
    AesSetIV((Aes*)aes, iv);

    return 0;
}


/* AES CBC Encrypt */
int CRYPT_AES_CBC_Encrypt(CRYPT_AES_CTX* aes, unsigned char* out,
                          const unsigned char* in, unsigned int inSz)
{
    AesCbcEncrypt((Aes*)aes, out, in, inSz);

    return 0;
}


/* AES CBC Decrypt */
int CRYPT_AES_CBC_Decrypt(CRYPT_AES_CTX* aes, unsigned char* out,
                          const unsigned char* in, unsigned int inSz)
{
    AesCbcDecrypt((Aes*)aes, out, in, inSz);

    return 0;
}


/* AES CTR Encrypt (used for decrypt too, with ENCRYPT key setup) */
int CRYPT_AES_CTR_Encrypt(CRYPT_AES_CTX* aes, unsigned char* out,
                          const unsigned char* in, unsigned int inSz)
{
    AesCtrEncrypt((Aes*)aes, out, in, inSz);

    return 0;
}


/* AES Direct mode encrypt, one block at a time */
int CRYPT_AES_DIRECT_Encrypt(CRYPT_AES_CTX* aes, unsigned char* out,
                             const unsigned char* in)
{
    AesEncryptDirect((Aes*)aes, out, in);

    return 0;
}


/* AES Direct mode decrypt, one block at a time */
int CRYPT_AES_DIRECT_Decrypt(CRYPT_AES_CTX* aes, unsigned char* out,
                             const unsigned char* in)
{
    AesDecryptDirect((Aes*)aes, out, in);

    return 0;
}


/* RSA Initialize */
int CRYPT_RSA_Initialize(CRYPT_RSA_CTX* rsa)
{
    rsa->holder = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL, DYNAMIC_TYPE_RSA);
    if (rsa->holder == NULL)
        return -1;

    InitRsaKey((RsaKey*)rsa->holder, NULL);

    return 0;
}


/* RSA Free resources */
int CRYPT_RSA_Free(CRYPT_RSA_CTX* rsa)
{
    FreeRsaKey((RsaKey*)rsa->holder);
    XFREE(rsa->holder, NULL, DYNAMIC_TYPE_RSA);
    rsa->holder = NULL;

    return 0;
}


/* RSA Public key decode ASN.1 */
int CRYPT_RSA_PublicKeyDecode(CRYPT_RSA_CTX* rsa, const unsigned char* in,
                              unsigned int inSz)
{
    unsigned int idx = 0;
    (void)idx;

    return RsaPublicKeyDecode(in, &idx, (RsaKey*)rsa->holder, inSz);
}


/* RSA Private key decode ASN.1 */
int CRYPT_RSA_PrivateKeyDecode(CRYPT_RSA_CTX* rsa, const unsigned char* in,
                               unsigned int inSz)
{
    unsigned int idx = 0;
    (void)idx;

    return RsaPrivateKeyDecode(in, &idx, (RsaKey*)rsa->holder, inSz);
}


/* RSA Public Encrypt */
int CRYPT_RSA_PublicEncrypt(CRYPT_RSA_CTX* rsa, unsigned char* out,
                            unsigned int outSz, const unsigned char* in,
                            unsigned int inSz, CRYPT_RNG_CTX* rng)
{
    return RsaPublicEncrypt(in, inSz, out, outSz, (RsaKey*)rsa->holder,
                            (RNG*)rng);
}


/* RSA Private Decrypt */
int CRYPT_RSA_PrivateDecrypt(CRYPT_RSA_CTX* rsa, unsigned char* out,
                             unsigned int outSz, const unsigned char* in,
                             unsigned int inSz)
{
    return RsaPrivateDecrypt(in, inSz, out, outSz, (RsaKey*)rsa->holder);
}


/* RSA Get Encrypt size helper */
int CRYPT_RSA_EncryptSizeGet(CRYPT_RSA_CTX* rsa) 
{
    return RsaEncryptSize((RsaKey*)rsa->holder);
}    


/* ECC init */
int CRYPT_ECC_Initialize(CRYPT_ECC_CTX* ecc)
{
    ecc->holder = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
    if (ecc->holder == NULL)
        return -1;

    ecc_init((ecc_key*)ecc->holder);

    return 0;
}


/* ECC free resources */
int CRYPT_ECC_Free(CRYPT_ECC_CTX* ecc)
{
    ecc_free((ecc_key*)ecc->holder);
    XFREE(ecc->holder, NULL, DYNAMIC_TYPE_ECC);
    ecc->holder = NULL;

    return 0;
}


/* ECC Public x963 Export */
int CRYPT_ECC_PublicExport(CRYPT_ECC_CTX* ecc, unsigned char* out,
                           unsigned int outSz, unsigned int* usedSz)
{
    int          ret;
    unsigned int inOut = outSz;

    ret = ecc_export_x963((ecc_key*)ecc->holder, out, &inOut);
    *usedSz = inOut;

    return ret;
}


/* ECC Public x963 Import */
int CRYPT_ECC_PublicImport(CRYPT_ECC_CTX* ecc, const unsigned char* in,
                           unsigned int inSz)
{
    return ecc_import_x963(in, inSz, (ecc_key*)ecc->holder);
}


/* ECC Private x963 Import */
int CRYPT_ECC_PrivateImport(CRYPT_ECC_CTX* ecc, const unsigned char* priv,
         unsigned int privSz, const unsigned char* pub, unsigned int pubSz)
{
    return ecc_import_private_key(priv, privSz, pub, pubSz,
                                 (ecc_key*)ecc->holder);
}


/* ECC DHE Make key */
int CRYPT_ECC_DHE_KeyMake(CRYPT_ECC_CTX* ecc, CRYPT_RNG_CTX* rng, int keySz)
{
    return ecc_make_key((RNG*)rng, keySz, (ecc_key*)ecc->holder);
}


/* ECC DHE Make shared secret with our private and peer public */
int CRYPT_ECC_DHE_SharedSecretMake(CRYPT_ECC_CTX* priv, CRYPT_ECC_CTX* pub,
                  unsigned char* out, unsigned int outSz, unsigned int* usedSz)
{
    int ret;
    unsigned int inOut = outSz;

    ret = ecc_shared_secret((ecc_key*)priv->holder, (ecc_key*)pub->holder,
                            out, &inOut);
    *usedSz = inOut;

    return ret;
}


/* ECC DSA Hash Sign */
int CRYPT_ECC_DSA_HashSign(CRYPT_ECC_CTX* ecc, CRYPT_RNG_CTX* rng,
                           unsigned char* sig, unsigned int sigSz,
                           unsigned int* usedSz, const unsigned char* in,
                           unsigned int inSz)
{
    int ret;
    unsigned int inOut = sigSz;

    ret = ecc_sign_hash(in, inSz, sig, &inOut, (RNG*)rng,
                       (ecc_key*)ecc->holder);
    *usedSz = inOut;

    return ret;
}


/* ECC DSA Hash Verify */
int CRYPT_ECC_DSA_HashVerify(CRYPT_ECC_CTX* ecc, const unsigned char* sig,
                             unsigned int sigSz, unsigned char* hash,
                             unsigned int hashSz, int* status)
{
    return ecc_verify_hash(sig, sigSz, hash, hashSz, status,
                          (ecc_key*)ecc->holder);
}


/* ECC get key size helper */
int CRYPT_ECC_KeySizeGet(CRYPT_ECC_CTX* ecc)
{
    return ecc_size((ecc_key*)ecc->holder);
}


/* ECC get signature size helper */
int CRYPT_ECC_SignatureSizeGet(CRYPT_ECC_CTX* ecc)
{
    return ecc_sig_size((ecc_key*)ecc->holder);
}



