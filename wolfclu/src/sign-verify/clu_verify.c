/* clu_verify.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#include <wolfclu/wolfclu/clu_header_main.h>
#include <wolfclu/wolfclu/clu_log.h>
#include <wolfclu/wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/wolfclu/sign-verify/clu_sign.h> /* for RSA_SIG_VER, ECC_SIG_VER,
                                             ED25519_SIG_VER */
#ifndef WOLFCLU_NO_FILESYSTEM

static byte* wolfCLU_generate_public_key_rsa(char* privKey, byte* outBuf,
                                      int* outBufSz)
{
#ifndef NO_RSA
    int ret;
    int privFileSz;
    word32 index = 0;
    XFILE privKeyFile;
    RsaKey key;
    WC_RNG rng;
    byte* keyBuf;

    if (outBufSz == NULL) {
        wolfCLU_LogError("Unexpected null output size variable");
        return NULL;
    }

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize RsaKey.\nRet: %d", ret);
        *outBufSz = ret;
        return outBuf;
    }


    /* read in and store private key */

    privKeyFile = XFOPEN(privKey, "rb");
    if (privKeyFile == NULL) {
        wolfCLU_LogError("Unable to open file %s", privKey);
        wc_FreeRsaKey(&key);
        return NULL;
    }
    XFSEEK(privKeyFile, 0, SEEK_END);
    privFileSz = (int)XFTELL(privKeyFile);
    keyBuf = (byte*)XMALLOC(privFileSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyBuf != NULL) {
        if (XFSEEK(privKeyFile, 0, SEEK_SET) != 0 || (int)XFREAD(keyBuf, 1, privFileSz, privKeyFile) != privFileSz) {
            XFCLOSE(privKeyFile);
            return NULL;
        }
    }
    XFCLOSE(privKeyFile);

    /* retrieving private key and storing in the RsaKey */
    ret = wc_RsaPrivateKeyDecode(keyBuf, &index, &key, privFileSz);
    XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret < 0 ) {
        wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
        *outBufSz = ret;
        wc_FreeRsaKey(&key);
        return outBuf;
    }

    /* set output buffer to twice the private key size to ensure enough space */
    *outBufSz = 2*wc_RsaEncryptSize(&key);

    /* setting up output buffer based on privateKeyFile size */
    outBuf = (byte*)XMALLOC(*outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf == NULL) {
        wc_FreeRsaKey(&key);
        return NULL;
    }
    XMEMSET(outBuf, 0, *outBufSz);

    ret = wc_RsaKeyToPublicDer(&key, outBuf, *outBufSz);
    if (ret < 0) {
        wolfCLU_LogError("Failed to create RSA public key.\nBuf size: %d\nRET: %d",
               *outBufSz, ret);
        *outBufSz = ret;
        wc_FreeRsaKey(&key);
        return outBuf;
    }
    *outBufSz = ret;
    wc_FreeRsaKey(&key);
    return outBuf;
#else
    return NOT_COMPILED_IN;
#endif
}

static int wolfCLU_generate_public_key_ed25519(char* privKey, byte* outBuf)
{
#ifdef HAVE_ED25519
    int ret;
    word32 outLen = ED25519_KEY_SIZE;
    XFILE privKeyFile;
    ed25519_key key;
    byte privBuf[ED25519_SIG_SIZE];

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(privBuf, 0, ED25519_SIG_SIZE);

    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ED25519.\nRet: %d", ret);
        return ret;
    }

    /* read in and store private key */
    privKeyFile = XFOPEN(privKey, "rb");
    if ((int)XFREAD(privBuf, 1, ED25519_SIG_SIZE, privKeyFile) != ED25519_SIG_SIZE) {
        XFCLOSE(privKeyFile);
        return WOLFCLU_FATAL_ERROR;
    }
    XFCLOSE(privKeyFile);

    /* retrieving private key and storing in the ED25519 */
    ret = wc_ed25519_import_private_key(privBuf,
                                        ED25519_KEY_SIZE,
                                        privBuf + ED25519_KEY_SIZE,
                                        ED25519_KEY_SIZE,
                                        &key);
    if (ret < 0 ) {
        wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
        return ret;
    }

    /* retrive public key from private */
    ret = wc_ed25519_export_public(&key, outBuf, &outLen);
    if (ret != 0) {
        wolfCLU_LogError("Failed to create ED25519 public key.\nRET: %d", ret);
        return ret;
    }
    return WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}


int wolfCLU_verify_signature(char* sig, char* hashFile, char* out,
        char* keyPath, int keyType, int pubIn)
{
    int hSz = 0;
    int fSz;
    int ret;

    byte* hash = NULL;
    byte* data = NULL;
    XFILE h;
    XFILE f;

    if (sig == NULL) {
        return BAD_FUNC_ARG;
    }

    f = XFOPEN(sig, "rb");
    if (f == NULL) {
        wolfCLU_LogError("unable to open file %s", sig);
        return BAD_FUNC_ARG;
    }

    XFSEEK(f, 0, SEEK_END);
    fSz = (int)XFTELL(f);

    data = (byte*)XMALLOC(fSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (data == NULL) {
        XFCLOSE(f);
        return MEMORY_E;
    }
    if (XFSEEK(f, 0, SEEK_SET) != 0 || (int)XFREAD(data, 1, fSz, f) != fSz) {
        XFCLOSE(f);
        return WOLFCLU_FATAL_ERROR;
    }
    XFCLOSE(f);

    switch(keyType) {
        case RSA_SIG_VER:
            ret = wolfCLU_verify_signature_rsa(data, out, fSz, keyPath, pubIn);
            break;

        case ECC_SIG_VER:
            h = XFOPEN(hashFile,"rb");
            if (h == NULL) {
                wolfCLU_LogError("unable to open file %s", hashFile);
                ret = BAD_FUNC_ARG;
                break;
            }

            XFSEEK(h, 0, SEEK_END);
            hSz = (int)XFTELL(h);

            hash = (byte*)XMALLOC(hSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (hash == NULL) {
                ret = MEMORY_E;
                XFCLOSE(h);
                break;
            }

            if (XFSEEK(h, 0, SEEK_SET) != 0 || (int)XFREAD(hash, 1, hSz, h) != hSz) {
                XFCLOSE(h);
                return WOLFCLU_FATAL_ERROR;
            }
            XFCLOSE(h);
            ret = wolfCLU_verify_signature_ecc(data, fSz, hash, hSz, keyPath,
                                               pubIn);
            break;

        case ED25519_SIG_VER:
        #ifdef HAVE_ED25519
            h = XFOPEN(hashFile, "rb");
            if (h == NULL) {
                wolfCLU_LogError("unable to open file %s", hashFile);
                ret = BAD_FUNC_ARG;
                break;
            }

            XFSEEK(h, 0, SEEK_END);
            hSz = (int)XFTELL(h);

            hash = (byte*)XMALLOC(hSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (hash == NULL) {
                ret = MEMORY_E;
                XFCLOSE(h);
                break;
            }

            if (XFSEEK(h, 0, SEEK_SET) != 0 || (int)XFREAD(hash, 1, hSz, h) != hSz) {
                XFCLOSE(h);
                return WOLFCLU_FATAL_ERROR;
            }
            XFCLOSE(h);
            ret = wolfCLU_verify_signature_ed25519(data, fSz, hash, hSz,
                                                   keyPath, pubIn);
        #endif
            break;

        default:
            wolfCLU_LogError("No valid verify algorithm selected.");
            ret = -1;
    }

    if (data != NULL) {
        XFREE(data , HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (hash != NULL) {
        XFREE(hash, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

int wolfCLU_verify_signature_rsa(byte* sig, char* out, int sigSz, char* keyPath,
                                 int pubIn)
{
#ifndef NO_RSA
    int ret;
    int keyFileSz = 0;
    word32 index = 0;
    XFILE keyPathFile;
    RsaKey key;
    WC_RNG rng;
    byte* keyBuf = NULL;
    byte* outBuf = NULL;
    int   outBufSz = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize RsaKey.\nRet: %d", ret);
        return ret;
    }

    if (pubIn == 1) {
        /* read in and store rsa key */
        keyPathFile = XFOPEN(keyPath, "rb");
        if (keyPathFile == NULL) {
            wolfCLU_LogError("unable to open file %s", keyPath);
            wc_FreeRsaKey(&key);
            return BAD_FUNC_ARG;
        }

        XFSEEK(keyPathFile, 0, SEEK_END);
        keyFileSz = (int)XFTELL(keyPathFile);
        keyBuf = (byte*)XMALLOC(keyFileSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (keyBuf != NULL) {
            if (XFSEEK(keyPathFile, 0, SEEK_SET) != 0 ||
                   (int)XFREAD(keyBuf, 1, keyFileSz, keyPathFile) != keyFileSz) {
                XFCLOSE(keyPathFile);
                return WOLFCLU_FATAL_ERROR;
            }
        }
        XFCLOSE(keyPathFile);
    }
    else {
        keyBuf = wolfCLU_generate_public_key_rsa(keyPath, keyBuf, &keyFileSz);
        if (keyFileSz < 0) {
                wolfCLU_LogError("Failed to derive public key from private key.");
                wc_FreeRsaKey(&key);
                return ret;
        }
    }

    /* retrieving public key and storing in the RsaKey */
    ret = wc_RsaPublicKeyDecode(keyBuf, &index, &key, keyFileSz);
    if (keyBuf != NULL) {
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret < 0 ) {
        wolfCLU_LogError("Failed to decode public key.\nRET: %d", ret);
        wc_FreeRsaKey(&key);
        return ret;
    }

    /* setting up output buffer based on key size */
    outBufSz = wc_RsaEncryptSize(&key);
    outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf == NULL) {
        wolfCLU_LogError("Failed to malloc output buffer");
        wc_FreeRsaKey(&key);
        return MEMORY_E;
    }
    XMEMSET(outBuf, 0, outBufSz);

    ret = wc_RsaSSL_Verify(sig, sigSz, outBuf, (word32)outBufSz, &key);
    if (ret < 0) {
        wolfCLU_LogError("Failed to verify data with RSA public key.\nRET: %d", ret);
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRsaKey(&key);
        return ret;
    }
    else {
        XFILE s = XFOPEN(out, "wb");
        if (s == NULL) {
            wolfCLU_LogError("unable to open file %s", out);
            ret = BAD_FUNC_ARG;
        }
        else {
            XFWRITE(outBuf, 1, ret, s);
            XFCLOSE(s);
        }
    }

    if (outBuf != NULL) {
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wc_FreeRsaKey(&key);
    return (ret < 0)? ret : WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_verify_signature_ecc(byte* sig, int sigSz, byte* hash, int hashSz,
                                 char* keyPath, int pubIn) {

#ifdef HAVE_ECC
    int ret;
    int keyFileSz;
    int stat = 0;
    word32 index = 0;

    XFILE   keyPathFile;
    ecc_key key;
    WC_RNG  rng;
    byte*   keyBuf;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    ret = wc_ecc_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ecc key.\nRet: %d", ret);
        return ret;
    }

    /* read in and store ecc key */
    keyPathFile = XFOPEN(keyPath, "rb");
    if (keyPathFile == NULL) {
        wolfCLU_LogError("unable to open file %s", keyPath);
        return BAD_FUNC_ARG;
    }

    XFSEEK(keyPathFile, 0, SEEK_END);
    keyFileSz = (int)XFTELL(keyPathFile);
    keyBuf = (byte*)XMALLOC(keyFileSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyBuf != NULL) {
        if (XFSEEK(keyPathFile, 0, SEEK_SET) != 0 ||
                   (int)XFREAD(keyBuf, 1, keyFileSz, keyPathFile) != keyFileSz) {
                XFCLOSE(keyPathFile);
                return WOLFCLU_FATAL_ERROR;
            }
    }
    XFCLOSE(keyPathFile);

    if (pubIn == 1) {
        /* retrieving public key and storing in the ecc key */
        ret = wc_EccPublicKeyDecode(keyBuf, &index, &key, keyFileSz);
        if (ret < 0 ) {
            wolfCLU_LogError("Failed to decode public key.\nRET: %d", ret);
            XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }
    else {
        /* retrieving private key and storing in the Ecc Key */
        ret = wc_EccPrivateKeyDecode(keyBuf, &index, &key, keyFileSz);
        if (ret != 0 ) {
            wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
            XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }

    if (keyBuf)
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    ret = wc_ecc_verify_hash(sig, sigSz, hash, hashSz, &stat, &key);
    if (ret < 0) {
        wolfCLU_LogError("Failed to verify data with Ecc public key.\nRET: %d", ret);
        return ret;
    }
    else if (stat == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "Valid Signature.");
    }
    else {
        wolfCLU_LogError("Invalid Signature.");
    }

    return WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_verify_signature_ed25519(byte* sig, int sigSz,
                              byte* hash, int hashSz, char* keyPath, int pubIn) {

#ifdef HAVE_ED25519
    int ret;
    int stat = 0;

    XFILE keyPathFile;
    ed25519_key key;
    byte* keyBuf = (byte*)XMALLOC(ED25519_KEY_SIZE, HEAP_HINT,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (keyBuf == NULL) {
        wolfCLU_LogError("malloc failed");
        return MEMORY_E;
    }

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(keyBuf, 0, ED25519_KEY_SIZE);

    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ED25519 key.\nRet: %d", ret);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /* retrieving public key and storing in the ED25519 key */
    if (pubIn == 1) {
        /* read in and store ED25519 key */
        keyPathFile = XFOPEN(keyPath, "rb");
        if (keyPathFile == NULL) {
            XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return BAD_FUNC_ARG;
        }
        if ((int)XFREAD(keyBuf, 1, ED25519_KEY_SIZE, keyPathFile) != ED25519_KEY_SIZE) {
            XFCLOSE(keyPathFile);
            return WOLFCLU_FATAL_ERROR;
        }
        XFCLOSE(keyPathFile);

    }
    else {
        ret = wolfCLU_generate_public_key_ed25519(keyPath, keyBuf);
        if (ret != 0) {
            wolfCLU_LogError("Failed to derive public key from private key.");
            XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }

    ret = wc_ed25519_import_public(keyBuf, ED25519_KEY_SIZE, &key);
    if (ret != 0 ) {
        wolfCLU_LogError("Failed to decode public key.\nRET: %d", ret);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    ret = wc_ed25519_verify_msg(sig, sigSz, hash, hashSz, &stat, &key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to verify data with ED25519 public key.\nRET: %d", ret);
        return ret;
    }
    else if (stat == 1) {
        WOLFCLU_LOG(WOLFCLU_L0, "Valid Signature.");
    }
    else {
        wolfCLU_LogError("Invalid Signature.");
    }

    return WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}
#endif /* WOLFCLU_NO_FILESYSTEM */
