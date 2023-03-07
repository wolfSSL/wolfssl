/* clu_sign.c
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
#include <wolfclu/wolfclu/sign-verify/clu_sign.h>

#ifndef WOLFCLU_NO_FILESYSTEM

int wolfCLU_sign_data(char* in, char* out, char* privKey, int keyType)
{
    int ret;
    int fSz;
    XFILE f;
    byte *data = NULL;

    f = XFOPEN(in, "rb");
    if (f == NULL) {
        wolfCLU_LogError("unable to open file %s", in);
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
        ret = wolfCLU_sign_data_rsa(data, out, fSz, privKey);
        break;

    case ECC_SIG_VER:
        ret = wolfCLU_sign_data_ecc(data, out, fSz, privKey);
        break;

    case ED25519_SIG_VER:
        ret = wolfCLU_sign_data_ed25519(data, out, fSz, privKey);
        break;

    default:
        wolfCLU_LogError("No valid sign algorithm selected.");
        ret = WOLFCLU_FATAL_ERROR;
    }

    XFREE(data, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wolfCLU_sign_data_rsa(byte* data, char* out, word32 dataSz, char* privKey)
{
#ifndef NO_RSA
    int ret;
    int privFileSz;
    word32 index = 0;

    XFILE privKeyFile;
    byte* keyBuf = NULL;

    RsaKey key;
    WC_RNG rng;

    byte* outBuf = NULL;
    int   outBufSz = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    /* init the RsaKey */
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize RsaKey\nRET: %d", ret);
        return ret;
    }

    /* read in and store private key */
    privKeyFile = XFOPEN(privKey, "rb");
    if (privKeyFile == NULL) {
        wolfCLU_LogError("unable to open file %s", privKey);
        return BAD_FUNC_ARG;
    }

    XFSEEK(privKeyFile, 0, SEEK_END);
    privFileSz = (int)XFTELL(privKeyFile);
    keyBuf = (byte*)XMALLOC(privFileSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyBuf == NULL) {
        XFCLOSE(privKeyFile);
        return MEMORY_E;
    }
    if (XFSEEK(privKeyFile, 0, SEEK_SET) != 0 || (int)XFREAD(keyBuf, 1, privFileSz, privKeyFile) != privFileSz) {
        XFCLOSE(privKeyFile);
        return WOLFCLU_FATAL_ERROR;
    }
    XFCLOSE(privKeyFile);

    /* retrieving private key and storing in the RsaKey */
    ret = wc_RsaPrivateKeyDecode(keyBuf, &index, &key, privFileSz);
    XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != 0 ) {
        wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
        return ret;
    }

    /* setting up output buffer based on key size */
    outBufSz = wc_RsaEncryptSize(&key);
    outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf == NULL) {
        return MEMORY_E;
    }
    XMEMSET(outBuf, 0, outBufSz);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

#ifdef WC_RSA_BLINDING
    ret = wc_RsaSetRNG(&key, &rng);
    if (ret < 0) {
        wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return ret;
    }
#endif

    ret = wc_RsaSSL_Sign(data, dataSz, outBuf, (word32)outBufSz, &key,
            &rng);
    if (ret < 0) {
        wolfCLU_LogError("Failed to sign data with RSA private key.\nRET: %d", ret);
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        wc_FreeRsaKey(&key);
        return ret;
    }
    else {
        XFILE s;
        s = XFOPEN(out, "wb");
        XFWRITE(outBuf, 1, outBufSz, s);
        XFCLOSE(s);
    }

    XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);
    wc_FreeRsaKey(&key);
    (void)index;
    return WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_sign_data_ecc(byte* data, char* out, word32 fSz, char* privKey)
{
#ifdef HAVE_ECC
    int ret;
    int privFileSz;
    word32 index = 0;
    word32 outLen;

    byte* keyBuf = NULL;
    XFILE privKeyFile;

    ecc_key key;
    WC_RNG rng;

    byte* outBuf = NULL;
    int   outBufSz = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    /* init the ecc key */
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ecc key\nRET: %d", ret);
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        return ret;
    }

    /* read in and store private key */
    privKeyFile = XFOPEN(privKey, "rb");
    if (privKeyFile == NULL) {
        wolfCLU_LogError("unable to open file %s", privKey);
        wc_FreeRng(&rng);
        return BAD_FUNC_ARG;
    }

    XFSEEK(privKeyFile, 0, SEEK_END);
    privFileSz = (int)XFTELL(privKeyFile);
    keyBuf = (byte*)XMALLOC(privFileSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyBuf == NULL) {
        wc_FreeRng(&rng);
        return MEMORY_E;
    }
    if (XFSEEK(privKeyFile, 0, SEEK_SET) != 0 || (int)XFREAD(keyBuf, 1, privFileSz, privKeyFile) != privFileSz) {
        XFCLOSE(privKeyFile);
        return WOLFCLU_FATAL_ERROR;
    }
    XFCLOSE(privKeyFile);

    /* retrieving private key and storing in the Ecc Key */
    ret = wc_EccPrivateKeyDecode(keyBuf, &index, &key, privFileSz);
    XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != 0 ) {
        wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
        wc_FreeRng(&rng);
        return ret;
    }

    /* setting up output buffer based on key size */
    outBufSz = wc_ecc_sig_size(&key);
    outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf == NULL) {
        wc_FreeRng(&rng);
        return MEMORY_E;
    }
    XMEMSET(outBuf, 0, outBufSz);
    outLen = (word32)outBufSz;

    /* signing input with ecc priv key to produce signature */
    ret = wc_ecc_sign_hash(data, fSz, outBuf, &outLen, &rng, &key);
    if (ret < 0) {
        wolfCLU_LogError("Failed to sign data with Ecc private key.\nRET: %d", ret);
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return ret;
    }
    else {
        XFILE s;
        s = XFOPEN(out, "wb");
        XFWRITE(outBuf, 1, outLen, s);
        XFCLOSE(s);
    }
    XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);

    (void)index;
    return WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfCLU_sign_data_ed25519 (byte* data, char* out, word32 fSz, char* privKey)
{
#ifdef HAVE_ED25519
    int ret;
    int privFileSz;
    word32 index = 0;
    word32 outLen;

    XFILE privKeyFile;
    byte* keyBuf = NULL;
    byte* outBuf = NULL;
    int   outBufSz = 0;

    ed25519_key key;
    WC_RNG rng;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));

    /* init the ED25519 key */
    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ed25519 key\nRET: %d", ret);
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        return ret;
    }

    /* read in and store private key */
    privKeyFile = XFOPEN(privKey, "rb");
    if (privKeyFile == NULL) {
        wolfCLU_LogError("unable to open file %s", privKey);
        wc_FreeRng(&rng);
        return BAD_FUNC_ARG;
    }

    XFSEEK(privKeyFile, 0, SEEK_END);
    privFileSz = (int)XFTELL(privKeyFile);
    keyBuf = (byte*)XMALLOC(privFileSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyBuf == NULL) {
        XFCLOSE(privKeyFile);
        wc_FreeRng(&rng);
        return MEMORY_E;
    }
    if (XFSEEK(privKeyFile, 0, SEEK_SET) != 0 || (int)XFREAD(keyBuf, 1, privFileSz, privKeyFile) != privFileSz) {
        XFCLOSE(privKeyFile);
        return WOLFCLU_FATAL_ERROR;
    }
    XFCLOSE(privKeyFile);

    /* retrieving private key and storing in the ED25519 Key */
    ret = wc_ed25519_import_private_key(keyBuf,
                                    ED25519_KEY_SIZE,
                                    keyBuf + ED25519_KEY_SIZE,
                                    ED25519_KEY_SIZE, &key);
    XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != 0 ) {
        wolfCLU_LogError("Failed to import private key.\nRET: %d", ret);
        wc_FreeRng(&rng);
        return ret;
    }

    /* setting up output buffer based on key size */
    outBufSz = ED25519_SIG_SIZE;
    outBuf = (byte*)XMALLOC(outBufSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf == NULL) {
        wc_FreeRng(&rng);
        return MEMORY_E;
    }
    XMEMSET(outBuf, 0, outBufSz);
    outLen = outBufSz;

    /* signing input with ED25519 priv key to produce signature */
    ret = wc_ed25519_sign_msg(data, fSz, outBuf, &outLen, &key);
    if (ret < 0) {
        wolfCLU_LogError("Failed to sign data with ED25519 private key.\nRET: %d", ret);
        XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        wc_FreeRng(&rng);
        return ret;
    }
    else {
        XFILE s;
        s = XFOPEN(out, "wb");
        XFWRITE(outBuf, 1, outBufSz, s);
        XFCLOSE(s);
    }
    XFREE(outBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    (void)index;
    wc_FreeRng(&rng);
    return WOLFCLU_SUCCESS;
#else
    return NOT_COMPILED_IN;
#endif
}
#endif /* !WOLFCLU_NO_FILESYSTEM */
