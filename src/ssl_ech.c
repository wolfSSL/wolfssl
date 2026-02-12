/* ssl_ech.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_SSL_ECH_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_ech.c does not need to be compiled separately from ssl.c
    #endif
#else

#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH)

/* create the hpke key and ech config to send to clients */
int wolfSSL_CTX_GenerateEchConfig(WOLFSSL_CTX* ctx, const char* publicName,
    word16 kemId, word16 kdfId, word16 aeadId)
{
    int ret = 0;
    word16 encLen = DHKEM_X25519_ENC_LEN;
    WOLFSSL_EchConfig* newConfig;
#ifdef WOLFSSL_SMALL_STACK
    Hpke* hpke = NULL;
    WC_RNG* rng;
#else
    Hpke hpke[1];
    WC_RNG rng[1];
#endif

    if (ctx == NULL || publicName == NULL)
        return BAD_FUNC_ARG;

    /* ECH spec limits public_name to 255 bytes (1-byte length prefix) */
    if (XSTRLEN(publicName) > 255)
        return BAD_FUNC_ARG;

    WC_ALLOC_VAR_EX(rng, WC_RNG, 1, ctx->heap, DYNAMIC_TYPE_RNG,
        return MEMORY_E);
    ret = wc_InitRng(rng);
    if (ret != 0) {
        WC_FREE_VAR_EX(rng, ctx->heap, DYNAMIC_TYPE_RNG);
        return ret;
    }

    newConfig = (WOLFSSL_EchConfig*)XMALLOC(sizeof(WOLFSSL_EchConfig),
        ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (newConfig == NULL)
        ret = MEMORY_E;
    else
        XMEMSET(newConfig, 0, sizeof(WOLFSSL_EchConfig));

    /* set random configId */
    /* TODO: if an equal configId is found should the old config be removed from
     * the LL? Prevents growth beyond 255+ items */
    if (ret == 0)
        ret = wc_RNG_GenerateByte(rng, &newConfig->configId);

    /* if 0 is selected for algorithms use default, may change with draft */
    if (kemId == 0)
        kemId = DHKEM_X25519_HKDF_SHA256;

    if (kdfId == 0)
        kdfId = HKDF_SHA256;

    if (aeadId == 0)
        aeadId = HPKE_AES_128_GCM;

    if (ret == 0) {
        /* set the kem id */
        newConfig->kemId = kemId;

        /* set the cipher suite, only 1 for now */
        newConfig->numCipherSuites = 1;
        newConfig->cipherSuites =
            (EchCipherSuite*)XMALLOC(sizeof(EchCipherSuite), ctx->heap,
            DYNAMIC_TYPE_TMP_BUFFER);

        if (newConfig->cipherSuites == NULL) {
            ret = MEMORY_E;
        }
        else {
            newConfig->cipherSuites[0].kdfId = kdfId;
            newConfig->cipherSuites[0].aeadId = aeadId;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        hpke = (Hpke*)XMALLOC(sizeof(Hpke), ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (hpke == NULL)
            ret = MEMORY_E;
    }
#endif

    if (ret == 0)
        ret = wc_HpkeInit(hpke, kemId, kdfId, aeadId, ctx->heap);

    /* generate the receiver private key */
    if (ret == 0)
        ret = wc_HpkeGenerateKeyPair(hpke, &newConfig->receiverPrivkey, rng);

    /* done with RNG */
    wc_FreeRng(rng);

    /* serialize the receiver key */
    if (ret == 0)
        ret = wc_HpkeSerializePublicKey(hpke, newConfig->receiverPrivkey,
            newConfig->receiverPubkey, &encLen);

    if (ret == 0) {
        newConfig->publicName = (char*)XMALLOC(XSTRLEN(publicName) + 1,
            ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (newConfig->publicName == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(newConfig->publicName, publicName,
                XSTRLEN(publicName) + 1);
        }
    }

    if (ret != 0) {
        if (newConfig) {
            XFREE(newConfig->cipherSuites, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(newConfig->publicName, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(newConfig, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    else {
        /* insert new configs at beginning of LL as preference should be given
         * to the most recently generated configs */
        if (ctx->echConfigs == NULL) {
            ctx->echConfigs = newConfig;
        }
        else {
            newConfig->next = ctx->echConfigs;
            ctx->echConfigs = newConfig;
        }
    }

    if (ret == 0)
        ret = WOLFSSL_SUCCESS;

    WC_FREE_VAR_EX(hpke, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(rng, ctx->heap, DYNAMIC_TYPE_RNG);

    return ret;
}

int wolfSSL_CTX_SetEchConfigsBase64(WOLFSSL_CTX* ctx, const char* echConfigs64,
    word32 echConfigs64Len)
{
    int ret = 0;
    word32 decodedLen = echConfigs64Len * 3 / 4 + 1;
    byte* decodedConfigs;

    if (ctx == NULL || echConfigs64 == NULL || echConfigs64Len == 0)
        return BAD_FUNC_ARG;

    decodedConfigs = (byte*)XMALLOC(decodedLen, ctx->heap,
        DYNAMIC_TYPE_TMP_BUFFER);

    if (decodedConfigs == NULL)
        return MEMORY_E;

    decodedConfigs[decodedLen - 1] = 0;

    /* decode the echConfigs */
    ret = Base64_Decode((const byte*)echConfigs64, echConfigs64Len,
        decodedConfigs, &decodedLen);

    if (ret != 0) {
        XFREE(decodedConfigs, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wolfSSL_CTX_SetEchConfigs(ctx, decodedConfigs, decodedLen);

    XFREE(decodedConfigs, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

int wolfSSL_CTX_SetEchConfigs(WOLFSSL_CTX* ctx, const byte* echConfigs,
    word32 echConfigsLen)
{
    int ret;

    if (ctx == NULL || echConfigs == NULL || echConfigsLen == 0)
        return BAD_FUNC_ARG;

    FreeEchConfigs(ctx->echConfigs, ctx->heap);
    ctx->echConfigs = NULL;
    ret = SetEchConfigsEx(&ctx->echConfigs, ctx->heap, echConfigs,
        echConfigsLen);

    if (ret == 0)
        return WOLFSSL_SUCCESS;

    return ret;
}

/* get the ech configs that the server context is using */
int wolfSSL_CTX_GetEchConfigs(WOLFSSL_CTX* ctx, byte* output,
    word32* outputLen) {
    if (ctx == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    /* if we don't have ech configs */
    if (ctx->echConfigs == NULL)
        return WOLFSSL_FATAL_ERROR;

    return GetEchConfigsEx(ctx->echConfigs, output, outputLen);
}

void wolfSSL_CTX_SetEchEnable(WOLFSSL_CTX* ctx, byte enable)
{
    if (ctx != NULL) {
        ctx->disableECH = !enable;
        if (ctx->disableECH) {
            TLSX_Remove(&ctx->extensions, TLSX_ECH, ctx->heap);
            FreeEchConfigs(ctx->echConfigs, ctx->heap);
            ctx->echConfigs = NULL;
        }
    }
}

/* set the ech config from base64 for our client ssl object, base64 is the
 * format ech configs are sent using dns records */
int wolfSSL_SetEchConfigsBase64(WOLFSSL* ssl, const char* echConfigs64,
    word32 echConfigs64Len)
{
    int ret = 0;
    word32 decodedLen = echConfigs64Len * 3 / 4 + 1;
    byte* decodedConfigs;

    if (ssl == NULL || echConfigs64 == NULL || echConfigs64Len == 0)
        return BAD_FUNC_ARG;

    /* already have ech configs */
    if (ssl->echConfigs != NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    decodedConfigs = (byte*)XMALLOC(decodedLen, ssl->heap,
        DYNAMIC_TYPE_TMP_BUFFER);

    if (decodedConfigs == NULL)
        return MEMORY_E;

    decodedConfigs[decodedLen - 1] = 0;

    /* decode the echConfigs */
    ret = Base64_Decode((const byte*)echConfigs64, echConfigs64Len,
      decodedConfigs, &decodedLen);

    if (ret != 0) {
        XFREE(decodedConfigs, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wolfSSL_SetEchConfigs(ssl, decodedConfigs, decodedLen);

    XFREE(decodedConfigs, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* set the ech config from a raw buffer, this is the format ech configs are
 * sent using retry_configs from the ech server */
int wolfSSL_SetEchConfigs(WOLFSSL* ssl, const byte* echConfigs,
    word32 echConfigsLen)
{
    int ret;

    if (ssl == NULL || echConfigs == NULL || echConfigsLen == 0)
        return BAD_FUNC_ARG;

    /* already have ech configs */
    if (ssl->echConfigs != NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    ret = SetEchConfigsEx(&ssl->echConfigs, ssl->heap, echConfigs,
        echConfigsLen);

    /* if we found valid configs */
    if (ret == 0) {
        return WOLFSSL_SUCCESS;
    }

    return ret;
}

/* get the raw ech config from our struct */
int GetEchConfig(WOLFSSL_EchConfig* config, byte* output, word32* outputLen)
{
    int i;
    word16 totalLen = 0;
    word16 publicNameLen;

    if (config == NULL || (output == NULL && outputLen == NULL))
        return BAD_FUNC_ARG;

    /* ECH spec limits public_name to 255 bytes (1-byte length prefix) */
    if (config->publicName == NULL || XSTRLEN(config->publicName) > 255)
        return BAD_FUNC_ARG;
    publicNameLen = (word16)XSTRLEN(config->publicName);

    /* 2 for version */
    totalLen += 2;
    /* 2 for length */
    totalLen += 2;
    /* 1 for configId */
    totalLen += 1;
    /* 2 for kemId */
    totalLen += 2;
    /* 2 for hpke_len */
    totalLen += 2;

    /* hpke_pub_key */
    switch (config->kemId) {
        case DHKEM_P256_HKDF_SHA256:
            totalLen += DHKEM_P256_ENC_LEN;
            break;
        case DHKEM_P384_HKDF_SHA384:
            totalLen += DHKEM_P384_ENC_LEN;
            break;
        case DHKEM_P521_HKDF_SHA512:
            totalLen += DHKEM_P521_ENC_LEN;
            break;
        case DHKEM_X25519_HKDF_SHA256:
            totalLen += DHKEM_X25519_ENC_LEN;
            break;
        case DHKEM_X448_HKDF_SHA512:
            totalLen += DHKEM_X448_ENC_LEN;
            break;
    }

    /* cipherSuitesLen */
    totalLen += 2;
    /* cipherSuites */
    totalLen += config->numCipherSuites * 4;
    /* public name len */
    totalLen += 2;

    /* public name */
    totalLen += publicNameLen;
    /* trailing zeros */
    totalLen += 2;

    if (output == NULL) {
        *outputLen = totalLen;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (totalLen > *outputLen) {
        *outputLen = totalLen;
        return INPUT_SIZE_E;
    }

    /* version */
    c16toa(TLSX_ECH, output);
    output += 2;

    /* length - 4 for version and length itself */
    c16toa(totalLen - 4, output);
    output += 2;

    /* configId */
    *output = config->configId;
    output++;
    /* kemId */
    c16toa(config->kemId, output);
    output += 2;

    /* length and key itself */
    switch (config->kemId) {
        case DHKEM_P256_HKDF_SHA256:
            c16toa(DHKEM_P256_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P256_ENC_LEN);
            output += DHKEM_P256_ENC_LEN;
            break;
        case DHKEM_P384_HKDF_SHA384:
            c16toa(DHKEM_P384_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P384_ENC_LEN);
            output += DHKEM_P384_ENC_LEN;
            break;
        case DHKEM_P521_HKDF_SHA512:
            c16toa(DHKEM_P521_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_P521_ENC_LEN);
            output += DHKEM_P521_ENC_LEN;
            break;
        case DHKEM_X25519_HKDF_SHA256:
            c16toa(DHKEM_X25519_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_X25519_ENC_LEN);
            output += DHKEM_X25519_ENC_LEN;
            break;
        case DHKEM_X448_HKDF_SHA512:
            c16toa(DHKEM_X448_ENC_LEN, output);
            output += 2;
            XMEMCPY(output, config->receiverPubkey, DHKEM_X448_ENC_LEN);
            output += DHKEM_X448_ENC_LEN;
            break;
    }

    /* cipherSuites len */
    c16toa(config->numCipherSuites * 4, output);
    output += 2;

    /* cipherSuites */
    for (i = 0; i < config->numCipherSuites; i++) {
        c16toa(config->cipherSuites[i].kdfId, output);
        output += 2;
        c16toa(config->cipherSuites[i].aeadId, output);
        output += 2;
    }

    /* set maximum name length to 0 */
    *output = 0;
    output++;

    /* publicName len */
    *output = (byte)publicNameLen;
    output++;

    /* publicName */
    XMEMCPY(output, config->publicName, publicNameLen);
    output += publicNameLen;

    /* terminating zeros */
    c16toa(0, output);
    /* output += 2; */

    *outputLen = totalLen;

    return 0;
}

/* wrapper function to get ech configs from application code */
int wolfSSL_GetEchConfigs(WOLFSSL* ssl, byte* output, word32* outputLen)
{
    if (ssl == NULL || outputLen == NULL)
        return BAD_FUNC_ARG;

    /* if we don't have ech configs */
    if (ssl->echConfigs == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    return GetEchConfigsEx(ssl->echConfigs, output, outputLen);
}

void wolfSSL_SetEchEnable(WOLFSSL* ssl, byte enable)
{
    if (ssl != NULL) {
        ssl->options.disableECH = !enable;
        if (ssl->options.disableECH) {
            TLSX_Remove(&ssl->extensions, TLSX_ECH, ssl->heap);
            FreeEchConfigs(ssl->echConfigs, ssl->heap);
            ssl->echConfigs = NULL;
        }
    }
}

int SetEchConfigsEx(WOLFSSL_EchConfig** outputConfigs, void* heap,
    const byte* echConfigs, word32 echConfigsLen)
{
    int ret = 0;
    int i;
    int j;
    word16 totalLength;
    word16 version;
    word16 length;
    word16 hpkePubkeyLen;
    word16 cipherSuitesLen;
    word16 publicNameLen;
    WOLFSSL_EchConfig* configList = NULL;
    WOLFSSL_EchConfig* workingConfig = NULL;
    WOLFSSL_EchConfig* lastConfig = NULL;
    byte* echConfig = NULL;

    if (outputConfigs == NULL || echConfigs == NULL || echConfigsLen == 0)
        return BAD_FUNC_ARG;

    /* check that the total length is well formed */
    ato16(echConfigs, &totalLength);

    if (totalLength != echConfigsLen - 2) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* skip the total length uint16_t */
    i = 2;

    do {
        echConfig = (byte*)echConfigs + i;
        ato16(echConfig, &version);
        ato16(echConfig + 2, &length);

        /* if the version does not match */
        if (version != TLSX_ECH) {
            /* we hit the end of the configs */
            if ( (word32)i + 2 >= echConfigsLen ) {
                break;
            }

            /* skip this config, +4 for version and length */
            i += length + 4;
            continue;
        }

        /* check if the length will overrun the buffer */
        if ((word32)i + length + 4 > echConfigsLen) {
            break;
        }

        if (workingConfig == NULL) {
            workingConfig =
                (WOLFSSL_EchConfig*)XMALLOC(sizeof(WOLFSSL_EchConfig), heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            configList = workingConfig;
            if (workingConfig != NULL) {
                workingConfig->next = NULL;
            }
        }
        else {
            lastConfig = workingConfig;
            workingConfig->next =
                (WOLFSSL_EchConfig*)XMALLOC(sizeof(WOLFSSL_EchConfig),
                heap, DYNAMIC_TYPE_TMP_BUFFER);
            workingConfig = workingConfig->next;
        }

        if (workingConfig == NULL) {
            ret = MEMORY_E;
            break;
        }

        XMEMSET(workingConfig, 0, sizeof(WOLFSSL_EchConfig));

        /* rawLen */
        workingConfig->rawLen = length + 4;

        /* raw body */
        workingConfig->raw = (byte*)XMALLOC(workingConfig->rawLen,
            heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingConfig->raw == NULL) {
            ret = MEMORY_E;
            break;
        }

        XMEMCPY(workingConfig->raw, echConfig, workingConfig->rawLen);

        /* skip over version and length */
        echConfig += 4;

        /* configId, 1 byte */
        workingConfig->configId = *(echConfig);
        echConfig++;
        /* kemId, 2 bytes */
        ato16(echConfig, &workingConfig->kemId);
        echConfig += 2;
        /* hpke public_key length, 2 bytes */
        ato16(echConfig, &hpkePubkeyLen);
        echConfig += 2;
        /* hpke public_key */
        if (hpkePubkeyLen > HPKE_Npk_MAX) {
            ret = BUFFER_E;
            break;
        }
        XMEMCPY(workingConfig->receiverPubkey, echConfig, hpkePubkeyLen);
        echConfig += hpkePubkeyLen;
        /* cipherSuitesLen */
        ato16(echConfig, &cipherSuitesLen);

        workingConfig->cipherSuites = (EchCipherSuite*)XMALLOC(cipherSuitesLen,
            heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingConfig->cipherSuites == NULL) {
            ret = MEMORY_E;
            break;
        }

        echConfig += 2;
        workingConfig->numCipherSuites = cipherSuitesLen / 4;
        /* cipherSuites */
        for (j = 0; j < workingConfig->numCipherSuites; j++) {
            ato16(echConfig + j * 4, &workingConfig->cipherSuites[j].kdfId);
            ato16(echConfig + j * 4 + 2,
                &workingConfig->cipherSuites[j].aeadId);
        }
        echConfig += cipherSuitesLen;
        /* ignore the maximum name length */
        echConfig++;
        /* publicNameLen */
        publicNameLen = *(echConfig);
        workingConfig->publicName = (char*)XMALLOC(publicNameLen + 1,
            heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (workingConfig->publicName == NULL) {
            ret = MEMORY_E;
            break;
        }
        echConfig++;
        /* publicName */
        XMEMCPY(workingConfig->publicName, echConfig, publicNameLen);
        /* null terminated */
        workingConfig->publicName[publicNameLen] = 0;

        /* add length to go to next config, +4 for version and length */
        i += length + 4;

        /* check that we support this config */
        for (j = 0; j < HPKE_SUPPORTED_KEM_LEN; j++) {
            if (hpkeSupportedKem[j] == workingConfig->kemId)
                break;
        }

        /* if we don't support the kem or at least one cipher suite */
        if (j >= HPKE_SUPPORTED_KEM_LEN ||
            EchConfigGetSupportedCipherSuite(workingConfig) < 0)
        {
            XFREE(workingConfig->cipherSuites, heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(workingConfig->publicName, heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(workingConfig->raw, heap, DYNAMIC_TYPE_TMP_BUFFER);
            workingConfig = lastConfig;
        }
    } while ((word32)i < echConfigsLen);

    /* if we found valid configs */
    if (ret == 0 && configList != NULL) {
        *outputConfigs = configList;

        return ret;
    }

    workingConfig = configList;

    while (workingConfig != NULL) {
        lastConfig = workingConfig;
        workingConfig = workingConfig->next;

        XFREE(lastConfig->cipherSuites, heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(lastConfig->publicName, heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(lastConfig->raw, heap, DYNAMIC_TYPE_TMP_BUFFER);

        XFREE(lastConfig, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret == 0)
        return WOLFSSL_FATAL_ERROR;

    return ret;
}

/* get the raw ech configs from our linked list of ech config structs */
int GetEchConfigsEx(WOLFSSL_EchConfig* configs, byte* output, word32* outputLen)
{
    int ret = 0;
    WOLFSSL_EchConfig* workingConfig = NULL;
    byte* outputStart = output;
    word32 totalLen = 2;
    word32 workingOutputLen = 0;

    if (configs == NULL || outputLen == NULL ||
            (output != NULL && *outputLen < totalLen)) {
        return BAD_FUNC_ARG;
    }


    /* skip over total length which we fill in later */
    if (output != NULL) {
        workingOutputLen = *outputLen - totalLen;
        output += 2;
    }
    else {
        /* caller getting the size only, set current 2 byte length size */
        *outputLen = totalLen;
    }

    workingConfig = configs;

    while (workingConfig != NULL) {
        /* get this config */
        ret = GetEchConfig(workingConfig, output, &workingOutputLen);

        if (output != NULL)
            output += workingOutputLen;

        /* add this config's length to the total length */
        totalLen += workingOutputLen;

        if (totalLen > *outputLen)
            workingOutputLen = 0;
        else
            workingOutputLen = *outputLen - totalLen;

        /* only error we break on, other 2 we need to keep finding length */
        if (ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG))
            return BAD_FUNC_ARG;

        workingConfig = workingConfig->next;
    }

    if (output == NULL) {
        *outputLen = totalLen;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (totalLen > *outputLen) {
        *outputLen = totalLen;
        return INPUT_SIZE_E;
    }

    /* total size -2 for size itself */
    c16toa(totalLen - 2, outputStart);

    *outputLen = totalLen;

    return WOLFSSL_SUCCESS;
}

#endif /* WOLFSSL_TLS13 && HAVE_ECH */

#endif /* !WOLFSSL_SSL_ECH_INCLUDED */

