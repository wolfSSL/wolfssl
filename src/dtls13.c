/* dtls13.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

#ifdef WOLFSSL_DTLS13

#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#endif

WOLFSSL_METHOD* wolfDTLSv1_3_client_method_ex(void* heap)
{
    WOLFSSL_METHOD* method;

    WOLFSSL_ENTER("DTLSv1_3_client_method_ex");

    method = (WOLFSSL_METHOD*)XMALLOC(sizeof(WOLFSSL_METHOD), heap,
        DYNAMIC_TYPE_METHOD);
    if (method)
        InitSSL_Method(method, MakeDTLSv1_3());

    return method;
}

WOLFSSL_METHOD* wolfDTLSv1_3_server_method_ex(void* heap)
{
    WOLFSSL_METHOD* method;

    WOLFSSL_ENTER("DTLSv1_3_server_method_ex");

    method = (WOLFSSL_METHOD*)XMALLOC(sizeof(WOLFSSL_METHOD), heap,
        DYNAMIC_TYPE_METHOD);
    if (method) {
        InitSSL_Method(method, MakeDTLSv1_3());
        method->side = WOLFSSL_SERVER_END;
    }

    return method;
}

WOLFSSL_METHOD* wolfDTLSv1_3_client_method(void)
{
    return wolfDTLSv1_3_client_method_ex(NULL);
}

WOLFSSL_METHOD* wolfDTLSv1_3_server_method(void)
{
    return wolfDTLSv1_3_server_method_ex(NULL);
}

#define SN_LABEL_SZ 2
static const byte snLabel[SN_LABEL_SZ + 1] = "sn";

/**
 * Dtls13DeriveSnKeys() - derive the key used to encrypt the record number
 * @ssl: ssl object
 * @provision: which side (CLIENT or SERVER) to provision
 */
int Dtls13DeriveSnKeys(WOLFSSL* ssl, int provision)
{
    byte key_dig[MAX_PRF_DIG];
    int ret = 0;

    if (provision & PROVISION_CLIENT) {
        WOLFSSL_MSG("Derive SN Client key");
        ret = Tls13DeriveKey(ssl, key_dig, ssl->specs.key_size,
            ssl->clientSecret, snLabel, SN_LABEL_SZ, ssl->specs.mac_algorithm,
            0);
        if (ret != 0)
            goto end;

        XMEMCPY(ssl->keys.client_sn_key, key_dig, ssl->specs.key_size);
    }

    if (provision & PROVISION_SERVER) {
        WOLFSSL_MSG("Derive SN Server key");
        ret = Tls13DeriveKey(ssl, key_dig, ssl->specs.key_size,
            ssl->serverSecret, snLabel, SN_LABEL_SZ, ssl->specs.mac_algorithm,
            0);
        if (ret != 0)
            goto end;

        XMEMCPY(ssl->keys.server_sn_key, key_dig, ssl->specs.key_size);
    }

end:
    ForceZero(key_dig, MAX_PRF_DIG);
    return ret;
}

static int Dtls13InitAesCipher(WOLFSSL* ssl, RecordNumberCiphers* cipher,
    const byte* key, word16 keySize)
{
    int ret;
    if (cipher->aes == NULL) {
        cipher->aes =
            (Aes*)XMALLOC(sizeof(Aes), ssl->heap, DYNAMIC_TYPE_CIPHER);
        if (cipher->aes == NULL)
            return MEMORY_E;
    }
    else {
        wc_AesFree(cipher->aes);
    }

    XMEMSET(cipher->aes, 0, sizeof(*cipher->aes));

    ret = wc_AesInit(cipher->aes, ssl->heap, INVALID_DEVID);
    if (ret != 0)
        return ret;

    return wc_AesSetKey(cipher->aes, key, keySize, NULL, AES_ENCRYPTION);
}

#ifdef HAVE_CHACHA
static int Dtls13InitChaChaCipher(RecordNumberCiphers* c, byte* key,
    word16 keySize, void* heap)
{
    (void)heap;

    if (c->chacha == NULL) {
        c->chacha = (ChaCha*)XMALLOC(sizeof(ChaCha), heap, DYNAMIC_TYPE_CIPHER);

        if (c->chacha == NULL)
            return MEMORY_E;
    }

    return wc_Chacha_SetKey(c->chacha, key, keySize);
}
#endif /* HAVE_CHACHA */

int Dtls13SetRecordNumberKeys(WOLFSSL* ssl, enum encrypt_side side)
{
    RecordNumberCiphers* enc = NULL;
    RecordNumberCiphers* dec = NULL;
    byte *encKey, *decKey;
    int ret;

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (side) {
    case ENCRYPT_SIDE_ONLY:
        enc = &ssl->dtlsRecordNumberEncrypt;
        break;
    case DECRYPT_SIDE_ONLY:
        dec = &ssl->dtlsRecordNumberDecrypt;
        break;
    case ENCRYPT_AND_DECRYPT_SIDE:
        enc = &ssl->dtlsRecordNumberEncrypt;
        dec = &ssl->dtlsRecordNumberDecrypt;
        break;
    }

    if (enc) {
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            encKey = ssl->keys.client_sn_key;
        else
            encKey = ssl->keys.server_sn_key;
    }

    if (dec) {
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            decKey = ssl->keys.server_sn_key;
        else
            decKey = ssl->keys.client_sn_key;
    }

    /* DTLSv1.3 supports only AEAD algorithm.  */
#if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
    if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm ||
        ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm) {

        if (enc) {
            ret = Dtls13InitAesCipher(ssl, enc, encKey, ssl->specs.key_size);
            if (ret != 0)
                return ret;
#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning AES Record Number enc key:");
            WOLFSSL_BUFFER(encKey, ssl->specs.key_size);
#endif /* WOLFSSL_DEBUG_TLS */
        }

        if (dec) {
            ret = Dtls13InitAesCipher(ssl, dec, decKey, ssl->specs.key_size);
            if (ret != 0)
                return ret;
#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning AES Record Number dec key:");
            WOLFSSL_BUFFER(decKey, ssl->specs.key_size);
#endif /* WOLFSSL_DEBUG_TLS */
        }

        return 0;
    }
#endif /* BUILD_AESGCM || HAVE_AESCCM */

#ifdef HAVE_CHACHA
    if (ssl->specs.bulk_cipher_algorithm == wolfssl_chacha) {
        if (enc) {
            ret = Dtls13InitChaChaCipher(enc, encKey, ssl->specs.key_size,
                ssl->heap);
            if (ret != 0)
                return ret;
#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning CHACHA Record Number enc key:");
            WOLFSSL_BUFFER(encKey, ssl->specs.key_size);
#endif /* WOLFSSL_DEBUG_TLS */
        }

        if (dec) {
            ret = Dtls13InitChaChaCipher(dec, decKey, ssl->specs.key_size,
                ssl->heap);
            if (ret != 0)
                return ret;
#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning CHACHA Record Number dec key:");
            WOLFSSL_BUFFER(decKey, ssl->specs.key_size);
#endif /* WOLFSSL_DEBUG_TLS */
        }

        return 0;
    }
#endif /* HAVE_CHACHA */

    return NOT_COMPILED_IN;
}

#endif /* WOLFSSL_DTLS13 */
