/* psa.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_HAVE_PSA_ENGINE)

#include <wolfssl/wolfcrypt/port/psa/crypto.h>

#if defined(HAVE_ECC)
#include <wolfssl/wolfcrypt/ecc.h>
#endif

#if !defined(NO_SHA256)
#include <wolfssl/wolfcrypt/sha256.h>
#endif

#if !defined(NO_AES)
#include <wolfssl/wolfcrypt/aes.h>
#endif

#include <wolfssl/wolfcrypt/random.h>

static psa_aead_operation_t zero_aead_operation;
static psa_cipher_operation_t zero_cipher_operation;
static psa_hash_operation_t zero_hash_operation;
static psa_key_derivation_operation_t zero_key_derivation_operation;
static psa_mac_operation_t zero_mac_operation;
static psa_key_attributes_t zero_key_attribute;

static int psa_initialized;
static psa_key_id_t psa_incremental_id;

/* max number of keys that can be used */
#define PSA_KEY_SLOTS 6

/** struct wc_psa_key
 * @attr: attributes of a key
 * @key: wolfssl native key used
 */
struct wc_psa_key {
    psa_key_attributes_t attr;
    void *key;
};

static wolfSSL_Mutex psa_key_slots_lock;
static struct wc_psa_key wc_psa_key_slots[PSA_KEY_SLOTS];

static struct wc_psa_key *psa_find_key(psa_key_id_t id)
{
    struct wc_psa_key *k;
    int i;

    if (id == PSA_KEY_ID_NULL)
        return NULL;

    if (id < PSA_KEY_ID_USER_MIN || id > PSA_KEY_ID_USER_MAX)
        return NULL;

    for (i = 0; i < PSA_KEY_SLOTS; ++i) {
        k = &wc_psa_key_slots[i];
        if (k->attr.id == id)
            return k;
    }

    return NULL;
}

static psa_key_id_t psa_get_new_id(void)
{
    int err;

    err = wc_LockMutex(&psa_key_slots_lock);
    if (err != 0)
        return PSA_KEY_ID_NULL;
    psa_incremental_id++;
    err = wc_UnLockMutex(&psa_key_slots_lock);

    if (psa_incremental_id > PSA_KEY_ID_USER_MAX)
        return PSA_KEY_ID_NULL;

    return psa_incremental_id;
}

static struct wc_psa_key *psa_find_free_slot(void)
{
    struct wc_psa_key *k;
    int err;
    int i;

    err = wc_LockMutex(&psa_key_slots_lock);
    if (err != 0)
        return NULL;

    for (i = 0; i < PSA_KEY_SLOTS; ++i) {
        k = &wc_psa_key_slots[i];
        if (k->attr.id == PSA_KEY_ID_NULL) {
            k->attr.id = PSA_KEY_ID_BUSY;
            wc_UnLockMutex(&psa_key_slots_lock);
            return k;
        }
    }

    wc_UnLockMutex(&psa_key_slots_lock);
    return NULL;
}

psa_status_t psa_not_implemented(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_aead_operation_t psa_aead_operation_init()
{
    return zero_aead_operation;
}

psa_cipher_operation_t psa_cipher_operation_init()
{
    return zero_cipher_operation;
}

psa_hash_operation_t psa_hash_operation_init()
{
    return zero_hash_operation;
}

psa_key_derivation_operation_t psa_key_derivation_operation_init()
{
    return zero_key_derivation_operation;
}

psa_mac_operation_t psa_mac_operation_init()
{
    return zero_mac_operation;
}

psa_key_attributes_t psa_key_attributes_init()
{
    return zero_key_attribute;
}

psa_status_t psa_crypto_init()
{
    int err;
    err = wc_InitMutex(&psa_key_slots_lock);
    if (err != 0)
        return PSA_ERROR_BAD_STATE;

    psa_initialized = 1;
    return PSA_SUCCESS;
}

psa_status_t psa_generate_random(uint8_t *output WC_MAYBE_UNUSED,
                                    size_t output_size WC_MAYBE_UNUSED)
{
    /* appease psa-arch-tests */
    if (psa_initialized == 0)
        return PSA_ERROR_BAD_STATE;

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t *attributes)
{
    struct wc_psa_key *_key;

    if (attributes == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;

    /* as for specs, clear attributes on failure  */
    psa_reset_key_attributes(attributes);

    if (psa_initialized == 0)
        return PSA_ERROR_BAD_STATE;

    _key = psa_find_key(key);
    if (_key == NULL)
        return PSA_ERROR_INVALID_HANDLE;

    XMEMCPY(attributes, &_key->attr, sizeof(*attributes));

    return PSA_SUCCESS;
}

void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
    if (attributes == NULL)
        return;

    XMEMSET(attributes, 0, sizeof(*attributes));
}


#ifdef HAVE_ECC

#if (!defined(NO_ECC256) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
#define PSA_ECC256
#endif

static psa_status_t psa_ecc_get_curve_id(const psa_key_attributes_t *attributes,
                                         size_t data_length,
                                         int *curve_id,
                                         size_t *bits,
                                         int is_secret_key)
{
    size_t _bits;

    switch (PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type)) {
    case PSA_ECC_FAMILY_SECP_R1:

        if (is_secret_key) {
            _bits = data_length * 8;
        } else {
            /* public key encoded as 0x04,qx,qy  */
            _bits = ((data_length - 1) / 2) * 8;
        }

        if (attributes->bits != 0 && attributes->bits != _bits)
                        return PSA_ERROR_INVALID_ARGUMENT;

        switch (_bits) {
#if defined(PSA_ECC256) && !defined(NO_ECC_SECP)
        case 256:
            *curve_id = ECC_SECP256R1;
            *bits = 256;
            return PSA_SUCCESS;
#endif /*defined(PSA_ECC256) && !defined(NO_ECC_SECP) */
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }

        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* can't reach here */
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t psa_ecc_import_key(const psa_key_attributes_t *attributes,
                                       const uint8_t *data,
                                       size_t data_length,
                                       psa_key_id_t *key)
{
    struct wc_psa_key *new_psa_key;
    struct ecc_key *new_ecc_key;
    const uint8_t *qx, *qy;
    psa_key_id_t new_id;
    psa_key_type_t type;
    psa_status_t ret;
    int curve_id;
    size_t bits;
    int wc_ret;

    type = attributes->type;

    if (data_length <= 1)
        return PSA_ERROR_INVALID_ARGUMENT;

    ret = psa_ecc_get_curve_id(attributes, data_length,
                               &curve_id, &bits,
                               PSA_KEY_TYPE_IS_KEY_PAIR(type));

    if (ret != PSA_SUCCESS)
        return ret;

    switch (PSA_KEY_TYPE_ECC_GET_FAMILY(attributes->type)) {
    case PSA_ECC_FAMILY_SECP_R1:
        new_ecc_key = XMALLOC(sizeof(*new_ecc_key), NULL, DYNAMIC_TYPE_ECC);
        if (!new_ecc_key)
            return PSA_ERROR_INSUFFICIENT_MEMORY;

        if (PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
            wc_ret = wc_ecc_import_private_key_ex(data, data_length,
                                                  NULL, 0, new_ecc_key,
                                                  curve_id);
            if (wc_ret != 0) {
                ret = PSA_ERROR_INVALID_ARGUMENT;
                goto out_free;
            }

            wc_ret = wc_ecc_make_pub(new_ecc_key, NULL);

        } else {
            qx = data + 1;
            qy = data + 1 + bits;

            wc_ret = wc_ecc_import_unsigned(new_ecc_key, qx, qy,
                                            NULL, curve_id);
        }

        if (wc_ret != 0) {
            ret = PSA_ERROR_INVALID_ARGUMENT;
            goto out_free;
        }
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    new_id = psa_get_new_id();
    if (new_id == PSA_KEY_ID_NULL) {
        ret = PSA_ERROR_BAD_STATE;
        goto out_free;
    }

    new_psa_key = psa_find_free_slot();
    if (new_psa_key == NULL) {
        ret = PSA_ERROR_INSUFFICIENT_STORAGE;
        goto out_free;
    }

    new_psa_key->attr.type = attributes->type;
    new_psa_key->attr.bits = bits;
    new_psa_key->attr.lifetime = attributes->lifetime;
    new_psa_key->attr.usage_flags = attributes->usage_flags;
    new_psa_key->attr.permitted_algs = attributes->permitted_algs;
    new_psa_key->key = (void*)new_ecc_key;
    *key = new_id;
    new_psa_key->attr.id = new_id;

    return PSA_SUCCESS;

 out_free:
    wc_ecc_free(new_ecc_key);
    free(new_ecc_key);
    return ret;
}
#endif // HAVE_ECC

#if !defined(NO_AES)
static psa_status_t psa_aes_cipher_decrypt(struct wc_psa_key *key,
                                           psa_algorithm_t alg,
                                           const uint8_t *input,
                                           size_t input_length,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{
    struct Aes aes;
    int ret;

#if defined(WOLFSSL_AES_COUNTER)
    if (alg == PSA_ALG_CTR) {
        if (input_length < AES_IV_SIZE || input_length % AES_BLOCK_SIZE != 0)
            return PSA_ERROR_INVALID_ARGUMENT;

        if (output_size < input_length - AES_IV_SIZE)
            return PSA_ERROR_BUFFER_TOO_SMALL;

        ret = wc_AesInit(&aes, NULL, DYNAMIC_TYPE_AES);
        if (ret != 0)
            return PSA_ERROR_BAD_STATE;

        ret = wc_AesSetKey(&aes, key->key,
                           key->attr.bits / 8,
                           input, /* IV is the first block of the input */
                           AES_DECRYPTION);
        if (ret != 0) {
            wc_AesFree(&aes);
            return PSA_ERROR_BAD_STATE;
        }

        ret = wc_AesCtrEncrypt(&aes, output,
                               input + AES_IV_SIZE,
                               input_length - AES_IV_SIZE);
        if (ret != 0) {
            wc_AesFree(&aes);
            return PSA_ERROR_BAD_STATE;
        }

        wc_AesFree(&aes);
        *output_length = input_length - AES_IV_SIZE;
        return PSA_SUCCESS;
    }
#endif

    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t psa_aes_cipher_encrypt(struct wc_psa_key *key,
                                           psa_algorithm_t alg,
                                           const uint8_t *input,
                                           size_t input_length,
                                           uint8_t *output,
                                           size_t output_size,
                                           size_t *output_length)
{
    uint8_t iv[AES_IV_SIZE];
    struct Aes aes;
    WC_RNG rng;
    int ret;

#if defined(WOLFSSL_AES_COUNTER)
    if (alg == PSA_ALG_CTR) {
        if (output_size < AES_IV_SIZE + input_length)
            return PSA_ERROR_BUFFER_TOO_SMALL;

       ret = wc_InitRng(&rng);
        if (ret != 0)
            return PSA_ERROR_INSUFFICIENT_ENTROPY;

        ret = wc_RNG_GenerateBlock(&rng, iv, AES_IV_SIZE);
        if (ret != 0) {
            wc_FreeRng(&rng);
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }

        wc_FreeRng(&rng);

        ret = wc_AesInit(&aes, NULL, DYNAMIC_TYPE_AES);
        if (ret != 0)
            return PSA_ERROR_BAD_STATE;

        ret = wc_AesSetKey(&aes, key->key,
                           key->attr.bits / 8, iv, AES_ENCRYPTION);
        if (ret != 0) {
            wc_AesFree(&aes);
            return PSA_ERROR_BAD_STATE;
        }

        XMEMCPY(output, iv, AES_IV_SIZE);
        ret = wc_AesCtrEncrypt(&aes,
                               output + AES_IV_SIZE,
                               input, input_length);
        if (ret != 0) {
            wc_AesFree(&aes);
            return PSA_ERROR_BAD_STATE;
        }

        wc_AesFree(&aes);
        *output_length = input_length + AES_IV_SIZE;
        return PSA_SUCCESS;
    }
#endif

    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t psa_aes_import_key(const psa_key_attributes_t *attributes,
                                       const uint8_t *data,
                                       size_t data_length,
                                       psa_key_id_t *key)
{
    struct wc_psa_key *k;
    psa_key_id_t key_id;
    psa_status_t ret;
    uint8_t *aes_key;

    if (data_length != AES_128_KEY_SIZE &&
        data_length != AES_192_KEY_SIZE &&
        data_length != AES_256_KEY_SIZE)
        return PSA_ERROR_INVALID_ARGUMENT;

    if (attributes->bits != 0 && attributes->bits != data_length * 8)
        return PSA_ERROR_INVALID_ARGUMENT;

    aes_key = XMALLOC(data_length, NULL, DYNAMIC_TYPE_AES);
    if (aes_key == NULL)
        return PSA_ERROR_INSUFFICIENT_MEMORY;

    key_id = psa_get_new_id();
    if (key_id == PSA_KEY_ID_NULL) {
        ret = PSA_ERROR_BAD_STATE;
        goto out_free;
    }

    XMEMCPY(aes_key, data, data_length);

    k = psa_find_free_slot();
    if (k == NULL) {
        ret = PSA_ERROR_BAD_STATE;
        goto out_free;
    }

    k->key = aes_key;
    k->attr.type = attributes->type;
    k->attr.bits = data_length * 8;
    k->attr.lifetime = attributes->lifetime;
    k->attr.usage_flags = attributes->usage_flags;
    k->attr.permitted_algs = attributes->permitted_algs;

    *key = key_id;
    k->attr.id = key_id;

    return PSA_SUCCESS;

out_free:
    free(aes_key);
    return ret;
}
#endif

psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            psa_key_id_t *key)
{
    psa_key_type_t type;

    if (psa_initialized != 1)
        return PSA_ERROR_BAD_STATE;

    *key = PSA_KEY_ID_NULL;

   if (attributes == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;

    type = attributes->type;
    if (type == PSA_KEY_TYPE_NONE)
        return PSA_ERROR_NOT_SUPPORTED;

    if (!PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime))
        return PSA_ERROR_NOT_SUPPORTED;

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)
    if (PSA_KEY_TYPE_IS_ECC(type))
        return psa_ecc_import_key(attributes, data, data_length, key);
#endif

#if !defined(NO_AES)
    if (type == PSA_KEY_TYPE_AES)
        return psa_aes_import_key(attributes, data, data_length, key);
#endif

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
    struct wc_psa_key *k;

    if (psa_initialized != 1)
        return PSA_ERROR_BAD_STATE;

    if (key == PSA_KEY_ID_NULL)
        return PSA_SUCCESS;

    k = psa_find_key(key);
    if (k == NULL)
        return PSA_ERROR_INVALID_HANDLE;

#if defined(HAVE_ECC)
    if (PSA_KEY_TYPE_IS_ECC(k->attr.type)) {
        wc_ecc_free(k->key);
        free(k->key);
        psa_reset_key_attributes(&k->attr);
        return PSA_SUCCESS;
    }
#endif /* HAVE_ECC */

#if !defined(NO_AES)
    if (k->attr.type == PSA_KEY_TYPE_AES) {
        free(k->key);
        psa_reset_key_attributes(&k->attr);
        return PSA_SUCCESS;
    }
#endif

    return PSA_ERROR_BAD_STATE;
}


#if !defined(NO_SHA256)
static psa_status_t psa_sha256_hash_compute(const uint8_t *input,
                                            size_t input_length,
                                            uint8_t *hash,
                                            size_t *hash_length)
{
    psa_status_t ret = PSA_ERROR_BAD_STATE;
    wc_Sha256 sha256;
    int err;

    err = wc_InitSha256(&sha256);
    if (err != 0)
        return PSA_ERROR_BAD_STATE;

    err = wc_Sha256Update(&sha256, input, input_length);
    if (err != 0) {
        ret = PSA_ERROR_BAD_STATE;
        goto out_free;
    }

    err = wc_Sha256Final(&sha256, hash);
    if (err != 0) {
        ret = PSA_ERROR_BAD_STATE;
        goto out_free;
    }

    *hash_length = WC_SHA256_DIGEST_SIZE;
    ret = PSA_SUCCESS;

 out_free:
    wc_Sha256Free(&sha256);
    return ret;
}
#endif

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                                 const uint8_t *input,
                                 size_t input_length,
                                 uint8_t *hash,
                                 size_t hash_size,
                                 size_t *hash_length)
{
    if (!PSA_ALG_IS_HASH(alg))
        return PSA_ERROR_NOT_SUPPORTED;

    if (input == NULL || hash == NULL || hash_size == 0 ||
        hash_length == NULL || PSA_HASH_LENGTH(alg) > hash_size)
        return PSA_ERROR_INVALID_ARGUMENT;

#if !defined(NO_SHA256)
    if (alg == PSA_ALG_SHA_256)
        return psa_sha256_hash_compute(input, input_length, hash, hash_length);
#endif

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_encrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *input,
                                   size_t input_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    struct wc_psa_key *k;

    k = psa_find_key(key);
    if (k == NULL)
        return PSA_ERROR_INVALID_HANDLE;

    if ((k->attr.usage_flags & PSA_KEY_USAGE_ENCRYPT) == 0)
        return PSA_ERROR_NOT_PERMITTED;

#if !defined(NO_AES)
    if (k->attr.type == PSA_KEY_TYPE_AES) {
        return psa_aes_cipher_encrypt(k, alg, input,
                                      input_length, output,
                                      output_size, output_length);
    }
#endif

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_decrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *input,
                                   size_t input_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    struct wc_psa_key *k;

    k = psa_find_key(key);
    if (k == NULL)
        return PSA_ERROR_INVALID_HANDLE;

    if ((k->attr.usage_flags & PSA_KEY_USAGE_DECRYPT) == 0)
        return PSA_ERROR_NOT_PERMITTED;

#if !defined(NO_AES)
    if (k->attr.type == PSA_KEY_TYPE_AES) {
        return psa_aes_cipher_decrypt(k, alg, input,
                                      input_length, output,
                                      output_size, output_length);
    }
#endif

    return PSA_ERROR_NOT_SUPPORTED;

}

#endif
