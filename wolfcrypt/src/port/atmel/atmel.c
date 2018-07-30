/* atmel.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

#if defined(WOLFSSL_ATMEL) || defined(WOLFSSL_ATECC508A)

#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#ifdef WOLFSSL_ATMEL
#define Aes Aes_Remap
#define Gmac Gmac_Remap
#include "asf.h"
#undef Aes
#undef Gmac
#endif /* WOLFSSL_ATMEL */

#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

static bool mAtcaInitDone = 0;

#ifdef WOLFSSL_ATECC508A

/* List of available key slots */
static int mSlotList[ATECC_MAX_SLOT+1];

/**
 * \brief Structure to contain certificate information.
 */
t_atcert atcert = {
	.signer_ca_size = 512,
	.signer_ca = { 0 },
	.signer_ca_pubkey = { 0 },
	.end_user_size = 512,
	.end_user = { 0 },
	.end_user_pubkey = { 0 }
};

static int atmel_init_enc_key(void);

#endif /* WOLFSSL_ATECC508A */


/**
 * \brief Generate random number to be used for hash.
 */
int atmel_get_random_number(uint32_t count, uint8_t* rand_out)
{
	int ret = 0;
#ifdef WOLFSSL_ATECC508A
	uint8_t i = 0;
	uint32_t copy_count = 0;
	uint8_t rng_buffer[RANDOM_NUM_SIZE];

	if (rand_out == NULL) {
		return -1;
	}

	while(i < count) {

		ret = atcatls_random(rng_buffer);
		if (ret != 0) {
			WOLFSSL_MSG("Failed to create random number!");
			return -1;
		}
		copy_count = (count - i > RANDOM_NUM_SIZE) ? RANDOM_NUM_SIZE : count - i;
		XMEMCPY(&rand_out[i], rng_buffer, copy_count);
		i += copy_count;
	}
    atcab_printbin_label((const uint8_t*)"\r\nRandom Number", rand_out, count);
#else
    // TODO: Use on-board TRNG
#endif
	return ret;
}

int atmel_get_random_block(unsigned char* output, unsigned int sz)
{
	return atmel_get_random_number((uint32_t)sz, (uint8_t*)output);
}

#ifdef WOLFSSL_ATMEL_TIME
extern struct rtc_module *_rtc_instance[RTC_INST_NUM];
#endif
long atmel_get_curr_time_and_date(long* tm)
{
    (void)tm;

#ifdef WOLFSSL_ATMEL_TIME
	/* Get current time */

    //struct rtc_calendar_time rtcTime;
	//rtc_calendar_get_time(_rtc_instance[0], &rtcTime);

    /* Convert rtc_calendar_time to seconds since UTC */
#endif

    return 0;
}



#ifdef WOLFSSL_ATECC508A

/* Function to allocate new slot number */
int atmel_ecc_alloc(void)
{
    int i, slot = -1;
    for (i=0; i <= ATECC_MAX_SLOT; i++) {
        /* Find free slot */
        if (mSlotList[i] == ATECC_INVALID_SLOT) {
            mSlotList[i] = i;
            slot = i;
            break;
        }
    }
    return slot;
}


/* Function to return slot number to avail list */
void atmel_ecc_free(int slot)
{
    if (slot >= 0 && slot <= ATECC_MAX_SLOT) {
        /* Mark slot of free */
        mSlotList[slot] = ATECC_INVALID_SLOT;
    }
}


/**
 * \brief Give enc key to read pms.
 */
static int atmel_set_enc_key(uint8_t* enckey, int16_t keysize)
{
    if (enckey == NULL || keysize != ATECC_KEY_SIZE) {
        return -1;
    }

    XMEMSET(enckey, 0xFF, keysize); // use default values

    return SSL_SUCCESS;
}


/**
 * \brief Write enc key before.
 */
static int atmel_init_enc_key(void)
{
	uint8_t ret = 0;
	uint8_t read_key[ATECC_KEY_SIZE] = { 0 };

	XMEMSET(read_key, 0xFF, sizeof(read_key));
	ret = atcab_write_bytes_slot(TLS_SLOT_ENC_PARENT, 0, read_key, sizeof(read_key));
	if (ret != ATCA_SUCCESS) {
		WOLFSSL_MSG("Failed to write key");
		return -1;
	}

	ret = atcatlsfn_set_get_enckey(atmel_set_enc_key);
	if (ret != ATCA_SUCCESS) {
		WOLFSSL_MSG("Failed to set enckey");
		return -1;
	}

	return ret;
}

static void atmel_show_rev_info(void)
{
#if 0
    uint32_t revision = 0;
    atcab_info((uint8_t*)&revision);
    printf("ATECC508A Revision: %x\n", (unsigned int)revision);
#endif
}

#endif /* WOLFSSL_ATECC508A */



void atmel_init(void)
{
    if (!mAtcaInitDone) {
#ifdef WOLFSSL_ATECC508A
        int i;

        /* Init the free slot list */
        for (i=0; i<=ATECC_MAX_SLOT; i++) {
            if (i == 0 || i == 2 || i == 7) {
                /* ECC Slots (mark avail) */
                mSlotList[i] = ATECC_INVALID_SLOT;
            }
            else {
                mSlotList[i] = i;
            }
        }

        /* Initialize the CryptoAuthLib to communicate with ATECC508A */
        atcatls_init(&cfg_ateccx08a_i2c_default);

        /* Init the I2C pipe encryption key. */
        /* Value is generated/stored during pair for the ATECC508A and stored
            on micro flash */
        /* For this example its a fixed value */
		if (atmel_init_enc_key() != ATCA_SUCCESS) {
			WOLFSSL_MSG("Failed to initialize transport key");
		}

        /* show revision information */
        atmel_show_rev_info();

        /* Configure the ECC508 for use with TLS API functions */
    #if 0
        atcatls_device_provision();
    #else
        atcatls_config_default();
    #endif
#endif /* WOLFSSL_ATECC508A */

        mAtcaInitDone = 1;
    }
}

void atmel_finish(void)
{
    if (mAtcaInitDone) {
#ifdef WOLFSSL_ATECC508A
        atcatls_finish();
#endif
        mAtcaInitDone = 0;
    }
}


/* Reference PK Callbacks */
#ifdef HAVE_PK_CALLBACKS

int atcatls_create_key_cb(WOLFSSL* ssl, ecc_key* key, word32 keySz,
    int ecc_curve, void* ctx)
{
    int ret;
    uint8_t peerKey[ATECC_PUBKEY_SIZE];
    uint8_t* qx = &peerKey[0];
    uint8_t* qy = &peerKey[ATECC_PUBKEY_SIZE/2];

    (void)ssl;
    (void)ctx;

    /* only supports P-256 */
    if (ecc_curve != ECC_SECP256R1 && keySz != ATECC_PUBKEY_SIZE/2) {
        return BAD_FUNC_ARG;
    }

    /* generate new ephemeral key on device */
    ret = atcatls_create_key(TLS_SLOT_ECDHE_PRIV, peerKey);
    if (ret != ATCA_SUCCESS) {
        ret = WC_HW_E; goto exit;
    }

    /* load generated ECC508A public key into key, used by wolfSSL */
    ret = wc_ecc_import_unsigned(key, qx, qy, NULL, ECC_SECP256R1);

exit:

#ifdef WOLFSSL_ATECC508A_DEBUG
    if (ret != 0) {
        printf("atcatls_create_key_cb: ret %d\n", ret);
    }
#endif

    return ret;
}

int atcatls_create_pms_cb(WOLFSSL* ssl, ecc_key* otherKey,
        unsigned char* pubKeyDer, unsigned int* pubKeySz,
        unsigned char* out, unsigned int* outlen,
        int side, void* ctx)
{
    int ret;
    ecc_key tmpKey;
    uint8_t  peerKeyBuf[ATECC_PUBKEY_SIZE];
    uint8_t* peerKey = peerKeyBuf;
    uint8_t* qx = &peerKey[0];
    uint8_t* qy = &peerKey[ATECC_PUBKEY_SIZE/2];
    word32 qxLen = ATECC_PUBKEY_SIZE/2, qyLen = ATECC_PUBKEY_SIZE/2;

    if (pubKeyDer == NULL || pubKeySz == NULL || out == NULL || outlen == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)ssl;
    (void)ctx;
    (void)otherKey;

    ret = wc_ecc_init(&tmpKey);
    if (ret != 0) {
        return ret;
    }

    XMEMSET(peerKey, 0, ATECC_PUBKEY_SIZE);

    /* for client: create and export public key */
    if (side == WOLFSSL_CLIENT_END) {
        /* generate new ephemeral key on device */
        ret = atcatls_create_key(TLS_SLOT_ECDHE_PRIV, peerKey);
        if (ret != ATCA_SUCCESS) {
            ret = WC_HW_E; goto exit;
        }

        /* convert raw unsigned public key to X.963 format for TLS */
        ret = wc_ecc_import_unsigned(&tmpKey, qx, qy, NULL, ECC_SECP256R1);
        if (ret == 0) {
            ret = wc_ecc_export_x963(&tmpKey, pubKeyDer, pubKeySz);
        }
    }

    /* for server: import public key */
    else if (side == WOLFSSL_SERVER_END) {
        /* import peer's key and export as raw unsigned for hardware */
        ret = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, &tmpKey, ECC_SECP256R1);
        if (ret == 0) {
            ret = wc_ecc_export_public_raw(&tmpKey, qx, &qxLen, qy, &qyLen);
        }
        (void)qxLen;
        (void)qyLen;
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    if (ret != 0) {
        goto exit;
    }

#if 1
    ret = atcatls_ecdh(TLS_SLOT_ECDHE_PRIV, peerKey, out);
#else
    /* other syntax for encrypted ECDH using key in another slot */
    ret = atcatls_ecdh_enc(TLS_SLOT_ECDHE_PRIV, TLS_SLOT_FEATURE_PRIV,
        peerKey, out);
#endif
    if (ret != ATCA_SUCCESS) {
        ret = WC_HW_E;
    }
    *outlen = ATECC_SIG_SIZE;

exit:
    wc_ecc_free(&tmpKey);

#ifdef WOLFSSL_ATECC508A_DEBUG
    if (ret != 0) {
        printf("atcatls_create_pms_cb: ret %d\n", ret);
    }
#endif

    return ret;
}


/**
 * \brief Sign received digest so far for private key to be proved.
 */
int atcatls_sign_certificate_cb(WOLFSSL* ssl, const byte* in, word32 inSz,
    byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
    int ret;
    byte sigRs[ATECC_SIG_SIZE*2];

    (void)ssl;
    (void)inSz;
    (void)key;
    (void)keySz;
    (void)ctx;

    if (in == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = atcatls_sign(TLS_SLOT_AUTH_PRIV, in, sigRs);
    if (ret != ATCA_SUCCESS) {
        ret = WC_HW_E; goto exit;
    }

    /* Encode with ECDSA signature */
    ret = wc_ecc_rs_raw_to_sig(
        &sigRs[0], ATECC_SIG_SIZE,
        &sigRs[ATECC_SIG_SIZE], ATECC_SIG_SIZE,
        out, outSz);
    if (ret != 0) {
        goto exit;
    }

exit:

#ifdef WOLFSSL_ATECC508A_DEBUG
    if (ret != 0) {
        printf("atcatls_sign_certificate_cb: ret %d\n", ret);
    }
#endif

    return ret;
}

/**
 * \brief Verify signature received from peers to prove peer's private key.
 */
int atcatls_verify_signature_cb(WOLFSSL* ssl, const byte* sig, word32 sigSz,
    const byte* hash, word32 hashSz, const byte* key, word32 keySz, int* result,
    void* ctx)
{
    int ret;
    ecc_key tmpKey;
    word32 idx = 0;
    uint8_t peerKey[ATECC_PUBKEY_SIZE];
    uint8_t* qx = &peerKey[0];
    uint8_t* qy = &peerKey[ATECC_PUBKEY_SIZE/2];
    word32 qxLen = ATECC_PUBKEY_SIZE/2, qyLen = ATECC_PUBKEY_SIZE/2;
    byte sigRs[ATECC_SIG_SIZE*2];
    word32 rSz = ATECC_SIG_SIZE;
    word32 sSz = ATECC_SIG_SIZE;

    (void)sigSz;
    (void)hashSz;
    (void)ctx;

    if (ssl == NULL || key == NULL || sig == NULL || hash == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }

    /* import public key and export public as unsigned bin for hardware */
    ret = wc_ecc_init(&tmpKey);
    if (ret == 0) {
        ret = wc_EccPublicKeyDecode(key, &idx, &tmpKey, keySz);
        if (ret == 0) {
            ret = wc_ecc_export_public_raw(&tmpKey, qx, &qxLen, qy, &qyLen);
        }
        wc_ecc_free(&tmpKey);

        (void)qxLen;
        (void)qyLen;
    }
    if (ret != 0) {
        goto exit;
    }

    /* decode the ECDSA signature */
    ret = wc_ecc_sig_to_rs(sig, sigSz,
        &sigRs[0], &rSz,
        &sigRs[ATECC_SIG_SIZE], &sSz);
    if (ret != 0) {
        goto exit;
    }
    (void)rSz;
    (void)sSz;

    ret = atcatls_verify(hash, sigRs, peerKey, (bool*)result);
    if (ret != ATCA_SUCCESS || !*result) {
        ret = WC_HW_E; goto exit;
    }

    ret = 0; /* success */

exit:

#ifdef WOLFSSL_ATECC508A_DEBUG
    if (ret != 0) {
        printf("atcatls_verify_signature_cb: ret %d\n", ret);
    }
#endif

    return ret;
}

#endif /* HAVE_PK_CALLBACKS */

#endif /* WOLFSSL_ATMEL || WOLFSSL_ATECC508A */