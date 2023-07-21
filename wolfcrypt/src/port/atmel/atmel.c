/* atmel.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/*
 * WOLFSSL_MANUALLY_SELECT_DEVICE_CONFIG             default: off (not defined)
          You can define this in a user_settings.h file to specify your custom
          configuration of a device
 * WOLFSSL_ATCA_DEVICE_NO      use first device in the list     default: 0
 */

#if defined(WOLFSSL_ATMEL) || defined(WOLFSSL_ATECC508A) || \
    defined(WOLFSSL_ATECC608A) || defined(WOLFSSL_ATECC_PKCB) || \
    defined(WOLFSSL_MICROCHIP_TA100)

#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#ifdef WOLFSSL_ATECC_TNGTLS
#include "tng/tng_atcacert_client.h"
#endif

#ifdef WOLFSSL_ATECC_TFLXTLS
#include "atcacert/atcacert_client.h"
#include "tng/cust_def_device.h"
#include "tng/cust_def_signer.h"
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_ATMEL
/* remap name conflicts */
#define Aes Aes_Remap
#define Gmac Gmac_Remap
#include "asf.h"
#undef Aes
#undef Gmac
#endif /* WOLFSSL_ATMEL */

#include <wolfssl/wolfcrypt/port/atmel/atmel.h>

#if defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC608A) || \
    defined(WOLFSSL_MICROCHIP_TA100)

#ifdef WOLFSSL_ATECC508A_TLS
    extern ATCA_STATUS device_init_default(void);
#endif

static int mAtcaInitDone = 0;

/* ATECC slotId handling */
static atmel_slot_alloc_cb mSlotAlloc;
static atmel_slot_dealloc_cb mSlotDealloc;
static byte mSlotList[ATECC_MAX_SLOT];
#ifndef SINGLE_THREADED
static wolfSSL_Mutex mSlotMutex;
#endif

/* Raspberry Pi uses /dev/i2c-1 */
#ifndef ATECC_I2C_ADDR
    #ifdef WOLFSSL_ATECC_TNGTLS
        #define ATECC_I2C_ADDR 0x6A
    #else
        #define ATECC_I2C_ADDR 0xC0
    #endif
#endif
#ifndef ATECC_I2C_BUS
#define ATECC_I2C_BUS  1
#endif
#ifdef ATECC_DEV_TYPE /* for backward compatibility */
    #define MICROCHIP_DEV_TYPE ATECC_DEV_TYPE
#endif
#ifndef MICROCHIP_DEV_TYPE
    #ifdef WOLFSSL_ATECC508A
        #define MICROCHIP_DEV_TYPE ATECC508A
    #elif defined(WOLFSSL_ATECC608A)
        #define MICROCHIP_DEV_TYPE ATECC608A
    #elif defined(WOLFSSL_MICROCHIP_TA100)
        #define MICROCHIP_DEV_TYPE TA100
    #endif
#endif
static int ateccx08a_cfg_initialized = 0;

#if defined(WOLFSSL_ATECC608A) && defined(MICROCHIP_MPLAB_HARMONY_3)
    /* Harmony3 will generate configuration based on user inputs */
    extern ATCAIfaceCfg atecc608_0_init_data;
#endif

#ifndef WOLFSSL_ATCA_DEVICE_NO
    /* Default to first device in the list*/
    #define WOLFSSL_ATCA_DEVICE_NO 0
#endif
    static ATCAIfaceCfg config_atmel_device[]  = {
    /* Enable and Select user configuration of device and parameters. */
#if defined(WOLFSSL_MANUALLY_SELECT_DEVICE_CONFIG)
     WOLFSSL_MANUALLY_SELECT_DEVICE_CONFIG,
    /* Try detecting all available device configs */
#elif defined(WOLFSSL_ATECC608A) && defined(MICROCHIP_MPLAB_HARMONY_3)
    atecc608_0_init_data,
#endif
#ifdef ATCA_HAL_SPI
    {
        .iface_type = ATCA_SPI_IFACE,
        .devtype    = MICROCHIP_DEV_TYPE,
        .atcaspi = {
            .bus = 0,
            .select_pin = 0,
            .baud = 16000000,
        },
        .wake_delay = 1500,
        .rx_retries = 20,
    },
#endif
#ifdef ATCA_HAL_I2C
    {
        .iface_type = ATCA_I2C_IFACE,
        .devtype    = MICROCHIP_DEV_TYPE,
        .atcai2c = {
            #ifdef ATCA_ENABLE_DEPRECATED
                .slave_addressus = 1,
            #else
                .address = ATECC_I2C_ADDR,
            #endif
            .baud = 400000,
        },
        .wake_delay = 1500,
        .rx_retries = 20,
    },
#endif
};
static ATCAIfaceCfg* gCfg = &config_atmel_device[WOLFSSL_ATCA_DEVICE_NO];

#if defined(WOLFSSL_MICROCHIP_TA100)
    #ifndef SHARED_DATA_ADDR
        #define SHARED_DATA_ADDR 0x8006
    #endif
        #define MAP_TO_HANDLE(value) (SHARED_DATA_ADDR + (value))
#else
    #define MAP_TO_HANDLE(value) value
#endif

#if defined(WOLFSSL_MICROCHIP_TA100)
/*
TA_ElementAttributes contains data element attributes of the handle
which is of 8 byte

typedef struct
{
    uint8_t  element_CKA;     //!< contains class, key_type & Algorithm mode
    uint16_t property;        //!< properties of the element
    uint8_t  usage_key;       //!< usage key
    uint8_t  write_key;       //!< write key
    uint8_t  read_key;        //!< read key
    uint8_t  permission;      //!< permission of the element usage|write|read|
                              //delete perm
    uint8_t  byte7_settings;  //!< Byte 7 attributes use_count|exportable|
                              // lockable|access_limit
} ATCA_PACKED ta_element_attributes_t;

See Shared Data Element Attributes in the programming specifications
*/
static ta_element_attributes_t sharedData_attr[ATECC_MAX_SLOT] = {
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
    {0x81, 0x1600, 0x00, 0x00, 0x00, 0x41, 0x10},
};
static ta_element_attributes_t* gSharedDataAttr = sharedData_attr;

#endif /* WOLFSSL_MICROCHIP_TA100 */
#endif /* WOLFSSL_ATECC508A */

/**
 * \brief Generate random number to be used for hash.
 */
int atmel_get_random_number(uint32_t count, uint8_t* rand_out)
{
    int ret = 0;
#if defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC608A) || \
    defined(WOLFSSL_MICROCHIP_TA100)
    uint8_t i = 0;
    uint32_t copy_count = 0;
    uint8_t rng_buffer[RANDOM_NUM_SIZE];

    if (rand_out == NULL) {
        return -1;
    }

    while (i < count) {
        ret = atcab_random(rng_buffer);
        if (ret != ATCA_SUCCESS) {
            WOLFSSL_MSG("Failed to create random number!");
            return -1;
        }
        copy_count =
                (count - i > RANDOM_NUM_SIZE) ? RANDOM_NUM_SIZE : count - i;
        XMEMCPY(&rand_out[i], rng_buffer, copy_count);
        i += copy_count;
    }
#ifdef ATCAPRINTF
    atcab_printbin_label((const char*)"\r\nRandom Number", rand_out, count);
#endif
#else
    /* TODO: Use on-board TRNG */
#endif
    return ret;
}

int atmel_get_random_block(unsigned char* output, unsigned int sz)
{
	return atmel_get_random_number((uint32_t)sz, (uint8_t*)output);
}

#if defined(WOLFSSL_ATMEL) && defined(WOLFSSL_ATMEL_TIME)
#include "asf.h"
#include "rtc_calendar.h"
extern struct rtc_module *_rtc_instance[RTC_INST_NUM];

long atmel_get_curr_time_and_date(long* tm)
{
    long rt = 0;

	/* Get current time */
    struct rtc_calendar_time rtcTime;
    const int monthDay[] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int month, year, yearLeap;

	rtc_calendar_get_time(_rtc_instance[0], &rtcTime);

    /* Convert rtc_calendar_time to seconds since UTC */
    month = rtcTime.month % 12;
    year =  rtcTime.year + rtcTime.month / 12;
    if (month < 0) {
        month += 12;
        year--;
    }
    yearLeap = (month > 1) ? year + 1 : year;
    rt = rtcTime.second
        + 60 * (rtcTime.minute
            + 60 * (rtcTime.hour
            + 24 * (monthDay[month] + rtcTime.day - 1
                + 365 * (year - 70)
                + (yearLeap - 69) / 4
                - (yearLeap - 1) / 100
                + (yearLeap + 299) / 400
                )
            )
        );

    (void)tm;
    return rt;
}
#endif

#if defined(WOLFSSL_MICROCHIP_TA100)
/* Set the Shared Data configuration for wolfSSL to use.
 *
 * Return 0 on success, negative upon error */
int wc_Microchip_SetSharedDataConfig(ta_element_attributes_t* cfg)
{
    WOLFSSL_MSG("Setting Shared Data configuration");
    if (cfg == NULL) {
        return -1;
    }
    /* copy configuration into our local struct */
    (void)XMEMMOVE(gSharedDataAttr, cfg,
                   sizeof(ta_element_attributes_t)*ATECC_MAX_SLOT);

    ateccx08a_cfg_initialized = 0;

    return 0;
}

#endif
#if defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC608A) || \
    defined(WOLFSSL_MICROCHIP_TA100)

/* Set the ATECC configuration for wolfSSL to use.
 *
 * Return 0 on success, negative upon error */
int wolfCrypt_ATECC_SetConfig(ATCAIfaceCfg* cfg)
{
    WOLFSSL_MSG("Setting ATECC ATCAIfaceCfg configuration");
    if (cfg == NULL) {
        return -1;
    }
    /* copy configuration into our local struct */
    (void)XMEMMOVE(gCfg, cfg, sizeof(ATCAIfaceCfg));

    ateccx08a_cfg_initialized = 0;

    return 0;
}

int atmel_ecc_translate_err(int status)
{
    switch (status) {
        case ATCA_SUCCESS:
            return 0;
        case ATCA_BAD_PARAM:
            return BAD_FUNC_ARG;
        case ATCA_ALLOC_FAILURE:
            return MEMORY_E;
        default:
        #ifdef WOLFSSL_ATECC_DEBUG
            printf("ATECC Failure: %x\n", (word32)status);
        #endif
            break;
    }
    return WC_HW_E;
}

/* Function to set the slotId allocator and deallocator */
int atmel_set_slot_allocator(atmel_slot_alloc_cb alloc,
                             atmel_slot_dealloc_cb dealloc)
{
#ifndef SINGLE_THREADED
    wc_LockMutex(&mSlotMutex);
#endif
    mSlotAlloc = alloc;
    mSlotDealloc = dealloc;
#ifndef SINGLE_THREADED
    wc_UnLockMutex(&mSlotMutex);
#endif
    return 0;
}

/* Function to allocate new slotId number */
int atmel_ecc_alloc(int slotType)
{
    int slotId = ATECC_INVALID_SLOT, i;

#ifndef SINGLE_THREADED
    wc_LockMutex(&mSlotMutex);
#endif

    if (mSlotAlloc) {
        slotId = mSlotAlloc(slotType);
    }
    else {
        switch (slotType) {
            case ATMEL_SLOT_ENCKEY:
                /* not reserved in mSlotList, so return */
                slotId = ATECC_SLOT_I2C_ENC;
                goto exit;
            case ATMEL_SLOT_DEVICE:
                /* not reserved in mSlotList, so return */
                slotId = ATECC_SLOT_AUTH_PRIV;
                goto exit;
            case ATMEL_SLOT_ECDHE:
                slotId = ATECC_SLOT_ECDHE_PRIV;
            #ifdef WOLFSSL_ATECC_TNGTLS
                /* not reserved in mSlotList, so return */
                goto exit;
            #else
                break;
            #endif
            case ATMEL_SLOT_ECDHE_ENC:
                slotId = ATECC_SLOT_ENC_PARENT;
            #ifdef WOLFSSL_ATECC_TNGTLS
                /* not reserved in mSlotList, so return */
                goto exit;
            #else
                break;
            #endif
            case ATMEL_SLOT_ECDHE_ALICE:
                /* not reserved in mSlotList, so return */
                slotId = ATECC_SLOT_ECDHE_PRIV_ALICE;
                goto exit;
            case ATMEL_SLOT_ECDHE_BOB:
                /* not reserved in mSlotList, so return */
                slotId = ATECC_SLOT_ECDHE_PRIV_BOB;
                goto exit;
            case ATMEL_SLOT_ANY:
                for (i=0; i < ATECC_MAX_SLOT; i++) {
                    /* Find free slotId */
                    if (mSlotList[i] == ATECC_INVALID_SLOT) {
                        slotId = i;
                        break;
                    }
                }
                break;
        }

        /* is slot available */
        if (mSlotList[slotId] != ATECC_INVALID_SLOT &&
            mSlotList[slotId] != slotId ) {
            slotId = ATECC_INVALID_SLOT;
        }
        else {
            mSlotList[slotId] = slotId;
        }
    }

exit:
#ifndef SINGLE_THREADED
    wc_UnLockMutex(&mSlotMutex);
#endif

    return slotId;
}


/* Function to return slotId number to available list */
void atmel_ecc_free(int slotId)
{
#ifndef SINGLE_THREADED
    wc_LockMutex(&mSlotMutex);
#endif
    if (mSlotDealloc) {
        mSlotDealloc(slotId);
    }
    else if (slotId >= 0 && slotId < ATECC_MAX_SLOT) {
        if (slotId != ATECC_SLOT_AUTH_PRIV && slotId != ATECC_SLOT_I2C_ENC
#ifdef WOLFSSL_ATECC_TNGTLS
            && slotId != ATMEL_SLOT_ECDHE_ENC
#endif
           ) {
            /* Mark slotId free */
            mSlotList[slotId] = ATECC_INVALID_SLOT;
        }
    }
#ifndef SINGLE_THREADED
    wc_UnLockMutex(&mSlotMutex);
#endif
}


/**
 * \brief Callback function for getting the current encryption key
 */
int atmel_get_enc_key_default(byte* enckey, word16 keysize)
{
    if (enckey == NULL || keysize != ATECC_KEY_SIZE) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(enckey, 0xFF, keysize); /* use default value */

    return 0;
}

/**
 * \brief Write enc key before.
 */
#if defined(WOLFSSL_ATECC_ECDH_ENC) || defined(WOLFSSL_ATECC_ECDH_IOENC)
static int atmel_init_enc_key(void)
{
    int ret;
	uint8_t read_key[ATECC_KEY_SIZE];
    uint8_t writeBlock = 0;
    uint8_t writeOffset = 0;
    int slotId;
    bool isLocked = false;

    slotId = atmel_ecc_alloc(ATMEL_SLOT_ENCKEY);

    /* check for encryption key slotId */
    if (slotId == ATECC_INVALID_SLOT)
        return BAD_FUNC_ARG;

    /* skip if slot has already been locked */
    ret = atcab_is_slot_locked(slotId, &isLocked);
    if (ret != ATCA_SUCCESS) {
        return atmel_ecc_translate_err(ret);

    } else if (isLocked) {
        return 0;
    }

    /* get encryption key */
    ATECC_GET_ENC_KEY(read_key, sizeof(read_key));

    ret = atcab_write_zone(ATCA_ZONE_DATA, slotId, writeBlock, writeOffset,
        read_key, ATCA_BLOCK_SIZE);
    ForceZero(read_key, sizeof(read_key));
    ret = atmel_ecc_translate_err(ret);

	return ret;
}
#endif

int atmel_get_rev_info(word32* revision)
{
    int ret;
    ret = atcab_info((uint8_t*)revision);
    ret = atmel_ecc_translate_err(ret);
    return ret;
}

void atmel_show_rev_info(void)
{
#ifdef WOLFSSL_ATECC_DEBUG
    word32 revision = 0;
    atmel_get_rev_info(&revision);
    printf("ATECC608 Revision: %x\n", (word32)revision);
#endif
}

#ifdef HAVE_ECC
int atmel_ecc_create_pms(int slotId, const uint8_t* peerKey, uint8_t* pms)
{
    int ret;
    uint8_t read_key[ATECC_KEY_SIZE];

#ifdef WOLFSSL_ATECC_ECDH_ENC
    int slotIdEnc;

    slotIdEnc = atmel_ecc_alloc(ATMEL_SLOT_ECDHE_ENC);
    if (slotIdEnc == ATECC_INVALID_SLOT)
        return BAD_FUNC_ARG;
#endif

    /* get encryption key */
    ATECC_GET_ENC_KEY(read_key, sizeof(read_key));

#ifdef WOLFSSL_ATECC_ECDH_ENC
    #ifdef WOLFSSL_MICROCHIP_TA100
        (void)slotId;
        ret = talib_ecdh_compat(atcab_get_device(), MAP_TO_HANDLE(slotIdEnc),
                                peerKey, pms);
    #else
        /* send the encrypted version of the ECDH command */
        ret = atcab_ecdh_enc(MAP_TO_HANDLE(slotId), peerKey, pms, read_key,
                                           MAP_TO_HANDLE(slotIdEnc));
    #endif
#elif defined(WOLFSSL_ATECC_ECDH_IOENC)
    /* encrypted ECDH command, using I/O protection key */
    ret = atcab_ecdh_ioenc(MAP_TO_HANDLE(slotId), peerKey, pms, read_key);
#else
    ret = atcab_ecdh(MAP_TO_HANDLE(slotId), peerKey, pms);
#endif

    ret = atmel_ecc_translate_err(ret);
    ForceZero(read_key, sizeof(read_key));
#ifdef WOLFSSL_ATECC_ECDH_ENC
    /* free the ECDHE slot */
    atmel_ecc_free(slotIdEnc);
#endif
    return ret;
}
#ifdef WOLFSSL_MICROCHIP_TA100
static uint8_t getCurveType(int curve_id)
{
    switch(curve_id)
    {
        case ECC_SECP256R1: return TA_KEY_TYPE_ECCP256;
        case ECC_SECP224R1: return TA_KEY_TYPE_ECCP224;
        case ECC_SECP384R1: return TA_KEY_TYPE_ECCP384;
        case ECC_SECP256K1: return TA_KEY_TYPE_SECP256K1;
        case ECC_BRAINPOOLP256R1: return TA_KEY_TYPE_ECCBP256R1;
        case ECC_CURVE_DEF: return TA_KEY_TYPE_ECCP256; /* default */
        default: WOLFSSL_MSG("Curve not identified");
            return MICROCHIP_INVALID_ECC;
    }
}
#endif /* WOLFSSL_MICROCHIP_TA100 */
int atmel_ecc_create_key(int slotId, int curve_id, byte* peerKey)
{
    int ret;
#ifndef WOLFSSL_MICROCHIP_TA100
    (void)curve_id;
#endif
    /* verify provided slotId */
    if (slotId == ATECC_INVALID_SLOT) {
        return WC_HW_WAIT_E;
    }
#ifdef WOLFSSL_MICROCHIP_TA100

    if (getCurveType(curve_id) == MICROCHIP_INVALID_ECC)
        return NOT_COMPILED_IN;

#endif
    /* generate new ephemeral key on device */
    ret = atcab_genkey(MAP_TO_HANDLE(slotId), peerKey);
    ret = atmel_ecc_translate_err(ret);
    return ret;
}

int atmel_ecc_sign(int slotId, const byte* message, byte* signature)
{
    int ret;

    ret = atcab_sign(MAP_TO_HANDLE(slotId), message, signature);
    ret = atmel_ecc_translate_err(ret);
    return ret;
}

int atmel_ecc_verify(const byte* message, const byte* signature,
    const byte* pubkey, int* pVerified)
{
    int ret;
    bool verified = false;

    ret = atcab_verify_extern(message, signature, pubkey, &verified);
    ret = atmel_ecc_translate_err(ret);
    if (pVerified)
        *pVerified = (int)verified;
    return ret;
}

#endif /* HAVE_ECC */
#endif /* WOLFSSL_ATECC508A || WOLFSSL_ATECC608A || WOLFSSL_MICROCHIP_TA100 */

#ifdef WOLFSSL_MICROCHIP_TA100

#ifndef NO_RSA
int wc_Microchip_rsa_create_key(struct RsaKey* key, int size, long e)
{
    ATCA_STATUS ret;
    ta_element_attributes_t rKeyA, uKeyA;
    size_t uKey_len = WOLFSSL_TA_KEY_TYPE_RSA_SIZE;

    (void)size;
    (void)e;

    ret = talib_handle_init_private_key(&rKeyA, WOLFSSL_TA_KEY_TYPE_RSA,
            TA_ALG_MODE_RSA_SSA_PSS,TA_PROP_SIGN_INT_EXT_DIGEST,
            TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    if (ret != ATCA_SUCCESS) return WC_HW_E;

    ret = talib_create_element(atcab_get_device(), &rKeyA, &key->rKeyH);
    if (ret != ATCA_SUCCESS) return WC_HW_E;

    ret = talib_handle_init_public_key(&uKeyA, WOLFSSL_TA_KEY_TYPE_RSA,
            TA_ALG_MODE_RSA_SSA_PSS, TA_PROP_VAL_NO_SECURE_BOOT_SIGN,
            TA_PROP_ROOT_PUB_KEY_VERIFY);
    if (ret != ATCA_SUCCESS) return WC_HW_E;

    ret = talib_create_element(atcab_get_device(), &uKeyA, &key->uKeyH);
    if (ret != ATCA_SUCCESS) return WC_HW_E;

    ret = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY,
            (uint32_t)key->rKeyH, key->uKey, &uKey_len);
    if (ret != ATCA_SUCCESS) return WC_HW_E;

    /* Write the RSA public key to the handle. */
    ret = talib_write_pub_key(atcab_get_device(), key->uKeyH, (uint16_t)uKey_len,
            key->uKey);

    ret = atmel_ecc_translate_err(ret);

    return ret;

}
int wc_Microchip_rsa_sign(const byte* in, word32 inLen, byte* out, word32 outLen,
                       RsaKey* key)
{
    int ret;
    uint16_t sign_size = outLen; /* WOLFSSL_TA_KEY_TYPE_RSA_SIZE */
    byte hash_data[WC_SHA256_DIGEST_SIZE];

    if ((ret = wc_Sha256Hash(in, inLen, hash_data)) != 0) {
       return ret;
    }

    ret = talib_sign_external(atcab_get_device(), WOLFSSL_TA_KEY_TYPE_RSA,
                              key->rKeyH, TA_HANDLE_INPUT_BUFFER, hash_data,
                              WC_SHA256_DIGEST_SIZE, out, &sign_size);
    ret = atmel_ecc_translate_err(ret);
    return ret;
}

int wc_Microchip_rsa_verify(const byte* in, word32 inLen, byte* sig, word32 sigLen,
                     RsaKey* key, int* pVerified)
{
    int ret;
    bool verified = false;
    byte hash_data[WC_SHA256_DIGEST_SIZE];

    if ((ret = wc_Sha256Hash(in, inLen, hash_data)) != 0) {
       return ret;
    }
    ret = talib_verify(atcab_get_device(), WOLFSSL_TA_KEY_TYPE_RSA,
                        TA_HANDLE_INPUT_BUFFER, key->uKeyH, sig,
                        sigLen, hash_data, WC_SHA256_DIGEST_SIZE, NULL,
                        sigLen, &verified);

    ret = atmel_ecc_translate_err(ret);
    if (pVerified)
        *pVerified = (int)verified;

    return ret;
}

int wc_Microchip_rsa_encrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                       RsaKey* key)
{
    int ret;

    /* Encrypt the plaintext with the rsa public key in handle */
    ret = talib_rsaenc_encrypt(atcab_get_device(), key->uKeyH,
                               inLen, in, outLen, out);
    ret = atmel_ecc_translate_err(ret);
    return ret;
}

int wc_Microchip_rsa_decrypt(const byte* in, word32 inLen, byte* out,
                          word32 outLen, RsaKey* key)
{
    int ret;
    /* Decrypt the ciphertext with the rsa private key in handle */
    ret = talib_rsaenc_decrypt(atcab_get_device(), key->rKeyH,
                             inLen, in, outLen, out);
    ret = atmel_ecc_translate_err(ret);
    return ret;
}

void wc_Microchip_rsa_free(struct RsaKey* key)
{
    if (key->rKeyH)
        (void)talib_delete_handle(atcab_get_device(), (uint32_t)key->rKeyH);
    if (key->uKeyH)
        (void)talib_delete_handle(atcab_get_device(), (uint32_t)key->uKeyH);

}
#endif /* NO_RSA */

#ifdef WOLFSSL_ATECC_DEBUG
static void atmel_print_info(ta_element_attributes_t attr)
{
    printf("{0x%02x, 0x%04x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x},\n",
            attr.element_CKA, attr.property, attr.usage_key, attr.write_key,
            attr.read_key, attr.permission , attr.byte7_settings);
}

static void atmel_Handle_Attributes(void)
{
    ATCA_STATUS status;
    ta_element_attributes_t attributes;
    (void) status;

    printf("Symmetric key AES \n"
           "Symmetric key HMAC \n"
           "Public key ECC \n"
           "Public key RSA \n"
           "Private key ECC - sign \n"
           "Private key ECC - keygen \n");
    status = talib_handle_init_symmetric_key(&attributes, TA_KEY_TYPE_AES128,
                                             TA_PROP_SYMM_KEY_USAGE_ANY);

    /* Symmetric key AES */
    atmel_print_info(attributes);

    status = talib_handle_init_symmetric_key(&attributes, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_MAC);
    /* Symmetric key HMAC */
    atmel_print_info(attributes);

    status = talib_handle_init_public_key(&attributes, TA_KEY_TYPE_ECCP256,
                       TA_ALG_MODE_ECC_ECDSA, TA_PROP_VAL_NO_SECURE_BOOT_SIGN,
                       TA_PROP_ROOT_PUB_KEY_VERIFY);

    /* Public key ECC */
    atmel_print_info(attributes);

    status = talib_handle_init_public_key(&attributes, WOLFSSL_TA_KEY_TYPE_RSA,
                    TA_ALG_MODE_RSA_SSA_PSS, TA_PROP_VAL_NO_SECURE_BOOT_SIGN,
                    TA_PROP_ROOT_PUB_KEY_VERIFY);
    /* Public key RSA */
    atmel_print_info(attributes);

    status = talib_handle_init_private_key(&attributes, TA_KEY_TYPE_ECCP256,
                              TA_ALG_MODE_ECC_ECDH, TA_PROP_SIGN_INT_EXT_DIGEST,
                              TA_PROP_KEY_AGREEMENT_OUT_BUFF);

    /* Private key ECC - sign */
    atmel_print_info(attributes);

    /* Byte 0 Element Attribute */
    attributes.element_CKA = TA_CLASS_PRIVATE_KEY |
            (uint8_t)(TA_KEY_TYPE_ECCP256 << TA_HANDLE_INFO_KEY_TYPE_SHIFT) |
            (uint8_t)(TA_ALG_MODE_ECC_ECDSA << TA_HANDLE_INFO_ALG_MODE_SHIFT);

    attributes.property = (uint16_t)0x00 /*Public Key Handle*/ |
            (uint16_t)(0x00 << TA_PROP_SESSION_KEY_SHIFT) |
    (uint16_t)(0x00 << TA_PROP_KEY_GEN_SHIFT) |
    (uint16_t)(TA_PROP_SIGN_INT_EXT_DIGEST << TA_PROP_SIGN_USE_SHIFT) |
    (uint16_t)(TA_PROP_NO_KEY_AGREEMENT << TA_PROP_KEY_AGREEMENT_SHIFT);

    /* Byte 3 Element Attribute */
    attributes.usage_key = 0x00;

    /* Byte 4 Element Attribute */
    attributes.write_key = 0x00;

    /* Byte 5 Element Attribute */
    attributes.read_key = 0x00;

    /* Byte 6 Element Attribute */
    attributes.permission = TA_PERM_USAGE(TA_PERM_ALWAYS) |
            TA_PERM_WRITE(TA_PERM_ALWAYS)| TA_PERM_READ(TA_PERM_ALWAYS) |
            TA_PERM_DELETE(TA_PERM_ALWAYS);

    /* Byte 7  Element Attribute */
    attributes.byte7_settings = ((0x00 & 0x03) << 0) /*Use Count*/ |
        TA_NOT_EXPORTABLE_FROM_CHIP_MASK | TA_PERMANENTLY_NOT_LOCKABLE_MASK |
    TA_ACCESS_LIMIT_ALWAYS_MASK | (0 << 7) /*Intrusion Detection (N/A here)*/;

     /* Private key ECC - keygen */
    atmel_print_info(attributes);

}
#endif

#define CHECK_STATUS(s)                                                        \
    if (s != ATCA_SUCCESS)                                                     \
    {                                                                          \
        printf("Error: Line %d in File %s\r\n", __LINE__, __FILE__);           \
        printf("STATUS = %X\r\n", s);                                          \
        printf("See atca_status.h for error code \r\n");                       \
        return atmel_ecc_translate_err(s);                                     \
    }
static int atmel_createHandles(void)
{
    ATCA_STATUS status;
    uint8_t is_handle_valid = 0;
    uint16_t shared_handle = SHARED_DATA_ADDR;
    int i;
#ifdef WOLFSSL_ATECC_DEBUG
    atmel_Handle_Attributes();
    printf("atmel_Handle_Attributes() finished \n\n");
#endif
    for (i = 0; i < ATECC_MAX_SLOT; i++ ) {

        status = talib_is_handle_valid(atcab_get_device(),
                                 (uint32_t)shared_handle, &is_handle_valid);
        CHECK_STATUS(status);
#ifdef WOLFSSL_ATECC_DEBUG
        atmel_print_info(gSharedDataAttr[i]);
#endif
        if(is_handle_valid == 0x01) {
            /* Handle already Exists */;
#ifndef WOLFSSL_NO_DEL_HANDLE
            status = talib_delete_handle(atcab_get_device(),
                                    (uint32_t)shared_handle);
            CHECK_STATUS(status);
#else
            shared_handle += 1;
            continue;
#endif
        }

        status = talib_create_element_with_handle(atcab_get_device(),
                shared_handle, &gSharedDataAttr[i]);
        CHECK_STATUS(status);
        shared_handle += 1;
    }
    return 0;
}
#endif /* WOLFSSL_MICROCHIP_TA100 */

int atmel_init(void)
{
    int ret = 0;

#if defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC608A) || \
    defined(WOLFSSL_MICROCHIP_TA100)

    if (!mAtcaInitDone) {
        ATCA_STATUS status;
        int i;

    #ifndef SINGLE_THREADED
        wc_InitMutex(&mSlotMutex);
    #endif

        /* Init the free slotId list */
        for (i=0; i<ATECC_MAX_SLOT; i++) {
            if (i == ATECC_SLOT_AUTH_PRIV || i == ATECC_SLOT_I2C_ENC
        #ifdef WOLFSSL_ATECC_TNGTLS
                || i == ATECC_SLOT_ENC_PARENT
        #endif
               ) {
                mSlotList[i] = i;
            }
            else {
                /* ECC Slots (mark avail) */
                mSlotList[i] = ATECC_INVALID_SLOT;
            }
        }
#ifdef MICROCHIP_MPLAB_HARMONY_3
        atcab_release();
        atcab_wakeup();
#endif
        if (ateccx08a_cfg_initialized == 0) {
            /* Setup the hardware interface using defaults */
            status = atcab_init(gCfg);
            /* Initialize the CryptoAuthLib to communicate with */
            if (status != ATCA_SUCCESS) {
                WOLFSSL_MSG("Failed to initialize atcab");
                return WC_HW_E;
            }
            #ifdef WOLFSSL_MICROCHIP_TA100
                /* create handles for TA100 */
                atmel_createHandles();
            #endif
        }

        /* show revision information */
        atmel_show_rev_info();

    #ifdef WOLFSSL_ATECC508A_TLS
        /* Configure the ECC508 for use with TLS API functions */
        device_init_default();
    #endif

#if defined(WOLFSSL_ATECC_ECDH_ENC) || defined(WOLFSSL_ATECC_ECDH_IOENC)
        /* Init the I2C pipe encryption key. */
        /* Value is generated/stored during pair for the ATECC508A and stored
            on micro flash */
        /* For this example its a fixed value */
        if (atmel_init_enc_key() != 0) {
            WOLFSSL_MSG("Failed to initialize transport key");
            return WC_HW_E;
        }
#endif

        mAtcaInitDone = 1;
    }
#endif /* WOLFSSL_ATECC508A */
    return ret;
}

void atmel_finish(void)
{
#if defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC608A) || \
    defined(WOLFSSL_MICROCHIP_TA100)
    if (mAtcaInitDone) {
        atcab_release();

    #ifndef SINGLE_THREADED
        wc_FreeMutex(&mSlotMutex);
    #endif

        mAtcaInitDone = 0;
    }
#endif
}


/* Reference PK Callbacks */
#ifdef HAVE_PK_CALLBACKS

/**
 * \brief Used on the server-side only for creating the ephemeral key for ECDH
 */
int atcatls_create_key_cb(WOLFSSL* ssl, ecc_key* key, unsigned int keySz,
    int ecc_curve, void* ctx)
{
    int ret;
    uint8_t peerKey[ATECC_PUBKEY_SIZE];
    uint8_t* qx = &peerKey[0];
    uint8_t* qy = &peerKey[ATECC_PUBKEY_SIZE/2];
    int slotId;

    (void)ssl;
    (void)ctx;

    /* ATECC508A only supports P-256 */
    if (ecc_curve == ECC_SECP256R1) {
        slotId = atmel_ecc_alloc(ATMEL_SLOT_ECDHE);
        if (slotId == ATECC_INVALID_SLOT)
            return WC_HW_WAIT_E;

        /* generate new ephemeral key on device */
        ret = atmel_ecc_create_key(MAP_TO_HANDLE(slotId), ecc_curve, peerKey);

        /* load generated ECC508A public key into key, used by wolfSSL */
        if (ret == 0) {
            ret = wc_ecc_import_unsigned(key, qx, qy, NULL, ECC_SECP256R1);
        }

        if (ret == 0) {
            key->slot = slotId;
        }
        else {
            atmel_ecc_free(slotId);
        #ifdef WOLFSSL_ATECC_DEBUG
            printf("atcatls_create_key_cb: ret %d\n", ret);
        #endif
        }
    }
    else {
    #ifndef WOLFSSL_ATECC508A_NOSOFTECC
        /* use software for non P-256 cases */
        WC_RNG rng;
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_ecc_make_key_ex(&rng, keySz, key, ecc_curve);
            wc_FreeRng(&rng);
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif /* !WOLFSSL_ATECC508A_NOSOFTECC */
    }
    return ret;
}

/**
 * \brief Creates a shared secret using a peer public key and a device key
 */
int atcatls_create_pms_cb(WOLFSSL* ssl, ecc_key* otherKey,
        unsigned char* pubKeyDer, word32* pubKeySz,
        unsigned char* out, word32* outlen,
        int side, void* ctx)
{
    int ret;
    ecc_key tmpKey;
    uint8_t  peerKeyBuf[ATECC_PUBKEY_SIZE];
    uint8_t* peerKey = peerKeyBuf;
    uint8_t* qx = &peerKey[0];
    uint8_t* qy = &peerKey[ATECC_PUBKEY_SIZE/2];
    word32 qxLen = ATECC_PUBKEY_SIZE/2, qyLen = ATECC_PUBKEY_SIZE/2;

    if (pubKeyDer == NULL || pubKeySz == NULL ||
        out == NULL || outlen == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)ssl;
    (void)ctx;
    (void)otherKey;

    ret = wc_ecc_init(&tmpKey);
    if (ret != 0) {
        return ret;
    }

    /* ATECC508A only supports P-256 */
    if (otherKey->dp->id == ECC_SECP256R1) {
        XMEMSET(peerKey, 0, ATECC_PUBKEY_SIZE);

        /* for client: create and export public key */
        if (side == WOLFSSL_CLIENT_END) {
            int slotId = atmel_ecc_alloc(ATMEL_SLOT_ECDHE);
            if (slotId == ATECC_INVALID_SLOT)
                return WC_HW_WAIT_E;
            tmpKey.slot = slotId;

            /* generate new ephemeral key on device */
            ret = atmel_ecc_create_key(MAP_TO_HANDLE(slotId), otherKey->dp->id,
                                                     peerKey);
            if (ret != ATCA_SUCCESS) {
                goto exit;
            }

            /* convert raw unsigned public key to X.963 format for TLS */
            ret = wc_ecc_import_unsigned(&tmpKey, qx, qy, NULL, ECC_SECP256R1);
            if (ret == 0) {
                ret = wc_ecc_export_x963(&tmpKey, pubKeyDer, pubKeySz);
            }

            /* export peer's key as raw unsigned for hardware */
            if (ret == 0) {
                ret = wc_ecc_export_public_raw(otherKey, qx, &qxLen,
                                               qy, &qyLen);
            }
        }

        /* for server: import public key */
        else if (side == WOLFSSL_SERVER_END) {
            tmpKey.slot = otherKey->slot;

            /* import peer's key and export as raw unsigned for hardware */
            ret = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, &tmpKey,
                                        ECC_SECP256R1);
            if (ret == 0) {
                ret = wc_ecc_export_public_raw(&tmpKey, qx, &qxLen, qy, &qyLen);
            }
        }
        else {
            ret = BAD_FUNC_ARG;
        }

        if (ret != 0) {
            goto exit;
        }

        ret = atmel_ecc_create_pms(tmpKey.slot, peerKey, out);
        *outlen = ATECC_KEY_SIZE;

    #if !defined(WOLFSSL_ATECC508A_NOIDLE) && !defined(WOLFSSL_MICROCHIP_TA100)
        /* put chip into idle to prevent watchdog situation on chip */
        atcab_idle();
    #endif

        (void)qxLen;
        (void)qyLen;
    }
    else {
    #ifndef WOLFSSL_ATECC508A_NOSOFTECC
        /* use software for non P-256 cases */
        ecc_key*  privKey = NULL;
        ecc_key*  pubKey = NULL;

        /* for client: create and export public key */
        if (side == WOLFSSL_CLIENT_END)
        {
            WC_RNG rng;
            privKey = &tmpKey;
            pubKey = otherKey;

            ret = wc_InitRng(&rng);
            if (ret == 0) {
                ret = wc_ecc_make_key_ex(&rng, 0, privKey, otherKey->dp->id);
                if (ret == 0) {
                    ret = wc_ecc_export_x963(privKey, pubKeyDer, pubKeySz);
                }
                wc_FreeRng(&rng);
            }
        }
        /* for server: import public key */
        else if (side == WOLFSSL_SERVER_END) {
            privKey = otherKey;
            pubKey = &tmpKey;

            ret = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, pubKey,
                otherKey->dp->id);
        }
        else {
            ret = BAD_FUNC_ARG;
        }

        /* generate shared secret and return it */
        if (ret == 0) {
            ret = wc_ecc_shared_secret(privKey, pubKey, out, outlen);
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif /* !WOLFSSL_ATECC508A_NOSOFTECC */
    }

exit:
    wc_ecc_free(&tmpKey);

#ifdef WOLFSSL_ATECC_DEBUG
    if (ret != 0) {
        printf("atcab_ecdh_enc: ret %d\n", ret);
    }
#endif

    return ret;
}


/**
 * \brief Sign received digest using private key on device
 */
int atcatls_sign_certificate_cb(WOLFSSL* ssl, const byte* in, unsigned int inSz,
    byte* out, word32* outSz, const byte* key, unsigned int keySz, void* ctx)
{
    int ret;
    byte sigRs[ATECC_SIG_SIZE];
    int slotId;

    (void)ssl;
    (void)inSz;
    (void)key;
    (void)keySz;
    (void)ctx;

    if (in == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    slotId = atmel_ecc_alloc(ATMEL_SLOT_DEVICE);
    if (slotId == ATECC_INVALID_SLOT)
        return WC_HW_WAIT_E;

    /* We can only sign with P-256 */
    ret = atmel_ecc_sign(MAP_TO_HANDLE(slotId), in, sigRs);
    if (ret != ATCA_SUCCESS) {
        ret = WC_HW_E; goto exit;
    }

#if !defined(WOLFSSL_ATECC508A_NOIDLE) && !defined(WOLFSSL_MICROCHIP_TA100)
    /* put chip into idle to prevent watchdog situation on chip */
    atcab_idle();
#endif

    /* Encode with ECDSA signature */
    ret = wc_ecc_rs_raw_to_sig(
        &sigRs[0], ATECC_SIG_SIZE/2,
        &sigRs[ATECC_SIG_SIZE/2], ATECC_SIG_SIZE/2,
        out, outSz);
    if (ret != 0) {
        goto exit;
    }

exit:

    atmel_ecc_free(slotId);

#ifdef WOLFSSL_ATECC_DEBUG
    if (ret != 0) {
        printf("atcatls_sign_certificate_cb: ret %d\n", ret);
    }
#endif

    return ret;
}

/**
 * \brief Verify signature received from peers to prove peer's private key.
 */
int atcatls_verify_signature_cb(WOLFSSL* ssl, const byte* sig,
    unsigned int sigSz, const byte* hash, unsigned int hashSz, const byte* key,
    unsigned int keySz, int* result, void* ctx)
{
    int ret;
    ecc_key tmpKey;
    word32 idx = 0;
    uint8_t peerKey[ATECC_PUBKEY_SIZE];
    uint8_t* qx = &peerKey[0];
    uint8_t* qy = &peerKey[ATECC_PUBKEY_SIZE/2];
    word32 qxLen = ATECC_PUBKEY_SIZE/2, qyLen = ATECC_PUBKEY_SIZE/2;
    byte sigRs[ATECC_SIG_SIZE];
    word32 rSz = ATECC_SIG_SIZE/2;
    word32 sSz = ATECC_SIG_SIZE/2;

    (void)sigSz;
    (void)hashSz;
    (void)ctx;

    if (ssl == NULL || key == NULL || sig == NULL ||
        hash == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }

    /* import public key */
    ret = wc_ecc_init(&tmpKey);
    if (ret == 0) {
        ret = wc_EccPublicKeyDecode(key, &idx, &tmpKey, keySz);
    }
    if (ret != 0) {
        goto exit;
    }

    if (tmpKey.dp->id == ECC_SECP256R1) {
        /* export public as unsigned bin for hardware */
        ret = wc_ecc_export_public_raw(&tmpKey, qx, &qxLen, qy, &qyLen);
        wc_ecc_free(&tmpKey);
        if (ret != 0) {
            goto exit;
        }

        /* decode the ECDSA signature */
        ret = wc_ecc_sig_to_rs(sig, sigSz,
            &sigRs[0], &rSz,
            &sigRs[ATECC_SIG_SIZE/2], &sSz);
        if (ret != 0) {
            goto exit;
        }

        ret = atmel_ecc_verify(hash, sigRs, peerKey, result);
        if (ret != ATCA_SUCCESS || !*result) {
            ret = WC_HW_E; goto exit;
        }

#if !defined(WOLFSSL_ATECC508A_NOIDLE) && !defined(WOLFSSL_MICROCHIP_TA100)
        /* put chip into idle to prevent watchdog situation on chip */
        atcab_idle();
    #endif
    }
    else {
    #ifndef WOLFSSL_ATECC508A_NOSOFTECC
        ret = wc_ecc_verify_hash(sig, sigSz, hash, hashSz, result, &tmpKey);
    #else
        ret = NOT_COMPILED_IN;
    #endif /* !WOLFSSL_ATECC508A_NOSOFTECC */
    }

    (void)rSz;
    (void)sSz;
    (void)qxLen;
    (void)qyLen;

    ret = 0; /* success */

exit:

#ifdef WOLFSSL_ATECC_DEBUG
    if (ret != 0) {
        printf("atcatls_verify_signature_cb: ret %d\n", ret);
    }
#endif

    return ret;
}

#ifdef ATCA_TFLEX_SUPPORT
static int atcatls_set_certificates(WOLFSSL_CTX *ctx) 
{
    #ifndef ATCATLS_SIGNER_CERT_MAX_SIZE
        #define ATCATLS_SIGNER_CERT_MAX_SIZE 0x250
    #endif
    #ifndef ATCATLS_DEVICE_CERT_MAX_SIZE
        #define ATCATLS_DEVICE_CERT_MAX_SIZE 0x250
    #endif
    #ifndef ATCATLS_CERT_BUFF_MAX_SIZE
        #define ATCATLS_CERT_BUFF_MAX_SIZE (ATCATLS_SIGNER_CERT_MAX_SIZE +\
                                               ATCATLS_DEVICE_CERT_MAX_SIZE)
    #endif
    #ifndef ATCATLS_PUBKEY_BUFF_MAX_SIZE
        #define ATCATLS_PUBKEY_BUFF_MAX_SIZE 65
    #endif

    int ret = 0;
    size_t signerCertSize = ATCATLS_SIGNER_CERT_MAX_SIZE;
    size_t deviceCertSize = ATCATLS_DEVICE_CERT_MAX_SIZE;
    uint8_t certBuffer[ATCATLS_CERT_BUFF_MAX_SIZE];
    uint8_t signerBuffer[ATCATLS_SIGNER_CERT_MAX_SIZE];
#ifdef WOLFSSL_ATECC_TFLXTLS
    uint8_t signerPubKeyBuffer[ATCATLS_PUBKEY_BUFF_MAX_SIZE];
#endif

#ifdef WOLFSSL_ATECC_TNGTLS
    ATCA_STATUS status;
    ret = tng_atcacert_max_signer_cert_size(&signerCertSize);
    if (ret != ATCACERT_E_SUCCESS) {
    #ifdef WOLFSSL_ATECC_DEBUG
       printf("Failed to get max signer cert size\r\n");
    #endif
       return ret;
    }
    else if (signerCertSize > ATCATLS_SIGNER_CERT_MAX_SIZE) {
    #ifdef WOLFSSL_ATECC_DEBUG
        printf("Signer CA cert buffer too small, need to increase at least"
               " to %d\r\n", signerCertSize);
    #endif
       return -1;
    }

    /* Read TNGTLS signer cert */
    status = tng_atcacert_read_signer_cert(signerBuffer, &signerCertSize);
    if (ATCA_SUCCESS != status) {
        ret = atmel_ecc_translate_err(status);
        return ret;
    }

    /* Read device cert signed by the signer above */
    status = tng_atcacert_read_device_cert(certBuffer, &deviceCertSize,
                                           signerBuffer);
    if (ATCA_SUCCESS != status) {
        ret = atmel_ecc_translate_err(status);
        return ret;
    }
    else if (deviceCertSize > ATCATLS_DEVICE_CERT_MAX_SIZE) {
    #ifdef WOLFSSL_ATECC_DEBUG
        printf("Device cert buffer too small, need to increase at least"
               " to %d\r\n", deviceCertSize);
    #endif
       return -1;
    }
#endif /* WOLFSSL_ATECC_TNGTLS */

#ifdef WOLFSSL_ATECC_TFLXTLS
    /* MAKE SURE TO COPY YOUR CUSTOM CERTIFICATE FILES UNDER CAL/tng
     * Verify variable names, here below the code uses typical tflxtls
     *  proto example.
     *
     * g_cert_def_1_signer
     * g_cert_ca_public_key_1_signer
     * g_cert_def_3_device
     */

    status = atcacert_read_cert(&g_cert_def_1_signer,
                            (const uint8_t*)g_cert_ca_public_key_1_signer,
                            signerBuffer, &signerCertSize);
    if (status != ATCA_SUCCESS) {
    #ifdef WOLFSSL_ATECC_DEBUG
        printf("Failed to read TFLXTLS signer cert!\r\n");
    #endif
        return (int)status;
    }
    else if (signerCertSize > ATCATLS_SIGNER_CERT_MAX_SIZE) {
    #ifdef WOLFSSL_ATECC_DEBUG
       printf("Signer TFLXTLS CA cert buffer too small, need to increase"
              " at least to %d\r\n", signerCertSize);
    #endif
       return -1;
    }

    status = atcacert_get_subj_public_key(&g_cert_def_1_signer, signerBuffer,
        signerCertSize, signerPubKeyBuffer);
    if (status != ATCA_SUCCESS) {
    #ifdef WOLFSSL_ATECC_DEBUG
        printf("Failed to read TFLXTLS signer public key!\r\n");
    #endif
       return (int)status;
    }

    status = atcacert_read_cert(&g_cert_def_3_device, signerPubKeyBuffer,
                                certBuffer, &deviceCertSize);
    if (status != ATCA_SUCCESS) {
    #ifdef WOLFSSL_ATECC_DEBUG
        printf("Failed to read device cert!\r\n");
    #endif
        return (int)status;
    }
#endif

    /* Prepare the full buffer adding the signer certificate */
    XMEMCPY(&certBuffer[deviceCertSize], signerBuffer, signerCertSize);

    ret = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,
          (const unsigned char*)certBuffer, (signerCertSize + deviceCertSize),
          WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
    #ifdef WOLFSSL_ATECC_DEBUG
        printf("Error registering certificate chain\r\n");
    #endif
        ret = -1;
    }
    else {
        ret = 0;
    }

    return ret;
}
#endif /* ATCA_TFLEX_SUPPORT */

int atcatls_set_callbacks(WOLFSSL_CTX* ctx)
{
    int ret = 0;
    wolfSSL_CTX_SetEccKeyGenCb(ctx, atcatls_create_key_cb);
    wolfSSL_CTX_SetEccVerifyCb(ctx, atcatls_verify_signature_cb);
    wolfSSL_CTX_SetEccSignCb(ctx, atcatls_sign_certificate_cb);
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, atcatls_create_pms_cb);

#ifdef ATCA_TFLEX_SUPPORT
#if defined(WOLFSSL_ATECC_TNGTLS) || defined(WOLFSSL_ATECC_TFLXTLS)
    ret = atcatls_set_certificates(ctx);
    if (ret != 0) {
    #ifdef WOLFSSL_ATECC_DEBUG
        printf("atcatls_set_certificates failed. (%d)\r\n", ret);
    #endif
    }
#endif
#endif /* ATCA_TFLEX_SUPPORT */
    return ret;
}

int atcatls_set_callback_ctx(WOLFSSL* ssl, void* user_ctx)
{
    wolfSSL_SetEccKeyGenCtx(ssl, user_ctx);
    wolfSSL_SetEccVerifyCtx(ssl, user_ctx);
    wolfSSL_SetEccSignCtx(ssl, user_ctx);
    wolfSSL_SetEccSharedSecretCtx(ssl, user_ctx);
    return 0;
}


#endif /* HAVE_PK_CALLBACKS */

#if defined(WOLFSSL_MICROCHIP_TA100) && !defined(NO_AES) && \
    defined(HAVE_AESGCM) && defined(WOLFSSL_MICROCHIP_AESGCM)
int wc_Microchip_aes_set_key(Aes* aes, const byte* key, word32 keylen,
                                        const byte* iv, int dir)
{
    ATCA_STATUS status;
    bool is_locked = false;

    (void)dir;
    (void)iv;

    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }
    aes->key_id = atmel_ecc_alloc(ATMEL_SLOT_ENCKEY);

    if (aes->key_id == ATECC_INVALID_SLOT) {
        return WC_HW_WAIT_E;
    }

    aes->keylen = keylen;
    aes->rounds = keylen/4 + 6;
    XMEMCPY(aes->key, key, keylen);

    /* Test if data zone is locked */
    status = talib_is_setup_locked(atcab_get_device(), &is_locked);
    if (!is_locked) {
        return WC_HW_WAIT_E;
    }

    status = talib_write_bytes_zone(atcab_get_device(), (uint8_t)ATCA_ZONE_DATA,
                       MAP_TO_HANDLE(aes->key_id), 0, (const uint8_t*)key,
                       (const size_t)keylen);
    CHECK_STATUS(status);

    status = talib_aes_gcm_keyload(atcab_get_device(), aes->key_id, keylen);
    CHECK_STATUS(status);

    return atmel_ecc_translate_err(status);
}

void wc_Microchip_aes_free(Aes* aes)
{
    (void)aes;
}

static int wc_Microchip_AesGcmCommon(Aes* aes, byte* out, const byte* in,
        word32 sz, const byte* iv, word32 ivSz, byte* authTag, word32 authTagSz,
        const byte* authIn, word32 authInSz, int dir)
{
    ATCA_STATUS status;
    atca_aes_gcm_ctx_t ctx;

    (void)out;
    (void)in;
    (void)sz;
    (void)iv;
    (void)ivSz;
    (void)authTag;
    (void)authTagSz;
    (void)authIn;
    (void)authInSz;
    (void)dir;

    (void)ctx;

    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }
    if (dir != AES_ENCRYPTION &&
        dir != AES_DECRYPTION) {
        return BAD_FUNC_ARG;
    }


    if (dir == AES_ENCRYPTION) {
        status = talib_aes_gcm_encrypt(atcab_get_device(), authIn,
                                       authInSz, iv, in, sz, out, authTag);
        CHECK_STATUS(status);
    }
    else {
        status = talib_aes_gcm_decrypt(atcab_get_device(), authIn,
             authInSz, iv, authTag, in, sz, out);

        /* Add cipher to gcm */
        status = atcab_aes_gcm_decrypt_update(&ctx, in, sz, out);
        CHECK_STATUS(status);
    }
    return atmel_ecc_translate_err(status);
}
int wc_Microchip_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz)
{
    return wc_Microchip_AesGcmCommon(aes, out, in, sz, iv, ivSz, authTag,
                            authTagSz, authIn, authInSz, AES_ENCRYPTION);
}

int wc_Microchip_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             const byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz)
{
    return wc_Microchip_AesGcmCommon(aes, out, in, sz, iv, ivSz, (byte*)authTag,
                                   authTagSz, authIn, authInSz, AES_DECRYPTION);
}
#endif /* WOLFSSL_MICROCHIP_TA100 && !NO_AES && HAVE_AESGCM */
#endif /* WOLFSSL_ATMEL || WOLFSSL_ATECC508A || WOLFSSL_ATECC_PKCB || \
          WOLFSSL_MICROCHIP_TA100 */
