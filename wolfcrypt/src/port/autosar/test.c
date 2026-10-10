/* test.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_AUTOSAR

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/autosar/Csm.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
    #include <wolfssl/wolfcrypt/aes.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
#endif
#define BLOCK_SIZE 16

/* Keystore slots the AES-CBC tests provision. Without redirection the driver
 * scans for the first slot matching the element ID and key length, so any slot
 * will do. With redirection it reads only the slots configured at build time,
 * so write where it is going to look. Assumes the primary input is the cipher
 * key and the secondary is the IV, as in the port README's example config. */
#ifdef REDIRECTION_CONFIG
    #define CBC_KEY_SLOT ((uint32)REDIRECTION_IN1_KEYID)
    #define CBC_IV_SLOT  ((uint32)REDIRECTION_IN2_KEYID)
#else
    #define CBC_KEY_SLOT 0U
    #define CBC_IV_SLOT  1U
#endif

static int singleshot_test(void)
{
    Std_ReturnType ret;

    uint8 cipher[BLOCK_SIZE * 2];
    uint8 plain[BLOCK_SIZE * 2];

    uint32 cipherSz = 0;
    uint32 plainSz  = 0;
    const uint8 msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const uint8 verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    const uint8 key[] = "0123456789abcdef   ";
    const uint8 iv[]  = "1234567890abcdef   ";

    XMEMSET(cipher, 0, BLOCK_SIZE);
    XMEMSET(plain, 0, BLOCK_SIZE);

    /* set key that will be used for encryption */
    ret = Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
            BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
        cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    if (XMEMCMP(cipher, verify, BLOCK_SIZE) != 0) {
        printf("Error with cipher data\n");
        return -1;
    }

    /* set key that will be used for decryption */
    ret = Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
            BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* decrypt data using AES CBC */
    ret = Csm_Decrypt(2U, CRYPTO_OPERATIONMODE_SINGLECALL, cipher, BLOCK_SIZE,
        plain, &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    if (XMEMCMP(msg, plain, BLOCK_SIZE) != 0) {
        printf("Error with plain data\n");
        return -1;
    }

    return 0;
}


static int update_test(void)
{
    Std_ReturnType ret;

    uint8 cipher[BLOCK_SIZE * 3];
    uint8 plain[BLOCK_SIZE * 3];

    uint32 cipherSz = 0;
    uint32 plainSz  = 0;
    const uint8 msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const uint8 key[] = "0123456789abcdef   ";
    const uint8 iv[]  = "1234567890abcdef   ";

    XMEMSET(cipher, 0, BLOCK_SIZE);
    XMEMSET(plain, 0, BLOCK_SIZE);

    /* set key that will be used for encryption */
    ret = Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
            BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(1U,
            CRYPTO_OPERATIONMODE_START | CRYPTO_OPERATIONMODE_UPDATE,
            msg, BLOCK_SIZE, cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    ret = Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE,
            cipher + BLOCK_SIZE, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    ret = Csm_Encrypt(1U,
            CRYPTO_OPERATIONMODE_UPDATE | CRYPTO_OPERATIONMODE_FINISH,
            msg, BLOCK_SIZE, cipher + (BLOCK_SIZE * 2), &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    /* set key that will be used for decryption */
    ret = Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
            BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* decrypt data using AES CBC */
    ret = Csm_Decrypt(2U,
            CRYPTO_OPERATIONMODE_START | CRYPTO_OPERATIONMODE_UPDATE,
            cipher, BLOCK_SIZE, plain, &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    ret = Csm_Decrypt(2U, CRYPTO_OPERATIONMODE_UPDATE, cipher + BLOCK_SIZE,
            BLOCK_SIZE, plain + BLOCK_SIZE, &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    ret = Csm_Decrypt(2U,
            CRYPTO_OPERATIONMODE_UPDATE | CRYPTO_OPERATIONMODE_FINISH,
            cipher + (BLOCK_SIZE * 2), BLOCK_SIZE,
            plain + (BLOCK_SIZE * 2), &plainSz);
    if (ret != E_OK) {
        printf("Issue with decrypting msg");
        return -1;
    }

    if (XMEMCMP(msg, plain, BLOCK_SIZE) != 0 ||
        XMEMCMP(msg, plain + BLOCK_SIZE, BLOCK_SIZE) != 0 ||
        XMEMCMP(msg, plain + (BLOCK_SIZE * 2), BLOCK_SIZE) != 0) {
        printf("Error with plain data\n");
        return -1;
    }

    return 0;
}


static int random_test(void)
{
    Std_ReturnType ret;

    int i;
    uint8 j;
    uint8 data[BLOCK_SIZE * 3];
    uint32 dataSz;
    XMEMSET(data, 0, BLOCK_SIZE * 3);

    /* make three calls, filling up data buffer */
    for (i = 0; i < 3; i++) {
        dataSz = BLOCK_SIZE;
        ret = Csm_RandomGenerate(0U, data + (i * BLOCK_SIZE), &dataSz);
        if (ret != E_OK) {
            printf("Issue with getting random data block");
            return -1;
        }

        if (dataSz != BLOCK_SIZE) {
            printf("Did not get full block of random data");
            return -1;
        }
    }

    /* simple test that is not all 0's still after random generate */
    j = 0;
    dataSz = sizeof(data);
    for (i = 0; i < (int)dataSz; i++) {
        j |= data[i];
    }
    if (j == 0) {
        printf("call to random generate produced all 0's");
        return -1;
    }

    /* fill full data buffer all at once */
    dataSz = sizeof(data);
    ret = Csm_RandomGenerate(0U, data, &dataSz);
    if (ret != E_OK) {
        printf("Issue with getting random data block");
        return -1;
    }

    if (dataSz != sizeof(data)) {
        printf("Did not get full block of random data");
        return -1;
    }
    return 0;
}


#ifndef MAX_KEYSTORE
    /* default max key slots from crypto.c */
    #define MAX_KEYSTORE 15
#elif MAX_KEYSTORE > 255
    #error "Too many entries"
#endif

#ifndef MAX_JOBS
    /* default max concurrent jobs from crypto.c. Mirrored the same way as
     * MAX_KEYSTORE: both are compile-time limits private to the driver, so a
     * build that overrides one on the command line gets it here too. */
    #define MAX_JOBS 10
#endif

/* How many jobs the small device-observed loops below open at once. MAX_JOBS
 * is overridable and a build may set it to 1 or 2, so take the smaller of the
 * two rather than assuming three slots exist. */
#define FEW_JOBS ((MAX_JOBS < 3) ? MAX_JOBS : 3)
static int key_test(void)
{
    Std_ReturnType ret;

    uint8 i;
    uint8 max = MAX_KEYSTORE;
    uint8 data[BLOCK_SIZE];
    uint32 dataSz;
    XMEMSET(data, 0, BLOCK_SIZE);

    for (i = 0; i < max; i++) {
        dataSz = BLOCK_SIZE;
        ret = Csm_RandomGenerate(0U, data, &dataSz);
        if (ret != E_OK) {
            printf("Issue with getting random data block for key");
            return -1;
        }

        if (dataSz != BLOCK_SIZE) {
            printf("Did not get full block of random data");
            return -1;
        }

        ret = Csm_KeyElementSet(i, CRYPTO_KE_CIPHER_KEY, data, BLOCK_SIZE);
        if (ret != E_OK) {
            printf("Issue with setting key id %d", i);
            return -1;
        }
    }

    /* try creating one more key for fail case */
    ret = Csm_KeyElementSet(i, CRYPTO_KE_CIPHER_KEY, data, BLOCK_SIZE);
    if (ret == E_OK) {
        printf("Created more keys than should be possible");
        return -1;
    }

    return 0;
}

#ifdef WOLFSSL_AUTOSAR_CMAC
/* RFC 4493 example 2: AES-128-CMAC over the first 16 bytes of the standard
 * NIST message with the standard key. */
static const uint8 cmacKey[BLOCK_SIZE] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};
static const uint8 cmacMsg[BLOCK_SIZE] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
};
static const uint8 cmacTag[BLOCK_SIZE] = {
    0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,
    0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c
};

static int mac_test(void)
{
    Std_ReturnType ret;
    Crypto_VerifyResultType verify;

    uint8  mac[BLOCK_SIZE];
    uint32 macSz;
    uint8  bad[BLOCK_SIZE];

    XMEMSET(mac, 0, sizeof(mac));

    /* key_test leaves a cipher key in every slot, and with the MAC services
     * built, element 0x01 means either service -- so the driver refuses to
     * guess. Start from an empty keystore so the plain Csm_Mac* calls, which
     * is what this case is covering, have one unambiguous slot to find. */
    Csm_Init(NULL);

    ret = Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_MAC_KEY, cmacKey,
            BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting MAC key");
        return -1;
    }

    /* single call generate, checked against the known answer */
    macSz = sizeof(mac);
    ret = Csm_MacGenerate(3U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, mac, &macSz);
    if (ret != E_OK) {
        printf("Issue with generating MAC");
        return -1;
    }

    if (macSz != BLOCK_SIZE || XMEMCMP(mac, cmacTag, BLOCK_SIZE) != 0) {
        printf("Error with MAC data\n");
        return -1;
    }

    /* verify the tag we just produced */
    verify = CRYPTO_E_VER_NOT_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, mac, BLOCK_SIZE * 8, &verify);
    if (ret != E_OK || verify != CRYPTO_E_VER_OK) {
        printf("Issue with verifying MAC");
        return -1;
    }

    /* a truncated compare uses the leading bits and must still match: 64
      * bits is the length a conformant SecOC caller would pass */
    verify = CRYPTO_E_VER_NOT_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, mac, 64, &verify);
    if (ret != E_OK || verify != CRYPTO_E_VER_OK) {
        printf("Issue with verifying truncated MAC");
        return -1;
    }

    /* a wrong tag must be rejected, and that is not a job failure */
    XMEMCPY(bad, mac, BLOCK_SIZE);
    bad[0] ^= 0xFF;
    verify = CRYPTO_E_VER_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, bad, BLOCK_SIZE * 8, &verify);
    if (ret != E_OK) {
        printf("Issue running MAC verify on a bad tag");
        return -1;
    }
    if (verify != CRYPTO_E_VER_NOT_OK) {
        printf("Bad MAC was accepted\n");
        return -1;
    }

    /* streamed generate over the same message, one block at a time, must
     * reach the same tag */
    XMEMSET(mac, 0, sizeof(mac));
    ret = Csm_MacGenerate(3U,
            CRYPTO_OPERATIONMODE_START | CRYPTO_OPERATIONMODE_UPDATE,
            cmacMsg, BLOCK_SIZE / 2, mac, &macSz);
    if (ret != E_OK) {
        printf("Issue with streamed MAC start");
        return -1;
    }

    macSz = sizeof(mac);
    ret = Csm_MacGenerate(3U,
            CRYPTO_OPERATIONMODE_UPDATE | CRYPTO_OPERATIONMODE_FINISH,
            cmacMsg + (BLOCK_SIZE / 2), BLOCK_SIZE / 2, mac, &macSz);
    if (ret != E_OK) {
        printf("Issue with streamed MAC finish");
        return -1;
    }

    if (macSz != BLOCK_SIZE || XMEMCMP(mac, cmacTag, BLOCK_SIZE) != 0) {
        printf("Error with streamed MAC data\n");
        return -1;
    }

    /* A tag shorter than the floor is refused rather than compared: a 1 byte
     * tag would be forged by guessing one byte. */
    verify = CRYPTO_E_VER_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, mac, 8, &verify);
    if (ret != E_NOT_OK || verify != CRYPTO_E_VER_NOT_OK) {
        printf("an 8 bit MAC was compared\n");
        return -1;
    }

    /* The floor itself must still work, since SecOC profile 1 relies on it. */
    verify = CRYPTO_E_VER_NOT_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, mac, (uint32)WOLFSSL_AUTOSAR_MAC_MIN_SZ * 8, &verify);
    if (ret != E_OK || verify != CRYPTO_E_VER_OK) {
        printf("the shortest allowed MAC was refused\n");
        return -1;
    }

    /* One bit below the floor. The bound has to be applied to the bit count,
     * not to the rounded-up byte count: rounding first would accept everything
     * from 8 * (MIN_SZ - 1) + 1 bits upwards, so a 17 bit tag would pass a
     * floor documented as 24 bits. */
    verify = CRYPTO_E_VER_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, mac, (uint32)WOLFSSL_AUTOSAR_MAC_MIN_SZ * 8 - 1,
            &verify);
    if (ret != E_NOT_OK || verify != CRYPTO_E_VER_NOT_OK) {
        printf("a MAC one bit below the floor was compared\n");
        return -1;
    }

    /* A length that is not a whole number of bytes: 28 bits is 3 full bytes
     * plus the top 4 bits of the fourth, which only the bit-based API can
     * ask for. Must match, and must stop mattering at bit 28. */
    verify = CRYPTO_E_VER_NOT_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, mac, 28, &verify);
    if (ret != E_OK || verify != CRYPTO_E_VER_OK) {
        printf("a 28 bit MAC did not verify\n");
        return -1;
    }

    XMEMCPY(bad, mac, BLOCK_SIZE);
    bad[3] ^= 0x08; /* bit 29: outside the compared 28 */
    verify = CRYPTO_E_VER_NOT_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, bad, 28, &verify);
    if (ret != E_OK || verify != CRYPTO_E_VER_OK) {
        printf("a 28 bit compare looked past bit 28\n");
        return -1;
    }

    bad[3] ^= 0x08;  /* undo */
    bad[3] ^= 0x80; /* bit 25: inside the compared 28 */
    verify = CRYPTO_E_VER_OK;
    ret = Csm_MacVerify(4U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
            BLOCK_SIZE, bad, 28, &verify);
    if (ret != E_OK || verify != CRYPTO_E_VER_NOT_OK) {
        printf("a 28 bit compare missed a flipped bit inside it\n");
        return -1;
    }

    /* A macLength that does not fit the buffer, on the byte-based
     * extension. */
    verify = CRYPTO_E_VER_OK;
    ret = wolfSSL_Csm_MacVerifyWithKey(4U, WOLFSSL_CSM_KEY_ID_ANY,
            CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, mac,
            1, 8, &verify);
    if (ret != E_NOT_OK || verify != CRYPTO_E_VER_NOT_OK) {
        printf("a MAC length past the buffer was accepted\n");
        return -1;
    }

    return 0;
}


/* A cipher key and a MAC key provisioned at the same time.
 *
 * The specification scopes key element IDs per key, so CRYPTO_KE_CIPHER_KEY
 * and CRYPTO_KE_MAC_KEY are both 0x01. With a flat keystore that makes the
 * element ID useless for telling them apart: resolving by element took the
 * first slot holding 0x01, so a MAC job quietly ran under the cipher key, and
 * key input redirection could not separate them either -- it maps an element
 * ID to one slot for every service.
 *
 * The decoy key is deliberately in a LOWER slot than the real MAC key, which
 * is the order that used to pick the wrong one.
 *
 * MAX_KEYSTORE has to be big enough for three distinct slots; a smaller build
 * still compiles, it just skips this. */
#if MAX_KEYSTORE > 2
#define MAC_KEY_SLOT 2U
static int keysep_test(void)
{
    Std_ReturnType ret;
    Crypto_VerifyResultType verify;
    uint8  mac[BLOCK_SIZE];
    uint32 macSz;
    uint8  encDecoy[BLOCK_SIZE * 2];
    uint8  encMac[BLOCK_SIZE * 2];
    uint8  plain[BLOCK_SIZE * 2];
    uint32 encDecoySz, encMacSz, plainSz;
    const uint8 decoy[BLOCK_SIZE] = {
        0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
        0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
    };
    const uint8 iv[BLOCK_SIZE] = {
        '1','2','3','4','5','6','7','8',
        '9','0','a','b','c','d','e','f'
    };

    if (CBC_KEY_SLOT >= MAC_KEY_SLOT) {
        printf("test needs the decoy key in a lower slot");
        return -1;
    }

    /* Start from a known keystore: key_test fills every slot, and this case
     * cares about which slots hold what. Safe to do here because this test
     * runs last. */
    Csm_Init(NULL);

    ret = Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, decoy,
            BLOCK_SIZE);
    if (ret == E_OK) {
        ret = Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                BLOCK_SIZE);
    }
    if (ret == E_OK) {
        ret = Csm_KeyElementSet(MAC_KEY_SLOT, CRYPTO_KE_MAC_KEY, cmacKey,
                BLOCK_SIZE);
    }
    if (ret != E_OK) {
        printf("Issue provisioning the two keys");
        return -1;
    }

#ifndef WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT
    /* With two slots holding element 0x01, a plain call cannot be resolved:
     * the driver refuses rather than computing a CMAC under the cipher key and
     * reporting success, which is what a SW-C written against the standard Csm
     * API would otherwise get.
     *
     * A build defining WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT has asked
     * for the old first-match scan, so it does not get this. */
    macSz = sizeof(mac);
    if (Csm_MacGenerate(5U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg,
                BLOCK_SIZE, mac, &macSz) != E_NOT_OK) {
        printf("an ambiguous key element was resolved anyway\n");
        return -1;
    }
    if (Csm_Encrypt(5U, CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE,
                encDecoy, &encDecoySz) != E_NOT_OK) {
        printf("an ambiguous cipher key was resolved anyway\n");
        return -1;
    }
#endif

    /* The MAC must come out under the key in MAC_KEY_SLOT. Without naming the
     * slot this is the decoy's tag. */
    macSz = sizeof(mac);
    XMEMSET(mac, 0, sizeof(mac));
    ret = wolfSSL_Csm_MacGenerateWithKey(6U, MAC_KEY_SLOT,
            CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, mac, &macSz);
    if (ret != E_OK) {
        printf("Issue generating a MAC with a named key");
        return -1;
    }
    if (macSz != BLOCK_SIZE || XMEMCMP(mac, cmacTag, BLOCK_SIZE) != 0) {
        printf("MAC did not use the named key\n");
        return -1;
    }

    verify = CRYPTO_E_VER_NOT_OK;
    ret = wolfSSL_Csm_MacVerifyWithKey(7U, MAC_KEY_SLOT,
            CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, cmacTag,
            BLOCK_SIZE, BLOCK_SIZE, &verify);
    if (ret != E_OK || verify != CRYPTO_E_VER_OK) {
        printf("Issue verifying a MAC with a named key");
        return -1;
    }

    /* The cipher side honours the name too: the same plaintext under the two
     * slots must not produce the same ciphertext. */
    encDecoySz = 0;
    ret = wolfSSL_Csm_EncryptWithKey(8U, CBC_KEY_SLOT,
            CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, encDecoy,
            &encDecoySz);
    if (ret != E_OK) {
        printf("Issue encrypting with the named cipher key");
        return -1;
    }

    encMacSz = 0;
    ret = wolfSSL_Csm_EncryptWithKey(9U, MAC_KEY_SLOT,
            CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, encMac,
            &encMacSz);
    if (ret != E_OK) {
        printf("Issue encrypting with the other named key");
        return -1;
    }

    if (XMEMCMP(encDecoy, encMac, BLOCK_SIZE) == 0) {
        printf("naming a different key slot changed nothing\n");
        return -1;
    }

    /* and it round trips under the slot it was encrypted with */
    plainSz = 0;
    ret = wolfSSL_Csm_DecryptWithKey(10U, CBC_KEY_SLOT,
            CRYPTO_OPERATIONMODE_SINGLECALL, encDecoy, BLOCK_SIZE, plain,
            &plainSz);
    if (ret != E_OK || XMEMCMP(plain, cmacMsg, BLOCK_SIZE) != 0) {
        printf("named key did not round trip\n");
        return -1;
    }

    /* a slot out of range, and an empty one, are refused rather than scanned
     * for something that happens to fit */
    encMacSz = 0;
    if (wolfSSL_Csm_EncryptWithKey(11U, (uint32)MAX_KEYSTORE,
                CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, encMac,
                &encMacSz) != E_NOT_OK) {
        printf("an out of range key slot was accepted\n");
        return -1;
    }

    /* An empty slot, which means the highest one this test did not fill --
     * CBC_KEY_SLOT and CBC_IV_SLOT move with the redirection config. */
    {
        uint32 empty = (uint32)MAX_KEYSTORE;
        uint32 i;

        for (i = (uint32)MAX_KEYSTORE; i > 0; i--) {
            uint32 slot = i - 1;

            if (slot != (uint32)CBC_KEY_SLOT && slot != (uint32)CBC_IV_SLOT &&
                    slot != MAC_KEY_SLOT) {
                empty = slot;
                break;
            }
        }

        if (empty != (uint32)MAX_KEYSTORE) {
            encMacSz = 0;
            if (wolfSSL_Csm_EncryptWithKey(12U, empty,
                        CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE,
                        encMac, &encMacSz) != E_NOT_OK) {
                printf("an empty key slot was accepted\n");
                return -1;
            }
        }
    }

    return 0;
}
#endif /* MAX_KEYSTORE > 2 */
#endif /* WOLFSSL_AUTOSAR_CMAC */


#ifdef REDIRECTION_CONFIG
static int redirect_test(void)
{
    Std_ReturnType ret;

    uint8 cipher[BLOCK_SIZE * 2];
    uint32 cipherSz = 0;
    const uint8 msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const uint8 verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    const uint8 key[] = "0123456789abcdef   ";  /* align */
    const uint8 iv[]  = "1234567890abcdef   ";  /* align */
    unsigned int i;

    XMEMSET(cipher, 0, BLOCK_SIZE);

    /* fill keystore with bad keys */
    for (i = 0; i < MAX_KEYSTORE; i++) {
        ret = Csm_KeyElementSet(i, CRYPTO_KE_CIPHER_KEY, verify, BLOCK_SIZE);
        if (ret != E_OK) {
            printf("Issue with setting key");
            return -1;
        }
    }

    /* set specific key that will be used for encryption */
    ret = Csm_KeyElementSet(REDIRECTION_IN1_KEYID, REDIRECTION_IN1_KEYELMID,
            key, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key");
        return -1;
    }

    ret = Csm_KeyElementSet(REDIRECTION_IN2_KEYID, REDIRECTION_IN2_KEYELMID,
            iv, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key IV");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(0U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
        cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg");
        return -1;
    }

    if (XMEMCMP(cipher, verify, BLOCK_SIZE) != 0) {
        printf("Error with cipher data ");
        return -1;
    }

    /* now set bad key to be used for encryption */
    ret = Csm_KeyElementSet(REDIRECTION_IN1_KEYID, REDIRECTION_IN1_KEYELMID,
            verify, BLOCK_SIZE);
    if (ret != E_OK) {
        printf("Issue with setting key ");
        return -1;
    }

    /* encrypt data using AES CBC */
    ret = Csm_Encrypt(0U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
        cipher, &cipherSz);
    if (ret != E_OK) {
        printf("Issue with encrypting msg ");
        return -1;
    }

    if (XMEMCMP(cipher, verify, BLOCK_SIZE) == 0) {
        printf("Error with cipher data ");
        return -1;
    }

    return 0;
}
#endif /* REDIRECTION_CONFIG */

#ifdef WOLF_CRYPTO_CB
/* Checks that a devId handed to Csm_Init() actually reaches a crypto callback,
 * and that no config still means software. Counts only; the callback returns
 * CRYPTOCB_UNAVAILABLE so wolfCrypt does the work and results stay correct. */
#define WOLFSSL_AUTOSAR_TEST_DEVID 7

static int cbCipher = 0;
static int cbRng = 0;
#ifdef WOLF_CRYPTO_CB_FREE
/* wc_AesFree()/wc_CmacFree() notify the device under WOLF_CRYPTO_CB_FREE, so
 * with that built a test can see a context actually being freed rather than
 * abandoned -- which is the only way the re-init teardown is observable. */
static int cbFree = 0;
#endif
#ifdef WOLFSSL_AUTOSAR_CMAC
static int cbCmac = 0;
#endif
static int cbBadDevId = 0;

static int autosarTestCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)ctx;

    if (devId != WOLFSSL_AUTOSAR_TEST_DEVID) {
        cbBadDevId++;
    }
    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

#ifdef WOLF_CRYPTO_CB_FREE
    /* A context being freed. Counted, not claimed: returning
     * CRYPTOCB_UNAVAILABLE leaves wolfCrypt to finish the teardown. */
    if (info->algo_type == WC_ALGO_TYPE_FREE) {
        cbFree++;
        return CRYPTOCB_UNAVAILABLE;
    }
#endif

    /* register/unregister arrive as WC_ALGO_TYPE_NONE and must succeed */
    if (info->algo_type == WC_ALGO_TYPE_NONE) {
        return 0;
    }

    if (info->algo_type == WC_ALGO_TYPE_CIPHER) {
        cbCipher++;
    }
    else if (info->algo_type == WC_ALGO_TYPE_RNG ||
             info->algo_type == WC_ALGO_TYPE_SEED) {
        cbRng++;
    }
#ifdef WOLFSSL_AUTOSAR_CMAC
    else if (info->algo_type == WC_ALGO_TYPE_CMAC) {
        cbCmac++;
    }
#endif

    return CRYPTOCB_UNAVAILABLE; /* fall back to software */
}

/* one AES-CBC round trip plus a random draw, and a MAC if built */
static int devid_exercise(void)
{
    Std_ReturnType ret;
    uint8  cipher[BLOCK_SIZE];
    uint8  plain[BLOCK_SIZE];
    uint8  rnd[BLOCK_SIZE];
    uint32 len;
    const uint8 key[] = "0123456789abcdef   ";  /* align */
    const uint8 iv[]  = "1234567890abcdef   ";  /* align */
    const uint8 msg[] = {
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };

    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
                BLOCK_SIZE) != E_OK) {
        return -1;
    }
    if (Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE)
            != E_OK) {
        return -1;
    }

    len = BLOCK_SIZE;
    ret = Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
            cipher, &len);
    if (ret != E_OK) {
        return -1;
    }

    len = BLOCK_SIZE;
    ret = Csm_Decrypt(2U, CRYPTO_OPERATIONMODE_SINGLECALL, cipher, BLOCK_SIZE,
            plain, &len);
    if (ret != E_OK || XMEMCMP(msg, plain, BLOCK_SIZE) != 0) {
        return -1;
    }

    len = BLOCK_SIZE;
    if (Csm_RandomGenerate(0U, rnd, &len) != E_OK) {
        return -1;
    }

#ifdef WOLFSSL_AUTOSAR_CMAC
    {
        uint8  mac[BLOCK_SIZE];
        uint32 macSz = BLOCK_SIZE;

        if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_MAC_KEY, key,
                    BLOCK_SIZE) != E_OK) {
            return -1;
        }
        if (Csm_MacGenerate(3U, CRYPTO_OPERATIONMODE_SINGLECALL, msg,
                    BLOCK_SIZE, mac, &macSz) != E_OK) {
            return -1;
        }
    }
#endif
    return 0;
}

static int devid_test(void)
{
    Csm_ConfigType config;
    int ret = 0;

    /* free slots in the device table are marked with INVALID_DEVID, which
     * only wolfCrypt_Init() sets up */
    if (wolfCrypt_Init() != 0) {
        printf("wolfCrypt_Init failed");
        return -1;
    }
    if (wc_CryptoCb_RegisterDevice(WOLFSSL_AUTOSAR_TEST_DEVID,
                autosarTestCryptoCb, NULL) != 0) {
        printf("could not register the test device");
        return -1;
    }

    /* no config: everything must stay in software */
    Csm_Init(NULL);
    cbCipher = 0; cbRng = 0; cbBadDevId = 0;
#ifdef WOLFSSL_AUTOSAR_CMAC
    cbCmac = 0;
#endif
    if (devid_exercise() != 0) {
        printf("jobs failed without a devId");
        ret = -1;
    }
    else if (cbCipher != 0 || cbRng != 0
    #ifdef WOLFSSL_AUTOSAR_CMAC
            || cbCmac != 0
    #endif
            ) {
        printf("callback ran even though no devId was configured");
        ret = -1;
    }

    /* with a devId the same jobs must reach the callback */
    if (ret == 0) {
        XMEMSET(&config, 0, sizeof(config));
        config.heap  = NULL;
        config.devId = WOLFSSL_AUTOSAR_TEST_DEVID;
        Csm_Init(&config);

        cbCipher = 0; cbRng = 0; cbBadDevId = 0;
#ifdef WOLFSSL_AUTOSAR_CMAC
        cbCmac = 0;
#endif
        if (devid_exercise() != 0) {
            printf("jobs failed with a devId");
            ret = -1;
        }
        else if (cbCipher == 0) {
            printf("cipher job did not reach the callback");
            ret = -1;
        }
        else if (cbRng == 0) {
            printf("random job did not reach the callback");
            ret = -1;
        }
#ifdef WOLFSSL_AUTOSAR_CMAC
        else if (cbCmac == 0) {
            printf("MAC job did not reach the callback");
            ret = -1;
        }
#endif
        else if (cbBadDevId != 0) {
            printf("callback saw the wrong devId");
            ret = -1;
        }
    }

    /* Csm_Init() first: it frees the DRBG and any job slot still holding a
     * context built on this device, which has to happen while the device is
     * still registered. Unregistering first would leave the callback
     * unavailable to the frees. */
    Csm_Init(NULL); /* leave the port in software mode */
    (void)wc_CryptoCb_UnRegisterDevice(WOLFSSL_AUTOSAR_TEST_DEVID);
    return ret;
}
#endif /* WOLF_CRYPTO_CB */


#if defined(WOLF_CRYPTO_CB) && defined(WOLF_PRIVATE_KEY_ID)
/* A key that never enters the keystore.
 *
 * The slot names the key with wolfSSL_Csm_KeyElementSetId(); a stand-in for
 * hardware holds the value and does the work in the crypto callback. The
 * ciphertext must come out identical to the ordinary raw-key path, which is
 * what proves the driver conveyed the right key rather than something that
 * merely looks encrypted. */
#define WOLFSSL_AUTOSAR_TEST_ID_DEVID 11

static const unsigned char autosarTestKeyId[] = { 0xDE, 0xAD, 0xBE, 0xEF };
static const uint8 autosarTestHsmKey[BLOCK_SIZE] = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
};
/* Can a cipher job use a named key in this build?
 *
 * The driver refuses one unless wolfCrypt's key-is-set check is actually
 * enforced: not merely defined, but honoured by the AES mode entry points this
 * back end provides -- see StartCbcJob(). So the expected outcome flips with
 * the build, and a test demanding success would fail on exactly the ECU
 * targets the refusal protects. MAC key handles are unaffected. */
#if defined(WOLFSSL_AES_REQUIRE_KEY_SET) && \
        !defined(WC_AES_KEY_SET_CHECK_UNSUPPORTED)
    #define AUTOSAR_TEST_CIPHER_HANDLES 1
#else
    #define AUTOSAR_TEST_CIPHER_HANDLES 0
#endif

static int cbIdHandled = 0;
static int cbIdWrong = 0;

static int autosarTestIdCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->algo_type == WC_ALGO_TYPE_NONE) {
        return 0;
    }

    if (info->algo_type == WC_ALGO_TYPE_CIPHER &&
            info->cipher.type == WC_CIPHER_AES_CBC) {
        Aes* jobAes = info->cipher.aescbc.aes;
        Aes  local;
        int  ret;

        /* the driver said WHICH key, not what it is */
        if (jobAes->idLen != (int)sizeof(autosarTestKeyId) ||
                XMEMCMP(jobAes->id, autosarTestKeyId,
                    sizeof(autosarTestKeyId)) != 0) {
            cbIdWrong++;
            return CRYPTOCB_UNAVAILABLE;
        }

        /* stand-in for hardware doing the work with the key it holds. The IV
         * is in aes->reg, which wc_AesSetIV() put there. */
        if (wc_AesInit(&local, NULL, INVALID_DEVID) != 0) {
            return WC_HW_E;
        }
        ret = wc_AesSetKey(&local, autosarTestHsmKey, BLOCK_SIZE,
                (const byte*)jobAes->reg,
                info->cipher.enc ? AES_ENCRYPTION : AES_DECRYPTION);
        if (ret == 0) {
            if (info->cipher.enc) {
                ret = wc_AesCbcEncrypt(&local, info->cipher.aescbc.out,
                        info->cipher.aescbc.in, info->cipher.aescbc.sz);
            }
            else {
                ret = wc_AesCbcDecrypt(&local, info->cipher.aescbc.out,
                        info->cipher.aescbc.in, info->cipher.aescbc.sz);
            }
        }
        wc_AesFree(&local);

        if (ret != 0) {
            return WC_HW_E;
        }
        cbIdHandled++;
        return 0; /* handled entirely by the "device" */
    }

    return CRYPTOCB_UNAVAILABLE;
}

static int keyhandle_test(void)
{
    Csm_ConfigType config;
    uint8  iv[BLOCK_SIZE];
    uint8  ref[BLOCK_SIZE];
    uint8  cipher[BLOCK_SIZE];
    uint8  plain[BLOCK_SIZE];
    uint32 len;
    int    i, ret = 0;
    const uint8 msg[] = {
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };

    for (i = 0; i < BLOCK_SIZE; i++) {
        iv[i] = (uint8)(0x10 + i);
    }

    if (wolfCrypt_Init() != 0) {
        printf("wolfCrypt_Init failed");
        return -1;
    }
    if (wc_CryptoCb_RegisterDevice(WOLFSSL_AUTOSAR_TEST_ID_DEVID,
                autosarTestIdCryptoCb, NULL) != 0) {
        printf("could not register the test device");
        return -1;
    }

    /* reference: the ordinary path, key material in the keystore */
    XMEMSET(&config, 0, sizeof(config));
    config.devId = INVALID_DEVID;
    Csm_Init(&config);
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY,
                autosarTestHsmKey, BLOCK_SIZE) != E_OK ||
        Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE)
            != E_OK) {
        printf("could not provision the reference key");
        ret = -1;
    }
    if (ret == 0) {
        len = BLOCK_SIZE;
        if (Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
                    ref, &len) != E_OK) {
            printf("reference encrypt failed");
            ret = -1;
        }
    }

    /* the handle path: the slot names the key, the device holds it */
    if (ret == 0) {
        cbIdHandled = 0;
        cbIdWrong = 0;
        XMEMSET(&config, 0, sizeof(config));
        config.devId = WOLFSSL_AUTOSAR_TEST_ID_DEVID;
        Csm_Init(&config);

        if (wolfSSL_Csm_KeyElementSetId(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY,
                    autosarTestKeyId,
                    (uint32)sizeof(autosarTestKeyId)) != E_OK) {
            printf("wolfSSL_Csm_KeyElementSetId failed");
            ret = -1;
        }
        else if (Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                    BLOCK_SIZE) != E_OK) {
            printf("could not provision the IV");
            ret = -1;
        }
    }

#if AUTOSAR_TEST_CIPHER_HANDLES
    if (ret == 0) {
        len = BLOCK_SIZE;
        if (Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
                    cipher, &len) != E_OK) {
            printf("encrypt with a named key failed");
            ret = -1;
        }
        else if (XMEMCMP(cipher, ref, BLOCK_SIZE) != 0) {
            printf("named key produced different ciphertext");
            ret = -1;
        }
        else if (cbIdHandled == 0) {
            printf("the device never saw the operation");
            ret = -1;
        }
        else if (cbIdWrong != 0) {
            printf("the device was given the wrong key identifier");
            ret = -1;
        }
    }

    if (ret == 0) {
        len = BLOCK_SIZE;
        if (Csm_Decrypt(2U, CRYPTO_OPERATIONMODE_SINGLECALL, cipher,
                    BLOCK_SIZE, plain, &len) != E_OK ||
                XMEMCMP(msg, plain, BLOCK_SIZE) != 0) {
            printf("round trip with a named key failed");
            ret = -1;
        }
    }
#else
    /* Nothing enforces the key-is-set check here, so the slot naming a key
     * must make the job fail outright -- not reach the device, and certainly
     * not fall through to an all-zero key schedule. */
    if (ret == 0) {
        len = BLOCK_SIZE;
        if (Csm_Encrypt(1U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
                    cipher, &len) == E_OK) {
            printf("a named cipher key was accepted where the key-is-set "
                   "check is not enforced");
            ret = -1;
        }
    }
    (void)plain;
    (void)ref;
#endif

    /* a label names a key the device does not have, so the operation must
     * fail rather than fall through to software and an all-zero key */
    if (ret == 0) {
        if (wolfSSL_Csm_KeyElementSetLabel(CBC_KEY_SLOT,
                    CRYPTO_KE_CIPHER_KEY, "no-such-key") != E_OK) {
            printf("wolfSSL_Csm_KeyElementSetLabel failed");
            ret = -1;
        }
        else {
            len = BLOCK_SIZE;
            if (Csm_Encrypt(3U, CRYPTO_OPERATIONMODE_SINGLECALL, msg,
                        BLOCK_SIZE, cipher, &len) == E_OK) {
                printf("unknown key label was accepted");
                ret = -1;
            }
        }
    }

#ifdef WOLFSSL_AUTOSAR_CMAC
    /* the MAC services cannot use a key they cannot see, and must say so */
    if (ret == 0) {
        uint8  mac[BLOCK_SIZE];
        uint32 macSz = BLOCK_SIZE;

        if (wolfSSL_Csm_KeyElementSetId(CBC_KEY_SLOT, CRYPTO_KE_MAC_KEY,
                    autosarTestKeyId,
                    (uint32)sizeof(autosarTestKeyId)) != E_OK) {
            printf("wolfSSL_Csm_KeyElementSetId failed for the MAC key");
            ret = -1;
        }
        else if (Csm_MacGenerate(4U, CRYPTO_OPERATIONMODE_SINGLECALL, msg,
                    BLOCK_SIZE, mac, &macSz) == E_OK) {
            printf("a MAC job accepted a named key");
            ret = -1;
        }
    }
#endif

    /* as in devid_test: tear the contexts down before the device they were
     * built on */
    Csm_Init(NULL);
    (void)wc_CryptoCb_UnRegisterDevice(WOLFSSL_AUTOSAR_TEST_ID_DEVID);
    return ret;
}
#ifdef WOLFSSL_AUTOSAR_CMAC
/* A MAC job whose key lives in the device.
 *
 * The MAC services used to refuse a named key, on the belief that wolfCrypt
 * rejects a NULL key before reaching its identifier path. It does not:
 * _InitCmac_common() stores the name, offers the operation to the crypto
 * callback, and only checks for a NULL key once the callback has declined. So
 * a named MAC key works, and is fail-closed for free -- a device that will not
 * do the work leaves CMAC initialization with nothing to use.
 *
 * The device here is a software CMAC under the key it "holds", driven through
 * all three stages the callback sees: init, update, final.
 */
#define MAC_ID_DEVID 12

static Cmac macDevCmac;
static int  macDevInit = 0;
static int  macDevClaimed = 0;
static int  macDevWrongId = 0;
static const unsigned char macKeyId[] = { 0x4D, 0x41, 0x43, 0x01 };
/* when set, the device expects this label instead of macKeyId */
static const char* macDevLabel = NULL;

#ifndef MAX_KEY_LABEL_LEN
    /* Mirrored from crypto.c, like MAX_KEYSTORE and MAX_JOBS above: one below
     * wolfCrypt's AES_MAX_LABEL_LEN, which is the longest label its CMAC will
     * carry. A build overriding it on the command line gets it here too. */
    #define MAX_KEY_LABEL_LEN (AES_MAX_LABEL_LEN - 1)
#endif

static int autosarMacIdCryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->algo_type == WC_ALGO_TYPE_NONE) {
        return 0;
    }
    if (info->algo_type != WC_ALGO_TYPE_CMAC) {
        return CRYPTOCB_UNAVAILABLE;
    }

    /* The driver named a key; it never handed over bytes. */
    if (info->cmac.cmac == NULL) {
        macDevWrongId++;
        return CRYPTOCB_UNAVAILABLE;
    }
    if (macDevLabel != NULL) {
        int want = (int)XSTRLEN(macDevLabel);

        /* The whole label has to arrive, which is the point of this case. */
        if (info->cmac.cmac->labelLen != want ||
                XMEMCMP(info->cmac.cmac->label, macDevLabel, (size_t)want)
                    != 0) {
            macDevWrongId++;
            return CRYPTOCB_UNAVAILABLE;
        }
    }
    else if (info->cmac.cmac->idLen != (int)sizeof(macKeyId) ||
            XMEMCMP(info->cmac.cmac->id, macKeyId, sizeof(macKeyId)) != 0) {
        macDevWrongId++;
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->cmac.key != NULL) {
        /* key material would mean the driver did not use the handle */
        macDevWrongId++;
        return CRYPTOCB_UNAVAILABLE;
    }

    /* init: no input and no output yet */
    if (info->cmac.in == NULL && info->cmac.out == NULL) {
        if (wc_InitCmac(&macDevCmac, cmacKey, BLOCK_SIZE, WC_CMAC_AES, NULL)
                != 0) {
            return WC_HW_E;
        }
        macDevInit = 1;
        macDevClaimed++;
        return 0;
    }
    if (info->cmac.in != NULL) {
        if (!macDevInit) {
            return WC_HW_E;
        }
        if (wc_CmacUpdate(&macDevCmac, info->cmac.in, info->cmac.inSz) != 0) {
            return WC_HW_E;
        }
        return 0;
    }
    if (info->cmac.out != NULL && info->cmac.outSz != NULL) {
        if (!macDevInit) {
            return WC_HW_E;
        }
        if (wc_CmacFinal(&macDevCmac, info->cmac.out, info->cmac.outSz) != 0) {
            return WC_HW_E;
        }
        macDevInit = 0;
        return 0;
    }

    return CRYPTOCB_UNAVAILABLE;
}

static int machandle_test(void)
{
    Csm_ConfigType config = WOLFSSL_CSM_CONFIG_DEFAULT;
    uint8  mac[BLOCK_SIZE];
    uint32 macSz;

    if (wolfCrypt_Init() != 0) {
        printf("wolfCrypt_Init failed");
        return -1;
    }
    if (wc_CryptoCb_RegisterDevice(MAC_ID_DEVID, autosarMacIdCryptoCb, NULL)
            != 0) {
        printf("could not register the MAC device");
        return -1;
    }

    config.devId = MAC_ID_DEVID;
    Csm_Init(&config);

    /* The slot names the key; no key material is ever stored. */
    if (wolfSSL_Csm_KeyElementSetId(0U, CRYPTO_KE_MAC_KEY, macKeyId,
                (uint32)sizeof(macKeyId)) != E_OK) {
        printf("could not name the MAC key");
        return -1;
    }

    macDevClaimed = 0;
    macDevWrongId = 0;
    macSz = sizeof(mac);
    XMEMSET(mac, 0, sizeof(mac));

    if (wolfSSL_Csm_MacGenerateWithKey(9U, 0U,
                CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, mac,
                &macSz) != E_OK) {
        printf("MAC job with a named key failed");
        return -1;
    }

    /* The known answer proves the device's key was used, not a zero key or
     * anything else that merely looked like a MAC. */
    if (macSz != BLOCK_SIZE || XMEMCMP(mac, cmacTag, BLOCK_SIZE) != 0) {
        printf("named MAC key produced the wrong tag\n");
        return -1;
    }
    if (macDevClaimed == 0) {
        printf("the device never saw the MAC job\n");
        return -1;
    }
    if (macDevWrongId != 0) {
        printf("the driver sent the wrong key identifier, or sent bytes\n");
        return -1;
    }

    /* And with no device, a named MAC key is refused rather than run under
     * whatever software would do with no key. */
    Csm_Init(NULL);
    if (wolfSSL_Csm_KeyElementSetId(0U, CRYPTO_KE_MAC_KEY, macKeyId,
                (uint32)sizeof(macKeyId)) != E_OK) {
        printf("could not name the MAC key again");
        return -1;
    }
    macSz = sizeof(mac);
    if (wolfSSL_Csm_MacGenerateWithKey(9U, 0U,
                CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, mac,
                &macSz) != E_NOT_OK) {
        printf("a named MAC key was accepted with no device\n");
        return -1;
    }

    /* A label of exactly MAX_KEY_LABEL_LEN must reach the device intact. This
     * is the case that used to break: wolfCrypt's CMAC copies a label only
     * below AES_MAX_LABEL_LEN and silently keeps none at that length, so a
     * limit set one too high produced a MAC job with no label at all. */
    {
        char maxLabel[MAX_KEY_LABEL_LEN + 1];
        int i;

        for (i = 0; i < MAX_KEY_LABEL_LEN; i++) {
            maxLabel[i] = (char)('a' + (i % 26));
        }
        maxLabel[MAX_KEY_LABEL_LEN] = '\0';

        config.devId = MAC_ID_DEVID;
        Csm_Init(&config);
        macDevLabel = maxLabel;
        if (wolfSSL_Csm_KeyElementSetLabel(0U, CRYPTO_KE_MAC_KEY, maxLabel)
                != E_OK) {
            printf("a maximum length label was refused");
            return -1;
        }

        macDevClaimed = 0;
        macDevWrongId = 0;
        macSz = sizeof(mac);
        if (wolfSSL_Csm_MacGenerateWithKey(10U, 0U,
                    CRYPTO_OPERATIONMODE_SINGLECALL, cmacMsg, BLOCK_SIZE, mac,
                    &macSz) != E_OK) {
            printf("MAC job with a maximum length label failed");
            return -1;
        }
        if (macSz != BLOCK_SIZE || XMEMCMP(mac, cmacTag, BLOCK_SIZE) != 0) {
            printf("maximum length label produced the wrong tag\n");
            return -1;
        }
        if (macDevClaimed == 0 || macDevWrongId != 0) {
            printf("the device did not receive the full label\n");
            return -1;
        }
        macDevLabel = NULL;
    }

    Csm_Init(NULL);
    (void)wc_CryptoCb_UnRegisterDevice(MAC_ID_DEVID);
    return 0;
}
#endif /* WOLFSSL_AUTOSAR_CMAC */
#endif /* WOLF_CRYPTO_CB && WOLF_PRIVATE_KEY_ID */


#ifdef WOLFSSL_AUTOSAR_DET
/* The DET entry point the port calls under WOLFSSL_AUTOSAR_DET. It is defined
 * whenever that macro is, with or without the MAC services: csm.c compiles the
 * call unconditionally, so a build without a definition here fails to link --
 * which is exactly what --enable-autosar -DWOLFSSL_AUTOSAR_DET used to do.
 *
 * det_test() below needs a service that reports a development error to drive
 * it, and only the MAC services do, so the test itself stays behind
 * WOLFSSL_AUTOSAR_CMAC while the definition does not.
 *
 * Checks that a development error reaches the DET with the IDs the CSM
 * specification assigns.
 *
 * This is here because an earlier version of the port reported a local 0-based
 * enum instead, so every ID a DET would have seen was wrong -- and nothing
 * caught it, because nothing used the correct values in the header.
 *
 * The test program supplies Det_ReportError itself, which is what an AUTOSAR
 * stack would do. */
static int detCalls = 0;
static uint16 detModuleId = 0;
static uint8  detInstanceId = 0xFF;
static uint8  detApiId = 0;
static uint8  detErrorId = 0;

/* prototype so -Wmissing-prototypes is satisfied; the real stack declares
 * this in Det.h. Std_ReturnType, as the specification has it. */
Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId,
        uint8 ErrorId);

Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId,
        uint8 ErrorId)
{
    detCalls++;
    detModuleId   = ModuleId;
    detInstanceId = InstanceId;
    detApiId      = ApiId;
    detErrorId    = ErrorId;
    return E_OK;
}


#ifdef WOLFSSL_AUTOSAR_CMAC
static int det_test(void)
{
    Std_VersionInfoType version;
    uint8  msg[BLOCK_SIZE];
    uint32 macSz = BLOCK_SIZE;

    XMEMSET(msg, 'x', sizeof(msg));

    /* The module identity used to be reported as zero for both fields. */
    XMEMSET(&version, 0, sizeof(version));
    Csm_GetVersionInfo(&version);
    if (version.moduleID != WOLFSSL_CSM_MODULE_ID) {
        printf("Csm_GetVersionInfo did not report the module ID");
        return -1;
    }

    detCalls = 0;
    detModuleId = 0;
    detApiId = 0;
    detErrorId = 0;

    /* A NULL output pointer is CSM_E_PARAM_POINTER, which the specification
     * numbers 0x01. */
    if (Csm_MacGenerate(5U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
                NULL, &macSz) != E_NOT_OK) {
        printf("a NULL MAC buffer was accepted");
        return -1;
    }

    if (detCalls != 1) {
        printf("the DET was called %d times, expected once", detCalls);
        return -1;
    }
    if (detModuleId != WOLFSSL_CSM_MODULE_ID) {
        printf("wrong module ID reported to the DET");
        return -1;
    }
    if (detErrorId != WOLFSSL_CSM_E_PARAM_POINTER) {
        printf("error ID 0x%02X reported, expected 0x%02X",
                detErrorId, WOLFSSL_CSM_E_PARAM_POINTER);
        return -1;
    }
    if (detApiId != WOLFSSL_CSM_API_ID_MAC_GENERATE) {
        printf("wrong API ID reported to the DET");
        return -1;
    }

    /* A re-init refused because a job is still open is the one failure a
     * caller cannot see any other way: Csm_Init() returns void, so without a
     * DET report the old heap, devId and keystore would stay in force with
     * nothing said. */
    Csm_Init(NULL);
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, msg, BLOCK_SIZE)
            != E_OK ||
            Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, msg,
                BLOCK_SIZE) != E_OK) {
        printf("could not provision for the refused init");
        return -1;
    }
    if (Csm_Encrypt(6U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            != E_OK) {
        printf("could not start a job to hold a slot");
        return -1;
    }

    detCalls = 0;
    detModuleId = 0;
    detApiId = 0xFE;
    detErrorId = 0;

    Csm_Init(NULL);

    if (detCalls != 1) {
        printf("the refused Csm_Init reported %d times, expected once",
                detCalls);
        return -1;
    }
    if (detErrorId != WOLFSSL_CSM_E_INIT_FAILED) {
        printf("error ID 0x%02X reported for the refused init, expected 0x%02X",
                detErrorId, WOLFSSL_CSM_E_INIT_FAILED);
        return -1;
    }
    if (detApiId != WOLFSSL_CSM_API_ID_INIT) {
        printf("wrong API ID reported for the refused init");
        return -1;
    }

    /* Cancel rather than FINISH, so this also covers the remedy the refusal
     * points the caller at. */
    if (Csm_CancelJob(6U, CRYPTO_OPERATIONMODE_FINISH) != E_OK) {
        printf("could not cancel the job holding the slot\n");
        return -1;
    }
    Csm_Init(NULL);

    return 0;
}
#endif /* WOLFSSL_AUTOSAR_CMAC */
#endif /* WOLFSSL_AUTOSAR_DET */


/* The job slot lifecycle, and the key lengths the keystore can hold.
 *
 * Neither had a test. The lifecycle paths matter because a job that fails
 * mid-stream used to keep its slot: the next START for that jobId claimed a
 * second one while FindJobSlot() kept returning the stale first, so UPDATE and
 * FINISH ran on the old context -- encrypting under the previous key and
 * reporting success. Repeat that and MAX_JOBS runs out.
 *
 * returns 0 on success */
static int joblife_test(void)
{
    uint8  cipher[BLOCK_SIZE * 2];
    uint8  plain[BLOCK_SIZE * 2];
    uint32 cipherSz, plainSz;
    int    i;
    int    lengthsRun = 0;
    const uint8 msg[BLOCK_SIZE] = {
        'j','o','b',' ','l','i','f','e',
        'c','y','c','l','e',' ','!','!'
    };
    const uint8 iv[BLOCK_SIZE] = {
        '1','2','3','4','5','6','7','8',
        '9','0','a','b','c','d','e','f'
    };
    /* 16, 24 and 32 byte keys, plus a length that is not an AES key */
    const uint8 k16[16] = {
        'k','e','y','1','2','8','b','i','t','s','.','.','.','.','.','.'
    };
    const uint8 k24[24] = {
        'k','e','y','1','9','2','b','i','t','s','.','.',
        '.','.','.','.','.','.','.','.','.','.','.','.'
    };
    const uint8 k32[32] = {
        'k','e','y','2','5','6','b','i','t','s','.','.','.','.','.','.',
        '.','.','.','.','.','.','.','.','.','.','.','.','.','.','.','.'
    };
    /* Not an AES key length, and short enough for the smallest keystore slot
     * a build can have: the slot is sized by AES_MAX_KEY_SIZE, so it is 16
     * bytes where AES-192 and AES-256 are compiled out, and a longer decoy
     * would be refused by the keystore rather than by the job -- which is the
     * refusal under test. */
    const uint8 kbad[8] = {
        'n','o','t','a','n','a','e','s'
    };

    /* one key slot, so the plain services have nothing to disambiguate */
    Csm_Init(NULL);

    if (Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv, BLOCK_SIZE)
            != E_OK) {
        printf("could not set the IV");
        return -1;
    }

    /* --- every AES key length this build has --- *
     *
     * Only the lengths it has: AES-192 and AES-256 can be compiled out, and
     * then the keystore slot itself is smaller (it is sized by
     * AES_MAX_KEY_SIZE), so Csm_KeyElementSet() rightly refuses the longer
     * key and a test demanding all three would fail a configuration the
     * driver supports correctly. */
    for (i = 0; i < 3; i++) {
        const uint8* key = (i == 0) ? k16 : ((i == 1) ? k24 : k32);
        uint32 keySz = (i == 0) ? 16U : ((i == 1) ? 24U : 32U);

        if (keySz > (uint32)(AES_MAX_KEY_SIZE / WOLFSSL_BIT_SIZE)) {
            continue;
        }
    #ifndef WOLFSSL_AES_128
        if (keySz == 16U) {
            continue;
        }
    #endif
    #ifndef WOLFSSL_AES_192
        if (keySz == 24U) {
            continue;
        }
    #endif
    #ifndef WOLFSSL_AES_256
        if (keySz == 32U) {
            continue;
        }
    #endif

        if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key, keySz)
                != E_OK) {
            printf("could not set a %u byte key", (unsigned int)keySz);
            return -1;
        }
        lengthsRun++;

        cipherSz = 0;
        if (Csm_Encrypt(20U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
                    cipher, &cipherSz) != E_OK) {
            printf("encrypt failed with a %u byte key", (unsigned int)keySz);
            return -1;
        }

        plainSz = 0;
        if (Csm_Decrypt(21U, CRYPTO_OPERATIONMODE_SINGLECALL, cipher,
                    BLOCK_SIZE, plain, &plainSz) != E_OK ||
                XMEMCMP(plain, msg, BLOCK_SIZE) != 0) {
            printf("round trip failed with a %u byte key",
                    (unsigned int)keySz);
            return -1;
        }
    }

    /* At least one length has to have run, or the loop above proved nothing
     * in this configuration. */
    if (lengthsRun == 0) {
        printf("no AES key length was exercised");
        return -1;
    }

    /* A stored key whose length is not an AES key length is refused by the
     * job that tries to use it, not by the keystore -- see kbad above for why
     * it is as short as it is. */
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, kbad,
                (uint32)sizeof(kbad)) != E_OK) {
        printf("could not store a %u byte key",
                (unsigned int)sizeof(kbad));
        return -1;
    }
    cipherSz = 0;
    if (Csm_Encrypt(22U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
                cipher, &cipherSz) != E_NOT_OK) {
        printf("a %u byte key was accepted as an AES key\n",
                (unsigned int)sizeof(kbad));
        return -1;
    }

    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, k16, 16U)
            != E_OK) {
        printf("could not restore the key");
        return -1;
    }

    /* --- a START on a job that is already active restarts it --- */
    if (Csm_Encrypt(23U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            != E_OK) {
        printf("could not start a streaming job");
        return -1;
    }
    /* feed it a block, then START again: the restart must discard that state,
     * so the result equals a single shot over one block */
    cipherSz = 0;
    if (Csm_Encrypt(23U, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE,
                cipher, &cipherSz) != E_OK) {
        printf("could not update a streaming job");
        return -1;
    }
    if (Csm_Encrypt(23U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            != E_OK) {
        printf("could not restart an active job");
        return -1;
    }
    XMEMSET(cipher, 0, sizeof(cipher));
    cipherSz = 0;
    if (Csm_Encrypt(23U,
                CRYPTO_OPERATIONMODE_UPDATE | CRYPTO_OPERATIONMODE_FINISH,
                msg, BLOCK_SIZE, cipher, &cipherSz) != E_OK) {
        printf("could not finish the restarted job");
        return -1;
    }
    XMEMSET(plain, 0, sizeof(plain));
    plainSz = 0;
    if (Csm_Decrypt(24U, CRYPTO_OPERATIONMODE_SINGLECALL, cipher, BLOCK_SIZE,
                plain, &plainSz) != E_OK ||
            XMEMCMP(plain, msg, BLOCK_SIZE) != 0) {
        printf("the restarted job did not encrypt from the start\n");
        return -1;
    }

    /* --- a restart that FAILS must not leave the old job runnable ---
     *
     * The dangerous order is: resolve and validate the new key first, retire
     * the old slot only once that has worked. A restart failing on the key --
     * provisioned away, or stored at a length AES does not take -- then
     * reported E_NOT_OK while the previous context stayed in the table, so an
     * UPDATE went on producing ciphertext under the key the caller had just
     * replaced, and the slot stayed claimed, which now also blocks
     * reconfiguration. */
    if (Csm_Encrypt(25U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            != E_OK) {
        printf("could not start the job to restart");
        return -1;
    }
    cipherSz = 0;
    if (Csm_Encrypt(25U, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE, cipher,
                &cipherSz) != E_OK) {
        printf("could not update the job to restart");
        return -1;
    }

    /* Replace the key with one no job can use, then restart: START fails. */
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, kbad,
                (uint32)sizeof(kbad)) != E_OK) {
        printf("could not store the unusable key");
        return -1;
    }
    if (Csm_Encrypt(25U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            != E_NOT_OK) {
        printf("a restart with an unusable key was accepted\n");
        return -1;
    }

    /* The old context has to be gone with it: an UPDATE finds nothing rather
     * than encrypting under the key that was replaced. */
    cipherSz = 0;
    if (Csm_Encrypt(25U, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE, cipher,
                &cipherSz) == E_OK) {
        printf("a failed restart left the job running under the old key\n");
        return -1;
    }
    /* And the slot with it, or a re-init would be refused forever. */
    if (Csm_CancelJob(25U, CRYPTO_OPERATIONMODE_FINISH) == E_OK) {
        printf("a failed restart kept its job slot\n");
        return -1;
    }

    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, k16, 16U)
            != E_OK) {
        printf("could not restore the key after the failed restart");
        return -1;
    }

    /* --- a job that fails after START must not keep its slot ---
     *
     * The failure has to happen in UPDATE, after a slot has been claimed: a
     * key the driver rejects fails in START, before there is anything to leak.
     * A NULL output buffer is what reaches wc_AesCbcEncrypt() and comes back
     * BAD_FUNC_ARG.
     *
     * Each iteration uses a distinct jobId, so a leaked slot is never reused
     * by the restart path -- the table simply runs out, which is what used to
     * happen. */
    {
        int n;

        for (n = 0; n < MAX_JOBS + 2; n++) {
            uint32 id = 30U + (uint32)n;

            if (Csm_Encrypt(id, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL,
                        NULL) != E_OK) {
                printf("could not start job %u\n", (unsigned int)id);
                return -1;
            }
            if (Csm_Encrypt(id, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE,
                        NULL, &cipherSz) != E_NOT_OK) {
                printf("a NULL output buffer was accepted\n");
                return -1;
            }
        }

        cipherSz = 0;
        if (Csm_Encrypt(25U, CRYPTO_OPERATIONMODE_SINGLECALL, msg, BLOCK_SIZE,
                    cipher, &cipherSz) != E_OK) {
            printf("the job table did not recover from failed jobs\n");
            return -1;
        }
    }

    /* --- FINISH on a job that was never started is an error --- */
    cipherSz = 0;
    if (Csm_Encrypt(26U, CRYPTO_OPERATIONMODE_FINISH, msg, BLOCK_SIZE, cipher,
                &cipherSz) != E_NOT_OK) {
        printf("FINISH on an unstarted job reported success\n");
        return -1;
    }

    return 0;
}


/* Csm_Init() called again while jobs are still open.
 *
 * The port documents a repeat Csm_Init() as re-reading the configuration, and
 * the driver has to tear down what the previous one built: a job still holding
 * a slot is freed rather than abandoned, which would leak a device-backed
 * context below and leave the table full. Nothing covered that.
 *
 * returns 0 on success */
static int reinit_test(void)
{
    uint8  cipher[BLOCK_SIZE * 2];
    uint32 cipherSz;
    int    n;
    const uint8 msg[BLOCK_SIZE] = {
        'r','e','i','n','i','t',' ','t','e','s','t',' ','!','!','!','!'
    };
    const uint8 key[BLOCK_SIZE] = {
        'k','e','y','f','o','r','r','e','i','n','i','t','1','2','3','4'
    };
    const uint8 iv[BLOCK_SIZE] = {
        '1','2','3','4','5','6','7','8',
        '9','0','a','b','c','d','e','f'
    };

    /* provision() helper equivalent: one key, one IV, known slots */
    Csm_Init(NULL);
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
                BLOCK_SIZE) != E_OK ||
            Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                BLOCK_SIZE) != E_OK) {
        printf("could not provision");
        return -1;
    }

    /* Fill the job table with streams and finish none of them. */
    for (n = 0; n < MAX_JOBS; n++) {
        if (Csm_Encrypt(40U + (uint32)n, CRYPTO_OPERATIONMODE_START, NULL, 0,
                    NULL, NULL) != E_OK) {
            printf("could not start job %d of %d", n, MAX_JOBS);
            return -1;
        }
    }

    /* With every slot taken the next START has to be refused -- otherwise the
     * rest of this test proves nothing. */
    if (Csm_Encrypt(60U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            == E_OK) {
        printf("job table did not fill up\n");
        return -1;
    }

    /* A re-init now has to be REFUSED: those jobs still own their slots, and
     * freeing the contexts under them would be a use-after-free against the
     * unlocked wc_AesCbcEncrypt() they are in. Observable because the refusal
     * leaves the table exactly as it was. */
    Csm_Init(NULL);
    if (Csm_Encrypt(61U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            == E_OK) {
        printf("Csm_Init tore down the job table with jobs still open\n");
        return -1;
    }

    /* FINISH them, which is what the caller is expected to do first. */
    for (n = 0; n < MAX_JOBS; n++) {
        cipherSz = 0;
        if (Csm_Encrypt(40U + (uint32)n, CRYPTO_OPERATIONMODE_FINISH, NULL, 0,
                    NULL, &cipherSz) != E_OK) {
            printf("could not finish job %d", n);
            return -1;
        }
    }

    /* Now the re-init goes through. */
    Csm_Init(NULL);

    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
                BLOCK_SIZE) != E_OK ||
            Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                BLOCK_SIZE) != E_OK) {
        printf("could not re-provision after Csm_Init");
        return -1;
    }

    /* The whole table must be available again. */
    for (n = 0; n < MAX_JOBS; n++) {
        if (Csm_Encrypt(70U + (uint32)n, CRYPTO_OPERATIONMODE_START, NULL, 0,
                    NULL, NULL) != E_OK) {
            printf("slot %d was not cleared by Csm_Init\n", n);
            return -1;
        }
    }

    /* And a jobId from before the re-init no longer has a context: its UPDATE
     * finds nothing rather than something stale. */
    cipherSz = 0;
    if (Csm_Encrypt(40U, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE, cipher,
                &cipherSz) == E_OK) {
        printf("a job from before Csm_Init still had a context\n");
        return -1;
    }

    /* Leave nothing open for the next case. */
    for (n = 0; n < MAX_JOBS; n++) {
        cipherSz = 0;
        (void)Csm_Encrypt(70U + (uint32)n, CRYPTO_OPERATIONMODE_FINISH, NULL,
                0, NULL, &cipherSz);
    }

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FREE)
    /* The part that is otherwise invisible: clearing the table would leave
     * the tests above just as green, because XMEMSET() alone frees the slots
     * for reuse. What it would NOT do is free the contexts in them. With a
     * device registered, wc_AesFree() notifies it, so a freed context can be
     * told from an abandoned one. */
    {
        Csm_ConfigType config = WOLFSSL_CSM_CONFIG_DEFAULT;
        int before;

        if (wolfCrypt_Init() != 0 ||
                wc_CryptoCb_RegisterDevice(WOLFSSL_AUTOSAR_TEST_DEVID,
                    autosarTestCryptoCb, NULL) != 0) {
            printf("could not register the test device");
            return -1;
        }

        config.devId = WOLFSSL_AUTOSAR_TEST_DEVID;
        Csm_Init(&config);
        if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
                    BLOCK_SIZE) != E_OK ||
                Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                    BLOCK_SIZE) != E_OK) {
            printf("could not provision for the device case");
            return -1;
        }

        for (n = 0; n < FEW_JOBS; n++) {
            if (Csm_Encrypt(80U + (uint32)n, CRYPTO_OPERATIONMODE_START, NULL,
                        0, NULL, NULL) != E_OK) {
                printf("could not start job %d with a devId", n);
                return -1;
            }
        }

        /* FINISH frees the context, and with a device registered the free is
         * visible: wc_AesFree() notifies it under WOLF_CRYPTO_CB_FREE. This is
         * what makes "the slot was released" distinguishable from "the table
         * entry was merely cleared" -- the distinction Csm_Init() now refuses
         * to blur by tearing down a job that is still open. */
        cbFree = 0;
        before = cbFree;
        for (n = 0; n < FEW_JOBS; n++) {
            cipherSz = 0;
            if (Csm_Encrypt(80U + (uint32)n, CRYPTO_OPERATIONMODE_FINISH, NULL,
                        0, NULL, &cipherSz) != E_OK) {
                printf("could not finish device job %d", n);
                return -1;
            }
        }
        if (cbFree <= before) {
            printf("FINISH abandoned the device contexts instead of freeing"
                   " them\n");
            return -1;
        }

        (void)wc_CryptoCb_UnRegisterDevice(WOLFSSL_AUTOSAR_TEST_DEVID);
    }
#endif

    /* Leave the table empty for whatever runs next. */
    Csm_Init(NULL);
    return 0;
}


/* Csm_CancelJob(): the way out for a job that will never be finished.
 *
 * A slot is held from START until FINISH, and Csm_Init() refuses to
 * reconfigure while any slot is held -- so without a cancel, one abandoned
 * stream would hold its slot for the life of the ECU and wedge every later
 * Csm_Init(): the configuration could never be changed again. CryIf_CancelJob
 * used to be a stub returning E_NOT_OK.
 *
 * returns 0 on success */
static int cancel_test(void)
{
    uint8  cipher[BLOCK_SIZE * 2];
    uint32 cipherSz;
    int    n;
    const uint8 msg[BLOCK_SIZE] = {
        'c','a','n','c','e','l',' ','t','e','s','t',' ','!','!','!','!'
    };
    const uint8 key[BLOCK_SIZE] = {
        'k','e','y','f','o','r','c','a','n','c','e','l','1','2','3','4'
    };
    const uint8 iv[BLOCK_SIZE] = {
        '1','2','3','4','5','6','7','8',
        '9','0','a','b','c','d','e','f'
    };

    Csm_Init(NULL);
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
                BLOCK_SIZE) != E_OK ||
            Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                BLOCK_SIZE) != E_OK) {
        printf("could not provision");
        return -1;
    }

    /* A job that owns no slot has nothing to cancel, and says so rather than
     * reporting a success the caller would read as "it is released now". */
    if (Csm_CancelJob(90U, CRYPTO_OPERATIONMODE_FINISH) == E_OK) {
        printf("cancelling a job that was never started reported success\n");
        return -1;
    }

    if (Csm_Encrypt(90U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            != E_OK) {
        printf("could not start the job to cancel");
        return -1;
    }
    if (Csm_CancelJob(90U, CRYPTO_OPERATIONMODE_FINISH) != E_OK) {
        printf("cancelling an open job failed\n");
        return -1;
    }

    /* The context went with the slot: an UPDATE finds nothing rather than
     * something stale. */
    cipherSz = (uint32)sizeof(cipher);
    if (Csm_Encrypt(90U, CRYPTO_OPERATIONMODE_UPDATE, msg, BLOCK_SIZE, cipher,
                &cipherSz) == E_OK) {
        printf("a cancelled job still had its context\n");
        return -1;
    }

    /* And cancelling it again finds nothing to free, rather than freeing the
     * same context twice. */
    if (Csm_CancelJob(90U, CRYPTO_OPERATIONMODE_FINISH) == E_OK) {
        printf("a job was cancelled twice\n");
        return -1;
    }

    /* The wedge itself: fill the table, abandon every job, and show that
     * cancelling them is enough to let a re-init through. */
    for (n = 0; n < MAX_JOBS; n++) {
        if (Csm_Encrypt(91U + (uint32)n, CRYPTO_OPERATIONMODE_START, NULL, 0,
                    NULL, NULL) != E_OK) {
            printf("could not start job %d of %d", n, MAX_JOBS);
            return -1;
        }
    }

    Csm_Init(NULL);
    if (Csm_Encrypt(200U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
            == E_OK) {
        printf("Csm_Init tore down the job table with jobs still open\n");
        return -1;
    }

    for (n = 0; n < MAX_JOBS; n++) {
        if (Csm_CancelJob(91U + (uint32)n, CRYPTO_OPERATIONMODE_FINISH)
                != E_OK) {
            printf("could not cancel abandoned job %d", n);
            return -1;
        }
    }

    Csm_Init(NULL);
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
                BLOCK_SIZE) != E_OK ||
            Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                BLOCK_SIZE) != E_OK) {
        printf("could not re-provision after the cancels");
        return -1;
    }
    for (n = 0; n < MAX_JOBS; n++) {
        if (Csm_Encrypt(120U + (uint32)n, CRYPTO_OPERATIONMODE_START, NULL, 0,
                    NULL, NULL) != E_OK) {
            printf("slot %d was not available after cancel and re-init\n", n);
            return -1;
        }
    }
    for (n = 0; n < MAX_JOBS; n++) {
        cipherSz = 0;
        (void)Csm_Encrypt(120U + (uint32)n, CRYPTO_OPERATIONMODE_FINISH, NULL,
                0, NULL, &cipherSz);
    }

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FREE)
    /* Releasing the slot is not the same as freeing the context in it, and
     * only a device can tell the difference: wc_AesFree() notifies one under
     * WOLF_CRYPTO_CB_FREE. Without this, a cancel that leaked every context
     * would pass each check above. */
    {
        Csm_ConfigType config = WOLFSSL_CSM_CONFIG_DEFAULT;
        int before;

        if (wolfCrypt_Init() != 0 ||
                wc_CryptoCb_RegisterDevice(WOLFSSL_AUTOSAR_TEST_DEVID,
                    autosarTestCryptoCb, NULL) != 0) {
            printf("could not register the test device");
            return -1;
        }

        config.devId = WOLFSSL_AUTOSAR_TEST_DEVID;
        Csm_Init(&config);
        if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, key,
                    BLOCK_SIZE) != E_OK ||
                Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, iv,
                    BLOCK_SIZE) != E_OK) {
            printf("could not provision for the device case");
            return -1;
        }

        if (Csm_Encrypt(130U, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
                != E_OK) {
            printf("could not start the device job to cancel");
            return -1;
        }

        cbFree = 0;
        before = cbFree;
        if (Csm_CancelJob(130U, CRYPTO_OPERATIONMODE_FINISH) != E_OK) {
            printf("could not cancel the device job\n");
            return -1;
        }
        if (cbFree <= before) {
            printf("cancel released the slot without freeing the context\n");
            return -1;
        }

        (void)wc_CryptoCb_UnRegisterDevice(WOLFSSL_AUTOSAR_TEST_DEVID);
    }
#endif

    /* Leave the table empty for whatever runs next. */
    Csm_Init(NULL);
    return 0;
}


#ifndef SINGLE_THREADED
/* Cipher jobs running against a concurrent Csm_Init().
 *
 * A START is a sequence, not a step: it copies the key out of the keystore,
 * checks it, reads the configured devId and only then claims a slot. Slot
 * ownership is what tells Csm_Init() a reconfiguration is unsafe, so before
 * the gate added for this, the whole of Crypto_Init() could run inside that
 * window -- finding no slot in use, wiping the keystore and publishing a new
 * heap and devId -- and leave the job building a context for the new device
 * out of the old configuration's key.
 *
 * Be clear about what this test does and does not do. It drives START, UPDATE,
 * FINISH and Csm_Init() across each other thousands of times and holds one
 * invariant: a job that ran to completion ran under the key that was
 * provisioned. It does NOT fail deterministically when the gate is removed --
 * checked by removing it -- because the window is a time-of-check race whose
 * accesses are all still taken under a lock, so a sanitizer has nothing to
 * report, and a software-only job keyed from the previous configuration
 * produces the right answer anyway. The gate's correctness rests on the lock
 * discipline; this test is what catches a crash, a deadlock, a leaked slot or
 * a wrong answer in that traffic, and under a sanitizer it also covers the
 * configuration publication paths. A job that fails is not a failure of the
 * test: a re-init between the key being provisioned and the job starting
 * legitimately leaves nothing to resolve.
 *
 * returns 0 on success */
#define GATE_THREADS 4
#define GATE_ROUNDS  150
#define GATE_INITS   (GATE_ROUNDS * GATE_THREADS)

static const uint8 gateKey[BLOCK_SIZE] = {
    'g','a','t','e','k','e','y','0','1','2','3','4','5','6','7','8'
};
static const uint8 gateIv[BLOCK_SIZE] = {
    'g','a','t','e','i','v','0','0','1','2','3','4','5','6','7','8'
};
static const uint8 gateMsg[BLOCK_SIZE] = {
    'g','a','t','e',' ','m','e','s','s','a','g','e',' ','!','!','!'
};
/* AES-128-CBC of gateMsg under gateKey and gateIv, filled in by the test
 * itself before the threads start, so this does not hard-code a vector the
 * rest of the suite already proves. */
static uint8 gateExpect[BLOCK_SIZE];
/* One slot per worker, read only after every join. A single shared flag would
 * be a data race between two workers finding a wrong answer at once -- in a
 * test whose point is to be run under a race detector, which would then report
 * the test rather than the driver. */
static int gateWrongAnswer[GATE_THREADS];

static THREAD_RETURN WOLFSSL_THREAD gate_worker(void* arg)
{
    size_t slot = (size_t)arg;
    uint32 id = 300U + (uint32)slot;
    int    i;

    for (i = 0; i < GATE_ROUNDS; i++) {
        uint8  cipher[BLOCK_SIZE];
        uint32 cipherSz = (uint32)sizeof(cipher);

        /* Re-provision every round: a concurrent re-init may have wiped the
         * keystore. Either call failing is that race, not an error. */
        if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, gateKey,
                    BLOCK_SIZE) != E_OK ||
                Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, gateIv,
                    BLOCK_SIZE) != E_OK) {
            continue;
        }

        if (Csm_Encrypt(id, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL)
                != E_OK) {
            continue;
        }

        if (Csm_Encrypt(id, CRYPTO_OPERATIONMODE_UPDATE, gateMsg, BLOCK_SIZE,
                    cipher, &cipherSz) != E_OK) {
            /* A failed UPDATE releases the slot by itself. */
            continue;
        }

        /* This is the part that cannot be excused by a race: the job ran to
         * completion, so it ran under the key that was provisioned. */
        if (cipherSz != BLOCK_SIZE ||
                XMEMCMP(cipher, gateExpect, BLOCK_SIZE) != 0) {
            gateWrongAnswer[slot] = 1;
        }

        cipherSz = 0;
        (void)Csm_Encrypt(id, CRYPTO_OPERATIONMODE_FINISH, NULL, 0, NULL,
                &cipherSz);
    }

    WOLFSSL_RETURN_FROM_THREAD(0);
}

/* A fixed number of re-inits rather than a stop flag: a plain flag read by one
 * thread and written by another is itself a data race, and this test exists to
 * be run under a race detector. If this thread finishes first the overlap ends
 * early, which costs coverage and nothing else. */
static THREAD_RETURN WOLFSSL_THREAD gate_initer(void* arg)
{
    int i;

    (void)arg;

    for (i = 0; i < GATE_INITS; i++) {
        Csm_Init(NULL);
    }

    WOLFSSL_RETURN_FROM_THREAD(0);
}

static int gate_test(void)
{
    THREAD_TYPE workers[GATE_THREADS];
    THREAD_TYPE initer;
    uint32 cipherSz = (uint32)sizeof(gateExpect);
    size_t i;

    Csm_Init(NULL);
    if (Csm_KeyElementSet(CBC_KEY_SLOT, CRYPTO_KE_CIPHER_KEY, gateKey,
                BLOCK_SIZE) != E_OK ||
            Csm_KeyElementSet(CBC_IV_SLOT, CRYPTO_KE_CIPHER_IV, gateIv,
                BLOCK_SIZE) != E_OK) {
        printf("could not provision");
        return -1;
    }

    /* The answer every thread has to agree with, taken quietly first. */
    if (Csm_Encrypt(299U, CRYPTO_OPERATIONMODE_SINGLECALL, gateMsg,
                BLOCK_SIZE, gateExpect, &cipherSz) != E_OK ||
            cipherSz != BLOCK_SIZE) {
        printf("could not compute the expected ciphertext");
        return -1;
    }

    for (i = 0; i < GATE_THREADS; i++) {
        gateWrongAnswer[i] = 0;
    }

    for (i = 0; i < GATE_THREADS; i++) {
        if (wolfSSL_NewThread(&workers[i], gate_worker, (void*)i) != 0) {
            printf("could not start worker %d", (int)i);
            return -1;
        }
    }
    if (wolfSSL_NewThread(&initer, gate_initer, NULL) != 0) {
        printf("could not start the re-init thread");
        for (i = 0; i < GATE_THREADS; i++) {
            (void)wolfSSL_JoinThread(workers[i]);
        }
        return -1;
    }

    for (i = 0; i < GATE_THREADS; i++) {
        if (wolfSSL_JoinThread(workers[i]) != 0) {
            printf("could not join worker %d", (int)i);
            return -1;
        }
    }
    if (wolfSSL_JoinThread(initer) != 0) {
        printf("could not join the re-init thread");
        return -1;
    }

    for (i = 0; i < GATE_THREADS; i++) {
        if (gateWrongAnswer[i]) {
            printf("worker %d ran a job to completion and produced the wrong"
                   " ciphertext\n", (int)i);
            return -1;
        }
    }

    /* Leave a clean table and keystore behind. */
    Csm_Init(NULL);
    return 0;
}
#endif /* !SINGLE_THREADED */


/* takes in test function test() and name of test
 * returns 1 if test failed and 0 if passed */
static int run_test(int(test)(void), const char* name)
{
    printf("%s", name);
    if (test() != 0) {
        printf("fail\n");
        return 1;
    }
    else {
        printf("pass\n");
    }
    return 0;
}


/* AES block size */
int main(int argc, char* argv[])
{
    int ret = 0;
    (void)argv;
    (void)argc;

    wolfSSL_Debugging_ON();
    Csm_Init(NULL);

    ret |= run_test(singleshot_test, "singleshot_test ... ");
    ret |= run_test(update_test, "update_test ... ");
    ret |= run_test(random_test, "random_test ... ");
    ret |= run_test(joblife_test, "joblife_test ... ");
    ret |= run_test(reinit_test, "reinit_test ... ");
    ret |= run_test(cancel_test, "cancel_test ... ");
#ifndef SINGLE_THREADED
    ret |= run_test(gate_test, "gate_test ... ");
#endif
    ret |= run_test(key_test, "key_test ... ");
#ifdef WOLF_CRYPTO_CB
    ret |= run_test(devid_test, "devid_test ... ");
#endif
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_PRIVATE_KEY_ID)
    ret |= run_test(keyhandle_test, "keyhandle_test ... ");
#ifdef WOLFSSL_AUTOSAR_CMAC
    ret |= run_test(machandle_test, "machandle_test ... ");
#endif
#endif
#if defined(WOLFSSL_AUTOSAR_DET) && defined(WOLFSSL_AUTOSAR_CMAC)
    ret |= run_test(det_test, "det_test ... ");
#endif
#ifdef WOLFSSL_AUTOSAR_CMAC
    ret |= run_test(mac_test, "mac_test ... ");
#endif
#ifdef REDIRECTION_CONFIG
    ret |= run_test(redirect_test, "redirect_test ... ");
#endif /* REDIRECTION_CONFIG */
    /* last: it leaves a decoy cipher key in the keystore */
#if defined(WOLFSSL_AUTOSAR_CMAC) && MAX_KEYSTORE > 2
    ret |= run_test(keysep_test, "keysep_test ... ");
#endif
    return ret;
}

#endif /* WOLFSSL_AUTOSAR */
