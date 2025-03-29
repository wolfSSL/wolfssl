/* wolfssl_AES_CTR.ino
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/*
The Advanced Encryption Standard (AES) is a specification for the encryption of electronic
data established by the U.S. National Institute of Standards and Technology (NIST) in 2001.

AES Counter mode (AES-CTR) is a "Block Cipher Mode of Operation" that
turns a block cipher into a stream cipher, as explained here:
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)

The wolfSSL AES algorithms in this sketch (e.g wc_AesCtrEncrypt) are just some of
many algorithms in the wolfSSL library. All are documented in the wolfSSL Manual at
https://www.wolfssl.com/documentation/manuals/wolfssl/group__AES.html

This sketch example demonstrates AES-CTR usage by first encrypting the input
data producing the cipher, then decrypt the cipher to reveal the original data.

Required user inputs
--------------------
1) Encryption Key
2) Initialization Vector ("iv")
3) The input data to be encrypted

Tested on
---------
Arduino UNO R4 WiFi (Renesas ARM Cortex M4)
Sparkfun MicroMod WiFi Function Board (ESP32-WROOM-32E)
Wemos D1 R32 Development Board (ESP32-WROOM-32)
Teensy 4.1 (ARM Cortex M7)

*/

#define  WOLFSSL_AES_CTR_EXAMPLE
#include <wolfssl.h>
#include <wolfssl/wolfcrypt/aes.h>

#if defined(NO_AES) or !defined(WOLFSSL_AES_COUNTER) or !defined(WOLFSSL_AES_128)
    /* edit user_settings.h in ~\Arduino\libraries\wolfssl\src
     *   e.g. for Windows:
     *      C:\Users\%USERNAME%\Documents\Arduino\libraries\wolfssl\src
     */
    #error "Missing AES, WOLFSSL_AES_COUNTER or WOLFSSL_AES_128"
#endif

/* macro to check for expected results */
#define ExpectIntEQ(p1, p2) if (p1 == p2) {                     \
                                Serial.println(F("OK"));        \
                             }                                  \
                             else {                             \
                                Serial.println(F("FAIL"));      \
                             }


/* USER INPUTS:
 * The Encryption Key (encKey) is confidential and must only be shared with
 * the intended recipient of the data. Length must be 16, 24, 32 or larger
 * multiples of AES_BLOCK_SIZE
 *
 * The initialization Vector (iv) is a nonce/counter (or 'salt') that is
 * incremented between each encryption to ensures no two ciphers are identical,
 * even if the input data is unchanged. Can be any length.
 *
 * The input data ("input") provides the bytes to be encrypted.
 * Must be 16, 24, 32 bytes, or larger multiples of AES_BLOCK_SIZE
 */

/* Choose one of these data sets, or provide your own. */
/* Example data set 1                                  */
byte encKey[] = {0x33,0x9a,0x28,0x9d,0x08,0x61,0xe8,0x34,
                 0x16,0xe5,0x8d,0xb7,0x58,0x33,0xdc,0x0a}; /* 16 bytes  */
byte     iv[] = {0x43,0x05,   0,   0,   0,   0,   0,   0,  /* Padded to */
                    0,   0,   0,   0,   0,   0,   0,   0}; /* 16 bytes  */
byte  input[] = {0x05,0x00,0x8c,0x0a,0x21,0x00,0x6a,0x00,
                 0x5c,0x00,0xff,0xff,0xc1,0xfc,0x25,0xc4}; /* 16 bytes  */

/*
 * Example data set 2
byte encKey[] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                 0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,
                 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                 0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66}; // 32 bytes

byte iv[] = "1234567890abcdef";

byte input[] = { // Now is the time for all w/o trailing 0
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20}; // 24 bytes
*/

/* create aes objects for encryption & decryption */
Aes aesEnc;
Aes aesDec;

/* Print out the data as HEX bytes with breaks every 8 bytes */
void reportData(byte * data, int sz) {
    int i;
    for (i = 0; i < sz; i++) {
        if (data[i] < 0x10) {
            Serial.print(F("0"));
        }
        Serial.print(data[i], HEX);
        if (i < sz - 1) {
            if (((i + 1) % 8) == 0) {
                Serial.print(F(" | "));
            }
            else {
                Serial.print(F(" "));
            }
        }
    }
    Serial.println();
}

/*****************************************************************************/
/*****************************************************************************/
/* Arduino setup()                                                           */
/*****************************************************************************/
/*****************************************************************************/
void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 1000) ; /* wait for serial, up to 1 sec     */

    Serial.println();
    Serial.println();
    Serial.println(F("===== wolfSSL example: AES Counter mode ====="));
    Serial.print(F("wolfSSL library version: "));
    Serial.println(LIBWOLFSSL_VERSION_STRING);
    Serial.println();
}


/*****************************************************************************/
/*****************************************************************************/
/* Arduino loop()                                                            */
/*****************************************************************************/
/*****************************************************************************/
void loop() {
    memset(&aesEnc, 0, sizeof(Aes)); /* fill aesEnc with zeros               */
    memset(&aesDec, 0, sizeof(Aes)); /* ditto aesDec                         */

    /* --------------------------------------------------------------------- */
    /* Choose blkSize of be 16, 24, 32 or larger multiples of 8, based       */
    /* on sizeof(input) data. Uncomment the relevant lines from following:   */

    Serial.print(F("data set 1 ["));
    uint32_t blkSize = AES_BLOCK_SIZE * 1;   /* 16 bytes (for data set 1)    */

    /* Serial.print(F("data set 2 - "));                                     */
    /* uint32_t blkSize = AES_BLOCK_SIZE * 1.5; // 24 bytes (for data set 2) */

    /* Serial.print(F("my data set - "));                                    */
    /* uint32_t blkSize = AES_BLOCK_SIZE * n;   // choose an appropriate n    */

    Serial.print(F("blkSize: "));
    Serial.print(blkSize);
    Serial.println(F(" bytes]"));
    Serial.println();
    /* ----------------------------------------------------------------------*/

    byte cipher[blkSize]; /* for the encrypted data (or "cipher")            */
    byte output[blkSize]; /* for the deciphered data                         */
    memset(cipher, 0, blkSize); /* fill with zeros                           */
    memset(output, 0, blkSize); /* fill with zeros                           */

    /* initialize structures for encryption and decryption.                  */
    Serial.println(F("--- Encryption ..."));
    Serial.print(F("init aes (enc) : "));

    /* init aesEnc structure, with NULL heap hint, dev id not used.          */
    ExpectIntEQ(wc_AesInit(&aesEnc, NULL, INVALID_DEVID), 0);

    /* set up the key + salt in the AES encryption structure.                */
    Serial.print(F("load key (enc) : "));
    ExpectIntEQ(wc_AesSetKey(&aesEnc, encKey, blkSize, iv, AES_ENCRYPTION), 0);

    /* encrypt */
    Serial.print(F("encryption done: "));
    ExpectIntEQ(wc_AesCtrEncrypt(&aesEnc, cipher,
                                 input, sizeof(input) / sizeof(byte) ), 0);

    Serial.println();
    Serial.println(F("--- Decryption ..."));
    /* set up the key + salt in the AES decryption structure.                */
    Serial.print(F("init aes (dec) : "));

    /* init aesDec structure, with NULL heap hint, dev id not used.          */
    ExpectIntEQ(wc_AesInit(&aesDec, NULL, INVALID_DEVID), 0);

    /* set up the key + salt in an AES decryption structure.                 */
    Serial.print(F("load key (dec) : "));
    ExpectIntEQ(wc_AesSetKey(&aesDec, encKey, blkSize, iv, AES_ENCRYPTION), 0);

    /* decrypt                                                               */
    Serial.print(F("decryption done: "));
    ExpectIntEQ(wc_AesCtrEncrypt(&aesDec, output,
                                 cipher,  sizeof(cipher) / sizeof(byte)), 0);
    Serial.println();

    /* Test for bad args                                                     */
    Serial.println(F("--- Check for bad arguments ..."));
    Serial.print(F("Bad arguments 1: "));
    ExpectIntEQ(wc_AesCtrEncrypt(NULL,  output,
                                 cipher, sizeof(cipher) / sizeof(byte)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    Serial.print(F("Bad arguments 2: "));
    ExpectIntEQ(wc_AesCtrEncrypt(&aesDec, NULL,
                                 cipher,  sizeof(cipher) / sizeof(byte)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    Serial.print(F("Bad arguments 3: "));
    ExpectIntEQ(wc_AesCtrEncrypt(&aesDec, output,
                                 NULL,    sizeof(cipher) / sizeof(byte)),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Display data and results.                                             */
    Serial.println();
    Serial.println(F("--- Inputs ..."));
    Serial.print(F("key     : ")); reportData(encKey, sizeof(encKey));
    Serial.print(F("salt/iv : ")); reportData(iv,     sizeof(iv));
    Serial.print(F("data in : ")); reportData(input,  sizeof(input));

    Serial.println();
    Serial.println(F("--- Outputs ..."));
    Serial.print(F("cipher  : "));
    reportData(cipher, sizeof(cipher));
    Serial.print(F("decipher: "));
    reportData(output, sizeof(output));
    Serial.println();

    if (memcmp(input, output, sizeof(input)) == 0) {
        Serial.println(F("** SUCCESS ** deciphered data matches input data."));
    }
    else {
        Serial.print(F("*** FAILED *** deciphered & input data DO NOT MATCH."));
    }
    Serial.println();

    /* Free up resources associated with the aes structures.                 */
    wc_AesFree(&aesEnc);
    wc_AesFree(&aesDec);

    Serial.println(F("===== end ====="));

    while (1) {
        /* nothing */
    }
}
