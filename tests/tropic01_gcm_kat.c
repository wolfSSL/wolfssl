/* tropic01_gcm_kat.c
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

/* Known-answer test for the AES-GCM branch of the TROPIC01 crypto
 * callback (Tropic01_CryptoCb).
 *
 * The callback swaps the device-resident key into the caller's Aes
 * context and runs the GCM operation in software. The GHASH subkey H
 * must be derived from the device key that is actually used for the
 * operation, not left over from the key the caller originally set on
 * the context.
 *
 * The KAT vectors are computed with AES-128-GCM under the TROPIC01Sim
 * default AES key (object-store R-memory slot 0, byte i is i*0x11 mod
 * 256; the callback passes the first keyLen bytes of the slot to the
 * software path).
 *
 * The test drives the callback the same way TLS does: the context is
 * created with WOLF_TROPIC01_DEVID and set with a caller (decoy) key,
 * so the pre-operation context holds H for the decoy key. Only a
 * callback that re-derives H from the device key it swaps in produces
 * the KAT ciphertext tag.
 *
 * Build (against the installed libwolfssl and libtropic v0.1.0, see
 * .github/workflows/tropic01-sim.yml): the installed headers carry no
 * options.h, so the feature macros of the library build must be
 * repeated on the command line.
 *   gcc -Wall -Wextra -O2 -DWOLFSSL_TROPIC01 -DWOLF_CRYPTO_CB \
 *       -DHAVE_AESGCM \
 *       -I<libtropic>/include -I<prefix>/include \
 *       tests/tropic01_gcm_kat.c \
 *       <libtropic>/hal/port/unix/lt_port_unix_tcp.c \
 *       -L<prefix>/lib -L<libtropic>/build \
 *       -L<libtropic>/build/trezor_crypto \
 *       -lwolfssl -ltropic -ltrezor_crypto -lm \
 *       -o tropic01_gcm_kat
 *
 * Run with the TROPIC01Sim tcp_server listening (TROPIC01_SIM_HOST,
 * TROPIC01_SIM_PORT). Exits 0 on pass, 1 on fail.
 */

#include <stdio.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/tropicsquare/tropic01.h>

#define KAT_PT_SZ    64
#define KAT_IV_SZ    12
#define KAT_AAD_SZ   16
#define KAT_TAG_SZ   16

/* Caller (decoy) session key the test sets on the context, standing
 * in for the TLS key. The buggy callback leaves H derived from this
 * key. */
static const byte kat_key_decoy[AES_128_KEY_SIZE] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
};

static const byte kat_iv[KAT_IV_SZ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
};

static const byte kat_pt[KAT_PT_SZ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

static const byte kat_aad[KAT_AAD_SZ] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
};

/* AES-128-GCM(kat_key_dev, kat_iv, kat_pt, kat_aad). */
static const byte kat_ct[KAT_PT_SZ] = {
    0x2b, 0xd4, 0x35, 0xc7, 0xaa, 0x92, 0x89, 0x67,
    0x97, 0x31, 0x23, 0x94, 0x1c, 0x80, 0x4f, 0xe2,
    0x1d, 0x0e, 0x9f, 0x59, 0x60, 0xa4, 0xf8, 0x9a,
    0x97, 0x47, 0xc0, 0x55, 0xfd, 0x16, 0x98, 0x37,
    0x16, 0xa8, 0xf0, 0x77, 0x35, 0x2d, 0x6f, 0xd7,
    0x5a, 0x84, 0xa1, 0xde, 0xfe, 0x3c, 0xfb, 0xcf,
    0xcf, 0x01, 0xb6, 0x8a, 0x9d, 0xf9, 0xbb, 0x85,
    0xc8, 0x21, 0x1d, 0xd1, 0x07, 0xc6, 0x76, 0x23
};

static const byte kat_tag[KAT_TAG_SZ] = {
    0xd4, 0x97, 0xe8, 0x39, 0xc9, 0xdf, 0xdc, 0x3b,
    0x56, 0xac, 0x9e, 0x79, 0x94, 0xb0, 0xaa, 0x21
};

/* Default host pairing keys (libtropic sh0 sample), matching the
 * TROPIC01Sim object store defaults. */
static const byte kat_sh0_priv[TROPIC01_PAIRING_KEY_SIZE] = {
    0xd0, 0x99, 0x92, 0xb1, 0xf1, 0x7a, 0xbc, 0x4d,
    0xb9, 0x37, 0x17, 0x68, 0xa2, 0x7d, 0xa0, 0x5b,
    0x18, 0xfa, 0xb8, 0x56, 0x13, 0xa7, 0x84, 0x2c,
    0xa6, 0x4c, 0x79, 0x10, 0xf2, 0x2e, 0x71, 0x6b
};

static const byte kat_sh0_pub[TROPIC01_PAIRING_KEY_SIZE] = {
    0xe7, 0xf7, 0x35, 0xba, 0x19, 0xa3, 0x3f, 0xd6,
    0x73, 0x23, 0xab, 0x37, 0x26, 0x2d, 0xe5, 0x36,
    0x08, 0xca, 0x57, 0x85, 0x76, 0x53, 0x43, 0x52,
    0xe1, 0x8f, 0x64, 0xe6, 0x13, 0xd3, 0x8d, 0x54
};

static int kat_check(const char* label, const byte* got,
        const byte* want, word32 sz)
{
    if (XMEMCMP(got, want, sz) != 0) {
        printf("FAIL: %s mismatch\n", label);
        return 0;
    }
    printf("PASS: %s matches KAT\n", label);
    return 1;
}

int main(void)
{
    int ret = 0;
    int ok = 0;
    int inited = 0;
    Aes enc;
    Aes dec;
    byte ct[KAT_PT_SZ];
    byte tag[KAT_TAG_SZ];
    byte out[KAT_PT_SZ];

    printf("TROPIC01 GCM callback KAT\n");

    ret = Tropic01_SetPairingKeys(PAIRING_KEY_SLOT_INDEX_0,
                                  kat_sh0_pub, kat_sh0_priv);
    if (ret != 0) {
        printf("FAIL: Tropic01_SetPairingKeys: %d\n", ret);
        goto cleanup;
    }

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("FAIL: wolfCrypt_Init: %d\n", ret);
        goto cleanup;
    }
    inited = 1;

    ret = wc_CryptoCb_RegisterDevice(WOLF_TROPIC01_DEVID,
                                     Tropic01_CryptoCb, NULL);
    if (ret != 0) {
        printf("FAIL: wc_CryptoCb_RegisterDevice: %d\n", ret);
        goto cleanup;
    }

    /* Encrypt KAT: the context is set with the decoy key, so the GHASH
     * subkey currently in it is for the decoy. The callback must
     * re-derive H from the device key it swaps in. */
    ret = wc_AesInit(&enc, NULL, WOLF_TROPIC01_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&enc, kat_key_decoy, AES_128_KEY_SIZE);
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&enc, ct, kat_pt, KAT_PT_SZ,
                               kat_iv, KAT_IV_SZ,
                               tag, KAT_TAG_SZ,
                               kat_aad, KAT_AAD_SZ);
    }
    if (ret == 0) {
        ok = kat_check("ciphertext", ct, kat_ct, KAT_PT_SZ);
        ok = kat_check("auth tag", tag, kat_tag, KAT_TAG_SZ) && ok;
    }
    else {
        printf("FAIL: encrypt KAT op: %d\n", ret);
        ok = 0;
    }
    wc_AesFree(&enc);

    /* Decrypt KAT: the KAT tag only verifies when the decrypt path
     * derives H from the device key as well. */
    ret = wc_AesInit(&dec, NULL, WOLF_TROPIC01_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&dec, kat_key_decoy, AES_128_KEY_SIZE);
    }
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&dec, out, kat_ct, KAT_PT_SZ,
                               kat_iv, KAT_IV_SZ,
                               (byte*)kat_tag, KAT_TAG_SZ,
                               kat_aad, KAT_AAD_SZ);
    }
    if (ret == 0) {
        ok = kat_check("decrypted plaintext", out, kat_pt, KAT_PT_SZ) && ok;
    }
    else {
        printf("FAIL: decrypt KAT op: %d\n", ret);
        ok = 0;
    }
    wc_AesFree(&dec);

cleanup:
    if (inited) {
        wolfCrypt_Cleanup();
    }

    if (ok) {
        printf("TROPIC01 GCM KAT: PASS\n");
        return 0;
    }
    printf("TROPIC01 GCM KAT: FAIL\n");
    return 1;
}
