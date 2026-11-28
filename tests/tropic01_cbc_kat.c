/* tropic01_cbc_kat.c
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

/* Known-answer test for the AES-CBC branch of the TROPIC01 crypto
 * callback (Tropic01_CryptoCb).
 *
 * The callback swaps the device-resident key into the caller's Aes
 * context and runs the CBC operation in software. The operation must
 * chain from the IV the caller installed on the context: wc_AesSetKey()
 * overwrites aes->reg, so the callback has to preserve the caller's
 * chaining state across the key swap. A callback that installs a
 * device-provisioned IV instead makes CBC deterministic - identical
 * plaintexts produce identical ciphertexts - and silently discards the
 * per-message IV the application chose.
 *
 * The KAT vectors are computed with AES-128-CBC under the TROPIC01Sim
 * default AES key (object-store R-memory slot 0, byte i is i*0x11 mod
 * 256; the callback passes the first keyLen bytes of the slot to the
 * software path) and the caller IV below, which is deliberately
 * different from the device IV fixture (R-memory slot 1, 00 01 02 ... 0f)
 * so a callback that restarts the chain from the device IV fails the
 * comparison.
 *
 * The test drives the callback the same way TLS does: the context is
 * created with WOLF_TROPIC01_DEVID and set with a caller (decoy) key
 * and the KAT IV. Only a callback that keeps the caller's IV produces
 * the KAT ciphertext.
 *
 * Build (against the installed libwolfssl and libtropic v0.1.0, see
 * .github/workflows/tropic01-sim.yml): the installed headers carry no
 * options.h, so the feature macros of the library build must be
 * repeated on the command line.
 *   gcc -Wall -Wextra -O2 -DWOLFSSL_TROPIC01 -DWOLF_CRYPTO_CB \
 *       -DHAVE_AES_CBC \
 *       -I<libtropic>/include -I<prefix>/include \
 *       tests/tropic01_cbc_kat.c \
 *       <libtropic>/hal/port/unix/lt_port_unix_tcp.c \
 *       -L<prefix>/lib -L<libtropic>/build \
 *       -L<libtropic>/build/trezor_crypto \
 *       -lwolfssl -ltropic -ltrezor_crypto -lm \
 *       -o tropic01_cbc_kat
 *
 * Run with the TROPIC01Sim tcp_server listening (TROPIC01_SIM_HOST,
 * TROPIC01_SIM_PORT). Exits 0 on pass, 1 on fail.
 */

#include <stdio.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/tropicsquare/tropic01.h>

#define KAT_PT_SZ    32

/* Caller (decoy) session key the test sets on the context, standing
 * in for the TLS key. The callback swaps in the device key. */
static const byte kat_key_decoy[AES_128_KEY_SIZE] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
};

/* Per-message IV the caller installs on the context. */
static const byte kat_iv[WC_AES_BLOCK_SIZE] = {
    0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x09,
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
};

static const byte kat_pt[KAT_PT_SZ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* AES-128-CBC(kat_key_dev, kat_iv, kat_pt). */
static const byte kat_ct[KAT_PT_SZ] = {
    0x0d, 0x97, 0xca, 0x41, 0x6c, 0x68, 0x39, 0x5f,
    0x37, 0x91, 0x91, 0x30, 0xe8, 0xd1, 0x35, 0x77,
    0x78, 0x6e, 0x86, 0x02, 0x31, 0x6a, 0x80, 0x0f,
    0x4e, 0x1a, 0x7d, 0xe9, 0x62, 0xe8, 0x1d, 0x28
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
    byte out[KAT_PT_SZ];

    printf("TROPIC01 CBC callback KAT\n");

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

    /* Encrypt KAT: the context is set with the decoy key and the KAT
     * IV. The callback must swap in the device key while chaining from
     * the caller's IV. */
    ret = wc_AesInit(&enc, NULL, WOLF_TROPIC01_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&enc, kat_key_decoy, AES_128_KEY_SIZE,
                           kat_iv, AES_ENCRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCbcEncrypt(&enc, ct, kat_pt, KAT_PT_SZ);
    }
    if (ret == 0) {
        ok = kat_check("ciphertext", ct, kat_ct, KAT_PT_SZ);
    }
    else {
        printf("FAIL: encrypt KAT op: %d\n", ret);
        ok = 0;
    }
    wc_AesFree(&enc);

    /* Decrypt KAT: the KAT ciphertext only decrypts to the plaintext
     * when the decrypt path chains from the caller's IV as well. */
    ret = wc_AesInit(&dec, NULL, WOLF_TROPIC01_DEVID);
    if (ret == 0) {
        ret = wc_AesSetKey(&dec, kat_key_decoy, AES_128_KEY_SIZE,
                           kat_iv, AES_DECRYPTION);
    }
    if (ret == 0) {
        ret = wc_AesCbcDecrypt(&dec, out, kat_ct, KAT_PT_SZ);
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
        printf("TROPIC01 CBC KAT: PASS\n");
        return 0;
    }
    printf("TROPIC01 CBC KAT: FAIL\n");
    return 1;
}
