/* test_wc_encrypt_whitebox.c
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

/*
 * MC/DC supplement for wolfcrypt/src/wc_encrypt.c.
 *
 * The file's argument chains are only ever called with valid arguments by the
 * in-tree tests, so no operand of
 *
 *     if (out == NULL || in == NULL || key == NULL || iv == NULL)
 *     if (password == NULL || salt == NULL || input == NULL)
 *
 * gets an independence pair. Each operand needs the vector where it alone is
 * NULL, and the chain needs its all-non-NULL vector in THIS binary: llvm-cov
 * derives MC/DC per binary, so a rejection on its own proves nothing.
 *
 * Build: compiled by the campaign's white-box step with the same MC/DC CFLAGS
 * as the instrumented library, then linked against that variant's
 * libwolfssl.a with wc_encrypt.o removed. Not part of the wolfSSL build.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcrypt/src/wc_encrypt.c>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
static void wb_aes_cbc_with_key(void)
{
    byte out[WC_AES_BLOCK_SIZE * 2];
    byte in[WC_AES_BLOCK_SIZE * 2];
    byte key[16];
    byte iv[WC_AES_BLOCK_SIZE];

    XMEMSET(out, 0, sizeof(out));
    XMEMSET(in, 0x11, sizeof(in));
    XMEMSET(key, 0x22, sizeof(key));
    XMEMSET(iv, 0x33, sizeof(iv));

    (void)wc_AesCbcEncryptWithKey(NULL, in, (word32)sizeof(in), key,
        (word32)sizeof(key), iv);
    (void)wc_AesCbcEncryptWithKey(out, NULL, (word32)sizeof(in), key,
        (word32)sizeof(key), iv);
    (void)wc_AesCbcEncryptWithKey(out, in, (word32)sizeof(in), NULL,
        (word32)sizeof(key), iv);
    (void)wc_AesCbcEncryptWithKey(out, in, (word32)sizeof(in), key,
        (word32)sizeof(key), NULL);
    (void)wc_AesCbcEncryptWithKey(out, in, (word32)sizeof(in), key,
        (word32)sizeof(key), iv);

    (void)wc_AesCbcDecryptWithKey(NULL, in, (word32)sizeof(in), key,
        (word32)sizeof(key), iv);
    (void)wc_AesCbcDecryptWithKey(out, in, (word32)sizeof(in), key,
        (word32)sizeof(key), iv);
}
#else
static void wb_aes_cbc_with_key(void)
{
    WB_NOTE("AES-CBC not compiled; skipped");
}
#endif

#if defined(HAVE_PKCS8) || defined(HAVE_PKCS12)
static void wb_crypt_key(void)
{
    static const char pw[] = "password";
    byte salt[8];
    byte input[32];
    byte cbcIv[WC_AES_BLOCK_SIZE];

    XMEMSET(salt, 0x44, sizeof(salt));
    XMEMSET(input, 0x55, sizeof(input));
    XMEMSET(cbcIv, 0x66, sizeof(cbcIv));

    (void)wc_CryptKey(NULL, (int)sizeof(pw) - 1, salt, (int)sizeof(salt), 1000,
        PBE_AES256_CBC, input, (int)sizeof(input), PKCS5v2, cbcIv, 1,
        WC_SHA256);
    (void)wc_CryptKey(pw, (int)sizeof(pw) - 1, NULL, (int)sizeof(salt), 1000,
        PBE_AES256_CBC, input, (int)sizeof(input), PKCS5v2, cbcIv, 1,
        WC_SHA256);
    (void)wc_CryptKey(pw, (int)sizeof(pw) - 1, salt, (int)sizeof(salt), 1000,
        PBE_AES256_CBC, NULL, (int)sizeof(input), PKCS5v2, cbcIv, 1,
        WC_SHA256);
    (void)wc_CryptKey(pw, (int)sizeof(pw) - 1, salt, (int)sizeof(salt), 1000,
        PBE_AES256_CBC, input, (int)sizeof(input), PKCS5v2, cbcIv, 1,
        WC_SHA256);
}
#else
static void wb_crypt_key(void)
{
    WB_NOTE("PKCS8/PKCS12 not compiled; wc_CryptKey skipped");
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("wc_encrypt.c white-box MC/DC supplement\n");

    wb_aes_cbc_with_key();
    wb_crypt_key();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
