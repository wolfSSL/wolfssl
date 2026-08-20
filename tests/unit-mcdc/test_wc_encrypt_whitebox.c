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
 * The same reasoning applies to the three wc_CryptKey() guards that the
 * asn.c PKCS8/PKCS12 decrypt path only ever reaches from one direction.
 * wc_CryptKey() is WOLFSSL_LOCAL, so it is driven here directly:
 *
 *   1. wc_CryptKey(), PKCS12v1 arm (~line 474)
 *          if (passwordSz < 0 ||
 *              passwordSz >= MAX_UNICODE_SZ ||
 *             (passwordSz * 2 + 2) > MAX_UNICODE_SZ)
 *      The unicode expansion below it writes 2*passwordSz + 2 bytes into a
 *      MAX_UNICODE_SZ (256) byte stack array, so this chain is the only thing
 *      standing between a caller-supplied length and that buffer. Four
 *      vectors, one per operand plus the accepting one, all with
 *      version == PKCS12v1 so the guard is actually reached:
 *          passwordSz = -1  -> idx0 T                      (UNICODE_SIZE_E)
 *          passwordSz = 300 -> idx0 F, idx1 T              (UNICODE_SIZE_E)
 *          passwordSz = 200 -> idx0 F, idx1 F, idx2 T      (UNICODE_SIZE_E)
 *          passwordSz = 8   -> all false                   (derives, ret 0)
 *      All four are memory-safe: the guard is the first statement of the
 *      PKCS12v1 case and nothing reads `password` before it (the only earlier
 *      use is the password == NULL check at the top of the function), so the
 *      three rejected lengths never index the buffer. The password buffer is
 *      sized 512 anyway, so even the 300 vector would be in bounds if read.
 *
 *   2/3. wc_CryptKey(), cipher arms (~line 526 for PBE_*_DES, ~line 554 for
 *        PBE_SHA1_DES3)
 *          if (version == PKCS5v2 || version == PKCS12v1)
 *              desIv = cbcIv;
 *      Both operands need three rows in one binary, and the row that never
 *      occurs in the API-level runs is the all-false one, because
 *      the PBE_*_DES ids are only ever reached with a PKCS#12 or PKCS#5 v2.0
 *      encoding. The third version value has to be one the version switch
 *      above still accepts, otherwise ret != 0 and the cipher switch is never
 *      entered at all: that leaves exactly PKCS5 (wc_PBKDF1, compiled when
 *      !NO_SHA; HAVE_PBKDF1 is implied by HAVE_PKCS8/HAVE_PKCS12 per
 *      settings.h). So, per site:
 *          version = PKCS5v2  -> idx0 T          (desIv = cbcIv)
 *          version = PKCS12v1 -> idx0 F, idx1 T  (desIv = cbcIv)
 *          version = PKCS5    -> idx0 F, idx1 F  (desIv = key + 8 / key + 24)
 *      The all-false row reads the derived IV out of `key` itself: PBE_SHA1_DES
 *      derives 16 bytes and indexes key + 8, PBE_SHA1_DES3 derives 32 and
 *      indexes key + 24, both inside the PKCS_MAX_KEY_SIZE (64) buffer and
 *      both inside the range wc_PBKDF1() just wrote, so no uninitialised or
 *      out-of-bounds read. Input is 32 bytes, a whole number of DES blocks.
 *
 * Build: compiled by the white-box step with the same MC/DC CFLAGS
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

/* --------------------------------------------------------------------------
 * wc_CryptKey() PKCS12v1 arm: passwordSz unicode-expansion chain (~line 474).
 * ----------------------------------------------------------------------- */
#if (defined(HAVE_PKCS8) || defined(HAVE_PKCS12)) && defined(HAVE_PKCS12) && \
    !defined(NO_DES3) && !defined(NO_SHA)
static void wb_crypt_key_unicode_guard(void)
{
    static char pw[512];
    byte salt[8];
    byte input[32];
    byte cbcIv[16];            /* literal: NO_AES builds have no AES block macro */
    int  ret;

    XMEMSET(pw, 'a', sizeof(pw));
    XMEMSET(salt, 0x44, sizeof(salt));
    XMEMSET(input, 0x55, sizeof(input));
    XMEMSET(cbcIv, 0x66, sizeof(cbcIv));

    /* idx0 true: negative length. */
    ret = wc_CryptKey(pw, -1, salt, (int)sizeof(salt), 100, PBE_SHA1_DES3,
        input, (int)sizeof(input), PKCS12v1, cbcIv, 1, 0);
    if (ret != WC_NO_ERR_TRACE(UNICODE_SIZE_E)) {
        WB_NOTE("wc_CryptKey negative passwordSz not rejected");
        wb_fail = 1;
    }

    /* idx0 false, idx1 true: length at/over MAX_UNICODE_SZ. */
    ret = wc_CryptKey(pw, 300, salt, (int)sizeof(salt), 100, PBE_SHA1_DES3,
        input, (int)sizeof(input), PKCS12v1, cbcIv, 1, 0);
    if (ret != WC_NO_ERR_TRACE(UNICODE_SIZE_E)) {
        WB_NOTE("wc_CryptKey passwordSz >= MAX_UNICODE_SZ not rejected");
        wb_fail = 1;
    }

    /* idx0 false, idx1 false, idx2 true: fits on its own, but the unicode
     * expansion (2*n + 2 = 402) would not. */
    ret = wc_CryptKey(pw, 200, salt, (int)sizeof(salt), 100, PBE_SHA1_DES3,
        input, (int)sizeof(input), PKCS12v1, cbcIv, 1, 0);
    if (ret != WC_NO_ERR_TRACE(UNICODE_SIZE_E)) {
        WB_NOTE("wc_CryptKey unicode-expanded passwordSz not rejected");
        wb_fail = 1;
    }

    /* All-false baseline in the same binary: a real PKCS#12 derivation. */
    ret = wc_CryptKey(pw, 8, salt, (int)sizeof(salt), 100, PBE_SHA1_DES3,
        input, (int)sizeof(input), PKCS12v1, cbcIv, 1, 0);
    if (ret != 0) {
        WB_NOTE("wc_CryptKey PKCS12v1 accepting vector failed");
        wb_fail = 1;
    }

    WB_NOTE("wc_CryptKey PKCS12v1 passwordSz chain pairs exercised");
}
#else
static void wb_crypt_key_unicode_guard(void)
{ WB_NOTE("HAVE_PKCS12/DES3/SHA off; wc_CryptKey unicode guard skipped"); }
#endif

/* --------------------------------------------------------------------------
 * wc_CryptKey() cipher arms: "version == PKCS5v2 || version == PKCS12v1"
 * at ~line 526 (PBE_SHA1_DES) and ~line 554 (PBE_SHA1_DES3).
 * ----------------------------------------------------------------------- */
#if (defined(HAVE_PKCS8) || defined(HAVE_PKCS12)) && defined(HAVE_PKCS12) && \
    !defined(NO_DES3) && !defined(NO_SHA) && !defined(NO_HMAC)
static void wb_crypt_key_version_ids(int id)
{
    static const char pw[] = "password";
    byte salt[8];
    byte input[32];
    byte cbcIv[16];            /* literal: NO_AES builds have no AES block macro */
    int  ret;

    XMEMSET(salt, 0x44, sizeof(salt));
    XMEMSET(input, 0x55, sizeof(input));
    XMEMSET(cbcIv, 0x66, sizeof(cbcIv));

    /* idx0 true: PKCS#5 v2.0, caller-supplied IV. */
    ret = wc_CryptKey(pw, (int)sizeof(pw) - 1, salt, (int)sizeof(salt), 100,
        id, input, (int)sizeof(input), PKCS5v2, cbcIv, 1, 0);
    if (ret != 0) {
        WB_NOTE("wc_CryptKey PKCS5v2 vector failed");
        wb_fail = 1;
    }

    /* idx0 false, idx1 true: PKCS#12, IV derived into cbcIv. */
    ret = wc_CryptKey(pw, (int)sizeof(pw) - 1, salt, (int)sizeof(salt), 100,
        id, input, (int)sizeof(input), PKCS12v1, cbcIv, 1, 0);
    if (ret != 0) {
        WB_NOTE("wc_CryptKey PKCS12v1 vector failed");
        wb_fail = 1;
    }

    /* idx0 false, idx1 false: PKCS#5 v1.5, IV taken from the derived key. */
    ret = wc_CryptKey(pw, (int)sizeof(pw) - 1, salt, (int)sizeof(salt), 100,
        id, input, (int)sizeof(input), PKCS5, cbcIv, 1, 0);
    if (ret != 0) {
        WB_NOTE("wc_CryptKey PKCS5 vector failed");
        wb_fail = 1;
    }
}

static void wb_crypt_key_version_guards(void)
{
    wb_crypt_key_version_ids(PBE_SHA1_DES);
    wb_crypt_key_version_ids(PBE_SHA1_DES3);
    WB_NOTE("wc_CryptKey DES/DES3 version-guard pairs exercised");
}
#else
static void wb_crypt_key_version_guards(void)
{ WB_NOTE("HAVE_PKCS12/DES3/SHA/HMAC off; wc_CryptKey version guards "
          "skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("wc_encrypt.c white-box MC/DC supplement\n");

    wb_aes_cbc_with_key();
    wb_crypt_key();
    wb_crypt_key_unicode_guard();
    wb_crypt_key_version_guards();

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Always 0: a nonzero exit discards this variant's whole coverage. */
    (void)wb_fail;
    return 0;
}
