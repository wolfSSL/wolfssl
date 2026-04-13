/* test_md5.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_md5.h>
#include <tests/api/test_digest.h>

/* Unit test for wc_InitMd5() and wc_InitMd5_ex() */
int test_wc_InitMd5(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_INIT_AND_INIT_EX_TEST(wc_Md5, Md5);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_UpdateMd5() */
int test_wc_Md5Update(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_UPDATE_TEST(wc_Md5, Md5);
#endif
    return EXPECT_RESULT();
}

/* Unit test for wc_Md5Final() */
int test_wc_Md5Final(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_FINAL_TEST(wc_Md5, Md5, MD5);
#endif
    return EXPECT_RESULT();
}

#define MD5_KAT_CNT     7

int test_wc_Md5_KATs(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_KATS_TEST_VARS(wc_Md5, MD5);

    /* From RFC 1321. */
    DIGEST_KATS_ADD("", 0,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04"
        "\xe9\x80\x09\x98\xec\xf8\x42\x7e");
    DIGEST_KATS_ADD("a", 1,
        "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8"
        "\x31\xc3\x99\xe2\x69\x77\x26\x61");
    DIGEST_KATS_ADD("abc", 3,
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
    DIGEST_KATS_ADD("message digest", 14,
        "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d"
        "\x52\x5a\x2f\x31\xaa\xf1\x61\xd0");
    DIGEST_KATS_ADD("abcdefghijklmnopqrstuvwxyz", 26,
        "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00"
        "\x7d\xfb\x49\x6c\xca\x67\xe1\x3b");
    DIGEST_KATS_ADD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789", 62,
        "\xd1\x74\xab\x98\xd2\x77\xd9\xf5"
        "\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f");
    DIGEST_KATS_ADD("1234567890123456789012345678901234567890"
                    "1234567890123456789012345678901234567890", 80,
        "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55"
        "\xac\x49\xda\x2e\x21\x07\xb6\x7a");

    DIGEST_KATS_TEST(Md5, MD5);
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5_other(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_OTHER_TEST(wc_Md5, Md5, MD5,
        "\xd9\xa6\xc2\x1f\xf4\x05\xab\x62"
        "\xd6\xad\xa8\xcd\x0c\xb9\x49\x14");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5Copy(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_COPY_TEST(wc_Md5, Md5, MD5,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04"
        "\xe9\x80\x09\x98\xec\xf8\x42\x7e",
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5GetHash(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    DIGEST_GET_HASH_TEST(wc_Md5, Md5, MD5,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04"
        "\xe9\x80\x09\x98\xec\xf8\x42\x7e",
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5Transform(void)
{
    EXPECT_DECLS;
#if !defined(NO_MD5) && (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    !defined(HAVE_MD5_CUST_API)
    DIGEST_TRANSFORM_TEST(wc_Md5, Md5, MD5,
        "\x61\x62\x63\x80\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x18\x00\x00\x00\x00\x00\x00\x00",
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0"
        "\xd6\x96\x3f\x7d\x28\xe1\x7f\x72");
#endif
    return EXPECT_RESULT();
}

int test_wc_Md5_Flags(void)
{
    EXPECT_DECLS;
#if !defined(NO_MD5) && defined(WOLFSSL_HASH_FLAGS)
    DIGEST_FLAGS_TEST(wc_Md5, Md5);
#endif
    return EXPECT_RESULT();
}

/* MC/DC residual-coverage test for wc_Md5Update (wolfcrypt/src/md5.c L361).
 *
 * The condition at L361 is:  (data == NULL && len == 0)
 * The existing DIGEST_UPDATE_TEST macro covers:
 *   - data==NULL, len==0  (T&&T -> branch taken, valid no-op)
 *   - data==NULL, len>0   (T&&F -> caught earlier at L345, BAD_FUNC_ARG)
 * Missing MC/DC independence pair for the "data == NULL" sub-condition:
 *   - data!=NULL, len==0  (F&&T -> branch NOT taken, valid no-op, continues)
 *
 * Additional boundary pairs exercised here to satisfy the full Update path:
 *   1. len=0,  non-NULL data  — L361 branch NOT taken; no data consumed.
 *   2. len=63, non-NULL data  — partial block fill, buffLen becomes 63.
 *   3. len=1 after len=63    — buffer exactly fills (63+1=64), compress fires.
 *   4. len=64, fresh state   — single complete block, no residual.
 *   5. len=128, fresh state  — two complete blocks.
 *   6. len=65, fresh state   — one full block + 1 residual byte.
 */
int test_wc_Md5UpdateResidualCoverage(void)
{
    EXPECT_DECLS;
#ifndef NO_MD5
    Md5    md5;
    byte   digest[WC_MD5_DIGEST_SIZE];
    byte   buf[WC_MD5_BLOCK_SIZE * 2 + 1]; /* 129 bytes */

    XMEMSET(buf, 0xA5, sizeof(buf));

    /* --- Pair 1: data != NULL, len == 0 (missing MC/DC pair for L361) ---
     * data != NULL  =>  (data == NULL) evaluates FALSE
     * len  == 0     =>  (len  == 0)   evaluates TRUE
     * AND result: FALSE  => branch at L361 NOT taken; function returns 0.
     */
    ExpectIntEQ(wc_InitMd5(&md5), 0);
    ExpectIntEQ(wc_Md5Update(&md5, buf, 0), 0);
    ExpectIntEQ(wc_Md5Final(&md5, digest), 0);
    /* Digest of empty message — confirms no data was absorbed. */
    ExpectBufEQ(digest,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04"
        "\xe9\x80\x09\x98\xec\xf8\x42\x7e",
        WC_MD5_DIGEST_SIZE);
    wc_Md5Free(&md5);

    /* --- Pair 2: partial fill (len=63) — buffLen<BLOCK_SIZE, no compress --- */
    ExpectIntEQ(wc_InitMd5(&md5), 0);
    ExpectIntEQ(wc_Md5Update(&md5, buf, WC_MD5_BLOCK_SIZE - 1), 0);
    wc_Md5Free(&md5);

    /* --- Pair 3: buffer-exactly-full (63 + 1 = 64) — compress fires ---
     * Exercises L380: (md5->buffLen == WC_MD5_BLOCK_SIZE) TRUE path.
     */
    ExpectIntEQ(wc_InitMd5(&md5), 0);
    ExpectIntEQ(wc_Md5Update(&md5, buf, WC_MD5_BLOCK_SIZE - 1), 0);
    ExpectIntEQ(wc_Md5Update(&md5, buf, 1), 0);
    wc_Md5Free(&md5);

    /* --- Pair 4: single complete block (len=64, fresh) ---
     * buffLen starts 0, so remainder path is skipped; full block processed.
     */
    ExpectIntEQ(wc_InitMd5(&md5), 0);
    ExpectIntEQ(wc_Md5Update(&md5, buf, WC_MD5_BLOCK_SIZE), 0);
    wc_Md5Free(&md5);

    /* --- Pair 5: two complete blocks (len=128, fresh) ---
     * Exercises multi-block path; both blocks processed, no residual.
     */
    ExpectIntEQ(wc_InitMd5(&md5), 0);
    ExpectIntEQ(wc_Md5Update(&md5, buf, WC_MD5_BLOCK_SIZE * 2), 0);
    wc_Md5Free(&md5);

    /* --- Pair 6: full block + 1 residual byte (len=65, fresh) ---
     * Exercises L432: (len > 0) TRUE — leftover byte saved to buffer.
     */
    ExpectIntEQ(wc_InitMd5(&md5), 0);
    ExpectIntEQ(wc_Md5Update(&md5, buf, WC_MD5_BLOCK_SIZE + 1), 0);
    ExpectIntEQ(wc_Md5Final(&md5, digest), 0);
    wc_Md5Free(&md5);

#endif /* NO_MD5 */
    return EXPECT_RESULT();
}

