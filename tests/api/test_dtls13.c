/* test_dtls13.c
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

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <tests/api/api.h>
#include <tests/utils.h>
#include <tests/api/test_dtls13.h>

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)


int test_dtls13_bad_epoch_ch(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const int EPOCH_OFF = 3;
    int groups[] = {
        WOLFSSL_ECC_SECP256R1,
        WOLFSSL_ECC_SECP384R1,
    };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* disable hrr cookie so we can later check msgsReceived.got_client_hello
     *  with just one message */
    ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);

    /* Set client groups to traditional only to avoid CH fragmentation */
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups, 2), WOLFSSL_SUCCESS);

    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntGE(test_ctx.s_len, EPOCH_OFF + 2);

    /* first CH should use epoch 0x0 */
    ExpectTrue((test_ctx.s_buff[EPOCH_OFF] == 0x0) &&
        (test_ctx.s_buff[EPOCH_OFF + 1] == 0x0));

    /* change epoch to 2 */
    test_ctx.s_buff[EPOCH_OFF + 1] = 0x2;

    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    ExpectIntNE(ssl_s->msgsReceived.got_client_hello, 1);

    /* resend the CH */
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    return EXPECT_RESULT();
}
#else
int test_dtls13_bad_epoch_ch(void)
{
    return TEST_SKIPPED;
}
#endif

#if defined(HAVE_NULL_CIPHER) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) \
    && defined(WOLFSSL_DTLS13)
static byte* test_find_string(const char *string,
    byte *buf, int buf_size)
{
    int string_size, i;

    string_size = (int)XSTRLEN(string);
    for (i = 0; i < buf_size - string_size - 1; i++) {
        if (XSTRCMP((char*)&buf[i], string) == 0)
            return &buf[i];
    }
    return NULL;
}

int test_wolfSSL_dtls13_null_cipher(void)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char *test_str = "test";
    int test_str_size;
    byte buf[255], *ptr = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    test_ctx.c_ciphers = test_ctx.s_ciphers = "TLS13-SHA256-SHA256";
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    test_str_size = XSTRLEN("test") + 1;
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), test_str_size);
    ExpectIntEQ(XSTRCMP((char*)buf, test_str), 0);

    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);

    /* check that the packet was sent cleartext */
    ExpectNotNull(ptr = test_find_string(test_str, test_ctx.s_buff,
        test_ctx.s_len));
    if (ptr != NULL) {
        /* modify the message */
        *ptr = 'H';
        /* bad messages should be ignored in DTLS */
        ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), -1);
        ExpectIntEQ(ssl_s->error, WC_NO_ERR_TRACE(WANT_READ));
    }

    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), 1);
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return TEST_SUCCESS;
}
#else
int test_wolfSSL_dtls13_null_cipher(void)
{
    return TEST_SKIPPED;
}
#endif

int test_dtls13_frag_ch_pq(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_HAVE_MLKEM)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char *test_str = "test";
    int test_str_size;
    byte buf[255];
#if defined(WOLFSSL_MLKEM_KYBER)
    #if !defined(WOLFSSL_NO_KYBER1024)
    int group = WOLFSSL_KYBER_LEVEL5;
    const char *group_name = "KYBER_LEVEL5";
    #elif !defined(WOLFSSL_NO_KYBER768)
    int group = WOLFSSL_KYBER_LEVEL3;
    const char *group_name = "KYBER_LEVEL3";
    #else
    int group = WOLFSSL_KYBER_LEVEL1;
    const char *group_name = "KYBER_LEVEL1";
    #endif
#elif !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
    #if !defined(WOLFSSL_NO_ML_KEM_1024)
    int group = WOLFSSL_ML_KEM_1024;
    const char *group_name = "ML_KEM_1024";
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
    int group = WOLFSSL_ML_KEM_768;
    const char *group_name = "ML_KEM_768";
    #else
    int group = WOLFSSL_ML_KEM_512;
    const char *group_name = "ML_KEM_512";
    #endif
#elif defined(WOLFSSL_PQC_HYBRIDS)
    #if defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768)
    int group = WOLFSSL_X25519MLKEM768;
    const char *group_name = "X25519MLKEM768";
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
    int group = WOLFSSL_SECP256R1MLKEM768;
    const char *group_name = "SecP256r1MLKEM768";
    #else
    int group = WOLFSSL_SECP384R1MLKEM1024;
    const char *group_name = "SecP384r1MLKEM1024";
    #endif
#endif

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    /* Add in a large post-quantum key share to make the CH long. */
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, group), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_c), group_name);
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_s), group_name);
    test_str_size = XSTRLEN("test") + 1;
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), test_str_size);
    ExpectIntEQ(XSTRCMP((char*)buf, test_str), 0);
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS) \
    && defined(WOLFSSL_DTLS_MTU) && defined(WOLFSSL_DTLS_CH_FRAG) && \
    defined(WOLFSSL_AES_256)
static int test_dtls_frag_ch_count_records(byte* b, int len)
{
    DtlsRecordLayerHeader* dtlsRH;
    int records = 0;
    size_t recordLen;
    while (len > 0) {
        records++;
        dtlsRH = (DtlsRecordLayerHeader*)b;
        recordLen = (dtlsRH->length[0] << 8) | dtlsRH->length[1];
        if (recordLen > (size_t)len)
            break;
        b += sizeof(DtlsRecordLayerHeader) + recordLen;
        len -= sizeof(DtlsRecordLayerHeader) + recordLen;
    }
    return records;
}
#endif

int test_dtls_frag_ch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_MTU) && defined(WOLFSSL_DTLS_CH_FRAG) && \
    defined(WOLFSSL_AES_256)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    static unsigned int DUMMY_MTU = 256;
    unsigned int len;
    unsigned char four_frag_CH[] = {
      0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xda, 0x01, 0x00, 0x02, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xce, 0xfe, 0xfd, 0xf3, 0x94, 0x01, 0x33, 0x2c, 0xcf, 0x2c, 0x47, 0xb1,
      0xe5, 0xa1, 0x7b, 0x19, 0x3e, 0xac, 0x68, 0xdd, 0xe6, 0x17, 0x6b, 0x85,
      0xad, 0x5f, 0xfc, 0x7f, 0x6e, 0xf0, 0xb9, 0xe0, 0x2e, 0xca, 0x47, 0x00,
      0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
      0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
      0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
      0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
      0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x02,
      0x7c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x0d, 0x00, 0x20,
      0x00, 0x1e, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06,
      0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01,
      0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x0a, 0x00, 0x0c,
      0x00, 0x0a, 0x00, 0x19, 0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01, 0x00,
      0x00, 0x16, 0x00, 0x00, 0x00, 0x33, 0x02, 0x39, 0x02, 0x37, 0x00, 0x17,
      0x00, 0x41, 0x04, 0x94, 0xdf, 0x36, 0xd7, 0xb3, 0x90, 0x6d, 0x01, 0xa1,
      0xe6, 0xed, 0x67, 0xf4, 0xd9, 0x9d, 0x2c, 0xac, 0x57, 0x74, 0xff, 0x19,
      0xbe, 0x5a, 0xc9, 0x30, 0x11, 0xb7, 0x2b, 0x59, 0x47, 0x80, 0x7c, 0xa9,
      0xb7, 0x31, 0x8c, 0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0xda, 0x01, 0x00, 0x02, 0xdc, 0x00, 0x00, 0x00, 0x00,
      0xce, 0x00, 0x00, 0xce, 0x9e, 0x13, 0x74, 0x3b, 0x86, 0xba, 0x69, 0x1f,
      0x12, 0xf7, 0xcd, 0x78, 0x53, 0xe8, 0x50, 0x4d, 0x71, 0x3f, 0x4b, 0x4e,
      0xeb, 0x3e, 0xe5, 0x43, 0x54, 0x78, 0x17, 0x6d, 0x00, 0x18, 0x00, 0x61,
      0x04, 0xd1, 0x99, 0x66, 0x4f, 0xda, 0xc7, 0x12, 0x3b, 0xff, 0xb2, 0xd6,
      0x2f, 0x35, 0xb6, 0x17, 0x1f, 0xb3, 0xd0, 0xb6, 0x52, 0xff, 0x97, 0x8b,
      0x01, 0xe8, 0xd9, 0x68, 0x71, 0x40, 0x02, 0xd5, 0x68, 0x3a, 0x58, 0xb2,
      0x5d, 0xee, 0xa4, 0xe9, 0x5f, 0xf4, 0xaf, 0x3e, 0x30, 0x9c, 0x3e, 0x2b,
      0xda, 0x61, 0x43, 0x99, 0x02, 0x35, 0x33, 0x9f, 0xcf, 0xb5, 0xd3, 0x28,
      0x19, 0x9d, 0x1c, 0xbe, 0x69, 0x07, 0x9e, 0xfc, 0xe4, 0x8e, 0xcd, 0x86,
      0x4a, 0x1b, 0xf0, 0xfc, 0x17, 0x94, 0x66, 0x53, 0xda, 0x24, 0x5e, 0xaf,
      0xce, 0xec, 0x62, 0x4c, 0x06, 0xb4, 0x52, 0x94, 0xb1, 0x4a, 0x7a, 0x8c,
      0x4f, 0x00, 0x19, 0x00, 0x85, 0x04, 0x00, 0x27, 0xeb, 0x99, 0x49, 0x7f,
      0xcb, 0x2c, 0x46, 0x54, 0x2d, 0x93, 0x5d, 0x25, 0x92, 0x58, 0x5e, 0x06,
      0xc3, 0x7c, 0xfb, 0x9a, 0xa7, 0xec, 0xcd, 0x9f, 0xe1, 0x6b, 0x2d, 0x78,
      0xf5, 0x16, 0xa9, 0x20, 0x52, 0x48, 0x19, 0x0f, 0x1a, 0xd0, 0xce, 0xd8,
      0x68, 0xb1, 0x4e, 0x7f, 0x33, 0x03, 0x7d, 0x0c, 0x39, 0xdb, 0x9c, 0x4b,
      0xf4, 0xe7, 0xc2, 0xf5, 0xdd, 0x51, 0x9b, 0x03, 0xa8, 0x53, 0x2b, 0xe6,
      0x00, 0x15, 0x4b, 0xff, 0xd2, 0xa0, 0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xda, 0x01, 0x00, 0x02, 0xdc, 0x00,
      0x00, 0x00, 0x01, 0x9c, 0x00, 0x00, 0xce, 0x58, 0x30, 0x10, 0x3d, 0x46,
      0xcc, 0xca, 0x1a, 0x44, 0xc8, 0x58, 0x9b, 0x27, 0x17, 0x67, 0x31, 0x96,
      0x8a, 0x66, 0x39, 0xf4, 0xcc, 0xc1, 0x9f, 0x12, 0x1f, 0x01, 0x30, 0x50,
      0x16, 0xd6, 0x89, 0x97, 0xa3, 0x66, 0xd7, 0x99, 0x50, 0x09, 0x6e, 0x80,
      0x87, 0xe4, 0xa2, 0x88, 0xae, 0xb4, 0x23, 0x57, 0x2f, 0x12, 0x60, 0xe7,
      0x7d, 0x44, 0x2d, 0xad, 0xbe, 0xe9, 0x0d, 0x01, 0x00, 0x01, 0x00, 0xd5,
      0xdd, 0x62, 0xee, 0xf3, 0x0e, 0xd9, 0x30, 0x0e, 0x38, 0xf3, 0x48, 0xf4,
      0xc9, 0x8f, 0x8c, 0x20, 0xf7, 0xd3, 0xa8, 0xb3, 0x87, 0x3c, 0x98, 0x5d,
      0x70, 0xc5, 0x03, 0x76, 0xb7, 0xd5, 0x0b, 0x7b, 0x23, 0x97, 0x6b, 0xe3,
      0xb5, 0x18, 0xeb, 0x64, 0x55, 0x18, 0xb2, 0x8a, 0x90, 0x1a, 0x8f, 0x0e,
      0x15, 0xda, 0xb1, 0x8e, 0x7f, 0xee, 0x1f, 0xe0, 0x3b, 0xb9, 0xed, 0xfc,
      0x4e, 0x3f, 0x78, 0x16, 0x39, 0x95, 0x5f, 0xb7, 0xcb, 0x65, 0x55, 0x72,
      0x7b, 0x7d, 0x86, 0x2f, 0x8a, 0xe5, 0xee, 0xf7, 0x57, 0x40, 0xf3, 0xc4,
      0x96, 0x4f, 0x11, 0x4d, 0x85, 0xf9, 0x56, 0xfa, 0x3d, 0xf0, 0xc9, 0xa4,
      0xec, 0x1e, 0xaa, 0x47, 0x90, 0x53, 0xdf, 0xe1, 0xb7, 0x78, 0x18, 0xeb,
      0xdd, 0x0d, 0x89, 0xb7, 0xf6, 0x15, 0x0e, 0x55, 0x12, 0xb3, 0x23, 0x17,
      0x0b, 0x59, 0x6f, 0x83, 0x05, 0x6b, 0xa6, 0xf8, 0x6c, 0x3a, 0x9b, 0x1b,
      0x50, 0x93, 0x51, 0xea, 0x95, 0x2d, 0x99, 0x96, 0x38, 0x16, 0xfe, 0xfd,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x7e, 0x01, 0x00,
      0x02, 0xdc, 0x00, 0x00, 0x00, 0x02, 0x6a, 0x00, 0x00, 0x72, 0x2d, 0x66,
      0x3e, 0xf2, 0x36, 0x5a, 0xf2, 0x23, 0x8f, 0x28, 0x09, 0xa9, 0x55, 0x8c,
      0x8f, 0xc0, 0x0d, 0x61, 0x98, 0x33, 0x56, 0x87, 0x7a, 0xfd, 0xa7, 0x50,
      0x71, 0x84, 0x2e, 0x41, 0x58, 0x00, 0x87, 0xd9, 0x27, 0xe5, 0x7b, 0xf4,
      0x6d, 0x84, 0x4e, 0x2e, 0x0c, 0x80, 0x0c, 0xf3, 0x8a, 0x02, 0x4b, 0x99,
      0x3a, 0x1f, 0x9f, 0x18, 0x7d, 0x1c, 0xec, 0xad, 0x60, 0x54, 0xa6, 0xa3,
      0x2c, 0x82, 0x5e, 0xf8, 0x8f, 0xae, 0xe1, 0xc4, 0x82, 0x7e, 0x43, 0x43,
      0xc5, 0x99, 0x49, 0x05, 0xd3, 0xf6, 0xdf, 0xa1, 0xb5, 0x2d, 0x0c, 0x13,
      0x2f, 0x1e, 0xb6, 0x28, 0x7c, 0x5c, 0xa1, 0x02, 0x6b, 0x8d, 0xa3, 0xeb,
      0xd4, 0x58, 0xe6, 0xa0, 0x7e, 0x6b, 0xaa, 0x09, 0x43, 0x67, 0x71, 0x87,
      0xa5, 0xcb, 0x68, 0xf3
    };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* Fragment msgs */
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, DUMMY_MTU), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_s, DUMMY_MTU), WOLFSSL_SUCCESS);

    /* Add in some key shares to make the CH long */
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP256R1),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP384R1),
            WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_ECC_SECP521R1),
            WOLFSSL_SUCCESS);
#ifdef HAVE_FFDHE_2048
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_FFDHE_2048),
            WOLFSSL_SUCCESS);
#endif
#ifdef HAVE_FFDHE_3072
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_FFDHE_3072),
            WOLFSSL_SUCCESS);
#endif
#ifdef HAVE_FFDHE_4096
    ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, WOLFSSL_FFDHE_4096),
            WOLFSSL_SUCCESS);
#endif

    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);

    /* Reject fragmented first CH */
    ExpectIntEQ(test_dtls_frag_ch_count_records(four_frag_CH,
            sizeof(four_frag_CH)), 4);
    len = sizeof(four_frag_CH);
    test_memio_clear_buffer(&test_ctx, 0);
    while (len > 0 && EXPECT_SUCCESS()) {
        unsigned int inj_len = len > DUMMY_MTU ? DUMMY_MTU : len;
        unsigned char *idx = four_frag_CH + sizeof(four_frag_CH) - len;
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char *)idx,
            inj_len), 0);
        len -= inj_len;
    }
    ExpectIntEQ(test_ctx.s_len, sizeof(four_frag_CH));
    while (test_ctx.s_len > 0 && EXPECT_SUCCESS()) {
        int s_len = test_ctx.s_len;
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        /* Fail if we didn't advance the buffer to avoid infinite loops */
        ExpectIntLT(test_ctx.s_len, s_len);
    }
    /* Expect all fragments read */
    ExpectIntEQ(test_ctx.s_len, 0);
    /* Expect quietly dropping fragmented first CH */
    ExpectIntEQ(test_ctx.c_len, 0);

#if defined(WOLFSSL_TLS13) && defined(HAVE_ECH)
    /* Disable ECH as it pushes it over our MTU */
    wolfSSL_SetEchEnable(ssl_c, 0);
#endif

    /* Limit options to make the CH a fixed length */
    /* See wolfSSL_parse_cipher_list for reason why we provide 1.3 AND 1.2
     * ciphersuite. This is only necessary when building with OPENSSL_EXTRA. */
#ifdef OPENSSL_EXTRA
    ExpectTrue(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES256-GCM-SHA384"
                                       ":DHE-RSA-AES256-GCM-SHA384"));
#else
    ExpectTrue(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES256-GCM-SHA384"));
#endif

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Count records. Expect 1 unfragmented CH */
    ExpectIntEQ(test_dtls_frag_ch_count_records(test_ctx.s_buff,
            test_ctx.s_len), 1);
    /* HRR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Count records. Expect fragmented CH */
    ExpectIntGT(test_dtls_frag_ch_count_records(test_ctx.s_buff,
            test_ctx.s_len), 1);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = ssl_s = NULL;
    ctx_c = ctx_s = NULL;
#endif
    return EXPECT_RESULT();
}

int test_dtls_empty_keyshare_with_cookie(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char ch_empty_keyshare_with_cookie[] = {
        0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x12, 0x01, 0x00, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x06, 0xfe, 0xfd, 0xfb, 0x8c, 0x9b, 0x28, 0xae, 0x50, 0x1c, 0x4d, 0xf3,
        0xb8, 0xcf, 0x4d, 0xd8, 0x7e, 0x93, 0x13, 0x7b, 0x9e, 0xd9, 0xeb, 0xe9,
        0x13, 0x4b, 0x0d, 0x7f, 0x2e, 0x43, 0x62, 0x8c, 0xe4, 0x57, 0x79, 0x00,
        0x00, 0x00, 0x36, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c, 0xc0,
        0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc,
        0xa8, 0xcc, 0xaa, 0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x24, 0xc0,
        0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00, 0x6b, 0x00, 0x67, 0x00,
        0x39, 0x00, 0x33, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0x01, 0x00, 0x00,
        0xa6, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x2c, 0x00, 0x47,
        0x00, 0x45, 0x20, 0xee, 0x4b, 0x17, 0x70, 0x63, 0xa0, 0x4c, 0x82, 0xbf,
        0x43, 0x01, 0x7d, 0x8d, 0xc1, 0x1b, 0x4e, 0x9b, 0xa0, 0x3c, 0x53, 0x1f,
        0xb7, 0xd1, 0x10, 0x81, 0xa8, 0xdf, 0xdf, 0x8c, 0x7f, 0xf3, 0x11, 0x13,
        0x01, 0x02, 0x3d, 0x3b, 0x7d, 0x14, 0x2c, 0x31, 0xb3, 0x60, 0x72, 0x4d,
        0xe5, 0x1a, 0xb2, 0xa3, 0x61, 0x77, 0x73, 0x03, 0x40, 0x0e, 0x5f, 0xc5,
        0x61, 0x38, 0x43, 0x56, 0x21, 0x4a, 0x95, 0xd5, 0x35, 0xa8, 0x0d, 0x00,
        0x0d, 0x00, 0x2a, 0x00, 0x28, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02,
        0x03, 0xfe, 0x0b, 0xfe, 0x0e, 0xfe, 0xa0, 0xfe, 0xa3, 0xfe, 0xa5, 0x08,
        0x06, 0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06,
        0x01, 0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x0a, 0x00,
        0x18, 0x00, 0x16, 0x00, 0x19, 0x00, 0x18, 0x00, 0x17, 0x00, 0x15, 0x01,
        0x00, 0x02, 0x3a, 0x02, 0x3c, 0x02, 0x3d, 0x2f, 0x3a, 0x2f, 0x3c, 0x2f,
        0x3d, 0x00, 0x16, 0x00, 0x00, 0x00, 0x33, 0x00, 0x02, 0x00, 0x00
    };
    DtlsRecordLayerHeader* dtlsRH;
    byte sequence_number[8];

    XMEMSET(&sequence_number, 0, sizeof(sequence_number));
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
        NULL, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char *)ch_empty_keyshare_with_cookie,
            sizeof(ch_empty_keyshare_with_cookie)), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Expect an alert. A plaintext alert should be exactly 15 bytes. */
    ExpectIntEQ(test_ctx.c_len, 15);
    dtlsRH = (DtlsRecordLayerHeader*)test_ctx.c_buff;
    ExpectIntEQ(dtlsRH->type, alert);
    ExpectIntEQ(dtlsRH->pvMajor, DTLS_MAJOR);
    ExpectIntEQ(dtlsRH->pvMinor, DTLSv1_2_MINOR);
    sequence_number[7] = 1;
    ExpectIntEQ(XMEMCMP(sequence_number, dtlsRH->sequence_number,
            sizeof(sequence_number)), 0);
    ExpectIntEQ(dtlsRH->length[0], 0);
    ExpectIntEQ(dtlsRH->length[1], 2);
    ExpectIntEQ(test_ctx.c_buff[13], alert_fatal);
    ExpectIntEQ(test_ctx.c_buff[14], illegal_parameter);

    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_dtls13_missing_finished_client(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char test_str[] = "test string";
    char test_buf[sizeof(test_str)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HRR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Let's clear the output */
    test_memio_clear_buffer(&test_ctx, 1);
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    /* Client second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server should not error out on a missing finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client rtx second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
    /* Client */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_s, test_str, sizeof(test_str)),
                sizeof(test_str));
    ExpectIntEQ(wolfSSL_read(ssl_c, test_buf, sizeof(test_buf)),
                sizeof(test_str));
    ExpectBufEQ(test_buf, test_str, sizeof(test_str));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_dtls13_missing_finished_server(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char test_str[] = "test string";
    char test_buf[sizeof(test_str)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HRR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Let's clear the output */
    test_memio_clear_buffer(&test_ctx, 0);
    ExpectFalse(wolfSSL_is_init_finished(ssl_c));
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, sizeof(test_str)),
                sizeof(test_str));
    /* Server should not error out on a missing finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client rtx second flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
    /* Let's send some app data */
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, sizeof(test_str)),
                sizeof(test_str));
    ExpectIntEQ(wolfSSL_read(ssl_s, test_buf, sizeof(test_buf)),
                sizeof(test_str));
    ExpectBufEQ(test_buf, test_str, sizeof(test_str));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_dtls13_finished_send_error_propagation(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* HRR */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* CH2 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* Server first flight with finished */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    /* Client second flight with finished - block sends to force error */
    test_ctx.s_len = TEST_MEMIO_BUF_SZ;
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    /* Verify the error is propagated, not silently swallowed as success */
    ExpectIntNE(wolfSSL_get_error(ssl_c, -1), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


/*----------------------------------------------------------------------------*/
/* DTLSv1.3-only tests moved from test_dtls.c (isolated from DTLS<=1.2 code)  */
/*----------------------------------------------------------------------------*/

/*-- basic_connection_id (test_dtls.c lines 422,580) ---*/
int test_dtls13_basic_connection_id(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CID)
    unsigned char client_cid[] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    unsigned char server_cid[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    unsigned char readBuf[50];
    void *        cid = NULL;
    const char* params[] = {
#ifndef NO_SHA256
#ifdef WOLFSSL_AES_128
#ifdef HAVE_AESGCM
        "TLS13-AES128-GCM-SHA256",
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        "TLS13-CHACHA20-POLY1305-SHA256",
#endif
#ifdef HAVE_AESCCM
        "TLS13-AES128-CCM-8-SHA256",
        "TLS13-AES128-CCM-SHA256",
#endif
#endif
#ifdef HAVE_NULL_CIPHER
        "TLS13-SHA256-SHA256",
#endif
#endif
    };
    size_t i;

    /* We check if the side included the CID in their output */
#define CLIENT_CID() mymemmem(test_ctx.s_buff, test_ctx.s_len, \
                              client_cid, sizeof(client_cid))
#define SERVER_CID() mymemmem(test_ctx.c_buff, test_ctx.c_len, \
                              server_cid, sizeof(server_cid))
#define RESET_CID(cid) if ((cid) != NULL) { \
                           ((char*)(cid))[0] = -1; \
                       }


    printf("\n");
    for (i = 0; i < XELEM_CNT(params) && EXPECT_SUCCESS(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;

        printf("Testing %s ... ", params[i]);

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, params[i]), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, params[i]), WOLFSSL_SUCCESS);

        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, server_cid, sizeof(server_cid)),
                1);
        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, client_cid, sizeof(client_cid)),
                1);

        /* CH1 */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNull(CLIENT_CID());
        /* HRR */
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNull(SERVER_CID());
        /* CH2 */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNull(CLIENT_CID());
        /* Server first flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNotNull(SERVER_CID());
        /* Client second flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectNotNull(CLIENT_CID());
        /* Server process flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_s), 1);
        /* Client process flight */
        ExpectIntEQ(wolfSSL_negotiate(ssl_c), 1);

        /* Write some data */
        ExpectIntEQ(wolfSSL_write(ssl_c, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        ExpectNotNull(CLIENT_CID());
        ExpectIntEQ(wolfSSL_write(ssl_s, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        ExpectNotNull(SERVER_CID());
        /* Read the data */
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
                XSTRLEN(params[i]));
        ExpectStrEQ(readBuf, params[i]);
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
                XSTRLEN(params[i]));
        ExpectStrEQ(readBuf, params[i]);
        /* Write short data */
        ExpectIntEQ(wolfSSL_write(ssl_c, params[i], 1), 1);
        ExpectNotNull(CLIENT_CID());
        ExpectIntEQ(wolfSSL_write(ssl_s, params[i], 1), 1);
        ExpectNotNull(SERVER_CID());
        /* Read the short data */
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), 1);
        ExpectIntEQ(readBuf[0], params[i][0]);
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 1);
        ExpectIntEQ(readBuf[0], params[i][0]);
        /* Write some data but with wrong CID */
        ExpectIntEQ(wolfSSL_write(ssl_c, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        /* Reset client cid. */
        ExpectNotNull(cid = CLIENT_CID());
        RESET_CID(cid);
        ExpectIntEQ(wolfSSL_write(ssl_s, params[i], (int)XSTRLEN(params[i])),
                XSTRLEN(params[i]));
        /* Reset server cid. */
        ExpectNotNull(cid = SERVER_CID());
        RESET_CID(cid);
        /* Try to read the data but it shouldn't be there */
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

        /* Close connection */
        ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
        ExpectNotNull(CLIENT_CID());
        ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);
        ExpectNotNull(SERVER_CID());
        ExpectIntEQ(wolfSSL_shutdown(ssl_c), 1);
        ExpectIntEQ(wolfSSL_shutdown(ssl_s), 1);

        if (EXPECT_SUCCESS())
            printf("ok\n");
        else
            printf("failed\n");

        wolfSSL_free(ssl_c);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }

#undef CLIENT_CID
#undef SERVER_CID
#undef RESET_CID

#endif
    return EXPECT_RESULT();
}

/*-- hrr_want_write (test_dtls.c lines 588,639) ---*/
int test_dtls13_hrr_want_write(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    const char msg[] = "hello";
    const int msgLen = sizeof(msg);
    struct test_memio_ctx test_ctx;
    char readBuf[sizeof(msg)];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    /* Client sends first ClientHello */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Force server to hit WANT_WRITE when producing the HRR */
    test_memio_simulate_want_write(&test_ctx, 0, 1);
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_WRITE);

    /* Allow the server to flush the HRR and proceed */
    test_memio_simulate_want_write(&test_ctx, 0, 0);
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Resume the DTLS 1.3 handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Verify post-handshake application data in both directions */
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- want_write_send_cb_helper (test_dtls.c lines 641,655) ---*/
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
struct test_dtls13_wwrite_ctx {
    int want_write;
    struct test_memio_ctx *text_ctx;
};
static int test_dtls13_want_write_send_cb(WOLFSSL *ssl, char *data, int sz, void *ctx)
{
    struct test_dtls13_wwrite_ctx *wwctx = (struct test_dtls13_wwrite_ctx *)ctx;
    wwctx->want_write = !wwctx->want_write;
    if (wwctx->want_write) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    return test_memio_write_cb(ssl, data, sz, wwctx->text_ctx);
}
#endif

/*-- every_write_want_write (test_dtls.c lines 665,740) ---*/
int test_dtls13_every_write_want_write(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char msg[] = "want-write";
    const int msgLen = sizeof(msg);
    char readBuf[sizeof(msg)];
    struct test_dtls13_wwrite_ctx wwctx_c;
    struct test_dtls13_wwrite_ctx wwctx_s;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    wwctx_c.want_write = 0;
    wwctx_c.text_ctx = &test_ctx;
    wolfSSL_SetIOWriteCtx(ssl_c, &wwctx_c);
    wolfSSL_SSLSetIOSend(ssl_c, test_dtls13_want_write_send_cb);
    wwctx_s.want_write = 0;
    wwctx_s.text_ctx = &test_ctx;
    wolfSSL_SetIOWriteCtx(ssl_s, &wwctx_s);
    wolfSSL_SSLSetIOSend(ssl_s, test_dtls13_want_write_send_cb);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);

    ExpectTrue(wolfSSL_is_init_finished(ssl_c));
    ExpectTrue(wolfSSL_is_init_finished(ssl_s));

    test_memio_simulate_want_write(&test_ctx, 0, 0);
    test_memio_simulate_want_write(&test_ctx, 1, 0);

    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SSLSetIOSend(ssl_c, test_memio_write_cb);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    wolfSSL_SSLSetIOSend(ssl_s, test_memio_write_cb);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    test_memio_simulate_want_write(&test_ctx, 0, 1);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_WRITE);
    test_memio_simulate_want_write(&test_ctx, 0, 0);
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    XMEMSET(readBuf, 0, sizeof(readBuf));
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_WRITE);
    test_memio_simulate_want_write(&test_ctx, 1, 0);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- epochs (test_dtls.c lines 823,871) ---*/
int test_dtls13_epochs(void) {
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte input[20];
    word32 inOutIdx = 0;

    XMEMSET(input, 0, sizeof(input));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    /* Some manual setup to enter the epoch check */
    ExpectTrue(ssl->options.tls1_3 = 1);

    inOutIdx = 0;
    if (ssl != NULL) ssl->keys.curEpoch64 = w64From32(0x0, 0x0);
    ExpectIntEQ(DoApplicationData(ssl, input, &inOutIdx, 0), SANITY_MSG_E);
    inOutIdx = 0;
    if (ssl != NULL) ssl->keys.curEpoch64 = w64From32(0x0, 0x2);
    ExpectIntEQ(DoApplicationData(ssl, input, &inOutIdx, 0), SANITY_MSG_E);

    if (ssl != NULL) ssl->keys.curEpoch64 = w64From32(0x0, 0x1);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, client_hello), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, server_hello), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, hello_verify_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, hello_retry_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, hello_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, encrypted_extensions), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, server_key_exchange), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, server_hello_done), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, client_key_exchange), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate_request), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate_verify), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, finished), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, certificate_status), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, change_cipher_hs), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, key_update), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, session_ticket), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, end_of_early_data), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, message_hash), SANITY_MSG_E);
    ExpectIntEQ(Dtls13CheckEpoch(ssl, no_shake), SANITY_MSG_E);

    wolfSSL_CTX_free(ctx);
    wolfSSL_free(ssl);
#endif
    return EXPECT_RESULT();
}

/*-- ack_order (test_dtls.c lines 873,951) ---*/
int test_dtls13_ack_order(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    word32 length = 0;
    /* struct {
     *     uint64 epoch;
     *     uint64 sequence_number;
     * } RecordNumber;
     * Big endian */
    static const unsigned char expected_output[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
    };

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Get a populated DTLS object */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    /* Clear the buffer of any extra messages */
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);

    /* Add seen records */
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 2)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 0)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 1)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 4)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 0)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 6)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3), w64From32(0, 6)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 1)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 2)), 0);
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 2), w64From32(0, 2)), 0);
    ExpectIntEQ(Dtls13WriteAckMessage(ssl_c, ssl_c->dtls13Rtx.seenRecords,
            ssl_c->dtls13Rtx.seenRecordsCount, &length), 0);

    if (EXPECT_SUCCESS()) {
        /* must zero the span reserved for the header to avoid read of uninited
         * data.
         */
        XMEMSET(ssl_c->buffers.outputBuffer.buffer, 0,
                5 /* DTLS13_UNIFIED_HEADER_SIZE */);
    }
    /* N * RecordNumber + 2 extra bytes for length */
    ExpectIntEQ(length, sizeof(expected_output) + 2);
    ExpectNotNull(mymemmem(ssl_c->buffers.outputBuffer.buffer,
            ssl_c->buffers.outputBuffer.bufferSize, expected_output,
            sizeof(expected_output)));

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- ack_overflow (test_dtls.c lines 953,1010) ---*/
int test_dtls13_ack_overflow(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    word32 length = 0;
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Edge case 1: one below limit - all inserts must succeed */
    for (i = 0; i < DTLS13_ACK_MAX_RECORDS - 1; i++) {
        ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 0),
                                    w64From32(0, (word32)i)), 0);
    }
    ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, DTLS13_ACK_MAX_RECORDS - 1);

    /* Edge case 2: insert the last allowed record - must succeed */
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 0),
                    w64From32(0, (word32)(DTLS13_ACK_MAX_RECORDS - 1))), 0);
    ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, DTLS13_ACK_MAX_RECORDS);

    /* Writing a full-but-valid list must succeed */
    ExpectIntEQ(Dtls13WriteAckMessage(ssl_c, ssl_c->dtls13Rtx.seenRecords,
                    ssl_c->dtls13Rtx.seenRecordsCount, &length), 0);

    /* Edge case 3: one over limit - must be silently dropped */
    ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 0),
                    w64From32(0, (word32)DTLS13_ACK_MAX_RECORDS)), 0);
    ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, DTLS13_ACK_MAX_RECORDS);

    if (EXPECT_SUCCESS()) {
        /* Bypass the insert guard to force the list one element over the limit,
         * then verify Dtls13WriteAckMessage errors out instead of
         * overflowing. */
        ssl_c->dtls13Rtx.seenRecordsCount = 0;
        ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 1),
                        w64From32(0, (word32)DTLS13_ACK_MAX_RECORDS)), 0);
        ssl_c->dtls13Rtx.seenRecordsCount =
                                           (word16)(DTLS13_ACK_MAX_RECORDS + 1);
        ExpectIntEQ(Dtls13WriteAckMessage(ssl_c, ssl_c->dtls13Rtx.seenRecords,
                        ssl_c->dtls13Rtx.seenRecordsCount, &length), BUFFER_E);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- ack_dup_write_counter (test_dtls.c lines 1012,1069) ---*/
int test_dtls13_ack_dup_write_counter(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(HAVE_WRITE_DUP)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_c2 = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    /* Drain any post-handshake messages */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Split ssl_c: ssl_c becomes READ_DUP_SIDE, ssl_c2 becomes WRITE_DUP_SIDE */
    ExpectNotNull(ssl_c2 = wolfSSL_write_dup(ssl_c));

    /* Cycle 1: add records, trigger handoff, verify counter is reset to 0 */
    for (i = 0; i < 5; i++)
        ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 3),
                                    w64From32(0, (word32)i)), 0);
    ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, 5);
    ssl_c->dtls13Rtx.sendAcks = 1;
    ExpectIntEQ(Dtls13DoScheduledWork(ssl_c), 0);
    /* seenRecords ownership was transferred to dupWrite->sendAckList;
     * seenRecordsCount must be reset to 0,  not left at 5. */
    ExpectNull(ssl_c->dtls13Rtx.seenRecords);
    ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, 0);

    /* Cycle 2 (different epoch to avoid the dup-filter): verify the counter
     * did not accumulate across the previous transfer.  Without the fix,
     * seenRecordsCount would now be 10 after this second batch. */
    for (i = 0; i < 5; i++)
        ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 4),
                                    w64From32(0, (word32)i)), 0);
    ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, 5);
    ssl_c->dtls13Rtx.sendAcks = 1;
    ExpectIntEQ(Dtls13DoScheduledWork(ssl_c), 0);
    ExpectNull(ssl_c->dtls13Rtx.seenRecords);
    ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_c2);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- get_message_seq_helper (test_dtls.c lines 1850,1867) ---*/
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS)
static int test_dtls13_get_message_seq(const char* msg, int msgSz,
    word16* msgSeq)
{
    int hsOff = DTLS_RECORD_HEADER_SZ;

    if (msg == NULL || msgSeq == NULL ||
            msgSz < DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ) {
        return BAD_FUNC_ARG;
    }

    *msgSeq = ((word16)(byte)msg[hsOff + 4] << 8) |
              (word16)(byte)msg[hsOff + 5];

    return WOLFSSL_SUCCESS;
}
#endif

/*-- ch2_rtx_no_ch1 (test_dtls.c lines 1869,1940) ---*/
int test_dtls13_ch2_rtx_no_ch1(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char* msg = NULL;
    int msgSz = 0;
    word16 ch1Seq = 0;
    int i;
    int foundCh1Seq = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    /* To force HRR */
    ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);

    /* CH1 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_memio_get_message(&test_ctx, 0, &msg, &msgSz, 0), 0);
    ExpectIntGE(msgSz, DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ);
    ExpectIntEQ(test_dtls13_get_message_seq(msg, msgSz, &ch1Seq),
        WOLFSSL_SUCCESS);

    /* HRR */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntGT(test_ctx.c_msg_count, 0);

    /* CH2 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntGT(test_ctx.s_msg_count, 0);

    /* Drop CH2 and trigger the client retransmission timeout. */
    test_memio_clear_buffer(&test_ctx, 0);
    if (wolfSSL_dtls13_use_quick_timeout(ssl_c))
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntGT(test_ctx.s_msg_count, 0);

    for (i = 0; i < test_ctx.s_msg_count && EXPECT_SUCCESS(); i++) {
        int hsOff = DTLS_RECORD_HEADER_SZ;
        word16 msgSeq = 0;

        ExpectIntEQ(test_memio_get_message(&test_ctx, 0, &msg, &msgSz, i), 0);
        /* memio stores one DTLS record per message in this handshake path. */
        if (msgSz >= DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ &&
                (byte)msg[0] == handshake && msg[hsOff] == client_hello) {
            ExpectIntEQ(test_dtls13_get_message_seq(msg, msgSz, &msgSeq),
                WOLFSSL_SUCCESS);
            if (msgSeq == ch1Seq)
                foundCh1Seq = 1;
        }
    }

    ExpectIntEQ(foundCh1Seq, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- frag_ch2_with_ch1_rtx (test_dtls.c lines 1942,2068) ---*/
int test_dtls13_frag_ch2_with_ch1_rtx(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) &&                           \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_DTLS) &&                        \
    defined(WOLFSSL_DTLS_MTU) && defined(WOLFSSL_DTLS_CH_FRAG) &&              \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char hrr[TEST_MEMIO_BUF_SZ];
    int hrrSz = (int)sizeof(hrr);
    char ch1Rtx[TEST_MEMIO_BUF_SZ];
    int ch1RtxSz = (int)sizeof(ch1Rtx);
    char ch2[TEST_MEMIO_BUF_SZ];
    int ch2Sz = 0;
    int ch2MsgCount = 0;
    int ch2MsgSizes[TEST_MEMIO_MAX_MSGS] = {0};
    /* The DTLS record sequence number occupies the last 8 bytes of the
     * record header. */
    int recordSeqOff = DTLS_RECORD_HEADER_SZ - 8;
    int ch2Seq = 0;
    int ch1RtxSeq = 0;
    int off;
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
        0);

    /* To force HRR */
    ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);

    /* CH1 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* HRR */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_memio_copy_message(&test_ctx, 1, hrr, &hrrSz, 0), 0);

    /* Drop HRR, trigger CH1 retransmission, copy and drop it */
    test_memio_clear_buffer(&test_ctx, 1);
    if (wolfSSL_dtls13_use_quick_timeout(ssl_c))
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, ch1Rtx, &ch1RtxSz, 0), 0);
    test_memio_clear_buffer(&test_ctx, 0);

    /* Force CH2 fragmentation. MTU must be small enough to fragment but large
     * enough that the cookie extension lands in the first fragment, otherwise
     * the server can't validate it statelessly and the test scenario (server
     * stateful after frag 1) does not hold. With --enable-all (PQ groups in
     * supported_groups), the cookie extension can sit ~400 bytes into CH2; 600
     * gives margin while still producing multiple fragments (CH2 is ~2KB). */
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, 600), WOLFSSL_SUCCESS);

    /* Forward HRR and let the client create fragmented CH2 */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 1, hrr, hrrSz), 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectIntGT(test_ctx.s_msg_count, 1);
    ExpectIntLE(test_ctx.s_msg_count, TEST_MEMIO_MAX_MSGS);
    ExpectIntLE(test_ctx.s_len, (int)sizeof(ch2));
    if (EXPECT_SUCCESS()) {
        ch2Sz = test_ctx.s_len;
        ch2MsgCount = test_ctx.s_msg_count;
        XMEMCPY(ch2, test_ctx.s_buff, ch2Sz);
        XMEMCPY(ch2MsgSizes, test_ctx.s_msg_sizes,
            sizeof(ch2MsgSizes[0]) * (size_t)ch2MsgCount);

        ch2Seq = ((byte)ch2[recordSeqOff + 4] << 8) |
                 (byte)ch2[recordSeqOff + 5];
        ch1RtxSeq = ch2Seq + ch2MsgCount;

        /* Synthesize a CH1 retransmission that can pass the replay window after
         * the first CH2 fragment makes the server stateful. The handshake
         * message_seq remains the original CH1 value; only the DTLS record
         * sequence is moved past the fragmented CH2 flight */
        ch1Rtx[recordSeqOff + 0] = 0;
        ch1Rtx[recordSeqOff + 1] = 0;
        ch1Rtx[recordSeqOff + 2] = 0;
        ch1Rtx[recordSeqOff + 3] = 0;
        ch1Rtx[recordSeqOff + 4] = (byte)(ch1RtxSeq >> 8);
        ch1Rtx[recordSeqOff + 5] = (byte)ch1RtxSeq;
    }

    test_memio_clear_buffer(&test_ctx, 0);

    /* Deliver CH2 first fragment only. Now server is stateful */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, ch2, ch2MsgSizes[0]), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Deliver the retransmitted CH1 between CH2 fragments, it should be
     * discarded as rtx */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, ch1Rtx, ch1RtxSz), 0);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    test_memio_clear_buffer(&test_ctx, 1);

    /* Deliver the rest of CH2 */
    off = ch2MsgSizes[0];
    for (i = 1; i < ch2MsgCount && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, ch2 + off,
            ch2MsgSizes[i]), 0);
        off += ch2MsgSizes[i];
    }

    /* Restore MTU so the client's input buffer can hold the full server
     * flight (e.g. an SH carrying a hybrid PQC key share). */
    ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, 1500), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- srtp_with_helper_and_stub (test_dtls.c lines 2276,2312) ---*/
#if defined(WOLFSSL_DTLS13) && defined(HAVE_SSL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_SRTP)
static int test_dtls_srtp_ctx_ready(WOLFSSL_CTX* ctx)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AEAD_AES_256_GCM:"
         "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32"),
          0);
    return EXPECT_RESULT();
}

int test_dtls_srtp(void)
{
    EXPECT_DECLS;
    test_ssl_cbf client_cbf;
    test_ssl_cbf server_cbf;

    XMEMSET(&client_cbf, 0, sizeof(client_cbf));
    XMEMSET(&server_cbf, 0, sizeof(server_cbf));

    client_cbf.method = wolfDTLSv1_3_client_method;
    client_cbf.ctx_ready = test_dtls_srtp_ctx_ready;
    server_cbf.method = wolfDTLSv1_3_server_method;
    server_cbf.ctx_ready = test_dtls_srtp_ctx_ready;

    ExpectIntEQ(test_wolfSSL_client_server_nofail_memio(&client_cbf,
        &server_cbf, NULL), TEST_SUCCESS);

    return EXPECT_RESULT();
}
#else
int test_dtls_srtp(void)
{
    EXPECT_DECLS;
    return EXPECT_RESULT();
}
#endif

/*-- min_rtx_interval (test_dtls.c lines 2890,2960) ---*/
int test_dtls13_min_rtx_interval(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && !defined(DTLS13_MIN_RTX_INTERVAL) && \
    !defined(NO_ASN_TIME)
    /* We don't want to test when DTLS13_MIN_RTX_INTERVAL is defined because
     * it may be too low to trigger reliably in a test. The default value is
     * 1 second which is sufficient for testing here. */
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int c_msg_count = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Setup DTLS 1.3 contexts */
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
                    wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* CH0 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), SSL_ERROR_WANT_READ);

    /* HRR */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), SSL_ERROR_WANT_READ);

    /* CH1 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), SSL_ERROR_WANT_READ);

    /* SH ... FINISHED */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), SSL_ERROR_WANT_READ);

    /* We should have SH ... FINISHED messages in the buffer */
    ExpectIntGE(test_ctx.c_msg_count, 2);

    /* Drop everything */
    test_memio_clear_buffer(&test_ctx, 1);

    /* First timeout. This one should trigger a retransmission */
    if (wolfSSL_dtls13_use_quick_timeout(ssl_s))
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), WOLFSSL_SUCCESS);
    /* Save the message count to make sure no new messages are sent */
    ExpectIntGE(test_ctx.c_msg_count, 2);
    c_msg_count = test_ctx.c_msg_count;

    /* Second timeout. This one should not trigger a retransmission */
    if (wolfSSL_dtls13_use_quick_timeout(ssl_s))
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), WOLFSSL_SUCCESS);
    /* This is the critical check. The message count should not increase
     * after the second timeout. DTLS13_MIN_RTX_INTERVAL should have blocked
     * retransmission here. */
    ExpectIntEQ(c_msg_count, test_ctx.c_msg_count);

    /* Now complete the handshake. We didn't clear the first retransmission
     * so the handshake should proceed without issues. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Cleanup */
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- no_session_id_echo (test_dtls.c lines 2965,3044) ---*/
int test_dtls13_no_session_id_echo(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    defined(HAVE_SESSION_TICKET) && defined(HAVE_ECC) && \
    !defined(WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    char readBuf[1];
    /* Pin to SECP256R1 to avoid a PQ-induced key-share HRR */
    int groups[] = { WOLFSSL_ECC_SECP256R1 };

    /* First connection: complete a DTLS 1.3 handshake to get a session */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Read to process any NewSessionTicket */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    /* Ensure the session has a non-empty session ID so the ClientHello
     * will have a populated legacy_session_id field (which is legal per
     * RFC 9147). */
    if (sess != NULL && sess->sessionIDSz == 0) {
        sess->sessionIDSz = ID_LEN;
        XMEMSET(sess->sessionID, 0x42, ID_LEN);
    }

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    /* Second connection: set the session on the client so the ClientHello
     * contains a non-empty legacy_session_id. Verify the server does NOT
     * echo it in the ServerHello. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups, 1), WOLFSSL_SUCCESS);
    /* Disable HRR cookie so the server directly sends a ServerHello */
    ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);

    /* Client sends ClientHello (with non-empty legacy_session_id) */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Server processes ClientHello and sends ServerHello + flight */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Verify the ServerHello on the wire.
     * Layout: DTLS Record Header (13) + DTLS Handshake Header (12) +
     *         ProtocolVersion (2) + Random (32) = offset 59 for
     *         legacy_session_id_echo length byte. */
    ExpectIntGE(test_ctx.c_len, 60);
    ExpectIntEQ(test_ctx.c_buff[0], handshake);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ], server_hello);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ +
        DTLS_HANDSHAKE_HEADER_SZ + OPAQUE16_LEN + RAN_LEN], 0);

    /* Complete the handshake */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- 5_9_0_compat (test_dtls.c lines 3049,3170) ---*/
int test_dtls13_5_9_0_compat(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID) && \
    defined(HAVE_ECC)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    char readBuf[1];
    /* Pin to SECP256R1 to avoid a PQ-induced key-share HRR */
    int groups[] = { WOLFSSL_ECC_SECP256R1 };
    /* RFC 8446 Section 4.1.3: an HRR is a ServerHello carrying this magic
     * random. Used to assert sub-test 1 is a real ServerHello, not an HRR. */
    static const byte hrrRandom[RAN_LEN] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    };

    /* --- initial connection: get a real session to carry the session ID --- */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* drain any NewSessionTicket before calling get1_session */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));

    /* Force a non-zero session ID - simulates a wolfSSL <=v5.9.0 client that
     * mistakenly sends 32 bytes as legacy_session_id in DTLS 1.3. */
    if (sess != NULL && sess->sessionIDSz == 0) {
        sess->sessionIDSz = ID_LEN;
        XMEMSET(sess->sessionID, 0x42, ID_LEN);
    }

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    /* --- sub-test 1: direct ServerHello (HRR cookie disabled) ---
     * Exercises DoTls13ClientHello (change 1) and
     * SendTls13ServerHello (change 2). */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);

    /* Client sends CH1 with non-empty legacy_session_id */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Server processes CH1 and sends ServerHello */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Verify that the ServerHello on the wire echoes the session ID.
     * Layout: DTLS Record Header (13) + DTLS Handshake Header (12) +
     *         ProtocolVersion (2) + Random (32) = byte 59 for
     *         legacy_session_id_echo length. */
    ExpectIntGE(test_ctx.c_len, 60);
    ExpectIntEQ(test_ctx.c_buff[0], handshake);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ], server_hello);
    /* Confirm it is a real ServerHello, not an HRR (also encoded as a
     * ServerHello but bearing the HelloRetryRequest magic random). */
    ExpectIntNE(XMEMCMP(&test_ctx.c_buff[DTLS_RECORD_HEADER_SZ +
        DTLS_HANDSHAKE_HEADER_SZ + OPAQUE16_LEN], hrrRandom, RAN_LEN), 0);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ +
        DTLS_HANDSHAKE_HEADER_SZ + OPAQUE16_LEN + RAN_LEN], ID_LEN);

    /* Complete the handshake - Finished MAC validates the transcript */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c); ssl_c = NULL;
    wolfSSL_free(ssl_s); ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c); ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s); ctx_s = NULL;

    /* --- sub-test 2: stateless HRR (HRR cookie enabled by default) ---
     * Exercises SendStatelessReplyDtls13 (change 4) and
     * RestartHandshakeHashWithCookie (change 3). */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, groups, 1), WOLFSSL_SUCCESS);

    /* Client sends CH1 */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Server sends stateless HRR (SendStatelessReplyDtls13) */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* Verify the HRR echoes the session ID at the same wire offset */
    ExpectIntGE(test_ctx.c_len, 60);
    ExpectIntEQ(test_ctx.c_buff[0], handshake);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ], server_hello);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ +
        DTLS_HANDSHAKE_HEADER_SZ + OPAQUE16_LEN + RAN_LEN], ID_LEN);

    /* Complete the handshake - Finished MAC validates RestartHandshakeHashWithCookie */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/*-- oversized_cert_chain (test_dtls.c lines 3174,3265) ---*/
int test_dtls13_oversized_cert_chain(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    XFILE f = XBADFILE;
    long sz = 0;
    byte *cert = NULL;
    byte *chain = NULL;
    int copies, off, i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    /* Read server cert */
    f = XFOPEN(svrCertFile, "rb");
    ExpectTrue(f != XBADFILE);
    if (EXPECT_SUCCESS()) {
        (void)XFSEEK(f, 0, XSEEK_END);
        sz = XFTELL(f);
        (void)XFSEEK(f, 0, XSEEK_SET);
    }
    ExpectTrue(sz > 0);
    cert = (byte*)XMALLOC((size_t)(sz + 1), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(cert);
    if (EXPECT_SUCCESS())
        ExpectIntEQ((int)XFREAD(cert, 1, (size_t)sz, f), (int)sz);
    if (f != XBADFILE)
        XFCLOSE(f);

    /* Build an oversized chain by duplicating the cert */
    copies = EXPECT_SUCCESS() ? (int)(70000 / sz) + 2 : 0;
    chain = (byte*)XMALLOC((size_t)(sz * copies + 1), NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(chain);
    off = 0;
    if (EXPECT_SUCCESS()) {
        for (i = 0; i < copies; i++) {
            XMEMCPY(chain + off, cert, (size_t)sz);
            off += (int)sz;
        }
    }

    /* Server context: load the oversized chain */
    ExpectNotNull(ctx_s = wolfSSL_CTX_new(wolfDTLSv1_3_server_method()));
    ExpectIntEQ(wolfSSL_CTX_use_certificate_chain_buffer(ctx_s,
        chain, (long)off), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIORecv(ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(ctx_s, test_memio_write_cb);
    }

    /* Client context: no verification (chain certs are duplicates) */
    ExpectNotNull(ctx_c = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    if (EXPECT_SUCCESS()) {
        wolfSSL_CTX_set_verify(ctx_c, WOLFSSL_VERIFY_NONE, NULL);
        wolfSSL_SetIORecv(ctx_c, test_memio_read_cb);
        wolfSSL_SetIOSend(ctx_c, test_memio_write_cb);
    }

    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
        wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    }

    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
        wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    }

    /* Handshake must not crash. If SendTls13Certificate mishandles the
     * oversized chain this will trigger a wild pointer dereference or stack
     * overflow resulting with the test failing.
     * The correct behaviour either returns BUFFER_E or succeeds
     * if the build config truncated the chain during loading. */
    (void)test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(chain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}
