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

/* Same as test_dtls13_frag_ch_pq but with the HRR cookie disabled on the
 * server, so the HelloRetryRequest carries no cookie extension (as a peer that
 * omits the optional DTLS 1.3 cookie would). The client must still send the
 * real (large) key share in the second ClientHello and let it fragment. */
int test_dtls13_frag_ch_pq_no_cookie(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_HAVE_MLKEM) \
    && defined(WOLFSSL_SEND_HRR_COOKIE)
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
    /* No cookie in the HRR: the server processes the first CH statelessly
     * disabled (dtlsStateful immediately) and reassembles the fragmented CH2. */
    ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_c), group_name);
    ExpectStrEQ(wolfSSL_get_curve_name(ssl_s), group_name);
    test_str_size = XSTRLEN("test") + 1;
    ExpectIntEQ(wolfSSL_write(ssl_c, test_str, test_str_size), test_str_size);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), test_str_size);
    ExpectIntEQ(XSTRCMP((char*)buf, test_str), 0);
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
    WOLFSSL_ALERT_HISTORY alertHistory;

    XMEMSET(input, 0, sizeof(input));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    /* Some manual setup to enter the epoch check */
    if (ssl != NULL) ssl->options.tls1_3 = 1;

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
    /* RFC 9147 5.6.1: EndOfEarlyData is not used in DTLS 1.3 and its receipt
     * must terminate the connection with an unexpected_message alert. */
    ExpectIntEQ(wolfSSL_get_alert_history(ssl, &alertHistory), WOLFSSL_SUCCESS);
    ExpectIntEQ(alertHistory.last_tx.level, alert_fatal);
    ExpectIntEQ(alertHistory.last_tx.code, unexpected_message);
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
    /* Flush the ACK those reads scheduled, so the seen-record list starts
     * empty and the counts below are exact. */
    TEST_DTLS13_PUMP(ssl_c);
    TEST_DTLS13_PUMP(ssl_s);

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
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* HRR */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* CH1 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* SH ... FINISHED */
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

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

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID) && \
    defined(HAVE_ECC)
/* RFC 8446 Section 4.1.3: an HRR is a ServerHello carrying this magic random.
 * Used to assert a real ServerHello was captured, not an HRR. */
static const byte hrrRandom[RAN_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};
#endif

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

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID) && \
    defined(HAVE_ECC)
/* Drive a compat-build resumption up to the point where the server's
 * ServerHello is sitting in the client's inbound buffer, echoing the session
 * ID the client sent. Returns 0 on success. */
static int compat_echo_setup(struct test_memio_ctx* test_ctx,
    WOLFSSL_CTX** ctx_c, WOLFSSL_CTX** ctx_s, WOLFSSL** ssl_c, WOLFSSL** ssl_s,
    WOLFSSL_SESSION** sess)
{
    EXPECT_DECLS;
    char readBuf[1];
    int groups[] = { WOLFSSL_ECC_SECP256R1 };
    int echoIdx = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ +
        OPAQUE16_LEN + RAN_LEN;

    XMEMSET(test_ctx, 0, sizeof(*test_ctx));
    ExpectIntEQ(test_memio_setup(test_ctx, ctx_c, ctx_s, ssl_c, ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(*ssl_c, groups, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(*ssl_c, *ssl_s, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_read(*ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(*ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(*sess = wolfSSL_get1_session(*ssl_c));

    /* A DTLS 1.3 client carries a ticket-derived session ID (SetTicket), so
     * the ClientHello legacy_session_id is non-empty. */
    ExpectIntEQ((*sess)->sessionIDSz, ID_LEN);

    wolfSSL_free(*ssl_c); *ssl_c = NULL;
    wolfSSL_free(*ssl_s); *ssl_s = NULL;
    wolfSSL_CTX_free(*ctx_c); *ctx_c = NULL;
    wolfSSL_CTX_free(*ctx_s); *ctx_s = NULL;

    XMEMSET(test_ctx, 0, sizeof(*test_ctx));
    ExpectIntEQ(test_memio_setup(test_ctx, ctx_c, ctx_s, ssl_c, ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_session(*ssl_c, *sess), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(*ssl_c, groups, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_disable_hrr_cookie(*ssl_s), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_negotiate(*ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(*ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_negotiate(*ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(*ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* A real ServerHello (not an HRR) echoing the client's session ID. */
    ExpectIntGE(test_ctx->c_len, echoIdx + 1 + ID_LEN);
    ExpectIntEQ(test_ctx->c_buff[DTLS_RECORD_HEADER_SZ], server_hello);
    ExpectIntNE(XMEMCMP(&test_ctx->c_buff[DTLS_RECORD_HEADER_SZ +
        DTLS_HANDSHAKE_HEADER_SZ + OPAQUE16_LEN], hrrRandom, RAN_LEN), 0);
    ExpectIntEQ(test_ctx->c_buff[echoIdx], ID_LEN);

    return EXPECT_RESULT() == TEST_SUCCESS ? 0 : -1;
}
#endif

/* The 5.9.0 compat path accepts an echoed legacy_session_id, but RFC 8446
 * Section 4.1.3 still requires the echo to be the value the client sent, so a
 * server echoing something else must be rejected. */
int test_dtls13_5_9_0_compat_bad_echo(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID) && \
    defined(HAVE_ECC)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    int echoIdx = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ +
        OPAQUE16_LEN + RAN_LEN;

    ExpectIntEQ(compat_echo_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        &sess), 0);

    /* Corrupt the echo so it no longer matches what the client sent. */
    if (EXPECT_SUCCESS())
        test_ctx.c_buff[echoIdx + 1] ^= 0xFF;

    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1),
        WC_NO_ERR_TRACE(INVALID_PARAMETER));

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A compat-enabled client must still interoperate with an RFC 9147 compliant
 * server, which omits the echo entirely. Rewrite the ServerHello to carry an
 * empty legacy_session_id_echo and confirm the client does not reject it. */
int test_dtls13_5_9_0_compat_empty_echo(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID) && \
    defined(HAVE_ECC)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL_SESSION *sess = NULL;
    int echoIdx = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ +
        OPAQUE16_LEN + RAN_LEN;
    /* DTLS record header: ... | length(2) at the end. */
    int recLenIdx = DTLS_RECORD_HEADER_SZ - OPAQUE16_LEN;
    /* DtlsHandShakeHeader: type(1) | length(3) | seq(2) | fragOff(3) |
     * fragLen(3). */
    int hsLenIdx = DTLS_RECORD_HEADER_SZ + OPAQUE8_LEN;
    int fragLenIdx = hsLenIdx + OPAQUE24_LEN + OPAQUE16_LEN + OPAQUE24_LEN;
    word32 hsLen, fragLen;
    word16 recLen;

    ExpectIntEQ(compat_echo_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        &sess), 0);

    if (EXPECT_SUCCESS()) {
        byte* b = test_ctx.c_buff;

        /* Drop the ID_LEN echo bytes and shrink the three enclosing lengths:
         * DTLS record length, handshake length, fragment length. */
        XMEMMOVE(&b[echoIdx + 1], &b[echoIdx + 1 + ID_LEN],
            (size_t)test_ctx.c_len - (size_t)(echoIdx + 1 + ID_LEN));
        b[echoIdx] = 0;
        /* c_msg_sizes tracks datagram boundaries separately, and read_cb hands
         * out exactly msg_sizes[pos] bytes - keep it in sync with c_len. */
        test_ctx.c_len -= ID_LEN;
        test_ctx.c_msg_sizes[0] -= ID_LEN;

        ato16(&b[recLenIdx], &recLen);
        c16toa((word16)(recLen - ID_LEN), &b[recLenIdx]);

        ato24(&b[hsLenIdx], &hsLen);
        c32to24(hsLen - ID_LEN, &b[hsLenIdx]);

        ato24(&b[fragLenIdx], &fragLen);
        c32to24(fragLen - ID_LEN, &b[fragLenIdx]);
    }

    /* The client must accept the empty echo and carry on. The rewrite breaks
     * the transcript, so it then waits for a flight that never validates
     * rather than rejecting the echo with INVALID_PARAMETER. */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    wolfSSL_SESSION_free(sess);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* wolfSSL_clear() wipes the DTLS 1.3 epoch table so a reused object does not
 * carry the previous connection's traffic keys. Everything that says which
 * epoch to use lives outside that table and only ever moves up, so it has to
 * be brought back with it. Run a second handshake over the same objects to
 * prove they really are reusable: with the table wiped and the numbers left
 * behind, Dtls13SetEpochKeys() fails the ClientHello with BAD_STATE_E. */
int test_dtls13_reuse_after_clear(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL))
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    char readBuf[16];
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* The handshake has to have moved off epoch 0, or the reset under test
     * has nothing to undo. */
    ExpectIntEQ(w64IsZero(ssl_c->dtls13Epoch), 0);
    ExpectIntEQ(w64IsZero(ssl_s->dtls13Epoch), 0);

    ExpectIntEQ(wolfSSL_write(ssl_c, "first", 5), 5);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 5);
    ExpectStrEQ(readBuf, "first");

    ExpectIntEQ(wolfSSL_clear(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_clear(ssl_s), WOLFSSL_SUCCESS);

    /* Only the unprotected epoch 0 survives, and the numbers agree with it. */
    for (i = 1; i < DTLS13_EPOCH_SIZE; i++) {
        ExpectIntEQ(ssl_c->dtls13Epochs[i].isValid, 0);
        ExpectIntEQ(ssl_s->dtls13Epochs[i].isValid, 0);
    }
    ExpectIntEQ(ssl_c->dtls13Epochs[0].isValid, 1);
    ExpectIntEQ(ssl_s->dtls13Epochs[0].isValid, 1);
    ExpectPtrEq(ssl_c->dtls13EncryptEpoch, &ssl_c->dtls13Epochs[0]);
    ExpectPtrEq(ssl_c->dtls13DecryptEpoch, &ssl_c->dtls13Epochs[0]);
    ExpectPtrEq(ssl_s->dtls13EncryptEpoch, &ssl_s->dtls13Epochs[0]);
    ExpectPtrEq(ssl_s->dtls13DecryptEpoch, &ssl_s->dtls13Epochs[0]);
    ExpectIntEQ(w64IsZero(ssl_c->dtls13Epoch), 1);
    ExpectIntEQ(w64IsZero(ssl_c->dtls13PeerEpoch), 1);
    ExpectIntEQ(w64IsZero(ssl_c->dtls13InvalidateBefore), 1);
    ExpectIntEQ(w64IsZero(ssl_s->dtls13Epoch), 1);
    ExpectIntEQ(w64IsZero(ssl_s->dtls13PeerEpoch), 1);
    ExpectIntEQ(w64IsZero(ssl_s->dtls13InvalidateBefore), 1);

    /* Whatever the first connection left in flight belongs to epochs that no
     * longer exist, so start the transport over as a new association would. */
    test_memio_clear_buffer(&test_ctx, 0);
    test_memio_clear_buffer(&test_ctx, 1);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectIntEQ(wolfSSL_write(ssl_c, "second", 6), 6);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), 6);
    ExpectStrEQ(readBuf, "second");

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
/* Dummy peer info callbacks for the session exporter/importer (required
 * unless built with WOLFSSL_SESSION_EXPORT_NOPEER). */
static int test_dtls13_export_get_peer(WOLFSSL* ssl, char* ip, int* ipSz,
        unsigned short* port, int* fam)
{
    (void)ssl;
    ip[0] = -1;
    *ipSz = 1;
    *port = 1;
    *fam = 2;
    return 1;
}

static int test_dtls13_export_set_peer(WOLFSSL* ssl, char* ip, int ipSz,
        unsigned short port, int fam)
{
    (void)ssl;
    (void)ip;
    (void)ipSz;
    (void)port;
    (void)fam;
    return 1;
}

static void test_dtls13_export_set_peer_cb(WOLFSSL_CTX* ctx)
{
    wolfSSL_CTX_SetIOGetPeer(ctx, test_dtls13_export_get_peer);
    wolfSSL_CTX_SetIOSetPeer(ctx, test_dtls13_export_set_peer);
}
#endif

/* Export of a DTLS 1.3 session must be refused mid-handshake, with a
 * KeyUpdate in flight and with a negotiated Connection ID. */
int test_dtls13_export_guards(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char buf[MAX_EXPORT_BUFFER];
    unsigned char readBuf[64];
    unsigned int sz;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);

    /* client: first flight sent, handshake not done */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    sz = sizeof(buf);
    ExpectIntEQ(wolfSSL_dtls_export(ssl_c, buf, &sz),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));
    sz = sizeof(buf);
    ExpectIntEQ(wolfSSL_dtls_export_state_only(ssl_c, buf, &sz),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));

    /* server: ClientHello consumed, handshake not done */
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    sz = sizeof(buf);
    ExpectIntEQ(wolfSSL_dtls_export(ssl_s, buf, &sz),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));
    sz = sizeof(buf);
    ExpectIntEQ(wolfSSL_dtls_export_state_only(ssl_s, buf, &sz),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* deliver the server's post-handshake NewSessionTickets and the client's
     * ACKs for them */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* KeyUpdate sent but not yet ACKed: export must refuse */
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
    if (ssl_c != NULL)
        ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 1);
    sz = sizeof(buf);
    ExpectIntEQ(wolfSSL_dtls_export(ssl_c, buf, &sz),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));
    sz = sizeof(buf);
    ExpectIntEQ(wolfSSL_dtls_export_state_only(ssl_c, buf, &sz),
        WC_NO_ERR_TRACE(NOT_READY_ERROR));

    /* deliver the KeyUpdate and its ACK */
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    if (ssl_c != NULL)
        ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 0);

    /* export must succeed again after the ACK */
    sz = sizeof(buf);
    ExpectIntGT(wolfSSL_dtls_export(ssl_c, buf, &sz), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = NULL;
    ssl_s = NULL;
    ctx_c = NULL;
    ctx_s = NULL;

#ifdef WOLFSSL_DTLS_CID
    /* connection with a negotiated CID: export must refuse */
    {
        unsigned char client_cid[] = { 1, 2, 3, 4 };
        unsigned char server_cid[] = { 5, 6, 7, 8 };

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        test_dtls13_export_set_peer_cb(ctx_c);
        test_dtls13_export_set_peer_cb(ctx_s);

        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, server_cid,
            sizeof(server_cid)), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
        ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, client_cid,
            sizeof(client_cid)), 1);

        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        sz = sizeof(buf);
        ExpectIntEQ(wolfSSL_dtls_export(ssl_s, buf, &sz),
            WC_NO_ERR_TRACE(DTLS_CID_ERROR));
        sz = sizeof(buf);
        ExpectIntEQ(wolfSSL_dtls_export_state_only(ssl_s, buf, &sz),
            WC_NO_ERR_TRACE(DTLS_CID_ERROR));

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif /* WOLFSSL_DTLS_CID */
#endif
    return EXPECT_RESULT();
}

/* Serialize an established DTLS 1.3 connection, restore it into a fresh
 * WOLFSSL object and continue the connection with the original peer. */
int test_dtls13_export_import_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char blob2[MAX_EXPORT_BUFFER];
    unsigned char readBuf[64];
    unsigned int sz, sz2;
    const char msgC[] = "client to server";
    const char msgS[] = "server to client";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* deliver NewSessionTickets and their ACKs */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    if (ssl_s != NULL)
        ExpectNull(ssl_s->dtls13Rtx.rtxRecords);

    /* some traffic so sequence numbers and windows are non-trivial */
    ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
        (int)sizeof(msgS));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
        (int)sizeof(msgS));

    /* a NULL output buffer returns the required size */
    sz = 0;
    ExpectIntEQ(wolfSSL_dtls_export(ssl_s, NULL, &sz), 0);
    ExpectIntEQ(sz, MAX_EXPORT_BUFFER);

    /* export the server, import into a fresh object from the same CTX */
    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);

    /* re-export of the imported object must be byte-identical */
    sz2 = sizeof(blob2);
    ExpectIntGT(wolfSSL_dtls_export(ssl_imp, blob2, &sz2), 0);
    ExpectIntEQ(sz2, sz);
    ExpectBufEQ(blob2, blob, sz);

    if (ssl_s != NULL && ssl_imp != NULL) {
        ExpectIntEQ(w64Equal(ssl_imp->dtls13Epoch, ssl_s->dtls13Epoch), 1);
        ExpectIntEQ(w64Equal(ssl_imp->dtls13PeerEpoch, ssl_s->dtls13PeerEpoch),
            1);
        ExpectNotNull(ssl_imp->dtls13EncryptEpoch);
        ExpectNotNull(ssl_imp->dtls13DecryptEpoch);
    }

    /* move the transport to the imported object */
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    /* traffic between the live client and the imported server */
    ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
        (int)sizeof(msgC));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_imp, readBuf, sizeof(readBuf)),
        (int)sizeof(msgC));
    ExpectStrEQ(readBuf, msgC);
    ExpectIntEQ(wolfSSL_write(ssl_imp, msgS, (int)sizeof(msgS)),
        (int)sizeof(msgS));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
        (int)sizeof(msgS));
    ExpectStrEQ(readBuf, msgS);

    /* same round trip for the client side */
    ssl_s = ssl_imp;
    ssl_imp = NULL;
    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_c, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_c));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_c);
    ssl_c = ssl_imp;
    ssl_imp = NULL;

    ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
        (int)sizeof(msgS));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
        (int)sizeof(msgS));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    ssl_c = NULL;
    ssl_s = NULL;
    ctx_c = NULL;
    ctx_s = NULL;

    /* run a mutual KeyUpdate so both directions move from epoch 3 to epoch 4
     * (wolfSSL responds to a peer KeyUpdate with its own) */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
    /* server: process KeyUpdate, ACK it, send responding KeyUpdate */
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    /* client: process ACK, process responding KeyUpdate and ACK it */
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    /* server: process the ACK of its responding KeyUpdate */
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    if (ssl_c != NULL) {
        ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 0);
        ExpectIntEQ(w64GetLow32(ssl_c->dtls13Epoch), DTLS13_EPOCH_TRAFFIC0 + 1);
        ExpectIntEQ(w64GetLow32(ssl_c->dtls13PeerEpoch),
            DTLS13_EPOCH_TRAFFIC0 + 1);
    }
    if (ssl_s != NULL) {
        ExpectIntEQ(ssl_s->dtls13WaitKeyUpdateAck, 0);
        ExpectIntEQ(w64GetLow32(ssl_s->dtls13Epoch), DTLS13_EPOCH_TRAFFIC0 + 1);
    }

    /* export/import the server at the post-KeyUpdate epoch */
    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_s);
    ssl_s = ssl_imp;
    ssl_imp = NULL;

    ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
        (int)sizeof(msgS));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
        (int)sizeof(msgS));

    /* export/import the client at the post-KeyUpdate epoch */
    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_c, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_c));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_c);
    ssl_c = ssl_imp;
    ssl_imp = NULL;

    ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msgC));
    ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
        (int)sizeof(msgS));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
        (int)sizeof(msgS));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
/* Walk the length-prefixed chunks of a serialized session and return the
 * payload offset and length of chunk chunkIdx (0 Options, 1 Keys,
 * 2 CipherSpecs, 3 PeerInfo, 4 Tls13State, 5 Dtls13State). Returns 0 on
 * success. Valid for DTLS blobs (no un-prefixed AES-CBC state involved). */
static int test_dtls13_export_find_chunk(const byte* blob, word32 sz,
    int chunkIdx, word32* off, word16* len)
{
    word32 idx = 2 * WOLFSSL_EXPORT_LEN; /* header and total length */
    word16 l;
    int i;

    if (sz > MAX_EXPORT_BUFFER)
        return -1;
    for (i = 0; i <= chunkIdx; i++) {
        if (idx + WOLFSSL_EXPORT_LEN > sz)
            return -1;
        l = (word16)((blob[idx] << 8) | blob[idx + 1]);
        idx += WOLFSSL_EXPORT_LEN;
        if (i == chunkIdx) {
            *off = idx;
            *len = l;
            return 0;
        }
        idx += l;
    }
    return -1;
}
#endif

/* Corrupt a valid exported blob and check each mutation is rejected with the
 * expected error. */
int test_dtls13_import_negative(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    /* field offsets inside the Dtls13State chunk */
    const word32 DTLS13_CHUNK_SEND_EPOCH_LO = 4;
    const word32 DTLS13_CHUNK_PEER_EPOCH_LO = 12;
    const word32 DTLS13_CHUNK_WINDOW_COUNT  = 40;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char bad[MAX_EXPORT_BUFFER + 64];
    unsigned char readBuf[64];
    unsigned int sz;
    word32 cut;
    word32 off = 0;
    word16 len = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    /* export argument checks */
    sz = sizeof(blob);
    ExpectIntEQ(wolfSSL_dtls_export(NULL, blob, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_dtls_export(ssl_s, blob, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* too small a buffer reports the needed size */
    sz = 16;
    ExpectIntEQ(wolfSSL_dtls_export(ssl_s, blob, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntGT(sz, 16);

    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);

    /* import argument checks */
    ExpectIntEQ(wolfSSL_dtls_import(NULL, blob, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, WOLFSSL_EXPORT_LEN),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* truncation at every position: with the total length field patched to
     * match, some chunk parser must reject the short buffer */
    for (cut = 2 * WOLFSSL_EXPORT_LEN; cut < sz && EXPECT_SUCCESS(); cut++) {
        XMEMCPY(bad, blob, cut);
        bad[WOLFSSL_EXPORT_LEN]     = (byte)((cut - WOLFSSL_EXPORT_LEN) >> 8);
        bad[WOLFSSL_EXPORT_LEN + 1] = (byte)(cut - WOLFSSL_EXPORT_LEN);
        ExpectIntLT(wolfSSL_dtls_import(ssl_imp, bad, cut), 0);
    }

    /* total length larger than the buffer */
    XMEMCPY(bad, blob, sz);
    bad[WOLFSSL_EXPORT_LEN]     = 0xFF;
    bad[WOLFSSL_EXPORT_LEN + 1] = 0xFF;
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* bad protocol byte */
    XMEMCPY(bad, blob, sz);
    bad[0] = 0xA8;
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* bad version nibble */
    XMEMCPY(bad, blob, sz);
    bad[1] = 0xA0;
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* unknown (future) export version 8 */
    XMEMCPY(bad, blob, sz);
    bad[1] = (byte)(((byte)DTLS_EXPORT_PRO & 0xF0) | 8);
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Keys chunk length field overflow */
    off = 0;
    len = 0;
    ExpectIntEQ(test_dtls13_export_find_chunk(blob, sz, 1, &off, &len), 0);
    if (EXPECT_SUCCESS() && off >= WOLFSSL_EXPORT_LEN && off + len <= sz) {
        XMEMCPY(bad, blob, sz);
        bad[off - WOLFSSL_EXPORT_LEN]     = 0xFF;
        bad[off - WOLFSSL_EXPORT_LEN + 1] = 0xFF;
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BUFFER_E));
    }

    /* Tls13State chunk */
    off = 0;
    len = 0;
    ExpectIntEQ(test_dtls13_export_find_chunk(blob, sz, 4, &off, &len), 0);
    if (EXPECT_SUCCESS() && off >= WOLFSSL_EXPORT_LEN && off + len <= sz) {
        /* length field overflow */
        XMEMCPY(bad, blob, sz);
        bad[off - WOLFSSL_EXPORT_LEN]     = 0xFF;
        bad[off - WOLFSSL_EXPORT_LEN + 1] = 0xFF;
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BUFFER_E));

        /* secret length not matching the negotiated cipher suite */
        XMEMCPY(bad, blob, sz);
        if (ssl_s != NULL) {
            ExpectIntGT(ssl_s->specs.hash_size, 0);
            bad[off] = (byte)(ssl_s->specs.hash_size ==
                WC_SHA256_DIGEST_SIZE ?
                WC_SHA384_DIGEST_SIZE : WC_SHA256_DIGEST_SIZE);
        }
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BAD_STATE_E));

        /* secret length above the largest supported secret */
        XMEMCPY(bad, blob, sz);
        bad[off] = 0xFF;
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BUFFER_E));
    }

    /* Dtls13State chunk */
    off = 0;
    len = 0;
    ExpectIntEQ(test_dtls13_export_find_chunk(blob, sz, 5, &off, &len), 0);
    ExpectIntEQ(len, WOLFSSL_EXPORT_DTLS13_SZ);
    if (EXPECT_SUCCESS() && off >= WOLFSSL_EXPORT_LEN && off + len <= sz) {
        /* send epoch below the first application traffic epoch */
        XMEMCPY(bad, blob, sz);
        bad[off + DTLS13_CHUNK_SEND_EPOCH_LO + 3] = DTLS13_EPOCH_HANDSHAKE;
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BAD_STATE_E));

        /* peer epoch below the first application traffic epoch */
        XMEMCPY(bad, blob, sz);
        bad[off + DTLS13_CHUNK_PEER_EPOCH_LO + 3] = DTLS13_EPOCH_HANDSHAKE;
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BAD_STATE_E));

        /* empty replay window */
        XMEMCPY(bad, blob, sz);
        bad[off + DTLS13_CHUNK_WINDOW_COUNT]     = 0;
        bad[off + DTLS13_CHUNK_WINDOW_COUNT + 1] = 0;
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BAD_STATE_E));

        /* huge replay window word count */
        XMEMCPY(bad, blob, sz);
        bad[off + DTLS13_CHUNK_WINDOW_COUNT]     = 0x7F;
        bad[off + DTLS13_CHUNK_WINDOW_COUNT + 1] = 0xFF;
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(BUFFER_E));

        /* a send epoch one above the peer epoch is a valid state and must
         * import */
        XMEMCPY(bad, blob, sz);
        bad[off + DTLS13_CHUNK_SEND_EPOCH_LO + 3] =
            DTLS13_EPOCH_TRAFFIC0 + 1;
        wolfSSL_free(ssl_imp);
        ssl_imp = NULL;
        ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz), (int)sz);
    }

    /* trailing garbage after the serialized session is ignored */
    XMEMCPY(bad, blob, sz);
    XMEMSET(bad + sz, 0xAA, 4);
    wolfSSL_free(ssl_imp);
    ssl_imp = NULL;
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz + 4), (int)sz);

    /* window words above ours are skipped (peer built with a larger
     * WOLFSSL_DTLS_WINDOW_WORDS) */
    off = 0;
    len = 0;
    ExpectIntEQ(test_dtls13_export_find_chunk(blob, sz, 5, &off, &len), 0);
    if (EXPECT_SUCCESS() && off >= WOLFSSL_EXPORT_LEN && off + len == sz) {
        XMEMCPY(bad, blob, off + len);
        XMEMSET(bad + off + len, 0xEE, 4); /* one extra window word */
        bad[off + DTLS13_CHUNK_WINDOW_COUNT + 1] =
            (byte)(WOLFSSL_DTLS_WINDOW_WORDS + 1);
        /* patch the chunk length and total length for the added word */
        bad[off - WOLFSSL_EXPORT_LEN]     = (byte)((len + 4) >> 8);
        bad[off - WOLFSSL_EXPORT_LEN + 1] = (byte)(len + 4);
        bad[WOLFSSL_EXPORT_LEN]     =
            (byte)((sz + 4 - WOLFSSL_EXPORT_LEN) >> 8);
        bad[WOLFSSL_EXPORT_LEN + 1] = (byte)(sz + 4 - WOLFSSL_EXPORT_LEN);
        wolfSSL_free(ssl_imp);
        ssl_imp = NULL;
        ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz + 4), (int)(sz + 4));
    }

    /* a DTLS 1.3 blob is not importable on a stream TLS 1.3 object */
    {
        WOLFSSL_CTX* ctx_tls = NULL;
        WOLFSSL* ssl_tls = NULL;

        ExpectNotNull(ctx_tls = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
        ExpectNotNull(ssl_tls = wolfSSL_new(ctx_tls));
        ExpectIntEQ(wolfSSL_tls_import(ssl_tls, blob, sz),
            WC_NO_ERR_TRACE(VERSION_ERROR));
        wolfSSL_free(ssl_tls);
        wolfSSL_CTX_free(ctx_tls);
    }

    /* a DTLS 1.3 blob is not importable on a DTLS 1.2 object */
    {
        WOLFSSL_CTX* ctx_12 = NULL;
        WOLFSSL* ssl_12 = NULL;

        ExpectNotNull(ctx_12 = wolfSSL_CTX_new(wolfDTLSv1_2_server_method()));
        ExpectNotNull(ssl_12 = wolfSSL_new(ctx_12));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_12, blob, sz),
            WC_NO_ERR_TRACE(VERSION_ERROR));
        wolfSSL_free(ssl_12);
        wolfSSL_CTX_free(ctx_12);
    }

    /* Unknown cipher suite bytes in the Options chunk are tolerated: the
     * suite lookup falls back to a placeholder name and the cipher
     * parameters used come from the CipherSpecs chunk. The suite bytes sit
     * 17 bytes before the end of the Options chunk (followed by the two
     * state machine bytes, minDowngrade, connect/accept/async state, the
     * four Encrypt-Then-MAC bytes, dtlsStateful and the two version
     * bytes). */
    off = 0;
    len = 0;
    ExpectIntEQ(test_dtls13_export_find_chunk(blob, sz, 0, &off, &len), 0);
    if (EXPECT_SUCCESS() && off + len <= sz && len >= 17) {
        XMEMCPY(bad, blob, sz);
        bad[off + len - 17] = 0xFF;
        bad[off + len - 16] = 0xFF;
        wolfSSL_free(ssl_imp);
        ssl_imp = NULL;
        ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz), (int)sz);
    }

    /* a DTLS session claiming a stream cipher type is rejected; the cipher
     * type byte follows the four 16-bit size fields and the bulk cipher
     * algorithm byte in the CipherSpecs chunk */
    off = 0;
    len = 0;
    ExpectIntEQ(test_dtls13_export_find_chunk(blob, sz, 2, &off, &len), 0);
    ExpectIntEQ(len, WOLFSSL_EXPORT_SPC_SZ);
    if (EXPECT_SUCCESS() && off + len <= sz) {
        XMEMCPY(bad, blob, sz);
        bad[off + 9] = stream;
        wolfSSL_free(ssl_imp);
        ssl_imp = NULL;
        ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, sz),
            WC_NO_ERR_TRACE(SANITY_CIPHER_E));
    }

    /* double import of the same blob is idempotent */
    wolfSSL_free(ssl_imp);
    ssl_imp = NULL;
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);

    /* the side of the connection comes from the blob, not from the CTX the
     * fresh object was created on */
    wolfSSL_free(ssl_imp);
    ssl_imp = NULL;
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_c));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    ExpectIntEQ(wolfSSL_GetSide(ssl_imp), WOLFSSL_SERVER_END);

    wolfSSL_free(ssl_imp);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* KeyUpdates keep working on an imported DTLS 1.3 connection, initiated from
 * either end, repeatedly. */
int test_dtls13_export_import_keyupdate(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char readBuf[64];
    unsigned int sz;
    const char msgC[] = "client data";
    const char msgS[] = "server data";
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_s);
    ssl_s = ssl_imp;
    ssl_imp = NULL;

    /* three KeyUpdates initiated by the imported server */
    for (i = 0; i < 3 && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wolfSSL_update_keys(ssl_s), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
            (int)sizeof(msgS));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
            (int)sizeof(msgS));
    }

    /* two KeyUpdates initiated by the live client */
    for (i = 0; i < 2 && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
            (int)sizeof(msgS));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
            (int)sizeof(msgS));
    }

    /* check both directions advanced five epochs */
    if (ssl_c != NULL) {
        ExpectIntEQ(w64GetLow32(ssl_c->dtls13Epoch), DTLS13_EPOCH_TRAFFIC0 + 5);
        ExpectIntEQ(w64GetLow32(ssl_c->dtls13PeerEpoch),
            DTLS13_EPOCH_TRAFFIC0 + 5);
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* The anti-replay window survives export/import: a record the original
 * connection already received, and a record received after import, are both
 * dropped when replayed into the imported connection. */
int test_dtls13_export_import_replay_window(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char readBuf[64];
    char oldRecord[256];
    char newRecord[256];
    int oldRecordSz = (int)sizeof(oldRecord);
    int newRecordSz = (int)sizeof(newRecord);
    unsigned int sz;
    const char msg1[] = "before export";
    const char msg2[] = "after import";
    const char msg3[] = "still alive";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    /* a record received by the original server before the export */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg1, (int)sizeof(msg1)),
        (int)sizeof(msg1));
    ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, oldRecord, &oldRecordSz,
        0), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msg1));

    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_s);
    ssl_s = ssl_imp;
    ssl_imp = NULL;

    /* replay of the pre-export record must be dropped */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, oldRecord,
        oldRecordSz), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* a record received once after import is dropped when replayed */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg2, (int)sizeof(msg2)),
        (int)sizeof(msg2));
    ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, newRecord, &newRecordSz,
        0), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msg2));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, newRecord,
        newRecordSz), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* normal traffic must still work after the replays */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg3, (int)sizeof(msg3)),
        (int)sizeof(msg3));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msg3));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* After a post-import KeyUpdate a replayed record of the retired epoch is
 * rejected by the imported connection. */
int test_dtls13_export_import_old_epoch_record(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char readBuf[64];
    char oldRecord[256];
    int oldRecordSz = (int)sizeof(oldRecord);
    unsigned int sz;
    const char msgA[] = "epoch three data";
    const char msgB[] = "epoch four data";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    /* an epoch 3 record, delivered and remembered for replay */
    ExpectIntEQ(wolfSSL_write(ssl_c, msgA, (int)sizeof(msgA)),
        (int)sizeof(msgA));
    ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, oldRecord, &oldRecordSz,
        0), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msgA));

    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_s);
    ssl_s = ssl_imp;
    ssl_imp = NULL;

    /* move both directions to epoch 4 */
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    /* the retired epoch 3 record must be rejected */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, oldRecord,
        oldRecordSz), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* epoch 4 traffic must still work */
    ExpectIntEQ(wolfSSL_write(ssl_c, msgB, (int)sizeof(msgB)),
        (int)sizeof(msgB));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msgB));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A KeyUpdate in flight toward the exported connection must complete against
 * the imported object, whether the record is delivered after the import or
 * lost and retransmitted. */
int test_dtls13_export_import_peer_keyupdate_inflight(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char readBuf[64];
    unsigned int sz;
    const char msgC[] = "client data";
    const char msgS[] = "server data";
    int i;

    /* i == 0: the in-flight KeyUpdate is delivered to the imported object.
     * i == 1: the in-flight KeyUpdate is lost with the original object and
     *         the client retransmits it to the imported one. */
    for (i = 0; i < 2 && EXPECT_SUCCESS(); i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        test_dtls13_export_set_peer_cb(ctx_c);
        test_dtls13_export_set_peer_cb(ctx_s);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

        /* export the server before the client sends a KeyUpdate toward it */
        sz = sizeof(blob);
        ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
        ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);

        ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
        wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
        wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
        wolfSSL_free(ssl_s);
        ssl_s = ssl_imp;
        ssl_imp = NULL;

        if (i == 1) {
            /* the KeyUpdate datagram is lost with the original process; the
             * client retransmits it on timeout. A quick timeout only flushes
             * ACKs, so a second timeout is needed to retransmit. */
            test_memio_clear_buffer(&test_ctx, 0);
            if (wolfSSL_dtls13_use_quick_timeout(ssl_c))
                ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_c), WOLFSSL_SUCCESS);
            ExpectIntGT(test_ctx.s_len, 0);
        }

        /* drive the KeyUpdate exchange against the imported server */
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        if (ssl_c != NULL) {
            ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 0);
            ExpectIntEQ(w64GetLow32(ssl_c->dtls13Epoch),
                DTLS13_EPOCH_TRAFFIC0 + 1);
            ExpectIntEQ(w64GetLow32(ssl_c->dtls13PeerEpoch),
                DTLS13_EPOCH_TRAFFIC0 + 1);
        }

        ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
            (int)sizeof(msgS));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
            (int)sizeof(msgS));

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
        ssl_c = NULL;
        ssl_s = NULL;
        ctx_c = NULL;
        ctx_s = NULL;
    }
#endif
    return EXPECT_RESULT();
}

/* A server exported right after the handshake still has the NewSessionTicket
 * records waiting to be acknowledged. Those are not carried in the export, so
 * the export must succeed and the imported connection must tolerate an ACK
 * for a record it no longer tracks. */
int test_dtls13_export_import_unacked_ticket(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT) && \
    defined(HAVE_SESSION_TICKET)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char readBuf[64];
    unsigned int sz;
    const char msgC[] = "client data";
    const char msgS[] = "server data";
    int i;

    /* i == 0: the client receives the tickets and ACKs them to the imported
     *         server, which no longer tracks those records.
     * i == 1: the tickets never reach the client at all. */
    for (i = 0; i < 2 && EXPECT_SUCCESS(); i++) {
        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        test_dtls13_export_set_peer_cb(ctx_c);
        test_dtls13_export_set_peer_cb(ctx_s);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        /* the handshake left the session tickets unacknowledged */
        if (ssl_s != NULL)
            ExpectNotNull(ssl_s->dtls13Rtx.rtxRecords);

        sz = sizeof(blob);
        ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
        ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
        /* the un-acknowledged records must not survive the import */
        if (ssl_imp != NULL)
            ExpectNull(ssl_imp->dtls13Rtx.rtxRecords);
        wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
        wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
        wolfSSL_free(ssl_s);
        ssl_s = ssl_imp;
        ssl_imp = NULL;

        if (i == 0) {
            /* the client reads the tickets and ACKs them */
            ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_c,
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)), WOLFSSL_ERROR_WANT_READ);
            /* the imported server must ignore the ACK for the dropped records */
            ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
            ExpectIntEQ(wolfSSL_get_error(ssl_s,
                WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)), WOLFSSL_ERROR_WANT_READ);
        }
        else {
            /* the tickets are lost in transit */
            test_memio_clear_buffer(&test_ctx, 1);
        }

        /* traffic must work in both variants */
        ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
            (int)sizeof(msgC));
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msgC));
        ExpectStrEQ(readBuf, msgC);
        ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
            (int)sizeof(msgS));
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
            (int)sizeof(msgS));
        ExpectStrEQ(readBuf, msgS);

        /* KeyUpdates must still work after the dropped records */
        ExpectIntEQ(wolfSSL_update_keys(ssl_s), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msgC));

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
        ssl_c = NULL;
        ssl_s = NULL;
        ctx_c = NULL;
        ctx_s = NULL;
    }
#endif
    return EXPECT_RESULT();
}

/* State-only export refreshes the volatile record layer state of an already
 * imported DTLS 1.3 session: the sequence numbers and the replay window of
 * the live connection are applied on top of a previously imported session
 * without carrying any key material. */
int test_dtls13_export_state_only_refresh(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char state[MAX_EXPORT_STATE_BUFFER];
    unsigned char readBuf[64];
    char staleRecord[256];
    int staleRecordSz = (int)sizeof(staleRecord);
    unsigned int sz;
    unsigned int stateSz;
    word32 i;
    const char msg[] = "traffic";
    Dtls13Epoch* eLive = NULL;
    Dtls13Epoch* eImp = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    /* the standby copy of the session */
    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);

    /* a NULL output buffer returns the required state blob size */
    stateSz = 0;
    ExpectIntEQ(wolfSSL_dtls_export_state_only(ssl_s, NULL, &stateSz), 0);
    ExpectIntEQ(stateSz, MAX_EXPORT_STATE_BUFFER);

    /* run traffic to advance sequence numbers and the replay window past
     * what the standby copy holds */
    for (i = 0; i < 4 && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)sizeof(msg)),
            (int)sizeof(msg));
        if (i == 0) {
            ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, staleRecord,
                &staleRecordSz, 0), 0);
        }
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msg));
        ExpectIntEQ(wolfSSL_write(ssl_s, msg, (int)sizeof(msg)),
            (int)sizeof(msg));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
            (int)sizeof(msg));
    }

    /* the standby copy is behind on both directions */
    if (ssl_s != NULL && ssl_imp != NULL) {
        eLive = Dtls13GetEpoch(ssl_s, ssl_s->dtls13Epoch);
        eImp  = Dtls13GetEpoch(ssl_imp, ssl_imp->dtls13Epoch);
        ExpectNotNull(eLive);
        ExpectNotNull(eImp);
        if (eLive != NULL && eImp != NULL) {
            ExpectIntEQ(w64Equal(eImp->nextSeqNumber, eLive->nextSeqNumber), 0);
            ExpectIntEQ(w64Equal(eImp->nextPeerSeqNumber,
                eLive->nextPeerSeqNumber), 0);
        }
    }

    /* refresh the standby copy from a state-only blob */
    stateSz = sizeof(state);
    ExpectIntGT(wolfSSL_dtls_export_state_only(ssl_s, state, &stateSz), 0);
    ExpectIntEQ(state[0], DTLS_EXPORT_STATE_PRO);
    ExpectIntEQ(state[1] & 0x0F, WOLFSSL_EXPORT_VERSION);
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, state, stateSz), (int)stateSz);

    /* the standby copy must match the live connection */
    if (ssl_s != NULL && ssl_imp != NULL) {
        eLive = Dtls13GetEpoch(ssl_s, ssl_s->dtls13Epoch);
        eImp  = Dtls13GetEpoch(ssl_imp, ssl_imp->dtls13Epoch);
        ExpectNotNull(eLive);
        ExpectNotNull(eImp);
        if (eLive != NULL && eImp != NULL) {
            ExpectIntEQ(w64Equal(eImp->nextSeqNumber, eLive->nextSeqNumber), 1);
            ExpectIntEQ(w64Equal(eImp->nextPeerSeqNumber,
                eLive->nextPeerSeqNumber), 1);
            ExpectIntEQ(XMEMCMP(eImp->window, eLive->window,
                sizeof(eImp->window)), 0);
        }
    }

    /* the refreshed copy must reject an already seen record */
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_s);
    ssl_s = ssl_imp;
    ssl_imp = NULL;

    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, staleRecord,
        staleRecordSz), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* normal traffic must still work */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, (int)sizeof(msg)),
        (int)sizeof(msg));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msg));
    ExpectStrEQ(readBuf, msg);
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, (int)sizeof(msg)),
        (int)sizeof(msg));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
        (int)sizeof(msg));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Negative cases for the DTLS 1.3 state-only blob. */
int test_dtls13_import_state_negative(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned char state[MAX_EXPORT_STATE_BUFFER];
    unsigned char bad[MAX_EXPORT_STATE_BUFFER];
    unsigned char readBuf[64];
    unsigned int sz;
    unsigned int stateSz;
    word32 cut;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

    sz = sizeof(blob);
    ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);

    stateSz = sizeof(state);
    ExpectIntGT(wolfSSL_dtls_export_state_only(ssl_s, state, &stateSz), 0);

    /* truncation at every position */
    for (cut = 2 * WOLFSSL_EXPORT_LEN; cut < stateSz && EXPECT_SUCCESS();
            cut++) {
        XMEMCPY(bad, state, cut);
        bad[WOLFSSL_EXPORT_LEN]     = (byte)((cut - WOLFSSL_EXPORT_LEN) >> 8);
        bad[WOLFSSL_EXPORT_LEN + 1] = (byte)(cut - WOLFSSL_EXPORT_LEN);
        ExpectIntLT(wolfSSL_dtls_import(ssl_imp, bad, cut), 0);
    }

    /* wrong protocol byte for a state blob */
    XMEMCPY(bad, state, stateSz);
    bad[0] = 0xA8;
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, stateSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* a pre-v7 state blob must be refused on a DTLS 1.3 object */
    XMEMCPY(bad, state, stateSz);
    bad[1] = (byte)(((byte)DTLS_EXPORT_STATE_PRO & 0xF0) |
                    ((byte)WOLFSSL_EXPORT_VERSION_6 & 0x0F));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, bad, stateSz),
        WC_NO_ERR_TRACE(VERSION_ERROR));

    /* a state blob whose epochs the target does not hold is refused: a state
     * refresh can not rebuild key material */
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    stateSz = sizeof(state);
    ExpectIntGT(wolfSSL_dtls_export_state_only(ssl_s, state, &stateSz), 0);
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, state, stateSz),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    wolfSSL_free(ssl_imp);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
/* Collects the session the library hands to the export callback. */
struct test_dtls13_export_cb_ctx {
    unsigned char blob[MAX_EXPORT_BUFFER];
    unsigned int  sz;
    int           calls;
};

static struct test_dtls13_export_cb_ctx test_dtls13_export_cb_state;

static int test_dtls13_export_cb(WOLFSSL* ssl, unsigned char* buf,
        unsigned int sz, void* userCtx)
{
    (void)ssl;
    (void)userCtx;
    if (sz > sizeof(test_dtls13_export_cb_state.blob))
        return -1;
    XMEMCPY(test_dtls13_export_cb_state.blob, buf, sz);
    test_dtls13_export_cb_state.sz = sz;
    test_dtls13_export_cb_state.calls++;
    return WOLFSSL_SUCCESS;
}
#endif

/* A DTLS 1.3 server with an export callback registered hands the serialized
 * session to it when the handshake completes, and that session is usable. */
int test_dtls13_export_callback(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    WOLFSSL *ssl_imp = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[64];
    const char msgC[] = "client data";
    const char msgS[] = "server data";

    XMEMSET(&test_dtls13_export_cb_state, 0,
        sizeof(test_dtls13_export_cb_state));
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    test_dtls13_export_set_peer_cb(ctx_c);
    test_dtls13_export_set_peer_cb(ctx_s);
    ExpectIntEQ(wolfSSL_CTX_dtls_set_export(ctx_s, test_dtls13_export_cb),
        WOLFSSL_SUCCESS);
    /* the callback is inherited by objects created after it is set */
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* the callback must have been invoked once with the serialized session */
    ExpectIntEQ(test_dtls13_export_cb_state.calls, 1);
    ExpectIntGT(test_dtls13_export_cb_state.sz, 0);
    ExpectIntEQ(test_dtls13_export_cb_state.blob[0], DTLS_EXPORT_PRO);
    ExpectIntEQ(test_dtls13_export_cb_state.blob[1] & 0x0F,
        WOLFSSL_EXPORT_VERSION);

    /* the callback's session must restore a working connection */
    ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, test_dtls13_export_cb_state.blob,
        test_dtls13_export_cb_state.sz),
        (int)test_dtls13_export_cb_state.sz);
    wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
    wolfSSL_free(ssl_s);
    ssl_s = ssl_imp;
    ssl_imp = NULL;

    /* the client still has the session tickets queued; drop them since the
     * exported session predates their acknowledgment */
    test_memio_clear_buffer(&test_ctx, 1);

    ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
        (int)sizeof(msgC));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
        (int)sizeof(msgC));
    ExpectStrEQ(readBuf, msgC);
    ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
        (int)sizeof(msgS));
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
        (int)sizeof(msgS));
    ExpectStrEQ(readBuf, msgS);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Export/import round trip across the DTLS 1.3 cipher suites: the secret and
 * key sizes differ (SHA-256 vs SHA-384) and ChaCha20-Poly1305 uses a
 * different record number protection cipher than the AES suites. */
int test_dtls13_export_import_ciphersuites(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SESSION_EXPORT)
    const char* suites[] = {
#ifndef NO_SHA256
#ifdef WOLFSSL_AES_128
#ifdef HAVE_AESGCM
        "TLS13-AES128-GCM-SHA256",
#endif
#ifdef HAVE_AESCCM
        "TLS13-AES128-CCM-SHA256",
#endif
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        "TLS13-CHACHA20-POLY1305-SHA256",
#endif
#endif
#if defined(WOLFSSL_SHA384) && defined(WOLFSSL_AES_256) && defined(HAVE_AESGCM)
        "TLS13-AES256-GCM-SHA384",
#endif
    };
    size_t i;

    for (i = 0; i < XELEM_CNT(suites) && EXPECT_SUCCESS(); i++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        WOLFSSL *ssl_imp = NULL;
        struct test_memio_ctx test_ctx;
        unsigned char blob[MAX_EXPORT_BUFFER];
        unsigned char readBuf[64];
        unsigned int sz;
        const char msgC[] = "client data";
        const char msgS[] = "server data";

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        test_dtls13_export_set_peer_cb(ctx_c);
        test_dtls13_export_set_peer_cb(ctx_s);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, suites[i]),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, suites[i]),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);

        sz = sizeof(blob);
        ExpectIntGT(wolfSSL_dtls_export(ssl_s, blob, &sz), 0);
        ExpectNotNull(ssl_imp = wolfSSL_new(ctx_s));
        ExpectIntEQ(wolfSSL_dtls_import(ssl_imp, blob, sz), (int)sz);
        wolfSSL_SetIOReadCtx(ssl_imp, &test_ctx);
        wolfSSL_SetIOWriteCtx(ssl_imp, &test_ctx);
        wolfSSL_free(ssl_s);
        ssl_s = ssl_imp;
        ssl_imp = NULL;

        /* traffic and a KeyUpdate on the restored connection */
        ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
            (int)sizeof(msgC));
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msgC));
        ExpectStrEQ(readBuf, msgC);
        ExpectIntEQ(wolfSSL_write(ssl_s, msgS, (int)sizeof(msgS)),
            (int)sizeof(msgS));
        XMEMSET(readBuf, 0, sizeof(readBuf));
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)),
            (int)sizeof(msgS));
        ExpectStrEQ(readBuf, msgS);

        ExpectIntEQ(wolfSSL_update_keys(ssl_s), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_write(ssl_c, msgC, (int)sizeof(msgC)),
            (int)sizeof(msgC));
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)),
            (int)sizeof(msgC));

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}
