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
#include <tests/api/test_dtls.h>
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

    /* Drain the post-handshake records on each side */
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectIntEQ(wolfSSL_shutdown(ssl_c), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), WOLFSSL_SHUTDOWN_NOT_DONE);
    ExpectIntEQ(wolfSSL_shutdown(ssl_c), 1);
    ExpectIntEQ(wolfSSL_shutdown(ssl_s), 1);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#else
int test_wolfSSL_dtls13_null_cipher(void)
{
    return TEST_SKIPPED;
}
#endif

#ifdef WOLFSSL_HAVE_MLKEM
#if defined(WOLFSSL_MLKEM_KYBER)
    #if !defined(WOLFSSL_NO_KYBER1024)
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_KYBER_LEVEL5
        #define TEST_DTLS13_PQ_GROUP_NAME "KYBER_LEVEL5"
    #elif !defined(WOLFSSL_NO_KYBER768)
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_KYBER_LEVEL3
        #define TEST_DTLS13_PQ_GROUP_NAME "KYBER_LEVEL3"
    #else
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_KYBER_LEVEL1
        #define TEST_DTLS13_PQ_GROUP_NAME "KYBER_LEVEL1"
    #endif
#elif !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
    #if !defined(WOLFSSL_NO_ML_KEM_1024)
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_ML_KEM_1024
        #define TEST_DTLS13_PQ_GROUP_NAME "ML_KEM_1024"
    #elif !defined(WOLFSSL_NO_ML_KEM_768)
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_ML_KEM_768
        #define TEST_DTLS13_PQ_GROUP_NAME "ML_KEM_768"
    #else
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_ML_KEM_512
        #define TEST_DTLS13_PQ_GROUP_NAME "ML_KEM_512"
    #endif
#elif !defined(WOLFSSL_NO_ML_KEM) && defined(WOLFSSL_PQC_HYBRIDS)
    #if defined(HAVE_CURVE25519) && !defined(WOLFSSL_NO_ML_KEM_768) && \
        ECC_MIN_KEY_SZ <= 256
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_X25519MLKEM768
        #define TEST_DTLS13_PQ_GROUP_NAME "X25519MLKEM768"
    #elif defined(HAVE_ECC) && !defined(NO_ECC_SECP) && \
        !defined(WOLFSSL_NO_ML_KEM_768) && \
        (!defined(NO_ECC256) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 256
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_SECP256R1MLKEM768
        #define TEST_DTLS13_PQ_GROUP_NAME "SecP256r1MLKEM768"
    #elif defined(HAVE_ECC) && !defined(NO_ECC_SECP) && \
        !defined(WOLFSSL_NO_ML_KEM_1024) && \
        (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 384
        #define TEST_DTLS13_PQ_GROUP      WOLFSSL_SECP384R1MLKEM1024
        #define TEST_DTLS13_PQ_GROUP_NAME "SecP384r1MLKEM1024"
    #endif
#endif
#endif /* WOLFSSL_HAVE_MLKEM */

int test_dtls13_frag_ch_pq(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(TEST_DTLS13_PQ_GROUP)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char *test_str = "test";
    int test_str_size;
    byte buf[255];
    int group = TEST_DTLS13_PQ_GROUP;
    const char *group_name = TEST_DTLS13_PQ_GROUP_NAME;

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
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(TEST_DTLS13_PQ_GROUP) \
    && defined(WOLFSSL_SEND_HRR_COOKIE)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char *test_str = "test";
    int test_str_size;
    byte buf[255];
    int group = TEST_DTLS13_PQ_GROUP;
    const char *group_name = TEST_DTLS13_PQ_GROUP_NAME;

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

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && ((defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE)) \
    || (defined(HAVE_SESSION_TICKET) && \
        defined(WOLFSSL_DTLS13_ECHO_LEGACY_SESSION_ID) && defined(HAVE_ECC)))
/* RFC 8446 Section 4.1.3: an HRR is a ServerHello carrying this magic random.
 * Used to assert a real ServerHello was captured, not an HRR. */
static const byte hrrRandom[RAN_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};
#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE)
/* Whether the first record the server has queued for the client is a plaintext
 * handshake record holding a ServerHello. When it is, *isHrr reports whether
 * its random is the HelloRetryRequest value. */
static int test_dtls13_reply_is_server_hello(
        const struct test_memio_ctx* test_ctx, int* isHrr)
{
    const int randomOff = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ +
        OPAQUE16_LEN;
    const char* msg = NULL;
    int msgSz = 0;

    *isHrr = 0;
    if (test_memio_get_message(test_ctx, 1, &msg, &msgSz, 0) != 0)
        return 0;
    if (msgSz < randomOff + RAN_LEN)
        return 0;
    if ((byte)msg[0] != handshake ||
            (byte)msg[DTLS_RECORD_HEADER_SZ] != server_hello)
        return 0;
    *isHrr = XMEMCMP(msg + randomOff, hrrRandom, RAN_LEN) == 0;
    return 1;
}
#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) \
    && ((defined(WOLFSSL_DTLS_MTU) && defined(WOLFSSL_AES_256)) || \
        (defined(HAVE_ECC) && !defined(NO_ECC256)))
/* Run the server until it has consumed every datagram queued for it. Whether
 * a reply was produced is for the caller to check in test_ctx->c_len. */
static int test_dtls13_server_read_all(struct test_memio_ctx* test_ctx,
        WOLFSSL* ssl_s)
{
    EXPECT_DECLS;
    /* wolfSSL_accept(), not wolfSSL_negotiate(): the generic accept path
     * decides whether the server starts out stateful */
    while (test_ctx->s_len > 0 && EXPECT_SUCCESS()) {
        int s_len = test_ctx->s_len;
        ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
        /* Fail if we didn't advance the buffer to avoid infinite loops */
        ExpectIntLT(test_ctx->s_len, s_len);
    }
    /* Expect all fragments read */
    ExpectIntEQ(test_ctx->s_len, 0);
    return EXPECT_RESULT();
}

#ifdef WOLFSSL_SEND_HRR_COOKIE
/* Deliver test_dtls13_four_frag_ch to the server one record per datagram and
 * run the server until it has consumed every datagram. */
static int test_dtls13_inject_four_frag_ch(struct test_memio_ctx* test_ctx,
        WOLFSSL* ssl_s)
{
    EXPECT_DECLS;
    const unsigned char* rec = test_dtls13_four_frag_ch;
    int len = (int)sizeof(test_dtls13_four_frag_ch);
    int records = 0;

    test_memio_clear_buffer(test_ctx, 0);
    while (len >= DTLS_RECORD_HEADER_SZ && EXPECT_SUCCESS()) {
        word16 payloadLen;
        int recLen;

        ato16(rec + DTLS_RECORD_HEADER_SZ - OPAQUE16_LEN, &payloadLen);
        recLen = DTLS_RECORD_HEADER_SZ + (int)payloadLen;
        ExpectIntLE(recLen, len);
        ExpectIntEQ(test_memio_inject_message(test_ctx, 0, (const char*)rec,
            recLen), 0);
        rec += recLen;
        len -= recLen;
        records++;
    }
    ExpectIntEQ(records, 4);
    ExpectIntEQ(test_ctx->s_len, sizeof(test_dtls13_four_frag_ch));
    ExpectIntEQ(test_dtls13_server_read_all(test_ctx, ssl_s), TEST_SUCCESS);
    return EXPECT_RESULT();
}
#endif
#endif

/* The retained bytes a pool holds for unverified ClientHellos */
#define TEST_DTLS_RX_UNVERIFIED_LIMIT WOLFSSL_DTLS_RX_UNVERIFIED_MAX_BYTES

#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
/* Entries in all shards */
static int test_dtls13_pool_count(const DtlsChPool* p)
{
    const DtlsMsg* m;
    int n = 0;
    int i;

    if (p == NULL)
        return -1;
    for (i = 0; i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++) {
        for (m = p->shard[i].head; m != NULL; m = m->next)
            n++;
    }
    return n;
}

/* Bytes retained by all shards */
static size_t test_dtls13_pool_bytes(const DtlsChPool* p)
{
    size_t n = 0;
    int i;

    for (i = 0; p != NULL && i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++)
        n += p->shard[i].bytes;
    return n;
}

/* Bytes the pool has reserved */
static size_t test_dtls13_pool_reserved(const DtlsChPool* p)
{
    return (size_t)WOLFSSL_ATOMIC_LOAD(p->reserved);
}

/* The entry that progressed next after m in any shard, or the least recently
 * progressed one of the pool when m is NULL */
static DtlsMsg* test_dtls13_pool_next(const DtlsChPool* p, const DtlsMsg* m)
{
    DtlsMsg* best = NULL;
    DtlsMsg* e;
    int i;

    for (i = 0; p != NULL && i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++) {
        for (e = p->shard[i].head; e != NULL; e = e->next) {
            if ((m == NULL || e->progress > m->progress) &&
                    (best == NULL || e->progress < best->progress))
                best = e;
        }
    }
    return best;
}

/* The least recently progressed entry of the pool */
static DtlsMsg* test_dtls13_pool_head(const DtlsChPool* p)
{
    return test_dtls13_pool_next(p, NULL);
}

/* The entry held for the peer test_dtls13_server_peer() set as id */
static DtlsMsg* test_dtls13_held_for(const DtlsChPool* p, int id)
{
    DtlsMsg* m;

    for (m = test_dtls13_pool_head(p); m != NULL;
            m = test_dtls13_pool_next(p, m)) {
        if (m->peer.sz == sizeof(int) &&
                XMEMCMP(m->peer.sa, &id, sizeof(int)) == 0)
            return m;
    }
    return NULL;
}

/* With no store in progress: the shards' counters match their entries, each
 * entry is in its hash's shard and in progress order, the reservation is what
 * the shards retain, the budget holds, and no entry is complete. */
static word32 test_dtls13_head_progress(const DtlsChPoolShard* sh)
{
    return (word32)WOLFSSL_ATOMIC_LOAD(sh->headProgress);
}

static word32 test_dtls13_next_progress(const DtlsChPoolShard* sh)
{
    return (word32)WOLFSSL_ATOMIC_LOAD(sh->nextProgress);
}

/* Whether sh publishes the progress of its head and of the entry after it,
 * 0 when there is none */
static int test_dtls13_head_progress_ok(const DtlsChPoolShard* sh)
{
    const DtlsMsg* next = sh->head != NULL ? sh->head->next : NULL;

    return test_dtls13_head_progress(sh) ==
            (sh->head != NULL ? sh->head->progress : 0U) &&
        test_dtls13_next_progress(sh) ==
            (next != NULL ? next->progress : 0U);
}

static int test_dtls13_pool_ok(const DtlsChPool* p)
{
    const DtlsMsg* m;
    int i;

    if (p == NULL)
        return 0;
    for (i = 0; i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++) {
        const DtlsChPoolShard* sh = &p->shard[i];

        if (!test_dtls13_head_progress_ok(sh))
            return 0;

        for (m = sh->head; m != NULL; m = m->next) {
            if (m->ready || DtlsChPoolShardIdx(&m->peer) != (word32)i)
                return 0;
            if (m->next != NULL && m->next->progress <= m->progress)
                return 0;
        }
        if (sh->bytes != DtlsMsgListRetainedBytes(sh->head))
            return 0;
    }
    return test_dtls13_pool_reserved(p) == test_dtls13_pool_bytes(p) &&
        test_dtls13_pool_bytes(p) <= TEST_DTLS_RX_UNVERIFIED_LIMIT;
}

/* Make m look as if it gained no bytes for longer than the pool keeps it */
static void test_dtls13_age(DtlsMsg* m)
{
    if (m != NULL)
        m->heldAt -= (word32)DTLS_TIMEOUT_MAX + 1;
}

/* Store bytes [off, off + len) of an sz byte ClientHello from peer id */
static int test_dtls13_pool_put(DtlsChPool* pool, int id, const byte* data,
        word32 sz, word32 off, word32 len)
{
    WOLFSSL_SOCKADDR peer;
    DtlsMsg* done = NULL;
    int ret;

    peer.sz = sizeof(id);
    peer.bufSz = sizeof(id);
    peer.sa = &id;
    ret = DtlsChPoolStore(pool, NULL, &peer, 0, 1, data, sz, client_hello, off,
        len, DTLS_TIMEOUT_MAX, NULL, &done);
    DtlsMsgListDelete(done, NULL);
    return ret;
}

static word32 test_dtls13_shard_of(int id)
{
    WOLFSSL_SOCKADDR peer;

    peer.sz = sizeof(id);
    peer.bufSz = sizeof(id);
    peer.sa = &id;
    return DtlsChPoolShardIdx(&peer);
}

/* The first id from id on whose shard is, or is not, shard */
static int test_dtls13_id_in(int id, word32 shard, int in)
{
    if (WOLFSSL_DTLS_CH_POOL_SHARDS == 1)
        return id;
    while ((test_dtls13_shard_of(id) == shard) != in)
        id++;
    return id;
}
#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
/* The context's pool */
static DtlsChPool* test_dtls13_ch_pool(WOLFSSL* s)
{
    if (s == NULL || s->ctx == NULL)
        return NULL;
    return &s->ctx->dtlsChPool;
}

/* Nothing of an unverified ClientHello is held: not in the context's pool
 * and not in the object's receive list */
static int test_dtls13_nothing_held(WOLFSSL* s)
{
    const DtlsChPool* p = test_dtls13_ch_pool(s);

    return p != NULL && test_dtls13_pool_count(p) == 0 &&
        test_dtls13_pool_bytes(p) == 0 && test_dtls13_pool_reserved(p) == 0 &&
        s->dtls_rx_msg_list == NULL;
}

#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
/* Point the server at the buffers and the peer identity of the next datagrams.
 * Memio has no address, so wolfSSL_dtls_set_peer() supplies one. */
static int test_dtls13_server_peer(WOLFSSL* ssl_s,
        struct test_memio_ctx* test_ctx, int peerId)
{
    wolfSSL_SetIOReadCtx(ssl_s, test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, test_ctx);
    return wolfSSL_dtls_set_peer(ssl_s, &peerId, sizeof(peerId));
}
#endif

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
/* Write body bytes [fragOff, fragOff + fragLen) of the message in record rec
 * as a record of its own, seq + recSeqAdd. Returns its size, or -1. */
static int test_dtls13_frag_range(const byte* rec, int recSz, word32 fragOff,
        word32 fragLen, word32 recSeqAdd, byte* out, int outSz)
{
    const int hdrSz = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
    const byte* hs = rec + DTLS_RECORD_HEADER_SZ;
    word32 msgLen, recSeq;

    if (recSz < hdrSz)
        return -1;
    ato24(hs + 1, &msgLen);
    if ((word32)recSz != (word32)hdrSz + msgLen || fragOff > msgLen ||
            fragLen > msgLen - fragOff ||
            (word32)outSz < (word32)hdrSz + fragLen)
        return -1;

    XMEMCPY(out, rec, hdrSz);
    /* low 32 bits of the 48-bit record sequence number */
    ato32(rec + DTLS_RECORD_HEADER_SZ - 6, &recSeq);
    c32toa(recSeq + recSeqAdd, out + DTLS_RECORD_HEADER_SZ - 6);
    c16toa((word16)(DTLS_HANDSHAKE_HEADER_SZ + fragLen),
        out + DTLS_RECORD_HEADER_SZ - 2);
    /* fragment_offset and fragment_length follow type(1) length(3) seq(2) */
    c32to24(fragOff, out + DTLS_RECORD_HEADER_SZ + 6);
    c32to24(fragLen, out + DTLS_RECORD_HEADER_SZ + 9);
    XMEMCPY(out + hdrSz, hs + DTLS_HANDSHAKE_HEADER_SZ + fragOff, fragLen);
    return hdrSz + (int)fragLen;
}

/* Write fragment fragIdx of the message in rec, fragSz body bytes at most, as
 * test_dtls13_frag_range(). Returns the size, 0 past the end, or -1. */
static int test_dtls13_frag_record(const byte* rec, int recSz, int fragSz,
        int fragIdx, byte* out, int outSz)
{
    const int hdrSz = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
    word32 msgLen, fragOff, fragLen;

    if (recSz < hdrSz)
        return -1;
    ato24(rec + DTLS_RECORD_HEADER_SZ + 1, &msgLen);
    if ((word32)recSz != (word32)hdrSz + msgLen)
        return -1;
    fragOff = (word32)fragIdx * (word32)fragSz;
    if (fragOff >= msgLen)
        return 0;
    fragLen = msgLen - fragOff;
    if (fragLen > (word32)fragSz)
        fragLen = (word32)fragSz;
    return test_dtls13_frag_range(rec, recSz, fragOff, fragLen,
        (word32)fragIdx, out, outSz);
}

/* Queue fragment fragIdx of the message in rec for the server. Returns 1 when
 * queued, 0 when there is no such fragment, -1 on error. */
static int test_dtls13_inject_frag(struct test_memio_ctx* test_ctx,
        const byte* rec, int recSz, int fragSz, int fragIdx)
{
    byte frag[TEST_MEMIO_BUF_SZ];
    int n = test_dtls13_frag_record(rec, recSz, fragSz, fragIdx, frag,
        (int)sizeof(frag));
    if (n <= 0)
        return n;
    if (test_memio_inject_message(test_ctx, 0, (const char*)frag, n) != 0)
        return -1;
    return 1;
}

/* Queue every fragment of the message in rec for the server, one datagram
 * each. Returns the number of fragments, or -1 on error. */
static int test_dtls13_inject_fragmented(struct test_memio_ctx* test_ctx,
        const byte* rec, int recSz, int fragSz)
{
    int i;
    for (i = 0; ; i++) {
        int ret = test_dtls13_inject_frag(test_ctx, rec, recSz, fragSz, i);
        if (ret < 0)
            return -1;
        if (ret == 0)
            return i;
    }
}

/* Client sends its first ClientHello; the record is copied to ch and removed
 * from the server's queue so the test can deliver it in pieces. */
static int test_dtls13_take_ch(struct test_memio_ctx* test_ctx,
        WOLFSSL* ssl_c, byte* ch, int* chSz)
{
    EXPECT_DECLS;
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    /* one record, whole ClientHello */
    ExpectIntEQ(test_ctx->s_msg_count, 1);
    ExpectIntEQ(test_memio_copy_message(test_ctx, 0, (char*)ch, chSz, 0), 0);
    test_memio_clear_buffer(test_ctx, 0);
    return EXPECT_RESULT();
}
#endif

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
    /* Hold nothing before the cookie verifies: a fragmented first ClientHello
     * is dropped, a second one accepted from the fragment with the cookie. */
    ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 0),
        WOLFSSL_SUCCESS);

    /* Reject fragmented first CH */
    ExpectIntEQ(test_dtls13_inject_four_frag_ch(&test_ctx, ssl_s),
        TEST_SUCCESS);
    /* Expect quietly dropping fragmented first CH */
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);

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

/* No-cookie accept is stateful before input, but notifies only on a complete
 * valid ClientHello. Retries and retransmitted fragments do not notify
 * again. */
int test_dtls13_frag_ch1_no_cookie(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE)
    int mode;
    int modes = 16;

#if defined(WOLFSSL_HAVE_MLKEM) && defined(OPENSSL_EXTRA)
    modes = 32;
#endif
    for (mode = 0; mode < modes && EXPECT_SUCCESS(); mode++) {
        WOLFSSL_CTX *ctx_s = NULL;
        WOLFSSL *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        int calls = 0;
        int records;
        int isHrr = 1;
        int offsets[5] = {0};
        int i;
        method_provider method_s = wolfDTLSv1_3_server_method;

#if defined(WOLFSSL_HAVE_MLKEM) && defined(OPENSSL_EXTRA)
        if (mode & 16)
            method_s = wolfDTLS_method;
#endif

        for (i = 0; i < 4; i++) {
            word16 payloadLen;
            ato16(test_dtls13_four_frag_ch + offsets[i] +
                DTLS_RECORD_HEADER_SZ - OPAQUE16_LEN, &payloadLen);
            offsets[i + 1] = offsets[i] + DTLS_RECORD_HEADER_SZ + payloadLen;
        }
        ExpectIntEQ(offsets[4], (int)sizeof(test_dtls13_four_frag_ch));

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, NULL, &ctx_s, NULL, &ssl_s,
            NULL, method_s), 0);
        if (!(mode & 16)) {
            ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1),
                WOLFSSL_SUCCESS);
        }
        ExpectIntEQ((mode & 1) ? wolfSSL_disable_hrr_cookie(ssl_s) :
            wolfSSL_disable_cookie(ssl_s), WOLFSSL_SUCCESS);
#if defined(WOLFSSL_HAVE_MLKEM) && defined(OPENSSL_EXTRA)
        if (mode & 16) {
            /* Promotion must enable the ML-KEM fragmentation default even
             * when cookies were disabled before the side was chosen. */
            ExpectIntEQ(ssl_s->options.side, WOLFSSL_NEITHER_END);
            wolfSSL_set_accept_state(ssl_s);
            ExpectIntEQ(ssl_s->options.sendCookie, 0);
        }
#endif
        ExpectIntEQ(wolfDTLS_SetChGoodCb(ssl_s, (mode & 8) ?
            test_dtls_no_cookie_ch_pause : test_dtls_no_cookie_ch_good,
            &calls), WOLFSSL_SUCCESS);
        /* Exercise both the generic and direct TLS 1.3 accept dispatch. */
        if (EXPECT_SUCCESS() && (mode & 2))
            ssl_s->options.tls1_3 = 1;

        ExpectIntEQ((mode & 2) ? wolfSSL_accept_TLSv13(ssl_s) :
            wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(calls, 0);
        ExpectIntEQ(ssl_s->options.dtlsStateful, 1);

        for (records = 0; records < 4 && EXPECT_SUCCESS(); records++) {
            const byte* rec;
            int recLen;

            /* Also accept a nonzero-offset fragment first. */
            i = records ^ ((mode & 4) ? 1 : 0);
            rec = test_dtls13_four_frag_ch + offsets[i];
            recLen = offsets[i + 1] - offsets[i];
            ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                (const char*)rec, recLen), 0);
            if ((mode & 8) && records == 3) {
                ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
                ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
                    WOLFSSL_ERROR_WANT_WRITE);
                ExpectIntEQ(calls, 1);
                /* A pause produces no reply for the peer. */
                ExpectIntEQ(test_ctx.c_len, 0);
            }
            ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
            ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
                WOLFSSL_ERROR_WANT_READ);
            /* Retry without new input: a pause is asked again, an accepted
             * ClientHello is not. */
            ExpectIntEQ(calls, records == 3 ? ((mode & 8) ? 2 : 1) : 0);
            ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
            ExpectIntEQ(test_ctx.s_len, 0);
            if (records == 0) {
                ExpectNotNull(ssl_s->dtls_rx_msg_list);
                ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
                ExpectIntEQ(test_ctx.c_len, 0);
                ExpectIntEQ(ssl_s->keys.dtls_expected_peer_handshake_number, 0);
                /* A retransmitted first fragment must not notify. */
                ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                    (const char*)rec, recLen), 0);
                ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
                ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
                    WOLFSSL_ERROR_WANT_READ);
                ExpectIntEQ(calls, 0);
            }
        }
        ExpectIntGT(test_ctx.c_len, 0);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
        ExpectIntEQ(isHrr, 0);
        ExpectIntEQ(ssl_s->keys.dtls_expected_peer_handshake_number, 1);
        ExpectIntEQ(ssl_s->keys.dtls_peer_handshake_number, 0);

        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}

/* Stateless accept rejects no-cookie mode without consuming input or changing
 * callbacks. Ordinary accept processes the complete CH and finishes
 * normally. */
int test_dtls13_no_cookie_handoff(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(HAVE_ECC) && defined(HAVE_SUPPORTED_CURVES) \
    && defined(WOLFSSL_SEND_HRR_COOKIE)
    int mode;

    for (mode = 0; mode < 8 && EXPECT_SUCCESS(); mode++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        int calls = 0;
        int group = WOLFSSL_ECC_SECP256R1;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        /* Exercise both a direct handshake and a key-share-only HRR/CH2. */
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_groups(ssl_s, &group, 1), WOLFSSL_SUCCESS);
        if (mode & 4)
            ExpectIntEQ(wolfSSL_NoKeyShares(ssl_c), WOLFSSL_SUCCESS);
        else
            ExpectIntEQ(wolfSSL_UseKeyShare(ssl_c, group), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfDTLS_SetChGoodCb(ssl_s, test_dtls_no_cookie_ch_good,
            &calls), WOLFSSL_SUCCESS);
        if (EXPECT_SUCCESS() && (mode & 2))
            ssl_s->options.tls1_3 = 1;
        ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
        if (mode & 1) {
            int queued = test_ctx.s_len;
            /* A fatal stateless rejection requires a separate SSL object. */
            WOLFSSL* rejected = wolfSSL_new(ctx_s);
            ExpectNotNull(rejected);
            wolfSSL_SetIOReadCtx(rejected, &test_ctx);
            ExpectIntEQ(wolfSSL_disable_hrr_cookie(rejected), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfDTLS_SetChGoodCb(rejected,
                test_dtls_no_cookie_ch_good, &calls), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfDTLS_accept_stateless(rejected),
                WOLFSSL_FATAL_ERROR);
            ExpectIntEQ(wolfSSL_get_error(rejected, WOLFSSL_FATAL_ERROR),
                WC_NO_ERR_TRACE(BAD_STATE_E));
            ExpectIntEQ(test_ctx.s_len, queued);
            ExpectIntEQ(test_ctx.c_len, 0);
            ExpectIntEQ(calls, 0);
            ExpectIntEQ(rejected->options.dtlsStateful, 0);
            ExpectTrue(rejected->chGoodCb == test_dtls_no_cookie_ch_good);
            ExpectTrue(rejected->chGoodCtx == &calls);
            ExpectIntEQ(rejected->options.disableRead, 0);
            ExpectIntEQ(rejected->options.returnOnGoodCh, 0);
            wolfSSL_free(rejected);
        }
        ExpectIntEQ(wolfSSL_accept(ssl_s), WOLFSSL_FATAL_ERROR);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, WOLFSSL_FATAL_ERROR),
            WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(calls, 1);
        ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
        ExpectIntEQ(calls, 1);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}


/* Clearing the pool frees every entry and leaves the setting alone */
int test_dtls13_clear_ch_pool_api(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_CTX *tls = NULL;
    struct test_memio_ctx test_ctx;
    byte peerBuf[4];
    WOLFSSL_SOCKADDR peer;
    byte data[8];
    DtlsMsg* done = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_CTX_dtls13_clear_ch_pool(NULL), BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_CTX_dtls13_clear_ch_pool(ctx_c), WOLFSSL_FAILURE);
    /* A context without a pool has nothing to clear */
    ExpectNotNull(tls = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectIntEQ(wolfSSL_CTX_dtls13_clear_ch_pool(tls), WOLFSSL_SUCCESS);
    wolfSSL_CTX_free(tls);

    XMEMSET(peerBuf, 1, sizeof(peerBuf));
    XMEMSET(data, 0x5a, sizeof(data));
    peer.sa = peerBuf;
    peer.sz = peer.bufSz = (unsigned int)sizeof(peerBuf);
    ExpectIntEQ(DtlsChPoolStore(test_dtls13_ch_pool(ssl_s), ctx_s->heap, &peer,
        0, 0, data, 8, client_hello, 0, 4, DTLS_TIMEOUT_MAX, ssl_s->heap,
        &done), 0);
    peerBuf[0] = 2;
    ExpectIntEQ(DtlsChPoolStore(test_dtls13_ch_pool(ssl_s), ctx_s->heap, &peer,
        0, 0, data, 8, client_hello, 0, 4, DTLS_TIMEOUT_MAX, ssl_s->heap,
        &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 2);
    ExpectIntEQ(wolfSSL_CTX_dtls13_clear_ch_pool(ctx_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectIntEQ(test_dtls13_pool_bytes(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectIntEQ(ctx_s->dtls13ReassembleChBeforeCookie, 1);
    /* The pool takes entries again */
    ExpectIntEQ(DtlsChPoolStore(test_dtls13_ch_pool(ssl_s), ctx_s->heap, &peer,
        0, 0, data, 8, client_hello, 0, 4, DTLS_TIMEOUT_MAX, ssl_s->heap,
        &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 1);
    ExpectIntEQ(wolfSSL_CTX_dtls13_clear_ch_pool(ctx_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* The knob, its argument checks and its context default. */
int test_dtls13_reassemble_ch_before_cookie_api(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(NULL, 1),
        BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_CTX_dtls13_reassemble_ch_before_cookie(NULL, 1),
        BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_c, 1),
        WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_CTX_dtls13_reassemble_ch_before_cookie(ctx_c, 1),
        WOLFSSL_FAILURE);

    /* On by default, inherited from the context */
    ExpectIntEQ(ssl_s->options.dtls13ReassembleChBeforeCookie, 1);
    ExpectIntEQ(wolfSSL_CTX_dtls13_reassemble_ch_before_cookie(ctx_s, 0),
        WOLFSSL_SUCCESS);
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    ExpectIntEQ(ssl_s->options.dtls13ReassembleChBeforeCookie, 0);
    ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtls13ReassembleChBeforeCookie, 1);
    ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 0),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtls13ReassembleChBeforeCookie, 0);

#if defined(HAVE_ECC) && !defined(NO_ECC256)
    {
        int group = WOLFSSL_ECC_SECP256R1;
        byte ch[TEST_MEMIO_BUF_SZ];
        int chSz = (int)sizeof(ch);
        int piece;

        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
            TEST_SUCCESS);
        piece = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 1) /
            2;
        ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 1),
            WOLFSSL_SUCCESS);

        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, 2),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 0), 1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);

        /* Turning an object off only stops it adding: the entries belong to
         * the context */
        ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 0),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, 3),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 0), 1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);

        /* Without a peer address nothing is held */
        ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 1),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_dtls_set_peer(ssl_s, NULL, 0), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 0), 1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
        ExpectNull(ssl_s->dtls_rx_msg_list);

        /* Turning the context off drops what its pool holds */
        ExpectIntEQ(wolfSSL_CTX_dtls13_reassemble_ch_before_cookie(ctx_s, 0),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
        ExpectIntEQ(test_dtls13_pool_bytes(&ctx_s->dtlsChPool), 0);
        ExpectNull(test_dtls13_pool_head(&ctx_s->dtlsChPool));
        ExpectIntEQ(test_ctx.c_len, 0);
    }
#endif

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A fragmented first ClientHello is reassembled and answered with a HRR, the
 * server still stateless after. Without a peer address it is dropped. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch1_reassemble_ex(int peerId)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);

    /* Canned four-fragment first ClientHello */
    ExpectIntEQ(test_dtls13_inject_four_frag_ch(&test_ctx, ssl_s),
        TEST_SUCCESS);
    if (peerId != 0) {
        ExpectIntGT(test_ctx.c_len, 0);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
        ExpectIntEQ(isHrr, 1);
    }
    else {
        ExpectIntEQ(test_ctx.c_len, 0);
    }
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    test_memio_clear_buffer(&test_ctx, 1);

    /* Real client. One classical group keeps its first ClientHello small and
     * in one record, which the test then splits into three datagrams. */
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_fragmented(&test_ctx, ch, chSz,
        (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) / 3), 3);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    if (peerId == 0) {
        /* No address: dropped. The whole ClientHello is answered. */
        ExpectIntEQ(test_ctx.c_len, 0);
        ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
        ExpectTrue(test_dtls13_nothing_held(ssl_s));
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
            chSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
    }
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch1_reassemble(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch1_reassemble_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch1_reassemble_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* The second ClientHello fragmented with the cookie past the first fragment,
 * as every peer sends it. Completed before the cookie check, or dropped. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch2_cookie_not_first_ex(int peerId)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    /* Shorter than legacy_version, random and the length bytes before the
     * extensions, so the first fragment holds no extension at all. */
    const int fragSz = 40;
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);

    /* CH1, HRR with cookie, CH2 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);

    /* Nothing held before the cookie verifies: every fragment is dropped */
    ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 0),
        WOLFSSL_SUCCESS);
    ExpectIntGE(test_dtls13_inject_fragmented(&test_ctx, ch, chSz, fragSz), 3);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* Reassembled, cookie verified on the complete message, server flight */
    ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(ssl_s, 1),
        WOLFSSL_SUCCESS);
    ExpectIntGE(test_dtls13_inject_fragmented(&test_ctx, ch, chSz, fragSz), 3);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    if (peerId == 0) {
        /* No address: dropped. The whole ClientHello is answered. */
        ExpectIntEQ(test_ctx.c_len, 0);
        ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
        ExpectTrue(test_dtls13_nothing_held(ssl_s));
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
            chSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
    }
    ExpectIntGT(test_ctx.c_len, 0);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch2_cookie_not_first(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch2_cookie_not_first_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch2_cookie_not_first_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
/* The offset in the body of the ClientHello in the plaintext DTLS record ch
 * just past its cookie extension, or 0 when it has none. */
static int test_dtls13_ch_cookie_end(const byte* ch, int chSz)
{
    const byte* body = ch + DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
    int sz = chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ;
    /* past legacy_version and random */
    int idx = OPAQUE16_LEN + RAN_LEN;
    int end;
    word16 len;

    /* legacy_session_id and the DTLS cookie field */
    if (idx >= sz)
        return 0;
    idx += 1 + body[idx];
    if (idx >= sz)
        return 0;
    idx += 1 + body[idx];
    /* cipher_suites */
    if (idx + OPAQUE16_LEN > sz)
        return 0;
    ato16(body + idx, &len);
    idx += OPAQUE16_LEN + len;
    /* legacy_compression_methods */
    if (idx >= sz)
        return 0;
    idx += 1 + body[idx];
    /* extensions */
    if (idx + OPAQUE16_LEN > sz)
        return 0;
    ato16(body + idx, &len);
    idx += OPAQUE16_LEN;
    end = idx + len;
    if (end > sz)
        return 0;
    while (idx + 2 * OPAQUE16_LEN <= end) {
        word16 type;

        ato16(body + idx, &type);
        ato16(body + idx + OPAQUE16_LEN, &len);
        idx += 2 * OPAQUE16_LEN + len;
        if (idx > end)
            return 0;
        if (type == TLSX_COOKIE)
            return idx;
    }
    return 0;
}
#endif

/* The second ClientHello fragmented with the cookie in the first fragment,
 * which arrives last: the held rest completes it at once. Aged, or without a
 * peer address, the rest is not held and the client must resend it. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch2_cookie_frag_last_ex(int peerId, int aged)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    byte frag[TEST_MEMIO_BUF_SZ];
    int fragSz = 0;
    /* Three fragments: the first ends just past the cookie extension and the
     * rest of the body is split in two. */
    int off[3] = { 0, 0, 0 };
    int len[3] = { 0, 0, 0 };
    int bodySz = 0;
    int i;
    int isHrr = 1;
    /* The later fragments are not there when the first verifies */
    int late = aged || peerId == 0;
    DtlsChPool* pool = NULL;
    DtlsMsg* held = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);

    /* CH1, HRR with cookie, CH2 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);

    bodySz = chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ;
    ExpectIntGT(len[0] = test_dtls13_ch_cookie_end(ch, chSz), 0);
    ExpectIntGE(bodySz - len[0], 2);
    off[1] = len[0];
    len[1] = (bodySz - len[0]) / 2;
    off[2] = off[1] + len[1];
    len[2] = bodySz - off[2];

    /* The later fragments are held: no reply, still stateless. Without an
     * address they are dropped. */
    for (i = 1; i < 3 && EXPECT_SUCCESS(); i++) {
        ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, (word32)off[i],
            (word32)len[i], (word32)i, frag, (int)sizeof(frag)), 0);
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
            (const char*)frag, fragSz), 0);
    }
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectNotNull(pool = test_dtls13_ch_pool(ssl_s));
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_pool_count(pool), 1);
        ExpectTrue(test_dtls13_pool_ok(pool));
        ExpectNotNull(held = test_dtls13_pool_head(pool));
        ExpectIntEQ(held != NULL ? (int)held->bytesReceived : -1,
            len[1] + len[2]);
        ExpectNull(ssl_s->dtls_rx_msg_list);
        if (aged)
            test_dtls13_age(held);
    }
    else {
        ExpectTrue(test_dtls13_nothing_held(ssl_s));
    }

    /* The first fragment verifies the cookie and, with the rest held, completes
     * the message at once. Otherwise the server waits for a resend. */
    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, (word32)off[0],
        (word32)len[0], 0, frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    if (late) {
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 0);
        ExpectIntEQ(test_dtls13_pool_count(pool), 0);
        ExpectTrue(test_dtls13_pool_ok(pool));
        ExpectNotNull(ssl_s->dtls_rx_msg_list);
        test_memio_clear_buffer(&test_ctx, 1);
        for (i = 1; i < 3 && EXPECT_SUCCESS(); i++) {
            ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz,
                (word32)off[i], (word32)len[i], (word32)(i + 2), frag,
                (int)sizeof(frag)), 0);
            ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                (const char*)frag, fragSz), 0);
        }
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
    }
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    ExpectIntEQ(test_dtls13_pool_count(pool), 0);
    ExpectTrue(test_dtls13_pool_ok(pool));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch2_cookie_frag_last(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch2_cookie_frag_last_ex(0, 0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch2_cookie_frag_last_ex(7, 0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch2_cookie_frag_last_ex(7, 1), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A forged first fragment, right length but no cookie, is held. When the
 * genuine one verifies the forged bytes must not replace the verified ones. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch2_forged_first_frag_ex(int peerId)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    byte bad[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int piece = 0;
    int isHrr = 1;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    /* CH1 and HRR */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    /* The cookie fits the first fragment: the last byte goes on its own. */
    piece = chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ - 1;

    /* Same framing, body past the version and random replaced */
    XMEMCPY(bad, ch, (size_t)chSz);
    XMEMSET(bad + DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ +
        OPAQUE16_LEN + RAN_LEN, 0xff, (size_t)(chSz - DTLS_RECORD_HEADER_SZ -
        DTLS_HANDSHAKE_HEADER_SZ - OPAQUE16_LEN - RAN_LEN));
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, bad, chSz, piece, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    /* Without an address it is dropped */
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)),
        peerId != 0 ? 1 : 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    ExpectIntEQ(test_dtls13_inject_fragmented(&test_ctx, ch, chSz, piece), 2);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    /* Nothing of the forged entry lies past the verified fragment: freed */
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch2_forged_first_frag(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch2_forged_first_frag_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch2_forged_first_frag_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A pooled fragment reaching into the first fragment that then verifies: the
 * bytes past it complete the ClientHello without a resend, the overlap is
 * taken from the verified copy. */
int test_dtls13_frag_ch2_overlap_handoff(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    byte frag[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int cut = 0;
    int bodySz = 0;
    int fragSz = 0;
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, 2),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);

    /* CH1, HRR with cookie, CH2 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    ExpectIntGT(cut = test_dtls13_ch_cookie_end(ch, chSz), 8);
    bodySz = chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ;

    /* The tail first, starting 8 bytes before the cookie ends: pooled */
    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, (word32)(cut - 8),
        (word32)(bodySz - (cut - 8)), 1, frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectIntEQ(test_ctx.c_len, 0);

    /* The first fragment, through the cookie, verifies and completes it */
    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, 0, (word32)cut, 0,
        frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
    ExpectNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Two peers fragment their first ClientHello at once on one server. Each is
 * reassembled and answered on its own, leaving the other's fragments. */
int test_dtls13_frag_ch1_interleaved_peers(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c1 = NULL, *ctx_c2 = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c1 = NULL, *ssl_c2 = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx1, test_ctx2;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch1[TEST_MEMIO_BUF_SZ], ch2[TEST_MEMIO_BUF_SZ];
    int ch1Sz = (int)sizeof(ch1), ch2Sz = (int)sizeof(ch2);
    const int hdrSz = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
    int fragSz1 = 0, fragSz2 = 0;
    int i;
    int isHrr = 0;

    XMEMSET(&test_ctx1, 0, sizeof(test_ctx1));
    XMEMSET(&test_ctx2, 0, sizeof(test_ctx2));
    ExpectIntEQ(test_memio_setup(&test_ctx1, &ctx_c1, &ctx_s, &ssl_c1, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx2, &ctx_c2, NULL, &ssl_c2, NULL,
        wolfDTLSv1_3_client_method, NULL), 0);
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c1, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c2, &group, 1), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_dtls13_take_ch(&test_ctx1, ssl_c1, ch1, &ch1Sz),
        TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx2, ssl_c2, ch2, &ch2Sz),
        TEST_SUCCESS);
    /* three fragments each */
    fragSz1 = (ch1Sz - hdrSz + 2) / 3;
    fragSz2 = (ch2Sz - hdrSz + 2) / 3;

    /* Deliver the fragments turn by turn. Neither ClientHello is complete
     * before its last fragment, so no reply until then. */
    for (i = 0; i < 2 && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx1, 1),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx1, ch1, ch1Sz, fragSz1, i),
            1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx1, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_ctx1.c_len, 0);
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx2, 2),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx2, ch2, ch2Sz, fragSz2, i),
            1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx2, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_ctx2.c_len, 0);
    }
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 2);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* Peer 1 completes: its HelloRetryRequest goes to peer 1 and peer 2's
     * partial ClientHello stays. */
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx1, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx1, ch1, ch1Sz, fragSz1, 2), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx1, ch1, ch1Sz, fragSz1, 3), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx1, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx1, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_ctx2.c_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectNotNull(test_dtls13_held_for(&ctx_s->dtlsChPool, 2));
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* Peer 2 completes */
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx2, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx2, ch2, ch2Sz, fragSz2, 2), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx2, ch2, ch2Sz, fragSz2, 3), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx2, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx2, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* One object serves one handshake: peer 1 goes on to complete it */
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx1, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_c1, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c1);
    wolfSSL_free(ssl_c2);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c1);
    wolfSSL_CTX_free(ctx_c2);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Exhaust the unverified byte budget with equal-sized partial ClientHellos. A
 * further peer evicts the oldest, while the newest peer is still served. */
int test_dtls13_frag_ch1_evict_oldest(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int fragSz;
    int peer;
    int capacity;
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    /* two fragments */
    fragSz = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 1) / 2;

    capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT /
        (sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket) + fragSz));
    ExpectIntGT(capacity, 1);
    /* The same ClientHello from one peer more than the byte budget holds. */
    for (peer = 1; peer <= capacity + 1 &&
            EXPECT_SUCCESS(); peer++) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peer),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, fragSz, 0),
            1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_ctx.c_len, 0);
    }
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), capacity);
    ExpectNull(test_dtls13_held_for(&ctx_s->dtlsChPool, 1));
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* Peer 1 was evicted: its second fragment starts a new entry that does not
     * complete, so no reply */
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, fragSz, 1), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), capacity);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));

    /* The newest peer is still held and completes */
    peer = capacity + 1;
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peer),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, fragSz, 1), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    /* Completion can require another eviction before the HRR frees it. */
    ExpectIntLE(test_dtls13_pool_count(&ctx_s->dtlsChPool), capacity - 1);
    ExpectNull(test_dtls13_held_for(&ctx_s->dtlsChPool, capacity + 1));
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* The announced completed allocation includes message and bucket metadata. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch1_over_bound_ex(int peerId)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    byte frag[TEST_MEMIO_BUF_SZ];
    int fragSz = 0;
    word32 maxPayload;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_dtls13_allow_ch_frag(ssl_s, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);

    /* First fragment of a message claiming one byte over the bound */
    ExpectIntGT(fragSz = test_dtls13_frag_record(ch, chSz, 100, 0, frag,
        (int)sizeof(frag)), 0);
    /* The last fragment is reserved as a new entry, so twice the metadata */
    maxPayload = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT - 2 * (sizeof(DtlsMsg) +
        sizeof(DtlsFragBucket) + ssl_s->buffers.dtlsCtx.peer.sz));
    /* A build whose protocol message limit is below the unverified budget
     * rejects at that limit instead. */
    maxPayload = min(maxPayload, MAX_HANDSHAKE_SZ);
    c32to24(maxPayload + 1,
        frag + DTLS_RECORD_HEADER_SZ + 1);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* At the bound it is held. No address: nothing held even within the
     * budget. */
    c32to24(maxPayload,
        frag + DTLS_RECORD_HEADER_SZ + 1);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    /* Freed with the context */
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)),
        peerId != 0 ? 1 : 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch1_over_bound(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch1_over_bound_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch1_over_bound_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A plaintext fragment reaching past its message is dropped, cookie exchange
 * on or off, and the genuine ClientHello is then answered. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_past_end_ex(int peerId)
{
    EXPECT_DECLS;
    int cookie;

    for (cookie = 0; cookie < 2 && EXPECT_SUCCESS(); cookie++) {
        WOLFSSL_CTX *ctx_c = NULL;
        WOLFSSL_CTX *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL;
        WOLFSSL *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        int group = WOLFSSL_ECC_SECP256R1;
        byte ch[TEST_MEMIO_BUF_SZ];
        int chSz = (int)sizeof(ch);
        byte frag[TEST_MEMIO_BUF_SZ];
        int fragSz = 0;
        int piece = 0;
        int isHrr = 0;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        if (peerId != 0) {
            ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
                WOLFSSL_SUCCESS);
        }
        if (!cookie) {
            ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);
        }
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
            TEST_SUCCESS);
        piece = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
            3;

        /* Last fragment, announcing a message that ends before it */
        ExpectIntGT(fragSz = test_dtls13_frag_record(ch, chSz, piece, 2, frag,
            (int)sizeof(frag)), 0);
        c32to24(10, frag + DTLS_RECORD_HEADER_SZ + 1);
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
            fragSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_ctx.c_len, 0);
        ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
        ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
        ExpectNull(ssl_s->dtls_rx_msg_list);

        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
            chSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
        ExpectIntEQ(isHrr, cookie);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_past_end(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_past_end_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_past_end_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A fragment planted before the cookie verifies, announcing another length,
 * is dropped when the cookie verifies: the stateful server must not fail. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch2_planted_fragment_ex(int peerId)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    byte frag[TEST_MEMIO_BUF_SZ];
    int fragSz = 0;
    int piece = 0;
    word32 msgLen = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    /* CH1 and HRR */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    /* The cookie fits the first fragment: the last byte goes on its own. */
    piece = chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ - 1;

    ExpectIntGT(fragSz = test_dtls13_frag_record(ch, chSz, piece, 1, frag,
        (int)sizeof(frag)), 0);
    if (EXPECT_SUCCESS()) {
        ato24(frag + DTLS_RECORD_HEADER_SZ + 1, &msgLen);
        c32to24(msgLen + 1, frag + DTLS_RECORD_HEADER_SZ + 1);
    }
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    /* Without an address it is dropped */
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)),
        peerId != 0 ? 1 : 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    ExpectIntEQ(test_dtls13_inject_fragmented(&test_ctx, ch, chSz, piece), 2);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectIntGT(test_ctx.c_len, 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectNull(ssl_s->dtls_rx_msg_list);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch2_planted_fragment(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch2_planted_fragment_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch2_planted_fragment_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A stale fragment of the second ClientHello, then the whole message: the
 * entry must not stay at the head of the list and stall later fragments. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && defined(WOLFSSL_DTLS_MTU) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
static int test_dtls13_frag_ch2_stale_fragment_ex(int peerId)
{
    EXPECT_DECLS;
    int mode;

    for (mode = 0; mode < 4 && EXPECT_SUCCESS(); mode++) {
        WOLFSSL_CTX *ctx_c = NULL;
        WOLFSSL_CTX *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL;
        WOLFSSL *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        int group = WOLFSSL_ECC_SECP256R1;
        byte ch[TEST_MEMIO_BUF_SZ];
        int chSz = (int)sizeof(ch);
        int piece = 0;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        if (peerId != 0) {
            ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
                WOLFSSL_SUCCESS);
        }
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
        if (mode & 1) {
            ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
                WOLFSSL_FILETYPE_PEM), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile,
                NULL), WOLFSSL_SUCCESS);
            wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER |
                WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
        /* CH1 and HRR */
        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
        ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
        ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
            TEST_SUCCESS);
        if (mode & 2) {
            ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_c, 400), WOLFSSL_SUCCESS);
            ExpectIntEQ(wolfSSL_dtls_set_mtu(ssl_s, 400), WOLFSSL_SUCCESS);
        }
        piece = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
            3;

        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 2), 1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        /* Without an address it is dropped */
        ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)),
            peerId != 0 ? 1 : 0);
        ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
        ExpectNull(ssl_s->dtls_rx_msg_list);

        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
            chSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
        ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
        ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
        ExpectNull(ssl_s->dtls_rx_msg_list);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
        ExpectNull(ssl_s->dtls_rx_msg_list);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch2_stale_fragment(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && defined(WOLFSSL_DTLS_MTU) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM)
    ExpectIntEQ(test_dtls13_frag_ch2_stale_fragment_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch2_stale_fragment_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A fragment whose length contradicts the held part of an unverified
 * ClientHello replaces it: a forger cannot pin the entry or fail the server. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch1_length_mismatch_ex(int peerId)
{
    EXPECT_DECLS;
    int forgedFirst;

    for (forgedFirst = 0; forgedFirst < 2 && EXPECT_SUCCESS(); forgedFirst++) {
        WOLFSSL_CTX *ctx_c = NULL;
        WOLFSSL_CTX *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL;
        WOLFSSL *ssl_s = NULL;
        struct test_memio_ctx test_ctx;
        int group = WOLFSSL_ECC_SECP256R1;
        byte ch[TEST_MEMIO_BUF_SZ];
        int chSz = (int)sizeof(ch);
        byte frag[TEST_MEMIO_BUF_SZ];
        int fragSz = 0;
        int piece = 0;
        int isHrr = 0;
        word32 msgLen = 0;
        DtlsChPool* pool = NULL;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
        if (peerId != 0) {
            ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
                WOLFSSL_SUCCESS);
        }
        ExpectNotNull(pool = test_dtls13_ch_pool(ssl_s));
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
            TEST_SUCCESS);
        piece = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
            3;

        if (!forgedFirst) {
            ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 0),
                1);
            ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
                TEST_SUCCESS);
            ExpectIntEQ(test_dtls13_pool_count(pool), peerId != 0 ? 1 : 0);
            ExpectTrue(test_dtls13_pool_ok(pool));
        }

        /* Second fragment announcing a longer message */
        ExpectIntGT(fragSz = test_dtls13_frag_record(ch, chSz, piece, 1, frag,
            (int)sizeof(frag)), 0);
        if (EXPECT_SUCCESS()) {
            ato24(frag + DTLS_RECORD_HEADER_SZ + 1, &msgLen);
            c32to24(msgLen + 1, frag + DTLS_RECORD_HEADER_SZ + 1);
        }
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
            fragSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_ctx.c_len, 0);
        ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
        if (peerId != 0) {
            /* Only the forged message is held */
            ExpectIntEQ(test_dtls13_pool_count(pool), 1);
            ExpectTrue(test_dtls13_pool_ok(pool));
            ExpectIntEQ(test_dtls13_pool_head(pool) != NULL ?
                test_dtls13_pool_head(pool)->sz : 0, msgLen + 1);
            ExpectNull(ssl_s->dtls_rx_msg_list);
        }
        else {
            ExpectTrue(test_dtls13_nothing_held(ssl_s));
        }

        /* The retransmitted ClientHello replaces it and completes */
        ExpectIntEQ(test_dtls13_inject_fragmented(&test_ctx, ch, chSz, piece),
            3);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        if (peerId == 0) {
            /* No address: dropped. The whole ClientHello is answered. */
            ExpectIntEQ(test_ctx.c_len, 0);
            ExpectTrue(test_dtls13_nothing_held(ssl_s));
            ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
                (const char*)ch, chSz), 0);
            ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
                TEST_SUCCESS);
        }
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
        ExpectIntEQ(isHrr, 1);
        ExpectIntEQ(test_dtls13_pool_count(pool), 0);
        ExpectTrue(test_dtls13_pool_ok(pool));
        ExpectNull(ssl_s->dtls_rx_msg_list);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch1_length_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch1_length_mismatch_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch1_length_mismatch_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A reassembled first ClientHello that fails to parse is released and the
 * stateless server goes on: the genuine ClientHello gets its HRR. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch1_bad_reassembled_ex(int peerId)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    byte bad[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int piece = 0;
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    if (peerId != 0) {
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peerId),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    piece = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) / 3;

    /* Same framing, body past the version and random replaced */
    XMEMCPY(bad, ch, (size_t)chSz);
    XMEMSET(bad + DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ +
        OPAQUE16_LEN + RAN_LEN, 0xff, (size_t)(chSz - DTLS_RECORD_HEADER_SZ -
        DTLS_HANDSHAKE_HEADER_SZ - OPAQUE16_LEN - RAN_LEN));
    ExpectIntEQ(test_dtls13_inject_fragmented(&test_ctx, bad, chSz, piece), 3);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    /* At most a stateless alert goes back. Without an address nothing is
     * reassembled, so nothing goes back. */
    if (peerId == 0) {
        ExpectIntEQ(test_ctx.c_len, 0);
    }
    else {
        ExpectTrue(test_ctx.c_len == 0 || test_ctx.c_buff[0] == alert);
    }
    test_memio_clear_buffer(&test_ctx, 1);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* Fresh record numbers for the genuine message */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
        chSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch1_bad_reassembled(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch1_bad_reassembled_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch1_bad_reassembled_ex(7), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* Peer 2's partial first ClientHello stays in the pool when peer 1's cookie
 * verifies and the server turns stateful; another server completes it. */
int test_dtls13_frag_ch2_verify_keeps_other_peers(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c1 = NULL, *ctx_c2 = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c1 = NULL, *ssl_c2 = NULL, *ssl_s = NULL, *c2 = NULL;
    struct test_memio_ctx test_ctx1, test_ctx2;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch1[TEST_MEMIO_BUF_SZ], ch2[TEST_MEMIO_BUF_SZ];
    int ch1Sz = (int)sizeof(ch1), ch2Sz = (int)sizeof(ch2);
    int piece1 = 0, piece2 = 0;
    int isHrr = 0;

    XMEMSET(&test_ctx1, 0, sizeof(test_ctx1));
    XMEMSET(&test_ctx2, 0, sizeof(test_ctx2));
    ExpectIntEQ(test_memio_setup(&test_ctx1, &ctx_c1, &ctx_s, &ssl_c1, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_setup(&test_ctx2, &ctx_c2, NULL, &ssl_c2, NULL,
        wolfDTLSv1_3_client_method, NULL), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c1, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c2, &group, 1), WOLFSSL_SUCCESS);

    /* Peer 1: CH1 and HRR */
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx1, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_c1), -1);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx1, ssl_c1, ch1, &ch1Sz),
        TEST_SUCCESS);
    /* The cookie fits the first fragment */
    piece1 = ch1Sz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ - 1;

    /* Peer 2: part of its first ClientHello */
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx2, ssl_c2, ch2, &ch2Sz),
        TEST_SUCCESS);
    piece2 = (ch2Sz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
        3;
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx2, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx2, ch2, ch2Sz, piece2, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx2, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectNull(ssl_s->dtls_rx_msg_list);

    /* Peer 1's second ClientHello verifies from its first fragment */
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx1, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx1, ch1, ch1Sz, piece1, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx1, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectIntEQ(ssl_s->dtls_rx_msg_list_sz, 1);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectNotNull(test_dtls13_held_for(&ctx_s->dtlsChPool, 2));
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx1, ch1, ch1Sz, piece1, 1), 1);
    ExpectIntEQ(test_memio_do_handshake(ssl_c1, ssl_s, 10, NULL), 0);
    ExpectNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectIntEQ(test_ctx2.c_len, 0);

    /* Another server of the context completes peer 2's ClientHello */
    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    ExpectIntEQ(test_dtls13_server_peer(c2, &test_ctx2, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx2, ch2, ch2Sz, piece2, 1), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx2, ch2, ch2Sz, piece2, 2), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx2, c2), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx2, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectIntEQ(test_memio_do_handshake(ssl_c2, c2, 10, NULL), 0);

    wolfSSL_free(ssl_c1);
    wolfSSL_free(ssl_c2);
    wolfSSL_free(c2);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c1);
    wolfSSL_CTX_free(ctx_c2);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Listener c1 holds partial ClientHellos from A and B and turns stateful with
 * A. B's stays with the context, and a second listener completes it. */
int test_dtls13_frag_ch_ctx_two_listeners(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_cA = NULL, *ctx_cB = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_cA = NULL, *ssl_cB = NULL, *c1 = NULL, *c2 = NULL;
    struct test_memio_ctx tA, tB;
    int group = WOLFSSL_ECC_SECP256R1;
    byte chA[TEST_MEMIO_BUF_SZ], chB[TEST_MEMIO_BUF_SZ];
    int chASz = (int)sizeof(chA), chBSz = (int)sizeof(chB);
    const int hdrSz = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
    int pieceA = 0, pieceB = 0;
    int isHrr = 0;
    DtlsMsg* held = NULL;

    XMEMSET(&tA, 0, sizeof(tA));
    XMEMSET(&tB, 0, sizeof(tB));
    ExpectIntEQ(test_memio_setup(&tA, &ctx_cA, &ctx_s, &ssl_cA, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_setup(&tB, &ctx_cB, NULL, &ssl_cB, NULL,
        wolfDTLSv1_3_client_method, NULL), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cA, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cB, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&tA, ssl_cA, chA, &chASz), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&tB, ssl_cB, chB, &chBSz), TEST_SUCCESS);
    pieceA = (chASz - hdrSz + 2) / 3;
    pieceB = (chBSz - hdrSz + 2) / 3;
    /* The pool allocates as the context's objects do, so a completed
     * ClientHello is handed over without a copy */
    ExpectNotNull(ctx_s);
    ExpectNotNull(c1);
    if (EXPECT_SUCCESS())
        ExpectPtrEq(ctx_s->heap, c1->heap);

    /* A's first fragment and two of B's at c1 */
    ExpectIntEQ(test_dtls13_server_peer(c1, &tA, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tA, chA, chASz, pieceA, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tA, c1), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_server_peer(c1, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 0), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 1), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(tA.c_len, 0);
    ExpectIntEQ(tB.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 2);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectNull(c1->dtls_rx_msg_list);

    /* A completes and gets its HelloRetryRequest */
    ExpectIntEQ(test_dtls13_server_peer(c1, &tA, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tA, chA, chASz, pieceA, 1), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&tA, chA, chASz, pieceA, 2), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tA, c1), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&tA, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);

    /* c1 serves A. B's partial stays with the context. */
    ExpectIntEQ(test_memio_do_handshake(ssl_cA, c1, 10, NULL), 0);
    ExpectIntEQ(c1->options.dtlsStateful, 1);
    ExpectIntEQ(tB.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectNotNull(held = test_dtls13_held_for(&ctx_s->dtlsChPool, 2));
    ExpectIntEQ(held != NULL ? (int)held->bytesReceived : -1, 2 * pieceB);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));

    /* A second listener completes B's ClientHello */
    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    ExpectIntEQ(test_dtls13_server_peer(c2, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 2), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&tB, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(c2->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectIntEQ(test_memio_do_handshake(ssl_cB, c2, 10, NULL), 0);

    wolfSSL_free(c2);
    wolfSSL_free(c1);
    wolfSSL_free(ssl_cA);
    wolfSSL_free(ssl_cB);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_cA);
    wolfSSL_CTX_free(ctx_cB);
#endif
    return EXPECT_RESULT();
}

/* A partial ClientHello held by the context outlives the server that stored
 * it, and a later server of the context completes it. */
int test_dtls13_frag_ch_ctx_survives_listener_free(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_cB = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_cB = NULL, *c1 = NULL, *c2 = NULL;
    struct test_memio_ctx tB;
    int group = WOLFSSL_ECC_SECP256R1;
    byte chB[TEST_MEMIO_BUF_SZ];
    int chBSz = (int)sizeof(chB);
    int pieceB = 0;
    int isHrr = 0;

    XMEMSET(&tB, 0, sizeof(tB));
    ExpectIntEQ(test_memio_setup(&tB, &ctx_cB, &ctx_s, &ssl_cB, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cB, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&tB, ssl_cB, chB, &chBSz), TEST_SUCCESS);
    pieceB = (chBSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
        3;

    ExpectIntEQ(test_dtls13_server_peer(c1, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 0), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 1), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(tB.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);

    wolfSSL_free(c1);
    c1 = NULL;
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectNotNull(test_dtls13_held_for(&ctx_s->dtlsChPool, 2));
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));

    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    ExpectIntEQ(test_dtls13_server_peer(c2, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 2), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&tB, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(c2->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectIntEQ(test_memio_do_handshake(ssl_cB, c2, 10, NULL), 0);

    wolfSSL_free(c2);
    wolfSSL_free(ssl_cB);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_cB);
#endif
    return EXPECT_RESULT();
}

/* The application drops its context reference while a server holds it: the
 * server still stores in the pool, freed with the context when it goes. */
int test_dtls13_frag_ch_ctx_free_pending(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int piece = 0;
    int peer;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    piece = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 1) / 2;

    for (peer = 1; peer <= 3 && EXPECT_SUCCESS(); peer++) {
        if (peer == 3) {
            /* Only the server's reference is left */
            wolfSSL_CTX_free(ctx_s);
            ctx_s = NULL;
        }
        ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, peer),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 0), 1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_ctx.c_len, 0);
        ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), peer);
        ExpectTrue(test_dtls13_pool_ok(test_dtls13_ch_pool(ssl_s)));
    }

    /* The last reference: the context and its entries go */
    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* The budget is shared by every server of the context: a store through one
 * evicts an entry another stored, and either completes any entry. */
int test_dtls13_frag_ch1_ctx_shared_budget(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *c1 = NULL, *c2 = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int fragSz;
    int peer;
    int capacity;
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    /* two fragments */
    fragSz = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 1) / 2;
    capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT /
        (sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket) + fragSz));
    ExpectIntGT(capacity, 1);

    /* Odd peers through c1, even ones and the last through c2 */
    for (peer = 1; peer <= capacity + 1 && EXPECT_SUCCESS(); peer++) {
        WOLFSSL* s = (peer % 2 == 1 && peer <= capacity) ? c1 : c2;
        ExpectIntEQ(test_dtls13_server_peer(s, &test_ctx, peer),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, fragSz, 0),
            1);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, s), TEST_SUCCESS);
        ExpectIntEQ(test_ctx.c_len, 0);
    }
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), capacity);
    /* Stored through c1, evicted by c2's store */
    ExpectNull(test_dtls13_held_for(&ctx_s->dtlsChPool, 1));
    ExpectNotNull(test_dtls13_held_for(&ctx_s->dtlsChPool, capacity + 1));
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectNull(c1->dtls_rx_msg_list);
    ExpectNull(c2->dtls_rx_msg_list);

    /* c1 completes what c2 started */
    ExpectIntEQ(test_dtls13_server_peer(c1, &test_ctx, capacity + 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, fragSz, 1), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, c1), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectNull(test_dtls13_held_for(&ctx_s->dtlsChPool, capacity + 1));
    ExpectIntLE(test_dtls13_pool_count(&ctx_s->dtlsChPool), capacity - 1);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));

    wolfSSL_free(c1);
    wolfSSL_free(c2);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
/* Deliver body bytes [off, off + len) of the message in rec to server s as a
 * record of its own and run s until it has read it */
static int test_dtls13_deliver_range(struct test_memio_ctx* test_ctx,
        WOLFSSL* s, const byte* rec, int recSz, word32 off, word32 len,
        word32 recSeqAdd)
{
    EXPECT_DECLS;
    byte frag[TEST_MEMIO_BUF_SZ];
    int fragSz = 0;

    ExpectIntGT(fragSz = test_dtls13_frag_range(rec, recSz, off, len,
        recSeqAdd, frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(test_ctx, s), TEST_SUCCESS);
    return EXPECT_RESULT();
}
#endif

/* A server without the peer's address holds nothing before the cookie
 * verifies: it drops fragments silently and answers whole ClientHellos. */
int test_dtls13_frag_ch_no_addr_dropped(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL, *c2 = NULL, *c3 = NULL;
    struct test_memio_ctx test_ctx, t2;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch1[TEST_MEMIO_BUF_SZ], ch2[TEST_MEMIO_BUF_SZ];
    int ch1Sz = (int)sizeof(ch1), ch2Sz = (int)sizeof(ch2);
    int bodySz = 0;
    int cookieEnd = 0;
    int piece = 0;
    int i;
    int isHrr = 0;
    DtlsChPool* pool = NULL;
    DtlsMsg* head = NULL;
    size_t bytes = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&t2, 0, sizeof(t2));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectNotNull(pool = test_dtls13_ch_pool(ssl_s));
    /* Memio reports no address */
    ExpectIntEQ(ssl_s->buffers.dtlsCtx.peer.sz, 0);

    /* The first ClientHello in three pieces, then the canned one in four:
     * every fragment is dropped */
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch1, &ch1Sz),
        TEST_SUCCESS);
    piece = (ch1Sz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) / 3;
    ExpectIntEQ(test_dtls13_inject_fragmented(&test_ctx, ch1, ch1Sz, piece),
        3);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));
    ExpectIntEQ(test_dtls13_inject_four_frag_ch(&test_ctx, ssl_s),
        TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));

    /* The whole first ClientHello gets a HelloRetryRequest */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch1,
        ch1Sz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));

    /* The second ClientHello split just past its cookie */
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch2, &ch2Sz),
        TEST_SUCCESS);
    bodySz = ch2Sz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ;
    ExpectIntGT(cookieEnd = test_dtls13_ch_cookie_end(ch2, ch2Sz), 0);
    ExpectIntGT(bodySz - cookieEnd, 0);

    /* The tail first: dropped */
    ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, ssl_s, ch2, ch2Sz,
        (word32)cookieEnd, (word32)(bodySz - cookieEnd), 1), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));

    /* The first fragment verifies at once. The server holds it as a message
     * of the connection, not in the pool. */
    ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, ssl_s, ch2, ch2Sz, 0,
        (word32)cookieEnd, 0), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectNotNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(test_dtls13_pool_count(pool), 0);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 0);
    test_memio_clear_buffer(&test_ctx, 1);

    /* The tail again, in a new record, completes it */
    ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, ssl_s, ch2, ch2Sz,
        (word32)cookieEnd, (word32)(bodySz - cookieEnd), 2), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Another server of the context holds a fragment for peer 7. One without
     * an address adds nothing next to it. */
    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    ExpectIntEQ(test_dtls13_server_peer(c2, &t2, 7), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&t2, ch1, ch1Sz, piece, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&t2, c2), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_pool_count(pool), 1);
    ExpectNotNull(head = test_dtls13_pool_head(pool));
    bytes = test_dtls13_pool_bytes(pool);

    ExpectNotNull(c3 = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(c3, &t2);
    wolfSSL_SetIOWriteCtx(c3, &t2);
    for (i = 0; i < 3 && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(test_dtls13_inject_frag(&t2, ch1, ch1Sz, piece, i), 1);
        ExpectIntEQ(test_dtls13_server_read_all(&t2, c3), TEST_SUCCESS);
        ExpectIntEQ(t2.c_len, 0);
        ExpectIntEQ(c3->options.dtlsStateful, 0);
        ExpectNull(c3->dtls_rx_msg_list);
        ExpectIntEQ(test_dtls13_pool_count(pool), 1);
        ExpectPtrEq(test_dtls13_pool_head(pool), head);
        ExpectIntEQ(test_dtls13_pool_bytes(pool), bytes);
        ExpectTrue(test_dtls13_pool_ok(pool));
    }

    wolfSSL_free(c3);
    wolfSSL_free(c2);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* The budget bounds all that a context's servers hold. c1 stores odd peers,
 * c2 even, c3 has no address: eviction crosses servers, never the growing
 * entry, a replaced entry counts once, and c3 adds nothing. */
int test_dtls13_frag_ch1_ctx_budget_two_objects(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *c1 = NULL, *c2 = NULL, *c3 = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    byte frag[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int fragSz = 0;
    int bodySz = 0;
    /* Small first fragments: many entries, each smaller than the growth */
    const int first = 16;
    int grow = 0;
    size_t entry = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket) +
        (size_t)first;
    size_t bytes = 0;
    int capacity = 0;
    int evicted = 0;
    int behind = 0;
    int count = 0;
    int peer;
    word32 msgLen = 0;
    DtlsChPool* pool = NULL;
    DtlsMsg* head = NULL;
    DtlsMsg* m = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    ExpectNotNull(c3 = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(c3, &test_ctx);
    wolfSSL_SetIOWriteCtx(c3, &test_ctx);
    ExpectNotNull(pool = test_dtls13_ch_pool(c1));
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    bodySz = chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ;
    /* All but the last byte: the entry grows but does not complete */
    grow = bodySz - first - 1;
    capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT / entry);
    ExpectIntGT(capacity, 4);
    /* What is left of the budget once full is less than one entry, so the
     * growth must evict */
    ExpectIntGT(grow, (int)entry);

    /* Fill the budget: odd peers through c1, even ones through c2 */
    for (peer = 1; peer <= capacity && EXPECT_SUCCESS(); peer++) {
        WOLFSSL* s = (peer % 2 == 1) ? c1 : c2;

        ExpectIntEQ(test_dtls13_server_peer(s, &test_ctx, peer),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, s, ch, chSz, 0,
            (word32)first, 0), TEST_SUCCESS);
        ExpectIntEQ(test_ctx.c_len, 0);
        ExpectIntEQ(test_dtls13_pool_count(pool), peer);
        ExpectTrue(test_dtls13_pool_bytes(pool) == (size_t)peer * entry);
        ExpectTrue(test_dtls13_pool_ok(pool));
    }

    /* c2's store evicts the oldest entry, which c1 stored */
    ExpectIntEQ(test_dtls13_server_peer(c2, &test_ctx, capacity + 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, c2, ch, chSz, 0,
        (word32)first, 0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_pool_count(pool), capacity);
    ExpectTrue(test_dtls13_pool_bytes(pool) == (size_t)capacity * entry);
    ExpectNull(test_dtls13_held_for(pool, 1));
    ExpectNotNull(test_dtls13_held_for(pool, capacity + 1));
    ExpectTrue(test_dtls13_pool_ok(pool));

    /* c1 grows the oldest entry, peer 2's from c2, without completing it. It
     * evicts the oldest other entries, never itself, and goes to the tail.
     * It evicts for the bound of its fragment: a new entry holding it. */
    evicted = (int)(((size_t)capacity * entry + entry - (size_t)first +
        (size_t)grow - TEST_DTLS_RX_UNVERIFIED_LIMIT + entry - 1) / entry);
    ExpectIntGE(evicted, 1);
    ExpectIntLE(evicted, capacity - 2);
    ExpectPtrEq(test_dtls13_pool_head(pool),
        test_dtls13_held_for(pool, 2));
    ExpectIntEQ(test_dtls13_server_peer(c1, &test_ctx, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, c1, ch, chSz,
        (word32)first, (word32)grow, 0), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    count = capacity - evicted;
    ExpectIntEQ(test_dtls13_pool_count(pool), count);
    ExpectNotNull(m = test_dtls13_held_for(pool, 2));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1, first + grow);
    ExpectIntEQ(m != NULL ? (int)m->fragBucketListCount : -1, 1);
    ExpectNull(test_dtls13_pool_next(pool, m));
    /* The entry behind peer 2 in its shard goes first, as the scan lands on
     * peer 2's own, then the oldest of the rest */
    evicted--;
    for (peer = 3, head = NULL; peer <= capacity + 1 && EXPECT_SUCCESS();
            peer++) {
        if (!behind && (WOLFSSL_DTLS_CH_POOL_SHARDS == 1 ||
                test_dtls13_shard_of(peer) == test_dtls13_shard_of(2))) {
            ExpectNull(test_dtls13_held_for(pool, peer));
            behind = 1;
        }
        else if (evicted > 0) {
            ExpectNull(test_dtls13_held_for(pool, peer));
            evicted--;
        }
        else {
            ExpectNotNull(test_dtls13_held_for(pool, peer));
            if (head == NULL)
                head = test_dtls13_held_for(pool, peer);
        }
    }
    ExpectIntEQ(behind, 1);
    ExpectPtrEq(test_dtls13_pool_head(pool), head);
    ExpectTrue(pool != NULL &&
        test_dtls13_pool_bytes(pool) == (size_t)count * entry +
        (size_t)grow);
    ExpectTrue(test_dtls13_pool_ok(pool));

    /* A fragment contradicting peer capacity + 1's entry, through c1,
     * replaces it. The bytes are counted once, but the bound of the new
     * entry is reserved before the old one is freed under the lock: at
     * capacity the oldest entry goes for it. */
    bytes = test_dtls13_pool_bytes(pool);
    if (TEST_DTLS_RX_UNVERIFIED_LIMIT - bytes < entry) {
        count--;
        bytes -= entry;
    }
    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, 0, (word32)first, 0,
        frag, (int)sizeof(frag)), 0);
    if (EXPECT_SUCCESS()) {
        ato24(frag + DTLS_RECORD_HEADER_SZ + 1, &msgLen);
        c32to24(msgLen + 1, frag + DTLS_RECORD_HEADER_SZ + 1);
    }
    ExpectIntEQ(test_dtls13_server_peer(c1, &test_ctx, capacity + 1),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, c1), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(pool), count);
    ExpectTrue(test_dtls13_pool_bytes(pool) == bytes);
    ExpectNotNull(m = test_dtls13_held_for(pool, capacity + 1));
    ExpectIntEQ(m != NULL ? (int)m->sz : -1, (int)msgLen + 1);
    ExpectNull(test_dtls13_pool_next(pool, m));
    ExpectTrue(test_dtls13_pool_ok(pool));

    /* c3 has no address: even all of a ClientHello adds nothing */
    head = test_dtls13_pool_head(pool);
    ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, c3, ch, chSz, 0,
        (word32)first, 0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_deliver_range(&test_ctx, c3, ch, chSz,
        (word32)first, (word32)(bodySz - first), 1), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(c3->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(pool), count);
    ExpectPtrEq(test_dtls13_pool_head(pool), head);
    ExpectTrue(test_dtls13_pool_bytes(pool) == bytes);
    ExpectTrue(test_dtls13_pool_ok(pool));

    /* Nothing unverified is held anywhere else */
    ExpectNull(c1->dtls_rx_msg_list);
    ExpectNull(c2->dtls_rx_msg_list);
    ExpectNull(c3->dtls_rx_msg_list);

    wolfSSL_free(c1);
    wolfSSL_free(c2);
    wolfSSL_free(c3);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && defined(WOLF_CRYPTO_CB) && \
    !defined(WOLF_CRYPTO_CB_ONLY_RSA) && !defined(WOLF_CRYPTO_CB_ONLY_ECC) && \
    !defined(WOLF_CRYPTO_CB_ONLY_SHA256) && \
    !defined(WOLF_CRYPTO_CB_ONLY_AES) && \
    !defined(WOLF_CRYPTO_CB_ONLY_SHA512) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ED25519) && \
    !defined(WOLF_CRYPTO_CB_ONLY_CURVE25519) && \
    !defined(WOLF_CRYPTO_CB_ONLY_MLKEM)
#define TEST_DTLS13_CH_CB_DEVID 0x4443
/* A device that does nothing: wolfCrypt falls back to software */
static int test_dtls13_ch_unavailable_cb(int devId, wc_CryptoInfo* info,
        void* ctx)
{
    (void)devId;
    (void)info;
    (void)ctx;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif

/* With a crypto device a whole ClientHello is stored before processing, but
 * never through the pool: a full pool neither drops it nor loses an entry. */
int test_dtls13_ch_whole_async_not_pooled(void)
{
    EXPECT_DECLS;
/* The callback leaves every operation to software, which a callback-only
 * build does not have. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && defined(WOLF_CRYPTO_CB) && \
    !defined(WOLF_CRYPTO_CB_ONLY_RSA) && !defined(WOLF_CRYPTO_CB_ONLY_ECC) && \
    !defined(WOLF_CRYPTO_CB_ONLY_SHA256) && \
    !defined(WOLF_CRYPTO_CB_ONLY_AES) && \
    !defined(WOLF_CRYPTO_CB_ONLY_SHA512) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ED25519) && \
    !defined(WOLF_CRYPTO_CB_ONLY_CURVE25519) && \
    !defined(WOLF_CRYPTO_CB_ONLY_MLKEM)
    int addr;

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_DTLS13_CH_CB_DEVID,
        test_dtls13_ch_unavailable_cb, NULL), 0);
    for (addr = 0; addr < 2 && EXPECT_SUCCESS(); addr++) {
        WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
        WOLFSSL *ssl_c = NULL, *ssl_s = NULL, *filler = NULL;
        struct test_memio_ctx test_ctx, tf;
        int group = WOLFSSL_ECC_SECP256R1;
        byte ch[TEST_MEMIO_BUF_SZ];
        int chSz = (int)sizeof(ch);
        int fragSz = 0;
        int capacity = 0;
        int peer;
        int isHrr = 0;
        DtlsChPool* pool = NULL;
        DtlsMsg* head = NULL;
        size_t bytes = 0;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        XMEMSET(&tf, 0, sizeof(tf));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method),
            0);
        ExpectIntEQ(wolfSSL_SetDevId(ssl_s, TEST_DTLS13_CH_CB_DEVID),
            WOLFSSL_SUCCESS);
        if (addr) {
            ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, 1000),
                WOLFSSL_SUCCESS);
        }
        ExpectNotNull(pool = test_dtls13_ch_pool(ssl_s));
        ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
            TEST_SUCCESS);

        /* Another server fills the pool */
        ExpectNotNull(filler = wolfSSL_new(ctx_s));
        fragSz = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ +
            1) / 2;
        capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT / (sizeof(DtlsMsg) +
            sizeof(int) + sizeof(DtlsFragBucket) + (size_t)fragSz));
        for (peer = 1; peer <= capacity && EXPECT_SUCCESS(); peer++) {
            ExpectIntEQ(test_dtls13_server_peer(filler, &tf, peer),
                WOLFSSL_SUCCESS);
            ExpectIntEQ(test_dtls13_inject_frag(&tf, ch, chSz, fragSz, 0), 1);
            ExpectIntEQ(test_dtls13_server_read_all(&tf, filler),
                TEST_SUCCESS);
            ExpectIntEQ(tf.c_len, 0);
        }
        ExpectIntEQ(test_dtls13_pool_count(pool), capacity);
        head = test_dtls13_pool_head(pool);
        bytes = test_dtls13_pool_bytes(pool);

        /* The whole first ClientHello is answered */
        ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ch,
            chSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s),
            TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
        ExpectIntEQ(isHrr, 1);
        ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
        ExpectNull(ssl_s->dtls_rx_msg_list);
        ExpectIntEQ(test_dtls13_pool_count(pool), capacity);
        ExpectPtrEq(test_dtls13_pool_head(pool), head);
        ExpectTrue(test_dtls13_pool_bytes(pool) == bytes);

        /* and so is the second */
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        ExpectIntEQ(test_dtls13_pool_count(pool), capacity);
        ExpectPtrEq(test_dtls13_pool_head(pool), head);
        ExpectTrue(test_dtls13_pool_bytes(pool) == bytes);
        ExpectTrue(test_dtls13_pool_ok(pool));

        wolfSSL_free(filler);
        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
    wc_CryptoCb_UnRegisterDevice(TEST_DTLS13_CH_CB_DEVID);
#endif
    return EXPECT_RESULT();
}

/* No peer address, asynchronous device: a whole ClientHello left pending
 * after its cookie verifies resumes as a message of the connection. */
int test_dtls13_ch_async_no_addr(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && \
    defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLFSSL_ASYNC_CRYPT_SW) && \
    !defined(WC_ECC_NONBLOCK) && !defined(WOLFSSL_SP_NONBLOCK)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    int devId = INVALID_DEVID;

    ExpectIntGE(wolfAsync_DevOpen(&devId), 0);
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_SetDevId(ssl_s, devId), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(ssl_s->buffers.dtlsCtx.peer.sz, 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 20, NULL), 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectIntEQ(test_dtls13_pool_count(test_dtls13_ch_pool(ssl_s)), 0);
    ExpectNull(ssl_s->dtls_rx_msg_list);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    wolfAsync_DevClose(&devId);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
/* B's second ClientHello split after its cookie: the later fragments reach
 * c1 while it serves A, the first fragment a new listener c2. sharedSecret
 * gives c2 c1's cookie secret; mode 1 turns holding before the cookie off. */
static int test_dtls13_frag_ch2_ctx_second(int sharedSecret, int mode)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_cA = NULL, *ctx_cB = NULL, *ctx_cD = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_cA = NULL, *ssl_cB = NULL, *ssl_cD = NULL;
    WOLFSSL *c1 = NULL, *c2 = NULL;
    struct test_memio_ctx tA, tB, tD;
    int group = WOLFSSL_ECC_SECP256R1;
    static const byte secret[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    byte chB[TEST_MEMIO_BUF_SZ], chD[TEST_MEMIO_BUF_SZ];
    int chBSz = (int)sizeof(chB), chDSz = (int)sizeof(chD);
    byte frag[TEST_MEMIO_BUF_SZ];
    int fragSz = 0;
    int off[3] = { 0, 0, 0 };
    int len[3] = { 0, 0, 0 };
    int bodySz = 0;
    int pieceD = 0;
    int i;
    int isHrr = 1;

    XMEMSET(&tA, 0, sizeof(tA));
    XMEMSET(&tB, 0, sizeof(tB));
    XMEMSET(&tD, 0, sizeof(tD));
    ExpectIntEQ(test_memio_setup(&tA, &ctx_cA, &ctx_s, &ssl_cA, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_setup(&tB, &ctx_cB, NULL, &ssl_cB, NULL,
        wolfDTLSv1_3_client_method, NULL), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cA, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cB, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_send_hrr_cookie(c1, secret, sizeof(secret)),
        WOLFSSL_SUCCESS);

    /* B's first ClientHello at c1 gets a HelloRetryRequest */
    ExpectIntEQ(test_dtls13_server_peer(c1, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_cB), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_cB, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(c1), -1);
    ExpectIntEQ(wolfSSL_get_error(c1, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&tB, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_take_ch(&tB, ssl_cB, chB, &chBSz), TEST_SUCCESS);

    /* Three fragments: the first ends just past the cookie extension */
    bodySz = chBSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ;
    ExpectIntGT(len[0] = test_dtls13_ch_cookie_end(chB, chBSz), 0);
    ExpectIntGE(bodySz - len[0], 2);
    off[1] = len[0];
    len[1] = (bodySz - len[0]) / 2;
    off[2] = off[1] + len[1];
    len[2] = bodySz - off[2];

    /* The later fragments are held by the context */
    for (i = 1; i < 3 && EXPECT_SUCCESS(); i++) {
        ExpectIntGT(fragSz = test_dtls13_frag_range(chB, chBSz,
            (word32)off[i], (word32)len[i], (word32)i, frag,
            (int)sizeof(frag)), 0);
        ExpectIntEQ(test_memio_inject_message(&tB, 0, (const char*)frag,
            fragSz), 0);
    }
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(tB.c_len, 0);
    ExpectIntEQ(c1->options.dtlsStateful, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));

    /* c1 serves A */
    ExpectIntEQ(test_dtls13_server_peer(c1, &tA, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_cA, c1, 10, NULL), 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);

    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    if (sharedSecret) {
        ExpectIntEQ(wolfSSL_send_hrr_cookie(c2, secret, sizeof(secret)),
            WOLFSSL_SUCCESS);
    }
    if (mode == 1) {
        /* An object with reassembly off adds nothing to the pool */
        ExpectIntEQ(wolfSSL_dtls13_reassemble_ch_before_cookie(c2, 0),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_server_peer(c2, &tB, 9), WOLFSSL_SUCCESS);
        ExpectIntGT(fragSz = test_dtls13_frag_range(chB, chBSz,
            (word32)off[1], (word32)len[1], 1, frag, (int)sizeof(frag)), 0);
        ExpectIntEQ(test_memio_inject_message(&tB, 0, (const char*)frag,
            fragSz), 0);
        ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
        ExpectIntEQ(tB.c_len, 0);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
        ExpectNull(test_dtls13_held_for(&ctx_s->dtlsChPool, 9));
    }

    /* B's first fragment reaches c2 */
    ExpectIntEQ(test_dtls13_server_peer(c2, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntGT(fragSz = test_dtls13_frag_range(chB, chBSz, (word32)off[0],
        (word32)len[0], 0, frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&tB, 0, (const char*)frag, fragSz),
        0);
    if (sharedSecret) {
        /* The cookie verifies and the held rest completes the message */
        ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
        ExpectIntEQ(c2->options.dtlsStateful, 1);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&tB, &isHrr), 1);
        ExpectIntEQ(isHrr, 0);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
        ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
        ExpectNull(c2->dtls_rx_msg_list);
        ExpectIntEQ(test_memio_do_handshake(ssl_cB, c2, 10, NULL), 0);
    }
    else {
        /* c2 cannot verify c1's cookie: a fatal alert, and c2 stays a
         * stateless server */
        ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
        ExpectIntGT(tB.c_len, DTLS_RECORD_HEADER_SZ + 1);
        ExpectIntEQ(tB.c_buff[0], alert);
        ExpectIntEQ(tB.c_buff[DTLS_RECORD_HEADER_SZ], alert_fatal);
        ExpectIntEQ(tB.c_buff[DTLS_RECORD_HEADER_SZ + 1], illegal_parameter);
        ExpectIntEQ(c2->options.dtlsStateful, 0);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
        ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
        ExpectNull(c2->dtls_rx_msg_list);
        test_memio_clear_buffer(&tB, 1);

        /* It still serves: client D's fragmented first ClientHello */
        ExpectIntEQ(test_memio_setup(&tD, &ctx_cD, NULL, &ssl_cD, NULL,
            wolfDTLSv1_3_client_method, NULL), 0);
        ExpectIntEQ(wolfSSL_set_groups(ssl_cD, &group, 1), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_take_ch(&tD, ssl_cD, chD, &chDSz),
            TEST_SUCCESS);
        pieceD = (chDSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ +
            2) / 3;
        ExpectIntEQ(test_dtls13_server_peer(c2, &tD, 4), WOLFSSL_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_fragmented(&tD, chD, chDSz, pieceD),
            3);
        ExpectIntEQ(test_dtls13_server_read_all(&tD, c2), TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&tD, &isHrr), 1);
        ExpectIntEQ(isHrr, 1);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
        ExpectIntEQ(test_memio_do_handshake(ssl_cD, c2, 10, NULL), 0);
    }

    wolfSSL_free(c1);
    wolfSSL_free(c2);
    wolfSSL_free(ssl_cA);
    wolfSSL_free(ssl_cB);
    wolfSSL_free(ssl_cD);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_cA);
    wolfSSL_CTX_free(ctx_cB);
    wolfSSL_CTX_free(ctx_cD);
    return EXPECT_RESULT();
}
#endif

/* The rest of a second ClientHello held by the context is taken by the server
 * that verifies its first fragment, when the servers share the secret. */
int test_dtls13_frag_ch2_ctx_handoff(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch2_ctx_second(1, 0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch2_ctx_second(1, 1), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A second ClientHello completed by a server with a different cookie secret
 * gets an illegal_parameter alert; the pool stays clean, the server goes on. */
int test_dtls13_frag_ch2_ctx_cookie_mismatch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch2_ctx_second(0, 0), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

/* A server moved to another context stores in the new context's pool. The
 * old context's entries stay with it and go when it is freed. */
int test_dtls13_frag_ch_ctx_set_ssl_ctx(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && \
    (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA))
    WOLFSSL_CTX *ctx_cB = NULL, *ctx_s = NULL, *ctx_s2 = NULL;
    WOLFSSL *ssl_cB = NULL, *c1 = NULL;
    struct test_memio_ctx tB;
    int group = WOLFSSL_ECC_SECP256R1;
    byte chB[TEST_MEMIO_BUF_SZ];
    int chBSz = (int)sizeof(chB);
    int pieceB = 0;

    XMEMSET(&tB, 0, sizeof(tB));
    ExpectIntEQ(test_memio_setup(&tB, &ctx_cB, &ctx_s, &ssl_cB, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_setup(&tB, NULL, &ctx_s2, NULL, NULL,
        NULL, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cB, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&tB, ssl_cB, chB, &chBSz), TEST_SUCCESS);
    pieceB = (chBSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
        3;

    ExpectIntEQ(test_dtls13_server_peer(c1, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);

    ExpectPtrEq(wolfSSL_set_SSL_CTX(c1, ctx_s2), ctx_s2);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 1), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(tB.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s2->dtlsChPool), 1);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectTrue(test_dtls13_pool_ok(&ctx_s2->dtlsChPool));

    /* The old context has no other user: its pool goes with it */
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;
    ExpectIntEQ(test_dtls13_server_peer(c1, &tB, 3), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, pieceB, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s2->dtlsChPool), 2);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s2->dtlsChPool));

    wolfSSL_free(c1);
    wolfSSL_free(ssl_cB);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_s2);
    wolfSSL_CTX_free(ctx_cB);
#endif
    return EXPECT_RESULT();
}

/* An abandoned partial ClientHello outlives its server. B starts over from the
 * same address with one of the same size. mode 0: the new first fragment
 * replaces the old one. mode 1, 2: the old entry aged out and never merges. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
static int test_dtls13_frag_ch1_ctx_stale_partial_ex(int mode)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_cA = NULL, *ctx_cB = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_cA = NULL, *ssl_cB = NULL, *c1 = NULL, *c2 = NULL;
    struct test_memio_ctx tA, tB;
    int group = WOLFSSL_ECC_SECP256R1;
    byte chOld[TEST_MEMIO_BUF_SZ], chNew[TEST_MEMIO_BUF_SZ];
    int chOldSz = (int)sizeof(chOld), chNewSz = (int)sizeof(chNew);
    int piece = 0;
    int isHrr = 0;
    int i;
    /* The fragments of the new ClientHello in the order they arrive. Its
     * handshake must not be answered before the last one. */
    static const int order[3][3] = { { 0, 1, 2 }, { 1, 2, 0 }, { 0, 1, 2 } };

    XMEMSET(&tA, 0, sizeof(tA));
    XMEMSET(&tB, 0, sizeof(tB));
    ExpectIntEQ(test_memio_setup(&tA, &ctx_cA, &ctx_s, &ssl_cA, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_setup(&tB, &ctx_cB, NULL, &ssl_cB, NULL,
        wolfDTLSv1_3_client_method, NULL), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cB, &group, 1), WOLFSSL_SUCCESS);
#ifdef HAVE_ECH
    /* GREASE ECH has a random length */
    wolfSSL_SetEchEnable(ssl_cB, 0);
#endif
    ExpectIntEQ(test_dtls13_take_ch(&tB, ssl_cB, chOld, &chOldSz),
        TEST_SUCCESS);
    piece = (chOldSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
        3;

    /* Some of B's fragments arrive, then B gives up */
    ExpectIntEQ(test_dtls13_server_peer(c1, &tB, 2), WOLFSSL_SUCCESS);
    if (mode == 2) {
        ExpectIntEQ(test_dtls13_inject_frag(&tB, chOld, chOldSz, piece, 1), 1);
        ExpectIntEQ(test_dtls13_inject_frag(&tB, chOld, chOldSz, piece, 2), 1);
    }
    else {
        ExpectIntEQ(test_dtls13_inject_frag(&tB, chOld, chOldSz, piece, 0), 1);
    }
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(tB.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    wolfSSL_free(ssl_cB);
    ssl_cB = NULL;

    /* A's cookie verifies at c1, which then goes */
    ExpectIntEQ(test_dtls13_server_peer(c1, &tA, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_memio_do_handshake(ssl_cA, c1, 10, NULL), 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    wolfSSL_free(c1);
    c1 = NULL;
    if (mode != 0)
        test_dtls13_age(test_dtls13_held_for(&ctx_s->dtlsChPool, 2));

    /* B starts over from the same address */
    test_memio_clear_buffer(&tB, 0);
    test_memio_clear_buffer(&tB, 1);
    ExpectIntEQ(test_memio_setup(&tB, &ctx_cB, NULL, &ssl_cB, NULL,
        wolfDTLSv1_3_client_method, NULL), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cB, &group, 1), WOLFSSL_SUCCESS);
#ifdef HAVE_ECH
    wolfSSL_SetEchEnable(ssl_cB, 0);
#endif
    ExpectIntEQ(test_dtls13_take_ch(&tB, ssl_cB, chNew, &chNewSz),
        TEST_SUCCESS);
    ExpectIntEQ(chNewSz, chOldSz);
    ExpectBufNE(chNew, chOld, chOldSz);

    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    ExpectIntEQ(test_dtls13_server_peer(c2, &tB, 2), WOLFSSL_SUCCESS);
    for (i = 0; i < 2; i++) {
        ExpectIntEQ(test_dtls13_inject_frag(&tB, chNew, chNewSz, piece,
            order[mode][i]), 1);
        ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
        ExpectIntEQ(tB.c_len, 0);
        ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
        ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    }
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chNew, chNewSz, piece,
        order[mode][2]), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&tB, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectIntEQ(test_memio_do_handshake(ssl_cB, c2, 10, NULL), 0);

    wolfSSL_free(c2);
    wolfSSL_free(ssl_cA);
    wolfSSL_free(ssl_cB);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_cA);
    wolfSSL_CTX_free(ctx_cB);
    return EXPECT_RESULT();
}
#endif

int test_dtls13_frag_ch1_ctx_stale_partial(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    ExpectIntEQ(test_dtls13_frag_ch1_ctx_stale_partial_ex(0), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch1_ctx_stale_partial_ex(1), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_frag_ch1_ctx_stale_partial_ex(2), TEST_SUCCESS);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && \
    defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY_LEAN) && \
    !defined(WOLFSSL_NO_MALLOC)
#define TEST_DTLS13_STATIC_MEMSZ 400000

/* Hold B's partial ClientHello through one server of a static memory context
 * and complete it through another. lateLoad: memory given after creation. */
static int test_dtls13_frag_ch_ctx_static_memory_ex(int lateLoad, byte* mem,
        word32 memSz)
{
    EXPECT_DECLS;
    WOLFSSL_CTX *ctx_cB = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_cB = NULL, *c1 = NULL, *c2 = NULL;
    struct test_memio_ctx tB;
    WOLFSSL_MEM_STATS base, now;
    int group = WOLFSSL_ECC_SECP256R1;
    byte chB[TEST_MEMIO_BUF_SZ];
    int chBSz = (int)sizeof(chB);
    int piece = 0;
    int isHrr = 0;

    XMEMSET(&tB, 0, sizeof(tB));
    XMEMSET(&base, 0, sizeof(base));
    XMEMSET(&now, 0, sizeof(now));
    if (lateLoad) {
        ExpectNotNull(ctx_s = wolfSSL_CTX_new(wolfDTLSv1_3_server_method()));
        ExpectIntEQ(wolfSSL_CTX_load_static_memory(&ctx_s, NULL, mem, memSz,
            0, 0), WOLFSSL_SUCCESS);
    }
    else {
        ExpectIntEQ(wolfSSL_CTX_load_static_memory(&ctx_s,
            wolfDTLSv1_3_server_method_ex, mem, memSz, 0, 0),
            WOLFSSL_SUCCESS);
    }
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
    if (ctx_s != NULL) {
        wolfSSL_SetIORecv(ctx_s, test_memio_read_cb);
        wolfSSL_SetIOSend(ctx_s, test_memio_write_cb);
    }
    /* What the context allocates on first use stays out of the count */
    ExpectNotNull(c1 = wolfSSL_new(ctx_s));
    wolfSSL_free(c1);
    c1 = NULL;
    ExpectIntEQ(wolfSSL_CTX_is_static_memory(ctx_s, &base), 1);

    ExpectIntEQ(test_memio_setup(&tB, &ctx_cB, &ctx_s, &ssl_cB, &c1,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_set_groups(ssl_cB, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&tB, ssl_cB, chB, &chBSz), TEST_SUCCESS);
    piece = (chBSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) /
        3;

    /* Each object allocates with a hint of its own */
    ExpectNotNull(c1);
    if (EXPECT_SUCCESS())
        ExpectPtrNE(ctx_s->heap, c1->heap);
    ExpectIntEQ(test_dtls13_server_peer(c1, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, piece, 0), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, piece, 1), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c1), TEST_SUCCESS);
    ExpectIntEQ(tB.c_len, 0);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 1);
    wolfSSL_free(c1);
    c1 = NULL;
    ExpectIntEQ(wolfSSL_CTX_is_static_memory(ctx_s, &now), 1);
    ExpectIntGT(now.curAlloc, base.curAlloc);

    /* Another server completes it, on its own hint */
    ExpectNotNull(c2 = wolfSSL_new(ctx_s));
    if (EXPECT_SUCCESS())
        ExpectPtrNE(ctx_s->heap, c2->heap);
    ExpectIntEQ(test_dtls13_server_peer(c2, &tB, 2), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_inject_frag(&tB, chB, chBSz, piece, 2), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&tB, c2), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&tB, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);
    ExpectTrue(test_dtls13_pool_ok(&ctx_s->dtlsChPool));
    ExpectIntEQ(test_memio_do_handshake(ssl_cB, c2, 10, NULL), 0);

    /* Every allocation went back where it came from */
    wolfSSL_free(c2);
    c2 = NULL;
    ExpectIntEQ(wolfSSL_CTX_is_static_memory(ctx_s, &now), 1);
    ExpectIntEQ(now.curAlloc, base.curAlloc);

    wolfSSL_free(ssl_cB);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_cB);
    return EXPECT_RESULT();
}
#endif

/* The pool allocates with the heap of the context and rebuilds a ClientHello
 * on the heap of the object that completes it. */
int test_dtls13_frag_ch_ctx_static_memory(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && \
    defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY_LEAN) && \
    !defined(WOLFSSL_NO_MALLOC)
    static byte mem[TEST_DTLS13_STATIC_MEMSZ];
    int lateLoad;

    for (lateLoad = 0; lateLoad < 2 && EXPECT_SUCCESS(); lateLoad++) {
        ExpectIntEQ(test_dtls13_frag_ch_ctx_static_memory_ex(lateLoad, mem,
            (word32)sizeof(mem)), TEST_SUCCESS);
    }
#endif
    return EXPECT_RESULT();
}

/* Which results of DtlsMsgStore() end the connection: only running out of
 * memory, or an authenticated peer exceeding the receive budget */
int test_dtls13_frag_store_fatal(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte data[32];
    word16 epoch = 0;
    int ret = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(data, 0xAB, sizeof(data));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* Plaintext could come from anyone: only memory ends the connection */
    ExpectIntEQ(DtlsMsgStoreFatal(ssl_s, 0), 0);
    ExpectIntEQ(DtlsMsgStoreFatal(ssl_s, DTLS_MSG_STORE_DROPPED), 0);
    ExpectIntEQ(DtlsMsgStoreFatal(ssl_s, WC_NO_ERR_TRACE(BAD_FUNC_ARG)), 0);
    ExpectIntEQ(DtlsMsgStoreFatal(ssl_s,
        WC_NO_ERR_TRACE(DTLS_TOO_MANY_FRAGMENTS_E)), 0);
    ExpectIntNE(DtlsMsgStoreFatal(ssl_s, WC_NO_ERR_TRACE(MEMORY_E)), 0);
    ExpectIntNE(DtlsMsgStoreFatal(ssl_s, WC_NO_ERR_TRACE(MEMORY_ERROR)), 0);

    /* The records of a peer that finished the handshake authenticate */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    if (EXPECT_SUCCESS()) {
        ExpectIntNE(ssl_s->keys.encryptionOn, 0);
        ExpectIntEQ(w64IsZero(ssl_s->keys.curEpoch64), 0);
        epoch = (word16)w64GetLow32(ssl_s->keys.curEpoch64);
    }
    ExpectIntEQ(DtlsMsgStoreFatal(ssl_s, 0), 0);
    ExpectIntEQ(DtlsMsgStoreFatal(ssl_s, DTLS_MSG_STORE_DROPPED), 0);
    ExpectIntNE(DtlsMsgStoreFatal(ssl_s,
        WC_NO_ERR_TRACE(DTLS_TOO_MANY_FRAGMENTS_E)), 0);
    ExpectIntNE(DtlsMsgStoreFatal(ssl_s, WC_NO_ERR_TRACE(MEMORY_E)), 0);
    /* A fragment that gives the message held another size is dropped */
    ExpectIntEQ(DtlsMsgStore(ssl_s, epoch, 20, data, 32, certificate, 0, 16,
        ssl_s->heap), 0);
    ret = DtlsMsgStore(ssl_s, epoch, 20, data, 24, certificate, 16, 8,
        ssl_s->heap);
    ExpectIntEQ(ret, WC_NO_ERR_TRACE(SEQUENCE_ERROR));
    ExpectIntEQ(DtlsMsgStoreFatal(ssl_s, ret), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(WOLFSSL_NO_TLS12)
/* Offset of the extensions in the body of a DTLS 1.2 ClientHello, or 0 when
 * the body ends before them */
static word32 test_dtls12_ch_ext_offset(const byte* body, word32 bodySz)
{
    word32 off = OPAQUE16_LEN + RAN_LEN;
    word16 suitesSz;

    if (off >= bodySz)
        return 0;
    off += 1 + body[off];
    if (off >= bodySz)
        return 0;
    off += 1 + body[off];
    if (off + OPAQUE16_LEN > bodySz)
        return 0;
    ato16(body + off, &suitesSz);
    off += OPAQUE16_LEN + suitesSz;
    if (off >= bodySz)
        return 0;
    off += 1 + body[off];
    return off < bodySz ? off : 0;
}
#endif

/* wolfSSL_clear() frees the receive list: a reused object starts with no
 * message of the last connection. */
int test_dtls13_clear_frees_rx_list(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && (defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE) || \
        defined(HAVE_CURL))
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte data[16];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(data, 0x5a, sizeof(data));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(DtlsMsgStore(ssl_s, 0, 3, data, (word32)sizeof(data),
        certificate, 0, 8, ssl_s->heap), 0);
    ExpectNotNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(ssl_s->dtls_rx_msg_list_sz, 1);
    ExpectIntGT(ssl_s->dtls_rx_msg_list_bytes, 0);
    ExpectIntEQ(wolfSSL_clear(ssl_s), WOLFSSL_SUCCESS);
    ExpectNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(ssl_s->dtls_rx_msg_list_sz, 0);
    ExpectIntEQ(ssl_s->dtls_rx_msg_list_bytes, 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A first fragment whose cookie fails is answered with an alert and not held:
 * holding it would cost other peers' entries. The genuine ones complete. */
int test_dtls13_frag_ch2_bad_cookie_dropped(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    byte bad[TEST_MEMIO_BUF_SZ];
    byte frag[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    int cut = 0;
    int bodySz = 0;
    int fragSz = 0;
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, 2),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);

    /* CH1, HRR with cookie, CH2 */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 1);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    ExpectIntGT(cut = test_dtls13_ch_cookie_end(ch, chSz), 0);
    bodySz = chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ;

    /* The first fragment with the last byte of the cookie changed */
    XMEMCPY(bad, ch, (size_t)chSz);
    bad[DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ + cut - 1] ^= 0x01;
    ExpectIntGT(fragSz = test_dtls13_frag_range(bad, chSz, 0, (word32)cut, 0,
        frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntGT(test_ctx.c_len, DTLS_RECORD_HEADER_SZ + 1);
    ExpectIntEQ(test_ctx.c_buff[0], alert);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ], alert_fatal);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ + 1], illegal_parameter);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);
    ExpectTrue(test_dtls13_nothing_held(ssl_s));
    test_memio_clear_buffer(&test_ctx, 1);

    /* The genuine first fragment verifies and the rest completes it */
    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, 0, (word32)cut, 1,
        frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, (word32)cut,
        (word32)(bodySz - cut), 2, frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A DTLS 1.2 second ClientHello in two fragments at a DTLS 1.3 server: the
 * first carries the cookie and is held, the second completes it. */
int test_dtls13_frag_ch2_dtls12_cookie(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(WOLFSSL_NO_TLS12)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    byte ch[TEST_MEMIO_BUF_SZ];
    byte frag[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    word32 bodySz = 0;
    word32 cut = 0;
    int fragSz = 0;
    int isHrr = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLS_server_method), 0);
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &test_ctx, 2),
        WOLFSSL_SUCCESS);

    /* The first ClientHello gets a HelloVerifyRequest */
    ExpectIntEQ(wolfSSL_connect(ssl_c), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntGT(test_ctx.c_len, 0);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 0);

    /* The second carries the cookie. Cut it after the compression methods so
     * the first fragment holds everything the cookie check parses. */
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    if (EXPECT_SUCCESS()) {
        bodySz = (word32)chSz - DTLS_RECORD_HEADER_SZ -
            DTLS_HANDSHAKE_HEADER_SZ;
        cut = test_dtls12_ch_ext_offset(ch + DTLS_RECORD_HEADER_SZ +
            DTLS_HANDSHAKE_HEADER_SZ, bodySz);
    }
    ExpectIntGT(cut, 0);
    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, 0, cut, 0, frag,
        (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    /* Verified: the server is stateful and holds the fragment */
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectNotNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(test_ctx.c_len, 0);

    ExpectIntGT(fragSz = test_dtls13_frag_range(ch, chSz, cut, bodySz - cut, 1,
        frag, (int)sizeof(frag)), 0);
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(ssl_s->version.minor, DTLSv1_2_MINOR);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(SINGLE_THREADED)
#define TEST_CH_POOL_THREADS 2
#define TEST_CH_POOL_OPS     5000
/* A quarter held for every peer exceeds the budget, so stores evict */
#define TEST_CH_POOL_PEERS   64
#define TEST_CH_POOL_MSG_SZ  ((TEST_DTLS_RX_UNVERIFIED_LIMIT / 16) & ~3)

static DtlsChPool test_ch_pool_shared;
static int test_ch_pool_bad[TEST_CH_POOL_THREADS];
static int test_ch_pool_out[TEST_CH_POOL_THREADS];
static byte test_ch_pool_data[TEST_CH_POOL_THREADS][TEST_CH_POOL_MSG_SZ];

/* Whether every byte msg holds is peer's: a message never mixes peers */
static int test_ch_pool_msg_ok(const DtlsMsg* msg, byte peer, word32 sz)
{
    const DtlsFragBucket* b;
    word32 i;

    if (msg->peer.sz != 0 || msg->sz != sz)
        return 0;
    if (msg->ready) {
        for (i = 0; i < msg->sz; i++) {
            if (msg->fullMsg[i] != (byte)(peer + 1))
                return 0;
        }
        return 1;
    }
    for (b = msg->fragBucketList; b != NULL; b = b->m.m.next) {
        for (i = 0; i < b->m.m.sz; i++) {
            if (b->buf[i] != (byte)(peer + 1))
                return 0;
        }
    }
    return 1;
}

static THREAD_RETURN WOLFSSL_THREAD test_dtls13_ch_pool_worker(void* args)
{
    int tno = ((func_args*)args)->argc;
    word32 rnd = 0x9e3779b9U * (word32)(tno + 1);
    byte peerId = 0;
    byte* data = test_ch_pool_data[tno];
    WOLFSSL_SOCKADDR peer;
    int i;

    peer.sz = 1;
    peer.bufSz = 1;
    peer.sa = &peerId;
    for (i = 0; i < TEST_CH_POOL_OPS; i++) {
        DtlsMsg* msg = NULL;
        word32 op;
        word32 quarter;

        rnd = rnd * 1103515245U + 12345U;
        peerId = (byte)((rnd >> 16) % TEST_CH_POOL_PEERS);
        op = (rnd >> 8) % 256;
        quarter = (rnd >> 24) % 4;
        XMEMSET(data, peerId + 1, TEST_CH_POOL_MSG_SZ);
        if (op == 0) {
            DtlsChPoolClear(&test_ch_pool_shared, NULL);
        }
        else if (op < 16) {
            msg = DtlsChPoolTakeRest(&test_ch_pool_shared, NULL, &peer, 0, 1, 0,
                TEST_CH_POOL_MSG_SZ, DTLS_TIMEOUT_MAX, NULL);
        }
        else {
            (void)DtlsChPoolStore(&test_ch_pool_shared, NULL, &peer, 0, 1, data,
                TEST_CH_POOL_MSG_SZ, client_hello,
                quarter * (TEST_CH_POOL_MSG_SZ / 4), TEST_CH_POOL_MSG_SZ / 4,
                DTLS_TIMEOUT_MAX, NULL, &msg);
        }
        if (msg != NULL) {
            if (!test_ch_pool_msg_ok(msg, peerId, TEST_CH_POOL_MSG_SZ))
                test_ch_pool_bad[tno]++;
            test_ch_pool_out[tno]++;
            DtlsMsgListDelete(msg, NULL);
        }
    }
    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif

/* Two threads store into, release from and clear one pool past its budget.
 * Each message that leaves holds one peer's bytes, and the counters agree. */
int test_dtls13_ch_pool_threads(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(SINGLE_THREADED)
    THREAD_TYPE threads[TEST_CH_POOL_THREADS];
    func_args args[TEST_CH_POOL_THREADS];
    int i;

    XMEMSET(args, 0, sizeof(args));
    XMEMSET(test_ch_pool_bad, 0, sizeof(test_ch_pool_bad));
    XMEMSET(test_ch_pool_out, 0, sizeof(test_ch_pool_out));
    ExpectTrue(TEST_CH_POOL_PEERS * (sizeof(DtlsMsg) + 1 +
        sizeof(DtlsFragBucket) + TEST_CH_POOL_MSG_SZ / 4) >
        TEST_DTLS_RX_UNVERIFIED_LIMIT);
    ExpectIntEQ(DtlsChPoolInit(&test_ch_pool_shared), 0);
    if (EXPECT_FAIL())
        return EXPECT_RESULT();
    for (i = 0; i < TEST_CH_POOL_THREADS; i++) {
        args[i].argc = i;
        start_thread(test_dtls13_ch_pool_worker, &args[i], &threads[i]);
    }
    for (i = 0; i < TEST_CH_POOL_THREADS; i++)
        join_thread(threads[i]);
    for (i = 0; i < TEST_CH_POOL_THREADS; i++) {
        ExpectIntEQ(test_ch_pool_bad[i], 0);
        ExpectIntGT(test_ch_pool_out[i], 0);
    }
    ExpectTrue(test_dtls13_pool_ok(&test_ch_pool_shared));
    ExpectIntLE(test_dtls13_pool_count(&test_ch_pool_shared),
        TEST_CH_POOL_PEERS);
    DtlsChPoolFree(&test_ch_pool_shared, NULL);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(SINGLE_THREADED)
#define TEST_CH_HS_THREADS 2
#define TEST_CH_HS_ROUNDS  12

/* The buffers of one handshake, too big for a thread's stack */
typedef struct test_dtls13_ch_hs_bufs {
    struct test_memio_ctx t;
    byte ch[TEST_MEMIO_BUF_SZ];
    byte frag[TEST_MEMIO_BUF_SZ];
} test_dtls13_ch_hs_bufs;

static WOLFSSL_CTX* test_ch_hs_ctx_s;
static WOLFSSL_CTX* test_ch_hs_ctx_c[TEST_CH_HS_THREADS];
static int test_ch_hs_fail[TEST_CH_HS_THREADS];

/* One handshake whose ClientHello the pool holds. mode 0: the first one in
 * three pieces. 1: the second, cookie past the first. 2: the second, first
 * piece last. */
static int test_dtls13_ch_hs_one(WOLFSSL_CTX* ctx_c, WOLFSSL_CTX* ctx_s,
        test_dtls13_ch_hs_bufs* b, int peerId, int mode)
{
    EXPECT_DECLS;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    const int hdrSz = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
    const char hello[] = "hello pool";
    char reply[sizeof(hello)];
    int group = WOLFSSL_ECC_SECP256R1;
    int chSz = (int)sizeof(b->ch);
    int cookieEnd = 0;
    int fragSz = 0;
    int isHrr = 0;

    XMEMSET(&b->t, 0, sizeof(b->t));
    /* The contexts are shared: only objects are made and freed here */
    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    if (EXPECT_SUCCESS()) {
        wolfSSL_SetIOReadCtx(ssl_c, &b->t);
        wolfSSL_SetIOWriteCtx(ssl_c, &b->t);
    }
    ExpectIntEQ(test_dtls13_server_peer(ssl_s, &b->t, peerId),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);

    if (mode == 0) {
        ExpectIntEQ(test_dtls13_take_ch(&b->t, ssl_c, b->ch, &chSz),
            TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_inject_fragmented(&b->t, b->ch, chSz,
            (chSz - hdrSz + 2) / 3), 3);
        ExpectIntEQ(test_dtls13_server_read_all(&b->t, ssl_s), TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&b->t, &isHrr), 1);
        ExpectIntEQ(isHrr, 1);
    }
    else {
        /* CH1, HRR with cookie, CH2 */
        ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(wolfSSL_accept(ssl_s), -1);
        ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&b->t, &isHrr), 1);
        ExpectIntEQ(isHrr, 1);
        ExpectIntEQ(test_dtls13_take_ch(&b->t, ssl_c, b->ch, &chSz),
            TEST_SUCCESS);
        if (mode == 1) {
            /* Pieces shorter than what precedes the extensions */
            ExpectIntGE(test_dtls13_inject_fragmented(&b->t, b->ch, chSz, 40),
                3);
        }
        else {
            ExpectIntGT(cookieEnd = test_dtls13_ch_cookie_end(b->ch, chSz),
                0);
            ExpectIntLT(cookieEnd, chSz - hdrSz);
            ExpectIntGT(fragSz = test_dtls13_frag_range(b->ch, chSz,
                (word32)cookieEnd, (word32)(chSz - hdrSz - cookieEnd), 1,
                b->frag, (int)sizeof(b->frag)), 0);
            ExpectIntEQ(test_memio_inject_message(&b->t, 0,
                (const char*)b->frag, fragSz), 0);
            ExpectIntGT(fragSz = test_dtls13_frag_range(b->ch, chSz, 0,
                (word32)cookieEnd, 0, b->frag, (int)sizeof(b->frag)), 0);
            ExpectIntEQ(test_memio_inject_message(&b->t, 0,
                (const char*)b->frag, fragSz), 0);
        }
        ExpectIntEQ(test_dtls13_server_read_all(&b->t, ssl_s), TEST_SUCCESS);
        ExpectIntEQ(test_dtls13_reply_is_server_hello(&b->t, &isHrr), 1);
        ExpectIntEQ(isHrr, 0);
    }
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_write(ssl_c, hello, (int)sizeof(hello)),
        (int)sizeof(hello));
    ExpectIntEQ(wolfSSL_read(ssl_s, reply, (int)sizeof(reply)),
        (int)sizeof(hello));
    ExpectIntEQ(wolfSSL_write(ssl_s, reply, (int)sizeof(reply)),
        (int)sizeof(reply));
    ExpectIntEQ(wolfSSL_read(ssl_c, reply, (int)sizeof(reply)),
        (int)sizeof(hello));
    ExpectBufEQ(reply, hello, sizeof(hello));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    return EXPECT_RESULT();
}

static THREAD_RETURN WOLFSSL_THREAD test_dtls13_ch_hs_worker(void* args)
{
    int tno = ((func_args*)args)->argc;
    test_dtls13_ch_hs_bufs* b;
    int r;

    b = (test_dtls13_ch_hs_bufs*)XMALLOC(sizeof(*b), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (b == NULL)
        test_ch_hs_fail[tno]++;
    for (r = 0; b != NULL && r < TEST_CH_HS_ROUNDS; r++) {
        /* A new peer each round, so no round meets another's entry */
        if (test_dtls13_ch_hs_one(test_ch_hs_ctx_c[tno], test_ch_hs_ctx_s, b,
                (tno + 1) * 1000 + r, r % 3) != TEST_SUCCESS)
            test_ch_hs_fail[tno]++;
    }
    XFREE(b, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif

/* Two threads run full handshakes through servers of one context, whose pool
 * holds every ClientHello on the way, in each way it can */
int test_dtls13_ch_pool_handshake_threads(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256) && !defined(SINGLE_THREADED)
    THREAD_TYPE threads[TEST_CH_HS_THREADS];
    func_args args[TEST_CH_HS_THREADS];
    struct test_memio_ctx t;
    test_dtls13_ch_hs_bufs* b = NULL;
    int i;

    XMEMSET(&t, 0, sizeof(t));
    XMEMSET(args, 0, sizeof(args));
    XMEMSET(test_ch_hs_fail, 0, sizeof(test_ch_hs_fail));
    test_ch_hs_ctx_s = NULL;
    for (i = 0; i < TEST_CH_HS_THREADS; i++) {
        test_ch_hs_ctx_c[i] = NULL;
        ExpectIntEQ(test_memio_setup(&t, &test_ch_hs_ctx_c[i],
            &test_ch_hs_ctx_s, NULL, NULL, wolfDTLSv1_3_client_method,
            wolfDTLSv1_3_server_method), 0);
    }
    /* One handshake first: wolfCrypt sets its CPU feature flags on first use
     * without a lock */
    ExpectNotNull(b = (test_dtls13_ch_hs_bufs*)XMALLOC(sizeof(*b), NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(test_dtls13_ch_hs_one(test_ch_hs_ctx_c[0],
            test_ch_hs_ctx_s, b, 1, 0), TEST_SUCCESS);
    }
    XFREE(b, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (EXPECT_SUCCESS()) {
        for (i = 0; i < TEST_CH_HS_THREADS; i++) {
            args[i].argc = i;
            start_thread(test_dtls13_ch_hs_worker, &args[i], &threads[i]);
        }
        for (i = 0; i < TEST_CH_HS_THREADS; i++)
            join_thread(threads[i]);
    }
    for (i = 0; i < TEST_CH_HS_THREADS; i++)
        ExpectIntEQ(test_ch_hs_fail[i], 0);
    ExpectNotNull(test_ch_hs_ctx_s);
    if (test_ch_hs_ctx_s != NULL) {
        ExpectIntEQ(test_dtls13_pool_count(&test_ch_hs_ctx_s->dtlsChPool), 0);
        ExpectTrue(test_dtls13_pool_ok(&test_ch_hs_ctx_s->dtlsChPool));
    }

    for (i = 0; i < TEST_CH_HS_THREADS; i++) {
        wolfSSL_CTX_free(test_ch_hs_ctx_c[i]);
        test_ch_hs_ctx_c[i] = NULL;
    }
    wolfSSL_CTX_free(test_ch_hs_ctx_s);
    test_ch_hs_ctx_s = NULL;
#endif
    return EXPECT_RESULT();
}

/* Cookie exchange off: the server is stateful from the start, but a plaintext
 * fragment contradicting the held ClientHello is dropped, not fatal. */
int test_dtls13_frag_ch1_no_cookie_conflict(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) \
    && defined(WOLFSSL_DTLS_CH_FRAG) && defined(WOLFSSL_SEND_HRR_COOKIE) && \
    defined(HAVE_ECC) && !defined(NO_ECC256)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    int group = WOLFSSL_ECC_SECP256R1;
    byte ch[TEST_MEMIO_BUF_SZ];
    int chSz = (int)sizeof(ch);
    byte frag[TEST_MEMIO_BUF_SZ];
    int fragSz = 0;
    int piece = 0;
    int isHrr = 1;
    word32 msgLen = 0;
    word32 recSeq = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(wolfSSL_disable_hrr_cookie(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_groups(ssl_c, &group, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_dtls13_take_ch(&test_ctx, ssl_c, ch, &chSz),
        TEST_SUCCESS);
    piece = (chSz - DTLS_RECORD_HEADER_SZ - DTLS_HANDSHAKE_HEADER_SZ + 2) / 3;

    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 0), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(ssl_s->options.dtlsStateful, 1);
    ExpectNotNull(ssl_s->dtls_rx_msg_list);
    ExpectIntEQ(test_dtls13_pool_count(&ctx_s->dtlsChPool), 0);

    ExpectIntGT(fragSz = test_dtls13_frag_record(ch, chSz, piece, 1, frag,
        (int)sizeof(frag)), 0);
    if (EXPECT_SUCCESS()) {
        ato24(frag + DTLS_RECORD_HEADER_SZ + 1, &msgLen);
        c32to24(msgLen + 1, frag + DTLS_RECORD_HEADER_SZ + 1);
        /* A record number of its own, or the replay window drops the
         * genuine fragment as a duplicate of it */
        ato32(frag + DTLS_RECORD_HEADER_SZ - 6, &recSeq);
        c32toa(recSeq + 10, frag + DTLS_RECORD_HEADER_SZ - 6);
    }
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)frag,
        fragSz), 0);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_ctx.c_len, 0);

    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 1), 1);
    ExpectIntEQ(test_dtls13_inject_frag(&test_ctx, ch, chSz, piece, 2), 1);
    ExpectIntEQ(test_dtls13_server_read_all(&test_ctx, ssl_s), TEST_SUCCESS);
    ExpectIntEQ(test_dtls13_reply_is_server_hello(&test_ctx, &isHrr), 1);
    ExpectIntEQ(isHrr, 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Direct pool coverage avoids record parsing and cookie generation masking
 * admission, LRU, completion and ownership regressions. */
int test_dtls13_ch_pool_unit(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte* data = NULL;
    byte peerBuf[16];
    byte alt[8];
    WOLFSSL_SOCKADDR peer;
    WOLFSSL_SOCKADDR none;
    DtlsMsg* current = NULL;
    DtlsMsg* other = NULL;
    DtlsMsg* done = NULL;
    DtlsMsg* saved = NULL;
    DtlsMsg* h = NULL;
    size_t base = sizeof(DtlsMsg) + sizeof(peerBuf) + sizeof(DtlsFragBucket);
    /* The largest ClientHello the pool completes: its last fragment is
     * reserved as a new entry on top of the one holding the rest */
    word32 len = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT - 2 * base);
    size_t bytes;
    word32 held = 0;
    word32 shard = 0;
    int i;

    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectNotNull(data = (byte*)XMALLOC(TEST_DTLS_RX_UNVERIFIED_LIMIT, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_FAIL()) {
        DtlsChPoolFree(&pool, NULL);
        return EXPECT_RESULT();
    }
    XMEMSET(data, 0x5a, TEST_DTLS_RX_UNVERIFIED_LIMIT);
    XMEMSET(peerBuf, 0x01, sizeof(peerBuf));
    peer.sz = sizeof(peerBuf);
    peer.bufSz = sizeof(peerBuf);
    peer.sa = peerBuf;
    XMEMSET(&none, 0, sizeof(none));

    ExpectIntEQ(DtlsChPoolStore(NULL, NULL, &peer, 0, 0, data, len,
        client_hello, 0, 1, DTLS_TIMEOUT_MAX, NULL, &done),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, NULL, 0, 0, data, len,
        client_hello, 0, 1, DTLS_TIMEOUT_MAX, NULL, &done),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 4, client_hello,
        3, 2, DTLS_TIMEOUT_MAX, NULL, &done), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNull(done);

    /* The peer copy is counted */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len,
        client_hello, 0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectNotNull(current = test_dtls13_pool_head(&pool));
    ExpectIntEQ(current != NULL ? (int)current->peer.bufSz : 0,
        sizeof(peerBuf));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), base + 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* Capacity remains allocated even if the logical address gets shorter */
    if (EXPECT_SUCCESS())
        current->peer.sz = 1;
    ExpectIntEQ(DtlsMsgListRetainedBytes(current), base + 1);
    if (EXPECT_SUCCESS())
        current->peer.sz = sizeof(peerBuf);
    /* A second peer goes after the first */
    peerBuf[0] = 2;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len,
        client_hello, 0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(other = test_dtls13_pool_next(&pool, current));
    bytes = 2 * (base + 1);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), bytes);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* An empty peer is no key, and a whole message is never held */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &none, 0, 0, data, len,
        client_hello, 0, 1, DTLS_TIMEOUT_MAX, NULL, &done),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &none, 0, 0, 1, len,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 4, client_hello,
        0, 4, DTLS_TIMEOUT_MAX, NULL, &done), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNull(done);
    ExpectPtrEq(test_dtls13_pool_head(&pool), current);
    ExpectPtrEq(test_dtls13_pool_next(&pool, current), other);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), bytes);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* An impossible completed CH must not evict the current entry or another
     * one. */
    peerBuf[0] = 3;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len + 1,
        client_hello, 0, 1,
        DTLS_TIMEOUT_MAX, NULL, &done), DTLS_MSG_STORE_DROPPED);
    peerBuf[0] = 1;
    ExpectNull(done);
    ExpectPtrEq(test_dtls13_pool_head(&pool), current);
    ExpectPtrEq(test_dtls13_pool_next(&pool, current), other);
    ExpectIntEQ(current != NULL ? (int)current->bytesReceived : 0, 1);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), bytes);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* A duplicate does not refresh; new bytes do, partial overlaps too */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len,
        client_hello, 0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectPtrEq(test_dtls13_pool_head(&pool), current);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len,
        client_hello, 0, 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectPtrEq(test_dtls13_pool_head(&pool), other);
    ExpectPtrEq(test_dtls13_pool_next(&pool, other), current);
    ExpectNull(test_dtls13_pool_next(&pool, current));
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), bytes + 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* Refresh other, making current the oldest again */
    peerBuf[0] = 2;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len,
        client_hello, 1, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectPtrEq(test_dtls13_pool_head(&pool), current);
    peerBuf[0] = 3;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len,
        client_hello, 0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 3);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* Completing the oldest, to the largest the pool holds, evicts both other
     * entries, never the one extended. The completed message leaves without
     * its peer. */
    peerBuf[0] = 1;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, len,
        client_hello, 2, len - 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectPtrEq(done, current);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), 0);
    ExpectNull(test_dtls13_pool_head(&pool));
    ExpectNotNull(done);
    if (done != NULL) {
        ExpectIntEQ(done->ready, 1);
        ExpectIntEQ(done->peer.sz, 0);
        ExpectNull(done->peer.sa);
        ExpectNull(done->next);
        ExpectBufEQ(done->fullMsg, data, len);
        ExpectIntEQ(DtlsMsgListRetainedBytes(done),
            base - sizeof(peerBuf) + len);
    }
    DtlsMsgListDelete(done, NULL);
    done = NULL;

    /* One entry per peer, the newest: another message, or a fragment
     * contradicting the one held, replaces it */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    h = test_dtls13_pool_head(&pool);
    ExpectIntEQ(h != NULL ? (int)h->seq : -1, 1);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 5, client_hello,
        1, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    h = test_dtls13_pool_head(&pool);
    ExpectIntEQ(h != NULL ? (int)h->sz : -1, 5);
    h = test_dtls13_pool_head(&pool);
    ExpectIntEQ(h != NULL ? (int)h->bytesReceived : -1, 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    ExpectNull(done);

    /* A fragment whose bytes differ from those it overlaps replaces the
     * entry too. Agreeing and disjoint fragments merge. */
    XMEMSET(alt, 0xa5, sizeof(alt));
    peerBuf[0] = 2;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 8, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    peerBuf[0] = 1;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 8, client_hello,
        0, 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 8, client_hello,
        1, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, alt, 8, client_hello,
        2, 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectNotNull(current = test_dtls13_pool_next(&pool,
        test_dtls13_pool_head(&pool)));
    ExpectIntEQ(current != NULL ? (int)current->bytesReceived : -1, 4);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 8, client_hello,
        3, 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectNotNull(current = test_dtls13_pool_next(&pool,
        test_dtls13_pool_head(&pool)));
    ExpectIntEQ(current != NULL ? (int)current->bytesReceived : -1, 2);
    ExpectIntEQ(current != NULL && current->fragBucketList != NULL ?
        (int)current->fragBucketList->m.m.offset : -1, 3);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* Every bucket the fragment spans is compared: [4,7) agrees with [3,5)
     * but not with [6,7), so it replaces the entry */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 8, client_hello,
        6, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(current != NULL ? (int)current->fragBucketListCount : -1, 2);
    XMEMSET(alt, 0x5a, 6);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, alt + 4, 8,
        client_hello, 4, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectNotNull(current = test_dtls13_pool_next(&pool,
        test_dtls13_pool_head(&pool)));
    ExpectIntEQ(current != NULL ? (int)current->bytesReceived : -1, 3);
    ExpectIntEQ(current != NULL && current->fragBucketList != NULL ?
        (int)current->fragBucketList->m.m.offset : -1, 4);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* The message it completes is all its own */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, alt, 8, client_hello,
        0, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, alt + 7, 8,
        client_hello, 7, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    if (done != NULL) {
        ExpectIntEQ(done->ready, 1);
        ExpectBufEQ(done->fullMsg, alt, 8);
    }
    DtlsMsgListDelete(done, NULL);
    done = NULL;
    peerBuf[0] = 2;
    ExpectNotNull(test_dtls13_pool_head(&pool));
    h = test_dtls13_pool_head(&pool);
    ExpectIntEQ(h != NULL ? (int)h->bytesReceived : -1, 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* A fragment opening one more gap than DTLS_FRAG_POOL_SZ is dropped, as
     * in the receive list; one touching what is held is taken */
    DtlsChPoolClear(&pool, NULL);
    peerBuf[0] = 1;
    for (i = 0; i < DTLS_FRAG_POOL_SZ && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data,
            2 * DTLS_FRAG_POOL_SZ + 2, client_hello, 2 * i, 1,
            DTLS_TIMEOUT_MAX, NULL, &done),
            0);
    }
    ExpectNotNull(current = test_dtls13_pool_head(&pool));
    ExpectIntEQ(current != NULL ? (int)current->fragBucketListCount : -1,
        DTLS_FRAG_POOL_SZ);
    bytes = test_dtls13_pool_bytes(&pool);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data,
        2 * DTLS_FRAG_POOL_SZ + 2, client_hello, 2 * DTLS_FRAG_POOL_SZ, 1,
        DTLS_TIMEOUT_MAX, NULL, &done), DTLS_MSG_STORE_DROPPED);
    ExpectPtrEq(test_dtls13_pool_head(&pool), current);
    ExpectIntEQ(current != NULL ? (int)current->fragBucketListCount : -1,
        DTLS_FRAG_POOL_SZ);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), bytes);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data,
        2 * DTLS_FRAG_POOL_SZ + 2, client_hello, 2 * DTLS_FRAG_POOL_SZ - 1, 1,
        DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(current != NULL ? (int)current->fragBucketListCount : -1,
        DTLS_FRAG_POOL_SZ);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data,
        2 * DTLS_FRAG_POOL_SZ + 2, client_hello, 1, 1,
        DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(current != NULL ? (int)current->fragBucketListCount : -1,
        DTLS_FRAG_POOL_SZ - 1);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* Clear */
    DtlsChPoolClear(&pool, NULL);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), 0);
    ExpectNull(test_dtls13_pool_head(&pool));

    /* Release: only the rest of the ClientHello whose first fragment
     * verified is returned, without its peer copy */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    peerBuf[0] = 2;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    peerBuf[0] = 3;
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 1, 4,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    peerBuf[0] = 1;
    ExpectNotNull(done = DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 1, 4,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    if (done != NULL) {
        ExpectIntEQ(done->peer.sz, 0);
        ExpectNull(done->peer.sa);
        ExpectIntEQ(DtlsMsgListRetainedBytes(done), base - sizeof(peerBuf) + 3);
        ExpectNull(done->next);
        ExpectPtrEq(DtlsMsgFind(done, 0, 1), done);
    }
    DtlsMsgListDelete(done, NULL);
    done = NULL;
    /* An overlap is cut away: only the bytes past the verified fragment */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(done = DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 2, 4,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    if (done != NULL) {
        ExpectIntEQ(done->bytesReceived, 2);
        ExpectIntEQ(done->fragBucketListCount, 1);
        ExpectNotNull(done->fragBucketList);
        if (done->fragBucketList != NULL) {
            ExpectIntEQ(done->fragBucketList->m.m.offset, 2);
            ExpectIntEQ(done->fragBucketList->m.m.sz, 2);
            ExpectBufEQ(done->fragBucketList->buf, data + 2, 2);
            ExpectNull(done->fragBucketList->m.m.next);
        }
    }
    DtlsMsgListDelete(done, NULL);
    done = NULL;
    /* Nothing past the verified fragment, another seq or another size: freed */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 4, 4,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    DtlsChPoolDrop(&pool, NULL, &peer, DTLS_TIMEOUT_MAX);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 2, 1, 4,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 1, 5,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    peerBuf[0] = 2;
    ExpectNotNull(test_dtls13_pool_head(&pool));
    h = test_dtls13_pool_head(&pool);
    ExpectIntEQ(h != NULL ? (int)h->bytesReceived : -1, 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    ExpectNull(done);
    DtlsChPoolFree(&pool, NULL);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);
    ExpectNull(test_dtls13_pool_head(&pool));
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);

    /* Adopting on the same heap keeps the message. A partial one comes from
     * the pool: no part of it overlaps an empty first fragment. */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        3, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(done = DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 0, 4,
        DTLS_TIMEOUT_MAX, NULL));
    saved = done;
    ExpectIntEQ(DtlsMsgAdopt(&done, NULL, NULL), 0);
    ExpectPtrEq(done, saved);
    ExpectIntEQ(DtlsMsgAdopt(NULL, NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#if !defined(WOLFSSL_STATIC_MEMORY) && !defined(XMALLOC_USER) && \
    !defined(WOLFSSL_HEAP_TEST)
    /* On another heap it is rebuilt, bucket by bucket */
    ExpectIntEQ(DtlsMsgAdopt(&done, NULL, (void*)&pool), 0);
    ExpectNotNull(done);
    ExpectPtrNE(done, saved);
    if (done != NULL) {
        ExpectIntEQ(done->ready, 0);
        ExpectIntEQ(done->bytesReceived, 3);
        ExpectIntEQ(done->fragBucketListCount, 2);
        ExpectIntEQ(done->type, client_hello);
        ExpectIntEQ(done->seq, 1);
        ExpectNotNull(done->fragBucketList);
        if (done->fragBucketList != NULL) {
            ExpectIntEQ(done->fragBucketList->m.m.offset, 0);
            ExpectIntEQ(done->fragBucketList->m.m.sz, 2);
            ExpectNotNull(done->fragBucketList->m.m.next);
        }
        if (done->fragBucketList != NULL &&
                done->fragBucketList->m.m.next != NULL) {
            ExpectIntEQ(done->fragBucketList->m.m.next->m.m.offset, 3);
            ExpectIntEQ(done->fragBucketList->m.m.next->m.m.sz, 1);
        }
    }
    DtlsMsgListDelete(done, (void*)&pool);
    /* and a complete one as a whole */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        2, 2, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(done);
    saved = done;
    ExpectIntEQ(DtlsMsgAdopt(&done, NULL, (void*)&pool), 0);
    ExpectNotNull(done);
    ExpectPtrNE(done, saved);
    if (done != NULL) {
        ExpectIntEQ(done->ready, 1);
        ExpectIntEQ(done->bytesReceived, 4);
        ExpectBufEQ(done->fullMsg, data, 4);
    }
    DtlsMsgListDelete(done, (void*)&pool);
#else
    DtlsMsgListDelete(done, NULL);
#endif
    done = NULL;
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);

    /* Only new bytes restart an entry's clock */
    peerBuf[0] = 1;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(current = test_dtls13_pool_head(&pool));
    if (current != NULL)
        current->heldAt -= (word32)DTLS_TIMEOUT_MAX / 2;
    saved = current;
    held = current != NULL ? current->heldAt : 0;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectPtrEq(test_dtls13_pool_head(&pool), saved);
    ExpectTrue(current != NULL && current->heldAt == held);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        2, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectPtrEq(test_dtls13_pool_head(&pool), saved);
    ExpectIntEQ(current != NULL ? (int)current->bytesReceived : -1, 2);
    ExpectTrue(current != NULL && current->heldAt != held);
    /* An entry that aged out is abandoned: a later disjoint fragment of the
     * same size starts a new entry instead of merging */
    test_dtls13_age(current);
    XMEMSET(alt, 0xa5, sizeof(alt));
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, alt, 4, client_hello,
        1, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectNotNull(current = test_dtls13_pool_head(&pool));
    ExpectIntEQ(current != NULL ? (int)current->bytesReceived : -1, 1);
    ExpectIntEQ(current != NULL && current->fragBucketList != NULL ?
        (int)current->fragBucketList->m.m.offset : -1, 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* A rest whose clock ran out is freed, not returned */
    DtlsChPoolClear(&pool, NULL);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    test_dtls13_age(test_dtls13_pool_head(&pool));
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 1, 4,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);
    ExpectIntEQ(test_dtls13_pool_bytes(&pool), 0);
    /* Any store in its shard frees it */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    test_dtls13_age(test_dtls13_pool_head(&pool));
    shard = DtlsChPoolShardIdx(&peer);
    for (i = 2; i < 256; i++) {
        peerBuf[0] = (byte)i;
        if (DtlsChPoolShardIdx(&peer) == shard)
            break;
    }
    ExpectIntLT(i, 256);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectNotNull(test_dtls13_pool_head(&pool));
    h = test_dtls13_pool_head(&pool);
    ExpectIntEQ(h != NULL ? ((byte*)h->peer.sa)[0] : 0, i);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    ExpectNull(done);
    DtlsChPoolClear(&pool, NULL);
    /* A hold time ahead of the clock, after a timer wrap or clock step, gives no
     * age. The store frees the entry, so the fragment starts a new one. */
    peerBuf[0] = 1;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(current = test_dtls13_pool_head(&pool));
    if (current != NULL)
        current->heldAt += 3600;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectNotNull(current = test_dtls13_pool_head(&pool));
    ExpectIntEQ(current != NULL ? (int)current->bytesReceived : -1, 1);
    ExpectIntEQ(current != NULL && current->fragBucketList != NULL ?
        (int)current->fragBucketList->m.m.offset : -1, 0);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolClear(&pool, NULL);
    /* A release frees it too: held 10 s before a 1 kHz 32-bit tick count
     * wrapped */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        1, 3, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(saved = test_dtls13_pool_head(&pool));
    peerBuf[0] = 2;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectPtrEq(test_dtls13_pool_head(&pool), saved);
    if (saved != NULL)
        saved->heldAt += (word32)(4294967UL - 10);
    peerBuf[0] = 1;
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 1, 1, 4,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectNotNull(test_dtls13_pool_head(&pool));
    h = test_dtls13_pool_head(&pool);
    ExpectIntEQ(h != NULL ? ((byte*)h->peer.sa)[0] : 0, 2);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolClear(&pool, NULL);

    /* Free leaves nothing, and the pool can be set up again */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    DtlsChPoolFree(&pool, NULL);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), 0);
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 1, data, 4, client_hello,
        0, 1, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolFree(&pool, NULL);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* A peer is its address bytes, whatever they look like: the same bytes are
 * one peer, any differing byte is another, padding of a sockaddr included */
int test_dtls13_ch_pool_peer_key(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte o1[16];
    byte o2[16];
    WOLFSSL_SOCKADDR pa;
    WOLFSSL_SOCKADDR pb;
    byte data[8];
    DtlsMsg* done = NULL;

    XMEMSET(data, 0x5a, sizeof(data));
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);

    /* The same bytes from another buffer complete the ClientHello */
    XMEMSET(o1, 0x01, sizeof(o1));
    XMEMCPY(o2, o1, sizeof(o2));
    pa.sa = o1;
    pa.sz = pa.bufSz = (unsigned int)sizeof(o1);
    pb.sa = o2;
    pb.sz = pb.bufSz = (unsigned int)sizeof(o2);
    ExpectIntEQ(DtlsChPoolShardIdx(&pa), DtlsChPoolShardIdx(&pb));
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pa, 0, 0, data, 8, client_hello,
        0, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pb, 0, 0, data, 8, client_hello,
        4, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNotNull(done);
    DtlsMsgListDelete(done, NULL);
    done = NULL;
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);

    /* One byte off is another peer */
    o2[sizeof(o2) - 1] = 0x02;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pa, 0, 0, data, 8, client_hello,
        0, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pb, 0, 0, data, 8, client_hello,
        4, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolClear(&pool, NULL);

    /* A shorter address is another peer, even as a prefix */
    pb.sa = o1;
    pb.sz = pb.bufSz = (unsigned int)sizeof(o1) - 1;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pa, 0, 0, data, 8, client_hello,
        0, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pb, 0, 0, data, 8, client_hello,
        4, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectTrue(test_dtls13_pool_ok(&pool));

#ifdef HAVE_SOCKADDR
    /* A sockaddr_in differing only in sin_zero is another peer: the bytes
     * are not interpreted, so a custom transport's 16-byte id that happens
     * to read as AF_INET is keyed whole too */
    {
        SOCKADDR_IN a4;
        SOCKADDR_IN b4;

        DtlsChPoolClear(&pool, NULL);
        XMEMSET(&a4, 0, sizeof(a4));
        a4.sin_family = WOLFSSL_IP4;
        a4.sin_port = 4433;
        a4.sin_addr.s_addr = 0x0100007fU;
        b4 = a4;
        XMEMSET(b4.sin_zero, 0xee, sizeof(b4.sin_zero));
        pa.sa = &a4;
        pa.sz = pa.bufSz = (unsigned int)sizeof(a4);
        pb.sa = &b4;
        pb.sz = pb.bufSz = (unsigned int)sizeof(b4);
        ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pa, 0, 0, data, 8,
            client_hello, 0, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
        ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &pb, 0, 0, data, 8,
            client_hello, 4, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
        ExpectNull(done);
        ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
        ExpectTrue(test_dtls13_pool_ok(&pool));
    }
#endif

    DtlsChPoolFree(&pool, NULL);
#endif
    return EXPECT_RESULT();
}

/* Only a DTLS context initializes the ClientHello pool. A TLS context's pool
 * takes nothing. */
int test_dtls13_ch_pool_ctx_init(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX* tls = NULL;
    WOLFSSL_CTX* dtls = NULL;
    byte peerBuf[4];
    WOLFSSL_SOCKADDR peer;
    byte data[8];
    DtlsMsg* done = NULL;

    XMEMSET(data, 0x5a, sizeof(data));
    XMEMSET(peerBuf, 0x07, sizeof(peerBuf));
    peer.sa = peerBuf;
    peer.sz = peer.bufSz = (unsigned int)sizeof(peerBuf);

    ExpectNotNull(tls = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    ExpectNotNull(dtls = wolfSSL_CTX_new(wolfDTLSv1_3_server_method()));
    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(tls->dtlsChPool.ready, 0);
        ExpectIntEQ(dtls->dtlsChPool.ready, 1);
        ExpectIntEQ(DtlsChPoolStore(&tls->dtlsChPool, tls->heap, &peer, 0, 0,
            data, 8, client_hello, 0, 4, DTLS_TIMEOUT_MAX, NULL, &done),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectNull(done);
        ExpectNull(DtlsChPoolTakeRest(&tls->dtlsChPool, tls->heap, &peer, 0, 0,
            4, 8, DTLS_TIMEOUT_MAX, NULL));
        DtlsChPoolDrop(&tls->dtlsChPool, tls->heap, &peer, DTLS_TIMEOUT_MAX);
        DtlsChPoolClear(&tls->dtlsChPool, tls->heap);
        ExpectIntEQ(DtlsChPoolStore(&dtls->dtlsChPool, dtls->heap, &peer, 0, 0,
            data, 8, client_hello, 0, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
        ExpectIntEQ(test_dtls13_pool_count(&dtls->dtlsChPool), 1);
    }
    wolfSSL_CTX_free(tls);
    wolfSSL_CTX_free(dtls);
#endif
    return EXPECT_RESULT();
}

/* An entry expires after the storing server's retransmission maximum, not a
 * fixed time. The rest taken for a verified first fragment ages the same. */
int test_dtls13_ch_pool_max_age(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte peerBuf[4];
    WOLFSSL_SOCKADDR peer;
    byte data[8];
    DtlsMsg* done = NULL;
    DtlsMsg* rest = NULL;
    word32 longer = 2 * (word32)DTLS_TIMEOUT_MAX;

    XMEMSET(data, 0x5a, sizeof(data));
    XMEMSET(peerBuf, 0x07, sizeof(peerBuf));
    peer.sa = peerBuf;
    peer.sz = peer.bufSz = (unsigned int)sizeof(peerBuf);
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);

    /* Older than the default but within a longer maximum: kept */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 8, client_hello,
        0, 4, longer, NULL, &done), 0);
    test_dtls13_age(test_dtls13_pool_head(&pool));
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 8, client_hello,
        4, 4, longer, NULL, &done), 0);
    ExpectNotNull(done);
    DtlsMsgListDelete(done, NULL);
    done = NULL;
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);

    /* Older than the maximum: gone, and the fragment starts over */
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 8, client_hello,
        0, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    test_dtls13_age(test_dtls13_pool_head(&pool));
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 8, client_hello,
        4, 4, DTLS_TIMEOUT_MAX, NULL, &done), 0);
    ExpectNull(done);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    DtlsChPoolClear(&pool, NULL);

    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 8, client_hello,
        4, 4, longer, NULL, &done), 0);
    test_dtls13_age(test_dtls13_pool_head(&pool));
    rest = DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 0, 4, 8, longer, NULL);
    ExpectNotNull(rest);
    DtlsMsgListDelete(rest, NULL);
    rest = NULL;
    ExpectIntEQ(DtlsChPoolStore(&pool, NULL, &peer, 0, 0, data, 8, client_hello,
        4, 4, longer, NULL, &done), 0);
    test_dtls13_age(test_dtls13_pool_head(&pool));
    ExpectNull(DtlsChPoolTakeRest(&pool, NULL, &peer, 0, 0, 4, 8,
        DTLS_TIMEOUT_MAX, NULL));
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);

    DtlsChPoolFree(&pool, NULL);
#endif
    return EXPECT_RESULT();
}

/* All shards share one budget. Eviction takes the oldest entry of the whole
 * pool, whatever its shard. A store evicts for the bound of its fragment,
 * a new entry holding it, before it learns what the fragment adds. */
int test_dtls13_ch_pool_shards(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte* data = NULL;
    const word32 msgSz = 512;
    const word32 first = 16;
    size_t entry = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket) +
        first;
    size_t left;
    size_t bytes = 0;
    /* The largest ClientHello the pool completes */
    word32 bigSz = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT -
        2 * (sizeof(int) + sizeof(DtlsMsg) + sizeof(DtlsFragBucket)));
    int capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT / entry);
    int order[TEST_DTLS_RX_UNVERIFIED_LIMIT / (sizeof(DtlsMsg) + 16)];
    int last = WOLFSSL_DTLS_CH_POOL_SHARDS - 1;
    int a, b, c, d, e, w, x, y, z;
    int id;
    int i;
    DtlsMsg* m = NULL;

    left = TEST_DTLS_RX_UNVERIFIED_LIMIT - (size_t)capacity * entry;
    ExpectIntGT(capacity, 4);
    ExpectIntLE(capacity, (int)(sizeof(order) / sizeof(order[0])));
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectNotNull(data = (byte*)XMALLOC(TEST_DTLS_RX_UNVERIFIED_LIMIT, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_FAIL()) {
        DtlsChPoolFree(&pool, NULL);
        return EXPECT_RESULT();
    }
    XMEMSET(data, 0x5a, TEST_DTLS_RX_UNVERIFIED_LIMIT);

    /* The oldest is in the last shard, so a scan from shard 0 meets other
     * entries first, and e is the next behind it there. The rest spread over
     * all shards. */
    a = test_dtls13_id_in(1, (word32)last, 1);
    e = test_dtls13_id_in(a + 1, (word32)last, 1);
    order[0] = a;
    order[1] = e;
    for (i = 2, id = 1; i < capacity; i++, id++) {
        while (id == a || id == e)
            id++;
        order[i] = id;
    }
    for (i = 0; i < capacity && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(test_dtls13_pool_put(&pool, order[i], data, msgSz, 0,
            first), 0);
        ExpectIntEQ(test_dtls13_pool_count(&pool), i + 1);
        ExpectTrue(test_dtls13_pool_bytes(&pool) == (size_t)(i + 1) * entry);
        ExpectTrue(test_dtls13_pool_ok(&pool));
    }
#if WOLFSSL_DTLS_CH_POOL_SHARDS > 1
    for (i = 0, id = 0; i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++)
        id += pool.shard[i].head != NULL;
    ExpectIntGT(id, 1);
#endif
    b = order[2];
    c = order[3];
    d = order[capacity - 1];

    /* A duplicate of a at capacity adds nothing but evicts for its bound:
     * e, the entry behind a's own, the oldest. a stays the oldest. */
    ExpectIntEQ(test_dtls13_pool_put(&pool, a, data, msgSz, 0, first), 0);
    ExpectPtrEq(test_dtls13_pool_head(&pool), test_dtls13_held_for(&pool, a));
    ExpectNull(test_dtls13_held_for(&pool, e));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* A new peer takes the room that made. The next one, outside a's shard,
     * evicts a and nothing else. */
    w = test_dtls13_id_in(capacity + 1, test_dtls13_shard_of(a), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, w, data, msgSz, 0, first), 0);
    ExpectNotNull(test_dtls13_held_for(&pool, a));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity);
    x = test_dtls13_id_in(w + 1, test_dtls13_shard_of(a), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, x, data, msgSz, 0, first), 0);
    ExpectNull(test_dtls13_held_for(&pool, a));
    ExpectNotNull(test_dtls13_held_for(&pool, x));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity);
    ExpectTrue(test_dtls13_pool_bytes(&pool) == (size_t)capacity * entry);
    ExpectPtrEq(test_dtls13_pool_head(&pool), test_dtls13_held_for(&pool, b));
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* Released bytes go back to the budget. New bytes make b the newest. */
    if (EXPECT_SUCCESS()) {
        WOLFSSL_SOCKADDR peer;

        peer.sz = sizeof(d);
        peer.bufSz = sizeof(d);
        peer.sa = &d;
        DtlsChPoolDrop(&pool, NULL, &peer, DTLS_TIMEOUT_MAX);
    }
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectIntEQ(test_dtls13_pool_put(&pool, b, data, msgSz, first, 1), 0);
    ExpectNotNull(m = test_dtls13_held_for(&pool, b));
    ExpectNull(test_dtls13_pool_next(&pool, m));
    ExpectPtrEq(test_dtls13_pool_head(&pool), test_dtls13_held_for(&pool, c));
    ExpectTrue(test_dtls13_pool_bytes(&pool) ==
        (size_t)(capacity - 1) * entry + 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* y needs just more than is left: it evicts c, the oldest, from another
     * shard when there is one, and not b */
    y = test_dtls13_id_in(x + 1, test_dtls13_shard_of(c), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, y, data, msgSz, 0,
        first + (word32)left), 0);
    ExpectNull(test_dtls13_held_for(&pool, c));
    ExpectNotNull(test_dtls13_held_for(&pool, b));
    ExpectNotNull(test_dtls13_held_for(&pool, y));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectTrue(test_dtls13_pool_bytes(&pool) ==
        (size_t)(capacity - 1) * entry + 1 + left);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* One more byte than the largest ClientHello the pool completes is
     * dropped before anything is evicted */
    z = y + 1;
    bytes = test_dtls13_pool_bytes(&pool);
    i = test_dtls13_pool_count(&pool);
    ExpectIntEQ(test_dtls13_pool_put(&pool, z, data, bigSz + 1, 0, 1),
        DTLS_MSG_STORE_DROPPED);
    ExpectTrue(test_dtls13_pool_bytes(&pool) == bytes);
    ExpectIntEQ(test_dtls13_pool_count(&pool), i);
    /* z holds one byte of the largest. The rest but its last byte evicts
     * every other entry for its bound, and the last byte's bound is just
     * what is left: it completes. */
    ExpectIntEQ(test_dtls13_pool_put(&pool, z, data, bigSz, 0, 1), 0);
    ExpectNotNull(test_dtls13_held_for(&pool, z));
    ExpectIntEQ(test_dtls13_pool_count(&pool), i + 1);
    ExpectIntEQ(test_dtls13_pool_put(&pool, z, data, bigSz, 1, bigSz - 2),
        0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectTrue(test_dtls13_pool_bytes(&pool) ==
        TEST_DTLS_RX_UNVERIFIED_LIMIT - entry + first - 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    ExpectIntEQ(test_dtls13_pool_put(&pool, z, data, bigSz, bigSz - 1, 1),
        0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), 0);

    /* With another store's add in flight, a duplicate adds nothing but
     * evicts one entry, its bound. A new peer evicts one entry and gets in. */
    DtlsChPoolClear(&pool, NULL);
    for (i = 1; i <= capacity; i++)
        ExpectIntEQ(test_dtls13_pool_put(&pool, i, data, msgSz, 0, first), 0);
    (void)wolfSSL_Atomic_Uint_AddFetch(&pool.reserved,
        (WC_ATOMIC_UINT_ARG)TEST_DTLS_RX_UNVERIFIED_LIMIT);
    ExpectIntEQ(test_dtls13_pool_put(&pool, 1, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectNotNull(test_dtls13_held_for(&pool, 1));
    ExpectTrue(test_dtls13_pool_bytes(&pool) ==
        (size_t)(capacity - 1) * entry);
    ExpectIntEQ(test_dtls13_pool_put(&pool, capacity + 1, data, msgSz, 0,
        first), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectNull(test_dtls13_held_for(&pool, 1));
    ExpectNotNull(test_dtls13_held_for(&pool, capacity + 1));
    (void)wolfSSL_Atomic_Uint_SubFetch(&pool.reserved,
        (WC_ATOMIC_UINT_ARG)TEST_DTLS_RX_UNVERIFIED_LIMIT);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    DtlsChPoolClear(&pool, NULL);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), 0);
    DtlsChPoolFree(&pool, NULL);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Eviction learns the storing peer's own entry when the lock-free scan lands
 * on it as the oldest: the entry behind it in its shard goes then, before
 * an older head elsewhere, and the shard is judged by its second published
 * value from then on. With nothing elsewhere, the entry behind the peer's
 * goes too. */
int test_dtls13_ch_pool_evict_own_shard(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte* data = NULL;
    size_t overhead = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket);
    word32 half = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT / 2 - overhead);
    DtlsMsg* m = NULL;
    int p = 1;
    int r;
#if WOLFSSL_DTLS_CH_POOL_SHARDS > 1
    const word32 msgSz = 1024;
    const word32 first = 16;
    size_t entry = overhead + first;
    int capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT / entry);
    word32 left = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT -
        (size_t)capacity * entry);
    int q;
    int id;
    int i;
#endif

    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectNotNull(data = (byte*)XMALLOC(TEST_DTLS_RX_UNVERIFIED_LIMIT, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_FAIL()) {
        DtlsChPoolFree(&pool, NULL);
        return EXPECT_RESULT();
    }
    XMEMSET(data, 0x5a, TEST_DTLS_RX_UNVERIFIED_LIMIT);
    r = test_dtls13_id_in(p + 1, test_dtls13_shard_of(p), 1);

#if WOLFSSL_DTLS_CH_POOL_SHARDS > 1
    /* p oldest, q the oldest elsewhere, r next behind p, then full */
    ExpectIntGT(capacity, 3);
    q = test_dtls13_id_in(r + 1, test_dtls13_shard_of(p), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, q, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, r, data, msgSz, 0, first), 0);
    for (i = 3, id = q + 1; i < capacity && EXPECT_SUCCESS(); i++, id++)
        ExpectIntEQ(test_dtls13_pool_put(&pool, id, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* p grows past what is left: the scan lands on p, so r goes, not the
     * older q */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, msgSz, first, left + 1),
        0);
    ExpectNull(test_dtls13_held_for(&pool, r));
    ExpectNotNull(test_dtls13_held_for(&pool, q));
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1,
        (int)(first + left + 1));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolClear(&pool, NULL);
#endif

    /* Two entries of half the budget, p ahead of r in one shard: p's growth
     * evicts r, the entry behind its own */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, half + 2, 0, half), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, r, data, half + 2, 0, half), 0);
    ExpectTrue(test_dtls13_pool_bytes(&pool) == TEST_DTLS_RX_UNVERIFIED_LIMIT);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, half + 2, half, 1), 0);
    ExpectNull(test_dtls13_held_for(&pool, r));
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1, (int)half + 1);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    DtlsChPoolFree(&pool, NULL);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* The entry behind the storing peer's own goes when the scan lands on the
 * peer's entry as the oldest of the pool, and the shard competes with its
 * second published value after that. The published values follow the head
 * as it leaves. */
int test_dtls13_ch_pool_evict_behind_own(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte* data = NULL;
    const word32 msgSz = 1024;
    const word32 first = 16;
    size_t entry = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket) +
        first;
    int capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT / entry);
    word32 left = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT -
        (size_t)capacity * entry);
    const DtlsChPoolShard* sh;
    DtlsMsg* m = NULL;
    word32 progress = 0;
    int p = 1;
    int q, r;
    int id;
    int i;

    ExpectIntGT(capacity, 3);
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectNotNull(data = (byte*)XMALLOC(TEST_DTLS_RX_UNVERIFIED_LIMIT, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_FAIL()) {
        DtlsChPoolFree(&pool, NULL);
        return EXPECT_RESULT();
    }
    XMEMSET(data, 0x5a, TEST_DTLS_RX_UNVERIFIED_LIMIT);
    sh = &pool.shard[test_dtls13_shard_of(p)];
    r = test_dtls13_id_in(p + 1, test_dtls13_shard_of(p), 1);
    q = test_dtls13_id_in(r + 1, test_dtls13_shard_of(p), 0);

    /* p heads its shard with r behind it: both are published */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, msgSz, 0, first), 0);
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectTrue(m != NULL && test_dtls13_head_progress(sh) == m->progress);
    ExpectTrue(test_dtls13_next_progress(sh) == 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, r, data, msgSz, 0, first), 0);
    ExpectNotNull(m = test_dtls13_held_for(&pool, r));
    ExpectTrue(m != NULL && test_dtls13_next_progress(sh) == m->progress);
    /* q and the rest are younger, in any shard, until full */
    ExpectIntEQ(test_dtls13_pool_put(&pool, q, data, msgSz, 0, first), 0);
    for (i = 3, id = q + 1; i < capacity && EXPECT_SUCCESS(); i++, id++)
        ExpectIntEQ(test_dtls13_pool_put(&pool, id, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity);
    ExpectPtrEq(test_dtls13_pool_next(&pool, test_dtls13_held_for(&pool, p)),
        test_dtls13_held_for(&pool, r));
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* p grows past what is left: r goes, the oldest but p, not q */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, msgSz, first, left + 1),
        0);
    ExpectNull(test_dtls13_held_for(&pool, r));
    ExpectNotNull(test_dtls13_held_for(&pool, q));
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1,
        (int)(first + left + 1));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolClear(&pool, NULL);

    /* The head leaves, to the young end on new bytes and then dropped: the
     * published values follow */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, r, data, msgSz, 0, first), 0);
    ExpectNotNull(m = test_dtls13_held_for(&pool, r));
    progress = m != NULL ? m->progress : 0;
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, msgSz, first, 1), 0);
    ExpectTrue(test_dtls13_head_progress(sh) == progress);
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectTrue(m != NULL && test_dtls13_next_progress(sh) == m->progress);
    if (EXPECT_SUCCESS()) {
        WOLFSSL_SOCKADDR peer;

        peer.sz = sizeof(r);
        peer.bufSz = sizeof(r);
        peer.sa = &r;
        DtlsChPoolDrop(&pool, NULL, &peer, DTLS_TIMEOUT_MAX);
    }
    ExpectTrue(m != NULL && test_dtls13_head_progress(sh) == m->progress);
    ExpectTrue(test_dtls13_next_progress(sh) == 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    DtlsChPoolFree(&pool, NULL);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* A store of an entry already held reserves the bound of its fragment, a
 * new entry holding it, and settles to what the fragment added: nothing for
 * a duplicate, its new bytes for a merge, a bucket more for a gap. */
int test_dtls13_ch_pool_reserve_bound(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte data[64];
    size_t overhead = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket);
    int p = 1;

    XMEMSET(data, 0x5a, sizeof(data));
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, 64, 0, 8), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), overhead + 8);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, 64, 0, 8), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), overhead + 8);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, 64, 4, 8), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), overhead + 12);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, 64, 20, 4), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool),
        overhead + sizeof(DtlsFragBucket) + 16);
    /* Closing the gap gives the bucket back */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, 64, 12, 8), 0);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), overhead + 24);
    ExpectTrue(test_dtls13_pool_reserved(&pool) ==
        test_dtls13_pool_bytes(&pool));
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolFree(&pool, NULL);
#endif
    return EXPECT_RESULT();
}

/* At capacity a retransmitted fragment evicts another peer's oldest entry
 * for its bound, though it adds nothing: the bound is reserved before the
 * entry is looked at. With the room there, it evicts nothing. */
int test_dtls13_ch_pool_evict_for_bound(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte* data = NULL;
    const word32 msgSz = 512;
    const word32 first = 16;
    size_t entry = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket) +
        first;
    int capacity = (int)(TEST_DTLS_RX_UNVERIFIED_LIMIT / entry);
    DtlsMsg* m = NULL;
    int i;

    ExpectIntGT(capacity, 2);
    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectNotNull(data = (byte*)XMALLOC(msgSz, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_FAIL()) {
        DtlsChPoolFree(&pool, NULL);
        return EXPECT_RESULT();
    }
    XMEMSET(data, 0x5a, msgSz);
    for (i = 1; i <= capacity && EXPECT_SUCCESS(); i++)
        ExpectIntEQ(test_dtls13_pool_put(&pool, i, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* The newest peer's first fragment again: peer 1 goes for its bound */
    ExpectIntEQ(test_dtls13_pool_put(&pool, capacity, data, msgSz, 0, first),
        0);
    ExpectNull(test_dtls13_held_for(&pool, 1));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectTrue(test_dtls13_pool_bytes(&pool) ==
        (size_t)(capacity - 1) * entry);
    ExpectNotNull(m = test_dtls13_held_for(&pool, capacity));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1, (int)first);
    ExpectPtrEq(test_dtls13_pool_head(&pool), test_dtls13_held_for(&pool, 2));
    ExpectTrue(test_dtls13_pool_ok(&pool));
    /* Again, in the room that made: nothing goes */
    ExpectIntEQ(test_dtls13_pool_put(&pool, capacity, data, msgSz, 0, first),
        0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity - 1);
    ExpectPtrEq(test_dtls13_pool_head(&pool), test_dtls13_held_for(&pool, 2));
    ExpectTrue(test_dtls13_pool_ok(&pool));

    DtlsChPoolFree(&pool, NULL);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* When the storing peer's own entry is the oldest of the pool, eviction
 * learns of it under the lock and goes on: the entry behind it in its shard
 * goes, with none the oldest head of another shard, and with nothing but
 * the peer's entry anywhere the store is dropped and the entry stays. */
int test_dtls13_ch_pool_evict_own_oldest(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte* data = NULL;
    size_t overhead = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket);
    word32 third = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT / 3 - overhead);
    word32 bigSz = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT - 2 * overhead);
    DtlsMsg* m = NULL;
    int p = 1;
    int q, r;
#if WOLFSSL_DTLS_CH_POOL_SHARDS > 1
    word32 half = (word32)(TEST_DTLS_RX_UNVERIFIED_LIMIT / 2 - overhead);
#endif

    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectNotNull(data = (byte*)XMALLOC(TEST_DTLS_RX_UNVERIFIED_LIMIT, NULL,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_FAIL()) {
        DtlsChPoolFree(&pool, NULL);
        return EXPECT_RESULT();
    }
    XMEMSET(data, 0x5a, TEST_DTLS_RX_UNVERIFIED_LIMIT);
    r = test_dtls13_id_in(p + 1, test_dtls13_shard_of(p), 1);
    q = test_dtls13_id_in(r + 1, test_dtls13_shard_of(p), 0);

    /* p, q, then r behind p in its shard, a third of the budget each: one
     * more byte for p evicts r, though q is older */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, third + 2, 0, third), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, q, data, third + 2, 0, third), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, r, data, third + 2, 0, third), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 3);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, third + 2, third, 1), 0);
    ExpectNull(test_dtls13_held_for(&pool, r));
    ExpectNotNull(test_dtls13_held_for(&pool, q));
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1, (int)third + 1);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 2);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolClear(&pool, NULL);

#if WOLFSSL_DTLS_CH_POOL_SHARDS > 1
    /* p alone in its shard, q in another, half each: q goes */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, half + 2, 0, half), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, q, data, half + 2, 0, half), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, half + 2, half, 1), 0);
    ExpectNull(test_dtls13_held_for(&pool, q));
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1, (int)half + 1);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));
    DtlsChPoolClear(&pool, NULL);
#endif

    /* Nothing but p, holding two buckets of the largest ClientHello: the
     * bound of its rest is one bucket more than the merge would leave, so
     * it is dropped and p stays */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, bigSz, 0, 1), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, bigSz, 2, 1), 0);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, bigSz, 3, bigSz - 3),
        DTLS_MSG_STORE_DROPPED);
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectIntEQ(m != NULL ? (int)m->bytesReceived : -1, 2);
    ExpectIntEQ(m != NULL ? (int)m->fragBucketListCount : -1, 2);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    DtlsChPoolFree(&pool, NULL);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* A fragment opening one gap too many is refused under the lock, after its
 * bound was reserved and, at capacity, evicted for: the reservation goes
 * back and the counter is what the shards retain. */
int test_dtls13_ch_pool_bucket_cap(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER)
    DtlsChPool pool;
    byte* data = NULL;
    const word32 msgSz = 512;
    const word32 first = 16;
    const word32 gapSz = 2 * DTLS_FRAG_POOL_SZ + first;
    size_t entry = sizeof(DtlsMsg) + sizeof(int) + sizeof(DtlsFragBucket) +
        first;
    size_t held = 0;
    int capacity = 0;
    DtlsMsg* m = NULL;
    int p = 1;
    int r;
    int id;
    int i;

    ExpectIntEQ(DtlsChPoolInit(&pool), 0);
    ExpectNotNull(data = (byte*)XMALLOC(msgSz, NULL, DYNAMIC_TYPE_TMP_BUFFER));
    if (EXPECT_FAIL()) {
        DtlsChPoolFree(&pool, NULL);
        return EXPECT_RESULT();
    }
    XMEMSET(data, 0x5a, msgSz);
    for (i = 0; i < DTLS_FRAG_POOL_SZ && EXPECT_SUCCESS(); i++)
        ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, gapSz, 2 * i, 1), 0);
    ExpectNotNull(m = test_dtls13_held_for(&pool, p));
    ExpectIntEQ(m != NULL ? (int)m->fragBucketListCount : -1,
        DTLS_FRAG_POOL_SZ);
    held = test_dtls13_pool_bytes(&pool);

    /* With room: refused, nothing changes */
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, gapSz,
        2 * DTLS_FRAG_POOL_SZ, first), DTLS_MSG_STORE_DROPPED);
    ExpectIntEQ(test_dtls13_pool_count(&pool), 1);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool), held);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    /* At capacity, r behind p in its shard and the rest anywhere: r goes
     * for the bound, then the fragment is refused */
    r = test_dtls13_id_in(p + 1, test_dtls13_shard_of(p), 1);
    capacity = (int)((TEST_DTLS_RX_UNVERIFIED_LIMIT - held) / entry);
    ExpectIntGT(capacity, 1);
    for (i = 0, id = r; i < capacity && EXPECT_SUCCESS(); i++, id++)
        ExpectIntEQ(test_dtls13_pool_put(&pool, id, data, msgSz, 0, first), 0);
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity + 1);
    ExpectIntEQ(test_dtls13_pool_put(&pool, p, data, gapSz,
        2 * DTLS_FRAG_POOL_SZ, first), DTLS_MSG_STORE_DROPPED);
    ExpectNull(test_dtls13_held_for(&pool, r));
    ExpectIntEQ(test_dtls13_pool_count(&pool), capacity);
    ExpectIntEQ(m != NULL ? (int)m->fragBucketListCount : -1,
        DTLS_FRAG_POOL_SZ);
    ExpectIntEQ(test_dtls13_pool_reserved(&pool),
        held + (size_t)(capacity - 1) * entry);
    ExpectTrue(test_dtls13_pool_ok(&pool));

    DtlsChPoolFree(&pool, NULL);
    XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(SINGLE_THREADED)
#define TEST_CH_SHARD_THREADS 4
#define TEST_CH_SHARD_OPS     4000
#define TEST_CH_SHARD_PEERS   200
#define TEST_CH_SHARD_MSG_SZ  ((TEST_DTLS_RX_UNVERIFIED_LIMIT / 8) & ~3)

static DtlsChPool test_ch_shard_pool;
static int test_ch_shard_bad[TEST_CH_SHARD_THREADS + 1];
static int test_ch_shard_out[TEST_CH_SHARD_THREADS];
static int test_ch_shard_snaps;
static int test_ch_shard_running;
static wolfSSL_Mutex test_ch_shard_mutex;
static byte test_ch_shard_data[TEST_CH_SHARD_THREADS][TEST_CH_SHARD_MSG_SZ];

/* Whether an entry of a shard after i has m's progress */
static int test_ch_shard_progress_taken(const DtlsChPool* p, int i,
                                     const DtlsMsg* m)
{
    const DtlsMsg* e;

    for (i++; i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++) {
        for (e = p->shard[i].head; e != NULL; e = e->next) {
            if (e->progress == m->progress)
                return 1;
        }
    }
    return 0;
}

/* With every shard lock held: counters match the lists in progress order, no
 * progress repeats, and the shards retain what is reserved, within the budget.
 * The library holds one shard lock at most, so taking them all cannot
 * deadlock. */
static int test_ch_shard_snapshot(DtlsChPool* p)
{
    size_t sum = 0;
    int ok = 1;
    int i;

    for (i = 0; i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++) {
        if (wc_LockMutex(&p->shard[i].lock) != 0)
            ok = 0;
    }
    for (i = 0; i < WOLFSSL_DTLS_CH_POOL_SHARDS; i++) {
        const DtlsChPoolShard* sh = &p->shard[i];
        const DtlsMsg* m;

        if (!test_dtls13_head_progress_ok(sh))
            ok = 0;
        for (m = sh->head; m != NULL; m = m->next) {
            if (m->ready || DtlsChPoolShardIdx(&m->peer) != (word32)i)
                ok = 0;
            if (m->next != NULL && m->next->progress <= m->progress)
                ok = 0;
            if (test_ch_shard_progress_taken(p, i, m))
                ok = 0;
        }
        if (sh->bytes != DtlsMsgListRetainedBytes(sh->head))
            ok = 0;
        sum += sh->bytes;
    }
    /* A store evicting holds its reservation with no shard locked */
    if (sum > test_dtls13_pool_reserved(p) ||
            sum > TEST_DTLS_RX_UNVERIFIED_LIMIT)
        ok = 0;
    for (i = WOLFSSL_DTLS_CH_POOL_SHARDS - 1; i >= 0; i--)
        wc_UnLockMutex(&p->shard[i].lock);
    return ok;
}

static THREAD_RETURN WOLFSSL_THREAD test_dtls13_ch_shard_worker(void* args)
{
    int tno = ((func_args*)args)->argc;
    word32 rnd = 0x85ebca6bU * (word32)(tno + 1);
    byte addr[2];
    byte* data = test_ch_shard_data[tno];
    WOLFSSL_SOCKADDR peer;
    int i;

    peer.sz = sizeof(addr);
    peer.bufSz = sizeof(addr);
    peer.sa = addr;
    addr[1] = 0x42;
    for (i = 0; i < TEST_CH_SHARD_OPS; i++) {
        DtlsMsg* msg = NULL;
        word32 op;
        word32 quarter;

        rnd = rnd * 1103515245U + 12345U;
        addr[0] = (byte)((rnd >> 16) % TEST_CH_SHARD_PEERS);
        op = (rnd >> 8) % 256;
        quarter = (rnd >> 24) % 4;
        XMEMSET(data, addr[0] + 1, TEST_CH_SHARD_MSG_SZ);
        if (op < 24) {
            msg = DtlsChPoolTakeRest(&test_ch_shard_pool, NULL, &peer, 0, 1, 0,
                TEST_CH_SHARD_MSG_SZ, DTLS_TIMEOUT_MAX, NULL);
        }
        else {
            (void)DtlsChPoolStore(&test_ch_shard_pool, NULL, &peer, 0, 1, data,
                TEST_CH_SHARD_MSG_SZ, client_hello,
                quarter * (TEST_CH_SHARD_MSG_SZ / 4), TEST_CH_SHARD_MSG_SZ / 4,
                DTLS_TIMEOUT_MAX, NULL, &msg);
        }
        if (msg != NULL) {
            if (!test_ch_pool_msg_ok(msg, addr[0], TEST_CH_SHARD_MSG_SZ))
                test_ch_shard_bad[tno]++;
            test_ch_shard_out[tno]++;
            DtlsMsgListDelete(msg, NULL);
        }
    }
    if (wc_LockMutex(&test_ch_shard_mutex) == 0) {
        test_ch_shard_running--;
        wc_UnLockMutex(&test_ch_shard_mutex);
    }
    WOLFSSL_RETURN_FROM_THREAD(0);
}

/* Checks the pool while the workers run, until they are done. It sleeps
 * between snapshots: a snapshot holds every shard lock, and mutexes are not
 * fair, so without the sleep the workers starve on some schedulers. */
static THREAD_RETURN WOLFSSL_THREAD test_dtls13_ch_shard_monitor(void* args)
{
    int running = 1;

    (void)args;
    while (running > 0) {
        if (!test_ch_shard_snapshot(&test_ch_shard_pool))
            test_ch_shard_bad[TEST_CH_SHARD_THREADS]++;
        test_ch_shard_snaps++;
        XSLEEP_MS(1);
        if (wc_LockMutex(&test_ch_shard_mutex) != 0)
            break;
        running = test_ch_shard_running;
        wc_UnLockMutex(&test_ch_shard_mutex);
    }
    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif

/* Threads store, complete and release ClientHellos of many peers across the
 * shards of one pool, past its budget, while one checks the budget holds. */
int test_dtls13_ch_pool_shards_threads(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS_CH_FRAG) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(SINGLE_THREADED)
    THREAD_TYPE threads[TEST_CH_SHARD_THREADS + 1];
    func_args args[TEST_CH_SHARD_THREADS + 1];
    int out = 0;
    int i;

    XMEMSET(args, 0, sizeof(args));
    XMEMSET(test_ch_shard_bad, 0, sizeof(test_ch_shard_bad));
    XMEMSET(test_ch_shard_out, 0, sizeof(test_ch_shard_out));
    test_ch_shard_snaps = 0;
    test_ch_shard_running = TEST_CH_SHARD_THREADS;
    ExpectTrue(TEST_CH_SHARD_PEERS * (sizeof(DtlsMsg) + 2 +
        sizeof(DtlsFragBucket) + TEST_CH_SHARD_MSG_SZ / 4) >
        4 * TEST_DTLS_RX_UNVERIFIED_LIMIT);
    ExpectIntEQ(wc_InitMutex(&test_ch_shard_mutex), 0);
    ExpectIntEQ(DtlsChPoolInit(&test_ch_shard_pool), 0);
    if (EXPECT_FAIL())
        return EXPECT_RESULT();
    for (i = 0; i <= TEST_CH_SHARD_THREADS; i++) {
        args[i].argc = i;
        start_thread(i < TEST_CH_SHARD_THREADS ? test_dtls13_ch_shard_worker :
            test_dtls13_ch_shard_monitor, &args[i], &threads[i]);
    }
    for (i = 0; i <= TEST_CH_SHARD_THREADS; i++)
        join_thread(threads[i]);
    for (i = 0; i < TEST_CH_SHARD_THREADS; i++) {
        ExpectIntEQ(test_ch_shard_bad[i], 0);
        out += test_ch_shard_out[i];
    }
    ExpectIntEQ(test_ch_shard_bad[TEST_CH_SHARD_THREADS], 0);
    ExpectIntGT(test_ch_shard_snaps, 0);
    ExpectIntGT(out, 0);
    ExpectTrue(test_dtls13_pool_ok(&test_ch_shard_pool));
    ExpectIntLE(test_dtls13_pool_count(&test_ch_shard_pool),
        TEST_CH_SHARD_PEERS);
    DtlsChPoolFree(&test_ch_shard_pool, NULL);
    ExpectIntEQ(wc_FreeMutex(&test_ch_shard_mutex), 0);
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

int test_dtls13_alert_with_pending_output(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    char msg[1300];

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(msg, 'A', sizeof(msg));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Stall the transport, then queue a record big enough that adding the
     * alert would exceed the MTU. */
    test_ctx.s_force_want_write = 1;
    ExpectIntLT(wolfSSL_write(ssl_s, msg, (int)sizeof(msg)), 0);
    ExpectIntGT((int)ssl_s->buffers.outputBuffer.length, 1288);

    /* EndOfEarlyData is not valid in DTLS 1.3 and raises a fatal alert. */
    ExpectIntEQ(Dtls13CheckEpoch(ssl_s, end_of_early_data), SANITY_MSG_E);

    ExpectIntLE((int)(ssl_s->buffers.outputBuffer.idx +
                      ssl_s->buffers.outputBuffer.length),
                (int)ssl_s->buffers.outputBuffer.bufferSize);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
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

#define TEST_DTLS13_KEY_UPDATE_ROUNDS DTLS13_EPOCH_SIZE

int test_dtls13_epoch_slot_reuse_replay(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    const char msg[] = "APP-DATA-REPLAY-CANARY";
    const int msgLen = (int)sizeof(msg) - 1;
    const w64wrapper retiredEpoch = w64From32(0, DTLS13_EPOCH_TRAFFIC0);
    const w64wrapper peerEpoch = w64From32(0, DTLS13_EPOCH_TRAFFIC0 + 1);
    char replay[512];
    int replayLen = (int)sizeof(replay);
    char readBuf[64];
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    for (i = 0; i < 4; i++) {
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    }
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);

    /* Capture an application-data record sent in the peer's current epoch. */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(test_memio_copy_message(&test_ctx, 0, replay, &replayLen, 0), 0);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    /* Control: while that epoch is still live, the replay window rejects it. */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, replay, replayLen), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* this avoid the client to request the server to send a keyUpdate back */
    if (ssl_c != NULL)
        ssl_c->keys.updateResponseReq = 1;
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    /* drop the ACK */
    test_memio_clear_buffer(&test_ctx, 1);
    ExpectTrue(w64Equal(ssl_s->dtls13PeerEpoch, peerEpoch));
    ExpectTrue(w64Equal(ssl_c->dtls13Epoch, retiredEpoch));
    ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 1);

    /* That still-in-flight epoch is what parks ssl->dtls13DecryptEpoch on the
     * slot Dtls13NewEpochSlot() is about to consider for eviction. */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);
    ExpectNotNull(ssl_s->dtls13DecryptEpoch);
    ExpectTrue(w64Equal(ssl_s->dtls13DecryptEpoch->epochNumber, retiredEpoch));

    /* Server key updates. PeerEpoch, PeerEpoch - 1 and Epoch must be preserved */
    for (i = 0; i < TEST_DTLS13_KEY_UPDATE_ROUNDS; i++) {
        if (ssl_s != NULL)
            ssl_s->keys.updateResponseReq = 1;
        ExpectIntEQ(wolfSSL_update_keys(ssl_s), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        /* wolfSSL_update_keys() reports success without sending while an
         * earlier KeyUpdate is unacked, so check the round actually closed. */
        ExpectIntEQ(ssl_s->dtls13WaitKeyUpdateAck, 0);
        ExpectTrue(w64Equal(ssl_s->dtls13Epoch,
            w64From32(0, DTLS13_EPOCH_TRAFFIC0 + (word32)i + 1)));
    }

    ExpectNull(Dtls13GetEpoch(ssl_s, w64From32(0, 0)));
    ExpectTrue(w64Equal(ssl_s->dtls13PeerEpoch, peerEpoch));
    ExpectTrue(w64Equal(ssl_c->dtls13Epoch, retiredEpoch));

    /* The retired epoch's record must not be delivered a second time. */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, replay, replayLen), 0);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    /* The peer is still transmitting in that epoch, so it must keep working.
     * Dropping its traffic instead of the replay is not a fix. */
    test_memio_clear_buffer(&test_ctx, 0);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_dtls13_epoch_slot_reuse_decrypt_epoch(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    const char msg[] = "APP-DATA-AFTER-SLOT-REUSE";
    const int msgLen = (int)sizeof(msg) - 1;
    const w64wrapper plaintextEpoch = w64From32(0, 0);
    const w64wrapper trafficEpoch = w64From32(0, DTLS13_EPOCH_TRAFFIC0);
    const w64wrapper ownEpoch = w64From32(0, DTLS13_EPOCH_TRAFFIC0 + 1);
    const w64wrapper peerEpoch = w64From32(0, DTLS13_EPOCH_TRAFFIC0 + 2);
    byte plaintextRec[DTLS_RECORD_HEADER_SZ];
    char readBuf[64];
    int i;

    XMEMSET(plaintextRec, 0, sizeof(plaintextRec));
    plaintextRec[0] = handshake;
    plaintextRec[1] = DTLS_MAJOR;
    plaintextRec[2] = DTLSv1_2_MINOR;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    for (i = 0; i < 4; i++) {
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    }
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);

    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);
    ExpectNotNull(ssl_s->dtls13DecryptEpoch);
    ExpectTrue(w64Equal(ssl_s->dtls13DecryptEpoch->epochNumber, trafficEpoch));

    if (ssl_s != NULL)
        ssl_s->keys.updateResponseReq = 1;
    ExpectIntEQ(wolfSSL_update_keys(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(ssl_s->dtls13WaitKeyUpdateAck, 0);
    ExpectTrue(w64Equal(ssl_s->dtls13Epoch, ownEpoch));

    for (i = 0; i < 2; i++) {
        if (ssl_c != NULL)
            ssl_c->keys.updateResponseReq = 1;
        ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 0);
    }
    ExpectTrue(w64Equal(ssl_s->dtls13Epoch, ownEpoch));
    ExpectTrue(w64Equal(ssl_s->dtls13PeerEpoch, peerEpoch));
    ExpectTrue(w64Equal(ssl_c->dtls13Epoch, peerEpoch));
    ExpectNotNull(Dtls13GetEpoch(ssl_s, trafficEpoch));

    if (ssl_s != NULL)
        ssl_s->dtls13DecryptEpoch = Dtls13GetEpoch(ssl_s, trafficEpoch);
    ExpectNotNull(ssl_s->dtls13DecryptEpoch);

    for (i = 0; ssl_s != NULL && i < 2 * DTLS13_EPOCH_SIZE &&
            Dtls13GetEpoch(ssl_s, trafficEpoch) != NULL; i++) {
        ExpectIntEQ(Dtls13NewEpoch(ssl_s,
            w64From32(0, DTLS13_EPOCH_TRAFFIC0 + 4 + (word32)i),
            ENCRYPT_SIDE_ONLY), 0);
    }
    ExpectNull(Dtls13GetEpoch(ssl_s, trafficEpoch));
    ExpectNull(Dtls13GetEpoch(ssl_s, plaintextEpoch));
    ExpectNull(ssl_s->dtls13DecryptEpoch);

    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
        (const char*)plaintextRec, (int)sizeof(plaintextRec)), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNull(ssl_s->dtls13DecryptEpoch);

    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);
    ExpectNotNull(ssl_s->dtls13DecryptEpoch);
    ExpectTrue(w64Equal(ssl_s->dtls13DecryptEpoch->epochNumber, peerEpoch));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

int test_dtls13_plaintext_ack_after_handshake(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    const char msg[] = "APP-DATA-AFTER-PLAINTEXT-ACK";
    const int msgLen = (int)sizeof(msg) - 1;
    const w64wrapper plaintextEpoch = w64From32(0, 0);
    const w64wrapper trafficEpoch = w64From32(0, DTLS13_EPOCH_TRAFFIC0);
    /* ahead of the receiving window of every epoch of this connection */
    const word32 ackSeq = 1000;
    /* DTLSPlaintext record holding an ACK with an empty record_numbers list */
    byte plaintextAck[DTLS_RECORD_HEADER_SZ + OPAQUE16_LEN];
    char readBuf[64];
    int i;

    XMEMSET(plaintextAck, 0, sizeof(plaintextAck));
    plaintextAck[0] = ack;
    plaintextAck[1] = DTLS_MAJOR;
    plaintextAck[2] = DTLSv1_2_MINOR;
    /* epoch (2 bytes) is 0, sequence number is the low 32 bits of the 48 bit
     * field that follows it */
    c32toa(ackSeq, plaintextAck + ENUM_LEN + VERSION_SZ + OPAQUE16_LEN +
        OPAQUE16_LEN);
    c16toa(OPAQUE16_LEN, plaintextAck + DTLS_RECORD_HEADER_SZ - LENGTH_SZ);

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    for (i = 0; i < 4; i++) {
        ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
        ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    }
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);

    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);
    ExpectNotNull(ssl_s->dtls13DecryptEpoch);
    ExpectTrue(w64Equal(ssl_s->dtls13DecryptEpoch->epochNumber, trafficEpoch));

    /* The epoch 0 slot is still around at this point, so setting it as the
     * decrypting epoch would succeed. An unprotected record received after the
     * handshake must be dropped before that: no record of epoch 0 can be
     * accepted anymore, and epoch 0 may well have been recycled already. */
    ExpectNotNull(Dtls13GetEpoch(ssl_s, plaintextEpoch));
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0,
        (const char*)plaintextAck, (int)sizeof(plaintextAck)), 0);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(ssl_s->dtls13DecryptEpoch);
    ExpectTrue(w64Equal(ssl_s->dtls13DecryptEpoch->epochNumber, trafficEpoch));

    /* the connection must keep working */
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A plaintext ACK during the encrypted handshake must not release the server
 * flight, nor be fatal if malformed. */
int test_dtls13_plaintext_ack_during_handshake(void)
{
    EXPECT_DECLS;
/* Without a clock (NO_ASN_TIME) retransmissions are not rate limited, so the
 * server flight is resent at points this sequence does not expect. */
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    !defined(NO_ASN_TIME)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    /* ACK, epoch 0, seq 1001, record_numbers length past the end */
    static const byte badAckRec[] = {
        0x1a, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe9,
        0x00, 0x02,
        0x00, 0x10
    };
    /* ACK, epoch 0, seq 1000, with 12 record numbers filled in below */
    byte ackRec[DTLS_RECORD_HEADER_SZ + OPAQUE16_LEN + 12 * DTLS13_RN_SIZE] = {
        0x1a, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8,
        0x00, 0xc2,
        0x00, 0xc0
    };
    byte* rn = ackRec + DTLS_RECORD_HEADER_SZ + OPAQUE16_LEN;
    w64wrapper epoch, seq;
    int i;

    /* epoch 0 seq 0..3, then epoch 2 seq 0..7 */
    for (i = 0; i < 12; i++, rn += DTLS13_RN_SIZE) {
        epoch = w64From32(0, i < 4 ? 0 : DTLS13_EPOCH_HANDSHAKE);
        seq = w64From32(0, (word32)(i < 4 ? i : i - 4));
        c64toa(&epoch, rn);
        c64toa(&seq, rn + OPAQUE64_LEN);
    }

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
    /* SH ... FINISHED, lost */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    test_memio_clear_buffer(&test_ctx, 1);
    ExpectIntEQ(wolfSSL_dtls13_has_pending_msg(ssl_s), 1);

    /* the server flight must stay in the retransmission buffer */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)ackRec,
        (int)sizeof(ackRec)), 0);
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_dtls13_has_pending_msg(ssl_s), 1);

    /* a malformed ACK must be dropped */
    ExpectIntEQ(test_memio_inject_message(&test_ctx, 0, (const char*)badAckRec,
        (int)sizeof(badAckRec)), 0);
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_dtls13_has_pending_msg(ssl_s), 1);

    /* the server retransmits its flight and the handshake completes */
    if (wolfSSL_dtls13_use_quick_timeout(ssl_s))
        ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_dtls_got_timeout(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntGT(test_ctx.c_msg_count, 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* DtlsResetState() runs whenever a DTLS server abandons a ClientHello on the
 * stateless path - which includes the ordinary cookie exchange, since the
 * object goes back to awaiting the verified ClientHello after sending the
 * HelloRetryRequest.
 *
 * It must not leave an alert behind in the history. DoClientHello() can send a
 * fatal alert there and then swallow the error (DtlsIgnoreError) so the
 * listener stays up; a stale alert_fatal makes the "already sent a more
 * specific fatal alert" guards suppress every later alert from that object, so
 * one bad ClientHello would mute alerts for every peer that follows. The reset
 * value has to be the -1 "no alert" sentinel InitSSL() uses, not zero, which
 * would read back as a close_notify that was never sent.
 *
 * The alert is planted directly rather than provoked: the error paths that
 * reach it need a malformed ClientHello that survives record and extension
 * parsing far enough to fail in the cookie check, and what this guards is the
 * reset itself. */
int test_dtls13_reset_clears_alert_history(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* Client sends ClientHello 1. */
    ExpectIntEQ(wolfSSL_negotiate(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    if (EXPECT_SUCCESS() && ssl_s != NULL) {
        /* Stand in for an alert sent while rejecting an earlier ClientHello. */
        ssl_s->alert_history.last_tx.code  = decode_error;
        ssl_s->alert_history.last_tx.level = alert_fatal;
    }

    /* Server answers statelessly and resets to await the verified
     * ClientHello, taking DtlsResetState() with it. */
    ExpectIntEQ(wolfSSL_negotiate(ssl_s), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);

    if (EXPECT_SUCCESS() && ssl_s != NULL) {
        /* Back to "nothing sent", so the guards do not mute the next alert,
         * and wolfSSL_get_alert_history() does not report a phantom
         * close_notify (code 0) or alert_none (level 0). */
        ExpectIntEQ(ssl_s->alert_history.last_tx.level, -1);
        ExpectIntEQ(ssl_s->alert_history.last_tx.code, -1);
    }

    /* The exchange still completes normally afterwards. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
/* Reports a receive timeout for the first *ctx calls, then no data. A
 * scheduled ACK takes one timeout of its own before the retransmit runs. */
static int test_dtls13_rtx_timeout_read_cb(WOLFSSL *ssl, char *data, int sz,
        void *ctx)
{
    int* timeouts = (int*)ctx;
    (void)ssl;
    (void)data;
    (void)sz;
    if (*timeouts > 0) {
        (*timeouts)--;
        return WOLFSSL_CBIO_ERR_TIMEOUT;
    }
    return WOLFSSL_CBIO_ERR_WANT_READ;
}
#endif

/* A receive timeout makes DTLS 1.3 send an ACK or retransmit. When the
 * transport cannot take it, the handshake reports want-write and the retry
 * completes the send. */
int test_dtls13_rtx_timeout_want_write(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL *ssl_c = NULL;
    struct test_memio_ctx test_ctx;
    int timeouts = 1;
    int sentBefore;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_c, NULL,
        wolfDTLSv1_3_client_method, NULL), 0);

    /* Send the ClientHello flight and wait on the server. */
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    sentBefore = test_ctx.s_len;

    /* The next receive reports a timeout while the transport refuses
     * writes. */
    wolfSSL_SetIOReadCtx(ssl_c, &timeouts);
    wolfSSL_SSLSetIORecv(ssl_c, test_dtls13_rtx_timeout_read_cb);
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_WRITE);
    ExpectIntEQ(test_ctx.s_len, sentBefore);

    /* With writes allowed again the retransmission reaches the peer. */
    test_memio_simulate_want_write(&test_ctx, 1, 0);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntGT(test_ctx.s_len, sentBefore);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}

/* The same timeout on the read path. wolfSSL_read() reports want-write and
 * marks the record it held, which wolfSSL_dtls13_do_scheduled_work() sends. */
int test_dtls13_rtx_timeout_want_write_read(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    const char msg[] = "read-path";
    const int msgLen = sizeof(msg);
    char readBuf[sizeof(msg)];
    int timeouts = 2;
    int sentBefore;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Leave a KeyUpdate buffered so a timeout has something to retransmit. */
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
    sentBefore = test_ctx.s_len;

    /* The next receive reports a timeout while the transport refuses
     * writes. */
    wolfSSL_SetIOReadCtx(ssl_c, &timeouts);
    wolfSSL_SSLSetIORecv(ssl_c, test_dtls13_rtx_timeout_read_cb);
    test_memio_simulate_want_write(&test_ctx, 1, 1);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_WRITE);
    ExpectIntEQ(test_ctx.s_len, sentBefore);

    /* Reading again reports no data rather than an error, and the record the
     * timeout could not write is still owed. */
    test_memio_simulate_want_write(&test_ctx, 1, 0);
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_dtls13_pending_work(ssl_c), 1);

    /* The pump sends it. */
    ExpectIntEQ(wolfSSL_dtls13_do_scheduled_work(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntGT(test_ctx.s_len, sentBefore);
    ExpectIntEQ(wolfSSL_dtls13_pending_work(ssl_c), 0);

    /* The connection still carries application data. */
    wolfSSL_SSLSetIORecv(ssl_c, test_memio_read_cb);
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    XMEMSET(readBuf, 0, sizeof(readBuf));
    ExpectIntEQ(wolfSSL_read(ssl_c, readBuf, sizeof(readBuf)), msgLen);
    ExpectStrEQ(readBuf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* RFC 9147 Section 4: a DTLS 1.3 receiver MUST ignore legacy_record_version
 * "for all purposes".  Garble those two bytes in the first unencrypted record
 * of the server's first flight (the HelloRetryRequest produced by the DTLS 1.3
 * stateless cookie exchange; the record header is not covered by the transcript
 * hash) and the handshake must still complete.  For DTLS 1.2 the record layer
 * version is still meaningful, so the same tampering must be rejected. */
int test_dtls13_ignore_legacy_record_version(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DTLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    struct test_memio_ctx test_ctx;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);

    /* Run the ClientHello, then the server's first flight. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* Bytes 1 and 2 of the record header are legacy_record_version. */
    ExpectIntGT(test_ctx.c_len, DTLS_RECORD_HEADER_SZ);
    if (EXPECT_SUCCESS()) {
        test_ctx.c_buff[1] = 0xEE;
        test_ctx.c_buff[2] = 0xEE;
    }

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    wolfSSL_CTX_free(ctx_c);
    ctx_c = NULL;
    wolfSSL_CTX_free(ctx_s);
    ctx_s = NULL;

#ifndef WOLFSSL_NO_TLS12
    /* Same tampering under TLS 1.2 must still be caught. */
    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method), 0);

    /* The record layer version of ClientHello, HelloVerifyRequest and
     * ServerHello is deliberately not checked: the version is not negotiated
     * yet when they are exchanged. Run the cookie exchange first, then tamper
     * with the record that follows the ServerHello. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS); /* ClientHello */
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS); /* HelloVerifyRequest */
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS); /* ClientHello+cookie */
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);
    ExpectIntNE(wolfSSL_accept(ssl_s), WOLFSSL_SUCCESS); /* server flight */
    ExpectIntEQ(wolfSSL_get_error(ssl_s, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WOLFSSL_ERROR_WANT_READ);

    /* Skip over the ServerHello record and garble the next record's version. */
    ExpectIntGT(test_ctx.c_len, DTLS_RECORD_HEADER_SZ);
    ExpectIntEQ(test_ctx.c_buff[0], handshake);
    ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ], server_hello);
    if (EXPECT_SUCCESS()) {
        int idx = DTLS_RECORD_HEADER_SZ +
            ((int)test_ctx.c_buff[DTLS_RECORD_HEADER_SZ - 2] << 8) +
            (int)test_ctx.c_buff[DTLS_RECORD_HEADER_SZ - 1];

        ExpectIntGT(test_ctx.c_len, idx + DTLS_RECORD_HEADER_SZ);
        ExpectIntEQ(test_ctx.c_buff[idx], handshake);
        if (EXPECT_SUCCESS()) {
            test_ctx.c_buff[idx + 1] = 0xEE;
            test_ctx.c_buff[idx + 2] = 0xEE;
        }
    }

    /* GetDtlsHandShakeHeader() detects the version mismatch (VERSION_ERROR),
     * but DoDtlsHandShakeMsg() reports any header parsing failure to the
     * caller as PARSE_ERROR. */
    ExpectIntNE(wolfSSL_connect(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR)),
        WC_NO_ERR_TRACE(PARSE_ERROR));

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
#endif
    return EXPECT_RESULT();
}

/* A NewSessionTicket ignored after ECH was not accepted consumes only the
 * message, not the record padding. */
int test_dtls13_ech_rejected_ticket_consumed(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13) && \
    defined(HAVE_ECH) && defined(HAVE_SESSION_TICKET)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    byte configs[512];
    word32 configsLen = (word32)sizeof(configs);
    /* DTLS handshake header followed by an (ignored) ticket body */
    byte msg[DTLS_HANDSHAKE_HEADER_SZ + 16];
    const word32 bodySz = (word32)sizeof(msg) - DTLS_HANDSHAKE_HEADER_SZ;
    word32 idx = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* ECH configured on the client but not accepted by the server */
    ExpectIntEQ(wolfSSL_CTX_GenerateEchConfig(ctx_s, "ech-public-name.com",
        0, 0, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_GetEchConfigs(ctx_s, configs, &configsLen),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SetEchConfigs(ssl_c, configs, configsLen),
        WOLFSSL_SUCCESS);

    XMEMSET(msg, 0, sizeof(msg));
    msg[0] = session_ticket;
    if (ssl_c != NULL) {
        ExpectIntEQ(ssl_c->options.disableECH, 0);
        ExpectIntEQ(ssl_c->options.echAccepted, 0);

        c32to24(bodySz, msg + OPAQUE8_LEN);
        c16toa(ssl_c->keys.dtls_expected_peer_handshake_number,
            msg + OPAQUE8_LEN + OPAQUE24_LEN);
        c32to24(bodySz, msg + DTLS_HANDSHAKE_HEADER_SZ - OPAQUE24_LEN);

        /* as if received in an application traffic record carrying the
         * content type byte and a 16 byte tag */
        ssl_c->curRL.pvMajor = ssl_c->version.major;
        ssl_c->curRL.pvMinor = DTLSv1_2_MINOR;
        ssl_c->keys.curEpoch64 = w64From32(0, DTLS13_EPOCH_TRAFFIC0);
        ssl_c->keys.padSz = 1 + 16;
    }

    if (EXPECT_SUCCESS()) {
        ExpectIntEQ(Dtls13HandshakeRecv(ssl_c, msg, &idx,
            (word32)sizeof(msg)), 0);
        /* only the message is consumed, not the record padding */
        ExpectIntEQ(idx, (word32)sizeof(msg));
    }

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* A KeyUpdate the transport refused is still in flight. */
int test_dtls13_update_keys_want_write(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS13)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    const char msg[] = "after the KeyUpdate";
    const int msgLen = (int)sizeof(msg) - 1;
    char buf[32];
    int required = -1;
    int msgCount;
    int i;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method), 0);
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    for (i = 0; i < 4; i++) {
        ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
        TEST_DTLS13_PUMP(ssl_c);
        ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), -1);
        TEST_DTLS13_PUMP(ssl_s);
    }
    ExpectIntEQ(test_ctx.c_len, 0);
    ExpectIntEQ(test_ctx.s_len, 0);
    ExpectIntEQ(wolfSSL_dtls13_has_pending_msg(ssl_c), 0);
    msgCount = test_ctx.s_msg_count;

    test_memio_simulate_want_write(&test_ctx, 1, 1);
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_ERROR_WANT_WRITE);
    ExpectIntEQ(test_ctx.s_msg_count, msgCount);
    ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 1);
    ExpectIntEQ(wolfSSL_dtls13_has_pending_msg(ssl_c), 1);
    ExpectIntEQ(wolfSSL_key_update_response(ssl_c, &required), 0);
    ExpectIntEQ(required, 1);
    ExpectIntEQ(wolfSSL_update_keys(ssl_c), WOLFSSL_SUCCESS);
    ExpectIntEQ(test_ctx.s_msg_count, msgCount);

    test_memio_simulate_want_write(&test_ctx, 1, 0);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    ExpectIntEQ(test_ctx.s_msg_count, msgCount + 2);
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), msgLen);
    ExpectStrEQ(buf, msg);
    TEST_DTLS13_PUMP(ssl_s);

    for (i = 0; i < 2; i++) {
        ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), -1);
        TEST_DTLS13_PUMP(ssl_c);
        ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), -1);
        TEST_DTLS13_PUMP(ssl_s);
    }
    ExpectIntEQ(ssl_c->dtls13WaitKeyUpdateAck, 0);
    ExpectIntEQ(wolfSSL_dtls13_has_pending_msg(ssl_c), 0);
    ExpectIntEQ(wolfSSL_key_update_response(ssl_c, &required), 0);
    ExpectIntEQ(required, 0);

    ExpectIntEQ(wolfSSL_write(ssl_s, msg, msgLen), msgLen);
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(wolfSSL_read(ssl_c, buf, sizeof(buf)), msgLen);
    ExpectStrEQ(buf, msg);
    ExpectIntEQ(wolfSSL_write(ssl_c, msg, msgLen), msgLen);
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(wolfSSL_read(ssl_s, buf, sizeof(buf)), msgLen);
    ExpectStrEQ(buf, msg);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
