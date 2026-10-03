/* test_ossl_sk.c
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
#include <wolfssl/openssl/lhash.h>
#include <wolfssl/openssl/ssl.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_sk.h>


int test_wolfSSL_sk_new_free_node(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_STACK* node = NULL;

    wolfSSL_sk_free_node(NULL);

    ExpectNotNull(node = wolfSSL_sk_new_node(HEAP_HINT));
    wolfSSL_sk_free_node(node);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_push_get_node(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_STACK* stack = NULL;
    WOLFSSL_STACK* node1 = NULL;
    WOLFSSL_STACK* node2 = NULL;
    WOLFSSL_STACK* node = NULL;

    ExpectNotNull(node1 = wolfSSL_sk_new_node(HEAP_HINT));
    ExpectNotNull(node2 = wolfSSL_sk_new_node(HEAP_HINT));

    ExpectNull(wolfSSL_sk_get_node(NULL, -1));
    ExpectNull(wolfSSL_sk_get_node(stack, -1));

    ExpectIntEQ(wolfSSL_sk_push_node(NULL, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_sk_push_node(&stack, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_sk_push_node(NULL, node1), WOLFSSL_FAILURE);

    ExpectIntEQ(wolfSSL_sk_push_node(&stack, node1), WOLFSSL_SUCCESS);
    ExpectPtrEq(stack, node1);
    ExpectIntEQ(wolfSSL_sk_push_node(&stack, node2), WOLFSSL_SUCCESS);
    ExpectPtrEq(stack, node2);

    ExpectNull(wolfSSL_sk_get_node(stack, -1));
    ExpectNull(wolfSSL_sk_get_node(stack, 2));

    ExpectNotNull(node = wolfSSL_sk_get_node(stack, 1));
    ExpectPtrEq(node, node1);
    ExpectNotNull(node = wolfSSL_sk_get_node(stack, 0));
    ExpectPtrEq(node, node2);

    wolfSSL_sk_free_node(node2);
    wolfSSL_sk_free_node(node1);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_free(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_STACK* stack = NULL;

    wolfSSL_sk_free(NULL);

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_push_pop(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && \
    !defined(NO_CERTS)
    WOLFSSL_STACK* stack = NULL;
    unsigned char data_1[1] = { 1 };
    unsigned char data_2[1] = { 2 };
    unsigned char data_3[1] = { 3 };

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    /* First node created and now have something to put data onto. */

    ExpectIntEQ(wolfSSL_sk_push(NULL , NULL  ), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_sk_push(NULL , data_1), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_sk_push(stack, NULL  ), WOLFSSL_FAILURE);

    ExpectNull(wolfSSL_sk_pop(NULL));

    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_2), 2);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_3), 3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_3), 1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_2), 2);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);

    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_insert(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && \
    !defined(NO_CERTS)
    WOLFSSL_STACK* stack = NULL;
    unsigned char data_1[1] = { 1 };
    unsigned char data_2[1] = { 2 };
    unsigned char data_3[1] = { 3 };

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    /* First node created and now have something to put data onto. */

    ExpectIntEQ(wolfSSL_sk_insert(NULL , NULL  , 0), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_sk_insert(NULL , data_1, 0), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_sk_insert(stack, NULL  , 0), WOLFSSL_FAILURE);

    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, 0), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, 0), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    /* Zero or negative creates a node at the bottom of the stack. */
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, -2), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, -2), 2);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_3, -2), 3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, 0), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, 1), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, 1), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, 0), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, 1), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, 1), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, 2), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, 1), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, 1), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, 2), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);

    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_shallow_sk_dup(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_STACK* stack = NULL;
    WOLFSSL_STACK* stack_dup = NULL;
    unsigned char data_1[1] = { 1 };
    unsigned char data_2[1] = { 2 };
    unsigned char data_3[1] = { 3 };

    ExpectNull(wolfSSL_shallow_sk_dup(NULL));

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    /* First node created and now have something to put data onto. */

    ExpectIntEQ(wolfSSL_sk_insert(stack, data_1, 0), 1);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_2, 0), 2);
    ExpectIntEQ(wolfSSL_sk_insert(stack, data_3, 0), 3);
    ExpectNotNull(stack_dup = wolfSSL_shallow_sk_dup(stack));
    ExpectPtrEq(wolfSSL_sk_pop(stack_dup), data_1);
    ExpectPtrEq(wolfSSL_sk_pop(stack_dup), data_2);
    ExpectPtrEq(wolfSSL_sk_pop(stack_dup), data_3);

    wolfSSL_sk_free(stack_dup);
    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_num(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_STACK* stack = NULL;
    unsigned char data_1[1] = { 1 };
    unsigned char data_2[1] = { 2 };
    unsigned char data_3[1] = { 3 };

    ExpectIntEQ(wolfSSL_sk_num(NULL), 0);

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    /* First node created and now have something to put data onto. */

    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 1);
    ExpectIntEQ(wolfSSL_sk_num(stack), 1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_2), 2);
    ExpectIntEQ(wolfSSL_sk_num(stack), 2);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_3), 3);
    ExpectIntEQ(wolfSSL_sk_num(stack), 3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_3);
    ExpectIntEQ(wolfSSL_sk_num(stack), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectIntEQ(wolfSSL_sk_num(stack), 1);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_num(stack), 0);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_3), 1);
    ExpectIntEQ(wolfSSL_sk_num(stack), 1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_2), 2);
    ExpectIntEQ(wolfSSL_sk_num(stack), 2);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 3);
    ExpectIntEQ(wolfSSL_sk_num(stack), 3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_num(stack), 2);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 3);
    ExpectIntEQ(wolfSSL_sk_num(stack), 3);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_1);
    ExpectIntEQ(wolfSSL_sk_num(stack), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectIntEQ(wolfSSL_sk_num(stack), 1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_2), 2);
    ExpectIntEQ(wolfSSL_sk_num(stack), 2);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_2);
    ExpectIntEQ(wolfSSL_sk_num(stack), 1);
    ExpectPtrEq(wolfSSL_sk_pop(stack), data_3);
    ExpectIntEQ(wolfSSL_sk_num(stack), 0);

    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_value(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_STACK* stack = NULL;
    unsigned char data_1[1] = { 1 };
    unsigned char data_2[1] = { 2 };
    unsigned char data_3[1] = { 3 };

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    /* First node created and now have something to put data onto. */

    ExpectNull(wolfSSL_sk_value(NULL, -1));
    ExpectNull(wolfSSL_sk_value(NULL, 1));
    ExpectNull(wolfSSL_sk_value(stack, -1));
    ExpectNull(wolfSSL_sk_value(stack, 0));

    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 1);
    ExpectNull(wolfSSL_sk_value(stack, 1));
    ExpectPtrEq(wolfSSL_sk_value(stack, 0), data_1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_2), 2);
    ExpectNull(wolfSSL_sk_value(stack, 2));
    ExpectPtrEq(wolfSSL_sk_value(stack, 1), data_2);
    ExpectPtrEq(wolfSSL_sk_value(stack, 0), data_1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_3), 3);
    ExpectNull(wolfSSL_sk_value(stack, 3));
    ExpectPtrEq(wolfSSL_sk_value(stack, 2), data_3);
    ExpectPtrEq(wolfSSL_sk_value(stack, 1), data_2);
    ExpectPtrEq(wolfSSL_sk_value(stack, 0), data_1);

    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
static void test_sk_xfree(void* data)
{
    XFREE(data, NULL, DYNAMIC_TYPE_OPENSSL);
}
#endif

int test_wolfssl_sk_GENERIC(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_STACK* stack = NULL;
    unsigned char data_1[1] = { 1 };
    unsigned char data_2[1] = { 2 };
    unsigned char data_3[1] = { 3 };
    char* str_1 = NULL;

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));

    ExpectIntEQ(wolfSSL_sk_GENERIC_push(stack, data_1), 1);
    ExpectNull(wolfSSL_sk_value(stack, 1));
    ExpectPtrEq(wolfSSL_sk_value(stack, 0), data_1);
    ExpectIntEQ(wolfSSL_sk_GENERIC_push(stack, data_2), 2);
    ExpectNull(wolfSSL_sk_value(stack, 2));
    ExpectPtrEq(wolfSSL_sk_value(stack, 1), data_2);
    ExpectPtrEq(wolfSSL_sk_value(stack, 0), data_1);
    ExpectIntEQ(wolfSSL_sk_GENERIC_push(stack, data_3), 3);
    ExpectNull(wolfSSL_sk_value(stack, 3));
    ExpectPtrEq(wolfSSL_sk_value(stack, 2), data_3);
    ExpectPtrEq(wolfSSL_sk_value(stack, 1), data_2);
    ExpectPtrEq(wolfSSL_sk_value(stack, 0), data_1);

    wolfSSL_sk_GENERIC_free(stack);
    stack = NULL;

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    wolfSSL_sk_GENERIC_pop_free(stack, test_sk_xfree);

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));
    ExpectNotNull(str_1 = (char*)XMALLOC(2, NULL, DYNAMIC_TYPE_OPENSSL));
    if (EXPECT_SUCCESS()) {
        XSTRNCPY(str_1, "1", 2);
    }
    ExpectIntEQ(wolfSSL_sk_GENERIC_push(stack, str_1), 1);
    if (EXPECT_FAIL()) {
        XFREE(str_1, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    wolfSSL_sk_GENERIC_pop_free(NULL, NULL);
    wolfSSL_sk_GENERIC_pop_free(NULL, test_sk_xfree);
    wolfSSL_sk_GENERIC_pop_free(stack, test_sk_xfree);
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_sk_SSL_COMP(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    ExpectIntEQ(wolfSSL_sk_SSL_COMP_num(NULL), 0);
#endif

#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_STUB)
    ExpectIntEQ(wolfSSL_sk_SSL_COMP_zero(NULL), WOLFSSL_FAILURE);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_CIPHER(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
    /* TODO: figure out a way to get a WOLFSSL_CIPHER to test with. */
    WOLFSSL_STACK* ciphers = NULL;

    ExpectNotNull(ciphers = wolfSSL_sk_new_cipher());

#ifndef NO_WOLFSSL_STUB
    ExpectNull(wolfSSL_sk_CIPHER_pop(NULL));
    ExpectNull(wolfSSL_sk_CIPHER_pop(ciphers));
#endif

    ExpectIntEQ(wolfSSL_sk_CIPHER_push(NULL, NULL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_sk_CIPHER_push(ciphers, NULL), WOLFSSL_FAILURE);

#ifdef OPENSSL_EXTRA
    wolfSSL_sk_CIPHER_free(NULL);
    wolfSSL_sk_CIPHER_free(ciphers);
#else
    wolfSSL_sk_free(ciphers);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_sk_WOLFSSL_STRING(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
    WOLF_STACK_OF(WOLFSSL_STRING)* strings = NULL;
    char* str_1 = NULL;
    char* str = NULL;

    ExpectNotNull(str_1 = (char*)XMALLOC(2, NULL, DYNAMIC_TYPE_OPENSSL));
    if (str_1 != NULL) {
        XSTRNCPY(str_1, "1", 2);
    }

    ExpectNotNull(strings = wolfSSL_sk_WOLFSSL_STRING_new());
    ExpectIntEQ(wolfSSL_sk_WOLFSSL_STRING_num(strings), 0);

    ExpectNull(wolfSSL_sk_WOLFSSL_STRING_value(NULL, 0));
    ExpectNull(wolfSSL_sk_WOLFSSL_STRING_value(NULL, 1));
    ExpectNull(wolfSSL_sk_WOLFSSL_STRING_value(strings, -1));
    ExpectNull(wolfSSL_sk_WOLFSSL_STRING_value(strings, 0));

    ExpectIntEQ(wolfSSL_sk_push(strings, str_1), 1);
    ExpectIntEQ(wolfSSL_sk_WOLFSSL_STRING_num(strings), 1);
    ExpectNull(wolfSSL_sk_WOLFSSL_STRING_value(strings, 1));
    ExpectPtrEq(str = wolfSSL_sk_WOLFSSL_STRING_value(strings, 0), str_1);
    if (str != str_1) {
        XFREE(str_1, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    wolfSSL_sk_WOLFSSL_STRING_free(NULL);
    wolfSSL_sk_WOLFSSL_STRING_free(strings);
#endif
    return EXPECT_RESULT();
}

int test_wolfssl_lh_retrieve(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && defined(OPENSSL_EXTRA) && defined(OPENSSL_ALL)
    WOLFSSL_STACK* stack = NULL;
    unsigned char data_1[1] = { 1 };

    /* If there is ever a public API that creates a stack with the same ifdef
     * protection then use it here instead of wolfSSL_sk_new_node(). */
    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));

    ExpectNull(wolfSSL_lh_retrieve(NULL, NULL));
    ExpectNull(wolfSSL_lh_retrieve(stack, NULL));
    ExpectNull(wolfSSL_lh_retrieve(NULL, data_1));
    /* No hash function. */
    ExpectNull(wolfSSL_lh_retrieve(stack, data_1));

    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 1);
    /* No hash function - data present. */
    ExpectNull(wolfSSL_lh_retrieve(stack, data_1));

    /* No public API to set hash function. */

    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}


/*******************************************************************************
 * SSL_CTX_get_ciphers() - stack of the ciphers configured on a CTX
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
/* A new SSL of ctx must report the same list, entry for entry. */
static int test_ctx_ciphers_match_ssl(WOLFSSL_CTX* ctx,
    WOLF_STACK_OF(WOLFSSL_CIPHER)* ctxSk)
{
    EXPECT_DECLS;
    WOLFSSL* ssl = NULL;
    WOLF_STACK_OF(WOLFSSL_CIPHER)* sslSk = NULL;
    int num = 0;
    int i;

    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectNotNull(sslSk = wolfSSL_get_ciphers_compat(ssl));
    ExpectIntGT(num = wolfSSL_sk_SSL_CIPHER_num(ctxSk), 0);
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sslSk), num);
    for (i = 0; EXPECT_SUCCESS() && (i < num); i++) {
        const WOLFSSL_CIPHER* c = wolfSSL_sk_SSL_CIPHER_value(ctxSk, i);
        const WOLFSSL_CIPHER* s = wolfSSL_sk_SSL_CIPHER_value(sslSk, i);
        char cDesc[256];
        char sDesc[256];

        ExpectNotNull(c);
        ExpectNotNull(s);
        if ((c == NULL) || (s == NULL))
            break;
        ExpectIntEQ(c->cipherSuite0, s->cipherSuite0);
        ExpectIntEQ(c->cipherSuite, s->cipherSuite);
        ExpectStrEQ(wolfSSL_CIPHER_get_name(c), wolfSSL_CIPHER_get_name(s));
        ExpectTrue(c->ssl == NULL);
        /* The ID is the suite of the entry, not of a session. */
        ExpectIntEQ((int)wolfSSL_CIPHER_get_id(c),
            ((int)c->cipherSuite0 << 8) | c->cipherSuite);
        ExpectIntEQ((int)wolfSSL_CIPHER_get_id(s),
            (int)wolfSSL_CIPHER_get_id(c));
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
        /* Same bookkeeping, so the same description. */
        ExpectIntEQ(c->in_stack, s->in_stack);
        ExpectIntEQ((int)c->offset, (int)s->offset);
        ExpectNotNull(wolfSSL_CIPHER_description(c, cDesc,
            (int)sizeof(cDesc)));
        ExpectNotNull(wolfSSL_CIPHER_description(s, sDesc,
            (int)sizeof(sDesc)));
        ExpectStrEQ(cDesc, sDesc);
    #else
        /* No session to describe. */
        ExpectNull(wolfSSL_CIPHER_description(c, cDesc,
            (int)sizeof(cDesc)));
        (void)sDesc;
    #endif
    }

    wolfSSL_free(ssl);
    return EXPECT_RESULT();
}
#endif

#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
/* The entry at idx must be the suite s0/s. Its name is the IANA one unless
 * built to report internal names. */
static int test_ctx_cipher_at(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk, int idx,
    byte s0, byte s, const char* iana, const char* name)
{
    EXPECT_DECLS;
    const WOLFSSL_CIPHER* c = NULL;
    const char* got = NULL;

    ExpectNotNull(c = wolfSSL_sk_SSL_CIPHER_value(sk, idx));
    if (c != NULL) {
        ExpectIntEQ(c->cipherSuite0, s0);
        ExpectIntEQ(c->cipherSuite, s);
    }
    ExpectNotNull(got = wolfSSL_CIPHER_get_name(c));
    ExpectTrue((got != NULL) &&
        ((XSTRCMP(got, iana) == 0) || (XSTRCMP(got, name) == 0)));

    return EXPECT_RESULT();
}
#endif

/* Default list of a new CTX, before any SSL derives it. */
int test_wolfSSL_CTX_get_ciphers_default(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLF_STACK_OF(WOLFSSL_CIPHER)* sk = NULL;
    Suites* suites = NULL;
    int num = 0;
    int i;

    ExpectNull(wolfSSL_CTX_get_ciphers_compat(NULL));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    if (ctx != NULL)
        suites = ctx->suites;
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntGT(num = wolfSSL_sk_SSL_CIPHER_num(sk), 0);
    /* Reading the list must not derive the CTX suites. */
    ExpectTrue((ctx != NULL) && (ctx->suites == suites));
    /* Owned by the CTX: same stack while the list is unchanged. */
    ExpectPtrEq(wolfSSL_CTX_get_ciphers_compat(ctx), sk);

    /* TLS 1.3 suites are preferred, as in OpenSSL. */
    for (i = 1; EXPECT_SUCCESS() && (i < num); i++) {
        const WOLFSSL_CIPHER* prev = wolfSSL_sk_SSL_CIPHER_value(sk, i - 1);
        const WOLFSSL_CIPHER* cur = wolfSSL_sk_SSL_CIPHER_value(sk, i);

        ExpectNotNull(prev);
        ExpectNotNull(cur);
        ExpectFalse((prev != NULL) && (cur != NULL) &&
            (prev->cipherSuite0 != TLS13_BYTE) &&
            (cur->cipherSuite0 == TLS13_BYTE));
    }
#if defined(BUILD_TLS_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    {
        const char* name;
        int tls13 = -1;
        int tls12 = -1;

        for (i = 0; i < num; i++) {
            name = wolfSSL_CIPHER_get_name(wolfSSL_sk_SSL_CIPHER_value(sk, i));
            if (name == NULL)
                continue;
            if ((XSTRCMP(name, "TLS_AES_128_GCM_SHA256") == 0) ||
                    (XSTRCMP(name, "TLS13-AES128-GCM-SHA256") == 0)) {
                tls13 = i;
            }
            if ((XSTRCMP(name, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == 0) ||
                    (XSTRCMP(name, "ECDHE-RSA-AES128-GCM-SHA256") == 0)) {
                tls12 = i;
            }
        }
        ExpectIntGE(tls13, 0);
        ExpectIntGT(tls12, tls13);
    }
#endif

    /* A new SSL derives the CTX suites and reports the same list. */
    ExpectIntEQ(test_ctx_ciphers_match_ssl(ctx, sk), TEST_SUCCESS);
    ExpectNotNull(ctx->suites);
    /* The derived suites are the defaults reported: the stack is kept. */
    ExpectPtrEq(wolfSSL_CTX_get_ciphers_compat(ctx), sk);
#if !defined(OPENSSL_COEXIST) && \
    (defined(OPENSSL_ALL) || defined(WOLFSSL_HAPROXY))
    ExpectPtrEq(SSL_CTX_get_ciphers(ctx), sk);
#endif

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* The list follows SSL_CTX_set_cipher_list(), in the order set. */
int test_wolfSSL_CTX_get_ciphers_set_list(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLF_STACK_OF(WOLFSSL_CIPHER)* sk = NULL;

    /* An OpenSSL keyword list. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "HIGH"), WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(test_ctx_ciphers_match_ssl(ctx, sk), TEST_SUCCESS);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;

#if !defined(WOLFSSL_NO_TLS12) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
    /* TLS 1.2 only, so the list is exactly the one set. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"),
        WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 2);
    ExpectIntEQ(test_ctx_cipher_at(sk, 0, ECC_BYTE,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256"), TEST_SUCCESS);
    ExpectIntEQ(test_ctx_cipher_at(sk, 1, ECC_BYTE,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384"), TEST_SUCCESS);
    ExpectIntEQ(test_ctx_ciphers_match_ssl(ctx, sk), TEST_SUCCESS);

    /* Setting the list again frees the old stack. The new one has the new
     * order and no stale entries. */
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 2);
    ExpectIntEQ(test_ctx_cipher_at(sk, 0, ECC_BYTE,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384"), TEST_SUCCESS);
    ExpectIntEQ(test_ctx_cipher_at(sk, 1, ECC_BYTE,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256"), TEST_SUCCESS);

    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256"), WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 1);
    ExpectIntEQ(test_ctx_cipher_at(sk, 0, ECC_BYTE,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256"), TEST_SUCCESS);
    ExpectIntEQ(test_ctx_ciphers_match_ssl(ctx, sk), TEST_SUCCESS);

    /* A rejected list changes nothing: the stack is kept. */
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "NOT-A-CIPHER"),
        WOLFSSL_FAILURE);
    ExpectPtrEq(wolfSSL_CTX_get_ciphers_compat(ctx), sk);

    wolfSSL_CTX_free(ctx);
#endif
#endif
    return EXPECT_RESULT();
}

/* Version options filter the list. NULL, not an empty stack, when nothing is
 * left, as SSL_get_ciphers() returns. */
int test_wolfSSL_CTX_get_ciphers_versions(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLF_STACK_OF(WOLFSSL_CIPHER)* sk = NULL;

#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12)
    /* Only TLS 1.2 left: same list as an SSL restricted the same way. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(wolfSSL_CTX_get_ciphers_compat(ctx));
    (void)wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_3);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(test_ctx_ciphers_match_ssl(ctx, sk), TEST_SUCCESS);
    if (sk != NULL) {
        const WOLFSSL_CIPHER* c = wolfSSL_sk_SSL_CIPHER_value(sk, 0);

        ExpectTrue((c != NULL) && (c->cipherSuite0 != TLS13_BYTE));
    }
    /* TLS 1.3 back on: the list is rebuilt with its suites. */
    (void)wolfSSL_CTX_clear_options(ctx, WOLFSSL_OP_NO_TLSv1_3);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(test_ctx_ciphers_match_ssl(ctx, sk), TEST_SUCCESS);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

#if !defined(WOLFSSL_NO_TLS12) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    /* The only suite needs TLS 1.2, which is turned off. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256"), WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    (void)wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_TLSv1_2);
    ExpectNull(wolfSSL_CTX_get_ciphers_compat(ctx));
    (void)wolfSSL_CTX_clear_options(ctx, WOLFSSL_OP_NO_TLSv1_2);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 1);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12)
    /* DTLS versions are filtered as the matching TLS ones. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(test_ctx_ciphers_match_ssl(ctx, sk), TEST_SUCCESS);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

    (void)ctx;
    (void)sk;
#endif
    return EXPECT_RESULT();
}
