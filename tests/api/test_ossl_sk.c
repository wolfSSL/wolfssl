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
#include <tests/utils.h>
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
#ifdef OPENSSL_EXTRA
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
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
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

int test_wolfSSL_sk_delete(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_STACK* stack = NULL;
    unsigned char data_1[1] = { 1 };
    unsigned char data_2[1] = { 2 };
    unsigned char data_3[1] = { 3 };

    ExpectNotNull(stack = wolfSSL_sk_new_node(HEAP_HINT));

    ExpectNull(wolfSSL_sk_delete(NULL, 0));
    ExpectNull(wolfSSL_sk_delete(stack, 0));

    ExpectIntEQ(wolfSSL_sk_push(stack, data_1), 1);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_2), 2);
    ExpectIntEQ(wolfSSL_sk_push(stack, data_3), 3);
    /* Out of range indexes remove nothing. */
    ExpectNull(wolfSSL_sk_delete(stack, -1));
    ExpectNull(wolfSSL_sk_delete(stack, 3));
    ExpectIntEQ(wolfSSL_sk_num(stack), 3);

    ExpectPtrEq(wolfSSL_sk_delete(stack, 1), data_2);
    ExpectIntEQ(wolfSSL_sk_num(stack), 2);
    ExpectPtrEq(wolfSSL_sk_value(stack, 0), data_1);
    ExpectPtrEq(wolfSSL_sk_value(stack, 1), data_3);
    ExpectPtrEq(wolfSSL_sk_delete(stack, 1), data_3);
    ExpectPtrEq(wolfSSL_sk_delete(stack, 0), data_1);
    ExpectIntEQ(wolfSSL_sk_num(stack), 0);
    ExpectNull(wolfSSL_sk_delete(stack, 0));

    wolfSSL_sk_free(stack);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_sk_insert(void)
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
#if defined(OPENSSL_EXTRA) && defined(OPENSSL_ALL)
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
        WOLFSSL_CIPHER saved;
        const char* ver = NULL;
        char cDesc[256];
        char sDesc[256];
        int cBits = -1;
        int sBits = -2;

        ExpectNotNull(c);
        ExpectNotNull(s);
        if ((c == NULL) || (s == NULL))
            break;
        /* Shared entries are only read: they must not change. */
        XMEMCPY(&saved, c, sizeof(saved));
        ExpectIntEQ(c->cipherSuite0, s->cipherSuite0);
        ExpectIntEQ(c->cipherSuite, s->cipherSuite);
        ExpectStrEQ(wolfSSL_CIPHER_get_name(c), wolfSSL_CIPHER_get_name(s));
        /* The ID is the suite of the entry, not of a session. */
        ExpectIntEQ((int)wolfSSL_CIPHER_get_id(c),
            ((int)c->cipherSuite0 << 8) | c->cipherSuite);
        ExpectIntEQ((int)wolfSSL_CIPHER_get_id(s),
            (int)wolfSSL_CIPHER_get_id(c));
        /* Both describe the suite, so they report the same. */
        ExpectNotNull(ver = wolfSSL_CIPHER_get_version(c));
        ExpectStrNE(ver, "unknown");
        ExpectStrEQ(ver, wolfSSL_CIPHER_get_version(s));
        ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, &cBits),
            wolfSSL_CIPHER_get_bits(s, &sBits));
        ExpectIntEQ(cBits, sBits);
        ExpectNotNull(wolfSSL_CIPHER_description(c, cDesc,
            (int)sizeof(cDesc)));
        ExpectNotNull(wolfSSL_CIPHER_description(s, sDesc,
            (int)sizeof(sDesc)));
        ExpectStrEQ(cDesc, sDesc);
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
        (void)wolfSSL_CIPHER_get_auth_nid(c);
        (void)wolfSSL_CIPHER_get_cipher_nid(c);
        (void)wolfSSL_CIPHER_get_digest_nid(c);
        (void)wolfSSL_CIPHER_get_kx_nid(c);
        (void)wolfSSL_CIPHER_is_aead(c);
    #endif
        ExpectBufEQ(c, &saved, sizeof(saved));
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

#if defined(OPENSSL_EXTRA) && !defined(NO_TLS)
/* c must report version ver, bits and a description that is name followed by
 * rest. */
static WC_MAYBE_UNUSED int test_cipher_reports(const WOLFSSL_CIPHER* c,
    const char* ver, int bits, const char* name, const char* rest)
{
    EXPECT_DECLS;
    char desc[256];
    int algBits = -1;

    XMEMSET(desc, 0, sizeof(desc));
    ExpectNotNull(c);
    ExpectNotNull(name);
    ExpectStrEQ(wolfSSL_CIPHER_get_version(c), ver);
    ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, &algBits), bits);
    ExpectIntEQ(algBits, bits);
    ExpectNotNull(wolfSSL_CIPHER_description(c, desc, (int)sizeof(desc)));
    ExpectIntEQ(XSTRNCMP(desc, name, XSTRLEN(name)), 0);
    ExpectStrEQ(desc + XSTRLEN(name), rest);

    return EXPECT_RESULT();
}

/* a and b report the same suite the same way: description and bits. Only the
 * version may differ. */
static WC_MAYBE_UNUSED int test_cipher_same_suite(const WOLFSSL_CIPHER* a,
    const WOLFSSL_CIPHER* b)
{
    EXPECT_DECLS;
    char descA[256];
    char descB[256];
    const char* kxA = NULL;
    const char* kxB = NULL;
    const char* sp = NULL;
    int algA = -1;
    int algB = -2;

    XMEMSET(descA, 0, sizeof(descA));
    XMEMSET(descB, 0, sizeof(descB));
    ExpectNotNull(wolfSSL_CIPHER_description(a, descA, (int)sizeof(descA)));
    ExpectNotNull(wolfSSL_CIPHER_description(b, descB, (int)sizeof(descB)));
    /* The name, then the version, then Kx=... */
    ExpectNotNull(sp = XSTRSTR(descA, " "));
    if (sp != NULL)
        ExpectIntEQ(XSTRNCMP(descA, descB, (size_t)(sp - descA) + 1), 0);
    ExpectNotNull(kxA = XSTRSTR(descA, " Kx="));
    ExpectNotNull(kxB = XSTRSTR(descB, " Kx="));
    if ((kxA != NULL) && (kxB != NULL))
        ExpectStrEQ(kxA, kxB);
    ExpectIntEQ(wolfSSL_CIPHER_get_bits(a, &algA),
        wolfSSL_CIPHER_get_bits(b, &algB));
    ExpectIntEQ(algA, algB);

    return EXPECT_RESULT();
}

/* OpenSSL's name of a TLS 1.3 suite is its IANA name. */
#ifndef NO_ERROR_STRINGS
    #define TEST_TLS13_NAME(iana, internal) iana
#else
    #define TEST_TLS13_NAME(iana, internal) internal
#endif
#endif

/* CTX entries have no SSL. They report the version, bits and description of
 * their own suite. */
int test_wolfSSL_CTX_get_ciphers_describe(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLF_STACK_OF(WOLFSSL_CIPHER)* sk = NULL;
    const WOLFSSL_CIPHER* c = NULL;
    char desc[256];

#if !defined(WOLFSSL_NO_TLS12) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256"),
        WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 2);
    c = wolfSSL_sk_SSL_CIPHER_value(sk, 0);
    ExpectIntEQ(test_cipher_reports(c, "TLSv1.2", 128,
        "ECDHE-RSA-AES128-GCM-SHA256",
        " TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(128) Mac=AEAD"), TEST_SUCCESS);
    c = wolfSSL_sk_SSL_CIPHER_value(sk, 1);
    ExpectIntEQ(test_cipher_reports(c, "TLSv1.2", 128,
        "ECDHE-RSA-AES128-SHA256",
        " TLSv1.2 Kx=ECDH Au=RSA Enc=AES(128) Mac=SHA256"), TEST_SUCCESS);
    /* Cut to fit and always terminated. */
    XMEMSET(desc, 'x', sizeof(desc));
    ExpectNotNull(wolfSSL_CIPHER_description(c, desc, 8));
    ExpectIntEQ((int)XSTRLEN(desc), 7);
    ExpectNull(wolfSSL_CIPHER_description(c, desc, 0));
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

#if defined(WOLFSSL_TLS13) && defined(BUILD_TLS_AES_128_GCM_SHA256)
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256"),
        WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 1);
    c = wolfSSL_sk_SSL_CIPHER_value(sk, 0);
    ExpectIntEQ(test_cipher_reports(c, "TLSv1.3", 128,
        TEST_TLS13_NAME("TLS_AES_128_GCM_SHA256", "TLS13-AES128-GCM-SHA256"),
        " TLSv1.3 Kx=any Au=any Enc=AESGCM(128) Mac=AEAD"), TEST_SUCCESS);
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

#if defined(WOLFSSL_TLS13) && defined(BUILD_TLS_SHA256_SHA256)
    /* Integrity-only: nothing is encrypted, so no strength. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx, "TLS13-SHA256-SHA256"),
        WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 1);
    c = wolfSSL_sk_SSL_CIPHER_value(sk, 0);
    ExpectStrEQ(wolfSSL_CIPHER_get_version(c), "TLSv1.3");
    ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, NULL), 0);
    XMEMSET(desc, 0, sizeof(desc));
    ExpectNotNull(wolfSSL_CIPHER_description(c, desc, (int)sizeof(desc)));
    ExpectStrEQ(desc, TEST_TLS13_NAME("TLS_SHA256_SHA256",
        "TLS13-SHA256-SHA256") " TLSv1.3 Kx=any Au=any Enc=None Mac=SHA256");
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_TLS12) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    /* Suites carry TLS versions, also in a DTLS list. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES128-GCM-SHA256"), WOLFSSL_SUCCESS);
    ExpectNotNull(sk = wolfSSL_CTX_get_ciphers_compat(ctx));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 1);
    ExpectStrEQ(wolfSSL_CIPHER_get_version(wolfSSL_sk_SSL_CIPHER_value(sk, 0)),
        "TLSv1.2");
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
#endif

    (void)ctx;
    (void)sk;
    (void)c;
    (void)desc;
#endif
    return EXPECT_RESULT();
}

/* Every suite of the library is found, also when not enabled on the SSL, and
 * describes itself. Its bits are only zero when nothing is encrypted. */
int test_wolfSSL_CIPHER_find_lib_suites(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const CipherSuiteInfo* names = GetCipherNames();
    int i;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    for (i = 0; EXPECT_SUCCESS() && (i < GetCipherNamesSize()); i++) {
        const WOLFSSL_CIPHER* c = NULL;
        const char* ver = NULL;
        const char* name = NULL;
        unsigned char id[2];
        char desc[256];
        int bits = -1;
        int algBits = -1;

        if (names[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS)
            continue;
        XMEMSET(desc, 0, sizeof(desc));
        id[0] = names[i].cipherSuite0;
        id[1] = names[i].cipherSuite;
        /* A lookup and the accessors leave the error queue alone. */
        wolfSSL_ERR_clear_error();
        ExpectNotNull(c = wolfSSL_SSL_CIPHER_find(ssl, id));
        ExpectIntEQ((int)wolfSSL_CIPHER_get_id(c), (id[0] << 8) | id[1]);
        ExpectNotNull(wolfSSL_CIPHER_description(c, desc, (int)sizeof(desc)));
        bits = wolfSSL_CIPHER_get_bits(c, &algBits);
        ExpectIntEQ((int)wolfSSL_ERR_get_error(), 0);
        /* A signaling value, not a suite. */
        if ((names[i].cipherSuite0 == CIPHER_BYTE) &&
                (names[i].cipherSuite == TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            continue;
        ExpectNotNull(ver = wolfSSL_CIPHER_get_version(c));
        ExpectStrNE(ver, "unknown");
        /* The suite's specs were decoded. */
        ExpectNull(XSTRSTR(desc, "unknown"));
        /* Named as OpenSSL names it: TLS 1.3 suites by their IANA name. */
        name = names[i].name;
    #ifndef NO_ERROR_STRINGS
        if (XSTRSTR(desc, " Kx=any ") != NULL)
            name = names[i].name_iana;
    #endif
        ExpectIntEQ(XSTRNCMP(desc, name, XSTRLEN(name)), 0);
        ExpectIntEQ(desc[XSTRLEN(name)], ' ');
        if (XSTRSTR(desc, "Enc=None") == NULL)
            ExpectIntGT(bits, 0);
        else
            ExpectIntEQ(bits, 0);
        ExpectIntGE(algBits, bits);
        if (EXPECT_FAIL())
            fprintf(stderr, "suite %s: %s\n", names[i].name, desc);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
/* A suite as OpenSSL describes it: name, Kx, Au, Enc, Mac and bits. wolfSSL
 * reports its own version between name and rest. */
typedef struct test_cipher_desc {
    byte suite0;
    byte suite;
    const char* name;
    const char* rest;
    int bits;
    int algBits;
} test_cipher_desc;

static const test_cipher_desc test_cipher_descs[] = {
#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    { ECC_BYTE, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      "ECDHE-RSA-AES128-GCM-SHA256",
      " Kx=ECDH Au=RSA Enc=AESGCM(128) Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    { CHACHA_BYTE, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
      "ECDHE-ECDSA-CHACHA20-POLY1305",
      " Kx=ECDH Au=ECDSA Enc=CHACHA20/POLY1305(256) Mac=AEAD", 256, 256 },
#endif
#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    { CIPHER_BYTE, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
      "DHE-RSA-AES256-GCM-SHA384",
      " Kx=DH Au=RSA Enc=AESGCM(256) Mac=AEAD", 256, 256 },
#endif
#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    { CIPHER_BYTE, TLS_RSA_WITH_AES_128_CBC_SHA, "AES128-SHA",
      " Kx=RSA Au=RSA Enc=AES(128) Mac=SHA1", 128, 128 },
#endif
#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    { CIPHER_BYTE, SSL_RSA_WITH_3DES_EDE_CBC_SHA, "DES-CBC3-SHA",
      " Kx=RSA Au=RSA Enc=3DES(168) Mac=SHA1", 112, 168 },
#endif
#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    { CIPHER_BYTE, SSL_RSA_WITH_RC4_128_MD5, "RC4-MD5",
      " Kx=RSA Au=RSA Enc=RC4(128) Mac=MD5", 128, 128 },
#endif
#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
    { CIPHER_BYTE, TLS_PSK_WITH_AES_128_CBC_SHA256, "PSK-AES128-CBC-SHA256",
      " Kx=PSK Au=PSK Enc=AES(128) Mac=SHA256", 128, 128 },
#endif
#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    { CIPHER_BYTE, TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
      "DHE-PSK-AES128-GCM-SHA256",
      " Kx=DHEPSK Au=PSK Enc=AESGCM(128) Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    { ECC_BYTE, TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
      "ECDHE-PSK-AES128-CBC-SHA256",
      " Kx=ECDHEPSK Au=PSK Enc=AES(128) Mac=SHA256", 128, 128 },
#endif
#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    { CIPHER_BYTE, TLS_DH_anon_WITH_AES_128_CBC_SHA, "ADH-AES128-SHA",
      " Kx=DH Au=None Enc=AES(128) Mac=SHA1", 128, 128 },
#endif
#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
    { CIPHER_BYTE, TLS_RSA_WITH_NULL_SHA256, "NULL-SHA256",
      " Kx=RSA Au=RSA Enc=None Mac=SHA256", 0, 0 },
#endif
#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_NULL_SHA
    { ECC_BYTE, TLS_ECDHE_ECDSA_WITH_NULL_SHA, "ECDHE-ECDSA-NULL-SHA",
      " Kx=ECDH Au=ECDSA Enc=None Mac=SHA1", 0, 0 },
#endif
#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    /* OpenSSL names it AES128-CCM8. */
    { ECC_BYTE, TLS_RSA_WITH_AES_128_CCM_8, "AES128-CCM-8",
      " Kx=RSA Au=RSA Enc=AESCCM8(128) Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    { ECC_BYTE, TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "ECDHE-ECDSA-AES128-CCM",
      " Kx=ECDH Au=ECDSA Enc=AESCCM(128) Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    { CIPHER_BYTE, TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
      "DHE-RSA-CAMELLIA128-SHA",
      " Kx=DH Au=RSA Enc=Camellia(128) Mac=SHA1", 128, 128 },
#endif
#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    { CIPHER_BYTE, TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256, "CAMELLIA256-SHA256",
      " Kx=RSA Au=RSA Enc=Camellia(256) Mac=SHA256", 256, 256 },
#endif
#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
    { ECC_BYTE, TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
      "ECDHE-ECDSA-ARIA128-GCM-SHA256",
      " Kx=ECDH Au=ECDSA Enc=ARIAGCM(128) Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    /* Static ECDH, as OpenSSL 1.0.2 described it. */
    { ECC_BYTE, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, "ECDH-RSA-AES128-SHA",
      " Kx=ECDH/RSA Au=ECDH Enc=AES(128) Mac=SHA1", 128, 128 },
#endif
#ifdef BUILD_TLS_AES_128_GCM_SHA256
    { TLS13_BYTE, TLS_AES_128_GCM_SHA256,
      TEST_TLS13_NAME("TLS_AES_128_GCM_SHA256", "TLS13-AES128-GCM-SHA256"),
      " Kx=any Au=any Enc=AESGCM(128) Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_CHACHA20_POLY1305_SHA256
    { TLS13_BYTE, TLS_CHACHA20_POLY1305_SHA256,
      TEST_TLS13_NAME("TLS_CHACHA20_POLY1305_SHA256",
          "TLS13-CHACHA20-POLY1305-SHA256"),
      " Kx=any Au=any Enc=CHACHA20/POLY1305(256) Mac=AEAD", 256, 256 },
#endif
#ifdef BUILD_TLS_AES_128_CCM_8_SHA256
    { TLS13_BYTE, TLS_AES_128_CCM_8_SHA256,
      TEST_TLS13_NAME("TLS_AES_128_CCM_8_SHA256",
          "TLS13-AES128-CCM-8-SHA256"),
      " Kx=any Au=any Enc=AESCCM8(128) Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_SM4_GCM_SM3
    { CIPHER_BYTE, TLS_SM4_GCM_SM3,
      TEST_TLS13_NAME("TLS_SM4_GCM_SM3", "TLS13-SM4-GCM-SM3"),
      " Kx=any Au=any Enc=SM4GCM Mac=AEAD", 128, 128 },
#endif
#ifdef BUILD_TLS_SHA256_SHA256
    /* Integrity-only: the HMAC key has bits but there is no strength. */
    { ECC_BYTE, TLS_SHA256_SHA256,
      TEST_TLS13_NAME("TLS_SHA256_SHA256", "TLS13-SHA256-SHA256"),
      " Kx=any Au=any Enc=None Mac=SHA256", 0, 256 },
#endif
#ifdef BUILD_TLS_SHA384_SHA384
    { ECC_BYTE, TLS_SHA384_SHA384,
      TEST_TLS13_NAME("TLS_SHA384_SHA384", "TLS13-SHA384-SHA384"),
      " Kx=any Au=any Enc=None Mac=SHA384", 0, 384 },
#endif
    { 0, 0, NULL, NULL, 0, 0 }
};
#endif

/* Suites are described, and report bits, as OpenSSL does. */
int test_wolfSSL_CIPHER_description_bits(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int i;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    for (i = 0; EXPECT_SUCCESS() && (test_cipher_descs[i].name != NULL);
            i++) {
        const test_cipher_desc* t = &test_cipher_descs[i];
        const WOLFSSL_CIPHER* c = NULL;
        const char* ver = NULL;
        unsigned char id[2];
        char desc[256];
        size_t nameLen = XSTRLEN(t->name);
        int algBits = -1;

        XMEMSET(desc, 0, sizeof(desc));
        id[0] = t->suite0;
        id[1] = t->suite;
        ExpectNotNull(c = wolfSSL_SSL_CIPHER_find(ssl, id));
        ExpectNotNull(ver = wolfSSL_CIPHER_get_version(c));
        ExpectNotNull(wolfSSL_CIPHER_description(c, desc, (int)sizeof(desc)));
        /* <name> <version><rest> */
        ExpectIntEQ(XSTRNCMP(desc, t->name, nameLen), 0);
        ExpectIntEQ(desc[nameLen], ' ');
        if (EXPECT_SUCCESS()) {
            ExpectIntEQ(XSTRNCMP(desc + nameLen + 1, ver, XSTRLEN(ver)), 0);
            ExpectStrEQ(desc + nameLen + 1 + XSTRLEN(ver), t->rest);
        }
        ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, &algBits), t->bits);
        ExpectIntEQ(algBits, t->algBits);
        ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, NULL), t->bits);
        if (EXPECT_FAIL())
            fprintf(stderr, "suite %s: %s\n", t->name, desc);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Copies of entries do not depend on the SSL they came from. */
int test_wolfSSL_CIPHER_outlives_ssl(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLF_STACK_OF(WOLFSSL_CIPHER)* dup = NULL;
    const WOLFSSL_CIPHER* c = NULL;
    char before[256];
    char after[256];
    const char* ver = NULL;
    int bits = 0;

    XMEMSET(before, 0, sizeof(before));
    XMEMSET(after, 0, sizeof(after));
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectNotNull(dup = wolfSSL_sk_dup(wolfSSL_get_ciphers_compat(ssl)));
    ExpectNotNull(c = wolfSSL_sk_SSL_CIPHER_value(dup, 0));
    ExpectNotNull(wolfSSL_CIPHER_description(c, before, (int)sizeof(before)));
    ExpectNotNull(ver = wolfSSL_CIPHER_get_version(c));
    bits = wolfSSL_CIPHER_get_bits(c, NULL);
    wolfSSL_free(ssl);
    ssl = NULL;

    ExpectNotNull(wolfSSL_CIPHER_description(c, after, (int)sizeof(after)));
    ExpectStrEQ(after, before);
    ExpectStrEQ(wolfSSL_CIPHER_get_version(c), ver);
    ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, NULL), bits);

    wolfSSL_sk_CIPHER_free(dup);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ECC) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
/* Handshake with the list "AES-GCM:AES-CBC". The current cipher reports the
 * session: the negotiated version and the AES-GCM specs. The list entry of
 * AES-CBC reports its own suite. */
static int test_cipher_current_tls12(method_provider mc, method_provider ms,
    const char* ver)
{
    EXPECT_DECLS;
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    WOLF_STACK_OF(WOLFSSL_CIPHER)* sk = NULL;
    const WOLFSSL_CIPHER* c = NULL;
    const WOLFSSL_CIPHER* pre = NULL;
    const char* list = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256";
    const char* name = "ECDHE-RSA-AES128-GCM-SHA256";
    const char* rest = " TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(128) Mac=AEAD";
#if !defined(NO_SESSION_CACHE) && !defined(NO_RESUME_SUITE_CHECK)
    WOLFSSL* ssl_r = NULL;
    WOLFSSL_SESSION* sess = NULL;
#endif
    char desc[256];

    if (XSTRCMP(ver, "TLSv1.2") != 0)
        rest = " DTLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(128) Mac=AEAD";

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        mc, ms), 0);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, list), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, list), WOLFSSL_SUCCESS);

    /* Before the handshake: no suite, the SSL's version. Nothing to look
     * up, so the error queue is left alone. */
    wolfSSL_ERR_clear_error();
    ExpectNotNull(pre = wolfSSL_get_current_cipher(ssl_c));
    ExpectIntEQ((int)wolfSSL_CIPHER_get_id(pre), 0);
    ExpectStrEQ(wolfSSL_CIPHER_get_version(pre), wolfSSL_get_version(ssl_c));
    ExpectIntEQ(wolfSSL_CIPHER_get_bits(pre, NULL), 0);
    ExpectNotNull(wolfSSL_CIPHER_description(pre, desc, (int)sizeof(desc)));
    ExpectIntEQ((int)wolfSSL_ERR_get_error(), 0);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    ExpectNotNull(c = wolfSSL_get_current_cipher(ssl_c));
    ExpectPtrEq(c, pre);
    ExpectIntEQ((int)wolfSSL_CIPHER_get_id(c),
        (ECC_BYTE << 8) | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    ExpectStrEQ(wolfSSL_get_version(ssl_c), ver);
    ExpectStrEQ(wolfSSL_CIPHER_get_version(c), ver);
    ExpectIntEQ(test_cipher_reports(c, ver, 128, name, rest), TEST_SUCCESS);
    ExpectNotNull(c = wolfSSL_get_current_cipher(ssl_s));
    ExpectStrEQ(wolfSSL_CIPHER_get_version(c), ver);
    ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, NULL), 128);

    ExpectNotNull(sk = wolfSSL_get_ciphers_compat(ssl_c));
    ExpectIntEQ(wolfSSL_sk_SSL_CIPHER_num(sk), 2);
    /* The list entry of the negotiated suite reports it the same way. */
    ExpectIntEQ(test_cipher_same_suite(wolfSSL_sk_SSL_CIPHER_value(sk, 0),
        wolfSSL_get_current_cipher(ssl_c)), TEST_SUCCESS);
    c = wolfSSL_sk_SSL_CIPHER_value(sk, 1);
    ExpectIntEQ(test_cipher_reports(c, "TLSv1.2", 128,
        "ECDHE-RSA-AES128-SHA256",
        " TLSv1.2 Kx=ECDH Au=RSA Enc=AES(128) Mac=SHA256"), TEST_SUCCESS);

#if !defined(NO_SESSION_CACHE) && !defined(NO_RESUME_SUITE_CHECK)
    /* The suite of the set session. Also once the ClientHello is sent: the
     * specs are only set up when the ServerHello is processed. */
    ExpectNotNull(sess = wolfSSL_get1_session(ssl_c));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, NULL, &ssl_r, NULL,
        mc, ms), 0);
    ExpectIntEQ(wolfSSL_set_session(ssl_r, sess), WOLFSSL_SUCCESS);
    ExpectNotNull(c = wolfSSL_get_current_cipher(ssl_r));
    ExpectIntEQ((int)wolfSSL_CIPHER_get_id(c),
        (ECC_BYTE << 8) | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    ExpectIntEQ(test_cipher_reports(c, ver, 128, name, rest), TEST_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_r), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_get_error(ssl_r, WOLFSSL_FATAL_ERROR),
        WOLFSSL_ERROR_WANT_READ);
    ExpectNotNull(c = wolfSSL_get_current_cipher(ssl_r));
    ExpectIntEQ(test_cipher_reports(c, ver, 128, name, rest), TEST_SUCCESS);
    wolfSSL_free(ssl_r);
    wolfSSL_SESSION_free(sess);
#endif

    /* SSL_clear() keeps the suite. */
    ExpectIntEQ(wolfSSL_clear(ssl_c), WOLFSSL_SUCCESS);
    ExpectNotNull(c = wolfSSL_get_current_cipher(ssl_c));
    ExpectIntEQ((int)wolfSSL_CIPHER_get_id(c),
        (ECC_BYTE << 8) | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    ExpectIntEQ(test_cipher_reports(c, ver, 128, name, rest), TEST_SUCCESS);

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return EXPECT_RESULT();
}
#endif

/* The current cipher reports the negotiated session. List entries of the same
 * SSL report their own suite. */
int test_wolfSSL_CIPHER_current(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    !defined(NO_RSA) && !defined(WOLFSSL_NO_TLS12) && defined(HAVE_ECC) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) && \
    defined(BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
    ExpectIntEQ(test_cipher_current_tls12(wolfTLSv1_2_client_method,
        wolfTLSv1_2_server_method, "TLSv1.2"), TEST_SUCCESS);
#ifdef WOLFSSL_DTLS
    ExpectIntEQ(test_cipher_current_tls12(wolfDTLSv1_2_client_method,
        wolfDTLSv1_2_server_method, "DTLSv1.2"), TEST_SUCCESS);
#endif
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(BUILD_TLS_AES_128_GCM_SHA256)
    {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX* ctx_c = NULL;
        WOLFSSL_CTX* ctx_s = NULL;
        WOLFSSL* ssl_c = NULL;
        WOLFSSL* ssl_s = NULL;
        const WOLFSSL_CIPHER* c = NULL;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_c, "TLS13-AES128-GCM-SHA256"),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set_cipher_list(ssl_s, "TLS13-AES128-GCM-SHA256"),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        ExpectNotNull(c = wolfSSL_get_current_cipher(ssl_c));
        ExpectStrEQ(wolfSSL_CIPHER_get_version(c), wolfSSL_get_version(ssl_c));
        ExpectIntEQ(test_cipher_reports(c, "TLSv1.3", 128,
            TEST_TLS13_NAME("TLS_AES_128_GCM_SHA256",
                "TLS13-AES128-GCM-SHA256"),
            " TLSv1.3 Kx=any Au=any Enc=AESGCM(128) Mac=AEAD"),
            TEST_SUCCESS);
        ExpectIntEQ(test_cipher_same_suite(wolfSSL_sk_SSL_CIPHER_value(
            wolfSSL_get_ciphers_compat(ssl_c), 0), c), TEST_SUCCESS);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(WOLFSSL_TLS13) && defined(BUILD_TLS_SHA256_SHA256) && \
    !defined(NO_RSA)
    {
        /* Integrity-only session: the bits of the HMAC key, no strength. */
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX* ctx_c = NULL;
        WOLFSSL_CTX* ctx_s = NULL;
        WOLFSSL* ssl_c = NULL;
        WOLFSSL* ssl_s = NULL;
        const WOLFSSL_CIPHER* c = NULL;
        char desc[256];
        int algBits = -1;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));
        XMEMSET(desc, 0, sizeof(desc));
        test_ctx.c_ciphers = "TLS13-SHA256-SHA256";
        test_ctx.s_ciphers = "TLS13-SHA256-SHA256";
        ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
            &ssl_s, wolfTLSv1_3_client_method, wolfTLSv1_3_server_method), 0);
        ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
        ExpectNotNull(c = wolfSSL_get_current_cipher(ssl_c));
        ExpectIntEQ((int)wolfSSL_CIPHER_get_id(c),
            (ECC_BYTE << 8) | TLS_SHA256_SHA256);
        ExpectStrEQ(wolfSSL_CIPHER_get_version(c), "TLSv1.3");
        ExpectIntEQ(wolfSSL_CIPHER_get_bits(c, &algBits), 0);
        ExpectIntEQ(algBits, 256);
        ExpectNotNull(wolfSSL_CIPHER_description(c, desc, (int)sizeof(desc)));
        ExpectStrEQ(desc, TEST_TLS13_NAME("TLS_SHA256_SHA256",
            "TLS13-SHA256-SHA256")
            " TLSv1.3 Kx=any Au=any Enc=None Mac=SHA256");
        ExpectIntEQ(test_cipher_same_suite(wolfSSL_sk_SSL_CIPHER_value(
            wolfSSL_get_ciphers_compat(ssl_c), 0), c), TEST_SUCCESS);

        wolfSSL_free(ssl_c);
        wolfSSL_free(ssl_s);
        wolfSSL_CTX_free(ctx_c);
        wolfSSL_CTX_free(ctx_s);
    }
#endif
    return EXPECT_RESULT();
}
