/* test_ossl_sk.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include <wolfssl/openssl/lhash.h>
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
    WOLFSSL_STACK* node;

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

