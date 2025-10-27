/* ssl_sk.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_SSL_SK_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_sk.c does not need to be compiled separately from ssl.c
    #endif
#else

/* In OpenSSL, OPENSSL_STACK is structure with an array of data pointers.
 *
 * In wolfSSL, WOLFSSL_STACK is a linked-list of nodes and therefore the first
 * node has no data but the type is set.
 * When the first data is set, the first node has the data stored against it and
 * the number of nodes goes up to 1.
 * If a new node is prepended then, to keep the pointer the same, the first
 * node is copied into a new node and inserted after first node, and the new
 * data is put into the first node.
 */

/*******************************************************************************
 * SK node APIs
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
/* Creates a generic wolfSSL stack node.
 *
 * @param [in] heap  eap hint for dynamic memory allocation.
 * @return  WOLFSSL_STACK structure on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap)
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_new_node");

    node = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), heap,
        DYNAMIC_TYPE_OPENSSL);
    if (node != NULL) {
        XMEMSET(node, 0, sizeof(*node));
        node->heap = heap;
    }

    return node;
}
#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(OPENSSL_ALL)
/* Disposes of WOLFSSL_STACK object.
 *
 * Cannot use node after this call.
 *
 * @param [in] node  WOLFSSL_STACK object.
 */
void wolfSSL_sk_free_node(WOLFSSL_STACK* node)
{
    /* Don't dereference node for heap when NULL. */
    if (node != NULL) {
        XFREE(node, node->heap, DYNAMIC_TYPE_OPENSSL);
    }
}
#endif

#if !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
/* Gets the node from stack at the index.
 *
 * @param [in] stack  Stack of nodes.
 * @param [in] idx    Index of node to get.
 * @return  Node at index on success.
 * @return  NULL when no node at index.
 */
WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* stack, int idx)
{
    int i;
    WOLFSSL_STACK* ret;

    if ((idx < 0) || (idx > (int)stack->num)) {
        ret = NULL;
    }
    else {
        ret = stack;
        for (i = 0; i < idx; i++) {
            ret = ret->next;
        }
    }

    return ret;
}
#endif /* !NO_CERT && OPENSSL_EXTRA*/

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Copy all fields from src into dst.
 *
 * Shallow copy only.
 *
 * @param [in, out] dst  Node to copy into.
 * @param [in]      src  Node to copy.
 */
static void wolfssl_sk_node_copy(WOLFSSL_STACK* dst, WOLFSSL_STACK* src)
{
    dst->data.generic = src->data.generic;
    dst->next         = src->next;
#ifdef OPENSSL_ALL
    dst->hash_fn      = src->hash_fn;
    dst->hash         = src->hash;
#endif
    dst->type         = src->type;
    dst->num          = src->num;
}

#ifndef NO_CERTS
/* Get data pointer from node.
 *
 * @param [in] node       Node to get data from.
 * @param [in] no_static  Don't return static data.
 * @return  Data pointer of node on success.
 * @return  NULL when node type is STACK_TYPE_CIPHER.
 */
static void* wolfssl_sk_node_get_data(WOLFSSL_STACK* node, int no_static)
{
    void *ret = NULL;

    switch (node->type) {
        case STACK_TYPE_CIPHER:
            if (!no_static) {
                ret = &node->data.cipher;
            }
            break;
        case STACK_TYPE_X509:
        case STACK_TYPE_GEN_NAME:
        case STACK_TYPE_BIO:
        case STACK_TYPE_OBJ:
        case STACK_TYPE_STRING:
        case STACK_TYPE_ACCESS_DESCRIPTION:
        case STACK_TYPE_X509_EXT:
        case STACK_TYPE_X509_REQ_ATTR:
        case STACK_TYPE_NULL:
        case STACK_TYPE_X509_NAME:
        case STACK_TYPE_X509_NAME_ENTRY:
        case STACK_TYPE_CONF_VALUE:
        case STACK_TYPE_X509_INFO:
        case STACK_TYPE_BY_DIR_entry:
        case STACK_TYPE_BY_DIR_hash:
        case STACK_TYPE_X509_OBJ:
        case STACK_TYPE_DIST_POINT:
        case STACK_TYPE_X509_CRL:
        default:
            ret = node->data.generic;
            break;
    }

    return ret;
}

/* Set data with type into node.
 *
 * @param [in, out] node  Node to place data into.
 * @param [in]      type  Type of data.
 * @param [in]      data  Data to set.
 */
static void wolfssl_sk_node_set_data(WOLFSSL_STACK* node, WOLF_STACK_TYPE type,
    const void* data)
{
    switch (type) {
        case STACK_TYPE_CIPHER:
#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            node->data.cipher = *(WOLFSSL_CIPHER*)data;
            if (node->hash_fn != NULL) {
                node->hash = node->hash_fn(&node->data.cipher);
            }
            break;
#endif
        case STACK_TYPE_X509:
        case STACK_TYPE_GEN_NAME:
        case STACK_TYPE_BIO:
        case STACK_TYPE_OBJ:
        case STACK_TYPE_STRING:
        case STACK_TYPE_ACCESS_DESCRIPTION:
        case STACK_TYPE_X509_EXT:
        case STACK_TYPE_X509_REQ_ATTR:
        case STACK_TYPE_NULL:
        case STACK_TYPE_X509_NAME:
        case STACK_TYPE_X509_NAME_ENTRY:
        case STACK_TYPE_CONF_VALUE:
        case STACK_TYPE_X509_INFO:
        case STACK_TYPE_BY_DIR_entry:
        case STACK_TYPE_BY_DIR_hash:
        case STACK_TYPE_X509_OBJ:
        case STACK_TYPE_DIST_POINT:
        case STACK_TYPE_X509_CRL:
        default:
            node->data.generic = (void*)data;
#ifdef OPENSSL_ALL
            if (node->hash_fn != NULL)
                node->hash = node->hash_fn(node->data.generic);
#endif
            break;
    }
}

/* Pushes the node onto the stack.
 *
 * stack will point to node on success.
 *
 * @param [in, out] stack  Stack of nodes.
 * @param [in]      node   Node to push on.
 *
 * @return WOLFSSL_SUCCESS on success
 * @return WOLFSSL_FAILURE when stack or node is NULL.
 */
int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* node)
{
    int ret = WOLFSSL_SUCCESS;

    /* Validate parameters. */
    if (stack == NULL || node == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    if (ret == WOLFSSL_SUCCESS) {
        if (*stack == NULL) {
            /* First node. */
            node->num = 1;
        }
        else {
            /* Place new node at start of the stack. */
            node->num  = (*stack)->num + 1;
            node->next = *stack;
        }
        /* Return new start. */
        *stack = node;
    }

    return ret;
}

/* Removes the node at the index from the stack and returns data.
 *
 * This is an internal API.
 *
 * @param [in, out] stack  Stack of nodes.
 * @param [in]      idx    Index of node to remove.
 * @return  Data in node on success.
 * @return  NULL when no node at index or no data.
 */
void* wolfSSL_sk_pop_node(WOLFSSL_STACK* stack, int idx)
{
    void* ret = NULL;
    WOLFSSL_STACK* tmp = NULL;
    WOLFSSL_STACK* prev;

    /* Validate parameters. */
    if ((stack != NULL) && (stack->num != 0)) {
        stack->num--;
        /* Popping first node handled differently. */
        if (idx == 0 || stack->next == NULL) {
            ret = wolfssl_sk_node_get_data(stack, 1);
            /* Clear out data if we are returning it. */
            if (ret != NULL) {
                stack->data.generic = NULL;
            }
            if (stack->next) {
                /* Keep the first node as it is the pointer passed in. */
                tmp = stack->next;
                wolfssl_sk_node_copy(stack, stack->next);
                wolfSSL_sk_free_node(tmp);
            }
        }
        else {
            /* Find node at index and take out it. */
            prev = stack;
            tmp = stack->next;
            while ((--idx != 0) && (tmp->next != NULL)) {
                prev = tmp;
                prev->num--;
                tmp = tmp->next;
            }
            prev->next = tmp->next;

            /* Get data to return and free node only. */
            ret = wolfssl_sk_node_get_data(tmp, 1);
            wolfSSL_sk_free_node(tmp);
        }
    }

    return ret;
}
#endif /* NO_CERTS */
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

/*******************************************************************************
 * SK APIs
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
/* Creates a new stack of the requested type.
 *
 * This is an internal API.
 *
 * @param [in] type  Type of stack.
 * @return  Empty stack on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_STACK* wolfssl_sk_new_type(WOLF_STACK_TYPE type)
{
    WOLFSSL_STACK* stack = wolfSSL_sk_new_node(NULL);
    if (stack != NULL) {
        stack->type = type;
    }
    return stack;
}
#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Creates a new NULL type stack.
 *
 * This is an internal API.
 *
 * @return  Empty stack on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_STACK* wolfSSL_sk_new_null(void)
{
    WOLFSSL_ENTER("wolfSSL_sk_new_null");

    return wolfssl_sk_new_type(STACK_TYPE_NULL);
}

/* Duplicate the data of a node into another.
 *
 * Limited too: STACK_TYPE_X509, STACK_TYPE_CIPHER, STACK_TYPE_GEN_NAME,
 *              STACK_TYPE_OBJ, STACK_TYPE_X509_OBJ.
 *
 * @param [in, out] dst  Destination node.
 * @param [in]      src  Source node.
 * @return  0 on success.
 * @return  1 when duplication failed or stack type is not supported.
 */
static int wolfssl_sk_dup_data(WOLFSSL_STACK* dst, WOLFSSL_STACK* src)
{
    int err = 0;

    switch (src->type) {
        case STACK_TYPE_X509:
            if (src->data.x509 == NULL) {
                break;
            }
            dst->data.x509 = wolfSSL_X509_dup(src->data.x509);
            if (dst->data.x509 == NULL) {
                WOLFSSL_MSG("wolfSSL_X509_dup error");
                err = 1;
                break;
            }
            break;
        case STACK_TYPE_CIPHER:
            wolfSSL_CIPHER_copy(&src->data.cipher, &dst->data.cipher);
            break;
        case STACK_TYPE_GEN_NAME:
            if (src->data.gn == NULL) {
                break;
            }
            dst->data.gn = wolfSSL_GENERAL_NAME_dup(src->data.gn);
            if (dst->data.gn == NULL) {
                WOLFSSL_MSG("wolfSSL_GENERAL_NAME_new error");
                err = 1;
                break;
            }
            break;
        case STACK_TYPE_OBJ:
            if (src->data.obj == NULL) {
                break;
            }
            dst->data.obj = wolfSSL_ASN1_OBJECT_dup(src->data.obj);
            if (dst->data.obj == NULL) {
                WOLFSSL_MSG("wolfSSL_ASN1_OBJECT_dup error");
                err = 1;
                break;
            }
            break;
        case STACK_TYPE_X509_OBJ:
        #if defined(OPENSSL_ALL)
            if (src->data.x509_obj == NULL) {
                break;
            }
            dst->data.x509_obj = wolfSSL_X509_OBJECT_dup(
                src->data.x509_obj);
            if (dst->data.x509_obj == NULL) {
                WOLFSSL_MSG("wolfSSL_X509_OBJECT_dup error");
                err = 1;
                break;
            }
            break;
        #endif
        case STACK_TYPE_BIO:
        case STACK_TYPE_STRING:
        case STACK_TYPE_ACCESS_DESCRIPTION:
        case STACK_TYPE_X509_EXT:
        case STACK_TYPE_X509_REQ_ATTR:
        case STACK_TYPE_NULL:
        case STACK_TYPE_X509_NAME:
        case STACK_TYPE_X509_NAME_ENTRY:
        case STACK_TYPE_CONF_VALUE:
        case STACK_TYPE_X509_INFO:
        case STACK_TYPE_BY_DIR_entry:
        case STACK_TYPE_BY_DIR_hash:
        case STACK_TYPE_DIST_POINT:
        case STACK_TYPE_X509_CRL:
        default:
            WOLFSSL_MSG("Unsupported stack type");
            err = 1;
            break;
    }

    return err;
}

/* Duplicate the stack of nodes.
 *
 * TODO: OpenSSL does a shallow copy but we have wolfSSL_shallow_sk_dup().
 *
 * Data is copied/duplicated - deep copy.
 *
 * Limited too: STACK_TYPE_X509, STACK_TYPE_CIPHER, STACK_TYPE_GEN_NAME,
 *              STACK_TYPE_OBJ, STACK_TYPE_X509_OBJ.
 *
 * @param [in, out] stack  Stack of nodes.
 * @return  A new stack of nodes with data duplicated/copied on success.
 * @return  NULL on error.
 */
WOLFSSL_STACK* wolfSSL_sk_dup(WOLFSSL_STACK* stack)
{
    WOLFSSL_STACK* ret = NULL;
    WOLFSSL_STACK* last = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_sk_dup");

    for (; stack != NULL; stack = stack->next) {
        /* New node for duplicate stack. */
        WOLFSSL_STACK* cur = wolfSSL_sk_new_node(stack->heap);
        if (cur == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_new_node error");
            err = 1;
            break;
        }

        if (ret == NULL) {
            /* Keep the first node for returning. */
            ret = cur;
        }
        if (last != NULL) {
            /* Add new node to end of list. */
            last->next = cur;
        }
        /* Update last node in linked list. */
        last = cur;

        wolfssl_sk_node_copy(cur, stack);
        /* We will allocate new memory for this */
        XMEMSET(&cur->data, 0, sizeof(cur->data));
        cur->next = NULL;

        err = wolfssl_sk_dup_data(cur, stack);
        if (err) {
            break;
        }
    }

    if (err && (ret != NULL)) {
        wolfSSL_sk_pop_free(ret, NULL);
        ret = NULL;
    }

    return ret;
}

/* Shallow duplicate a stack of nodes.
 *
 * @param [in] stack  Stack of nodes.
 * @return  A new stack of nodes with data duplicated/copied on success.
 * @return  NULL on error.
 */
WOLFSSL_STACK* wolfSSL_shallow_sk_dup(WOLFSSL_STACK* stack)
{

    WOLFSSL_STACK* ret = NULL;
    WOLFSSL_STACK** prev = &ret;

    WOLFSSL_ENTER("wolfSSL_shallow_sk_dup");

    for (; stack != NULL; stack = stack->next) {
        WOLFSSL_STACK* cur = wolfSSL_sk_new_node(stack->heap);
        if (cur == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_new_node error");
            wolfSSL_sk_free(ret);
            ret = NULL;
            break;
        }

        wolfssl_sk_node_copy(cur, stack);
        cur->next = NULL;

        *prev = cur;
        prev = &cur->next;
    }

    return ret;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(OPENSSL_ALL)
/* Free the nodes in the stack only.
 *
 * @param [in] stack  Stack of nodes.
 */
void wolfSSL_sk_free(WOLFSSL_STACK* stack)
{
    WOLFSSL_ENTER("wolfSSL_sk_free");

    while (stack != NULL) {
        WOLFSSL_STACK* next = stack->next;
        wolfSSL_sk_free_node(stack);
        stack = next;
    }
}
#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_ALL)
/* Get the number of nodes in the stack.
 *
 * @param [in] stack  Stack of nodes.
 * @return  Number of nodes in stack on success.
 * @return  0 when no nodes or stack is NULL.
 */
int wolfSSL_sk_num(const WOLFSSL_STACK* stack)
{
    int num = 0;

    WOLFSSL_ENTER("wolfSSL_sk_num");

    if (stack != NULL) {
        num = (int)stack->num;
    }

    return num;
}

/* Get the value/data in a node from the stack at the index.
 *
 * If stack type is STACK_TYPE_CONF_VALUE and OPENSSL_EXTRA is not defined,
 * the value will be NULL.
 *
 * @param [in] stack  Stack of nodes.
 * @param [in] i      Index of node to get value/data.
 * @return  Data in node at index on success.
 * @return  NULL when no node at index.
 */
void* wolfSSL_sk_value(const WOLFSSL_STACK* sk, int i)
{
    void* val;

    WOLFSSL_ENTER("wolfSSL_sk_value");

    for (; (sk != NULL) && (i > 0); i--) {
        sk = sk->next;
    }

    if (sk == NULL) {
        val = NULL;
    }
    else {
        switch (sk->type) {
            case STACK_TYPE_CIPHER:
                val = (void*)&sk->data.cipher;
                break;
            case STACK_TYPE_CONF_VALUE:
        #ifndef OPENSSL_EXTRA
                val = NULL;
                break;
        #endif
            case STACK_TYPE_X509:
            case STACK_TYPE_GEN_NAME:
            case STACK_TYPE_BIO:
            case STACK_TYPE_OBJ:
            case STACK_TYPE_STRING:
            case STACK_TYPE_ACCESS_DESCRIPTION:
            case STACK_TYPE_X509_EXT:
            case STACK_TYPE_X509_REQ_ATTR:
            case STACK_TYPE_NULL:
            case STACK_TYPE_X509_NAME:
            case STACK_TYPE_X509_NAME_ENTRY:
            case STACK_TYPE_X509_INFO:
            case STACK_TYPE_BY_DIR_entry:
            case STACK_TYPE_BY_DIR_hash:
            case STACK_TYPE_X509_OBJ:
            case STACK_TYPE_DIST_POINT:
            case STACK_TYPE_X509_CRL:
            default:
                val = sk->data.generic;
                break;
        }
    }

    return val;
}
#endif

#if (!defined(NO_CERTS) && (defined(OPENSSL_EXTRA) || \
     defined(WOLFSSL_WPAS_SMALL))) || defined(WOLFSSL_QT) || \
     defined(OPENSSL_ALL)
/* Put the data into a node at the top of the stack.
 *
 * @param [in, out] stack  Stack of objects.
 * @param [in]      data   Data to store in stack.
 * @return  Number of nodes in stack on success.
 * @return  WOLFSSL_FAILURE when data is NULL.
 * @return  WOLFSSL_FATAL_ERROR when stack is NULL.
 */
int wolfSSL_sk_push(WOLFSSL_STACK* stack, const void *data)
{
    WOLFSSL_ENTER("wolfSSL_sk_push");

    return wolfSSL_sk_insert(stack, data, -1);
}

/* Put the data into a node at an index in the stack.
 *
 * @param [in, out] stack  Stack of objects.
 * @param [in]      data   Data to store in stack.
 * @return  Number of nodes in stack on success.
 * @return  WOLFSSL_FAILURE when data is NULL.
 * @return  WOLFSSL_FATAL_ERROR when stack is NULL.
 */
int wolfSSL_sk_insert(WOLFSSL_STACK *stack, const void *data, int idx)
{
    int ret;
    WOLFSSL_STACK* node;
    WOLFSSL_ENTER("wolfSSL_sk_insert");

    /* Validate parameters. */
    if (stack == NULL) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    else if (data == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    else if (stack->num == 0) {
        /* No data set in stack - set data into empty first node. */
        wolfssl_sk_node_set_data(stack, stack->type, data);
        stack->num = 1;
        ret = 1;
    }
    else {
        /* Create a new node. */
        node = wolfSSL_sk_new_node(stack->heap);
        if (node == NULL) {
            WOLFSSL_MSG("Memory error");
            ret = WOLFSSL_FAILURE;
        }
        else {
            /* Place at front of linked-list. */
            if (idx == 0) {
                /* Special case where we need to change the values in the head
                 * element to avoid changing the initial pointer. */
                wolfssl_sk_node_copy(node, stack);
                wolfssl_sk_node_set_data(stack, stack->type, data);
                stack->num++;
                stack->next = node;
            }
            /* Place new node with data into list. */
            else {
                WOLFSSL_STACK* prev;
                unsigned long num = stack->num;

                node->type    = stack->type;
            #ifdef OPENSSL_ALL
                node->hash_fn = stack->hash_fn;
            #endif
                /* Put data into new node. */
                wolfssl_sk_node_set_data(node, stack->type, data);

                /* Update count as new node being placed after first. */
                stack->num++;
                prev = stack;
                while (((--idx) != 0) && (prev->next != NULL)) {
                    prev = prev->next;
                    /* Update count as new node being placed after this one. */
                    prev->num = num--;
                }
                /* Set count for new node. */
                node->num = num;
                /* Place node in linked list after prev. */
                node->next = prev->next;
                prev->next = node;
            }

            /* Returning new stack count. */
            ret = (int)stack->num;
        }
    }

    return ret;
}
#endif

#if !defined(NO_CERTS) && (defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_WPAS_SMALL))
/* Remove the top node from the stack and return its data.
 *
 * @param [in, out] stack  Stack of nodes with data.
 * @return  Data in top node on success.
 * @return  NULL when stack is NULL or stack is empty.
 */
void* wolfSSL_sk_pop(WOLFSSL_STACK* stack)
{
    WOLFSSL_ENTER("wolfSSL_sk_pop");

    return wolfSSL_sk_pop_node(stack, -1);
}

#endif /* !NO_CERTS && (OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL) */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Pop off data from the stack. Checks that the type matches the stack type.
 *
 * This is an internal API.
 *
 * @param [in, out] stack  Stack of data.
 * @param [in]      type   Type of stack.
 * @return  Data on success.
 * @return  NULL when stack is NULL or no nodes left in stack.
 */
void* wolfssl_sk_pop_type(WOLFSSL_STACK* stack, WOLF_STACK_TYPE type)
{
    void* data = NULL;

    /* Check we have a stack passed in of the right type. */
    if ((stack != NULL) && (stack->type == type))
        data = wolfSSL_sk_pop(stack);

    return data;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_ALL)
/* Get the free function for the stack type.
 *
 * @param [in] type  Type of stack object.
 * @return  A free function on success.
 * @return  NULL when no free function to use.
 */
static wolfSSL_sk_freefunc wolfssl_sk_get_free_func(WOLF_STACK_TYPE type)
{
    wolfSSL_sk_freefunc func = NULL;

    switch(type) {
       case STACK_TYPE_ACCESS_DESCRIPTION:
        #if defined(OPENSSL_ALL)
            func = (wolfSSL_sk_freefunc)wolfSSL_ACCESS_DESCRIPTION_free;
        #endif
            break;
        case STACK_TYPE_X509:
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_free;
            break;
        case STACK_TYPE_X509_OBJ:
        #ifdef OPENSSL_ALL
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_OBJECT_free;
        #endif
            break;
        case STACK_TYPE_OBJ:
            func = (wolfSSL_sk_freefunc)wolfSSL_ASN1_OBJECT_free;
            break;
        case STACK_TYPE_DIST_POINT:
        #ifdef OPENSSL_EXTRA
            func = (wolfSSL_sk_freefunc)wolfSSL_DIST_POINT_free;
        #endif
            break;
        case STACK_TYPE_GEN_NAME:
            func = (wolfSSL_sk_freefunc)wolfSSL_GENERAL_NAME_free;
            break;
        case STACK_TYPE_STRING:
        #if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
            defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
            func = (wolfSSL_sk_freefunc)wolfSSL_WOLFSSL_STRING_free;
        #endif
            break;
        case STACK_TYPE_X509_NAME:
        #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) \
            && !defined(WOLFCRYPT_ONLY)
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_NAME_free;
        #endif
            break;
        case STACK_TYPE_X509_NAME_ENTRY:
        #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) \
            && !defined(WOLFCRYPT_ONLY)
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_NAME_ENTRY_free;
        #endif
            break;
        case STACK_TYPE_X509_EXT:
        #if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_EXTENSION_free;
        #endif
            break;
        case STACK_TYPE_X509_REQ_ATTR:
        #if defined(OPENSSL_ALL) && \
            (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_REQ))
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_ATTRIBUTE_free;
        #endif
            break;
        case STACK_TYPE_CONF_VALUE:
        #if defined(OPENSSL_ALL)
            func = (wolfSSL_sk_freefunc)wolfSSL_X509V3_conf_free;
        #endif
            break;
        case STACK_TYPE_X509_INFO:
        #if defined(OPENSSL_ALL)
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_INFO_free;
        #endif
            break;
        case STACK_TYPE_BIO:
        #if !defined(NO_BIO) && defined(OPENSSL_EXTRA)
            func = (wolfSSL_sk_freefunc)wolfSSL_BIO_vfree;
        #endif
            break;
        case STACK_TYPE_BY_DIR_entry:
        #if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && \
            !defined(NO_WOLFSSL_DIR)
            func = (wolfSSL_sk_freefunc)wolfSSL_BY_DIR_entry_free;
        #endif
            break;
        case STACK_TYPE_BY_DIR_hash:
        #if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && \
            !defined(NO_WOLFSSL_DIR)
            func = (wolfSSL_sk_freefunc)wolfSSL_BY_DIR_HASH_free;
        #endif
            break;
        case STACK_TYPE_X509_CRL:
        #if defined(HAVE_CRL) && (defined(OPENSSL_EXTRA) || \
            defined(WOLFSSL_WPAS_SMALL))
            func = (wolfSSL_sk_freefunc)wolfSSL_X509_CRL_free;
        #endif
            break;
        case STACK_TYPE_CIPHER:
            /* Static copy kept in node. */
        case STACK_TYPE_NULL:
        default:
            break;
    }

    return func;
}

/* Free all nodes and the dynamic data associated with them.
 *
 * This is an internal API.
 *
 * @param [in, out] sk    Stack of objects.
 * @param [in]      func  Function to use to free objects.
 */
void wolfSSL_sk_pop_free(WOLFSSL_STACK* stack, wolfSSL_sk_freefunc func)
{
    WOLFSSL_ENTER("wolfSSL_sk_pop_free");

    /* Validate parameters. */
    if (stack == NULL) {
        /* pop_free can be called with NULL, do not print bad argument */
        return;
    }
#if defined(WOLFSSL_QT)
    /* In Qt v15.5, it calls OPENSSL_sk_free(xxx, OPENSSL_sk_free).
    *  By using OPENSSL_sk_free for free causes access violation.
    *  Therefore, switching free func to wolfSSL_ACCESS_DESCRIPTION_free
    *  is needed even when func isn't NULL.
    */
    if (stack->type == STACK_TYPE_ACCESS_DESCRIPTION) {
        func = (wolfSSL_sk_freefunc)wolfSSL_ACCESS_DESCRIPTION_free;
    }
#endif
    /* Discover free function if none provided. */
    if (func == NULL) {
        func = wolfssl_sk_get_free_func(stack->type);
    }

    /* Free all nodes and data. */
    while (stack != NULL) {
        WOLFSSL_STACK* next = stack->next;

        /* Free the data of the node. */
        if ((func != NULL) && (stack->type != STACK_TYPE_CIPHER)) {
            func(stack->data.generic);
        }
        /* Dispose of node. */
        XFREE(stack, stack->heap, DYNAMIC_TYPE_OPENSSL);
        stack = next;
    }
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

/*******************************************************************************
 * Stack - Generic
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Free the nodes in the stack only.
 *
 * @param [in] stack  Stack of nodes.
 */
void wolfSSL_sk_GENERIC_free(WOLFSSL_STACK* sk)
{
    wolfSSL_sk_free(sk);
}

/* Free all nodes and the dynamic data associated with them.
 *
 * This is an internal API.
 *
 * @param [in, out] sk    Stack of objects.
 * @param [in]      func  Function to use to free objects.
 */
void wolfSSL_sk_GENERIC_pop_free(WOLFSSL_STACK* sk, void (*f) (void*))
{
    WOLFSSL_ENTER("wolfSSL_sk_GENERIC_pop_free");
    wolfSSL_sk_pop_free(sk, (wolfSSL_sk_freefunc)f);
}

/* Put the data into a node at the top of the stack.
 *
 * @param [in, out] stack  Stack of objects.
 * @param [in]      data   Data to store in stack.
 * @return  Number of nodes in stack on success.
 * @return  WOLFSSL_FAILURE when data is NULL.
 * @return  WOLFSSL_FATAL_ERROR when stack is NULL.
 */
int wolfSSL_sk_GENERIC_push(WOLFSSL_STACK* sk, void* generic)
{
    WOLFSSL_ENTER("wolfSSL_sk_GENERIC_push");

    return wolfSSL_sk_push(sk, generic);
}
#endif

/*******************************************************************************
 * Stack - Compression
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Get the number of compression algorithms in stack.
 *
 * @param [in] stack  Stack of compression algorithms.
 * @return  Number of compression algorithms in stack on success.
 * @return  0 when no compression algorithms or stack is NULL.
 */
int wolfSSL_sk_SSL_COMP_num(WOLF_STACK_OF(WOLFSSL_COMP)* stack)
{
    return wolfSSL_sk_num(stack);
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_STUB)
/* Remove all compression algorithms from stack.
 *
 * TBD
 * Used when
 *   wolfSSL_set_options(ssl, SSL_OP_NO_COMPRESSION);
 * is called.
 *
 * @param [in, out] stack  Stack of compression algorithms.
 * @return  WOLFSSL_FAILURE always.
 */
int wolfSSL_sk_SSL_COMP_zero(WOLFSSL_STACK* stack)
{
    (void)stack;
    WOLFSSL_STUB("wolfSSL_sk_SSL_COMP_zero");
    return WOLFSSL_FAILURE;
}
#endif

/*******************************************************************************
 * Stack - Cipher
 ******************************************************************************/

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
/* Creates a new stack of ciphers.
 *
 * This is not an OpenSSL API.
 *
 * @return  Empty stack on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_STACK* wolfSSL_sk_new_cipher(void)
{
    return wolfssl_sk_new_type(STACK_TYPE_CIPHER);
}

/* Put the cipher into a node at the top of the stack.
 *
 * This is an internal API.
 *
 * @param [in, out] stack   Stack of ciphers.
 * @param [in]      cipher  Cipher to store in stack.
 * @return  Number of ciphers in stack on success.
 * @return  WOLFSSL_FAILURE when data is NULL.
 * @return  WOLFSSL_FATAL_ERROR when stack is NULL.
 */
int wolfSSL_sk_CIPHER_push(WOLF_STACK_OF(WOLFSSL_CIPHER)* stack,
    WOLFSSL_CIPHER* cipher)
{
    return wolfSSL_sk_push(stack, cipher);
}

#ifndef NO_WOLFSSL_STUB
/* Does not do anythting at this time.
 *
 * @param [in, out] stack  Stack of nodes with data.
 * @return  NULL always.
 */
WOLFSSL_CIPHER* wolfSSL_sk_CIPHER_pop(WOLF_STACK_OF(WOLFSSL_CIPHER)* stack)
{
    WOLFSSL_STUB("wolfSSL_sk_CIPHER_pop");
    (void)stack;
    return NULL;
}
#endif /* NO_WOLFSSL_STUB */
#endif /* WOLFSSL_QT || OPENSSL_ALL */

#if defined(OPENSSL_EXTRA)
/* Free the nodes in the stack only.
 *
 * Ciphers are stored into a structure in a node and therefore don't need to be
 * freed.
 *
 * @param [in] ciphers  Stack of ciphers.
 */
void wolfSSL_sk_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* ciphers)
{
    WOLFSSL_ENTER("wolfSSL_sk_CIPHER_free");

    wolfSSL_sk_free(ciphers);
}
#endif /* OPENSSL_ALL */

#ifdef OPENSSL_EXTRA
/* Get the number of ciphers in the stack.
 *
 * @param [in] ciphers  Stack of ciphers.
 * @return  Number of strings in stack on success.
 * @return  0 when no strings or stack is NULL.
 */
int wolfSSL_sk_SSL_CIPHER_num(const WOLF_STACK_OF(WOLFSSL_CIPHER)* ciphers)
{
    WOLFSSL_ENTER("wolfSSL_sk_SSL_CIPHER_num");
    return wolfSSL_sk_num(ciphers);
}

/* Get the cipher from the stack at the index.
 *
 * @param [in] ciphers  Stack of cihers
 * @param [in] i        Index of node to get cipher from.
 * @return  Cipher in node at index on success.
 * @return  NULL when no node at index.
 */
WOLFSSL_CIPHER* wolfSSL_sk_SSL_CIPHER_value(WOLFSSL_STACK* ciphers, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_SSL_CIPHER_value");
    return (WOLFSSL_CIPHER*)wolfSSL_sk_value(ciphers, i);
}
#endif

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
/* Get the priority level of the cipher if it is in the stack.
 *
 * Priority level is the number of ciphers minus the idex of the cipher.
 *
 * @param [in] ciphers  Stack of ciphers.
 * @param [in] cipher   Cipher to find in stack.
 * @return  Priority level of cipher on success.
 * @return  WOLFSSL_FATAL_ERROR (-1) on failure to match.
 */
int wolfSSL_sk_SSL_CIPHER_find(WOLF_STACK_OF(WOLFSSL_CIPHER)* ciphers,
    const WOLFSSL_CIPHER* cipher)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    if (ciphers != NULL && cipher != NULL) {
        int i;
        int num = wolfSSL_sk_SSL_CIPHER_num(ciphers);
        WOLFSSL_STACK* next = ciphers;

        for (i = 0; (i < num) && (next != NULL); i++) {
            /* Match on SSL/TLS cipher suite values. */
            if ((next->data.cipher.cipherSuite0 == cipher->cipherSuite0) &&
                    (next->data.cipher.cipherSuite == cipher->cipherSuite)) {
                /* reverse because stack pushed highest on first */
                ret = num - i;
                break;
            }
            next = next->next;
        }
    }

    return ret;
}

/* Free the nodes in the stack only.
 *
 * @param [in] ciphers  Stack of ciphers.
 */
void wolfSSL_sk_SSL_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_SSL_CIPHER_free");
    wolfSSL_sk_free(sk);
}
#endif /* OPENSSL_ALL || OPENSSL_EXTRA */

/*******************************************************************************
 * Stack - String
 ******************************************************************************/

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
/* Creates a new stack of strings.
 *
 * @return  Empty stack on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLF_STACK_OF(WOLFSSL_STRING)* wolfSSL_sk_WOLFSSL_STRING_new(void)
{
    return wolfssl_sk_new_type(STACK_TYPE_STRING);
}

/* Free the nodes and strings of the stack.
 *
 * OpenSSL equivalent does not free data.
 *
 * @param [in] strings  Stack of strings.
 */
void wolfSSL_sk_WOLFSSL_STRING_free(WOLF_STACK_OF(WOLFSSL_STRING)* strings)
{
    WOLFSSL_ENTER("wolfSSL_sk_WOLFSSL_STRING_free");

    wolfSSL_sk_pop_free(strings, NULL);
}

/* Get the string from the node at an index.
 *
 * @param [in] strings  Stack of strings.
 * @param [in] idx      Index of node.
 * @return  String in node at index on success.
 * @return  NULL when no node at index.
 */
WOLFSSL_STRING wolfSSL_sk_WOLFSSL_STRING_value(
    WOLF_STACK_OF(WOLFSSL_STRING)* strings, int idx)
{
    return (WOLFSSL_STRING)wolfSSL_sk_value(strings, idx);
}

/* Get the number of strings in the stack.
 *
 * @param [in] strings  Stack of strings.
 * @return  Number of strings in stack on success.
 * @return  0 when no strings or stack is NULL.
 */
int wolfSSL_sk_WOLFSSL_STRING_num(WOLF_STACK_OF(WOLFSSL_STRING)* strings)
{
    return wolfSSL_sk_num(strings);
}
#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */

/*******************************************************************************
 * Stack - Linear Hash
 ******************************************************************************/

#if !defined(NO_CERTS) && defined(OPENSSL_EXTRA) && defined(OPENSSL_ALL)
/* Retrieve data from the stack by comparing with hash.
 *
 * @param [in] stack  Stack of data.
 * @param [in] data   Data to look-up.
 * @return  Data of node with the same hash as data passed in.
 * @return  NULL when no match found.
 */
void *wolfSSL_lh_retrieve(WOLFSSL_STACK *stack, void *data)
{
    unsigned long hash;
    void* sk_data = NULL;

    WOLFSSL_ENTER("wolfSSL_lh_retrieve");

    /* Validate parameters. */
    if ((stack == NULL) || (data == NULL)) {
        WOLFSSL_MSG("Bad parameters");
    }
    else if (stack->hash_fn == NULL) {
        WOLFSSL_MSG("No hash function defined");
    }
    else {
        /* Calculate hassh of data we are looking for. */
        hash = stack->hash_fn(data);

        while (stack != NULL) {
            /* Calculate hash if not done so yet. */
            if (!stack->hash) {
                sk_data = wolfssl_sk_node_get_data(stack, 0);
                stack->hash = stack->hash_fn(sk_data);
            }
            /* Return data if hash matches. */
            if (stack->hash == hash) {
                if (sk_data == NULL) {
                    sk_data = wolfssl_sk_node_get_data(stack, 0);
                }
                break;
            }

            /* Not data to return. */
            sk_data = NULL;
            stack = stack->next;
        }
    }

    return sk_data;
}
#endif /* !NO_CERTS && OPENSSL_EXTRA && OPENSSL_ALL */

#endif /* !WOLFSSL_SSL_SK_INCLUDED */
