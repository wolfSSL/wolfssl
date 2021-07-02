/* tlsx_base.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/tlsx_base.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>

#ifdef HAVE_TLS_EXTENSIONS

/* XXX: Calls to TLSX_FreeAll() are upcalls into src/tls.c
 *      Suggested solution: modify TLSX_Push(), TLSX_Prepend(), TLSX_Remove()
 *      to take extra param of the free func to call for duplicate extension.
 *      (and replace TLSX_FreeAll() use in the functions in this file)
 * To balance TLSX_New(), could implement TLSX_Delete() as:
 * TLSX_Delete (void *extension, void *head, void(*free_fn)(void *, void *))
 * {
 *    if (free_fn) free_fn(extension->data, heap);
 *    XFREE(extension, heap, DYNAMIC_TYPE_TLSX);
 * }
 */
/*void TLSX_FreeAll(TLSX* list, void* heap);*//*<wolfssl/internal.h>*/

/** Creates a new extension. */
static TLSX* TLSX_New(TLSX_Type type, const void* data, void* heap)
{
    TLSX* extension = (TLSX*)XMALLOC(sizeof(TLSX), heap, DYNAMIC_TYPE_TLSX);

    (void)heap;

    if (extension) {
        extension->type = type;
        extension->data = (void *)data;
        extension->resp = 0;
        extension->next = NULL;
    }

    return extension;
}

/**
 * Creates a new extension and pushes it to the provided list.
 * Checks for duplicate extensions, keeps the newest.
 */
int TLSX_Push(TLSX** list, TLSX_Type type, const void* data, void* heap)
{
    TLSX* extension = TLSX_New(type, data, heap);

    if (extension == NULL)
        return MEMORY_E;

    /* pushes the new extension on the list. */
    extension->next = *list;
    *list = extension;

    /* remove duplicate extensions, there should be only one of each type. */
    do {
        if (extension->next && extension->next->type == type) {
            TLSX *next = extension->next;

            extension->next = next->next;
            next->next = NULL;

            TLSX_FreeAll(next, heap);

            /* there is no way to occur more than
             * two extensions of the same type.
             */
            break;
        }
    } while ((extension = extension->next));

    return 0;
}

#ifdef WOLFSSL_TLS13

/**
 * Creates a new extension and prepend it to the provided list.
 * Checks for duplicate extensions, keeps the newest.
 */
int TLSX_Prepend(TLSX** list, TLSX_Type type, void* data, void* heap)
{
    TLSX* extension = TLSX_New(type, data, heap);
    TLSX* curr = *list;

    if (extension == NULL)
        return MEMORY_E;

    /* remove duplicate extensions, there should be only one of each type. */
    while (curr && curr->next) {
        if (curr->next->type == type) {
            TLSX *next = curr->next;

            curr->next = next->next;
            next->next = NULL;

            TLSX_FreeAll(next, heap);
        }
        curr = curr->next;
    }

    if (curr)
        curr->next = extension;
    else
        *list = extension;

    return 0;
}

#endif /* WOLFSSL_TLS13 */

#ifndef NO_WOLFSSL_CLIENT

int TLSX_CheckUnsupportedExtension(WOLFSSL* ssl, TLSX_Type type)
{
    TLSX *extension = TLSX_Find(ssl->extensions, type);

    if (!extension)
        extension = TLSX_Find(ssl->ctx->extensions, type);

    return extension == NULL;
}

int TLSX_HandleUnsupportedExtension(WOLFSSL* ssl)
{
    SendAlert(ssl, alert_fatal, unsupported_extension);
    return UNSUPPORTED_EXTENSION;
}

#endif

/** Mark an extension to be sent back to the client. */
void TLSX_SetResponse(WOLFSSL* ssl, TLSX_Type type)
{
    TLSX *extension = TLSX_Find(ssl->extensions, type);

    if (extension)
        extension->resp = 1;
}

/** Finds an extension in the provided list. */
TLSX* TLSX_Find(TLSX* list, TLSX_Type type)
{
    TLSX* extension = list;

    while (extension && extension->type != type)
        extension = extension->next;

    return extension;
}

/** Remove an extension. */
void TLSX_Remove(TLSX** list, TLSX_Type type, void* heap)
{
    TLSX* extension = *list;
    TLSX** next = list;

    while (extension && extension->type != type) {
        next = &extension->next;
        extension = extension->next;
    }

    if (extension) {
        *next = extension->next;
        extension->next = NULL;
        TLSX_FreeAll(extension, heap);
    }
}

#endif /* HAVE_TLS_EXTENSIONS */
