/* dtls13.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

#ifdef WOLFSSL_DTLS13

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

WOLFSSL_METHOD* wolfDTLSv1_3_client_method_ex(void* heap)
{
    WOLFSSL_METHOD* method;

    WOLFSSL_ENTER("DTLSv1_3_client_method_ex");

    method = (WOLFSSL_METHOD*)XMALLOC(sizeof(WOLFSSL_METHOD), heap,
        DYNAMIC_TYPE_METHOD);
    if (method)
        InitSSL_Method(method, MakeDTLSv1_3());

    return method;
}

WOLFSSL_METHOD* wolfDTLSv1_3_server_method_ex(void* heap)
{
    WOLFSSL_METHOD* method;

    WOLFSSL_ENTER("DTLSv1_3_server_method_ex");

    method = (WOLFSSL_METHOD*)XMALLOC(sizeof(WOLFSSL_METHOD), heap,
        DYNAMIC_TYPE_METHOD);
    if (method) {
        InitSSL_Method(method, MakeDTLSv1_3());
        method->side = WOLFSSL_SERVER_END;
    }

    return method;
}

WOLFSSL_METHOD* wolfDTLSv1_3_client_method(void)
{
    return wolfDTLSv1_3_client_method_ex(NULL);
}

WOLFSSL_METHOD* wolfDTLSv1_3_server_method(void)
{
    return wolfDTLSv1_3_server_method_ex(NULL);
}

#endif /* WOLFSSL_DTLS13 */
