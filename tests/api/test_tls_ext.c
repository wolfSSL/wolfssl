/* test_tls_ems.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <tests/unit.h>
#include <tests/api/test_tls_ext.h>

int test_wolfSSL_DisableExtendedMasterSecret(void)
{
    EXPECT_DECLS;
#if defined(HAVE_EXTENDED_MASTER) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    ExpectNotNull(ctx);
    ExpectNotNull(ssl);

    /* error cases */
    ExpectIntNE(WOLFSSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(NULL));
    ExpectIntNE(WOLFSSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(NULL));

    /* success cases */
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(ctx));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(ssl));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}
