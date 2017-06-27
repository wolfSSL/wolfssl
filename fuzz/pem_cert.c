/* pem_cert.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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

#include <stdlib.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* testing wolfSSL_CTX_use_certificate_buffer with PEM as the filetype*/

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz)
{
    WOLFSSL_CTX *ctx;
    int          ret;

    wolfSSL_Init();

    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());

    wolfSSL_CTX_load_verify_buffer(ctx, data, sz, SSL_FILETYPE_PEM);

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
