/* test_ssl_misc_whitebox.c
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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#if defined(__linux__) && !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)

#include <stdio.h>

static int failSeek = -1;
static int shortRead;

static int test_fseek(FILE* file, long offset, int whence)
{
    if (whence == failSeek)
        return -1;
    return fseek(file, offset, whence);
}

static size_t test_fread(void* buf, size_t size, size_t count, FILE* file)
{
    if (shortRead && count > 0)
        count--;
    return fread(buf, size, count, file);
}

#undef XFSEEK
#undef XFREAD
#define XFSEEK test_fseek
#define XFREAD test_fread
#include <src/ssl.c>

int main(void)
{
    static const char path[] = "./certs/ca-cert.der";
    FILE* file = fopen(path, "rb");
    StaticBuffer content;
#ifndef WOLFSSL_SMALL_STACK
    byte buffer[256];
#endif
    long size = 0;
    int failed = 0;

    if (file == NULL)
        return 1;
    if (wolfssl_file_len(NULL, &size) != WOLFSSL_BAD_FILE)
        failed = 1;
    if (wolfssl_file_len(file, &size) != 0 || size <= 0 || ftell(file) != 0)
        failed = 1;

    failSeek = SEEK_END;
    if (wolfssl_file_len(file, &size) != WOLFSSL_BAD_FILE)
        failed = 1;
    failSeek = SEEK_SET;
    if (wolfssl_file_len(file, &size) != WOLFSSL_BAD_FILE)
        failed = 1;
    failSeek = -1;
    fclose(file);

#ifdef WOLFSSL_SMALL_STACK
    static_buffer_init(&content);
#else
    static_buffer_init(&content, buffer, (word32)sizeof(buffer));
#endif
    if (wolfssl_read_file_static(NULL, &content, NULL, DYNAMIC_TYPE_FILE,
            &size) != WOLFSSL_BAD_FILE)
        failed = 1;
    if (wolfssl_read_file_static("./certs/no-such-file.der", &content, NULL,
            DYNAMIC_TYPE_FILE, &size) != WOLFSSL_BAD_FILE)
        failed = 1;
    if (wolfssl_read_file_static(path, &content, NULL, DYNAMIC_TYPE_FILE,
            &size) != 0 || size <= 0)
        failed = 1;
    static_buffer_free(&content, NULL, DYNAMIC_TYPE_FILE);

#ifdef WOLFSSL_SMALL_STACK
    static_buffer_init(&content);
#else
    static_buffer_init(&content, buffer, (word32)sizeof(buffer));
#endif
    shortRead = 1;
    if (wolfssl_read_file_static(path, &content, NULL, DYNAMIC_TYPE_FILE,
            &size) != WOLFSSL_BAD_FILE)
        failed = 1;
    shortRead = 0;
    static_buffer_free(&content, NULL, DYNAMIC_TYPE_FILE);

    if (failed)
        puts("ssl_misc white-box: unexpected file I/O result");
    return failed;
}

#else
int main(void)
{
    return 0;
}
#endif
