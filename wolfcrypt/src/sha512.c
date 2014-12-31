/* sha512.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha512.h>

#if defined(WOLFSSL_SHA512) || defined(CYASSL_SHA512)

int wc_InitSha512(Sha512* sha)
{
    return InitSha512(sha);
}


int wc_Sha512Update(Sha512* sha, const byte* data, word32 len)
{
    return Sha512Update(sha, data, len);
}


int wc_Sha512Final(Sha512* sha, byte* out)
{
    return Sha512Final(sha, out);
}


int wc_Sha512Hash(const byte* data, word32 len, byte* out)
{
    return Sha512Hash(data, len, out);
}

#if defined(CYASSL_SHA384) || defined(WOLFSSL_SHA384) || defined(HAVE_AESGCM)

int wc_InitSha384(Sha384* sha)
{
    return InitSha384(sha);
}


int wc_Sha384Update(Sha384* sha, const byte* data, word32 len)
{
    return Sha384Update(sha, data, len);
}


int wc_Sha384Final(Sha384* sha, byte* out)
{
    return Sha384Final(sha, out);
}


int wc_Sha384Hash(const byte* data, word32 len, byte* out)
{
    return Sha384Hash(data, len, out);
}

#endif /* WOLFSSL_SHA384 */

#endif /* WOLFSSL_SHA512 */

