/* sha256.c
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


/* code submitted by raphael.huck@efixo.com */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>

#if !defined(NO_SHA256)

int wc_InitSha256(Sha256* sha)
{
    return InitSha256(sha);
}


int wc_Sha256Update(Sha256* sha, const byte* data, word32 len)
{
    return Sha256Update(sha, data, len);    
}


int wc_Sha256Final(Sha256* sha, byte* out)
{
    return Sha256Final(sha, out);
}


int wc_Sha256Hash(const byte* data, word32 len, byte* out)
{
    return Sha256Hash(data, len, out);
}

#endif

