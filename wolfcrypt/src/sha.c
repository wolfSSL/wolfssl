/* sha.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
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

#if !defined(NO_SHA)

#ifdef HAVE_FIPS
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS
#endif

#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #include <wolfcrypt/src/misc.c>
#endif

int wc_InitSha(Sha* sha)
{
    return InitSha(sha);
}

int wc_ShaUpdate(Sha* sha, const byte* data, word32 len)
{
    return ShaUpdate(sha, data, len);
}

int wc_ShaFinal(Sha* sha, byte* hash)
{
    return ShaFinal(sha, hash);
}


int wc_ShaHash(const byte* data, word32 len, byte* hash)
{
    return ShaHash(data, len, hash);
}


/* fips wrapper calls, user can call direct */
#ifdef HAVE_FIPS
	int wc_InitSha_fips(Sha* sha)
	{
	    return InitSha_fips(sha);
	}
	
	
	int wc_ShaUpdate_fips(Sha* sha, const byte* data, word32 len)
	{
	    return ShaUpdate_fips(sha, data, len);
	}
	
	
	int wc_ShaFinal_fips(Sha* sha, byte* out)
	{
	    return ShaFinal_fips(sha,out);
	}
#endif /* HAVE_FIPS */
#endif /* NO_SHA */

