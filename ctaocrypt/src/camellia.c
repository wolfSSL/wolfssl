/* aes.c
 *
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef HAVE_CAMELLIA

#include <cyassl/ctaocrypt/camellia.h>
#include <cyassl/ctaocrypt/error.h>
#include <cyassl/ctaocrypt/logging.h>
#ifdef NO_INLINE
    #include <cyassl/ctaocrypt/misc.h>
#else
    #include <ctaocrypt/src/misc.c>
#endif


int CamelliaSetKey(Camellia* cam,
                   const byte* key, word32 len, const byte* iv, int dir)
{
    (void)cam;
    (void)key;
    (void)len;
    (void)iv;
    (void)dir;
    return 0;
}


void CamelliaEncrypt(Camellia* cam, byte* out, const byte* in, word32 sz)
{
    (void)cam;
    (void)out;
    (void)in;
    (void)sz;
}


void CamelliaDecrypt(Camellia* cam, byte* out, const byte* in, word32 sz)
{
    (void)cam;
    (void)out;
    (void)in;
    (void)sz;
}


void CamelliaCbcEncrypt(Camellia* cam, byte* out, const byte* in, word32 sz)
{
    (void)cam;
    (void)out;
    (void)in;
    (void)sz;
}


void CamelliaCbcDecrypt(Camellia* cam, byte* out, const byte* in, word32 sz)
{
    (void)cam;
    (void)out;
    (void)in;
    (void)sz;
}


#endif /* HAVE_CAMELLIA */
