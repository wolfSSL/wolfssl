/* compress.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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


#ifdef HAVE_LIBZ


#include <cyassl/ctaocrypt/compress.h>
#include <cyassl/ctaocrypt/error.h>
#include <cyassl/ctaocrypt/logging.h>
#ifdef NO_INLINE
    #include <cyassl/ctaocrypt/misc.h>
#else
    #include <ctaocrypt/src/misc.c>
#endif


int Compress(byte* out, word32 outSz, const byte* in, word32 inSz, word32 flags)
/*
 * out - pointer to destination buffer
 * outSz - size of destination buffer
 * in - pointer to source buffer to compress
 * inSz - size of source to compress
 * flags - flags to control how compress operates 
 *
 * return:
 *    negative - error code
 *    positive - bytes stored in out buffer
 * 
 * Note, the output buffer still needs to be larger than the input buffer.
 * The right chunk of data won't compress at all, and the lookup table will
 * add to the size of the output. The libz code says the compressed
 * buffer should be srcSz + 0.1% + 12.
 */
{
    word32 copySz = outSz <= inSz ? outSz : inSz;
    (void)flags;
    XMEMMOVE(out, in, copySz);

    return (int)copySz;
}


int DeCompress(byte* out, word32 outSz, const byte* in, word32 inSz)
{
    word32 copySz = outSz <= inSz ? outSz : inSz;
    XMEMMOVE(out, in, copySz);

    return (int)copySz;
}


#endif /* HAVE_LIBZ */

