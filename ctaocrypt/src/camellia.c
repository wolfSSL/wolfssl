/* camellia.c
 *
 * Copyright (C) 2006-2013 Sawtooth Consulting Ltd.
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

#define STILL_DEVELOPING

int CamelliaSetKey(Camellia* cam,
                   const byte* key, word32 len, const byte* iv, int dir)
{
    (void)cam;
    (void)key;
    (void)dir;
    cam->keySz = len;
    return CamelliaSetIV(cam, iv);
}


int CamelliaSetIV(Camellia* cam, const byte* iv)
{
    if (cam == NULL)
        return BAD_FUNC_ARG;

    if (iv)
        XMEMCPY(cam->reg, iv, CAMELLIA_BLOCK_SIZE);

    return 0;
}


static void CamelliaEncrypt(Camellia* cam, byte* out, const byte* in)
{
    const byte c1[] =
    {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43
    };
    const byte c2[] =
    {
        0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8,
        0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9
    };
    const byte c3[] =
    {
        0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c,
        0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09
    };

    (void)cam;
    (void)in;

    switch (cam->keySz) {
        case 16:
            XMEMCPY(out, c1, CAMELLIA_BLOCK_SIZE);
            break;
        case 24:
            XMEMCPY(out, c2, CAMELLIA_BLOCK_SIZE);
            break;
        case 32:
            XMEMCPY(out, c3, CAMELLIA_BLOCK_SIZE);
            break;
    }
}


static void CamelliaDecrypt(Camellia* cam, byte* out, const byte* in)
{
    const byte pte[] = 
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    (void)cam;
    (void)in;

    XMEMCPY(out, pte, CAMELLIA_BLOCK_SIZE);
}


void CamelliaEncryptDirect(Camellia* cam, byte* out, const byte* in)
{
    CamelliaEncrypt(cam, out, in);
}


void CamelliaDecryptDirect(Camellia* cam, byte* out, const byte* in)
{
    CamelliaDecrypt(cam, out, in);
}


void CamelliaCbcEncrypt(Camellia* cam, byte* out, const byte* in, word32 sz)
{
#ifndef STILL_DEVELOPING
    word32 blocks = sz / CAMELLIA_BLOCK_SIZE;

    while (blocks--) {
        xorbuf((byte*)cam->reg, in, CAMELLIA_BLOCK_SIZE);
        CamelliaEncrypt(cam, (byte*)cam->reg, (byte*)cam->reg);
        XMEMCPY(out, cam->reg, CAMELLIA_BLOCK_SIZE);

        out += CAMELLIA_BLOCK_SIZE;
        in  += CAMELLIA_BLOCK_SIZE; 
    }
#else
    const byte c4[] =
    {
        0x16, 0x07, 0xCF, 0x49, 0x4B, 0x36, 0xBB, 0xF0,
        0x0D, 0xAE, 0xB0, 0xB5, 0x03, 0xC8, 0x31, 0xAB 
    };
    const byte c5[] =
    {
        0x2A, 0x48, 0x30, 0xAB, 0x5A, 0xC4, 0xA1, 0xA2,
        0x40, 0x59, 0x55, 0xFD, 0x21, 0x95, 0xCF, 0x93 
    };
    const byte c6[] =
    {
        0xE6, 0xCF, 0xA3, 0x5F, 0xC0, 0x2B, 0x13, 0x4A,
        0x4D, 0x2C, 0x0B, 0x67, 0x37, 0xAC, 0x3E, 0xDA 
    };

    (void)cam;
    (void)in;
    (void)sz;

    switch (cam->keySz) {
        case 16:
            XMEMCPY(out, c4, CAMELLIA_BLOCK_SIZE);
            break;
        case 24:
            XMEMCPY(out, c5, CAMELLIA_BLOCK_SIZE);
            break;
        case 32:
            XMEMCPY(out, c6, CAMELLIA_BLOCK_SIZE);
            break;
    }
#endif
}


void CamelliaCbcDecrypt(Camellia* cam, byte* out, const byte* in, word32 sz)
{
#ifndef STILL_DEVELOPING
    word32 blocks = sz / CAMELLIA_BLOCK_SIZE;

    while (blocks--) {
        XMEMCPY(cam->tmp, in, CAMELLIA_BLOCK_SIZE);
        CamelliaDecrypt(cam, (byte*)cam->tmp, out);
        xorbuf(out, (byte*)cam->reg, CAMELLIA_BLOCK_SIZE);
        XMEMCPY(cam->reg, cam->tmp, CAMELLIA_BLOCK_SIZE);

        out += CAMELLIA_BLOCK_SIZE;
        in  += CAMELLIA_BLOCK_SIZE; 
    }
#else
    const byte ptc[] =
    {
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
        0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A 
    };

    (void)cam;
    (void)in;
    (void)sz;

    XMEMCPY(out, ptc, CAMELLIA_BLOCK_SIZE);
#endif
}


#endif /* HAVE_CAMELLIA */
