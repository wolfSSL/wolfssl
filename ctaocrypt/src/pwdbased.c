/* pwdbased.c
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
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


#ifndef NO_PWDBASED

#include "pwdbased.h"
#include "ctc_hmac.h"
#ifdef CYASSL_SHA512
    #include "sha512.h"
#endif
#ifdef NO_INLINE
    #include "misc.h"
#else
    #include "misc.c"
#endif



#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */


int PBKDF1(byte* output, const byte* passwd, int pLen, const byte* salt,
           int sLen, int iterations, int kLen, int hashType)
{
    Md5  md5;
    Sha  sha;
    int  hLen = (hashType == MD5) ? MD5_DIGEST_SIZE : SHA_DIGEST_SIZE;
    int  i;
    byte buffer[SHA_DIGEST_SIZE];  /* max size */

    if (hashType != MD5 && hashType != SHA)
        return -1;

    if (kLen > hLen)
        return -1;

    if (iterations < 1)
        return -1;

    if (hashType == MD5) {
        InitMd5(&md5);
        Md5Update(&md5, passwd, pLen);
        Md5Update(&md5, salt,   sLen);
        Md5Final(&md5,  buffer);
    }
    else {
        InitSha(&sha);
        ShaUpdate(&sha, passwd, pLen);
        ShaUpdate(&sha, salt,   sLen);
        ShaFinal(&sha,  buffer);
    }

    for (i = 1; i < iterations; i++) {
        if (hashType == MD5) {
            Md5Update(&md5, buffer, hLen);
            Md5Final(&md5,  buffer);
        }
        else {
            ShaUpdate(&sha, buffer, hLen);
            ShaFinal(&sha,  buffer);
        }
    }
    XMEMCPY(output, buffer, kLen);

    return 0;
}


int PBKDF2(byte* output, const byte* passwd, int pLen, const byte* salt,
           int sLen, int iterations, int kLen, int hashType)
{
    word32 i = 1;
    int    hLen;
    int    j;
    Hmac   hmac;
    byte   buffer[INNER_HASH_SIZE];  /* max size */

    if (hashType == MD5) {
        hLen = MD5_DIGEST_SIZE;
    }
    else if (hashType == SHA) {
        hLen = SHA_DIGEST_SIZE;
    }
    else if (hashType == SHA256) {
        hLen = SHA256_DIGEST_SIZE;
    }
#ifdef CYASSL_SHA512
    else if (hashType == SHA512) {
        hLen = SHA512_DIGEST_SIZE;
    }
#endif
    else
        return -1;  /* bad HMAC hashType */

    HmacSetKey(&hmac, hashType, passwd, pLen);

    while (kLen) {
        int currentLen;
        HmacUpdate(&hmac, salt, sLen);

        /* encode i */
        for (j = 0; j < 4; j++) {
            byte b = i >> ((3-j) * 8);
            HmacUpdate(&hmac, &b, 1);
        }
        HmacFinal(&hmac, buffer);

        currentLen = min(kLen, hLen);
        XMEMCPY(output, buffer, currentLen);

        for (j = 1; j < iterations; j++) {
            HmacUpdate(&hmac, buffer, hLen);
            HmacFinal(&hmac, buffer);
            xorbuf(output, buffer, currentLen);
        }

        output += currentLen;
        kLen   -= currentLen;
        i++;
    }

    return 0;
}

#endif /* NO_PWDBASED */

