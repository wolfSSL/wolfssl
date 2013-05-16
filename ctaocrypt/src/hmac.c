/* hmac.c
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

#include <cyassl/ctaocrypt/settings.h>

#ifndef NO_HMAC

#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/error.h>


#ifdef HAVE_CAVIUM
    static void HmacCaviumFinal(Hmac* hmac, byte* hash);
    static void HmacCaviumUpdate(Hmac* hmac, const byte* msg, word32 length);
    static void HmacCaviumSetKey(Hmac* hmac, int type, const byte* key,
                                 word32 length);
#endif

static int InitHmac(Hmac* hmac, int type)
{
    hmac->innerHashKeyed = 0;
    hmac->macType = (byte)type;

    if (!(type == MD5 || type == SHA || type == SHA256 || type == SHA384
                      || type == SHA512))
        return BAD_FUNC_ARG;

    switch (type) {
        #ifndef NO_MD5
        case MD5:
            InitMd5(&hmac->hash.md5);
        break;
        #endif

        #ifndef NO_SHA
        case SHA:
            InitSha(&hmac->hash.sha);
        break;
        #endif
        
        #ifndef NO_SHA256
        case SHA256:
            InitSha256(&hmac->hash.sha256);
        break;
        #endif
        
        #ifdef CYASSL_SHA384
        case SHA384:
            InitSha384(&hmac->hash.sha384);
        break;
        #endif
        
        #ifdef CYASSL_SHA512
        case SHA512:
            InitSha512(&hmac->hash.sha512);
        break;
        #endif
        
        default:
        break;
    }

    return 0;
}


void HmacSetKey(Hmac* hmac, int type, const byte* key, word32 length)
{
    byte*  ip = (byte*) hmac->ipad;
    byte*  op = (byte*) hmac->opad;
    word32 i, hmac_block_size = 0;

#ifdef HAVE_CAVIUM
    if (hmac->magic == CYASSL_HMAC_CAVIUM_MAGIC)
        return HmacCaviumSetKey(hmac, type, key, length);
#endif

    InitHmac(hmac, type);

    switch (hmac->macType) {
        #ifndef NO_MD5
        case MD5:
        {
            hmac_block_size = MD5_BLOCK_SIZE;
            if (length <= MD5_BLOCK_SIZE) {
                XMEMCPY(ip, key, length);
            }
            else {
                Md5Update(&hmac->hash.md5, key, length);
                Md5Final(&hmac->hash.md5, ip);
                length = MD5_DIGEST_SIZE;
            }
        }
        break;
        #endif

        #ifndef NO_SHA
        case SHA:
        {
            hmac_block_size = SHA_BLOCK_SIZE;
            if (length <= SHA_BLOCK_SIZE) {
                XMEMCPY(ip, key, length);
            }
            else {
                ShaUpdate(&hmac->hash.sha, key, length);
                ShaFinal(&hmac->hash.sha, ip);
                length = SHA_DIGEST_SIZE;
            }
        }
        break;
        #endif

        #ifndef NO_SHA256
        case SHA256:
        {
    		hmac_block_size = SHA256_BLOCK_SIZE;
            if (length <= SHA256_BLOCK_SIZE) {
                XMEMCPY(ip, key, length);
            }
            else {
                Sha256Update(&hmac->hash.sha256, key, length);
                Sha256Final(&hmac->hash.sha256, ip);
                length = SHA256_DIGEST_SIZE;
            }
        }
        break;
        #endif

        #ifdef CYASSL_SHA384
        case SHA384:
        {
            hmac_block_size = SHA384_BLOCK_SIZE;
            if (length <= SHA384_BLOCK_SIZE) {
                XMEMCPY(ip, key, length);
            }
            else {
                Sha384Update(&hmac->hash.sha384, key, length);
                Sha384Final(&hmac->hash.sha384, ip);
                length = SHA384_DIGEST_SIZE;
            }
        }
        break;
        #endif

        #ifdef CYASSL_SHA512
        case SHA512:
        {
            hmac_block_size = SHA512_BLOCK_SIZE;
            if (length <= SHA512_BLOCK_SIZE) {
                XMEMCPY(ip, key, length);
            }
            else {
                Sha512Update(&hmac->hash.sha512, key, length);
                Sha512Final(&hmac->hash.sha512, ip);
                length = SHA512_DIGEST_SIZE;
            }
        }
        break;
        #endif

        default:
        break;
    }
    if (length < hmac_block_size)
        XMEMSET(ip + length, 0, hmac_block_size - length);

    for(i = 0; i < hmac_block_size; i++) {
        op[i] = ip[i] ^ OPAD;
        ip[i] ^= IPAD;
    }
}


static void HmacKeyInnerHash(Hmac* hmac)
{
    switch (hmac->macType) {
        #ifndef NO_MD5
        case MD5:
            Md5Update(&hmac->hash.md5, (byte*) hmac->ipad, MD5_BLOCK_SIZE);
        break;
        #endif

        #ifndef NO_SHA
        case SHA:
            ShaUpdate(&hmac->hash.sha, (byte*) hmac->ipad, SHA_BLOCK_SIZE);
        break;
        #endif

        #ifndef NO_SHA256
        case SHA256:
            Sha256Update(&hmac->hash.sha256,
                                         (byte*) hmac->ipad, SHA256_BLOCK_SIZE);
        break;
        #endif

        #ifdef CYASSL_SHA384
        case SHA384:
            Sha384Update(&hmac->hash.sha384,
                                         (byte*) hmac->ipad, SHA384_BLOCK_SIZE);
        break;
        #endif

        #ifdef CYASSL_SHA512
        case SHA512:
            Sha512Update(&hmac->hash.sha512,
                                         (byte*) hmac->ipad, SHA512_BLOCK_SIZE);
        break;
        #endif

        default:
        break;
    }

    hmac->innerHashKeyed = 1;
}


void HmacUpdate(Hmac* hmac, const byte* msg, word32 length)
{
#ifdef HAVE_CAVIUM
    if (hmac->magic == CYASSL_HMAC_CAVIUM_MAGIC)
        return HmacCaviumUpdate(hmac, msg, length);
#endif

    if (!hmac->innerHashKeyed)
        HmacKeyInnerHash(hmac);

    switch (hmac->macType) {
        #ifndef NO_MD5
        case MD5:
            Md5Update(&hmac->hash.md5, msg, length);
        break;
        #endif

        #ifndef NO_SHA
        case SHA:
            ShaUpdate(&hmac->hash.sha, msg, length);
        break;
        #endif

        #ifndef NO_SHA256
        case SHA256:
            Sha256Update(&hmac->hash.sha256, msg, length);
        break;
        #endif

        #ifdef CYASSL_SHA384
        case SHA384:
            Sha384Update(&hmac->hash.sha384, msg, length);
        break;
        #endif

        #ifdef CYASSL_SHA512
        case SHA512:
            Sha512Update(&hmac->hash.sha512, msg, length);
        break;
        #endif

        default:
        break;
    }

}


void HmacFinal(Hmac* hmac, byte* hash)
{
#ifdef HAVE_CAVIUM
    if (hmac->magic == CYASSL_HMAC_CAVIUM_MAGIC)
        return HmacCaviumFinal(hmac, hash);
#endif

    if (!hmac->innerHashKeyed)
        HmacKeyInnerHash(hmac);

    switch (hmac->macType) {
        #ifndef NO_MD5
        case MD5:
        {
            Md5Final(&hmac->hash.md5, (byte*) hmac->innerHash);

            Md5Update(&hmac->hash.md5, (byte*) hmac->opad, MD5_BLOCK_SIZE);
            Md5Update(&hmac->hash.md5,
                                     (byte*) hmac->innerHash, MD5_DIGEST_SIZE);

            Md5Final(&hmac->hash.md5, hash);
        }
        break;
        #endif

        #ifndef NO_SHA
        case SHA:
        {
            ShaFinal(&hmac->hash.sha, (byte*) hmac->innerHash);

            ShaUpdate(&hmac->hash.sha, (byte*) hmac->opad, SHA_BLOCK_SIZE);
            ShaUpdate(&hmac->hash.sha,
                                     (byte*) hmac->innerHash, SHA_DIGEST_SIZE);

            ShaFinal(&hmac->hash.sha, hash);
        }
        break;
        #endif

        #ifndef NO_SHA256
        case SHA256:
        {
            Sha256Final(&hmac->hash.sha256, (byte*) hmac->innerHash);

            Sha256Update(&hmac->hash.sha256,
                                (byte*) hmac->opad, SHA256_BLOCK_SIZE);
            Sha256Update(&hmac->hash.sha256,
                                (byte*) hmac->innerHash, SHA256_DIGEST_SIZE);

            Sha256Final(&hmac->hash.sha256, hash);
        }
        break;
        #endif

        #ifdef CYASSL_SHA384
        case SHA384:
        {
            Sha384Final(&hmac->hash.sha384, (byte*) hmac->innerHash);

            Sha384Update(&hmac->hash.sha384,
                                 (byte*) hmac->opad, SHA384_BLOCK_SIZE);
            Sha384Update(&hmac->hash.sha384,
                                 (byte*) hmac->innerHash, SHA384_DIGEST_SIZE);

            Sha384Final(&hmac->hash.sha384, hash);
        }
        break;
        #endif

        #ifdef CYASSL_SHA512
        case SHA512:
        {
            Sha512Final(&hmac->hash.sha512, (byte*) hmac->innerHash);

            Sha512Update(&hmac->hash.sha512,
                                 (byte*) hmac->opad, SHA512_BLOCK_SIZE);
            Sha512Update(&hmac->hash.sha512,
                                 (byte*) hmac->innerHash, SHA512_DIGEST_SIZE);

            Sha512Final(&hmac->hash.sha512, hash);
        }
        break;
        #endif

        default:
        break;
    }

    hmac->innerHashKeyed = 0;
}


#ifdef HAVE_CAVIUM

/* Initiliaze Hmac for use with Nitrox device */
int HmacInitCavium(Hmac* hmac, int devId)
{
    if (hmac == NULL)
        return -1;

    if (CspAllocContext(CONTEXT_SSL, &hmac->contextHandle, devId) != 0)
        return -1;

    hmac->keyLen  = 0;
    hmac->dataLen = 0;
    hmac->type    = 0;
    hmac->devId   = devId;
    hmac->magic   = CYASSL_HMAC_CAVIUM_MAGIC;
    hmac->data    = NULL;        /* buffered input data */
   
    hmac->innerHashKeyed = 0;

    return 0;
}


/* Free Hmac from use with Nitrox device */
void HmacFreeCavium(Hmac* hmac)
{
    if (hmac == NULL)
        return;

    CspFreeContext(CONTEXT_SSL, hmac->contextHandle, hmac->devId);
    hmac->magic = 0;
    XFREE(hmac->data, NULL, DYNAMIC_TYPE_CAVIUM_TMP);
    hmac->data = NULL;
}


static void HmacCaviumFinal(Hmac* hmac, byte* hash)
{
    word32 requestId;

    if (CspHmac(CAVIUM_BLOCKING, hmac->type, NULL, hmac->keyLen,
                (byte*)hmac->ipad, hmac->dataLen, hmac->data, hash, &requestId,
                hmac->devId) != 0) {
        CYASSL_MSG("Cavium Hmac failed");
    } 
    hmac->innerHashKeyed = 0;  /* tell update to start over if used again */
}


static void HmacCaviumUpdate(Hmac* hmac, const byte* msg, word32 length)
{
    word16 add = (word16)length;
    word32 total;
    byte*  tmp;

    if (length > CYASSL_MAX_16BIT) {
        CYASSL_MSG("Too big msg for cavium hmac");
        return;
    }

    if (hmac->innerHashKeyed == 0) {  /* starting new */
        hmac->dataLen        = 0;
        hmac->innerHashKeyed = 1;
    }

    total = add + hmac->dataLen;
    if (total > CYASSL_MAX_16BIT) {
        CYASSL_MSG("Too big msg for cavium hmac");
        return;
    }

    tmp = XMALLOC(hmac->dataLen + add, NULL,DYNAMIC_TYPE_CAVIUM_TMP);
    if (tmp == NULL) {
        CYASSL_MSG("Out of memory for cavium update");
        return;
    }
    if (hmac->dataLen)
        XMEMCPY(tmp, hmac->data,  hmac->dataLen);
    XMEMCPY(tmp + hmac->dataLen, msg, add);
        
    hmac->dataLen += add;
    XFREE(hmac->data, NULL, DYNAMIC_TYPE_CAVIUM_TMP);
    hmac->data = tmp;
}


static void HmacCaviumSetKey(Hmac* hmac, int type, const byte* key,
                             word32 length)
{
    hmac->macType = (byte)type;
    if (type == MD5)
        hmac->type = MD5_TYPE;
    else if (type == SHA)
        hmac->type = SHA1_TYPE;
    else if (type == SHA256)
        hmac->type = SHA256_TYPE;
    else  {
        CYASSL_MSG("unsupported cavium hmac type");
    }

    hmac->innerHashKeyed = 0;  /* should we key Startup flag */

    hmac->keyLen = (word16)length;
    /* store key in ipad */
    XMEMCPY(hmac->ipad, key, length);
}

#endif /* HAVE_CAVIUM */

#endif /* NO_HMAC */

