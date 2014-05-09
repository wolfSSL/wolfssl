/* pic32mz-hash.c
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

#include <cyassl/ctaocrypt/settings.h>

#ifdef CYASSL_PIC32MZ_HASH

#include <cyassl/ctaocrypt/logging.h>
#include <cyassl/ctaocrypt/md5.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/sha256.h>

#include <cyassl/ctaocrypt/port/pic32/pic32mz-crypt.h>

#if !defined(NO_MD5) && !defined(NO_SHA) && !defined(NO_SHA256)

static void reset_engine(pic32mz_desc *desc_l, int algo)
{
    pic32mz_desc *desc ;
    desc = KVA0_TO_KVA1(desc_l) ;

    CECON = 1 << 6;
    while (CECON);

    /* Make sure everything is clear first before we make settings. */
    XMEMSET((void *)KVA0_TO_KVA1(&desc->sa), 0, sizeof(desc->sa));
    XMEMSET((void *)KVA0_TO_KVA1(&desc->bd[0]), 0, sizeof(desc->bd[0]));
    XMEMSET((void *)KVA0_TO_KVA1(&desc->bd[1]), 0, sizeof(desc->bd[1]));

    /* Set up the security association */
    desc->sa.SA_CTRL.ALGO = algo ;
    desc->sa.SA_CTRL.LNC = 1;
    desc->sa.SA_CTRL.FB = 1;
    desc->sa.SA_CTRL.ENCTYPE = 1;
    desc->sa.SA_CTRL.LOADIV = 1;

    /* Set up the buffer descriptor */
    desc->err = 0 ;
    desc->bd[0].BD_CTRL.LAST_BD = 1;
    desc->bd[0].BD_CTRL.LIFM = 1;
    desc->bd[0].SA_ADDR = KVA_TO_PA(&desc->sa);
    desc->bd[1].BD_CTRL.LAST_BD = 1;
    desc->bd[1].BD_CTRL.LIFM = 1;
    desc->bd[1].SA_ADDR = KVA_TO_PA(&desc->sa);
    desc_l->bdCount = 0 ;
    CEBDPADDR = KVA_TO_PA(&(desc->bd[0]));

    CECON = 0x27;
}

#define PIC32MZ_IF_RAM(addr) (KVA_TO_PA(addr) < 0x80000)

static void update_engine(pic32mz_desc *desc_l, const char *input, word32 len,
                    word32 *hash)
{
    pic32mz_desc *desc ;
    int i ;
    int total ;
    desc = KVA0_TO_KVA1(desc_l) ;

    i = desc_l->bdCount ;
    if(i >= PIC32MZ_MAX_BD) {
        desc_l->err = 1 ;
        return ;
    }

    if(PIC32MZ_IF_RAM(input))
        XMEMCPY(KVA0_TO_KVA1(input), input, len) ; /* Sync phys with cache */
    desc->bd[i].SRCADDR = KVA_TO_PA(input);
    /* Finally, turn on the buffer descriptor */
    if (len % 4)
         desc->bd[i].BD_CTRL.BUFLEN = (len + 4) - (len % 4);
    else desc->bd[i].BD_CTRL.BUFLEN =  len ;

    if(i == 0) {
        desc->bd[i].MSGLEN =  len ;
        desc->bd[i].BD_CTRL.SA_FETCH_EN = 1;
    } else {
        desc->bd[i-1].NXTPTR  = KVA_TO_PA(&(desc->bd[i])) ;
        desc->bd[i].BD_CTRL.DESC_EN = 1;
        desc->bd[i-1].BD_CTRL.LAST_BD = 0 ;
        desc->bd[i-1].BD_CTRL.LIFM    = 0 ;
        total = desc->bd[i-1].MSGLEN + len ;
        desc->bd[i].MSGLEN = total ;
        desc->bd[i-1].MSGLEN = total ;
    }
    desc->bd[i].UPDPTR = KVA_TO_PA(hash);
    desc_l->bdCount ++ ;

    #ifdef DEBUG_CYASSL
    printf("Input[bd=%d, len=%d]:%x->\"%s\"\n", desc_l->bdCount, len, input, input) ;
    print_mem(input, len+4) ;
    #endif
}

static void start_engine(pic32mz_desc *desc) {
    bufferDescriptor *hash_bd[2] ;
    hash_bd[0] = (bufferDescriptor *)KVA0_TO_KVA1(&(desc->bd[0])) ;
    hash_bd[0]->BD_CTRL.DESC_EN = 1;
}

void wait_engine(pic32mz_desc *desc, char *hash, int hash_sz) {
    unsigned int i;
    unsigned int *intptr;
#undef DEBUG_CYASSL
    #ifdef DEBUG_CYASSL
    printf("desc(%x)[bd:%d * 2, sz:%d]\n", desc, sizeof(desc->bd[0]),
                                                 sizeof(desc->sa) );
    print_mem(KVA0_TO_KVA1(&(desc->bd[0])), sizeof(desc->bd[0])) ;
    print_mem(KVA0_TO_KVA1(&(desc->bd[1])), sizeof(desc->bd[0])) ;
    #endif

    WAIT_ENGINE ;
    
    XMEMCPY(hash, KVA0_TO_KVA1(hash), hash_sz) ;

    #ifdef DEBUG_CYASSL
    print_mem(KVA0_TO_KVA1(hash), hash_sz) ;
    print_mem(             hash , hash_sz) ;
    #endif
    for (i = 0, intptr = (unsigned int *)hash; i < hash_sz/sizeof(unsigned int);
                                                                  i++, intptr++)
    {
        *intptr = ntohl(*intptr);
    }
}

static int fillBuff(char *buff, int *bufflen, const char *data, int len, int blocksz)
{
    int room, copysz ;

    room = blocksz - *bufflen ;
    copysz = (len <= room) ? len : room ;
    XMEMCPY(buff, data, copysz) ;
    *bufflen += copysz ;
    return (*bufflen == blocksz) ? 1 : 0 ;
}

#endif

#ifndef NO_MD5
void InitMd5(Md5* md5)
{
    CYASSL_ENTER("InitMd5\n") ;
    XMEMSET((void *)md5, 0xcc, sizeof(Md5)) ;
    XMEMSET((void *)KVA0_TO_KVA1(md5), 0xcc, sizeof(Md5)) ;
    reset_engine(&(md5->desc), PIC32_ALGO_MD5) ;

}

void Md5Update(Md5* md5, const byte* data, word32 len)
{
     CYASSL_ENTER("Md5Update\n") ;
     update_engine(&(md5->desc), data, len, md5->digest) ;
}

void Md5Final(Md5* md5, byte* hash)
{
     CYASSL_ENTER("Md5Final\n") ;
    start_engine(&(md5->desc)) ;
    wait_engine(&(md5->desc), (char *)md5->digest, MD5_HASH_SIZE) ;
    XMEMCPY(hash, md5->digest, MD5_HASH_SIZE) ;
    InitMd5(md5);  /* reset state */
}
#endif

#ifndef NO_SHA
int InitSha(Sha* sha)
{
    CYASSL_ENTER("InitSha\n") ;
    XMEMSET((void *)sha, 0xcc, sizeof(Sha)) ;
    XMEMSET((void *)KVA0_TO_KVA1(sha), 0xcc, sizeof(Sha)) ;
    reset_engine(&(sha->desc), PIC32_ALGO_SHA1) ;
    return 0;
}

int ShaUpdate(Sha* sha, const byte* data, word32 len)
{
    CYASSL_ENTER("ShaUpdate\n") ;
    update_engine(&(sha->desc), data, len, sha->digest) ;
    return 0;
}

int ShaFinal(Sha* sha, byte* hash)
{
    CYASSL_ENTER("ShaFinal\n") ;
    start_engine(&(sha->desc)) ;
    wait_engine(&(sha->desc), (char *)sha->digest, SHA1_HASH_SIZE) ;
    XMEMCPY(hash, sha->digest, SHA1_HASH_SIZE) ;

    InitSha(sha);  /* reset state */
    return 0;
}
#endif /* NO_SHA */

#ifndef NO_SHA256
int InitSha256(Sha256* sha256)
{
    CYASSL_ENTER("InitSha256\n") ;
    XMEMSET((void *)sha256, 0xcc, sizeof(Sha256)) ;
    XMEMSET((void *)KVA0_TO_KVA1(sha256), 0xcc, sizeof(Sha256)) ;
    reset_engine(&(sha256->desc), PIC32_ALGO_SHA256) ;
    return 0;
}

int Sha256Update(Sha256* sha256, const byte* data, word32 len)
{
    CYASSL_ENTER("Sha256Update\n") ;
    update_engine(&(sha256->desc), data, len, sha256->digest) ;

    return 0;
}

int Sha256Final(Sha256* sha256, byte* hash)
{
    CYASSL_ENTER("Sha256Final\n") ;
    start_engine(&(sha256->desc)) ;
    wait_engine(&(sha256->desc), (char *)sha256->digest, SHA256_HASH_SIZE) ;
    XMEMCPY(hash, sha256->digest, SHA256_HASH_SIZE) ;
    InitSha256(sha256);  /* reset state */

    return 0;
}
#endif /* NO_SHA256 */

#endif



