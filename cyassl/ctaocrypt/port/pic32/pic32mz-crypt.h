/* pic32mz-crypt.h
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

#ifndef PIC32MZ_CRYPT_H
#define PIC32MZ_CRYPT_H

#ifdef  CYASSL_PIC32MZ_CRYPT

#define MICROCHIP_PIC32
#include <xc.h>
#include <sys/endian.h>
#include <sys/kmem.h>
#include "../../../../mplabx/crypto.h"


#define PIC32_ENCRYPTION      0b1
#define PIC32_DECRYPTION      0b0

#define PIC32_ALGO_HMAC1     0b01000000
#define PIC32_ALGO_SHA256    0b00100000
#define PIC32_ALGO_SHA1      0b00010000
#define PIC32_ALGO_MD5       0b00001000
#define PIC32_ALGO_AES       0b00000100
#define PIC32_ALGO_TDES      0b00000010
#define PIC32_ALGO_DES       0b00000001

#define PIC32_CRYPTOALGO_AES_GCM 0b1110
#define PIC32_CRYPTOALGO_RCTR    0b1101
#define PIC32_CRYPTOALGO_RCBC    0b1001
#define PIC32_CRYPTOALGO_REBC    0b1000
#define PIC32_CRYPTOALGO_TCBC    0b0101
#define PIC32_CRYPTOALGO_CBC     0b0001

#define PIC32_AES_KEYSIZE_256     0b10
#define PIC32_AES_KEYSIZE_192     0b01
#define PIC32_AES_KEYSIZE_128     0b00

#define PIC32_AES_BLOCK_SIZE 16
#define MD5_HASH_SIZE 16
#define SHA1_HASH_SIZE 20
#define SHA256_HASH_SIZE 32
#define PIC32_HASH_SIZE 32

#define PIC32MZ_MAX_BD   2
typedef struct {      /* Crypt Engine descripter */
    int bdCount ;
    int err   ;
    volatile bufferDescriptor 
        bd[PIC32MZ_MAX_BD] __attribute__((aligned (8), coherent));
    securityAssociation 
        sa                 __attribute__((aligned (8), coherent));
} pic32mz_desc ;

#define PIC32MZ_IF_RAM(addr) (KVA_TO_PA(addr) < 0x80000)

#define WAIT_ENGINE \
    { volatile int v ; while (CESTATbits.ACTIVE) ; for(v=0; v<100; v++) ; }

#ifdef DEBUG_CYASSL
static void print_mem(const unsigned char *p, int size) {
    for(; size>0; size--, p++) {
        if(size%4 == 0)printf(" ") ;
            printf("%02x", (int)*p) ;
    }
    puts("") ;
}
#endif

#endif
#endif /* PIC32MZ_CRYPT_H */
