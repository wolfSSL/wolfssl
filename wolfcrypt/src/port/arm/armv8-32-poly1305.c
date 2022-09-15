/* armv8-32-poly1305.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



/*****************************************************************

   This code can be built as a standalone application, the test
   code to support that is at the bottom of the file.  One of
   the test cases matches the test data in RFC 7539.  The 
   standalone test output is similar to RFC 7539.

   The poly1305 algorithm takes two inputs, they are as follows.
	1. the message data
	2. a 256 bit key
   The algorithm outputs a 16 byte authentication value.
  
   The 16 bytes are transmitted with the message.  
   The receiving side runs the poly1305 algorithm and 
   compares the 16 byte result on the receiving side to
   16 bytes sent with the message.  If the two 16 byte
   values match, then the message is authenticated.

   The poly1305 algorithm requires a unique 256 bit key
   for each message.  The sender and receiver keys must
   stay in sync. This means that a pseudo random key must 
   be generated on both sides using the same algorithm 
   and the same initial key.
  
   It is common to use the ChaCha20 algorithm to generate
   the pseudo random key.  The initial 256 bit key is normally
   shared during the setup up of the connection between 
   sender and receiver.	

   The 256 bit key is broken down into two 128 bit parts; 
   namely r and s.  In the algorithm, r is clamped, meaning
   certain bits are set to zero.  According to the RFC, r can
   remain the same between runs of the algorithm, but s must 
   always change.  Therefore the ChaCha20 solution mentioned 
   above could be used to generate a 128 bit or 256 bit unique
   key each time. 

   This code was compiled and tested with the following tool chain.

	gcc-arm-10.2-2020.11-aarch64-arm-none-linux-guneabihf

   The development environment was Ubunutu, image file
	
	libre-computer-aml-s905x-cc-ubuntu-bionic-mate-mali-4.19.55+-2019-06-24.img 

   In order the run the resulting executable the 32 bit libs must
   be added to the system.  The following commands accomplish this.

	sudo dpkg --add-architecture armhf
	sudo apt-get update
	sudo apt-get install libc6:armhf libstdc++6:armhf

*****************************************************************/


/* if building as a standalone to match the RFC 7539 
   Be sure to pass gcc "-D POLY1305_STAND_ALONE". */
#ifdef POLY1305_STAND_ALONE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef struct poly1305_struct
{
    unsigned r[5];
    unsigned h[5];
    unsigned finished;
} Poly1305;

#define WOLFSSL_ARMASM		1
/* leave __aarch64__ undefined */
//#define WOLFSSL_ARMASM_NO_NEON  1
#define POLY1305_VERBOSE 	1
#else

#ifdef WOLFSSL_ARMASM
#ifndef __aarch64__
/* these includes are technically not necessary */
#include <wolfssl/wolfcrypt/settings.h>

#include <stdint.h>
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/poly1305.h>
#include <stddef.h>

#endif
#endif

#endif


#ifdef WOLFSSL_ARMASM
#ifndef __aarch64__


/**********************************************************
  calculateRsquared	Take the input array of 5 26 bit
			values, and multiply it by itself
		        to create a squared result.
  r			input array of 5 26 bit values
  rsquared		output array of 5 26 bit values
**********************************************************/
void calculateRsquared(unsigned *r, unsigned *rsquared);
void calculateRsquared(unsigned *r, unsigned *rsquared)
{
	unsigned long long r_2_l[5];
	unsigned long long c;
	int i;

	/* d0 = h0 * r0 + h1 * 5*r4 + h2 * 5*r3 + h3 * 5*r2 + h4 * 5*r1 */
	/* d1 = h0 * r1 + h1 * r0   + h2 * 5*r4 + h3 * 5*r3 + h4 * 5*r2 */
	/* d2 = h0 * r2 + h1 * r1   + h2 * r0   + h3 * 5*r4 + h4 * 5*r3 */
	/* d3 = h0 * r3 + h1 * r2   + h2 * r1   + h3 * r0   + h4 * 5*r4 */
	/* d4 = h0 * r4 + h1 * r3   + h2 * r2   + h3 * r1   + h4 * r0   */

        r_2_l[0] = ((unsigned long long) r[0] * (unsigned long long) r[0] )
 	       + ((unsigned long long) r[1] * ((unsigned long long) r[4]) * 5) 
	       + ((unsigned long long) r[2] * ((unsigned long long) r[3]) * 5) 
	       + ((unsigned long long) r[3] * ((unsigned long long) r[2]) * 5) 
	       + ((unsigned long long) r[4] * ((unsigned long long) r[1]) * 5); 

        r_2_l[1] = ((unsigned long long) r[0] * (unsigned long long) r[1] )	 		       + ((unsigned long long) r[1] * (unsigned long long) r[0] ) 
	       + ((unsigned long long) r[2] * ((unsigned long long) r[4]) * 5) 
	       + ((unsigned long long) r[3] * ((unsigned long long) r[3]) * 5 ) 
	       + ((unsigned long long) r[4] * ((unsigned long long) r[2]) * 5 ); 

        r_2_l[2] = ((unsigned long long) r[0] * (unsigned long long) r[2] )	 		       + ((unsigned long long) r[1] * (unsigned long long) r[1] ) 
	       + ((unsigned long long) r[2] * (unsigned long long) r[0] ) 
	       + ((unsigned long long) r[3] * ((unsigned long long) r[4]) * 5 ) 
	       + ((unsigned long long) r[4] * ((unsigned long long) r[3]) * 5 ); 

        r_2_l[3] = ((unsigned long long) r[0] * (unsigned long long) r[3] )	 		       + ((unsigned long long) r[1] * (unsigned long long) r[2] ) 
	       + ((unsigned long long) r[2] * (unsigned long long) r[1] ) 
	       + ((unsigned long long) r[3] * (unsigned long long) r[0] ) 
	       + ((unsigned long long) r[4] * ((unsigned long long) r[4]) * 5 ); 

        r_2_l[4] = ((unsigned long long) r[0] * (unsigned long long) r[4] )	 		       + ((unsigned long long) r[1] * (unsigned long long) r[3] ) 
	       + ((unsigned long long) r[2] * (unsigned long long) r[2] ) 
	       + ((unsigned long long) r[3] * (unsigned long long) r[1] ) 
	       + ((unsigned long long) r[4] * (unsigned long long) r[0] ); 

        c = (r_2_l[0] >> 26); 
	r_2_l[0] = r_2_l[0] & 0x3ffffff;
        r_2_l[1] += c;

        c = (r_2_l[1] >> 26);
	r_2_l[1] = r_2_l[1] & 0x3ffffff;
        r_2_l[2] += c;     

        c = (r_2_l[2] >> 26);
	r_2_l[2] = r_2_l[2] & 0x3ffffff;
        r_2_l[3] += c;     

        c = (r_2_l[3] >> 26);
	r_2_l[3] = r_2_l[3] & 0x3ffffff;
        r_2_l[4] += c;     

        c = (r_2_l[4] >> 26);
	r_2_l[4] = r_2_l[4] & 0x3ffffff;
        r_2_l[0] += 5 * c;     

        r_2_l[1] += (r_2_l[0] >> 26);
	r_2_l[0] = r_2_l[0] & 0x3ffffff;

	for (i=0;i<5;++i)
		rsquared[i] = (unsigned) r_2_l[i];
}



/**********************************************************
  armv8_32_poly1305_blocks	This routine implements the 
			poly1305 algorithm.  The processing
			of the 16 byte pieces of the 
			message is implemented in assembly.
			Care was taken in implementing the
			assembly to optimize speed by 
			minimizing memory references as
			well as minimizing instructions.
			The poly1305 algorithm is implemented
			by using multiple 26 bit values 
			to represent the larger 16 byte and 
			17 byte numbers.  This is control
			register overflow during the 
			multiplications and subsequent 
			additions.  For more information
			reference the article NEON Cryto
			by Daniel Berstein and Peter
			Schwabe.
  ctx			poly1305 structure containing the r and
		 	h values broke into 26 bit pieces.
			The result of this routine is returned
			int the h array of 26 bit values.
  msgData		Message data to run the algorithm 
			against.
  keyData		256 bit key that is broken down 
			into the r and s subcomponents.
**********************************************************/
/* variable assembly code creates on stack */
#define BYTES_SP_OFF              20
#define HIBIT_LOCAL_SP_OFF        24

void armv8_32_poly1305_blocks(Poly1305* ctx, 
                              const unsigned char *msgData,
                              size_t msgDataLen);

/* WOLFSSL_ARMASM_NO_NEON is used in armv8-32-sha512-asm.S */
#ifdef WOLFSSL_ARMASM_NO_NEON2
void armv8_32_poly1305_blocks(Poly1305* ctx, 
                              const unsigned char *msgData,
                              size_t msgDataLen)
{
        /* these variables will be referenced via r7 in the assembly */
        unsigned r[5], *r_ptrLocal, h[5], *h_ptrLocal;
        unsigned msgDataOnStack = (unsigned)msgData;
        unsigned msgDataLenOnStack = msgDataLen;
        unsigned hibitOnStack = (ctx->finished) ? 0 : ((unsigned) 1 << 24);

        memcpy(r, ctx->r, 5 * sizeof(unsigned));
        memcpy(h, ctx->h, 5 * sizeof(unsigned));

        /* 32 bit pointer, this is necessary to pass the pointer value
           into the assembly code */
        r_ptrLocal = (unsigned *) r;
        h_ptrLocal = (unsigned *) h;

#ifdef POLY1305_VERBOSE
        int i;
        for (i=0;i<5;++i) printf("h%d %07X ", i, h[i]);
        printf("\n");

        printf("armv8_32_poly1305_blocks() data len %d\n", msgDataLen);
#endif

        __asm__ __volatile__ (
                ".align        8                                \n\t"
                
                /* valid registers are r0..r12, sp, lr, pc, cpsr, fpscr */
                
                /* now load the stored h, this should all zero */
                "LDR        r5, %[h_ptr]                        \n\t"
                "LDM        r5, { r6, r8, r9, r10, r11 }        \n\t"
                /* r6 = h0  r8 = h1  r9 = h2  r10 = h3  r11 = h4 */
        
                /* in some cases, r7 is used to reference the local variables 
                   on the stack; if -O2 is passed to gcc, the sp may used 
                        used to reference local variables. */
                "LDR        r0, %[bytes]                        \n\t"
                "LDR        r1, %[r_ptr]                        \n\t"
                "LDR        r2, %[hibit]                        \n\t"
                "LDR        r5, %[m]                            \n\t"

                "PUSH       { r7 }                              \n\t"
                "SUB        sp, #28                             \n\t"
                
                /* -O2 gcc parameters means r7 is not used for local
                   variables, but sp is used for local variables */
                /* free up r7 by moving variables referenced
                   via r7 to recently allocated stack space */
                "STR        r0, [sp, %[BYTES_STORE]]            \n\t"
                "STR        r2, [sp, %[HIBIT_LOCAL]]            \n\t"

                "LDM        r1, { r0, r1, r2, r3, r4 }          \n\t"
                "STM        sp, { r0, r1, r2, r3, r4 }          \n\t"

                "MOV        r7, r5                              \n\t"

        "armv8_32_poly1305_loop:                                \n\t"

                /* The poly1305 algorithm requires that a 01 byte 
                   be placed after the last byte of the block. */                 
                
                "LDR        r5, [sp, %[BYTES_STORE]]            \n\t"  /* mem 1 */
                "CMP        r5, #0                              \n\t"
                "BEQ        armv8_32_poly1305_done              \n\t"
                "SUBS       r5, r5, #16                         \n\t"
                
                /* branch for least likely case, may help with pipelining */
                /* ARMv8 uses predictive pipelining.  There is no way
                   to specify in the instruction encoding the more likely
                   case.  */
                "BLT        armv8_32_poly1305_last_block        \n\t"  

                /* this block is 16 bytes */
                "STR        r5, [sp, %[BYTES_STORE]]            \n\t"  /* mem 2 */

                /* load next 16 byte block of message */                
                "LDM        r7, { r0, r1, r2, r3 }              \n\t"  /* mem 3 */
                "ADD        r7, r7, #16                         \n\t"

                /* in RFC 7539, each block processed is prepended by
                     a byte of value 0x01.  In the wolfSSL implementation,
                   the setting of this value is based on the value found
                   in ctx->finish. To save a memory reference, this code
                   could be replicated one version adding the byte, one
                   version not. */

                /* This is byte 16, past the 128 bits of w19:w18:w17:w16 
                   Hence, update is done to h4. */  
                "LDR        r5, [sp, %[HIBIT_LOCAL]]            \n\t"  /* mem 4 */
                "ADD        r11, r11, r5                        \n\t"
                        
        "armv8_32_poly1305_done_01_byte_appended:               \n\t"

                "MOV        r5, #0x3FFFFFF                      \n\t"

                /* break data into 26 bit pieces. 
                   Bit offsets are 0, 26, 52, 78 and 104 */
                   
                /* h0 += r0 & 0x3FFFFFF; */
                "AND        r12, r0, r5                         \n\t"
                "ADD        r6, r6, r12                         \n\t"
                /* h1 += (r1:r0 >> 26) & 0x3FFFFFF */
                "LSR        r12, r0, #26                        \n\t"  /* 26 */
                "ADD        r12, r12, r1, LSL #6                \n\t"
                "AND        r12, r12, r5                        \n\t"
                "ADD        r8, r8, r12                         \n\t"
                /* h2 += (r2:r1 >> 20) & 0x3FFFFFF */
                "LSR        r12, r1, #20                        \n\t"  /* 20+32 = 52 */
                "ADD        r12, r12, r2, LSL #12               \n\t"
                "AND        r12, r12, r5                        \n\t"
                "ADD        r9, r9, r12                         \n\t"
                /* h3 += (r3:r2 >> 14) & 0x3FFFFFF */
                "LSR        r12, r2, #14                        \n\t"  /* 14+32+32 = 78 */
                "ADD        r12, r12, r3, LSL #18               \n\t"
                "AND        r12, r12, r5                        \n\t"
                "ADD        r10, r10, r12                       \n\t"
                /* h4 += r3 >> 8                   */
                "ADD        r11, r11, r3, LSR #8                \n\t"  /* 8+32+32+32 = 104 */

                /* pull in the 26 bit components of the r key */
                "LDM        sp, { r0, r1, r2, r3, r4 }          \n\t"   /* mem 5 */
                /* r0 = BED685  r1 = 3555502  r2 = 47C036  r3 = 1003949  r4 = 806D5 */
                
                "MOV        r5, #5                              \n\t"

        "checkRegs:                                             \n\t"
                /* d0 = h0 * r0 + h1 * 5*r4 + h2 * 5*r3 + h3 * 5*r2 + h4 * 5*r1 */
                /* d1 = h0 * r1 + h1 * r0   + h2 * 5*r4 + h3 * 5*r3 + h4 * 5*r2 */
                /* d2 = h0 * r2 + h1 * r1   + h2 * r0   + h3 * 5*r4 + h4 * 5*r3 */
                /* d3 = h0 * r3 + h1 * r2   + h2 * r1   + h3 * r0   + h4 * 5*r4 */
                /* d4 = h0 * r4 + h1 * r3   + h2 * r2   + h3 * r1   + h4 * r0   */

                /*  r14 is the link register, r13 is the sp */
                /*  r14:r12 = r6 * r0 + (r8 * r4 +  r9 * r3 +  r10 * r2 +  r11 * r1) * r5 */
                /*  r14:r12 = r6 * r1 +  r8 * r0 + (r9 * r4 +  r10 * r3 +  r11 * r2) * r5 */
                /*  r14:r12 = r6 * r2 +  r8 * r1 +  r9 * r0 + (r10 * r4 +  r11 * r3) * r5 */
                /*  r14:r12 = r6 * r3 +  r8 * r2 +  r9 * r1 +  r10 * r0 + (r11 * r4) * r5 */
                /*  r14:r12 = r6 * r4 +  r8 * r3 +  r9 * r2 +  r10 * r1 +  r11 * r0       */

                /* d4 */
                "UMULL      r12, r14, r6, r4                    \n\t"
                "UMLAL      r12, r14, r8, r3                    \n\t"
                "UMLAL      r12, r14, r9, r2                    \n\t"
                "UMLAL      r12, r14, r10, r1                   \n\t"
                "UMLAL      r12, r14, r11, r0                   \n\t"

                "PUSH       { r12, r14 }                        \n\t"   /* mem 6 */

                /* 8F852 C3AB3DA1 */

                /* d3 */
                "UMULL      r12, r14, r6, r3                    \n\t"
                "UMLAL      r12, r14, r8, r2                    \n\t"
                "UMLAL      r12, r14, r9, r1                    \n\t"
                "UMLAL      r12, r14, r10, r0                   \n\t"
                "MUL        r11, r11, r5                        \n\t"
                "UMLAL      r12, r14, r11, r4                   \n\t"

                "PUSH       { r12, r14 }                        \n\t"   /* mem 7 */

                /* C753B 56120E14 */

                /* d2 */
                "UMULL      r12, r14, r6, r2                    \n\t"
                "UMLAL      r12, r14, r8, r1                    \n\t"
                "UMLAL      r12, r14, r9, r0                    \n\t"
                "MUL        r10, r10, r5                        \n\t"
                "UMLAL      r12, r14, r10, r4                   \n\t"
                "UMLAL      r12, r14, r11, r3                   \n\t"

                "PUSH       { r12, r14 }                        \n\t"   /* mem 8 */

                /* 10019D F79AAF81 */

                /* d1 */
                "UMULL      r12, r14, r6, r1                    \n\t"
                "UMLAL      r12, r14, r8, r0                    \n\t"
                "MUL        r9, r9, r5                          \n\t"
                "UMLAL      r12, r14, r9, r4                    \n\t"
                "UMLAL      r12, r14, r10, r3                   \n\t"
                "UMLAL      r12, r14, r11, r2                   \n\t"

                "PUSH       { r12, r14 }                        \n\t"   /* mem 9 */

                /* D3993 E9038575 */

                /* d0 */
                "UMULL      r12, r14, r6, r0                    \n\t"
                "MUL        r8, r8, r5                          \n\t"
                "UMLAL      r12, r14, r8, r4                    \n\t"
                "UMLAL      r12, r14, r9, r3                    \n\t"
                "UMLAL      r12, r14, r10, r2                   \n\t"
                "UMLAL      r12, r14, r11, r1                   \n\t"

                /* 29DD73 07661C87 */


                /* registers r6, r8, r9, r10, r11 must be 
                   populated with above results after accounting 
                   for overflow past 26 bit. */

                /* doing d0 --> d1 --> d2 --> d3 --> d4 --> d1 -->d2 */

                "MOV        r5, #0x3FFFFFF                      \n\t"
                "AND        r6, r12, r5                         \n\t"   /* d0 */

                /* d0 overflow to d1 */
                "POP        { r0, r1, r2, r3, r4, r9, r10, r11 } \n\t"  /* mem 10 */

                "ADDS       r0, r0, r12, LSR #26                \n\t"
                "ADC        r1, r1, #0                          \n\t"
                "ADDS       r0, r0, r14, LSL #6                 \n\t"
                "ADC        r1, r1, #0                          \n\t"

                "AND        r8, r0, r5                          \n\t"   /* d1 */

                /* d1 overflow to d2 */

                "ADDS       r2, r2, r0, LSR #26                 \n\t"
                "ADC        r3, r3, #0                          \n\t"
                "ADDS       r2, r2, r1, LSL #6                  \n\t"
                "ADC        r3, r3, #0                          \n\t"

                "MOV        r0, r9                              \n\t"

                "AND        r9, r2, r5                          \n\t"   /* d2 */

                /* d2 overflow to d3 */

                "ADDS       r4, r4, r2, LSR #26                 \n\t"
                "ADC        r0, r0, #0                          \n\t"
                "ADDS       r4, r4, r3, LSL #6                  \n\t"
                "ADC        r0, r0, #0                          \n\t"

                /* d3 overflow to d4 */

                "ADDS       r10, r10, r4, LSR #26               \n\t"
                "ADC        r11, r11, #0                        \n\t"
                "ADDS       r10, r10, r0, LSL #6                \n\t"
                "ADC        r11, r11, #0                        \n\t"

                /* d4 overflow to d0, must be multiplied by 5 */        

                "LSR        r0, r10, #26                        \n\t"
                "ADD        r0, r0, r11, LSL #6                 \n\t"
                "MOV        r1, #5                              \n\t"        
                "MUL        r0, r0, r1                          \n\t"
                "ADD        r6, r6, r0                          \n\t"

                "AND        r11, r10, r5                        \n\t"   /* d4 */

                "AND        r10, r4, r5                         \n\t"   /* d3 */

                /* d0 overflow to d1 */

                "ADD        r8, r8, r6, LSR #26                 \n\t"   /* d1 done */

                "AND        r6, r6, r5                          \n\t"   /* d0 done */        

                "B          armv8_32_poly1305_loop              \n\t"
        
        "armv8_32_poly1305_last_block:                          \n\t"

                /* This is the last block of the message
                   and the block is less than 16 bytes */
                "MOV        r0, #0                              \n\t"
                "STR        r0, [sp, %[BYTES_STORE]]            \n\t"
        
                "LDR        r0, [sp, %[HIBIT_LOCAL]]            \n\t"

                /* Make sure the upper bytes of the 
                   32 bit pieces are set to zero. 
                   Set the byte past the last message
                   data byte to 01. */

                "PUSH       { r4, r6, r8 }                      \n\t"        

                "MOV        r1,  #0                             \n\t"
                "MOV        r2,  #0                             \n\t"
                "MOV        r3,  #0                             \n\t"
                "MOV        r4,  #0xFFFFFFFF                    \n\t"
                "LSR        r0, r0, #24                         \n\t"
                "MOV        r6,  r0                             \n\t"

                /* always going to load at least one */                
                "LDR        r0, [r7]                            \n\t"

                /* byte offset to bit offset */ 
                "ADD        r5, r5, #16                         \n\t"
                "LSL        r5, r5, #3                          \n\t"                        

                /* which block */
                "CMP        r5, #32                             \n\t"
                "BGE        not_word_0                          \n\t"

                /* case word 0 */
        "case0:"
                "LSL        r8, r4, r5                          \n\t"
                "BIC        r0, r0, r8                          \n\t"
                "LSL        r8, r6, r5                          \n\t"
                "ADD        r0, r0, r8                          \n\t"
                "B          last_block_done                     \n\t"

        "not_word_0:                                            \n\t"
                "LDR        r1, [r7, #4]                        \n\t"
                
                "SUB        r5, r5, #32                         \n\t"
                "CMP        r5, #32                             \n\t"
                "BGE        not_word_1                          \n\t"

                "LSL        r8, r4, r5                          \n\t"
                "BIC        r1, r1, r8                          \n\t"
                "LSL        r8, r6, r5                          \n\t"
                "ADD        r1, r1, r8                          \n\t"                
                "B          last_block_done                     \n\t"

        "not_word_1:                                            \n\t"
                "LDR        r2, [r7, #8]                        \n\t"

                "SUB        r5, r5, #32                         \n\t"
                "CMP        r5, #32                             \n\t"
                "BGE        not_word_2                          \n\t"

                "LSL        r8, r4, r5                          \n\t"
                "BIC        r2, r2, r8                          \n\t"
                "LSL        r8, r6, r5                          \n\t"
                "ADD        r2, r2, r8                          \n\t"                
                "B          last_block_done                     \n\t"

        "not_word_2:                                            \n\t"
                "LDR        r3, [r7, #0xC]                      \n\t"

                "SUB        r5, r5, #32                         \n\t"

                "LSL        r8, r4, r5                          \n\t"
                "BIC        r3, r3, r8                          \n\t"
                "LSL        r8, r6, r5                          \n\t"
                "ADD        r3, r3, r8                          \n\t"        

        "last_block_done:                                       \n\t"

                "POP        { r4, r6, r8 }                      \n\t"        
        
                "b          armv8_32_poly1305_done_01_byte_appended \n\t"
        
        "armv8_32_poly1305_done:                                \n\t"

                "ADD        sp, #28                             \n\t"
                "POP        { r7 }                              \n\t"

                /* store final result */
                "LDR        r0, %[h_ptr]                        \n\t"
                "STM        r0, { r6, r8, r9, r10, r11 }        \n\t"
                
                : [m]              "+m" (msgDataOnStack),        /* input */
                  [r_ptr]          "+m" (r_ptrLocal),            /* input */
                  [h_ptr]          "+m" (h_ptrLocal),            /* input, output */
                  [bytes]          "+m" (msgDataLenOnStack),     /* input */
                  [hibit]          "+m" (hibitOnStack)           /* input */
                  
                : [BYTES_STORE]    "I" (BYTES_SP_OFF),
                  [HIBIT_LOCAL]    "I" (HIBIT_LOCAL_SP_OFF)
                : "memory", "cc", 
                        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10",
                        "r11", "r12", "lr"
        );

        memcpy(ctx->r, r, 5 * sizeof(unsigned));
        memcpy(ctx->h, h, 5 * sizeof(unsigned));

#ifdef POLY1305_VERBOSE
        for (i=0;i<5;++i) printf("h%d %07X ", i, ctx->h[i]);
        printf("\n");

        printf("armv8_32_poly1305_blocks() leaving\n");
#endif

}

#else

void armv8_32_poly1305_blocks(Poly1305* ctx, 
			const unsigned char *msgData,
                     	size_t msgDataLen)
{
	unsigned r[5], *r_ptrLocal, h1[5], h2[5], *h1_ptrLocal;
	unsigned *h2_ptrLocal, *r2_ptrLocal;
	unsigned msgDataOnStack = (unsigned)msgData;
	unsigned msgDataLenOnStack = msgDataLen;
	/* 1 << 128 */
 	unsigned hibitOnStack = (ctx->finished) ? 0 : ((unsigned) 1 << 24); 
    	unsigned r_2[5];
	int i;

	memcpy(r, ctx->r, 5*sizeof(unsigned));

	if (msgDataLen <= 16)
	{
		memcpy(h1, ctx->h, 5*sizeof(unsigned));
		memset(h2, 0, 5*sizeof(unsigned));
	}
	else
	{
		memset(h1, 0, 5*sizeof(unsigned));
		memcpy(h2, ctx->h, 5*sizeof(unsigned));
	}

	calculateRsquared(r, r_2);

	/* 32 bit pointer, this is necessary to pass the pointer value
           into the assembly code */
	r_ptrLocal = (unsigned *) r;
 	r2_ptrLocal = r_2;
	h1_ptrLocal = (unsigned *) h1;
	h2_ptrLocal = (unsigned *) h2;

#ifdef POLY1305_VERBOSE
	int j;
	printf("armv8_32_poly1305_blocks() >> Before Assembly << ");
	printf("  length of data (%d) 0x%X\n\n", msgDataLen, msgDataLen);

	for (i=0;i<5;++i) 
		printf("h%d %08X ", i, h1[i]);
	printf("\n");

	printf(" r ");
	for (j=0;j<5;++j) 
		printf(" %d %08X ", j, r[j]);
	printf("\n");
	/* 00BED685  03555502  0047C036  01003949  000806D5 */
	
	printf(" r^2 ");
	for (j=0;j<5;++j) 
		printf(" %d %08X ", j, r_2[j]);
	printf("\n");
	
	/* CA0455  1DD847D  23C50AA  36BC0AC  19106A3 */
#endif

	__asm__ __volatile__ (
		".align	8	 				\n\t"

		/* valid registers are d0..d31 */

		/* load r values into d0..d4 */
		"LDR		r11, %[r_ptr]			\n\t"
		"LDM		r11, { r0, r1, r2, r3, r4 }	\n\t"

		"LDR		r11, %[r2_ptr]			\n\t"
		"LDM		r11, { r5, r6, r8, r9, r10 }	\n\t"

		"VMOV		s0, s1, r0, r5			\n\t"   /* d0 */
		"VMOV		s2, s3, r1, r6			\n\t"   /* d1 */
		"VMOV		s4, s5, r2, r8			\n\t"   /* d2 */
		"VMOV		s6, s7, r3, r9			\n\t"   /* d3 */
		"VMOV		s8, s9, r4, r10			\n\t"   /* d4 */

		"MOV		r0, #5				\n\t"
		"MUL		r1, r1, r0			\n\t"
		"MUL		r2, r2, r0			\n\t"
		"MUL		r3, r3, r0			\n\t"
		"MUL		r4, r4, r0			\n\t"

		"MUL		r6, r6, r0			\n\t"
		"MUL		r8, r8, r0			\n\t"
		"MUL		r9, r9, r0			\n\t"
		"MUL		r10, r10, r0			\n\t"

		"VMOV		s10, s11, r1, r6		\n\t"   /* d5 */
		"VMOV		s12, s13, r2, r8		\n\t"   /* d6 */
		"VMOV		s14, s15, r3, r9		\n\t"   /* d7 */
		"VMOV		s16, s17, r4, r10		\n\t"   /* d8 */
		
		/* load h values into d10..d15 */
		"LDR		r11, %[h_ptr1]			\n\t"
		"LDM		r11, { r0, r1, r2, r3, r4 }	\n\t"
		"LDR		r11, %[h_ptr2]			\n\t"
		"LDM		r11, { r5, r6, r8, r9, r10 }	\n\t"

		"VMOV		s18, s19, r0, r5		\n\t"   /* d9  */
		"VMOV		s20, s21, r1, r6		\n\t"   /* d10 */
		"VMOV		s22, s23, r2, r8		\n\t"   /* d11 */
		"VMOV		s24, s25, r3, r9		\n\t"   /* d12 */
		"VMOV		s26, s27, r4, r10		\n\t"   /* d13 */

		"VMOV		d24, d9				\n\t"
		"VMOV		d25, d10			\n\t"
		"VMOV		d26, d11			\n\t"
		"VMOV		d27, d12			\n\t"
		"VMOV		d28, d13			\n\t"
		"LDR		r1, %[m]			\n\t"
		"LDR		r2, %[bytes]			\n\t"
		"LDR		r3, %[hibit]			\n\t"

		"VMOV		s28, s29, r3, r3		\n\t"   /* d14 */
		"VMOV 		d29, d14 			\n\t"   /* d29 */

		"VMOV.i32	d30, #0x3FFFFFF			\n\t"
		"VSHR.u64	d30, #32			\n\t"

		"VMOV.i32	d27, #0x5			\n\t"
		"VSHR.u64	d27, #32			\n\t"

	"armv8_32_poly1305_loop:				\n\t"

		/* The poly1305 algorithm requires that a 01 byte 
		   be placed after the last byte of the block. */ 		

		"CMP		r2, #0				\n\t"
		"BEQ		armv8_32_poly1305_done		\n\t"
	
		/* branch for least likely case, may help with pipelining */
		/* ARMv8 uses predictive pipelining.  There is no way
		   to specify in the instruction encoding the more likely
		   case.  */
		"CMP		r2, #16				\n\t"
		"BLT		armv8_32_poly1305_last_block	\n\t"  

		"SUBS 		r2, r2, #16			\n\t"

		/* this block is 16 bytes */		

		/* load next 16 byte block of message */		
		"LDM		r1, { r4, r5, r6, r8 }		\n\t"
		"ADD		r1, r1, #16			\n\t"

		/* in RFC 7539, each block processed is prepended by
  		   a byte of value 0x01.  In the wolfSSL implementation,
		   the setting of this value is based on the value found
		   in ctx->finish. To save a memory reference, this code
		   could be replicated one version adding the byte, one
		   version not. */

		/* This is byte 16, past the 128 bits of 
		   Hence, update is done to h4. */  
	

	"armv8_32_poly1305_done_01_byte_appended:		\n\t"

		"CMP		r2, #0				\n\t"
		"BEQ		onlyOneBlock			\n\t"			

	"twoBlocks:						\n\t"
		/* r4 = 70797243  r5 = 72676F74  r6 = 69687061  r8 = 6F462063 */

		"VMOV		r9, s27				\n\t"
		"ADD		r9, r9, r3			\n\t"
		"VMOV		s27, r9				\n\t"

		"MOV	    r9, #0x3FFFFFF			\n\t"

              	/* h0 += r4 & 0x3FFFFFF; */
		"VMOV	    r10, s19				\n\t"	/* s19, s21 */
		"VMOV	    r11, s21				\n\t"

                "AND        r0, r4, r9                         \n\t"
                "ADD        r10, r10, r0                       \n\t"   /* 797243 */

                /* h1 += (r5:r4 >> 26) & 0x3FFFFFF */
                "LSR        r0, r4, #26                        \n\t"   /* 26 */
                "ADD        r0, r0, r5, LSL #6                \n\t"
                "AND        r0, r0, r9                        \n\t"
                "ADD        r11, r11, r0                       \n\t"   /* 1DBDD1C */
	
		"VMOV	    s19, r10				\n\t"
		"VMOV	    s21, r11				\n\t"	

                /* h2 += (r6:r5 >> 20) & 0x3FFFFFF */
		"VMOV	    r10, s23				\n\t"  /* s23, s25 */
		"VMOV	    r11, s25				\n\t"

                "LSR        r0, r5, #20                        \n\t"  /* 20+32 = 52 */
                "ADD        r0, r0, r6, LSL #12               \n\t"
                "AND        r0, r0, r9                        \n\t"
                "ADD        r10, r10, r0                       \n\t"  /* 3061726 */
                /* h3 += (r8:r6 >> 14) & 0x3FFFFFF */
                "LSR        r0, r6, #14                        \n\t"  /* 14+32+32 = 78 */
                "ADD        r0, r0, r8, LSL #18               \n\t"
                "AND        r0, r0, r9                        \n\t"
                "ADD        r11, r11, r0                       \n\t"  /* 18dA5A1 */

		"VMOV	    s23, r10				\n\t"
		"VMOV	    s25, r11				\n\t"

                /* h4 += r3 >> 8                   */
		"VMOV	    r10, s27				\n\t"
                "ADD        r10, r10, r8, LSR #8                \n\t"  /* 8+32+32+32 = 104 */
		"VMOV	    s27, r10				\n\t"  /* 16F4620 */

		/* s19 = 0797243  s21 = 1DBDD1C  s23 = 3061726  s25 = 18DA5A1  s27 = 16F4620 */
		
		"CMP	    r2, #16				\n\t"
		"BLT	    armv8_32_poly1305_last_block	\n\t"  

		/* FIX */
		"LDM	    r1, { r4, r5, r6, r8 }		\n\t"
		"ADD	    r1, r1, #16				\n\t"
		"SUBS 	    r2, r2, #16				\n\t"

	"onlyOneBlock:						\n\t"

		/* FIX must handle short blocks as well */
		/* FIX HIBIT */
		/* set hibit for a full size 16 byte block */
		"VMOV	    r9, s26				\n\t"
		"ADD	    r9, r9, r3				\n\t"
		"VMOV	    s26, r9				\n\t"

	"onlyOneBlock_hibit_set:				\n\t"

		"MOV	    r9, #0x3FFFFFF 			\n\t"

              	/* h0 += r4 & 0x3FFFFFF; */
		"VMOV	    r10, s18				\n\t"	/* s18, s20 */
		"VMOV	    r11, s20				\n\t"

                "AND        r0, r4, r9                         \n\t"
                "ADD        r10, r10, r0                       \n\t"

                /* h1 += (r5:r4 >> 26) & 0x3FFFFFF */
                "LSR        r0, r4, #26                        \n\t"   /* 26 */
                "ADD        r0, r0, r5, LSL #6                \n\t"
                "AND        r0, r0, r9                        \n\t"
                "ADD        r11, r11, r0                       \n\t"  
	
		"VMOV	    s18, r10				\n\t"
		"VMOV	    s20, r11				\n\t"	

                /* h2 += (r6:r5 >> 20) & 0x3FFFFFF */
		"VMOV	    r10, s22				\n\t"  /* s22, s24 */
		"VMOV	    r11, s24				\n\t"

                "LSR        r0, r5, #20                        \n\t"  /* 20+32 = 52 */
                "ADD        r0, r0, r6, LSL #12               \n\t"
                "AND        r0, r0, r9                        \n\t"
                "ADD        r10, r10, r0                       \n\t"  
                /* h3 += (r8:r6 >> 14) & 0x3FFFFFF */
                "LSR        r0, r6, #14                        \n\t"  /* 14+32+32 = 78 */
                "ADD        r0, r0, r8, LSL #18               \n\t"
                "AND        r0, r0, r9                        \n\t"
                "ADD        r11, r11, r0                       \n\t"  

		"VMOV	    s22, r10				\n\t"
		"VMOV	    s24, r11				\n\t"

                /* h4 += r3 >> 8                   */
		"VMOV	    r10, s26				\n\t"  /* s26 */
                "ADD        r10, r10, r8, LSR #8                \n\t"  /* 8+32+32+32 = 104 */
		"VMOV	    s26, r10				\n\t" 

		/* s18 = 06D7572  s20 = 0D95488  s22 = 3261657  s24 = 081A18D  s26 = 1746573 */

	"checkRegs:						\n\t"
		/* partial0 = h0 * r0 + h1 * 5*r4 + h2 * 5*r3 + h3 * 5*r2 + h4 * 5*r1 */
		/* partial1 = h0 * r1 + h1 * r0   + h2 * 5*r4 + h3 * 5*r3 + h4 * 5*r2 */
		/* partial2 = h0 * r2 + h1 * r1   + h2 * r0   + h3 * 5*r4 + h4 * 5*r3 */
		/* partial3 = h0 * r3 + h1 * r2   + h2 * r1   + h3 * r0   + h4 * 5*r4 */
		/* partial4 = h0 * r4 + h1 * r3   + h2 * r2   + h3 * r1   + h4 * r0   */

	
		/*  d15 = d9 * d0 +  d10 * d8 +  d11 * d7 +  d12 * d6 +  d13 * d5 */
		/*  d16 = d9 * d1 +  d10 * d0 +  d11 * d8 +  d12 * d7 +  d13 * d6 */
		/*  d17 = d9 * d2 +  d10 * d1 +  d11 * d0 +  d12 * d8 +  d13 * d7 */
		/*  d18 = d9 * d3 +  d10 * d2 +  d11 * d1 +  d12 * d0 +  d13 * d8 */
		/*  d19 = d9 * d4 +  d10 * d3 +  d11 * d2 +  d12 * d1 +  d13 * d0  */


		/* registers d15, d16, d17, d18, d19 contain the 
		   incremental d results. */


      		/* partial0 = q8 = d17:d16 */
		"VMULL.u32	q8,  d9, d0   			\n\t"
		"VMLAL.u32	q8, d10, d8   			\n\t"
		"VMLAL.u32	q8, d11, d7   			\n\t"
		"VMLAL.u32	q8, d12, d6   			\n\t"
		"VMLAL.u32	q8, d13, d5   			\n\t"
		/* 29DD73 07661C87 */

      		/* partial1 = q9 = d19:d18 */
		"VMULL.u32	q9,  d9, d1   			\n\t"
		"VMLAL.u32	q9, d10, d0   			\n\t"
		"VMLAL.u32	q9, d11, d8   			\n\t"
		"VMLAL.u32	q9, d12, d7   			\n\t"
		"VMLAL.u32	q9, d13, d6   			\n\t"
		/* D3993 E9038575 */

 		/* partial1 = q10 = d21:d20 */
		"VMULL.u32	q10,  d9, d2   			\n\t"
		"VMLAL.u32	q10, d10, d1   			\n\t"
		"VMLAL.u32	q10, d11, d0   			\n\t"
		"VMLAL.u32	q10, d12, d8   			\n\t"
		"VMLAL.u32	q10, d13, d7   			\n\t"
		/* 10019D F79AAF81 */

 		/* partial1 = q11 = d23:d22 */
		"VMULL.u32	q11,  d9, d3   			\n\t"
		"VMLAL.u32	q11, d10, d2   			\n\t"
		"VMLAL.u32	q11, d11, d1   			\n\t"
		"VMLAL.u32	q11, d12, d0   			\n\t"
		"VMLAL.u32	q11, d13, d8   			\n\t"
		/* C753B 56120E14 */

 		/* partial1 = q12 = d25:d24 */
		"VMULL.u32	q12,  d9, d4   			\n\t"
		"VMLAL.u32	q12, d10, d3   			\n\t"
		"VMLAL.u32	q12, d11, d2   			\n\t"
		"VMLAL.u32	q12, d12, d1   			\n\t"
		"VMLAL.u32	q12, d13, d0   			\n\t"
	        /* 8F852 C3AB3DA1 */

		/* message buff 1 times r 
		   d16 = 02929E2 D10FA341 
	 	   d18 = 0071FD6 14380FCE 
		   d20 = 00CA7F3 14E3B1DB 
		   d22 = 00BC46F BD0D158C  
		   d24 = 0048496 DE32A7D5 */

		/* message buff 2 times r squared 
		   d17 = 06165D0 CB2EA8BD 
		   d19 = 044A41C F0475619 
		   d21 = 02B9EA1 79EE3BD7 
                   d23 = 017E1B1 ED6D017F 
		   d25 = 011E440 9C3DCCF2 */

		/* doing d0 --> d1 --> d2 --> d3 --> d4 --> d1 -->d2 */
		
		/* d16 --> d18 --> d20 --> d22 --> d24 --> d16 --> d18 */

		/* d0 = d16 * 0x3FFFFF */
		"VAND.u64	d15, d16, d30			\n\t"  
		"VMOV 		s18, s30			\n\t"	/* d0 */

		/* d9 = 10FA341 value before wrap around */

		/* d1 = (d18 + (d16 >> 26)) & 0x3FFFFFF */
		"VSHR.u64	d28, d16, #26			\n\t"
		"VADD.u64	d18, d18, d28			\n\t"
		"VAND.u64	d15, d18, d30			\n\t"   /* d1 */
		"VMOV		s20, s30			\n\t"

		/* d10 = 43EA6A8   */

		/* d1 overflow to d2 */

		/* d2 = (d20 + (d18 >> 26)) & 0x3FFFFFF */
		"VSHR.u64	d28, d18, #26			\n\t"
		"VADD.u64	d20, d20, d28			\n\t"
		"VAND.u64	d15, d20, d30			\n\t"   /* d2 */
		"VMOV		s22, s30			\n\t"		

		/* d2 overflow to d3 */

		"VSHR.u64	d28, d20, #26			\n\t"
		"VADD.u64	d22, d22, d28			\n\t"
		"VAND.u64	d15, d22, d30			\n\t"   /* d3 */
		"VMOV		s24, s30			\n\t"

		/* d3 overflow to d4 */

		"VSHR.u64	d28, d22, #26			\n\t"
		"VADD.u64	d24, d24, d28			\n\t"
		"VAND.u64	d15, d24, d30			\n\t"   /* d4 */
		"VMOV		s26, s30			\n\t"
		
		/* d4 overflow to d0 */

		"VSHR.u64	d15, d24, #26			\n\t"
		/* multiply d15 by 5 */
		"VMOV		r6, s30				\n\t"
		"MOV		r5, #5				\n\t"
		"MUL		r6, r5, r6			\n\t"
		"VMOV		r4, s18				\n\t"
		"ADD		r4, r4, r6			\n\t"   /* d0 + 5 * d4 roll over */
		
		"MOV		r5, #0x3FFFFFF			\n\t"
		"AND		r8, r4, r5			\n\t"
		"VMOV		s18, r8				\n\t"
		
		"VMOV		r6, s20				\n\t"	
		"ADD		r6, r6, r4, LSR #26		\n\t"
		"VMOV		s20, r6				\n\t"


		/* final H values : d9 = 2B55FD9  d10 = 2828883  d11 = 2ABA762 
				   d12 = 371251  d13 = 123C3C5 */


		/* doing d0 --> d1 --> d2 --> d3 --> d4 --> d1 -->d2 */
		
		/* d17 --> d19 --> d21 --> d23 --> d25 --> d17 --> d19 */

		/* d0 = d16 * 0x3FFFFF */
		"VAND.u64	d15, d17, d30			\n\t"  
		"VMOV 		s19, s30			\n\t"	/* d0 */

		/* d9 = 10FA341 value before wrap around */

		/* d1 = (d18 + (d16 >> 26)) & 0x3FFFFFF */
		"VSHR.u64	d28, d17, #26			\n\t"
		"VADD.u64	d19, d19, d28			\n\t"
		"VAND.u64	d15, d19, d30			\n\t"   /* d1 */
		"VMOV		s21, s30			\n\t"

		/* d10 = 43EA6A8   */

		/* d1 overflow to d2 */

		/* d2 = (d20 + (d18 >> 26)) & 0x3FFFFFF */
		"VSHR.u64	d28, d19, #26			\n\t"
		"VADD.u64	d21, d21, d28			\n\t"
		"VAND.u64	d15, d21, d30			\n\t"   /* d2 */
		"VMOV		s23, s30			\n\t"		

		/* d2 overflow to d3 */

		"VSHR.u64	d28, d21, #26			\n\t"
		"VADD.u64	d23, d23, d28			\n\t"
		"VAND.u64	d15, d23, d30			\n\t"   /* d3 */
		"VMOV		s25, s30			\n\t"

		/* d3 overflow to d4 */

		"VSHR.u64	d28, d23, #26			\n\t"
		"VADD.u64	d25, d25, d28			\n\t"
		"VAND.u64	d15, d25, d30			\n\t"   /* d4 */
		"VMOV		s27, s30			\n\t"
		
		/* d4 overflow to d0 */

		"VSHR.u64	d15, d25, #26			\n\t"
		/* multiply d15 by 5 */
		"VMOV		r6, s30				\n\t"
		"MOV		r5, #5				\n\t"
		"MUL		r6, r5, r6			\n\t"
		"VMOV		r4, s19				\n\t"
		"ADD		r4, r4, r6			\n\t"   /* d0 + 5 * d4 roll over */
		
		"MOV		r5, #0x3FFFFFF			\n\t"
		"AND		r8, r4, r5			\n\t"
		"VMOV		s19, r8				\n\t"
		
		"VMOV		r6, s21				\n\t"	
		"ADD		r6, r6, r4, LSR #26		\n\t"
		"VMOV		s21, r6				\n\t"

		/* final H values : d9 = 18BF985  d10 = A0CA51  d11 = 3174319  
				   d12 = 54A9E1  d13 = 2363970 */

		"CMP 		r2, #0x10  		 \n\t"
		"BLE		oneBlockLeft		 \n\t"

		/* add the two h vectors together */
		"MOV		r5, #0			\n\t"
		"VMOV		r4, r10, s18, s19	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s18, s19, r5, r4	\n\t"

		"VMOV		r4, r10, s20, s21	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s20, s21, r5, r4	\n\t"

		"VMOV		r4, r10, s22, s23	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s22, s23, r5, r4	\n\t"

		"VMOV		r4, r10, s24, s25	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s24, s25, r5, r4	\n\t"

		"VMOV		r4, r10, s26, s27	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s26, s27, r5, r4	\n\t"
		"B		armv8_32_poly1305_loop	\n\t"

	"oneBlockLeft: 					\n\t"
		/* only one block left in message */
		/* add the two h vectors together */
		"MOV		r5, #0			\n\t"
		"VMOV		r4, r10, s18, s19	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s18, s19, r4, r5	\n\t"

		"VMOV		r4, r10, s20, s21	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s20, s21, r4, r5	\n\t"

		"VMOV		r4, r10, s22, s23	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s22, s23, r4, r5	\n\t"

		"VMOV		r4, r10, s24, s25	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s24, s25, r4, r5	\n\t"

		"VMOV		r4, r10, s26, s27	\n\t"
		"ADD		r4, r4, r10		\n\t"
		"VMOV		s26, s27, r4, r5	\n\t"
		"B		armv8_32_poly1305_loop	\n\t"
	
	"armv8_32_poly1305_last_block:			\n\t"

		/* This is the last block of the message
		   and the block is less than 16 bytes */

		/* r1 is message pointer
		   r2 is byte count, which is less than 16 
		   r3 is hibit	*/

		/* Make sure the upper bytes of the 
		   32 bit pieces are set to zero. 
		   Set the byte past the last message
		   data byte to 01. */

		"MOV	r10, r2				\n\t"

		"PUSH	{ r0, r1, r2, r3 } 		\n\t"

		"MOV	r9,  r1				\n\t"	

		"LSR	r3,  r3, #24			\n\t"
		"MOV	r6,  r3				\n\t"

		"MOV    r1,  #0				\n\t"
		"MOV	r2,  #0				\n\t"
		"MOV	r3,  #0				\n\t"
		"MOV	r4,  #0xFFFFFFFF		\n\t"

		/* always going to load at least one */		
		"LDR	r0, [r9]			\n\t"

		/* byte offset to bit offset */ 
		"LSL	r10, r10, #3			\n\t"			

		/* which block */
		"CMP	r10, #32			\n\t"
		"BGE	not_word_0			\n\t"

		/* case word 0 */
	"case0:"
		"LSL	r8, r4, r10			\n\t"
		"BIC  	r0, r0, r8			\n\t"
		"LSL	r8, r6, r10			\n\t"
		"ADD	r0, r0, r8			\n\t"
		"B	last_block_done			\n\t"

	"not_word_0:	 				\n\t"
		"LDR	r1, [r9, #4]			\n\t"
		
		"SUB	r10, r10, #32			\n\t"
		"CMP	r10, #32			\n\t"
		"BGE	not_word_1			\n\t"

		"LSL	r8, r4, r10			\n\t"
		"BIC  	r1, r1, r8			\n\t"
		"LSL	r8, r6, r10			\n\t"
		"ADD	r1, r1, r8			\n\t"		
		"B	last_block_done			\n\t"

	"not_word_1:					\n\t"
		"LDR	r2, [r9, #8]			\n\t"

		"SUB	r10, r10, #32			\n\t"
		"CMP	r10, #32			\n\t"
		"BGE	not_word_2			\n\t"

		"LSL	r8, r4, r10			\n\t"
		"BIC  	r2, r2, r8			\n\t"
		"LSL	r8, r6, r10			\n\t"
		"ADD	r2, r2, r8			\n\t"		
		"B	last_block_done			\n\t"

	"not_word_2:					\n\t"
		"LDR	r3, [r9, #0xC]			\n\t"

		"SUB	r10, r10, #32			\n\t"

		"LSL	r8, r4, r10			\n\t"
		"BIC  	r3, r3, r8			\n\t"
		"LSL	r8, r6, r10			\n\t"
		"ADD	r3, r3, r8			\n\t"	

	"last_block_done:				\n\t"

		"MOV 	r4, r0				\n\t"
		"MOV 	r5, r1				\n\t"
		"MOV 	r6, r2				\n\t"
		"MOV 	r8, r3				\n\t"

		"POP	{ r0, r1, r2, r3 }	\n\t"	

		/* set the byte count to 0 */
		"MOV		r2, #0			\n\t"
	
		"b		onlyOneBlock_hibit_set	\n\t"	

		"b 	armv8_32_poly1305_done_01_byte_appended \n\t"
	
		".align 2 \n\t"
	"armv8_32_poly1305_done:			\n\t"

		"VMOV	r0, s18				\n\t"
		"VMOV	r1, s20				\n\t"
		"VMOV	r2, s22				\n\t"
		"VMOV	r3, s24				\n\t"
		"VMOV	r4, s26				\n\t"

                /* store final result */
                "LDR    r10, %[h_ptr1]                   \n\t"
                "STM    r10, { r0, r1, r2, r3, r4 }      \n\t"

		: [m] 		  "+m" (msgDataOnStack),	/* input */
		  [r_ptr]  	  "+m" (r_ptrLocal),		/* input */
		  [r2_ptr]	  "+m" (r2_ptrLocal),		/* input */
		  [h_ptr1]  	  "+m" (h1_ptrLocal),		/* input, output */
		  [h_ptr2]  	  "+m" (h2_ptrLocal),		/* input, output */
		  [bytes]  	  "+m" (msgDataLenOnStack),	/* input */
		  [hibit]	  "+m" (hibitOnStack)		/* input */
		: [BYTES_STORE]    "I" (BYTES_SP_OFF),
		  [HIBIT_LOCAL]    "I" (HIBIT_LOCAL_SP_OFF)
		: "memory", "cc", 
			"r0", "r1", "r2", "r3", "r4",
			"r5", "r6", "r8", "r9", "r10",
			"r11",
			"r12",
			"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
			"d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18",
			"d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27",
			"d28", "d29", "d30", "d31"
	);

	/* testing with testsuite/testsuite.test demonstrates that the
	   below reduction is necessary. */

	/* do reduction */
	int over;
	
	over = h1[0]>>26;
	h1[0] = h1[0] & 0x3FFFFFF;
	h1[1] += over;

	over = h1[1]>>26;
	h1[1] = h1[1] & 0x3FFFFFF;
	h1[2] += over;
	
	over = h1[2]>>26;
	h1[2] = h1[2] & 0x3FFFFFF;
	h1[3] += over;

	over = h1[3]>>26;
	h1[3] = h1[3] & 0x3FFFFFF;
	h1[4] += over;

	over = h1[4]>>26;
	h1[4] = h1[4] & 0x3FFFFFF;

	h1[0] += (over * 5);
	over = h1[0]>>26;
	h1[0] = h1[0] & 0x3FFFFFF;

	h1[1] += over;

	memcpy(ctx->h, h1, 5 * sizeof(unsigned));

#ifdef POLY1305_VERBOSE
	printf("\narmv8_32_poly1305_blocks() leaving\n");
#endif

}

#endif  /* #ifdef  WOLFSSL_ARMASM_NO_NEON */

#endif	/* #ifndef __aarch64__   */
#endif  /* #ifdef  WOLFSSL_ARMASM */


/**********************************************************
  assembly test code  this code can be placed in the NEON 
  assembly routine to copy out the d registers
**********************************************************/
#if 0

	"testArray:  \n\t"
		"LDR 		r6, %[test1] \n\t"
		"VSTR 		d0, [r6, #0] \n\t" 	
		"VSTR 		d1, [r6, #8] \n\t" 	
		"VSTR 		d2, [r6, #0x10] \n\t" 	
		"VSTR 		d3, [r6, #0x18] \n\t" 	
		"VSTR 		d4, [r6, #0x20] \n\t" 
		"VSTR 		d5, [r6, #0x28] \n\t" 	
		"VSTR 		d6, [r6, #0x30] \n\t" 	
		"VSTR 		d7, [r6, #0x38] \n\t" 	
		"VSTR 		d8, [r6, #0x40] \n\t" 	
		"VSTR 		d9, [r6, #0x48] \n\t" 
		"VSTR 		d10, [r6, #0x50] \n\t" 	
		"VSTR 		d11, [r6, #0x58] \n\t" 	
		"VSTR 		d12, [r6, #0x60] \n\t" 	
		"VSTR 		d13, [r6, #0x68] \n\t" 	
		"VSTR 		d14, [r6, #0x70] \n\t" 
		"VSTR 		d15, [r6, #0x78] \n\t" 	

		"VSTR 		d16, [r6, #0x80] \n\t" 	
		"VSTR 		d17, [r6, #0x88] \n\t" 
		"VSTR 		d18, [r6, #0x90] \n\t" 	
		"VSTR 		d19, [r6, #0x98] \n\t" 	
		"VSTR 		d20, [r6, #0xA0] \n\t" 	
		"VSTR 		d21, [r6, #0xA8] \n\t" 	
		"VSTR 		d22, [r6, #0xB0] \n\t" 
		"VSTR 		d23, [r6, #0xB8] \n\t" 	

		"VSTR 		d24, [r6, #0xC0] \n\t" 	
		"VSTR 		d25, [r6, #0xC8] \n\t" 
		"VSTR 		d26, [r6, #0xD0] \n\t" 	
		"VSTR 		d27, [r6, #0xD8] \n\t" 	
		"VSTR 		d28, [r6, #0xE0] \n\t" 	
		"VSTR 		d29, [r6, #0xE8] \n\t" 	
		"VSTR 		d30, [r6, #0xF0] \n\t" 
		"VSTR 		d31, [r6, #0xF8] \n\t" 	

void output_test_array(unsigned *test1Array)
{
	int i;

	printf("\n\n THIS stuff \n\n");
	for (i=0;i<64;){
		 printf("%d %08X ", i/2, test1Array[i+1]);
		 printf(" %08X \n",  test1Array[i]);
		 i+=2;
	}
}




#endif


#ifdef POLY1305_STAND_ALONE

/**********************************************************
  print16	Output the given 16 bytes as one big
		number.  Note 16 bytes is 128 bit.
**********************************************************/
void print16(const char *startText, unsigned char *data);
void print16(const char *startText, unsigned char *data)
{
	printf("%s %08X %08X %08X %08X\n", startText, *(unsigned*)(data+0xc),
			*(unsigned*)(data+0x8),
			*(unsigned*)(data+4),
			*(unsigned*)data);
}


/**********************************************************
  print17	Output the given 17 bytes as one big
		number.  
**********************************************************/
void print17(const char *startText, unsigned char *data);
void print17(const char *startText, unsigned char *data)
{
	printf("%s %02X %08X%08X %08X%08X \n", startText, data[16], 
				*(unsigned *)(data+0xC), *(unsigned *)(data+8),
				*(unsigned *)(data+4), *(unsigned *)(data));
}


/**********************************************************
  printBytes	Print the specified number of bytes, one
		byte at a time.
**********************************************************/
void printBytes(const char *startText, unsigned char *data, int len);
void printBytes(const char *startText, unsigned char *data, int len)
{
	int i;
	
	printf("%s", startText);
	
	for (i=0;i<len;++i)
	{
		printf("%02X", data[i]);
		if (i<len-1) printf(":");
	}
	printf("\n");
}


/**********************************************************
  clamp_r	Set the correct bits in the 128 bit r key
		to zero.
**********************************************************/
void clamp_r(unsigned char *r);
void clamp_r(unsigned char *r)
{
	printBytes("r = ", r, 16);
	
	r[3] &= 0xF;
	r[7] &= 0xF;
	r[11] &= 0xF;
	r[15] &= 0xF;
	
	r[4] &= 0xFC;
	r[8] &= 0xFC;
	r[12] &= 0xFC;
	
	print16("after clamp ", r);
}


/**********************************************************
  add17		Add two 17 byte numbers together.  This is
		used as part of the algorithm to combine
		26 bit pieces into one 17 byte number.
**********************************************************/
void add17(unsigned char *dest, unsigned char *src);
void add17(unsigned char *dest, unsigned char *src)
{
	int i;
	short result;
	unsigned char of=0;
	
	for (i=0;i<17;++i)
	{
		result = dest[i] + src[i] + of;
		
		dest[i] = (unsigned char)result;
		
		if (result & 0xFF00) of=1; else of=0; 
	}
}


/**********************************************************
  convert26BitValuesTo17Byte
		Convert the 5 specified 26 bit values to
		a single 17 byte value.
  input16Bit	Input array of 5 26 bit values.  
  result	Output of 17 bytes which represent one
		130 bit number.
*********************************************************/
void convert26BitValuesTo17Byte(unsigned *input26Bit, unsigned char *result);
void convert26BitValuesTo17Byte(unsigned *input26Bit, unsigned char *result)
{
	unsigned char tmp[25];
	unsigned over, val24;

	memset(result, 0, 17);
	*(unsigned *)(result+0) = (unsigned)input26Bit[0];		/* 0 */

	over = input26Bit[1] >> (24-2);
	val24 = (input26Bit[1] << 2) & 0xFFFFFF;    /* 26 + 2 = 28 */
	memset(tmp, 0, 17);
	*(unsigned *)(tmp+3) = val24; 
	add17(result, tmp);
	memset(tmp, 0, 17);
	*(unsigned *)(tmp+6) = over;
	add17(result, tmp);

	over = input26Bit[2] >> (24-4);
	val24 = (input26Bit[2] << 4) & 0xFFFFFF;    /* 26 + 2 = 28 */

	memset(tmp, 0, 17);
	*(unsigned*)(tmp+6) = val24;
	add17(result, tmp);
	memset(tmp, 0, 17);
	*(unsigned *)(tmp+9) = over;
	add17(result, tmp);

	over = input26Bit[3] >> (24-6);
	val24 = (input26Bit[3] << 6) & 0xFFFFFF;    /* 26 + 2 = 28 */

	memset(tmp, 0, 17);
	*(unsigned*)(tmp+9) = val24;
	add17(result, tmp);
	memset(tmp, 0, 17);
	*(unsigned *)(tmp+12) = over;
	add17(result, tmp);

	memset(tmp, 0, 17);
	*(unsigned*)(tmp+13) = input26Bit[4];		/* 26+26+26+26 =104 */
	add17(result, tmp);	

	result[16] &= 3;
}


/* test data set from RFC 7539 */
#if 0
/* two 16 byte blocks */
unsigned char testData[]="Cryptographic Forum Research set"; 
unsigned char testData1[]="Cryptographic Fo";
unsigned char testData2[]="rum Research set"; 
unsigned char resultCheck[]="\x5F\x5C\xC1\xDE\x46\x9B\x6E\xA5\x79\x9B\x03\x9F\x64\x7E\xF2\x75";
#endif

unsigned char testKey[]="\x85\xd6\xBE\x78\x57\x55\x6d\x33\x7F\x44\x52\xfe\x42\xd5\x06\xa8\x01\x03\x80\x8a\xfb\x0d\xb2\xFD\x4A\xBF\xF6\xAF\x41\x49\xF5\x1B";

#if 0
unsigned char testData[]="Cryptographic Forum Research Group"; 
unsigned char resultCheck[]="\xA8\x06\x1D\xC1\x30\x51\x36\xC6\xC2\x2B\x8B\xAF\x0C\x01\x27\xA9";
#endif

#if 0
/* four 16 byte blocks  - neon matches A32 */
unsigned char testData[]="Cryptographic Forum Research setCryptographic Forum Research set"; 
unsigned char resultCheck[]="\x4A\xD3\x08\x6D\x13\x5B\x12\x5C\xCF\xC2\x1A\xAD\xA0\xBA\x75\x3F";
#endif

#if 0
/* three 16 byte blocks */
unsigned char testData[]="Cryptographic Forum Research set1234567890123456"; 
unsigned char resultCheck[]="\x90\x0A\xA4\x0B\xFD\x90\xC7\x12\x52\x95\x08\x49\xF6\x20\x86\xEC";
#endif

#if 0
/* three 16 byte blocks + an under sized block */
unsigned char testData[]="Cryptographic Forum Research set1234567890123456123"; 
unsigned char resultCheck[]="\x32\x03\x0B\x51\x7E\x49\xA8\x0D\xBF\x02\xD6\x99\x46\x79\xE2\x28";
#endif

#if 0
/* three 16 byte blocks + an under sized block */
unsigned char testData[]="Cryptographic Forum Research set12345678901234561234"; 
/* neon version gets \x67\x20\x0F\xFA */
unsigned char resultCheck[]="\x5D\x41\x13\xDC\xBF\x24\x25\xD4\x12\x20\xF2\x51\x67\x21\x0F\xFA";  
#endif

#if 0
/* four 16 byte blocks - neon results push limits of 17 byte add. */
unsigned char testData[]="Cryptographic Forum Research set12345678901234561234567890123456"; 
/* neon gets  \x59\xBB\x07\x1C */
unsigned char resultCheck[]="\x46\x3C\x3D\x0F\xD4\x1A\x8C\xF0\xE7\x34\x9C\x72\x59\xBC\x07\x1C";  
#endif

#if 0
/* three 16 byte blocks + an under sized block */
unsigned char testData[]="Cryptographic Forum Research set1234567890123456111111"; 
unsigned char resultCheck[]="\xF8\x2E\xC4\xEF\x9B\x3C\x6A\xC1\x61\x73\xD4\xE9\x3C\x65\x93\x3B";  
#endif

#if 0
/* two 16 byte blocks + an under sized block */
unsigned char testData[]="Cryptographic Forum Research set1234"; 
unsigned char resultCheck[]="\xA2\x0F\x7A\xD8\xE8\x9A\x60\xF6\x7C\x80\x5E\x28\x04\x86\x8D\xCA";
#endif

#if 1
/* eight 16 byte blocks */
unsigned char testData[]="Cryptographic Forum Research setCryptographic Forum Research setCryptographic Forum Research setCryptographic Forum Research set"; 
unsigned char resultCheck[]="\xAE\xF7\x74\x3B\x69\x72\x8A\x4F\xD7\x32\x60\xB6\x7E\x0B\x60\x88";
#endif
	
#if 0
/* eight 16 byte blocks */
unsigned char testData[]="Crypto"; 
unsigned char resultCheck[]="\xE2\x33\xC2\x33\x97\x5C\xDC\x37\xE6\x7B\xF9\xFC\x59\x33\xB5\x7F";
#endif



int main(void)
{
	unsigned char *msgData, *keyData;
	int msgDataLen;
	unsigned char result16Byte[16];
	Poly1305  ctx;
 	unsigned char *r, *s, acc[17];
	int i;
	unsigned *pt;

	msgData = testData;
	msgDataLen = strlen((const char *)msgData);	
	keyData = testKey;

	pt = (unsigned*)msgData;

	printf("\n%s\n", msgData);
	for (i=0;i<10;++i) 
		printf(" %d %X\n", i, pt[i]);
	printf("\n");

	printf("message len %d\n\n", msgDataLen);

	/* some modifications of the test data for test
	   purposes.  Used in part to test the assembly
	   algorithm for the last block of the message. */

	r = keyData;
	s = keyData+16;

	print16("s as a 128-bit number ", s);
	clamp_r(r);

	/* break the 16 byte value into 26 bit parts. */         
	ctx.r[0] = *(unsigned *)(r) & 0x3FFFFFF;
	ctx.r[1] = ((*(unsigned *)(r + 3)) >> 2) & 0x3FFFFFF;
	ctx.r[2] = ((*(unsigned *)(r + 6)) >> 4) & 0x3FFFFFF;
	ctx.r[3] = ((*(unsigned *)(r + 9)) >> 6) & 0x3FFFFFF;
	/* + 12 so you don't reference outside array, ie don't use +13 */
	ctx.r[4] = ((*(unsigned *)(r + 12)) >> 8) & 0xFFFFFF;

	ctx.finished = 0;  /* setups up hibit, 0 is normal value */

	/* Should always start as zero.
           Passing into assembly routine to match what is already 
	   implemented in wolfSSL armv8_poly1305.c.  
	   For debugging, the C routine could break the message into 
	   16 byte chunks and call the assembly routine over and over
	   with the 16 byte chunks and the updated h value. */
	memset(ctx.h, 0, 5 * sizeof(unsigned));

	/* Some of the test cases found in 
           wolfcrypt/test/test.c : poly1305_test() start with a
	   non-zero h vector. */

	/* for (i=0;i<5;++i)
		ctx.h[i] = i; */

#if 0
	unsigned r_1[5], r_2[5];
	unsigned h1[5];
	unsigned h3[5];
	int o, q;

        msgData=testData1;
        msgDataLen=strlen((char *)msgData);

	memcpy(r_1, ctx.r, 5*sizeof(unsigned));

	/* copy r_2 to r */
	calculateRsquared(r_1, r_2);

	memcpy(ctx.r, r_2, 5*sizeof(unsigned));

	armv8_32_poly1305_blocks(&ctx, msgData, msgDataLen);

	printf("\n(M block 1) * r^2 values :");

	for (o=0;o<5;++o)
	{
		printf(" %X ", ctx.h[o]);
	}
	printf("\n\n");

	memcpy(h3, ctx.h, 5 * sizeof(unsigned));

        msgData=testData2;
        msgDataLen=strlen((char *)msgData);

	printf("\n\nr ");
	for (q=0;q<5;++q)	
	{
		printf(" %X ", ctx.r[q]);
	}
	printf("\n");

	memset(ctx.h, 0, 5*sizeof(unsigned));

	memcpy(ctx.r, r_1, 5*sizeof(unsigned));

	armv8_32_poly1305_blocks(&ctx, msgData, msgDataLen);

	printf("\n(M block 2) * r values :");
	
	for (o=0;o<5;++o)
	{
		printf(" %X ", ctx.h[o]);
	}
	printf("\n\n");

	int k;
	for (k=0;k<5;++k)
		ctx.h[k] += h3[k];
#endif

#if 1
	msgData = testData;
	msgDataLen = strlen((char *)msgData);

	armv8_32_poly1305_blocks(&ctx, msgData, msgDataLen);

	printf("\n\nFinal H values :");
	int o;
	for (o=0;o<5;++o)
	{
		printf(" %X ", ctx.h[o]);
	}
	printf("\n\n");
#endif
	
	convert26BitValuesTo17Byte(ctx.h, acc);

	/* make output match what is seen in RFC */
	print17("Acc = ((Acc+Block) * r) % P = ", acc);
	add17(acc, s);
	print17("Acc + s = ", acc);

	memcpy(result16Byte, acc, 16);

	printBytes(" Tag = ", result16Byte, 16); 

	if (!memcmp(result16Byte, resultCheck, 16))
		printf("Result matches RFC 7539\n\n");
	else	
		printf("Result does not match RFC 7539\n\n");
}
#endif

