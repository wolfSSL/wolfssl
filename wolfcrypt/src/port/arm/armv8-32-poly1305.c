/*****************************************************************

   The test data in this code matches the test data in RFC 7539.

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

#define WOLFSSL_ARMASM           1
/* leave __aarch64__ undefined */
#define POLY1305_VERBOSE         1

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
  armv8_32_poly1305_blocks        This routine implements the 
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
                        17 byte numbers.  Breaking the 
                        larger numbers down into 26 bit 
                        pieces means that math operations will
                        not overflow the 32 bit registers.
                        For more information reference the article 
                        NEON Cryto by Daniel Berstein and Peter
                        Schwabe.

  ctx                   poly1305 structure containing the r and
                        h values broke into 26 bit pieces.
                        The result of this routine is returned
                        int the h array of 26 bit values.
  msgData               Message data to run the algorithm 
                        against.
  keyData               256 bit key that is broken down 
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

/**********************************************************
  armv8_32_poly1305_blocks        This routine implements the 
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
                        17 byte numbers.  Breaking the 
                        larger numbers down into 26 bit 
                        pieces means that math operations will
                        not overflow the 32 bit registers.
                        For more information reference the article 
                        NEON Cryto by Daniel Berstein and Peter
                        Schwabe.
                        
                        This version of the algorithm uses 
                        NEON s registers to temporarily store
                        values so that the stack does not need
                        to be used.

  ctx                   poly1305 structure containing the r and
                        h values broke into 26 bit pieces.
                        The result of this routine is returned
                        int the h array of 26 bit values.
  msgData                Message data to run the algorithm 
                        against.
  keyData               256 bit key that is broken down 
                        into the r and s subcomponents.
**********************************************************/
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
                ".align     8                                   \n\t"
                
                /* valid registers are r0..r12, sp, lr, pc, cpsr, fpscr */
                
                /* now load the stored h, this should all zero */
                "LDR        r5, %[h_ptr]                        \n\t"
                "LDM        r5, { r6, r8, r9, r10, r11 }        \n\t"
                /* r6 = h0  r8 = h1  r9 = h2  r10 = h3  r11 = h4 */
        
                /* in some cases, r7 is used to reference the local variables 
                   on the stack; if -O2 is passed to gcc, the sp may used 
                        used to reference local variables. */
                "LDR        r0, %[hibit]                        \n\t"
                "LDR        r1, %[bytes]                        \n\t"
                "LDR        r2, %[r_ptr]                        \n\t"

                "VMOV       s2, r0                              \n\t"
                "VMOV       s4, r1                              \n\t"

                "LDM        r2, { r0, r1, r2, r3, r4 }          \n\t"
                "VMOV       s6, r0                              \n\t"
                "VMOV       s7, r1                              \n\t"
                "VMOV       s8, r2                              \n\t"
                "VMOV       s9, r3                              \n\t"
                "VMOV       s10, r4                             \n\t"

                "LDR        r5, %[m]                            \n\t"
                "PUSH       { r7 }                              \n\t"
                "MOV        r7, r5                              \n\t"

                /* s2 - hibit
                   s4 - bytes
                   s6, s7, s8, s9, s10 - r in 26 bit pieces */

        "armv8_32_poly1305_loop:                                \n\t"

                /* The poly1305 algorithm requires that a 01 byte 
                   be placed after the last byte of the block. */                 
                
                "VMOV       r5, s4                              \n\t"
                "CMP        r5, #0                              \n\t"
                "BEQ        armv8_32_poly1305_done              \n\t"
                "SUBS       r5, r5, #16                         \n\t"
                
                /* branch for least likely case, may help with pipelining */
                /* ARMv8 uses predictive pipelining.  There is no way
                   to specify in the instruction encoding the more likely
                   case.  */
                "BLT        armv8_32_poly1305_last_block        \n\t"  

                /* this block is 16 bytes */
                "VMOV       s4, r5                              \n\t"

                /* load next 16 byte block of message */                
                "LDM        r7, { r0, r1, r2, r3 }              \n\t"   /* mem 1 */
                "ADD        r7, r7, #16                         \n\t"

                /* in RFC 7539, each block processed is prepended by
                     a byte of value 0x01.  In the wolfSSL implementation,
                   the setting of this value is based on the value found
                   in ctx->finish. To save a memory reference, this code
                   could be replicated one version adding the byte, one
                   version not. */

                /* This is byte 16, past the 128 bits of w19:w18:w17:w16 
                   Hence, update is done to h4. */  
                /* add in hibit */
                "VMOV       r5, s2                              \n\t"
                "ADD        r11, r11, r5                        \n\t"
                        
        "armv8_32_poly1305_done_01_byte_appended:               \n\t"

                "mov        r5, #0x3FFFFFF                      \n\t"

                /* break data into 26 bit pieces. 
                   Bit offsets are 0, 26, 52, 78 and 104 */
                   
                /* h0 += r0 & 0x3FFFFFF; */
                "AND        r12, r0, r5                         \n\t"
                "ADD        r6, r6, r12                         \n\t"
                /* h1 += (r1:r0 >> 26) & 0x3FFFFFF */
                "LSR        r12, r0, #26                        \n\t"   /* 26 */
                "ADD        r12, r12, r1, LSL #6                \n\t"
                "AND        r12, r12, r5                        \n\t"
                "ADD        r8, r8, r12                         \n\t"
                /* h2 += (r2:r1 >> 20) & 0x3FFFFFF */         
                "LSR        r12, r1, #20                        \n\t"   /* 20+32 = 52 */
                "ADD        r12, r12, r2, LSL #12               \n\t"
                "AND        r12, r12, r5                        \n\t"
                "ADD        r9, r9, r12                         \n\t"
                /* h3 += (r3:r2 >> 14) & 0x3FFFFFF */
                "LSR        r12, r2, #14                        \n\t"   /* 14+32+32 = 78 */
                "ADD        r12, r12, r3, LSL #18               \n\t"
                "AND        r12, r12, r5                        \n\t"
                "ADD        r10, r10, r12                       \n\t"
                /* h4 += r3 >> 8                   */
                "ADD        r11, r11, r3, LSR #8                \n\t"   /* 8+32+32+32 = 104 */

                /* pull in the 26 bit components of the r key */
                "VMOV       r0, s6                              \n\t"
                "VMOV       r1, s7                              \n\t"
                "VMOV       r2, s8                              \n\t"
                "VMOV       r3, s9                              \n\t"
                "VMOV       r4, s10                             \n\t"

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

                "VMOV       s12, s13, r12, r14                  \n\t"

                /* 8F852 C3AB3DA1 */

                /* d3 */
                "UMULL      r12, r14, r6, r3                    \n\t"
                "UMLAL      r12, r14, r8, r2                    \n\t"
                "UMLAL      r12, r14, r9, r1                    \n\t"
                "UMLAL      r12, r14, r10, r0                   \n\t"
                "MUL        r11, r11, r5                        \n\t"
                "UMLAL      r12, r14, r11, r4                   \n\t"

                "VMOV       s14, s15, r12, r14                  \n\t"

                /* C753B 56120E14 */

                /* d2 */
                "UMULL      r12, r14, r6, r2                    \n\t"
                "UMLAL      r12, r14, r8, r1                    \n\t"
                "UMLAL      r12, r14, r9, r0                    \n\t"
                "MUL        r10, r10, r5                        \n\t"
                "UMLAL      r12, r14, r10, r4                   \n\t"
                "UMLAL      r12, r14, r11, r3                   \n\t"

                "VMOV       s16, s17, r12, r14                  \n\t"

                /* 10019D F79AAF81 */

                /* d1 */
                "UMULL      r12, r14, r6, r1                    \n\t"
                "UMLAL      r12, r14, r8, r0                    \n\t"
                "MUL        r9, r9, r5                          \n\t"
                "UMLAL      r12, r14, r9, r4                    \n\t"
                "UMLAL      r12, r14, r10, r3                   \n\t"
                "UMLAL      r12, r14, r11, r2                   \n\t"

                "VMOV       s18, s19, r12, r14                  \n\t"

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
                "AND        r6, r12, r5                         \n\t"  /* d0 */

                /* d0 overflow to d1 */

                "VMOV       r0, r1, s18, s19                    \n\t"
                "ADDS       r0, r0, r12, LSR #26                \n\t"
                "ADC        r1, r1, #0                          \n\t"
                "ADDS       r0, r0, r14, LSL #6                 \n\t"
                "ADC        r1, r1, #0                          \n\t"

                "AND        r8, r0, r5                          \n\t"  /* d1 */

                /* d1 overflow to d2 */

                "VMOV       r2, r3, s16, s17                    \n\t"
                "ADDS       r2, r2, r0, LSR #26                 \n\t"
                "ADC        r3, r3, #0                          \n\t"
                "ADDS       r2, r2, r1, LSL #6                  \n\t"
                "ADC        r3, r3, #0                          \n\t"

                "AND        r9, r2, r5                          \n\t"  /* d2 */

                /* d2 overflow to d3 */

                "VMOV       r0, r1, s14, s15                    \n\t"
                "ADDS       r0, r0, r2, LSR #26                 \n\t"
                "ADC        r1, r1, #0                          \n\t"
                "ADDS       r0, r0, r3, LSL #6                  \n\t"
                "ADC        r1, r1, #0                          \n\t"

                "AND        r10, r0, r5                         \n\t"  /* d3 */

                /* d3 overflow to d4 */

                "VMOV       r2, r3, s12, s13                    \n\t"
                "ADDS       r2, r2, r0, LSR #26                 \n\t"
                "ADC        r3, r3, #0                          \n\t"
                "ADDS       r2, r2, r1, LSL #6                  \n\t"
                "ADC        r3, r3, #0                          \n\t"

                "AND        r11, r2, r5                         \n\t"  /* d4 */

                /* d4 overflow to d0, must be multiplied by 5 */        

                "LSR        r0, r2, #26                         \n\t"
                "ADD        r0, r0, r3, LSL #6                  \n\t"
                "MOV        r1, #5                              \n\t"        
                "MUL        r0, r0, r1                          \n\t"
                "ADD        r6, r6, r0                          \n\t"  /* d0 updated */

                /* d0 overflow to d1 */

                "ADD        r8, r8, r6, LSR #26                 \n\t"  /* d1 done */

                "AND        r6, r6, r5                          \n\t"  /* d0 done */

                "B          armv8_32_poly1305_loop              \n\t"
        
        "armv8_32_poly1305_last_block:                          \n\t"

                /* This is the last block of the message
                   and the block is less than 16 byte */

                /* set s4 to 0, d2 is s5:s4 */
                "VEOR       d2, d2                              \n\t"
        
                "VMOV       r0, s2                              \n\t"  /* hibit */

                /* Make sure the upper bytes of the 
                   32 bit pieces are set to zero. 
                   Set the byte past the last message
                   data byte to 01. */

                "PUSH        { r4, r6, r8 }                     \n\t"        

                "MOV        r1,  #0                             \n\t"
                "MOV        r2,  #0                             \n\t"
                "MOV        r3,  #0                             \n\t"
                "MOV        r4,  #0xFFFFFFFF                    \n\t"
                "LSR        r0,  r0, #24                        \n\t"
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
        
                ".align 2 \n\t"
        "armv8_32_poly1305_done:                                \n\t"
                "POP        { r7 }                              \n\t"

                /* store final result */
                "LDR        r0, %[h_ptr]                        \n\t"
                "STM        r0, { r6, r8, r9, r10, r11 }        \n\t"
                
                : [m]            "+m" (msgDataOnStack),        /* input */
                  [r_ptr]        "+m" (r_ptrLocal),            /* input */
                  [h_ptr]        "+m" (h_ptrLocal),            /* input, output */
                  [bytes]        "+m" (msgDataLenOnStack),     /* input */
                  [hibit]        "+m" (hibitOnStack)           /* input */
                : 
                : "memory", "cc", 
                        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r8", "r9", "r10",
                        "r11", "r12", "lr",
                        "s2", "s4", "s6", "s7", "s8", "s9", "s10", "d2",
                        "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19"
        );

        memcpy(ctx->r, r, 5 * sizeof(unsigned));
        memcpy(ctx->h, h, 5 * sizeof(unsigned));

#ifdef POLY1305_VERBOSE
        for (i=0;i<5;++i) printf("h%d %07X ", i, ctx->h[i]);
        printf("\n");

        printf("armv8_32_poly1305_blocks() leaving\n");
#endif

}

#endif  /* #ifdef  WOLFSSL_ARMASM_NO_NEON */

#endif  /* #ifndef __aarch64__   */
#endif  /* #ifdef  WOLFSSL_ARMASM */




#ifdef POLY1305_STAND_ALONE

/**********************************************************
  print16        Output the given 16 bytes as one big
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
  print17        Output the given 17 bytes as one big
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
  printBytes        Print the specified number of bytes, one
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
  clamp_r        Set the correct bits in the 128 bit r key
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
  add17                Add two 17 byte numbers together.  This is
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
  input16Bit        Input array of 5 26 bit values.  
  result        Output of 17 bytes which represent one
                130 bit number.
**********************************************************/
void convert26BitValuesTo17Byte(unsigned *input26Bit, unsigned char *result);
void convert26BitValuesTo17Byte(unsigned *input26Bit, unsigned char *result)
{
        unsigned char tmp[17];

        memset(result, 0, 17);
        *(unsigned*)(result+0) = input26Bit[0];

        memset(tmp, 0, 17);
        *(unsigned*)(tmp+3)  = input26Bit[1] << 2;
        add17(result, tmp);

        memset(tmp, 0, 17);
        *(unsigned*)(tmp+6)  = input26Bit[2] << 4;
        add17(result, tmp);

        memset(tmp, 0, 17);
        *(unsigned*)(tmp+9)  = input26Bit[3] << 6;
        add17(result, tmp);

        memset(tmp, 0, 17);
        *(unsigned*)(tmp+13) = input26Bit[4];
        add17(result, tmp);        

        result[16] &= 3;
}


/* test data set from RFC 7539 */
//unsigned char testData []="Cryptographic Forum Research set"; 
unsigned char testData[]="Cryptographic Forum Research Group"; 
//unsigned char testData []="12345678901234561234567890123456";
unsigned char testKey[]="\x85\xd6\xBE\x78\x57\x55\x6d\x33\x7F\x44\x52\xfe\x42\xd5\x06\xa8\x01\x03\x80\x8a\xfb\x0d\xb2\xFD\x4A\xBF\xF6\xAF\x41\x49\xF5\x1B";

unsigned char resultCheck[]="\xA8\x06\x1D\xC1\x30\x51\x36\xC6\xC2\x2B\x8B\xAF\x0C\x01\x27\xA9";


unsigned char msgDataCopy[100];                

int main(void)
{
        unsigned char *msgData, *keyData;
        int msgDataLen;
        unsigned char result16Byte[16];
        Poly1305  ctx;
         unsigned char *r, *s, acc[17];

        msgData = testData;
        msgDataLen = strlen((const char *)msgData);        
        keyData = testKey;


        unsigned *pt;
        pt = (unsigned*)msgData;

        int i;
        printf("%s\n", msgData);
        for (i=0;i<10;++i) printf(" %d %X\n", i, pt[i]);
        printf("\n");

        printf("message len %d\n", msgDataLen);


        /* some modifications of the test data for test
           purposes.  Used in part to test the assembly
           algorithm for the last block of the message. */
#if 0
        /* add junk at end for testing */
        memcpy(msgDataCopy, msgData, msgDataLen);
        msgData = msgDataCopy;
        *(unsigned*)(msgData+msgDataLen) = 0x12345678;
        *(unsigned*)(msgData+msgDataLen+4) = 0x12345678;
        *(unsigned*)(msgData+msgDataLen+8) = 0x11111111;
#endif
        
#if 0
        /* make test data a boundary case length
           for testing. */
        memcpy(msgDataCopy, msgData, msgDataLen);
        msgData = msgDataCopy;

        strcat(msgData, "more stuff");
        msgDataLen = strlen(msgData);        
#endif

#if 0
        /* just run poly1305 on the first 16 byte 
            block of the test data. */
        strcpy(msgDataCopy, "Cryptographic Fo");
        msgData = msgDataCopy;
        msgDataLen = strlen(msgData);                
#endif

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

        ctx.finished = 0;

        /* Should always start as zero.
           Passing into assembly routine to match what is already 
           implemented in wolfSSL armv8_poly1305.c.  
           For debugging, the C routine could break the message into 
           16 byte chunks and call the assembly routine over and over
           with the 16 byte chunks and the updated h value. */
        memset(ctx.h, 0, 5 * sizeof(unsigned));

        armv8_32_poly1305_blocks(&ctx, msgData, msgDataLen);

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



