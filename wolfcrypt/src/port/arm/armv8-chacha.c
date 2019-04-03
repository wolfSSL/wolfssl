/* armv8-chacha.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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
 *
 */


#ifdef WOLFSSL_ARMASM

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_CHACHA

#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef CHACHA_AEAD_TEST
    #include <stdio.h>
#endif

#ifdef BIG_ENDIAN_ORDER
    #define LITTLE32(x) ByteReverseWord32(x)
#else
    #define LITTLE32(x) (x)
#endif

/* Number of rounds */
#define ROUNDS  20

#define U32C(v) (v##U)
#define U32V(v) ((word32)(v) & U32C(0xFFFFFFFF))
#define U8TO32_LITTLE(p) LITTLE32(((word32*)(p))[0])

#define ROTATE(v,c) rotlFixed(v, c)
#define XOR(v,w)    ((v) ^ (w))
#define PLUS(v,w)   (U32V((v) + (w)))
#define PLUSONE(v)  (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

#define ARM_SIMD_LEN_BYTES 16

/**
  * Set up iv(nonce). Earlier versions used 64 bits instead of 96, this version
  * uses the typical AEAD 96 bit nonce and can do record sizes of 256 GB.
  */
int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter)
{
    word32 temp[CHACHA_IV_WORDS];/* used for alignment of memory */

#ifdef CHACHA_AEAD_TEST
    word32 i;
    printf("NONCE : ");
    for (i = 0; i < CHACHA_IV_BYTES; i++) {
        printf("%02x", inIv[i]);
    }
    printf("\n\n");
#endif

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(temp, inIv, CHACHA_IV_BYTES);

    ctx->X[CHACHA_IV_BYTES+0] = counter;           /* block counter */
    ctx->X[CHACHA_IV_BYTES+1] = LITTLE32(temp[0]); /* fixed variable from nonce */
    ctx->X[CHACHA_IV_BYTES+2] = LITTLE32(temp[1]); /* counter from nonce */
    ctx->X[CHACHA_IV_BYTES+3] = LITTLE32(temp[2]); /* counter from nonce */

    return 0;
}

/* "expand 32-byte k" as unsigned 32 byte */
static const word32 sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
/* "expand 16-byte k" as unsigned 16 byte */
static const word32 tau[4] = {0x61707865, 0x3120646e, 0x79622d36, 0x6b206574};

/**
  * Key setup. 8 word iv (nonce)
  */
int wc_Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz)
{
    const word32* constants;
    const byte*   k;

#ifdef XSTREAM_ALIGN
    word32 alignKey[8];
#endif

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (keySz != (CHACHA_MAX_KEY_SZ/2) && keySz != CHACHA_MAX_KEY_SZ)
        return BAD_FUNC_ARG;

#ifdef XSTREAM_ALIGN
    if ((wolfssl_word)key % 4) {
        WOLFSSL_MSG("wc_ChachaSetKey unaligned key");
        XMEMCPY(alignKey, key, keySz);
        k = (byte*)alignKey;
    }
    else {
        k = key;
    }
#else
    k = key;
#endif /* XSTREAM_ALIGN */

#ifdef CHACHA_AEAD_TEST
    word32 i;
    printf("ChaCha key used :\n");
    for (i = 0; i < keySz; i++) {
        printf("%02x", key[i]);
        if ((i + 1) % 8 == 0)
           printf("\n");
    }
    printf("\n\n");
#endif

    ctx->X[4] = U8TO32_LITTLE(k +  0);
    ctx->X[5] = U8TO32_LITTLE(k +  4);
    ctx->X[6] = U8TO32_LITTLE(k +  8);
    ctx->X[7] = U8TO32_LITTLE(k + 12);
    if (keySz == CHACHA_MAX_KEY_SZ) {
        k += 16;
        constants = sigma;
    }
    else {
        constants = tau;
    }
    ctx->X[ 8] = U8TO32_LITTLE(k +  0);
    ctx->X[ 9] = U8TO32_LITTLE(k +  4);
    ctx->X[10] = U8TO32_LITTLE(k +  8);
    ctx->X[11] = U8TO32_LITTLE(k + 12);
    ctx->X[ 0] = constants[0];
    ctx->X[ 1] = constants[1];
    ctx->X[ 2] = constants[2];
    ctx->X[ 3] = constants[3];

    return 0;
}

/**
  * Converts word into bytes with rotations having been done.
  */
static WC_INLINE void wc_Chacha_wordtobyte(word32 output[CHACHA_CHUNK_WORDS],
    const word32 input[CHACHA_CHUNK_WORDS])
{
    word32 x[CHACHA_CHUNK_WORDS];
    word32 i;

    XMEMCPY(x, input, CHACHA_CHUNK_BYTES);

    for (i = (ROUNDS); i > 0; i -= 2) {
//        __asm__ __volatile__ (
//        		"LDR w0, %[x_in], #16 \n"
//        		"LDR w1, %[x_in], #16 \n"
//        		"LDR w2, %[x_in], #16 \n"
//        		"LDR w3, %[x_in], #16 \n"
//
//        		"ADD w0, w0, w1 \n"
//        		"EOR w3, w3, w0 \n"
//        		"ROR w3, w3, #16 \n"
//
//        		"ADD w2, w2, w3 \n"
//        		"EOR w1, w1, w2 \n"
//        		"ROR w1, w1, #20 \n"
//
//        		"ADD w0, w0, w1 \n"
//        		"EOR w3, w3, w0 \n"
//        		"ROR w3, w3, #24 \n"
//
//        		"ADD w2, w2, w3 \n"
//        		"EOR w1, w1, w2 \n"
//        		"ROR w1, w1, #25 \n"
//
//        		"STR w0, %[x_out], #16 \n"
//        		"STR w1, %[x_out], #16 \n"
//        		"STR w2, %[x_out], #16 \n"
//        		"STR w3, %[x_out], #16 \n"
//
//        		: [x_out] "=m" (x)
//			    : [x_in] "m" (x)
//				: "memory", "w0", "w1", "w2", "w3"
//        );

        __asm__ __volatile__ (
        		// v0  0  1  2  3
        		// v1  4  5  6  7
        		// v2  8  9 10 11
        		// v3 12 13 14 15
        		// load CHACHA state as shown above
        		"LD1 { v0.4S-v3.4S }, %[x_in] \n"

        		// ODD ROUND

        		"ADD v0.4S, v0.4S, v1.4S \n"
        		"EOR v3.16B, v3.16B, v0.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v3.4S, #16 \n"
        		"USHR v3.4S, v3.4S, #16 \n"
        		"ORR v3.16B, v3.16B, v4.16B \n"

        		"ADD v2.4S, v2.4S, v3.4S \n"
        		"EOR v1.16B, v1.16B, v2.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v1.4S, #12 \n"
        		"USHR v1.4S, v1.4S, #20 \n"
        		"ORR v1.16B, v1.16B, v4.16B \n"

        		"ADD v0.4S, v0.4S, v1.4S \n"
        		"EOR v3.16B, v3.16B, v0.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v3.4S, #8 \n"
        		"USHR v3.4S, v3.4S, #24 \n"
        		"ORR v3.16B, v3.16B, v4.16B \n"

        		"ADD v2.4S, v2.4S, v3.4S \n"
        		"EOR v1.16B, v1.16B, v2.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v1.4S, #7 \n"
        		"USHR v1.4S, v1.4S, #25 \n"
        		"ORR v1.16B, v1.16B, v4.16B \n"

        		"ST1 { v0.4S-v3.4S }, %[x_out] \n"

        		: [x_out] "=m" (x)
			    : [x_in] "m" (x)
				: "memory", "v0", "v1", "v2", "v3", "v4"
        );

        __asm__ __volatile__ (
        		// v0   0  1  2  3
        		// v1   5  6  7  4
        		// v2  10 11  8  9
        		// v3  15 12 13 14
        		// load CHACHA state with indexes shifted as shown above
        		"LD1 { v0.4S-v3.4S }, %[x_in] \n"

        		// EVEN ROUND

        		// loading of shifted chacha state is done using Table vector Lookup (TBL)
        		// rotate 32 bit word vector elements left by 1
        		// v5: 0x07060504 0x0B0A0908 0x0F0E0D0C 0x03020100
        		// rotate 32 bit word vector elements left by 2
        		// v6: 0x0B0A0908 0x0F0E0D0C 0x03020100 0x07060504
        		// rotate 32 bit word vector elements left by 3
        		// v7: 0x0F0E0D0C 0x03020100 0x07060504 0x0B0A0908
        		// The above values are stored in the v5-v7 registers and when used as the index
        		// it rotates the elements of the vector.

        		// loading the table vector lookup addresses into v5-v7
        		// v5
        		"MOV  x0, 0x0504 \n"
        		"MOVK x0, 0x0706, LSL #16 \n"
        		"MOVK x0, 0x0908, LSL #32 \n"
        		"MOVK x0, 0x0B0A, LSL #48 \n"
        		"MOV v5.D[0], x0 \n"
        		"MOV  x0, 0x0D0C \n"
        		"MOVK x0, 0x0F0E, LSL #16 \n"
        		"MOVK x0, 0x0100, LSL #32 \n"
        		"MOVK x0, 0x0302, LSL #48 \n"
        		"MOV v5.D[1], x0 \n"

        		// v6
        		"MOV  x0, 0x0908 \n"
        		"MOVK x0, 0x0B0A, LSL #16 \n"
        		"MOVK x0, 0x0D0C, LSL #32 \n"
        		"MOVK x0, 0x0F0E, LSL #48 \n"
        		"MOV v6.D[0], x0 \n"
        		"MOV  x0, 0x0100 \n"
        		"MOVK x0, 0x0302, LSL #16 \n"
        		"MOVK x0, 0x0504, LSL #32 \n"
        		"MOVK x0, 0x0706, LSL #48 \n"
        		"MOV v6.D[1], x0 \n"

        		// v7
        		"MOV  x0, 0x0D0C \n"
        		"MOVK x0, 0x0F0E, LSL #16 \n"
        		"MOVK x0, 0x0100, LSL #32 \n"
        		"MOVK x0, 0x0302, LSL #48 \n"
        		"MOV v7.D[0], x0 \n"
        		"MOV  x0, 0x0504 \n"
        		"MOVK x0, 0x0706, LSL #16 \n"
        		"MOVK x0, 0x0908, LSL #32 \n"
        		"MOVK x0, 0x0B0A, LSL #48 \n"
        		"MOV v7.D[1], x0 \n"

        		"TBL v1.16B, { v1.16B }, v5.16B \n" // shift elements left by one
        		"TBL v2.16B, { v2.16B }, v6.16B \n" // shift elements left by two
        		"TBL v3.16B, { v3.16B }, v7.16B \n" // shift elements left by three

        		"ADD v0.4S, v0.4S, v1.4S \n"
        		"EOR v3.16B, v3.16B, v0.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v3.4S, #16 \n"
        		"USHR v3.4S, v3.4S, #16 \n"
        		"ORR v3.16B, v3.16B, v4.16B \n"

        		"ADD v2.4S, v2.4S, v3.4S \n"
        		"EOR v1.16B, v1.16B, v2.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v1.4S, #12 \n"
        		"USHR v1.4S, v1.4S, #20 \n"
        		"ORR v1.16B, v1.16B, v4.16B \n"

        		"ADD v0.4S, v0.4S, v1.4S \n"
        		"EOR v3.16B, v3.16B, v0.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v3.4S, #8 \n"
        		"USHR v3.4S, v3.4S, #24 \n"
        		"ORR v3.16B, v3.16B, v4.16B \n"

        		"ADD v2.4S, v2.4S, v3.4S \n"
        		"EOR v1.16B, v1.16B, v2.16B \n"
        		// SIMD instructions don't support rotation so we have to cheat using shifts and a help register
        		"SHL v4.4S, v1.4S, #7 \n"
        		"USHR v1.4S, v1.4S, #25 \n"
        		"ORR v1.16B, v1.16B, v4.16B \n"

        		"TBL v1.16B, { v1.16B }, v7.16B \n" // shift elements left by three
        		"TBL v2.16B, { v2.16B }, v6.16B \n" // shift elements left by two
        		"TBL v3.16B, { v3.16B }, v5.16B \n" // shift elements left by one

        		"ST1 { v0.4S-v3.4S }, %[x_out] \n"

        		: [x_out] "=m" (x)
			    : [x_in] "m" (x)
				: "memory",
				  "x0",
				  "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"
		);

//        QUARTERROUND(0, 4,  8, 12)
//        QUARTERROUND(1, 5,  9, 13)
//        QUARTERROUND(2, 6, 10, 14)
//        QUARTERROUND(3, 7, 11, 15)
//        QUARTERROUND(0, 5, 10, 15)
//        QUARTERROUND(1, 6, 11, 12)
//        QUARTERROUND(2, 7,  8, 13)
//        QUARTERROUND(3, 4,  9, 14)
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        x[i] = PLUS(x[i], input[i]);
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        output[i] = LITTLE32(x[i]);
    }
}

/**
  * Encrypt a stream of bytes
  */
static void wc_Chacha_encrypt_bytes(ChaCha* ctx, const byte* m, byte* c,
                                    word32 bytes)
{
    byte*  output;
    word32 temp[CHACHA_CHUNK_WORDS]; /* used to make sure aligned */
    word32 i;

    output = (byte*)temp;

    for (; bytes > 0;) {
        wc_Chacha_wordtobyte(temp, ctx->X);
        ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);
        if (bytes <= CHACHA_CHUNK_BYTES) {

        	while (bytes >= ARM_SIMD_LEN_BYTES) {
                __asm__ __volatile__ (
                		"LD1 { v0.16B }, [%[m]] \n"
                		"LD1 { v1.16B }, [%[output]] \n"
                		"EOR v0.16B, v0.16B, v1.16B \n"
                		"ST1 { v0.16B }, [%[c]] \n"
                		: [c] "=r" (c)
    				    : "0" (c), [m] "r" (m), [output] "r" (output)
    					: "memory", "v0", "v1"
                );

                bytes -= ARM_SIMD_LEN_BYTES;
                c += ARM_SIMD_LEN_BYTES;
                m += ARM_SIMD_LEN_BYTES;
                output += ARM_SIMD_LEN_BYTES;
        	}

        	if (bytes >= ARM_SIMD_LEN_BYTES / 2) {
                __asm__ __volatile__ (
                		"LD1 { v0.8B }, [%[m]] \n"
                		"LD1 { v1.8B }, [%[output]] \n"
                		"EOR v0.8B, v0.8B, v1.8B \n"
                		"ST1 { v0.8B }, [%[c]] \n"
                		: [c] "=r" (c)
    				    : "0" (c), [m] "r" (m), [output] "r" (output)
    					: "memory", "v0", "v1"
                );

                bytes -= ARM_SIMD_LEN_BYTES / 2;
                c += ARM_SIMD_LEN_BYTES / 2;
                m += ARM_SIMD_LEN_BYTES / 2;
                output += ARM_SIMD_LEN_BYTES / 2;
        	}

            for (i = 0; i < bytes; ++i) {
                c[i] = m[i] ^ output[i];
            }

            return;
        }

        // assume CHACHA_CHUNK_BYTES == 64
        __asm__ __volatile__ (
        		"LD1 { v0.16B-v3.16B }, [%[m]] \n"
        		"LD1 { v4.16B-v7.16B }, [%[output]] \n"
        		"EOR v0.16B, v0.16B, v4.16B \n"
        		"EOR v1.16B, v1.16B, v5.16B \n"
        		"EOR v2.16B, v2.16B, v6.16B \n"
        		"EOR v3.16B, v3.16B, v7.16B \n"
        		"ST1 { v0.16B-v3.16B }, [%[c]] \n"
        		: [c] "=r" (c)
			    : "0" (c), [m] "r" (m), [output] "r" (output)
				: "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"
        );

        bytes -= CHACHA_CHUNK_BYTES;
        c += CHACHA_CHUNK_BYTES;
        m += CHACHA_CHUNK_BYTES;
    }
}

/**
  * API to encrypt/decrypt a message of any size.
  */
int wc_Chacha_Process(ChaCha* ctx, byte* output, const byte* input,
                      word32 msglen)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    wc_Chacha_encrypt_bytes(ctx, input, output, msglen);

    return 0;
}

#endif /* HAVE_CHACHA*/

#endif /* WOLFSSL_ARMASM */
