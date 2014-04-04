/* random.c
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

/* on HPUX 11 you may need to install /dev/random see
   http://h20293.www2.hp.com/portal/swdepot/displayProductInfo.do?productNumber=KRNG11I

*/

#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/error-crypt.h>

#ifdef NO_RC4
    #include <cyassl/ctaocrypt/sha256.h>

    #ifdef NO_INLINE
        #include <cyassl/ctaocrypt/misc.h>
    #else
        #define MISC_DUMM_FUNC misc_dummy_random
        #include <ctaocrypt/src/misc.c>
    #endif
#endif

#if defined(USE_WINDOWS_API)
    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0400
    #endif
    #include <windows.h>
    #include <wincrypt.h>
#else
    #if !defined(NO_DEV_RANDOM) && !defined(CYASSL_MDK_ARM) \
                                && !defined(CYASSL_IAR_ARM)
            #include <fcntl.h>
        #ifndef EBSNET
            #include <unistd.h>
        #endif
    #else
        /* include headers that may be needed to get good seed */
    #endif
#endif /* USE_WINDOWS_API */


#ifdef NO_RC4

/* Start NIST DRBG code */

#define OUTPUT_BLOCK_LEN (256/8)
#define MAX_REQUEST_LEN  (0x1000)
#define MAX_STRING_LEN   (0x100000000)
#define RESEED_MAX       (0x100000000000LL)
#define ENTROPY_SZ       256

#define DBRG_SUCCESS 0
#define DBRG_ERROR 1
#define DBRG_NEED_RESEED 2


enum {
    dbrgInitC     = 0,
    dbrgReseed    = 1,
    dbrgGenerateW = 2,
    dbrgGenerateH = 3,
    dbrgInitV
};


static int Hash_df(RNG* rng, byte* out, word32 outSz, byte type, byte* inA, word32 inASz,
                               byte* inB, word32 inBSz, byte* inC, word32 inCSz)
{
    byte ctr;
    int i;
    int len;
    word32 bits = (outSz * 8); /* reverse byte order */

    #ifdef LITTLE_ENDIAN_ORDER
        bits = ByteReverseWord32(bits);
    #endif
    len = (outSz / SHA256_DIGEST_SIZE)
        + ((outSz % SHA256_DIGEST_SIZE) ? 1 : 0);

    for (i = 0, ctr = 1; i < len; i++, ctr++)
    {
        if (InitSha256(&rng->sha) != 0)
            return DBRG_ERROR;
        Sha256Update(&rng->sha, &ctr, sizeof(ctr));
        Sha256Update(&rng->sha, (byte*)&bits, sizeof(bits));
        /* churning V is the only string that doesn't have
         * the type added */
        if (type != dbrgInitV)
            Sha256Update(&rng->sha, &type, sizeof(type));
        Sha256Update(&rng->sha, inA, inASz);
        if (inB != NULL && inBSz > 0)
            Sha256Update(&rng->sha, inB, inBSz);
        if (inC != NULL && inCSz > 0)
            Sha256Update(&rng->sha, inC, inCSz);
        Sha256Final(&rng->sha, rng->digest);

        if (outSz > SHA256_DIGEST_SIZE) {
            XMEMCPY(out, rng->digest, SHA256_DIGEST_SIZE);
            outSz -= SHA256_DIGEST_SIZE;
            out += SHA256_DIGEST_SIZE;
        }
        else {
            XMEMCPY(out, rng->digest, outSz);
        }
    }

    return DBRG_SUCCESS;
}


static int Hash_DBRG_Reseed(RNG* rng, byte* entropy, word32 entropySz)
{
    byte seed[DBRG_SEED_LEN];

    Hash_df(rng, seed, sizeof(seed), dbrgInitV, rng->V, sizeof(rng->V),
                                                  entropy, entropySz, NULL, 0);
    XMEMCPY(rng->V, seed, sizeof(rng->V));
    XMEMSET(seed, 0, sizeof(seed));

    Hash_df(rng, rng->C, sizeof(rng->C), dbrgInitC, rng->V, sizeof(rng->V),
                                                             NULL, 0, NULL, 0);
    rng->reseed_ctr = 1;
    return 0;
}

static INLINE void array_add_one(byte* data, word32 dataSz)
{
    int i;

    for (i = dataSz - 1; i >= 0; i--)
    {
        data[i]++;
        if (data[i] != 0) break;
    }
}

static int Hash_gen(RNG* rng, byte* out, word32 outSz, byte* V)
{
    byte data[DBRG_SEED_LEN];
    int i, ret;
    int len = (outSz / SHA256_DIGEST_SIZE)
        + ((outSz % SHA256_DIGEST_SIZE) ? 1 : 0);

    XMEMCPY(data, V, sizeof(data));
    for (i = 0; i < len; i++) {
        ret = InitSha256(&rng->sha);
        if (ret != 0) return ret;
        Sha256Update(&rng->sha, data, sizeof(data));
        Sha256Final(&rng->sha, rng->digest);
        if (outSz > SHA256_DIGEST_SIZE) {
            XMEMCPY(out, rng->digest, SHA256_DIGEST_SIZE);
            outSz -= SHA256_DIGEST_SIZE;
            out += SHA256_DIGEST_SIZE;
            array_add_one(data, DBRG_SEED_LEN);
        }
        else {
            XMEMCPY(out, rng->digest, outSz);
        }
    }
    XMEMSET(data, 0, sizeof(data));

    return 0;
}


static INLINE void array_add(byte* d, word32 dLen, byte* s, word32 sLen)
{
    word16 carry = 0;

    if (dLen > 0 && sLen > 0 && dLen >= sLen) {
        int sIdx, dIdx;

        for (sIdx = sLen - 1, dIdx = dLen - 1; sIdx >= 0; dIdx--, sIdx--)
        {
            carry += d[dIdx] + s[sIdx];
            d[dIdx] = carry;
            carry >>= 8;
        }
        if (dIdx > 0)
            d[dIdx] += carry;
    }
}


static int Hash_DBRG_Generate(RNG* rng, byte* out, word32 outSz)
{
    int ret;

    if (rng->reseed_ctr != RESEED_MAX) {
        byte type = dbrgGenerateH;

        if (Hash_gen(rng, out, outSz, rng->V) != 0)
            return DBRG_ERROR;
        if (InitSha256(&rng->sha) != 0)
            return DBRG_ERROR;
        Sha256Update(&rng->sha, &type, sizeof(type));
        Sha256Update(&rng->sha, rng->V, sizeof(rng->V));
        Sha256Final(&rng->sha, rng->digest);
        array_add(rng->V, sizeof(rng->V), rng->digest, sizeof(rng->digest));
        array_add(rng->V, sizeof(rng->V), rng->C, sizeof(rng->C));
        array_add(rng->V, sizeof(rng->V),
                              (byte*)&rng->reseed_ctr, sizeof(rng->reseed_ctr));
        rng->reseed_ctr++;
        ret = DBRG_SUCCESS;
    }
    else {
        ret = DBRG_NEED_RESEED;
    }
    return ret;
}


static void Hash_DBRG_Instantiate(RNG* rng, byte* seed, word32 seedSz)
{
    XMEMSET(rng, 0, sizeof(*rng));
    Hash_df(rng, rng->V, sizeof(rng->V), dbrgInitV, seed, seedSz, NULL, 0, NULL, 0);
    Hash_df(rng, rng->C, sizeof(rng->C), dbrgInitC, rng->V, sizeof(rng->V),
                                                             NULL, 0, NULL, 0);
    rng->reseed_ctr = 1;
}


static int Hash_DBRG_Uninstantiate(RNG* rng)
{
    int result = DBRG_ERROR;

    if (rng != NULL) {
        XMEMSET(rng, 0, sizeof(*rng));
        result = DBRG_SUCCESS;
    }

    return result;
}

/* End NIST DRBG Code */



/* Get seed and key cipher */
int InitRng(RNG* rng)
{
    byte entropy[ENTROPY_SZ];
    int  ret = DBRG_ERROR;

    if (GenerateSeed(&rng->seed, entropy, sizeof(entropy)) == 0) {
        Hash_DBRG_Instantiate(rng, entropy, sizeof(entropy));
        ret = DBRG_SUCCESS;
    }
    XMEMSET(entropy, 0, sizeof(entropy));
    return ret;
}


/* place a generated block in output */
void RNG_GenerateBlock(RNG* rng, byte* output, word32 sz)
{
    int ret;

    XMEMSET(output, 0, sz);
    ret = Hash_DBRG_Generate(rng, output, sz);
    if (ret == DBRG_NEED_RESEED) {
        byte entropy[ENTROPY_SZ];
        ret = GenerateSeed(&rng->seed, entropy, sizeof(entropy));
        if (ret == 0) {
            Hash_DBRG_Reseed(rng, entropy, sizeof(entropy));
            ret = Hash_DBRG_Generate(rng, output, sz);
        }
        else
            ret = DBRG_ERROR;
        XMEMSET(entropy, 0, sizeof(entropy));
    }
}


byte RNG_GenerateByte(RNG* rng)
{
    byte b;
    RNG_GenerateBlock(rng, &b, 1);

    return b;
}


void FreeRng(RNG* rng)
{
    Hash_DBRG_Uninstantiate(rng);
}

#else /* NO_RC4 */

/* Get seed and key cipher */
int InitRng(RNG* rng)
{
    byte key[32];
    byte junk[256];
    int  ret;

#ifdef HAVE_CAVIUM
    if (rng->magic == CYASSL_RNG_CAVIUM_MAGIC)
        return 0;
#endif
    ret = GenerateSeed(&rng->seed, key, sizeof(key));

    if (ret == 0) {
        Arc4SetKey(&rng->cipher, key, sizeof(key));
        RNG_GenerateBlock(rng, junk, sizeof(junk));  /* rid initial state */
    }

    return ret;
}

#ifdef HAVE_CAVIUM
    static void CaviumRNG_GenerateBlock(RNG* rng, byte* output, word32 sz);
#endif

/* place a generated block in output */
void RNG_GenerateBlock(RNG* rng, byte* output, word32 sz)
{
#ifdef HAVE_CAVIUM
    if (rng->magic == CYASSL_RNG_CAVIUM_MAGIC)
        return CaviumRNG_GenerateBlock(rng, output, sz);
#endif
    XMEMSET(output, 0, sz);
    Arc4Process(&rng->cipher, output, output, sz);
}


byte RNG_GenerateByte(RNG* rng)
{
    byte b;
    RNG_GenerateBlock(rng, &b, 1);

    return b;
}


#ifdef HAVE_CAVIUM

#include <cyassl/ctaocrypt/logging.h>
#include "cavium_common.h"

/* Initiliaze RNG for use with Nitrox device */
int InitRngCavium(RNG* rng, int devId)
{
    if (rng == NULL)
        return -1;

    rng->devId = devId;
    rng->magic = CYASSL_RNG_CAVIUM_MAGIC;

    return 0;
}


static void CaviumRNG_GenerateBlock(RNG* rng, byte* output, word32 sz)
{
    word   offset = 0;
    word32 requestId;

    while (sz > CYASSL_MAX_16BIT) {
        word16 slen = (word16)CYASSL_MAX_16BIT;
        if (CspRandom(CAVIUM_BLOCKING, slen, output + offset, &requestId,
                      rng->devId) != 0) {
            CYASSL_MSG("Cavium RNG failed");
        }
        sz     -= CYASSL_MAX_16BIT;
        offset += CYASSL_MAX_16BIT;
    }
    if (sz) {
        word16 slen = (word16)sz;
        if (CspRandom(CAVIUM_BLOCKING, slen, output + offset, &requestId,
                      rng->devId) != 0) {
            CYASSL_MSG("Cavium RNG failed");
        }
    }
}

#endif /* HAVE_CAVIUM */

#endif /* NO_RC4 */


#if defined(USE_WINDOWS_API)


int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    if(!CryptAcquireContext(&os->handle, 0, 0, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT))
        return WINCRYPT_E;

    if (!CryptGenRandom(os->handle, sz, output))
        return CRYPTGEN_E;

    CryptReleaseContext(os->handle, 0);

    return 0;
}


#elif defined(HAVE_RTP_SYS) || defined(EBSNET)

#include "rtprand.h"   /* rtp_rand () */
#include "rtptime.h"   /* rtp_get_system_msec() */


int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    int i;
    rtp_srand(rtp_get_system_msec());

    for (i = 0; i < sz; i++ ) {
        output[i] = rtp_rand() % 256;
        if ( (i % 8) == 7)
            rtp_srand(rtp_get_system_msec());
    }

    return 0;
}


#elif defined(MICRIUM)

int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
        NetSecure_InitSeed(output, sz);
    #endif
    return 0;
}

#elif defined(MBED)

/* write a real one !!!, just for testing board */
int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    int i;
    for (i = 0; i < sz; i++ )
        output[i] = i;

    return 0;
}

#elif defined(MICROCHIP_PIC32)

#ifdef MICROCHIP_MPLAB_HARMONY
    #define PIC32_SEED_COUNT _CP0_GET_COUNT
#else
    #if !defined(CYASSL_MICROCHIP_PIC32MZ)
        #include <peripheral/timer.h>
    #endif
    #define PIC32_SEED_COUNT ReadCoreTimer
#endif
    #ifdef CYASSL_MIC32MZ_RNG
        #include "xc.h"
        int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
        {
            int i ;
            byte rnd[8] ;
            word32 *rnd32 = (word32 *)rnd ;
            word32 size = sz ;
            byte* op = output ;

            /* This part has to be replaced with better random seed */
            RNGNUMGEN1 = ReadCoreTimer();
            RNGPOLY1 = ReadCoreTimer();
            RNGPOLY2 = ReadCoreTimer();
            RNGNUMGEN2 = ReadCoreTimer();
#ifdef DEBUG_CYASSL
            printf("GenerateSeed::Seed=%08x, %08x\n", RNGNUMGEN1, RNGNUMGEN2) ;
#endif
            RNGCONbits.PLEN = 0x40;
            RNGCONbits.PRNGEN = 1;
            for(i=0; i<5; i++) { /* wait for RNGNUMGEN ready */
                volatile int x ;
                x = RNGNUMGEN1 ;
                x = RNGNUMGEN2 ;
            }
            do {
                rnd32[0] = RNGNUMGEN1;
                rnd32[1] = RNGNUMGEN2;

                for(i=0; i<8; i++, op++) {
                    *op = rnd[i] ;
                    size -- ;
                    if(size==0)break ;
                }
            } while(size) ;
            return 0;
        }
    #else  /* CYASSL_MIC32MZ_RNG */
        /* uses the core timer, in nanoseconds to seed srand */
        int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
        {
            int i;
            srand(PIC32_SEED_COUNT() * 25);

            for (i = 0; i < sz; i++ ) {
                output[i] = rand() % 256;
                if ( (i % 8) == 7)
                    srand(PIC32_SEED_COUNT() * 25);
            }
            return 0;
        }
    #endif /* CYASSL_MIC32MZ_RNG */

#elif defined(FREESCALE_MQX)

    #ifdef FREESCALE_K70_RNGA
        /*
         * Generates a RNG seed using the Random Number Generator Accelerator
         * on the Kinetis K70. Documentation located in Chapter 37 of
         * K70 Sub-Family Reference Manual (see Note 3 in the README for link).
         */
        int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
        {
            int i;

            /* turn on RNGA module */
            SIM_SCGC3 |= SIM_SCGC3_RNGA_MASK;

            /* set SLP bit to 0 - "RNGA is not in sleep mode" */
            RNG_CR &= ~RNG_CR_SLP_MASK;

            /* set HA bit to 1 - "security violations masked" */
            RNG_CR |= RNG_CR_HA_MASK;

            /* set GO bit to 1 - "output register loaded with data" */
            RNG_CR |= RNG_CR_GO_MASK;

            for (i = 0; i < sz; i++) {

                /* wait for RNG FIFO to be full */
                while((RNG_SR & RNG_SR_OREG_LVL(0xF)) == 0) {}

                /* get value */
                output[i] = RNG_OR;
            }

            return 0;
        }

    #elif defined(FREESCALE_K53_RNGB)
        /*
         * Generates a RNG seed using the Random Number Generator (RNGB)
         * on the Kinetis K53. Documentation located in Chapter 33 of
         * K53 Sub-Family Reference Manual (see note in the README for link).
         */
        int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
        {
            int i;

            /* turn on RNGB module */
            SIM_SCGC3 |= SIM_SCGC3_RNGB_MASK;

            /* reset RNGB */
            RNG_CMD |= RNG_CMD_SR_MASK;

            /* FIFO generate interrupt, return all zeros on underflow,
             * set auto reseed */
            RNG_CR |= (RNG_CR_FUFMOD_MASK | RNG_CR_AR_MASK);

            /* gen seed, clear interrupts, clear errors */
            RNG_CMD |= (RNG_CMD_GS_MASK | RNG_CMD_CI_MASK | RNG_CMD_CE_MASK);

            /* wait for seeding to complete */
            while ((RNG_SR & RNG_SR_SDN_MASK) == 0) {}

            for (i = 0; i < sz; i++) {

                /* wait for a word to be available from FIFO */
                while((RNG_SR & RNG_SR_FIFO_LVL_MASK) == 0) {}

                /* get value */
                output[i] = RNG_OUT;
            }

            return 0;
        }

	#else
        #warning "write a real random seed!!!!, just for testing now"

        int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
        {
            int i;
            for (i = 0; i < sz; i++ )
                output[i] = i;

            return 0;
        }
	#endif /* FREESCALE_K70_RNGA */

#elif defined(CYASSL_SAFERTOS) || defined(CYASSL_LEANPSK) \
   || defined(CYASSL_IAR_ARM)

#warning "write a real random seed!!!!, just for testing now"

int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    word32 i;
    for (i = 0; i < sz; i++ )
        output[i] = i;

    (void)os;

    return 0;
}

#elif defined(STM32F2_RNG)
    #undef RNG
    #include "stm32f2xx_rng.h"
    #include "stm32f2xx_rcc.h"
    /*
     * Generate a RNG seed using the hardware random number generator
     * on the STM32F2. Documentation located in STM32F2xx Standard Peripheral
     * Library document (See note in README).
     */
    int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        int i;

        /* enable RNG clock source */
        RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_RNG, ENABLE);

        /* enable RNG peripheral */
        RNG_Cmd(ENABLE);

        for (i = 0; i < sz; i++) {
            /* wait until RNG number is ready */
            while(RNG_GetFlagStatus(RNG_FLAG_DRDY)== RESET) { }

            /* get value */
            output[i] = RNG_GetRandomNumber();
        }

        return 0;
    }
#elif defined(CYASSL_LPC43xx) || defined(CYASSL_STM32F2xx)

    #warning "write a real random seed!!!!, just for testing now"

    int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        int i;

        for (i = 0; i < sz; i++ )
            output[i] = i;

        return 0;
    }

#elif defined(CUSTOM_RAND_GENERATE)

   /* Implement your own random generation function
    * word32 rand_gen(void);
    * #define CUSTOM_RAND_GENERATE  rand_gen  */

   int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
   {
     int i;

     for (i = 0; i < sz; i++ )
         output[i] = CUSTOM_RAND_GENERATE();

     return 0;
   }

#elif defined(NO_DEV_RANDOM)

#error "you need to write an os specific GenerateSeed() here"

/*
int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    return 0;
}
*/


#else /* !USE_WINDOWS_API && !HAVE_RPT_SYS && !MICRIUM && !NO_DEV_RANDOM */


/* may block */
int GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    int ret = 0;

    os->fd = open("/dev/urandom",O_RDONLY);
    if (os->fd == -1) {
        /* may still have /dev/random */
        os->fd = open("/dev/random",O_RDONLY);
        if (os->fd == -1)
            return OPEN_RAN_E;
    }

    while (sz) {
        int len = (int)read(os->fd, output, sz);
        if (len == -1) {
            ret = READ_RAN_E;
            break;
        }

        sz     -= len;
        output += len;

        if (sz) {
#ifdef BLOCKING
            sleep(0);             /* context switch */
#else
            ret = RAN_BLOCK_E;
            break;
#endif
        }
    }
    close(os->fd);

    return ret;
}

#endif /* USE_WINDOWS_API */

