/* random.h
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


#ifndef CTAO_CRYPT_RANDOM_H
#define CTAO_CRYPT_RANDOM_H

#include <cyassl/ctaocrypt/types.h>

#ifndef NO_RC4
    #include <cyassl/ctaocrypt/arc4.h>
#else
    #include <cyassl/ctaocrypt/sha256.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif


#if defined(USE_WINDOWS_API)
    #if defined(_WIN64)
        typedef unsigned __int64 ProviderHandle;
        /* type HCRYPTPROV, avoid #include <windows.h> */
    #else
        typedef unsigned long ProviderHandle;
    #endif
#endif


/* OS specific seeder */
typedef struct OS_Seed {
    #if defined(USE_WINDOWS_API)
        ProviderHandle handle;
    #else
        int fd;
    #endif
} OS_Seed;


CYASSL_LOCAL
int GenerateSeed(OS_Seed* os, byte* seed, word32 sz);

#if defined(CYASSL_MDK_ARM)
#undef RNG
#define RNG CyaSSL_RNG   /* for avoiding name conflict in "stm32f2xx.h" */
#endif

#ifndef NO_RC4

#define CYASSL_RNG_CAVIUM_MAGIC 0xBEEF0004

/* secure Random Nnumber Generator */


typedef struct RNG {
    OS_Seed seed;
    Arc4    cipher;
#ifdef HAVE_CAVIUM
    int    devId;           /* nitrox device id */
    word32 magic;           /* using cavium magic */
#endif
} RNG;


#ifdef HAVE_CAVIUM
    CYASSL_API int  InitRngCavium(RNG*, int);
#endif

#else /* NO_RC4 */

#define DBRG_SEED_LEN (440/8)


/* secure Random Nnumber Generator */
typedef struct RNG {
    OS_Seed seed;

    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    byte V[DBRG_SEED_LEN];
    byte C[DBRG_SEED_LEN];
    word64 reseed_ctr;
} RNG;

#endif

CYASSL_API int  InitRng(RNG*);
CYASSL_API void RNG_GenerateBlock(RNG*, byte*, word32 sz);
CYASSL_API byte RNG_GenerateByte(RNG*);

#ifdef NO_RC4
    CYASSL_API void FreeRng(RNG*);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_RANDOM_H */

