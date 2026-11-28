/* mpfs_athena.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* The Athena F5200 "TeraFire" user cryptoprocessor of the PolarFire SoC "S"
 * grade parts, through the wolfCrypt crypto callback: SHA-224, SHA-256,
 * SHA-384, SHA-512 and SHA-512/t; AES-ECB, CBC, CTR and GCM, AES-CMAC and AES
 * key wrap at every key size, with ECB carrying AES-XTS; the NRBG as the seed
 * of wolfCrypt's DRBG, and optionally the engine's own DRBG; ECDSA, ECDH and
 * EC key generation on P-192 to P-521; and the raw RSA public and CRT private
 * operations.
 *
 * The engine is driven by Microchip's CAL (Crypto Abstraction Library), which
 * is referenced by include path and never vendored: it carries a Mercury
 * Systems notice. Point the build at the CAL directory with
 * ./configure --with-mpfs-athena=PATH, or add it to the include path and define
 * WOLFSSL_MICROCHIP_MPFS and WOLFSSL_MPFS_ATHENA in user_settings.h.
 *
 * Register the device once, after wolfCrypt_Init():
 *
 *      wc_MpfsAthena_RegisterDevice(WC_MPFS_ATHENA_DEVID);
 *      wc_MpfsAthena_SelfTest();
 *
 * then pass that devId to the _ex init of the object: wc_InitSha256_ex(),
 * wc_AesInit(), wc_ecc_init_ex(), wc_InitRsaKey_ex(), wc_InitRng_ex() and so
 * on. Objects tagged with any other devId stay in software.
 *
 * Each family can be kept in software: WC_MPFS_ATHENA_NO_SHA256 (SHA-224 and
 * SHA-256), WC_MPFS_ATHENA_NO_SHA512 (SHA-512 and SHA-512/t; SHA-384 follows
 * WOLFSSL_SHA384), WC_MPFS_ATHENA_NO_CBC, WC_MPFS_ATHENA_NO_GCM,
 * WC_MPFS_ATHENA_NO_KEYWRAP, WC_MPFS_ATHENA_NO_CMAC, WC_MPFS_ATHENA_NO_RNG,
 * WC_MPFS_ATHENA_NO_ECC and WC_MPFS_ATHENA_NO_RSA.
 *
 * Both published CAL archives are soft-float lp64, so every object linked
 * against them must be built -mabi=lp64. The port is M-mode bare metal: the
 * archives are non-PIC and bake in physical addresses, so they cannot be linked
 * into a shared library or used from Linux user space.
 */

#ifndef WOLFPORT_MPFS_ATHENA_H
#define WOLFPORT_MPFS_ATHENA_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_MPFS_ATHENA

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_MPFS_ATHENA needs WOLF_CRYPTO_CB; include \
<wolfssl/wolfcrypt/settings.h> first, which sets it"
#endif

#include <wolfssl/wolfcrypt/cryptocb.h>

/* The User Crypto base in the Libero design. The CAL published with
 * polarfire-soc-bare-metal-examples reads it from a global the caller owns
 * (config_user.h declares g_user_crypto_base_addr and defines PKX0_BASE from
 * it), so the port defines that global. The CAL shipped with
 * hart-software-services bakes the address in instead and never references the
 * symbol, which is why it looks unused in that build. Define
 * WC_MPFS_ATHENA_NO_BASE_ADDR when the platform already supplies it. */
#ifndef WC_MPFS_ATHENA_BASE_ADDR
    #define WC_MPFS_ATHENA_BASE_ADDR 0x22000000UL
#endif

/* ATHENAREG: ATHENA_CR +0x00, STALL_CR +0x04, UPPER_ADDRESS +0x08. */
#ifndef WC_MPFS_ATHENA_REG_BASE
    #define WC_MPFS_ATHENA_REG_BASE 0x20127000UL
#endif

/* MSS SYSREG, for SUBBLK_CLOCK_CR and SOFT_RESET_CR. */
#ifndef WC_MPFS_ATHENA_SYSREG_BASE
    #define WC_MPFS_ATHENA_SYSREG_BASE 0x20002000UL
#endif

/* Opaque room for one CAL SATRESCONTEXT, in words because CAL wants the
 * alignment. 144 bytes on both published header sets; the port static-asserts
 * the real size so a CAL update cannot silently overflow it. */
#ifndef WC_MPFS_ATHENA_CTX_WORDS
    #define WC_MPFS_ATHENA_CTX_WORDS 48
#endif

/* iGetBlockLen(SATHASHTYPE_SHA384). A non-final CALHashCtx() call must be a
 * whole number of blocks; this is two SHA-256 blocks, so every SHA-2 type is
 * fed in multiples of it. */
#ifndef WC_MPFS_ATHENA_BLOCK_SZ
    #define WC_MPFS_ATHENA_BLOCK_SZ 128
#endif

/* Concurrent SHA-2 contexts the port can offload when there is no heap
 * (WOLFSSL_NO_MALLOC or WOLFSSL_STATIC_MEMORY). Beyond this, hashing falls back
 * to software. Each slot costs WC_MPFS_ATHENA_CTX_WORDS words plus a block. */
#ifndef WC_MPFS_ATHENA_HASH_SLOTS
    #define WC_MPFS_ATHENA_HASH_SLOTS 4
#endif

/* Smallest AES-ECB request the engine serves; shorter ones go to software.
 * XTS sends its tweak and stealing tail as one-block calls, and a CAL round
 * trip per block loses to software. Self-test needs twice this as scratch. */
#ifndef WC_MPFS_ATHENA_AES_MIN_SZ
    #define WC_MPFS_ATHENA_AES_MIN_SZ 32
#endif

/* Smallest AES-GCM payload the engine serves; shorter ones go to software. */
#ifndef WC_MPFS_ATHENA_GCM_MIN_SZ
    #define WC_MPFS_ATHENA_GCM_MIN_SZ 0
#endif

/* Largest RSA modulus the engine serves, in bits; larger keys go to software.
 * The operand scratch for one operation scales with it. */
#ifndef WC_MPFS_ATHENA_RSA_MAX_BITS
    #define WC_MPFS_ATHENA_RSA_MAX_BITS 4096
#endif

/* Define WC_MPFS_ATHENA_RSA_PUBLIC to also serve RSA public operations. They
 * are left to software by default: with a small public exponent the engine is
 * slower than software. */

/* With WC_MPFS_ATHENA_RNG_DRBG, generate calls between reseeds of the
 * engine's DRBG. */
#ifndef WC_MPFS_ATHENA_DRBG_RESEED
    #define WC_MPFS_ATHENA_DRBG_RESEED 1024
#endif

WOLFSSL_API int wc_MpfsAthena_Init(void);
WOLFSSL_API int wc_MpfsAthena_RegisterDevice(int devId);
WOLFSSL_API void wc_MpfsAthena_UnRegisterDevice(int devId);
WOLFSSL_API int wc_MpfsAthena_CryptoDevCb(int devId, wc_CryptoInfo* info,
    void* ctx);
/* Known-answer tests, compiled only with WC_MPFS_ATHENA_SELFTEST; otherwise
 * wc_MpfsAthena_SelfTest() returns NOT_COMPILED_IN. */
WOLFSSL_API int wc_MpfsAthena_SelfTest(void);
WOLFSSL_API const char* wc_MpfsAthena_SelfTestDesc(void);
WOLFSSL_API word32 wc_MpfsAthena_GetCbCount(void);
/* NRBG entropy; random.c's wc_GenerateSeed() calls it for every RNG. */
#if !defined(WC_NO_RNG) && defined(HAVE_HASHDRBG) && \
    !defined(CUSTOM_RAND_GENERATE_BLOCK) && !defined(WC_MPFS_ATHENA_NO_RNG)
WOLFSSL_API int wc_MpfsAthena_GenerateSeed(byte* output, word32 sz);
#endif

#endif /* WOLFSSL_MPFS_ATHENA */

#endif /* WOLFPORT_MPFS_ATHENA_H */
