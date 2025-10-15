/* cpuid.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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



#ifndef WOLF_CRYPT_CPUID_H
#define WOLF_CRYPT_CPUID_H


#include <wolfssl/wolfcrypt/types.h>


#ifdef __cplusplus
    extern "C" {
#endif

#if (defined(WOLFSSL_X86_64_BUILD) || defined(USE_INTEL_SPEEDUP) || \
    defined(WOLFSSL_AESNI) || defined(WOLFSSL_SP_X86_64_ASM)) && \
    !defined(WOLFSSL_NO_ASM)
    #define HAVE_CPUID
    #define HAVE_CPUID_INTEL
#endif
#if (defined(WOLFSSL_AARCH64_BUILD) || (defined(__aarch64__) && \
     defined(WOLFSSL_ARMASM))) && !defined(WOLFSSL_NO_ASM)
    #define HAVE_CPUID
    #define HAVE_CPUID_AARCH64
#endif

#define WC_CPUID_INITIALIZER 0xffffffffU
typedef word32 cpuid_flags_t;
#if !defined(WOLFSSL_NO_ATOMICS) && !defined(SINGLE_THREADED)
    typedef wolfSSL_Atomic_Uint cpuid_flags_atomic_t;
    #define WC_CPUID_ATOMIC_INITIALIZER \
        WOLFSSL_ATOMIC_INITIALIZER(WC_CPUID_INITIALIZER)
#else
    typedef word32 cpuid_flags_atomic_t;
    #define WC_CPUID_ATOMIC_INITIALIZER WC_CPUID_INITIALIZER
#endif

#ifdef HAVE_CPUID_INTEL

    #define CPUID_AVX1   0x0001
    #define CPUID_AVX2   0x0002
    #define CPUID_RDRAND 0x0004
    #define CPUID_RDSEED 0x0008
    #define CPUID_BMI2   0x0010   /* MULX, RORX */
    #define CPUID_AESNI  0x0020
    #define CPUID_ADX    0x0040   /* ADCX, ADOX */
    #define CPUID_MOVBE  0x0080   /* Move and byte swap */
    #define CPUID_BMI1   0x0100   /* ANDN */
    #define CPUID_SHA    0x0200   /* SHA-1 and SHA-256 instructions */

    #define IS_INTEL_AVX1(f)    (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_AVX1)
    #define IS_INTEL_AVX2(f)    (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_AVX2)
    #define IS_INTEL_RDRAND(f)  (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_RDRAND)
    #define IS_INTEL_RDSEED(f)  (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_RDSEED)
    #define IS_INTEL_BMI2(f)    (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_BMI2)
    #define IS_INTEL_AESNI(f)   (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_AESNI)
    #define IS_INTEL_ADX(f)     (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_ADX)
    #define IS_INTEL_MOVBE(f)   (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_MOVBE)
    #define IS_INTEL_BMI1(f)    (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_BMI1)
    #define IS_INTEL_SHA(f)     (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_SHA)

#elif defined(HAVE_CPUID_AARCH64)

    #define CPUID_AES         0x0001    /* AES enc/dec */
    #define CPUID_PMULL       0x0002    /* Carryless multiplication */
    #define CPUID_SHA256      0x0004    /* SHA-256 digest */
    #define CPUID_SHA512      0x0008    /* SHA-512 digest */
    #define CPUID_RDM         0x0010    /* SQRDMLAH and SQRDMLSH */
    #define CPUID_SHA3        0x0020    /* SHA-3 digest */
    #define CPUID_SM3         0x0040    /* SM3 digest */
    #define CPUID_SM4         0x0080    /* SM4 enc/dec */
    #define CPUID_SB          0x0100    /* Speculation barrier */

    #define IS_AARCH64_AES(f)       (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_AES)
    #define IS_AARCH64_PMULL(f)     (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_PMULL)
    #define IS_AARCH64_SHA256(f)    (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_SHA256)
    #define IS_AARCH64_SHA512(f)    (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_SHA512)
    #define IS_AARCH64_RDM(f)       (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_RDM)
    #define IS_AARCH64_SHA3(f)      (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_SHA3)
    #define IS_AARCH64_SM3(f)       (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_SM3)
    #define IS_AARCH64_SM4(f)       (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_SM4)
    #define IS_AARCH64_SB(f)        (WOLFSSL_ATOMIC_COERCE_UINT(f) & CPUID_SB)

#endif

#ifdef HAVE_CPUID
    cpuid_flags_t cpuid_get_flags(void);

    /* Idempotent flag getter -- fast, but return value (whether updated) is not
     * strictly reliable.
     */
    static WC_INLINE int cpuid_get_flags_ex(cpuid_flags_t *flags) {
        if (*flags == WC_CPUID_INITIALIZER) {
            *flags = cpuid_get_flags();
            return 1;
        }
        else
            return 0;
    }

    /* Strictly race-free flag getter -- slow, but the return value is strictly
     * accurate.
     */
    static WC_INLINE int cpuid_get_flags_atomic(cpuid_flags_atomic_t *flags) {
        if (WOLFSSL_ATOMIC_LOAD(*flags) == WC_CPUID_INITIALIZER) {
            cpuid_flags_t old_cpuid_flags = WC_CPUID_INITIALIZER;
            return wolfSSL_Atomic_Uint_CompareExchange
                (flags, &old_cpuid_flags, cpuid_get_flags());
        }
        else
            return 0;
    }

    /* Public APIs to modify flags. */

    #ifdef WOLFSSL_API_PREFIX_MAP
        #define cpuid_select_flags wc_cpuid_select_flags
        #define cpuid_set_flag wc_cpuid_set_flag
        #define cpuid_clear_flag wc_cpuid_clear_flag
    #endif /* WOLFSSL_API_PREFIX_MAP */

    WOLFSSL_API void cpuid_select_flags(cpuid_flags_t flags);
    WOLFSSL_API void cpuid_set_flag(cpuid_flags_t flag);
    WOLFSSL_API void cpuid_clear_flag(cpuid_flags_t flag);

#endif

#ifdef __cplusplus
    }   /* extern "C" */
#endif


#endif /* WOLF_CRYPT_CPUID_H */
