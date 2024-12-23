/* cpuid.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/cpuid.h>

#if defined(HAVE_CPUID) || defined(HAVE_CPUID_INTEL) || \
    defined(HAVE_CPUID_AARCH64)
    static word32 cpuid_check = 0;
    static word32 cpuid_flags = 0;
#endif

#ifdef HAVE_CPUID_INTEL
    /* Each platform needs to query info type 1 from cpuid to see if aesni is
     * supported. Also, let's setup a macro for proper linkage w/o ABI conflicts
     */

    #ifndef _MSC_VER
        #define cpuid(reg, leaf, sub)\
            __asm__ __volatile__ ("cpuid":\
                "=a" ((reg)[0]), "=b" ((reg)[1]), "=c" ((reg)[2]), "=d" ((reg)[3]) :\
                "a" (leaf), "c"(sub));
    #else
        #include <intrin.h>

        #define cpuid(a,b,c) __cpuidex((int*)a,b,c)
    #endif /* _MSC_VER */

    #define EAX 0
    #define EBX 1
    #define ECX 2
    #define EDX 3

    static word32 cpuid_flag(word32 leaf, word32 sub, word32 num, word32 bit)
    {
        int got_intel_cpu = 0;
        int got_amd_cpu = 0;
        unsigned int reg[5];
        reg[4] = '\0';
        cpuid(reg, 0, 0);

        /* check for Intel cpu */
        if (XMEMCMP((char *)&(reg[EBX]), "Genu", 4) == 0 &&
            XMEMCMP((char *)&(reg[EDX]), "ineI", 4) == 0 &&
            XMEMCMP((char *)&(reg[ECX]), "ntel", 4) == 0) {
            got_intel_cpu = 1;
        }

        /* check for AMD cpu */
        if (XMEMCMP((char *)&(reg[EBX]), "Auth", 4) == 0 &&
            XMEMCMP((char *)&(reg[EDX]), "enti", 4) == 0 &&
            XMEMCMP((char *)&(reg[ECX]), "cAMD", 4) == 0) {
            got_amd_cpu = 1;
        }

        if (got_intel_cpu || got_amd_cpu) {
            cpuid(reg, leaf, sub);
            return ((reg[num] >> bit) & 0x1);
        }
        return 0;
    }


    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
            if (cpuid_flag(1, 0, ECX, 28)) { cpuid_flags |= CPUID_AVX1  ; }
            if (cpuid_flag(7, 0, EBX,  5)) { cpuid_flags |= CPUID_AVX2  ; }
            if (cpuid_flag(7, 0, EBX,  8)) { cpuid_flags |= CPUID_BMI2  ; }
            if (cpuid_flag(1, 0, ECX, 30)) { cpuid_flags |= CPUID_RDRAND; }
            if (cpuid_flag(7, 0, EBX, 18)) { cpuid_flags |= CPUID_RDSEED; }
            if (cpuid_flag(1, 0, ECX, 25)) { cpuid_flags |= CPUID_AESNI ; }
            if (cpuid_flag(7, 0, EBX, 19)) { cpuid_flags |= CPUID_ADX   ; }
            if (cpuid_flag(1, 0, ECX, 22)) { cpuid_flags |= CPUID_MOVBE ; }
            if (cpuid_flag(7, 0, EBX,  3)) { cpuid_flags |= CPUID_BMI1  ; }
            if (cpuid_flag(7, 0, EBX, 29)) { cpuid_flags |= CPUID_SHA   ; }

            cpuid_check = 1;
        }
    }
#elif defined(HAVE_CPUID_AARCH64)

#define CPUID_AARCH64_FEAT_AES         ((word64)1 << 4)
#define CPUID_AARCH64_FEAT_AES_PMULL   ((word64)1 << 5)
#define CPUID_AARCH64_FEAT_SHA256      ((word64)1 << 12)
#define CPUID_AARCH64_FEAT_SHA256_512  ((word64)1 << 13)
#define CPUID_AARCH64_FEAT_RDM         ((word64)1 << 28)
#define CPUID_AARCH64_FEAT_SHA3        ((word64)1 << 32)
#define CPUID_AARCH64_FEAT_SM3         ((word64)1 << 36)
#define CPUID_AARCH64_FEAT_SM4         ((word64)1 << 40)

#ifdef WOLFSSL_AARCH64_PRIVILEGE_MODE
    /* https://developer.arm.com/documentation/ddi0601/2024-09/AArch64-Registers
     * /ID-AA64ISAR0-EL1--AArch64-Instruction-Set-Attribute-Register-0 */

    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
            word64 features;

            __asm__ __volatile (
                "mrs    %[feat], ID_AA64ISAR0_EL1\n"
                : [feat] "=r" (features)
                :
                :
            );

            if (features & CPUID_AARCH64_FEAT_AES)
                cpuid_flags |= CPUID_AES;
            if (features & CPUID_AARCH64_FEAT_AES_PMULL) {
                cpuid_flags |= CPUID_AES;
                cpuid_flags |= CPUID_PMULL;
            }
            if (features & CPUID_AARCH64_FEAT_SHA256)
                cpuid_flags |= CPUID_SHA256;
            if (features & CPUID_AARCH64_FEAT_SHA256_512)
                cpuid_flags |= CPUID_SHA256 | CPUID_SHA512;
            if (features & CPUID_AARCH64_FEAT_RDM)
                cpuid_flags |= CPUID_RDM;
            if (features & CPUID_AARCH64_FEAT_SHA3)
                cpuid_flags |= CPUID_SHA3;
            if (features & CPUID_AARCH64_FEAT_SM3)
                cpuid_flags |= CPUID_SM3;
            if (features & CPUID_AARCH64_FEAT_SM4)
                cpuid_flags |= CPUID_SM4;

            cpuid_check = 1;
        }
    }
#elif defined(__linux__)
    /* https://community.arm.com/arm-community-blogs/b/operating-systems-blog/
     * posts/runtime-detection-of-cpu-features-on-an-armv8-a-cpu */

    #include <sys/auxv.h>
    #include <asm/hwcap.h>

    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
            word64 hwcaps = getauxval(AT_HWCAP);

            if (hwcaps & HWCAP_AES)
                cpuid_flags |= CPUID_AES;
            if (hwcaps & HWCAP_PMULL)
                cpuid_flags |= CPUID_PMULL;
            if (hwcaps & HWCAP_SHA2)
                cpuid_flags |= CPUID_SHA256;
            if (hwcaps & HWCAP_SHA512)
                cpuid_flags |= CPUID_SHA512;
            if (hwcaps & HWCAP_ASIMDRDM)
                cpuid_flags |= CPUID_RDM;
            if (hwcaps & HWCAP_SHA3)
                cpuid_flags |= CPUID_SHA3;
            if (hwcaps & HWCAP_SM3)
                cpuid_flags |= CPUID_SM3;
            if (hwcaps & HWCAP_SM4)
                cpuid_flags |= CPUID_SM4;

            cpuid_check = 1;
        }
    }
#elif defined(__ANDROID__) || defined(ANDROID)
    /* https://community.arm.com/arm-community-blogs/b/operating-systems-blog/
     * posts/runtime-detection-of-cpu-features-on-an-armv8-a-cpu */

    #include "cpu-features.h"

    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
            word64 features = android_getCpuFeatures();

            if (features & ANDROID_CPU_ARM_FEATURE_AES)
                cpuid_flags |= CPUID_AES;
            if (features & ANDROID_CPU_ARM_FEATURE_PMULL)
                cpuid_flags |= CPUID_PMULL;
            if (features & ANDROID_CPU_ARM_FEATURE_SHA2)
                cpuid_flags |= CPUID_SHA256;

            cpuid_check = 1;
        }
    }
#elif defined(__APPLE__)
    /* https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/
     * determining_instruction_set_characteristics */

    #include <sys/sysctl.h>

    static word64 cpuid_get_sysctlbyname(const char* name)
    {
        word64 ret = 0;
        size_t size = sizeof(ret);

        sysctlbyname(name, &ret, &size, NULL, 0);

        return ret;
    }

    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
            if (cpuid_get_sysctlbyname("hw.optional.arm.FEAT_AES") != 0)
                cpuid_flags |= CPUID_AES;
            if (cpuid_get_sysctlbyname("hw.optional.arm.FEAT_PMULL") != 0)
                cpuid_flags |= CPUID_PMULL;
            if (cpuid_get_sysctlbyname("hw.optional.arm.FEAT_SHA256") != 0)
                cpuid_flags |= CPUID_SHA256;
            if (cpuid_get_sysctlbyname("hw.optional.arm.FEAT_SHA512") != 0)
                cpuid_flags |= CPUID_SHA512;
            if (cpuid_get_sysctlbyname("hw.optional.arm.FEAT_RDM") != 0)
                cpuid_flags |= CPUID_RDM;
            if (cpuid_get_sysctlbyname("hw.optional.arm.FEAT_SHA3") != 0)
                cpuid_flags |= CPUID_SHA3;
        #ifdef WOLFSSL_ARMASM_CRYPTO_SM3
            cpuid_flags |= CPUID_SM3;
        #endif
        #ifdef WOLFSSL_ARMASM_CRYPTO_SM4
            cpuid_flags |= CPUID_SM4;
        #endif

            cpuid_check = 1;
        }
    }
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
    /* https://man.freebsd.org/cgi/man.cgi?elf_aux_info(3) */

    #include <sys/auxv.h>

    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
            word64 features = 0;

            elf_aux_info(AT_HWCAP, &features, sizeof(features));

            if (features & CPUID_AARCH64_FEAT_AES)
                cpuid_flags |= CPUID_AES;
            if (features & CPUID_AARCH64_FEAT_PMULL)
                cpuid_flags |= CPUID_PMULL;
            if (features & CPUID_AARCH64_FEAT_SHA256)
                cpuid_flags |= CPUID_SHA256;
            if (features & CPUID_AARCH64_FEAT_SHA256_512)
                cpuid_flags |= CPUID_SHA256 | CPUID_SHA512;
            if (features & CPUID_AARCH64_FEAT_RDM)
                cpuid_flags |= CPUID_RDM;
            if (features & CPUID_AARCH64_FEAT_SHA3)
                cpuid_flags |= CPUID_SHA3;
            if (features & CPUID_AARCH64_FEAT_SM3)
                cpuid_flags |= CPUID_SM3;
            if (features & CPUID_AARCH64_FEAT_SM4)
                cpuid_flags |= CPUID_SM4;

            cpuid_check = 1;
        }
    }
#else
    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
        #ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
            cpuid_flags |= CPUID_AES;
            cpuid_flags |= CPUID_PMULL;
            cpuid_flags |= CPUID_SHA256;
        #endif
        #ifdef WOLFSSL_ARMASM_CRYPTO_SHA512
            cpuid_flags |= CPUID_SHA512;
        #endif
        #ifndef WOLFSSL_AARCH64_NO_SQRMLSH
            cpuid_flags |= CPUID_RDM;
        #endif
        #ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
            cpuid_flags |= CPUID_SHA3;
        #endif
        #ifdef WOLFSSL_ARMASM_CRYPTO_SM3
            cpuid_flags |= CPUID_SM3;
        #endif
        #ifdef WOLFSSL_ARMASM_CRYPTO_SM4
            cpuid_flags |= CPUID_SM4;
        #endif

            cpuid_check = 1;
        }
    }
#endif
#elif defined(HAVE_CPUID)
    void cpuid_set_flags(void)
    {
        if (!cpuid_check) {
            cpuid_flags = 0;
            cpuid_check = 1;
        }
    }
#endif

#ifdef HAVE_CPUID

    word32 cpuid_get_flags(void)
    {
        if (!cpuid_check)
            cpuid_set_flags();
        return cpuid_flags;
    }

    void cpuid_select_flags(word32 flags)
    {
        cpuid_flags = flags;
    }

    void cpuid_set_flag(word32 flag)
    {
        cpuid_flags |= flag;
    }

    void cpuid_clear_flag(word32 flag)
    {
        cpuid_flags &= ~flag;
    }

#endif /* HAVE_CPUID */
