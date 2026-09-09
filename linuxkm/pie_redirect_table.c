/* pie_redirect_table.c -- module load/unload hooks for libwolfssl.ko
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

#if !defined(WC_CONTAINERIZE_THIS)
    #error pie_redirect_table.c must be compiled -DWC_CONTAINERIZE_THIS.
#endif

#if !defined(__PIE__) && !defined(WC_NO_PIE_FLAG)
    #error pie_redirect_table.c must be compiled -fPIE or -DWC_NO_PIE_FLAG.
#endif

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/ssl.h>

/* compiling -fPIE results in references to the GOT or equivalent thereof, which remain after linking
 * even if all other symbols are resolved by the link.  naturally there is no
 * GOT in the kernel, and the wolfssl Kbuild script explicitly checks that no
 * GOT relocations occur in the PIE objects, but we still need to include a
 * dummy value here, scoped to the module, to eliminate the otherwise unresolved
 * symbol.
 */
#if defined(CONFIG_X86)
    extern void * const _GLOBAL_OFFSET_TABLE_;
    void * const _GLOBAL_OFFSET_TABLE_ = 0;
#elif defined(CONFIG_MIPS)
  extern void * const _gp_disp;
  void * const _gp_disp = 0;
#endif

struct wolfssl_linuxkm_pie_redirect_table wolfssl_linuxkm_pie_redirect_table;

const struct wolfssl_linuxkm_pie_redirect_table
*wolfssl_linuxkm_get_pie_redirect_table(void) {
    return &wolfssl_linuxkm_pie_redirect_table;
}

/* The compiler emits memcpy/memset calls no macro can catch, and the container
 * may hold no undefined symbol (linuxkm/Kbuild:301), so define them here.  On
 * arm64 the work goes to the kernel's own __memcpy()/__memset() through the
 * redirect table (arch/arm64/lib/memcpy.S:243, memset.S:206).  The loops below
 * run only before that table is filled, and on MIPS throughout. */
#if defined(CONFIG_MIPS) || defined(CONFIG_ARM64)
    #undef memcpy
    void *memcpy(void *dest, const void *src, size_t n) {
        char *dest_i = (char *)dest;
        char *dest_end = dest_i + n;
        char *src_i = (char *)src;
#if defined(CONFIG_ARM64) && !defined(__ARCH_MEMCPY_NO_REDIRECT)
        if (wolfssl_linuxkm_pie_redirect_table.memcpy != NULL)
            return wolfssl_linuxkm_pie_redirect_table.memcpy(dest, src, n);
#endif
        while (dest_i < dest_end)
            *dest_i++ = *src_i++;
        return dest;
    }

    #undef memset
    void *memset(void *dest, int c, size_t n) {
        char *dest_i = (char *)dest;
        char *dest_end = dest_i + n;
#if defined(CONFIG_ARM64) && !defined(__ARCH_MEMSET_NO_REDIRECT)
        if (wolfssl_linuxkm_pie_redirect_table.memset != NULL)
            return wolfssl_linuxkm_pie_redirect_table.memset(dest, c, n);
#endif
        while (dest_i < dest_end)
            *dest_i++ = c;
        return dest;
    }
#endif

#if defined(CONFIG_ARM)
    /* 32-bit Arm code calls the EABI division helpers and the container cannot
     * reach the kernel's, so they live here.  Division by zero returns 0. */
    unsigned int __aeabi_uidiv(unsigned int n, unsigned int d);
    unsigned int __aeabi_uidiv(unsigned int n, unsigned int d) {
        unsigned int q = 0, r = 0;
        int i;
        if (d == 0)
            return 0u;
        for (i = 31; i >= 0; i--) {
            /* Restoring division with a mask instead of a branch. */
            unsigned int mask;
            r = (r << 1) | ((n >> i) & 1u);
            mask = 0u - (unsigned int)(r >= d);
            r -= d & mask;
            q |= (1u << i) & mask;
        }
        return q;
    }

    /* Quotient in the low word, remainder in the high word, as the EABI
     * expects in r0 and r1. */
    /* The EABI pair is r0 = quotient, r1 = remainder; a 64-bit return puts its
     * low word in r0 only on little-endian, so pack by byte order. */
    #ifdef __ARMEB__
        #define WC_AEABI_PACK(q, r) (((unsigned long long)(q) << 32) | (r))
        #define WC_AEABI_Q(v) ((unsigned int)((v) >> 32))
        #define WC_AEABI_R(v) ((unsigned int)(v))
    #else
        #define WC_AEABI_PACK(q, r) (((unsigned long long)(r) << 32) | (q))
        #define WC_AEABI_Q(v) ((unsigned int)(v))
        #define WC_AEABI_R(v) ((unsigned int)((v) >> 32))
    #endif
    unsigned long long __aeabi_uidivmod(unsigned int n, unsigned int d);
    unsigned long long __aeabi_uidivmod(unsigned int n, unsigned int d) {
        unsigned int q = 0, r = 0;
        int i;
        if (d == 0)
            return 0ULL;
        for (i = 31; i >= 0; i--) {
            unsigned int mask;
            r = (r << 1) | ((n >> i) & 1u);
            mask = 0u - (unsigned int)(r >= d);
            r -= d & mask;
            q |= (1u << i) & mask;
        }
        return WC_AEABI_PACK(q, r);
    }

    /* Signed forms work on unsigned magnitudes so INT_MIN is well defined;
     * INT_MIN / -1 returns INT_MIN, as SDIV does. */
    int __aeabi_idiv(int n, int d);
    int __aeabi_idiv(int n, int d) {
        int neg = (n < 0) ^ (d < 0);
        unsigned int un = (n < 0) ? (0u - (unsigned int)n) : (unsigned int)n;
        unsigned int ud = (d < 0) ? (0u - (unsigned int)d) : (unsigned int)d;
        unsigned int uq = __aeabi_uidiv(un, ud);
        return neg ? (int)(0u - uq) : (int)uq;
    }

    unsigned long long __aeabi_idivmod(int n, int d);
    unsigned long long __aeabi_idivmod(int n, int d) {
        int nneg = (n < 0);
        int qneg = (n < 0) ^ (d < 0);
        unsigned int un = nneg ? (0u - (unsigned int)n) : (unsigned int)n;
        unsigned int ud = (d < 0) ? (0u - (unsigned int)d) : (unsigned int)d;
        unsigned long long um = __aeabi_uidivmod(un, ud);
        unsigned int uq = WC_AEABI_Q(um);
        unsigned int ur = WC_AEABI_R(um);
        int q = qneg ? (int)(0u - uq) : (int)uq;
        int r = nneg ? (int)(0u - ur) : (int)ur;
        return WC_AEABI_PACK((unsigned int)q, (unsigned int)r);
    }
#endif /* CONFIG_ARM */
