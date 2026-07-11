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

/* placeholder implementations for missing functions.
 * ARM/ARM64 need these like MIPS: gcc auto-emits memcpy/memset libcalls that
 * the in-core integrity check forbids as undefined symbols. */
#if defined(CONFIG_MIPS) || defined(CONFIG_ARM) || defined(CONFIG_ARM64)
    #undef memcpy
    void *memcpy(void *dest, const void *src, size_t n) {
        char *dest_i = (char *)dest;
        char *dest_end = dest_i + n;
        char *src_i = (char *)src;
        while (dest_i < dest_end)
            *dest_i++ = *src_i++;
        return dest;
    }

    #undef memset
    void *memset(void *dest, int c, size_t n) {
        char *dest_i = (char *)dest;
        char *dest_end = dest_i + n;
        while (dest_i < dest_end)
            *dest_i++ = c;
        return dest;
    }
#endif

#if defined(CONFIG_ARM)
    /* 32-bit ARM has no HW divide and the PIE FIPS container cannot reference
     * the kernel's EABI helpers.  *idivmod returns quot in r0, rem in r1. */
    unsigned int __aeabi_uidiv(unsigned int n, unsigned int d);
    unsigned int __aeabi_uidiv(unsigned int n, unsigned int d) {
        unsigned int q = 0, r = 0;
        int i;
        if (d == 0)
            return ~0u;
        for (i = 31; i >= 0; i--) {
            r = (r << 1) | ((n >> i) & 1u);
            if (r >= d) {
                r -= d;
                q |= (1u << i);
            }
        }
        return q;
    }

    unsigned long long __aeabi_uidivmod(unsigned int n, unsigned int d);
    unsigned long long __aeabi_uidivmod(unsigned int n, unsigned int d) {
        unsigned int q = 0, r = 0;
        int i;
        if (d == 0)
            return (unsigned long long)n << 32; /* quot=0, rem=n */
        for (i = 31; i >= 0; i--) {
            r = (r << 1) | ((n >> i) & 1u);
            if (r >= d) {
                r -= d;
                q |= (1u << i);
            }
        }
        return ((unsigned long long)r << 32) | q;
    }

    int __aeabi_idiv(int n, int d);
    int __aeabi_idiv(int n, int d) {
        int neg = (n < 0) ^ (d < 0);
        unsigned int un = (n < 0) ? (unsigned int)(-(long)n) : (unsigned int)n;
        unsigned int ud = (d < 0) ? (unsigned int)(-(long)d) : (unsigned int)d;
        unsigned int uq = __aeabi_uidiv(un, ud);
        return neg ? -(int)uq : (int)uq;
    }

    unsigned long long __aeabi_idivmod(int n, int d);
    unsigned long long __aeabi_idivmod(int n, int d) {
        int nneg = (n < 0);
        int qneg = (n < 0) ^ (d < 0);
        unsigned int un = nneg ? (unsigned int)(-(long)n) : (unsigned int)n;
        unsigned int ud = (d < 0) ? (unsigned int)(-(long)d) : (unsigned int)d;
        unsigned long long um = __aeabi_uidivmod(un, ud);
        unsigned int uq = (unsigned int)um;
        unsigned int ur = (unsigned int)(um >> 32);
        int q = qneg ? -(int)uq : (int)uq;
        int r = nneg ? -(int)ur : (int)ur;
        return ((unsigned long long)(unsigned int)r << 32) | (unsigned int)q;
    }
#endif /* CONFIG_ARM */
