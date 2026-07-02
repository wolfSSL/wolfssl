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
 *
 * ARM/ARM64 need these like MIPS: --enable-armasm omits -mgeneral-regs-only,
 * so gcc auto-emits raw memcpy/memset libcalls for aggregate copies in the
 * PIE FIPS container.  WC_PIE_INDIRECT_SYM only redirects source-level
 * XMEMCPY/XMEMSET, not compiler-emitted libcalls, and the in-core integrity
 * check forbids ANY undefined symbol, so define them here.  (The pure-C C1
 * build does not auto-vectorize and never references these.) */
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
    /* 32-bit ARM's baseline ISA has no integer-divide, so gcc emits these EABI
     * helpers for '/' and '%'.  The kernel exports them
     * (arch/arm/lib/lib1funcs.S), but the self-contained PIE FIPS container may
     * not reference external symbols (in-core integrity forbids ANY undefined
     * symbol), so provide them here.  Restoring (bit-at-a-time) division --
     * correctness over speed; crypto-path divisions are on small
     * sizes/indices.  Per the EABI, __aeabi_*idivmod return a little-endian
     * 64-bit value: quotient in r0 (low word), remainder in r1 (high word). */
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
