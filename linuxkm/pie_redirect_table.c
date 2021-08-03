/* pie_redirect_table.c -- module load/unload hooks for libwolfssl.ko
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>

/* compiling -fPIE results in references to the GOT, which remain after linking
 * even if all other symbols are resolved by the link.  naturally there is no
 * GOT in the kernel, and the wolfssl Kbuild script explicitly checks that no
 * GOT relocations occur in the PIE objects, but we still need to include a
 * dummy value here, scoped to the module, to eliminate the otherwise unresolved
 * symbol.
 */
extern void *_GLOBAL_OFFSET_TABLE_;
void *_GLOBAL_OFFSET_TABLE_ = 0;

struct wolfssl_linuxkm_pie_redirect_table wolfssl_linuxkm_pie_redirect_table;

const struct wolfssl_linuxkm_pie_redirect_table
*wolfssl_linuxkm_get_pie_redirect_table(void) {
    return &wolfssl_linuxkm_pie_redirect_table;
}

const unsigned int wolfCrypt_All_ro_end[];
const unsigned int wolfCrypt_All_ro_end[] =
/* random values, analogous to wolfCrypt_FIPS_ro_{start,end} */
{ 0xa4aaaf71, 0x55c4b7d0 };
