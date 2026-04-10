/* module_exports_entropy.c -- exported symbol list for wolfentropy.ko
 *
 * Exports ONLY the three public wolfEntropy API functions into the WOLFSSL
 * symbol namespace.  Every other symbol compiled into wolfentropy.ko
 * (wolfCrypt_Init, wc_Sha3_*, wc_InitMutex, etc.) is deliberately NOT
 * exported, so loading wolfentropy.ko alongside libwolfssl.ko causes no
 * symbol collisions.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/wolfentropy.h>

#include <linux/version.h>

/* Compatibility shim: kernels before ~4.15 lack EXPORT_SYMBOL_NS_GPL. */
#ifndef EXPORT_SYMBOL_NS
#define EXPORT_SYMBOL_NS(sym, ns) EXPORT_SYMBOL(sym)
#endif
#ifndef EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns) EXPORT_SYMBOL_GPL(sym)
#endif

/* In Linux >= 6.13 the namespace argument to EXPORT_SYMBOL_NS_GPL must be a
 * quoted string; earlier kernels take a bare token.  Handle both here so this
 * static file does not need a kernel-version-aware Kbuild recipe. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
#  define WOLFSSL_EXPORT_ENTROPY(sym) EXPORT_SYMBOL_NS_GPL(sym, "WOLFSSL")
#else
#  define WOLFSSL_EXPORT_ENTROPY(sym) EXPORT_SYMBOL_NS_GPL(sym, WOLFSSL)
#endif

#ifdef HAVE_ENTROPY_MEMUSE

/* Primary entropy output: called by wc_linuxkm_GenerateSeed_wolfEntropy()
 * in the FIPS module's glue layer (linuxkm/module_hooks.c). */
WOLFSSL_EXPORT_ENTROPY(wc_Entropy_Get);

/* Raw entropy output for SP 800-90B assessment tooling. */
WOLFSSL_EXPORT_ENTROPY(wc_Entropy_GetRawEntropy);

/* On-demand continuous health test (e.g. for POST). */
WOLFSSL_EXPORT_ENTROPY(wc_Entropy_OnDemandTest);

#endif /* HAVE_ENTROPY_MEMUSE */
