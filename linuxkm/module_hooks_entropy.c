/* module_hooks_entropy.c -- Linux kernel module init/exit for wolfentropy.ko
 *
 * This module provides the wolfEntropy SP 800-90B entropy source for use by
 * a separately-installed wolfSSL FIPS kernel module (libwolfssl.ko).
 *
 * It initialises the wolfEntropy jitter-based entropy collector at load time
 * and tears it down at unload time.  It exports wc_Entropy_Get(),
 * wc_Entropy_GetRawEntropy(), and wc_Entropy_OnDemandTest() so that a FIPS
 * libwolfssl.ko can call wc_Entropy_Get() through the seed callback
 * registered via wc_SetSeed_Cb().
 *
 * Load order: wolfentropy.ko must be loaded BEFORE libwolfssl.ko.  The
 * reference to wc_Entropy_Get in libwolfssl.ko is declared weak (see
 * module_hooks.c), which means modpost does NOT record wolfentropy as a
 * hard dependency and modules.dep will not list it.  MODULE_SOFTDEP("pre:
 * wolfentropy") in libwolfssl.ko is what directs modprobe to load the
 * two modules in the right order -- note it is only a hint, honoured by
 * modprobe but ignored by insmod.  wc_linuxkm_GenerateSeed_wolfEntropy()
 * also NULL-checks the weak pointer at runtime and fails the seed
 * callback cleanly if wolfentropy.ko was not loaded first.
 *
 * On the libwolfssl.ko side: configure --enable-linuxkm-wolfentropy-ko
 * arranges the whole contract -- it defines both WC_LINUXKM_WOLFENTROPY_IN_GLUE_LAYER
 * (to route DRBG seeding through wc_linuxkm_GenerateSeed_wolfEntropy)
 * and WC_LINUXKM_WOLFENTROPY_EXTERNAL (to select the weak-extern code
 * path and activate MODULE_SOFTDEP / MODULE_IMPORT_NS(WOLFSSL)).  The
 * legacy in-tree path (wolfentropy.c compiled into libwolfssl.ko) is
 * auto-detected by linuxkm_wc_port.h when HAVE_FIPS + HAVE_ENTROPY_MEMUSE
 * are both set, and in that path no external module is needed.
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
#include <wolfssl/version.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int __init wolfentropy_init(void)
#else
static int wolfentropy_init(void)
#endif
{
    int ret;

    ret = Entropy_Init();
    if (ret != 0) {
        pr_err("wolfentropy: Entropy_Init() failed with return code %d.\n",
               ret);
        return -ECANCELED;
    }

    pr_info("wolfentropy: wolfEntropy SP 800-90B entropy source loaded "
            "(wolfSSL " LIBWOLFSSL_VERSION_STRING ").\n");
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void __exit wolfentropy_exit(void)
#else
static void wolfentropy_exit(void)
#endif
{
    Entropy_Final();
    pr_info("wolfentropy: wolfEntropy entropy source unloaded.\n");
}

module_init(wolfentropy_init);
module_exit(wolfentropy_exit);

/* wc_port.c calls wc_ecc_fp_init() / wc_ecc_fp_free() from wolfCrypt_Init()
 * and wolfCrypt_Cleanup().  wolfentropy.ko never calls either of those, so
 * these references are dead code, but modpost still requires the symbols to
 * be resolvable within the module.  Provide minimal no-op stubs here.
 */
#if defined(HAVE_ECC) && defined(FP_ECC)
#include <wolfssl/wolfcrypt/ecc.h>
void wc_ecc_fp_init(void) {}
void wc_ecc_fp_free(void) {}
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("https://www.wolfssl.com/");
MODULE_DESCRIPTION("wolfEntropy SP 800-90B jitter entropy source for wolfSSL FIPS DRBG");
MODULE_VERSION(LIBWOLFSSL_VERSION_STRING);
