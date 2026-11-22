/* zephyr_init.c
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

#include <wolfssl/wolfcrypt/settings.h>

/* The port's log module, for the boot-time hooks below. Zephyr before 3.2 has
 * no zephyr/ include prefix, so the headers stay out until one of them needs
 * them. */

#if defined(CONFIG_WOLFSSL_SYS_INIT) || defined(CONFIG_WOLFCRYPT_FIPS_V5)

#include <errno.h>

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(wolfssl, CONFIG_WOLFSSL_LOG_LEVEL);

#endif

/* Only a port that brings up a peripheral needs a boot-time hook. */

#ifdef CONFIG_WOLFSSL_SYS_INIT

#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/wolfcrypt/wc_port.h>
#else
    #include <wolfssl/ssl.h>
#endif

static int wolfssl_module_init(void)
{
    int ret;

    /* Zephyr hands a non-device SYS_INIT return only to a trace hook, so the
     * failure would otherwise leave no evidence. */
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        LOG_ERR("wolfCrypt_Init failed: %d", ret);
        return -EIO;
    }
#else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        LOG_ERR("wolfSSL_Init failed: %d", ret);
        return -EIO;
    }
#endif

    return 0;
}

/* POST_KERNEL because initialization takes mutexes and may allocate, late
 * within it because a port needs the SoC and clock init that runs there. */
SYS_INIT(wolfssl_module_init, POST_KERNEL, 99);

#endif /* CONFIG_WOLFSSL_SYS_INIT */

/* DRBG seed source for the FIPS v5 bundles, whose wc_GenerateSeed() is a bare
 * sys_rand_get() and so not a CSPRNG on the xoshiro or test generators.
 * Outside the module boundary. The tree's Zephyr wc_GenerateSeed() in
 * wolfcrypt/src/random.c reads the entropy device, but the bundle's random.c
 * replaces that file, so Zephyr's CSPRNG, which reads the same device, stands
 * in for it here. */

#ifdef CONFIG_WOLFCRYPT_FIPS_V5

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Zephyr 3.7 or later: CONFIG_WOLFCRYPT_FIPS selects STATIC_INIT_GNU. */
#include <zephyr/random/random.h>

/* CSPRNG_ENABLED follows ENTROPY_HAS_DRIVER, and CMakeLists.txt holds the
 * generator to the hardware one, so the seed comes straight from the driver. */
#if !defined(CONFIG_CSPRNG_ENABLED) && !defined(CONFIG_TEST_RANDOM_GENERATOR)
    #error "FIPS v5 seeds its DRBG from the Zephyr CSPRNG: enable an entropy driver"
#endif

int wolfssl_zephyr_seed(OS_Seed* os, byte* seed, word32 sz)
{
    (void)os;
#ifdef CONFIG_CSPRNG_ENABLED
    return (sys_csrand_get(seed, sz) == 0) ? 0 : RNG_FAILURE_E;
#else
    /* CONFIG_TEST_RANDOM_GENERATOR, which Zephyr already flags as insecure. */
    sys_rand_get(seed, sz);
    return 0;
#endif
}

/* wolfSSL_Init() registers WC_GENERATE_SEED_DEFAULT only on its first call,
 * and wolfCrypt-only builds never call it. wc_SetSeed_Cb() is refused until
 * the power-on self test has run, which is a C constructor, so register at
 * APPLICATION level: Zephyr runs the constructors just before it. */
static int wolfssl_zephyr_seed_init(void)
{
    int ret = wc_SetSeed_Cb(wolfssl_zephyr_seed);

    /* Zephyr hands this return only to a trace hook, and every later
     * wc_InitRng() would fail with DRBG_NO_SEED_CB, so say why here. */
    if (ret != 0) {
        LOG_ERR("wc_SetSeed_Cb failed: %d", ret);
        return -EIO;
    }
    return 0;
}

SYS_INIT(wolfssl_zephyr_seed_init, APPLICATION, 0);

#endif /* CONFIG_WOLFCRYPT_FIPS_V5 */
