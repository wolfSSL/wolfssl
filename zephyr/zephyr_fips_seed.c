/* zephyr_fips_seed.c
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

/* DRBG seed source for the FIPS v5 bundles, whose wc_GenerateSeed() is a bare
 * sys_rand_get() and so not a CSPRNG on the xoshiro or test generators.
 * Outside the module boundary. The tree's Zephyr wc_GenerateSeed() in
 * wolfcrypt/src/random.c reads the entropy device the same way, but the
 * bundle's random.c replaces that file, so the loop is repeated here. */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef CONFIG_WOLFCRYPT_FIPS_V5

#include <errno.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Zephyr 3.7 or later: CONFIG_WOLFCRYPT_FIPS selects STATIC_INIT_GNU. */
#include <zephyr/init.h>
#include <zephyr/devicetree.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>

LOG_MODULE_DECLARE(wolfssl, CONFIG_WOLFSSL_LOG_LEVEL);

/* A chosen node that is disabled has no device behind it, so check both. */
#if defined(CONFIG_ENTROPY_HAS_DRIVER) && DT_HAS_CHOSEN(zephyr_entropy) && \
    DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_entropy), okay)
    #define WOLF_SEED_ENTROPY_DEVICE
    #include <zephyr/device.h>
    #include <zephyr/drivers/entropy.h>
#elif defined(CONFIG_CSPRNG_ENABLED)
    #define WOLF_SEED_CSPRNG
#elif !defined(CONFIG_TEST_RANDOM_GENERATOR)
    #error "FIPS v5 seeds its DRBG from a zephyr,entropy device or CSPRNG"
#endif

int wolfssl_zephyr_seed(OS_Seed* os, byte* seed, word32 sz)
{
#if defined(WOLF_SEED_ENTROPY_DEVICE)
    const struct device* dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
    word32 off = 0;
    uint16_t chunk;

    (void)os;
    if (!device_is_ready(dev)) {
        return RNG_FAILURE_E;
    }
    /* entropy_get_entropy() takes a uint16_t length. */
    while (off < sz) {
        chunk = (sz - off > 0xFFFFU) ? (uint16_t)0xFFFFU : (uint16_t)(sz - off);
        if (entropy_get_entropy(dev, seed + off, chunk) != 0) {
            return RNG_FAILURE_E;
        }
        off += chunk;
    }
    return 0;
#elif defined(WOLF_SEED_CSPRNG)
    (void)os;
    return (sys_csrand_get(seed, sz) == 0) ? 0 : RNG_FAILURE_E;
#else
    /* CONFIG_TEST_RANDOM_GENERATOR, which Zephyr already flags as insecure. */
    (void)os;
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
