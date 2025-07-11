/* lkcapi_glue.c -- glue logic to register wolfCrypt implementations with
 * the Linux Kernel Cryptosystem
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

/* included by linuxkm/module_hooks.c */

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
    #error LINUXKM_LKCAPI_REGISTER is supported only on Linux kernel versions >= 5.4.0.
#endif

#if defined(CONFIG_CRYPTO_MANAGER) && \
    !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    /* kernel crypto self-test includes test setups that have different expected
     * results FIPS vs non-FIPS, and the required kernel exported symbol
     * "fips_enabled" is only available in CONFIG_CRYPTO_FIPS kernels (otherwise
     * it's a macro hardcoding it to literal 0).
     */
    #if defined(CONFIG_CRYPTO_FIPS) != defined(HAVE_FIPS)
        #error CONFIG_CRYPTO_MANAGER requires that CONFIG_CRYPTO_FIPS match HAVE_FIPS.
    #endif
    #include <linux/fips.h>
#endif

/* need misc.c for ForceZero(). */
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef WOLFSSL_LINUXKM_LKCAPI_PRIORITY
    /* Larger number means higher priority.  The highest in-tree priority is
     * 4001, in the Cavium driver.
     *
     * Note bene, when the kernel dynamically constructs compound algorithms, it
     * computes their priorities by multiplying the priority of the base
     * algorithm by up to 10, and/or adding to it the priority of a second base
     * algorithm, or a constant up to 200, so it's not safe to use a value near
     * INT_MAX here.
     */
    #define WOLFSSL_LINUXKM_LKCAPI_PRIORITY 100000
#endif

#if defined(CONFIG_CRYPTO_MANAGER_EXTRA_TESTS) || \
    defined(CONFIG_CRYPTO_SELFTESTS_FULL)
    static int disable_setkey_warnings = 0;
#else
    #define disable_setkey_warnings 0
#endif

#ifdef HAVE_FIPS
    #ifndef HAVE_FIPS_VERSION
        #define WOLFKM_DRIVER_FIPS "-fips-140"
    #elif HAVE_FIPS_VERSION >= 5
        #define WOLFKM_DRIVER_FIPS "-fips-140-3"
    #elif HAVE_FIPS_VERSION == 2
        #define WOLFKM_DRIVER_FIPS "-fips-140-2"
    #else
        #define WOLFKM_DRIVER_FIPS "-fips-140"
    #endif
#else
    #define WOLFKM_DRIVER_FIPS ""
#endif

#define WOLFKM_DRIVER_SUFFIX_BASE "-wolfcrypt" WOLFKM_DRIVER_FIPS

#define WOLFKM_INSTALL_NOTICE(alg)                                      \
    pr_info("%s self-test OK -- "                                       \
            "registered for %s with priority %d.\n",                    \
            (alg).base.cra_driver_name,                                 \
            (alg).base.cra_name,                                        \
            (alg).base.cra_priority);                                   \

#if defined(WOLFSSL_AESNI) || defined(USE_INTEL_SPEEDUP) || \
    defined(USE_INTEL_SPEEDUP_FOR_AES)
    #define LKCAPI_HAVE_ARCH_ACCEL
#endif

#if defined(LKCAPI_HAVE_ARCH_ACCEL) &&                   \
    (!defined(WC_C_DYNAMIC_FALLBACK) ||                  \
     (defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0))) && \
    !defined(WC_LINUXKM_C_FALLBACK_IN_SHIMS)
    #define WC_LINUXKM_C_FALLBACK_IN_SHIMS
#elif !defined(LKCAPI_HAVE_ARCH_ACCEL)
    #undef WC_LINUXKM_C_FALLBACK_IN_SHIMS
#endif

#if defined(WC_LINUXKM_C_FALLBACK_IN_SHIMS) && !defined(CAN_SAVE_VECTOR_REGISTERS)
    #error WC_LINUXKM_C_FALLBACK_IN_SHIMS is defined but CAN_SAVE_VECTOR_REGISTERS is missing.
#endif

WC_MAYBE_UNUSED static int check_skcipher_driver_masking(struct crypto_skcipher *tfm, const char *alg_name, const char *expected_driver_name) {
#ifdef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
    (void)tfm; (void)alg_name; (void)expected_driver_name;
    return 0;
#else
    const char *actual_driver_name;
    int ret;
    int alloced_tfm = 0;

    if (! tfm) {
        alloced_tfm = 1;
        tfm = crypto_alloc_skcipher(alg_name, 0, 0);
    }
    if (IS_ERR(tfm)) {
        pr_err("error: allocating skcipher algorithm %s failed: %ld\n",
               alg_name, PTR_ERR(tfm));
        return -EINVAL;
    }
    actual_driver_name = crypto_tfm_alg_driver_name(crypto_skcipher_tfm(tfm));
    if (strcmp(actual_driver_name, expected_driver_name)) {
        pr_err("error: unexpected implementation for %s: %s (expected %s)\n",
               alg_name, actual_driver_name, expected_driver_name);
        ret = -ENOENT;
    } else
        ret = 0;

    if (alloced_tfm)
        crypto_free_skcipher(tfm);

    return ret;
#endif
}

WC_MAYBE_UNUSED static int check_aead_driver_masking(struct crypto_aead *tfm, const char *alg_name, const char *expected_driver_name) {
#ifdef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
    (void)tfm; (void)alg_name; (void)expected_driver_name;
    return 0;
#else
    const char *actual_driver_name;
    int ret;
    int alloced_tfm = 0;

    if (! tfm) {
        alloced_tfm = 1;
        tfm = crypto_alloc_aead(alg_name, 0, 0);
    }
    if (IS_ERR(tfm)) {
        pr_err("error: allocating AEAD algorithm %s failed: %ld\n",
               alg_name, PTR_ERR(tfm));
        return -EINVAL;
    }
    actual_driver_name = crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm));
    if (strcmp(actual_driver_name, expected_driver_name)) {
        pr_err("error: unexpected implementation for %s: %s (expected %s)\n",
               alg_name, actual_driver_name, expected_driver_name);
        ret = -ENOENT;
    } else
        ret = 0;

    if (alloced_tfm)
        crypto_free_aead(tfm);

    return ret;
#endif
}

WC_MAYBE_UNUSED static int check_shash_driver_masking(struct crypto_shash *tfm, const char *alg_name, const char *expected_driver_name) {
#ifdef LINUXKM_LKCAPI_PRIORITY_ALLOW_MASKING
    (void)tfm; (void)alg_name; (void)expected_driver_name;
    return 0;
#else
    const char *actual_driver_name;
    int ret;
    int alloced_tfm = 0;

    if (! tfm) {
        alloced_tfm = 1;
        tfm = crypto_alloc_shash(alg_name, 0, 0);
    }
    if (IS_ERR(tfm)) {
        pr_err("error: allocating shash algorithm %s failed: %ld\n",
               alg_name, PTR_ERR(tfm));
        return -EINVAL;
    }
    actual_driver_name = crypto_tfm_alg_driver_name(crypto_shash_tfm(tfm));
    if (strcmp(actual_driver_name, expected_driver_name)) {
        pr_err("error: unexpected implementation for %s: %s (expected %s)\n",
               alg_name, actual_driver_name, expected_driver_name);
        ret = -ENOENT;
    } else
        ret = 0;

    if (alloced_tfm)
        crypto_free_shash(tfm);

    return ret;
#endif
}

#include "lkcapi_aes_glue.c"
#include "lkcapi_sha_glue.c"
#include "lkcapi_ecdsa_glue.c"
#include "lkcapi_ecdh_glue.c"
#include "lkcapi_rsa_glue.c"
#include "lkcapi_dh_glue.c"

static int linuxkm_lkcapi_register(void);
static int linuxkm_lkcapi_unregister(void);

#if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
    !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
static int enabled_fips = 0;
#endif

static ssize_t install_algs_handler(struct kobject *kobj, struct kobj_attribute *attr,
                              const char *buf, size_t count)
{
    int arg;
    int ret;

    (void)kobj;
    (void)attr;

    if (kstrtoint(buf, 10, &arg) || arg != 1)
        return -EINVAL;

    pr_info("wolfCrypt: Installing algorithms");

    ret = linuxkm_lkcapi_register();
    if (ret != 0)
        return ret;

    return count;
}

static ssize_t deinstall_algs_handler(struct kobject *kobj, struct kobj_attribute *attr,
                              const char *buf, size_t count)
{
    int arg;
    int ret;

    (void)kobj;
    (void)attr;

    if (kstrtoint(buf, 10, &arg) || arg != 1)
        return -EINVAL;

    pr_info("wolfCrypt: Deinstalling algorithms");

    ret = linuxkm_lkcapi_unregister();
    if (ret != 0)
        return ret;

#if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
    !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    if (enabled_fips) {
        pr_info("wolfCrypt: restoring fips_enabled to off.");
        enabled_fips = fips_enabled = 0;
    }
#endif

    return count;
}

/* create control channels at /sys/module/libwolfssl/{install_algs,deinstall_algs} */

static struct kobj_attribute install_algs_attr = __ATTR(install_algs, 0220, NULL, install_algs_handler);
static struct kobj_attribute deinstall_algs_attr = __ATTR(deinstall_algs, 0220, NULL, deinstall_algs_handler);

static int installed_sysfs_LKCAPI_files = 0;

static int linuxkm_lkcapi_sysfs_install(void) {
    int ret;
    if (! installed_sysfs_LKCAPI_files) {
        ret = linuxkm_lkcapi_sysfs_install_node(&install_algs_attr, NULL);
        if (ret)
            return ret;
        ret = linuxkm_lkcapi_sysfs_install_node(&deinstall_algs_attr, NULL);
        if (ret)
            return ret;
        installed_sysfs_LKCAPI_files = 1;
    }
    return 0;
}

static int linuxkm_lkcapi_sysfs_deinstall(void) {
    if (installed_sysfs_LKCAPI_files) {
        int ret = linuxkm_lkcapi_sysfs_deinstall_node(&install_algs_attr, NULL);
        if (ret)
            return ret;
        ret = linuxkm_lkcapi_sysfs_deinstall_node(&deinstall_algs_attr, NULL);
        if (ret)
            return ret;
        installed_sysfs_LKCAPI_files = 0;
    }
    return 0;
}

static int linuxkm_lkcapi_registered = 0;
static int linuxkm_lkcapi_n_registered = 0;

static int linuxkm_lkcapi_register(void)
{
    int ret = -1;
    int seen_err = 0;

    ret = linuxkm_lkcapi_sysfs_install();
    if (ret)
        return ret;

#if defined(CONFIG_CRYPTO_MANAGER_EXTRA_TESTS) || \
    defined(CONFIG_CRYPTO_SELFTESTS_FULL)
    /* temporarily disable warnings around setkey failures, which are expected
     * from the crypto fuzzer in FIPS configs, and potentially in others.
     * unexpected setkey failures are fatal errors returned by the fuzzer.
     */
    disable_setkey_warnings = 1;
#endif
#if !defined(LINUXKM_DONT_FORCE_FIPS_ENABLED) && \
    defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
    !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    if (! fips_enabled) {
        /* assert system-wide FIPS status, to disable FIPS-forbidden
         * test vectors and fuzzing from the CRYPTO_MANAGER.
         */
        pr_info("wolfCrypt: changing fips_enabled from 0 to 1 for FIPS module.");
        enabled_fips = fips_enabled = 1;
    }
#endif

#define REGISTER_ALG(alg, alg_class, tester) do {                            \
        if (! alg ## _loaded) {                                              \
            ret =  (crypto_register_ ## alg_class)(&(alg));                  \
            if (ret) {                                                       \
                seen_err = ret;                                              \
                pr_err("ERROR: crypto_register_" #alg_class " for %s failed "\
                       "with return code %d.\n",                             \
                       (alg).base.cra_driver_name, ret);                     \
            } else {                                                         \
                ret = (tester());                                            \
                if (ret) {                                                   \
                    seen_err = -EINVAL;                                      \
                    pr_err("ERROR: wolfCrypt self-test for %s failed "       \
                           "with return code %d.\n",                         \
                           (alg).base.cra_driver_name, ret);                 \
                    (crypto_unregister_ ## alg_class)(&(alg));               \
                    if (! (alg.base.cra_flags & CRYPTO_ALG_DEAD)) {          \
                        pr_err("ERROR: alg %s not _DEAD "                    \
                               "after crypto_unregister_%s -- "              \
                               "marking as loaded despite test failure.",    \
                               (alg).base.cra_driver_name,                   \
                               #alg_class);                                  \
                        alg ## _loaded = 1;                                  \
                        ++linuxkm_lkcapi_n_registered;                       \
                    }                                                        \
                } else {                                                     \
                    alg ## _loaded = 1;                                      \
                    ++linuxkm_lkcapi_n_registered;                           \
                    WOLFKM_INSTALL_NOTICE(alg)                               \
                }                                                            \
            }                                                                \
        }                                                                    \
    } while (0)

#if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
    !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
/* Same as above, but allow for option to skip problematic algs that are
 * not consistently labeled fips_allowed in crypto/testmgr.c, and hence
 * may be rejected by the kernel at runtime if is_fips is true. */
#define REGISTER_ALG_OPTIONAL(alg, alg_class, tester) do {\
        if (! alg ## _loaded) {                                              \
            ret =  (crypto_register_ ## alg_class)(&(alg));                  \
            if (ret) {                                                       \
                if (fips_enabled && (ret == WC_NO_ERR_TRACE(NOT_COMPILED_IN))) { \
                    pr_info("wolfCrypt: skipping FIPS-incompatible alg %s.\n", \
                            (alg).base.cra_driver_name);                     \
                }                                                            \
                else {                                                       \
                    seen_err = ret;                                          \
                    pr_err("ERROR: crypto_register_" #alg_class              \
                           " for %s failed "                                 \
                           "with return code %d.\n",                         \
                           (alg).base.cra_driver_name, ret);                 \
                }                                                            \
            } else {                                                         \
                ret = (tester());                                            \
                if (ret) {                                                   \
                    if (fips_enabled && (ret == WC_NO_ERR_TRACE(NOT_COMPILED_IN))) { \
                        pr_info("wolfCrypt: skipping FIPS-incompatible alg %s.\n", \
                                (alg).base.cra_driver_name);                 \
                    }                                                        \
                    else {                                                   \
                        seen_err = -EINVAL;                                  \
                        pr_err("ERROR: wolfCrypt self-test for %s failed "   \
                               "with return code %d.\n",                     \
                               (alg).base.cra_driver_name, ret);             \
                    }                                                        \
                    (crypto_unregister_ ## alg_class)(&(alg));               \
                    if (! (alg.base.cra_flags & CRYPTO_ALG_DEAD)) {          \
                        pr_err("ERROR: alg %s not _DEAD "                    \
                               "after crypto_unregister_%s -- "              \
                               "marking as loaded despite test failure.",    \
                               (alg).base.cra_driver_name,                   \
                               #alg_class);                                  \
                        alg ## _loaded = 1;                                  \
                        ++linuxkm_lkcapi_n_registered;                       \
                    }                                                        \
                } else {                                                     \
                    alg ## _loaded = 1;                                      \
                    ++linuxkm_lkcapi_n_registered;                           \
                    WOLFKM_INSTALL_NOTICE(alg)                               \
                }                                                            \
            }                                                                \
        }                                                                    \
    } while (0)
#endif /* HAVE_FIPS && CONFIG_CRYPTO_MANAGER && etc.. */

    /* We always register the derivative/composite algs first, to assure that
     * the kernel doesn't synthesize them dynamically from our primitives.
     */

#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    REGISTER_ALG(gcmAesAead_rfc4106, aead, linuxkm_test_aesgcm_rfc4106);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM
    REGISTER_ALG(gcmAesAead, aead, linuxkm_test_aesgcm);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESXTS
    REGISTER_ALG(xtsAesAlg, skcipher, linuxkm_test_aesxts);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCFB
    REGISTER_ALG(cfbAesAlg, skcipher, linuxkm_test_aescfb);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESOFB
    REGISTER_ALG(ofbAesAlg, skcipher, linuxkm_test_aesofb);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCBC
    REGISTER_ALG(cbcAesAlg, skcipher, linuxkm_test_aescbc);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCTR
    REGISTER_ALG(ctrAesAlg, skcipher, linuxkm_test_aesctr);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESECB
    REGISTER_ALG(ecbAesAlg, skcipher, linuxkm_test_aesecb);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    REGISTER_ALG(sha1_hmac_alg, shash, linuxkm_test_sha1_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    REGISTER_ALG(sha2_224_hmac_alg, shash, linuxkm_test_sha2_224_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    REGISTER_ALG(sha2_256_hmac_alg, shash, linuxkm_test_sha2_256_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    REGISTER_ALG(sha2_384_hmac_alg, shash, linuxkm_test_sha2_384_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    REGISTER_ALG(sha2_512_hmac_alg, shash, linuxkm_test_sha2_512_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    REGISTER_ALG(sha3_224_hmac_alg, shash, linuxkm_test_sha3_224_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    REGISTER_ALG(sha3_256_hmac_alg, shash, linuxkm_test_sha3_256_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    REGISTER_ALG(sha3_384_hmac_alg, shash, linuxkm_test_sha3_384_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
    REGISTER_ALG(sha3_512_hmac_alg, shash, linuxkm_test_sha3_512_hmac);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    REGISTER_ALG(sha1_alg, shash, linuxkm_test_sha1);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
    REGISTER_ALG(sha2_224_alg, shash, linuxkm_test_sha2_224);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
    REGISTER_ALG(sha2_256_alg, shash, linuxkm_test_sha2_256);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
    REGISTER_ALG(sha2_384_alg, shash, linuxkm_test_sha2_384);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
    REGISTER_ALG(sha2_512_alg, shash, linuxkm_test_sha2_512);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
    REGISTER_ALG(sha3_224_alg, shash, linuxkm_test_sha3_224);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
    REGISTER_ALG(sha3_256_alg, shash, linuxkm_test_sha3_256);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
    REGISTER_ALG(sha3_384_alg, shash, linuxkm_test_sha3_384);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
    REGISTER_ALG(sha3_512_alg, shash, linuxkm_test_sha3_512);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG
    /* special installation handler for wc_linuxkm_drbg, to conditionally
     * install it as the system-wide default rng.
     */
    if (! wc_linuxkm_drbg_loaded) {
        ret = wc_linuxkm_drbg_startup();
        if (ret == 0)
            ++linuxkm_lkcapi_n_registered;
        else
            seen_err = ret;
    }
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_ECDSA
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)) &&    \
        defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_FIPS) && \
        defined(CONFIG_CRYPTO_MANAGER) &&                    \
        !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
        /*
         * ecdsa was not recognized as fips_allowed before linux v6.3
         * in kernel crypto/testmgr.c.
         */
        #if defined(LINUXKM_ECC192)
        REGISTER_ALG_OPTIONAL(ecdsa_nist_p192, akcipher,
                              linuxkm_test_ecdsa_nist_p192);
        #endif /* LINUXKM_ECC192 */

        REGISTER_ALG_OPTIONAL(ecdsa_nist_p256, akcipher,
                              linuxkm_test_ecdsa_nist_p256);

        REGISTER_ALG_OPTIONAL(ecdsa_nist_p384, akcipher,
                              linuxkm_test_ecdsa_nist_p384);

        #if defined(HAVE_ECC521)
        REGISTER_ALG_OPTIONAL(ecdsa_nist_p521, akcipher,
                              linuxkm_test_ecdsa_nist_p521);
        #endif /* HAVE_ECC521 */
    #else
        #if defined(LINUXKM_ECC192)
        REGISTER_ALG(ecdsa_nist_p192, akcipher,
                     linuxkm_test_ecdsa_nist_p192);
        #endif /* LINUXKM_ECC192 */

        REGISTER_ALG(ecdsa_nist_p256, akcipher,
                     linuxkm_test_ecdsa_nist_p256);

        REGISTER_ALG(ecdsa_nist_p384, akcipher,
                     linuxkm_test_ecdsa_nist_p384);

        #if defined(HAVE_ECC521)
        REGISTER_ALG(ecdsa_nist_p521, akcipher,
                     linuxkm_test_ecdsa_nist_p521);
        #endif /* HAVE_ECC521 */
    #endif /* if linux < 6.3 && HAVE_FIPS && etc.. */

    #if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)) &&    \
        defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_FIPS) && \
        defined(CONFIG_CRYPTO_MANAGER) &&                    \
        !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    #endif

#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

#ifdef LINUXKM_LKCAPI_REGISTER_ECDH

   /* In kernels before 5.13.0, ecdh-nist-p256 was not recognized as
    * fips_allowed, and ecdh-nist-p384 was completely
    * missing before 5.14 and not fips_allowed before 5.15.
    *
    * RedHat also recently patched their crypto manager to mark ECDH
    * !fips_allowed due the vagaries of their own certificate.  (See 5074fb61f6,
    * 2025-Mar-13.)
    *
    * Given the above, and given we're not actually relying on the crypto
    * manager for FIPS self tests, and given the FIPS ECDH implementation passes
    * the non-FIPS ECDH crypto manager tests, the pragmatic solution we settle
    * on here is for ECDH loading to be optional when fips and fips tests are
    * enabled. Failures because of !fips_allowed are skipped over.
    */
    #if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_FIPS) && \
        defined(CONFIG_CRYPTO_MANAGER) &&             \
        !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
        #if defined(LINUXKM_ECC192)
        REGISTER_ALG_OPTIONAL(ecdh_nist_p192, kpp, linuxkm_test_ecdh_nist_p192);
        #endif /* LINUXKM_ECC192 */
        REGISTER_ALG_OPTIONAL(ecdh_nist_p256, kpp, linuxkm_test_ecdh_nist_p256);
        REGISTER_ALG_OPTIONAL(ecdh_nist_p384, kpp, linuxkm_test_ecdh_nist_p384);
    #else
        #if defined(LINUXKM_ECC192)
        REGISTER_ALG(ecdh_nist_p192, kpp, linuxkm_test_ecdh_nist_p192);
        #endif /* LINUXKM_ECC192 */
        REGISTER_ALG(ecdh_nist_p256, kpp, linuxkm_test_ecdh_nist_p256);
        REGISTER_ALG(ecdh_nist_p384, kpp, linuxkm_test_ecdh_nist_p384);
    #endif /* CONFIG_CRYPTO_FIPS && etc.. */
#endif /* LINUXKM_LKCAPI_REGISTER_ECDH */

#ifdef LINUXKM_LKCAPI_REGISTER_RSA
    #if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
        /* linux kernel < 6.13 consists of:
         *   akcipher: "pkcs1pad(<rsa>, <hash>)" */
        #ifdef WOLFSSL_SHA224
        REGISTER_ALG(pkcs1_sha224, akcipher, linuxkm_test_pkcs1_sha224);
        #endif /* WOLFSSL_SHA224 */
        #ifndef NO_SHA256
        REGISTER_ALG(pkcs1_sha256, akcipher, linuxkm_test_pkcs1_sha256);
        #endif /* !NO_SHA256 */
        #ifdef WOLFSSL_SHA384
        REGISTER_ALG(pkcs1_sha384, akcipher, linuxkm_test_pkcs1_sha384);
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA512
        REGISTER_ALG(pkcs1_sha512, akcipher, linuxkm_test_pkcs1_sha512);
        #endif /* WOLFSSL_SHA512 */
        #ifdef WOLFSSL_SHA3
        REGISTER_ALG(pkcs1_sha3_256, akcipher, linuxkm_test_pkcs1_sha3_256);
        REGISTER_ALG(pkcs1_sha3_384, akcipher, linuxkm_test_pkcs1_sha3_384);
        REGISTER_ALG(pkcs1_sha3_512, akcipher, linuxkm_test_pkcs1_sha3_512);
        #endif /* WOLFSSL_SHA3 */
    #else
        /* linux kernel >= 6.13 consists of:
         *   akcipher: "pkcs1pad(<rsa>)"
         *   sig:      "pkcs1(<rsa>, <hash>)" */
        #ifdef WOLFSSL_SHA224
        REGISTER_ALG(pkcs1_sha224, sig, linuxkm_test_pkcs1_sha224);
        #endif /* WOLFSSL_SHA224 */
        #ifndef NO_SHA256
        REGISTER_ALG(pkcs1_sha256, sig, linuxkm_test_pkcs1_sha256);
        #endif /* !NO_SHA256 */
        #ifdef WOLFSSL_SHA384
        REGISTER_ALG(pkcs1_sha384, sig, linuxkm_test_pkcs1_sha384);
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA512
        REGISTER_ALG(pkcs1_sha512, sig, linuxkm_test_pkcs1_sha512);
        #endif /* WOLFSSL_SHA512 */
        #ifdef WOLFSSL_SHA3
        REGISTER_ALG(pkcs1_sha3_256, sig, linuxkm_test_pkcs1_sha3_256);
        REGISTER_ALG(pkcs1_sha3_384, sig, linuxkm_test_pkcs1_sha3_384);
        REGISTER_ALG(pkcs1_sha3_512, sig, linuxkm_test_pkcs1_sha3_512);
        #endif /* WOLFSSL_SHA3 */

        REGISTER_ALG(pkcs1pad, akcipher, linuxkm_test_pkcs1pad);
    #endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */

    #if defined(LINUXKM_DIRECT_RSA)
    /* Note, direct RSA must be registered after all PKCS1 algs have been
     * registered, to assure that the kernel doesn't dynamically synthesize any
     * PKCS1 implementations using the raw primitive.
     */
    REGISTER_ALG(direct_rsa, akcipher, linuxkm_test_rsa);
    #endif /* LINUXKM_DIRECT_RSA */
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_DH
    #ifdef HAVE_FFDHE_2048
    REGISTER_ALG(ffdhe2048, kpp, linuxkm_test_ffdhe2048);
    #endif /* HAVE_FFDHE_2048 */

    #ifdef HAVE_FFDHE_3072
    REGISTER_ALG(ffdhe3072, kpp, linuxkm_test_ffdhe3072);
    #endif /* HAVE_FFDHE_3072 */

    #ifdef HAVE_FFDHE_4096
    REGISTER_ALG(ffdhe4096, kpp, linuxkm_test_ffdhe4096);
    #endif /* HAVE_FFDHE_4096 */

    #ifdef HAVE_FFDHE_6144
    REGISTER_ALG(ffdhe6144, kpp, linuxkm_test_ffdhe6144);
    #endif /* HAVE_FFDHE_6144 */

    #ifdef HAVE_FFDHE_8192
    REGISTER_ALG(ffdhe8192, kpp, linuxkm_test_ffdhe8192);
    #endif /* HAVE_FFDHE_8192 */

    #ifdef LINUXKM_DH
    REGISTER_ALG(dh, kpp, linuxkm_test_dh);
    #endif /* LINUXKM_DH */
#endif /* LINUXKM_LKCAPI_REGISTER_DH */

#undef REGISTER_ALG
#undef REGISTER_ALG_OPTIONAL

#if defined(CONFIG_CRYPTO_MANAGER_EXTRA_TESTS) || \
    defined(CONFIG_CRYPTO_SELFTESTS_FULL)
    disable_setkey_warnings = 0;
#endif

    pr_info("wolfCrypt: %d algorithm%s registered.", linuxkm_lkcapi_n_registered,
            linuxkm_lkcapi_n_registered == 1 ? "" : "s");

    if (ret == -1) {
        /* no installations occurred */
        if (linuxkm_lkcapi_registered)
            return -EEXIST;
        else {
            linuxkm_lkcapi_registered = 1;
            return 0;
        }
    }
    else {
        /* flag that linuxkm_lkcapi_register has been called, even if an error
         * occurred.
         */
        linuxkm_lkcapi_registered = 1;
        return seen_err;
    }
}

static int linuxkm_lkcapi_unregister(void)
{
    int seen_err = 0;
    int n_deregistered = 0;

    if (linuxkm_lkcapi_n_registered == 0)
        return -ENOENT;

#define UNREGISTER_ALG(alg, alg_class)                                   \
    do {                                                                 \
        if (alg ## _loaded) {                                            \
            if (alg.base.cra_flags & CRYPTO_ALG_DEAD) {                  \
                pr_err("alg %s already CRYPTO_ALG_DEAD.",                \
                       alg.base.cra_driver_name);                        \
                alg ## _loaded = 0;                                      \
                ++n_deregistered;                                        \
            }                                                            \
            else {                                                       \
                int cur_refcnt =                                         \
                    WC_LKM_REFCOUNT_TO_INT(alg.base.cra_refcnt);         \
                if (cur_refcnt == 1) {                                   \
                    (crypto_unregister_ ## alg_class)(&(alg));           \
                    if (! (alg.base.cra_flags & CRYPTO_ALG_DEAD)) {      \
                        pr_err("ERROR: alg %s not _DEAD after "          \
                               "crypto_unregister_%s -- "                \
                               "leaving marked as loaded.",              \
                               (alg).base.cra_driver_name,               \
                               #alg_class);                              \
                        seen_err = -EBUSY;                               \
                    } else {                                             \
                        alg ## _loaded = 0;                              \
                        ++n_deregistered;                                \
                    }                                                    \
                }                                                        \
                else {                                                   \
                    pr_err("alg %s cannot be uninstalled (refcnt = %d)", \
                           alg.base.cra_driver_name, cur_refcnt);        \
                    if (cur_refcnt > 0) { seen_err = -EBUSY; }           \
                }                                                        \
            }                                                            \
        }                                                                \
    } while (0)

#ifdef LINUXKM_LKCAPI_REGISTER_AESCBC
    UNREGISTER_ALG(cbcAesAlg, skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCFB
    UNREGISTER_ALG(cfbAesAlg, skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM
    UNREGISTER_ALG(gcmAesAead, aead);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    UNREGISTER_ALG(gcmAesAead_rfc4106, aead);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESXTS
    UNREGISTER_ALG(xtsAesAlg, skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCTR
    UNREGISTER_ALG(ctrAesAlg, skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESOFB
    UNREGISTER_ALG(ofbAesAlg, skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESECB
    UNREGISTER_ALG(ecbAesAlg, skcipher);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    UNREGISTER_ALG(sha1_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
    UNREGISTER_ALG(sha2_224_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
    UNREGISTER_ALG(sha2_256_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
    UNREGISTER_ALG(sha2_384_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
    UNREGISTER_ALG(sha2_512_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
    UNREGISTER_ALG(sha3_224_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
    UNREGISTER_ALG(sha3_256_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
    UNREGISTER_ALG(sha3_384_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
    UNREGISTER_ALG(sha3_512_alg, shash);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    UNREGISTER_ALG(sha1_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    UNREGISTER_ALG(sha2_224_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    UNREGISTER_ALG(sha2_256_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    UNREGISTER_ALG(sha2_384_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    UNREGISTER_ALG(sha2_512_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    UNREGISTER_ALG(sha3_224_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    UNREGISTER_ALG(sha3_256_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    UNREGISTER_ALG(sha3_384_hmac_alg, shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
    UNREGISTER_ALG(sha3_512_hmac_alg, shash);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_HASH_DRBG
    /* special deinstallation handler for wc_linuxkm_drbg, to deinstall it as
     * the system-wide default rng.
     */
    if (wc_linuxkm_drbg_loaded) {
        int ret = wc_linuxkm_drbg_cleanup();
        if (ret == 0)
            ++n_deregistered;
        else
            seen_err = ret;
    }
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_ECDSA
    #if defined(LINUXKM_ECC192)
        UNREGISTER_ALG(ecdsa_nist_p192, akcipher);
    #endif /* LINUXKM_ECC192 */
    UNREGISTER_ALG(ecdsa_nist_p256, akcipher);
    UNREGISTER_ALG(ecdsa_nist_p384, akcipher);
    #if defined(HAVE_ECC521)
        UNREGISTER_ALG(ecdsa_nist_p521, akcipher);
    #endif /* HAVE_ECC521 */
#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

#ifdef LINUXKM_LKCAPI_REGISTER_ECDH
    #if defined(LINUXKM_ECC192)
        UNREGISTER_ALG(ecdh_nist_p192, kpp);
    #endif /* LINUXKM_ECC192 */
    UNREGISTER_ALG(ecdh_nist_p256, kpp);
    UNREGISTER_ALG(ecdh_nist_p384, kpp);
    /* no ecdh p521 in kernel. */
#endif /* LINUXKM_LKCAPI_REGISTER_ECDH */

#ifdef LINUXKM_LKCAPI_REGISTER_RSA
    #if defined(LINUXKM_DIRECT_RSA)
        UNREGISTER_ALG(direct_rsa, akcipher);
    #endif /* LINUXKM_DIRECT_RSA */

    #if !defined(LINUXKM_AKCIPHER_NO_SIGNVERIFY)
        #ifdef WOLFSSL_SHA224
            UNREGISTER_ALG(pkcs1_sha224, akcipher);
        #endif /* WOLFSSL_SHA224 */
        #ifndef NO_SHA256
            UNREGISTER_ALG(pkcs1_sha256, akcipher);
        #endif /* !NO_SHA256 */
        #ifdef WOLFSSL_SHA384
            UNREGISTER_ALG(pkcs1_sha384, akcipher);
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA384
            UNREGISTER_ALG(pkcs1_sha384, akcipher);
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA512
            UNREGISTER_ALG(pkcs1_sha512, akcipher);
        #endif /* WOLFSSL_SHA512 */
        #ifdef WOLFSSL_SHA3
            UNREGISTER_ALG(pkcs1_sha3_256, akcipher);
            UNREGISTER_ALG(pkcs1_sha3_384, akcipher);
            UNREGISTER_ALG(pkcs1_sha3_512, akcipher);
        #endif /* WOLFSSL_SHA3 */
    #else
        #ifdef WOLFSSL_SHA224
            UNREGISTER_ALG(pkcs1_sha224, sig);
        #endif /* WOLFSSL_SHA224 */
        #ifndef NO_SHA256
            UNREGISTER_ALG(pkcs1_sha256, sig);
        #endif /* !NO_SHA256 */
        #ifdef WOLFSSL_SHA384
            UNREGISTER_ALG(pkcs1_sha384, sig);
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA384
            UNREGISTER_ALG(pkcs1_sha384, sig);
        #endif /* WOLFSSL_SHA384 */
        #ifdef WOLFSSL_SHA512
            UNREGISTER_ALG(pkcs1_sha512, sig);
        #endif /* WOLFSSL_SHA512 */
        #ifdef WOLFSSL_SHA3
            UNREGISTER_ALG(pkcs1_sha3_256, sig);
            UNREGISTER_ALG(pkcs1_sha3_384, sig);
            UNREGISTER_ALG(pkcs1_sha3_512, sig);
        #endif /* WOLFSSL_SHA3 */

        UNREGISTER_ALG(pkcs1pad, akcipher);
    #endif /* !LINUXKM_AKCIPHER_NO_SIGNVERIFY */
#endif /* LINUXKM_LKCAPI_REGISTER_RSA */

#ifdef LINUXKM_LKCAPI_REGISTER_DH
    #ifdef LINUXKM_DH
    UNREGISTER_ALG(dh, kpp);
    #endif /* LINUXKM_DH */
    #ifdef HAVE_FFDHE_2048
    UNREGISTER_ALG(ffdhe2048, kpp);
    #endif /* HAVE_FFDHE_2048 */

    #ifdef HAVE_FFDHE_3072
    UNREGISTER_ALG(ffdhe3072, kpp);
    #endif /* HAVE_FFDHE_3072 */

    #ifdef HAVE_FFDHE_4096
    UNREGISTER_ALG(ffdhe4096, kpp);
    #endif /* HAVE_FFDHE_4096 */

    #ifdef HAVE_FFDHE_6144
    UNREGISTER_ALG(ffdhe6144, kpp);
    #endif /* HAVE_FFDHE_6144 */

    #ifdef HAVE_FFDHE_8192
    UNREGISTER_ALG(ffdhe8192, kpp);
    #endif /* HAVE_FFDHE_8192 */
#endif /* LINUXKM_LKCAPI_REGISTER_DH */

#undef UNREGISTER_ALG

    linuxkm_lkcapi_n_registered -= n_deregistered;
    pr_info("wolfCrypt: %d algorithm%s deregistered, %d remain%s registered.",
            n_deregistered, n_deregistered == 1 ? "" : "s",
            linuxkm_lkcapi_n_registered, linuxkm_lkcapi_n_registered == 1 ? "s" : "");

    if (linuxkm_lkcapi_n_registered > 0)
        return -EBUSY;

    linuxkm_lkcapi_registered = 0;

    return seen_err;
}
