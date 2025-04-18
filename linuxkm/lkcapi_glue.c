/* lkcapi_glue.c -- glue logic to register wolfCrypt implementations with
 * the Linux Kernel Cryptosystem
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* included by linuxkm/module_hooks.c */

#ifndef LINUXKM_LKCAPI_REGISTER
    #error lkcapi_glue.c included in non-LINUXKM_LKCAPI_REGISTER project.
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
    #error LINUXKM_LKCAPI_REGISTER is supported only on Linux kernel versions >= 5.4.0.
#endif

/* kernel crypto self-test includes test setups that have different expected
 * results FIPS vs non-FIPS.
 */
#if defined(CONFIG_CRYPTO_MANAGER) && \
    !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    #if defined(CONFIG_CRYPTO_FIPS) != defined(HAVE_FIPS)
        #error CONFIG_CRYPTO_MANAGER requires that CONFIG_CRYPTO_FIPS match HAVE_FIPS.
    #endif
    #include <linux/fips.h>
#endif

#if defined(HAVE_FIPS) && FIPS_VERSION3_LT(6,0,0)
    /* need misc.c for ForceZero(). */
    #ifdef NO_INLINE
        #include <wolfssl/wolfcrypt/misc.h>
    #else
        #define WOLFSSL_MISC_INCLUDED
        #include <wolfcrypt/src/misc.c>
    #endif
#endif

#ifndef WOLFSSL_LINUXKM_LKCAPI_PRIORITY
    /* Larger number means higher priority.  The highest in-tree priority is
     * 4001, in the Cavium driver.
     */
    #define WOLFSSL_LINUXKM_LKCAPI_PRIORITY 10000
#endif

#ifdef CONFIG_CRYPTO_MANAGER_EXTRA_TESTS
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

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES
    enum linux_errcodes {
        my_EINVAL = EINVAL,
        my_ENOMEM = ENOMEM,
        my_EBADMSG = EBADMSG
    };

    #undef EINVAL
    #undef ENOMEM
    #undef EBADMSG

    #define EINVAL WC_ERR_TRACE(my_EINVAL)
    #define ENOMEM WC_ERR_TRACE(my_ENOMEM)
    #define EBADMSG WC_ERR_TRACE(my_EBADMSG)
#endif

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

#ifndef NO_AES
    #include "lkcapi_aes_glue.c"
#endif

#include "lkcapi_sha_glue.c"

#ifdef HAVE_ECC
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_ECDSA)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_ECDSA)
        #define LINUXKM_LKCAPI_REGISTER_ECDSA
    #endif

    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_ECDH)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_ECDH)
        #define LINUXKM_LKCAPI_REGISTER_ECDH
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_ECDSA
    #undef LINUXKM_LKCAPI_REGISTER_ECDH
#endif /* HAVE_ECC */

#if !defined(NO_RSA)
    #if (defined(LINUXKM_LKCAPI_REGISTER_ALL) && !defined(LINUXKM_LKCAPI_DONT_REGISTER_RSA)) && \
        !defined(LINUXKM_LKCAPI_REGISTER_RSA)
        #define LINUXKM_LKCAPI_REGISTER_RSA
    #endif
#else
    #undef LINUXKM_LKCAPI_REGISTER_RSA
#endif /* !NO_RSA */

/*
 * extra checks on kernel version, and ecc sizes.
 */
#if defined (LINUXKM_LKCAPI_REGISTER_ECDSA)
    #if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0) && \
        defined(CONFIG_CRYPTO_FIPS) && defined(CONFIG_CRYPTO_MANAGER)
        /**
         * note: ecdsa was not recognized as fips_allowed before linux v6.3
         * in kernel crypto/testmgr.c, and will not pass the tests.
         * */
        #undef LINUXKM_LKCAPI_REGISTER_ECDSA
    #endif /* linux < 6.3.0 && CONFIG_CRYPTO_FIPS && CONFIG_CRYPTO_MANAGER */

    #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && \
        ECC_MIN_KEY_SZ <= 192 && !defined(CONFIG_CRYPTO_FIPS)
        /* only register p192 if specifically enabled, and if not fips. */
        #define LINUXKM_ECC192
    #endif
#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

#ifdef LINUXKM_LKCAPI_REGISTER_ECDH
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
        /* currently incompatible with kernel 5.12 or earlier. */
        #undef LINUXKM_LKCAPI_REGISTER_ECDH
    #endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
    /**
     * notes:
     *   - ecdsa supported with linux 6.12 and earlier for now, only.
     *   - pkcs1pad rsa supported both before and after linux 6.13, but
     *     without sign/verify after linux 6.13.
     *
     * In linux 6.13 the sign/verify callbacks were removed from
     * akcipher_alg, and ecdsa changed from a struct akcipher_alg type to
     * struct sig_alg type.
     *
     * pkcs1pad rsa remained a struct akcipher_alg, but without sign/verify
     * functionality.
     * */
    #if defined (LINUXKM_LKCAPI_REGISTER_ECDSA)
        #undef LINUXKM_LKCAPI_REGISTER_ECDSA
    #endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

    #if defined (LINUXKM_LKCAPI_REGISTER_RSA)
        #define LINUXKM_AKCIPHER_NO_SIGNVERIFY
    #endif /* LINUXKM_LKCAPI_REGISTER_RSA */
#endif /* linux >= 6.13.0 */

#if defined (LINUXKM_LKCAPI_REGISTER_ECDSA)
    #include "linuxkm/lkcapi_ecdsa_glue.c"
#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

#if defined (LINUXKM_LKCAPI_REGISTER_ECDH)
    #include "linuxkm/lkcapi_ecdh_glue.c"
#endif /* LINUXKM_LKCAPI_REGISTER_ECDH */

#if defined(LINUXKM_LKCAPI_REGISTER_RSA)
    #include "linuxkm/lkcapi_rsa_glue.c"
#endif /* LINUXKM_LKCAPI_REGISTER_RSA */

static int linuxkm_lkcapi_register(void)
{
    int ret = 0;
#if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
        !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    int enabled_fips = 0;
#endif

#ifdef CONFIG_CRYPTO_MANAGER_EXTRA_TESTS
    /* temporarily disable warnings around setkey failures, which are expected
     * from the crypto fuzzer in FIPS configs, and potentially in others.
     * unexpected setkey failures are fatal errors returned by the fuzzer.
     */
    disable_setkey_warnings = 1;
#endif
#if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
        !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    if (! fips_enabled) {
        /* temporarily assert system-wide FIPS status, to disable FIPS-forbidden
         * test vectors and fuzzing from the CRYPTO_MANAGER.
         */
        enabled_fips = fips_enabled = 1;
    }
#endif

#define REGISTER_ALG(alg, installer, tester) do {                       \
        if (alg ## _loaded) {                                           \
            pr_err("ERROR: %s is already registered.\n",                \
                   (alg).base.cra_driver_name);                         \
            ret = -EEXIST;                                              \
            goto out;                                                   \
        }                                                               \
                                                                        \
        ret =  (installer)(&(alg));                                     \
                                                                        \
        if (ret) {                                                      \
            pr_err("ERROR: " #installer " for %s failed "               \
                   "with return code %d.\n",                            \
                   (alg).base.cra_driver_name, ret);                    \
            goto out;                                                   \
        }                                                               \
                                                                        \
        alg ## _loaded = 1;                                             \
                                                                        \
        ret = (tester());                                               \
                                                                        \
        if (ret) {                                                      \
            pr_err("ERROR: self-test for %s failed "                    \
                   "with return code %d.\n",                            \
                   (alg).base.cra_driver_name, ret);                    \
            goto out;                                                   \
        }                                                               \
        pr_info("%s self-test OK -- "                                   \
                "registered for %s with priority %d.\n",                \
                (alg).base.cra_driver_name,                             \
                (alg).base.cra_name,                                    \
                (alg).base.cra_priority);                               \
    } while (0)

#ifdef LINUXKM_LKCAPI_REGISTER_AESCBC
    REGISTER_ALG(cbcAesAlg, crypto_register_skcipher, linuxkm_test_aescbc);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCFB
    REGISTER_ALG(cfbAesAlg, crypto_register_skcipher, linuxkm_test_aescfb);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM
    REGISTER_ALG(gcmAesAead, crypto_register_aead, linuxkm_test_aesgcm);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    REGISTER_ALG(gcmAesAead_rfc4106, crypto_register_aead, linuxkm_test_aesgcm_rfc4106);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESXTS
    REGISTER_ALG(xtsAesAlg, crypto_register_skcipher, linuxkm_test_aesxts);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCTR
    REGISTER_ALG(ctrAesAlg, crypto_register_skcipher, linuxkm_test_aesctr);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESOFB
    REGISTER_ALG(ofbAesAlg, crypto_register_skcipher, linuxkm_test_aesofb);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESECB
    REGISTER_ALG(ecbAesAlg, crypto_register_skcipher, linuxkm_test_aesecb);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    REGISTER_ALG(sha1_alg, crypto_register_shash, linuxkm_test_sha1);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
    REGISTER_ALG(sha2_224_alg, crypto_register_shash, linuxkm_test_sha2_224);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
    REGISTER_ALG(sha2_256_alg, crypto_register_shash, linuxkm_test_sha2_256);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
    REGISTER_ALG(sha2_384_alg, crypto_register_shash, linuxkm_test_sha2_384);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
    REGISTER_ALG(sha2_512_alg, crypto_register_shash, linuxkm_test_sha2_512);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
    REGISTER_ALG(sha3_224_alg, crypto_register_shash, linuxkm_test_sha3_224);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
    REGISTER_ALG(sha3_256_alg, crypto_register_shash, linuxkm_test_sha3_256);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
    REGISTER_ALG(sha3_384_alg, crypto_register_shash, linuxkm_test_sha3_384);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
    REGISTER_ALG(sha3_512_alg, crypto_register_shash, linuxkm_test_sha3_512);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1_HMAC
    REGISTER_ALG(sha1_hmac_alg, crypto_register_shash, linuxkm_test_sha1_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    REGISTER_ALG(sha2_224_hmac_alg, crypto_register_shash, linuxkm_test_sha2_224_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    REGISTER_ALG(sha2_256_hmac_alg, crypto_register_shash, linuxkm_test_sha2_256_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    REGISTER_ALG(sha2_384_hmac_alg, crypto_register_shash, linuxkm_test_sha2_384_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    REGISTER_ALG(sha2_512_hmac_alg, crypto_register_shash, linuxkm_test_sha2_512_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    REGISTER_ALG(sha3_224_hmac_alg, crypto_register_shash, linuxkm_test_sha3_224_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    REGISTER_ALG(sha3_256_hmac_alg, crypto_register_shash, linuxkm_test_sha3_256_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    REGISTER_ALG(sha3_384_hmac_alg, crypto_register_shash, linuxkm_test_sha3_384_hmac);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
    REGISTER_ALG(sha3_512_hmac_alg, crypto_register_shash, linuxkm_test_sha3_512_hmac);
#endif


#ifdef LINUXKM_LKCAPI_REGISTER_ECDSA
    #if defined(LINUXKM_ECC192)
    REGISTER_ALG(ecdsa_nist_p192, crypto_register_akcipher,
                 linuxkm_test_ecdsa_nist_p192);
    #endif /* LINUXKM_ECC192 */

    REGISTER_ALG(ecdsa_nist_p256, crypto_register_akcipher,
                 linuxkm_test_ecdsa_nist_p256);

    REGISTER_ALG(ecdsa_nist_p384, crypto_register_akcipher,
                 linuxkm_test_ecdsa_nist_p384);

    #if defined(HAVE_ECC521)
    REGISTER_ALG(ecdsa_nist_p521, crypto_register_akcipher,
                 linuxkm_test_ecdsa_nist_p521);
    #endif /* HAVE_ECC521 */
#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

#ifdef LINUXKM_LKCAPI_REGISTER_ECDH
    #if defined(LINUXKM_ECC192)
    REGISTER_ALG(ecdh_nist_p192, crypto_register_kpp,
                 linuxkm_test_ecdh_nist_p192);
    #endif /* LINUXKM_ECC192 */

    REGISTER_ALG(ecdh_nist_p256, crypto_register_kpp,
                 linuxkm_test_ecdh_nist_p256);

    REGISTER_ALG(ecdh_nist_p384, crypto_register_kpp,
                 linuxkm_test_ecdh_nist_p384);
#endif /* LINUXKM_LKCAPI_REGISTER_ECDH */

#ifdef LINUXKM_LKCAPI_REGISTER_RSA
    #if defined(LINUXKM_DIRECT_RSA)
    REGISTER_ALG(direct_rsa, crypto_register_akcipher, linuxkm_test_rsa);
    #endif /* LINUXKM_DIRECT_RSA */
    #ifndef NO_SHA256
    REGISTER_ALG(pkcs1_sha256, crypto_register_akcipher,
                 linuxkm_test_pkcs1_sha256);
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA512
    REGISTER_ALG(pkcs1_sha512, crypto_register_akcipher,
                 linuxkm_test_pkcs1_sha512);
    #endif /* WOLFSSL_SHA512 */
#endif

#undef REGISTER_ALG

    out:

#if defined(HAVE_FIPS) && defined(CONFIG_CRYPTO_MANAGER) && \
        !defined(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS)
    if (enabled_fips)
        fips_enabled = 0;
#endif
#ifdef CONFIG_CRYPTO_MANAGER_EXTRA_TESTS
    disable_setkey_warnings = 0;
#endif

    return ret;
}

static void linuxkm_lkcapi_unregister(void)
{
#define UNREGISTER_ALG(alg, uninstaller) do {                           \
        if (alg ## _loaded) {                                           \
            (uninstaller)(&(alg));                                      \
            alg ## _loaded = 0;                                         \
        }                                                               \
    } while (0)

#ifdef LINUXKM_LKCAPI_REGISTER_AESCBC
    UNREGISTER_ALG(cbcAesAlg, crypto_unregister_skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCFB
    UNREGISTER_ALG(cfbAesAlg, crypto_unregister_skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM
    UNREGISTER_ALG(gcmAesAead, crypto_unregister_aead);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESGCM_RFC4106
    UNREGISTER_ALG(gcmAesAead_rfc4106, crypto_unregister_aead);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESXTS
    UNREGISTER_ALG(xtsAesAlg, crypto_unregister_skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESCTR
    UNREGISTER_ALG(ctrAesAlg, crypto_unregister_skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESOFB
    UNREGISTER_ALG(ofbAesAlg, crypto_unregister_skcipher);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_AESECB
    UNREGISTER_ALG(ecbAesAlg, crypto_unregister_skcipher);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    UNREGISTER_ALG(sha1_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224
    UNREGISTER_ALG(sha2_224_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256
    UNREGISTER_ALG(sha2_256_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384
    UNREGISTER_ALG(sha2_384_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512
    UNREGISTER_ALG(sha2_512_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224
    UNREGISTER_ALG(sha3_224_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256
    UNREGISTER_ALG(sha3_256_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384
    UNREGISTER_ALG(sha3_384_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512
    UNREGISTER_ALG(sha3_512_alg, crypto_unregister_shash);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_SHA1
    UNREGISTER_ALG(sha1_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_224_HMAC
    UNREGISTER_ALG(sha2_224_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_256_HMAC
    UNREGISTER_ALG(sha2_256_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_384_HMAC
    UNREGISTER_ALG(sha2_384_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA2_512_HMAC
    UNREGISTER_ALG(sha2_512_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_224_HMAC
    UNREGISTER_ALG(sha3_224_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_256_HMAC
    UNREGISTER_ALG(sha3_256_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_384_HMAC
    UNREGISTER_ALG(sha3_384_hmac_alg, crypto_unregister_shash);
#endif
#ifdef LINUXKM_LKCAPI_REGISTER_SHA3_512_HMAC
    UNREGISTER_ALG(sha3_512_hmac_alg, crypto_unregister_shash);
#endif

#ifdef LINUXKM_LKCAPI_REGISTER_ECDSA
    #if defined(LINUXKM_ECC192)
        UNREGISTER_ALG(ecdsa_nist_p192, crypto_unregister_akcipher);
    #endif /* LINUXKM_ECC192 */
    UNREGISTER_ALG(ecdsa_nist_p256, crypto_unregister_akcipher);
    UNREGISTER_ALG(ecdsa_nist_p384, crypto_unregister_akcipher);
    #if defined(HAVE_ECC521)
        UNREGISTER_ALG(ecdsa_nist_p521, crypto_unregister_akcipher);
    #endif /* HAVE_ECC521 */
#endif /* LINUXKM_LKCAPI_REGISTER_ECDSA */

#ifdef LINUXKM_LKCAPI_REGISTER_ECDH
    #if defined(LINUXKM_ECC192)
        UNREGISTER_ALG(ecdh_nist_p192, crypto_unregister_kpp);
    #endif /* LINUXKM_ECC192 */
    UNREGISTER_ALG(ecdh_nist_p256, crypto_unregister_kpp);
    UNREGISTER_ALG(ecdh_nist_p384, crypto_unregister_kpp);
    /* no ecdh p521 in kernel. */
#endif /* LINUXKM_LKCAPI_REGISTER_ECDH */

#ifdef LINUXKM_LKCAPI_REGISTER_RSA
    #if defined(LINUXKM_DIRECT_RSA)
        UNREGISTER_ALG(direct_rsa, crypto_unregister_akcipher);
    #endif /* LINUXKM_DIRECT_RSA */
    #ifndef NO_SHA256
        UNREGISTER_ALG(pkcs1_sha256, crypto_unregister_akcipher);
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA512
        UNREGISTER_ALG(pkcs1_sha512, crypto_unregister_akcipher);
    #endif /* WOLFSSL_SHA512 */
#endif /* LINUXKM_LKCAPI_REGISTER_RSA */

#undef UNREGISTER_ALG
}
