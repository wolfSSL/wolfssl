/* module_hooks.c -- module load/unload hooks for libwolfssl.ko
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#ifndef WOLFSSL_LICENSE
#ifdef WOLFSSL_COMMERCIAL_LICENSE
#define WOLFSSL_LICENSE "wolfSSL Commercial"
#else
#define WOLFSSL_LICENSE "GPL v2"
#endif
#endif

#define FIPS_NO_WRAPPERS

#define WOLFSSL_NEED_LINUX_CURRENT

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/version.h>
#else
    #include <wolfssl/ssl.h>
#endif
#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif
#ifndef NO_CRYPT_TEST
    #include <wolfcrypt/test/test.h>
    #include <linux/delay.h>
#endif

static int libwolfssl_cleanup(void) {
    int ret;
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0)
        pr_err("wolfCrypt_Cleanup() failed: %s\n", wc_GetErrorString(ret));
    else
        pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS)
        pr_err("wolfSSL_Cleanup() failed: %s\n", wc_GetErrorString(ret));
    else
        pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#endif

    return ret;
}

#ifdef HAVE_LINUXKM_PIE_SUPPORT

extern int wolfCrypt_PIE_first_function(void);
extern int wolfCrypt_PIE_last_function(void);
extern const unsigned int wolfCrypt_PIE_rodata_start[];
extern const unsigned int wolfCrypt_PIE_rodata_end[];

/* cheap portable ad-hoc hash function to confirm bitwise stability of the PIE
 * binary image.
 */
static unsigned int hash_span(char *start, char *end) {
    unsigned int sum = 1;
    while (start < end) {
        unsigned int rotate_by;
        sum ^= *start++;
        rotate_by = (sum ^ (sum >> 5)) & 31;
        sum = (sum << rotate_by) | (sum >> (32 - rotate_by));
    }
    return sum;
}

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE
extern struct wolfssl_linuxkm_pie_redirect_table wolfssl_linuxkm_pie_redirect_table;
static int set_up_wolfssl_linuxkm_pie_redirect_table(void);
#endif /* USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE */

#endif /* HAVE_LINUXKM_PIE_SUPPORT */

#ifdef HAVE_FIPS
static void lkmFipsCb(int ok, int err, const char* hash)
{
    if ((! ok) || (err != 0))
        pr_err("libwolfssl FIPS error: %s\n", wc_GetErrorString(err));
    if (err == IN_CORE_FIPS_E) {
        pr_err("In-core integrity hash check failure.\n"
               "Update verifyCore[] in fips_test.c with new hash \"%s\" and rebuild.\n",
               hash ? hash : "<null>");
    }
}
#endif

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
#ifndef CONFIG_MODULE_SIG
#error WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE requires a CONFIG_MODULE_SIG kernel.
#endif
static int updateFipsHash(void);
#endif

#ifdef WOLFSSL_LINUXKM_BENCHMARKS
#undef HAVE_PTHREAD
#define STRING_USER
#define NO_MAIN_FUNCTION
#define current_time benchmark_current_time
#define WOLFSSL_NO_FLOAT_FMT
#include "wolfcrypt/benchmark/benchmark.c"
#endif /* WOLFSSL_LINUXKM_BENCHMARKS */

#ifdef LINUXKM_REGISTER_ALG
#if defined(NO_AES)
    #error LINUXKM_REGISTER_ALG requires AES.
#endif

#if !defined(HAVE_AESGCM) && !defined(HAVe_AES_CBC) && !defined(WOLFSSL_AES_CFB)
    #error LINUXKM_REGISTER_ALG requires AES-CBC, CFB, or GCM.
#endif

#if defined(HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM)
    #error LINUXKM_REGISTER_ALG requires AESGCM_STREAM.
#endif

#define WOLFKM_CBC_NAME   "cbc(aes)"
#define WOLFKM_CFB_NAME   "cfb(aes)"
#define WOLFKM_GCM_NAME   "gcm(aes)"
#define WOLFKM_CBC_DRIVER "cbc-aes-wolfcrypt"
#define WOLFKM_CFB_DRIVER "cfb-aes-wolfcrypt"
#define WOLFKM_GCM_DRIVER "gcm-aes-wolfcrypt"
#define WOLFKM_ALG_PRIORITY (100)
static int  linuxkm_register_alg(void);
static void linuxkm_unregister_alg(void);
static int  linuxkm_test_alg(void);
static int  linuxkm_test_cbc(void);
static int  linuxkm_test_cfb(void);
static int  linuxkm_test_gcm(void);
#endif /* endif LINUXKM_REGISTER_ALG */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int __init wolfssl_init(void)
#else
static int wolfssl_init(void)
#endif
{
    int ret;

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
    if (THIS_MODULE->sig_ok == false) {
        pr_err("wolfSSL module load aborted -- bad or missing module signature with FIPS dynamic hash.\n");
        return -ECANCELED;
    }
    ret = updateFipsHash();
    if (ret < 0) {
        pr_err("wolfSSL module load aborted -- updateFipsHash: %s\n",wc_GetErrorString(ret));
        return -ECANCELED;
    }
#endif

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE
    ret = set_up_wolfssl_linuxkm_pie_redirect_table();
    if (ret < 0)
        return ret;
#endif

#ifdef HAVE_LINUXKM_PIE_SUPPORT

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    /* see linux commit ac3b432839 */
    #define THIS_MODULE_TEXT_BASE (THIS_MODULE->mem[MOD_TEXT].base)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->mem[MOD_TEXT].size)
    #define THIS_MODULE_RO_BASE (THIS_MODULE->mem[MOD_RODATA].base)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->mem[MOD_RODATA].size)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
    #define THIS_MODULE_TEXT_BASE (THIS_MODULE->core_layout.base)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->core_layout.text_size)
    #define THIS_MODULE_RO_BASE ((char *)THIS_MODULE->core_layout.base + THIS_MODULE->core_layout.text_size)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->core_layout.ro_size)
#else
    #define THIS_MODULE_TEXT_BASE (THIS_MODULE->module_core)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->core_text_size)
    #define THIS_MODULE_RO_BASE ((char *)THIS_MODULE->module_core + THIS_MODULE->core_ro_size)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->core_ro_size)
#endif

    {
        char *pie_text_start = (char *)wolfCrypt_PIE_first_function;
        char *pie_text_end = (char *)wolfCrypt_PIE_last_function;
        char *pie_rodata_start = (char *)wolfCrypt_PIE_rodata_start;
        char *pie_rodata_end = (char *)wolfCrypt_PIE_rodata_end;
        unsigned int text_hash, rodata_hash;

        if ((pie_text_start < pie_text_end) &&
            (pie_text_start >= (char *)THIS_MODULE_TEXT_BASE) &&
            (pie_text_end - (char *)THIS_MODULE_TEXT_BASE <= THIS_MODULE_TEXT_SIZE))
        {
            text_hash = hash_span(pie_text_start, pie_text_end);
        } else {
            pr_info("out-of-bounds PIE fenceposts! pie_text_start=%px pie_text_end=%px (span=%lu)"
                    " core_layout.base=%px text_end=%px\n",
                    pie_text_start,
                    pie_text_end,
                    pie_text_end-pie_text_start,
                    THIS_MODULE_TEXT_BASE,
                    (char *)THIS_MODULE_TEXT_BASE + THIS_MODULE_TEXT_SIZE);
            text_hash = 0;
        }

        if ((pie_rodata_start < pie_rodata_end) && // cppcheck-suppress comparePointers
            (pie_rodata_start >= (char *)THIS_MODULE_RO_BASE) &&
            (pie_rodata_end - (char *)THIS_MODULE_RO_BASE <= THIS_MODULE_RO_SIZE))
        {
            rodata_hash = hash_span(pie_rodata_start, pie_rodata_end);
        } else {
            pr_info("out-of-bounds PIE fenceposts! pie_rodata_start=%px pie_rodata_end=%px (span=%lu)"
                    " core_layout.base+core_layout.text_size=%px rodata_end=%px\n",
                    pie_rodata_start,
                    pie_rodata_end,
                    pie_rodata_end-pie_rodata_start,
                    (char *)THIS_MODULE_RO_BASE,
                    (char *)THIS_MODULE_RO_BASE + THIS_MODULE_RO_SIZE);
            rodata_hash = 0;
        }

        /* note, "%pK" conceals the actual layout information.  "%px" exposes
         * the true module start address, which is potentially useful to an
         * attacker.
         */
        pr_info("wolfCrypt container hashes (spans): text 0x%x (%lu), rodata 0x%x (%lu)\n",
                text_hash, pie_text_end-pie_text_start,
                rodata_hash, pie_rodata_end-pie_rodata_start);
    }
#endif /* HAVE_LINUXKM_PIE_SUPPORT */

#ifdef HAVE_FIPS
    ret = wolfCrypt_SetCb_fips(lkmFipsCb);
    if (ret != 0) {
        pr_err("wolfCrypt_SetCb_fips() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
    fipsEntry();
    ret = wolfCrypt_GetStatus_fips();
    if (ret != 0) {
        pr_err("wolfCrypt_GetStatus_fips() failed: %s\n", wc_GetErrorString(ret));
        if (ret == IN_CORE_FIPS_E) {
            const char *newhash = wolfCrypt_GetCoreHash_fips();
            pr_err("Update verifyCore[] in fips_test.c with new hash \"%s\" and rebuild.\n",
                   newhash ? newhash : "<null>");
        }
        return -ECANCELED;
    }

    pr_info("wolfCrypt FIPS ["

#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 3)
            "ready"
#elif defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2) \
    && defined(WOLFCRYPT_FIPS_RAND)
            "140-2 rand"
#elif defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
            "140-2"
#else
            "140"
#endif
            "] POST succeeded.\n");
#endif /* HAVE_FIPS */

#ifdef WC_RNG_SEED_CB
    ret = wc_SetSeed_Cb(wc_GenerateSeed);
    if (ret < 0) {
        pr_err("wc_SetSeed_Cb() failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
#endif

#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        pr_err("wolfCrypt_Init() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        pr_err("wolfSSL_Init() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#endif

#ifndef NO_CRYPT_TEST
    ret = wolfcrypt_test(NULL);
    if (ret < 0) {
        pr_err("wolfcrypt self-test failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
    pr_info("wolfCrypt self-test passed.\n");
#endif

#ifdef WOLFSSL_LINUXKM_BENCHMARKS
    wolfcrypt_benchmark_main(0, (char**)NULL);
#endif

#ifdef WOLFCRYPT_ONLY
    pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " loaded%s"
            ".\nSee https://www.wolfssl.com/ for more information.\n"
            "wolfCrypt Copyright (C) 2006-present wolfSSL Inc.  Licensed under " WOLFSSL_LICENSE ".\n",
#ifdef CONFIG_MODULE_SIG
            THIS_MODULE->sig_ok ? " with valid module signature" : " without valid module signature"
#else
            ""
#endif
        );
#else
    pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " loaded%s"
            ".\nSee https://www.wolfssl.com/ for more information.\n"
            "wolfSSL Copyright (C) 2006-present wolfSSL Inc.  Licensed under " WOLFSSL_LICENSE ".\n",
#ifdef CONFIG_MODULE_SIG
            THIS_MODULE->sig_ok ? " with valid module signature" : " without valid module signature"
#else
            ""
#endif
        );
#endif

#if defined(LINUXKM_REGISTER_ALG) && !defined(NO_AES)
    ret = linuxkm_register_alg();

    if (ret) {
        pr_err("linuxkm_register_alg failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        linuxkm_unregister_alg();
        msleep(10);
        return -ECANCELED;
    }

    ret = linuxkm_test_alg();

    if (ret) {
        pr_err("linuxkm_test_alg failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        linuxkm_unregister_alg();
        msleep(10);
        return -ECANCELED;
    }
#endif
    return 0;
}

module_init(wolfssl_init);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void __exit wolfssl_exit(void)
#else
static void wolfssl_exit(void)
#endif
{
    (void)libwolfssl_cleanup();

#if defined(LINUXKM_REGISTER_ALG) && !defined(NO_AES)
    linuxkm_unregister_alg();
#endif
    return;
}

module_exit(wolfssl_exit);

MODULE_LICENSE(WOLFSSL_LICENSE);
MODULE_AUTHOR("https://www.wolfssl.com/");
MODULE_DESCRIPTION("libwolfssl cryptographic and protocol facilities");
MODULE_VERSION(LIBWOLFSSL_VERSION_STRING);

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE

/* get_current() is an inline or macro, depending on the target -- sidestep the whole issue with a wrapper func. */
static struct task_struct *my_get_current_thread(void) {
    return get_current();
}

/* ditto for preempt_count(). */
static int my_preempt_count(void) {
    return preempt_count();
}

#if defined(WOLFSSL_LINUXKM_SIMD_X86) && defined(WOLFSSL_COMMERCIAL_LICENSE)

/* ditto for fpregs_lock/fpregs_unlock */
#ifdef WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS
static void my_fpregs_lock(void) {
    fpregs_lock();
}

static void my_fpregs_unlock(void) {
    fpregs_unlock();
}

#endif /* WOLFSSL_LINUXKM_SIMD_X86 && WOLFSSL_COMMERCIAL_LICENSE */

#endif /* USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE */

static int set_up_wolfssl_linuxkm_pie_redirect_table(void) {
    memset(
        &wolfssl_linuxkm_pie_redirect_table,
        0,
        sizeof wolfssl_linuxkm_pie_redirect_table);

#ifndef __ARCH_MEMCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcmp = memcmp;
#endif
#ifndef __ARCH_MEMCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcpy = memcpy;
#endif
#ifndef __ARCH_MEMSET_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memset = memset;
#endif
#ifndef __ARCH_MEMMOVE_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memmove = memmove;
#endif
#ifndef __ARCH_STRCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strcmp = strcmp;
#endif
#ifndef __ARCH_STRNCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncmp = strncmp;
#endif
#ifndef __ARCH_STRCASECMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strcasecmp = strcasecmp;
#endif
#ifndef __ARCH_STRNCASECMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncasecmp = strncasecmp;
#endif
#ifndef __ARCH_STRLEN_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strlen = strlen;
#endif
#ifndef __ARCH_STRSTR_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strstr = strstr;
#endif
#ifndef __ARCH_STRNCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncpy = strncpy;
#endif
#ifndef __ARCH_STRNCAT_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncat = strncat;
#endif
    wolfssl_linuxkm_pie_redirect_table.kstrtoll = kstrtoll;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        wolfssl_linuxkm_pie_redirect_table._printk = _printk;
    #else
        wolfssl_linuxkm_pie_redirect_table.printk = printk;
    #endif
    wolfssl_linuxkm_pie_redirect_table.snprintf = snprintf;

    wolfssl_linuxkm_pie_redirect_table._ctype = _ctype;

    wolfssl_linuxkm_pie_redirect_table.kmalloc = kmalloc;
    wolfssl_linuxkm_pie_redirect_table.kfree = kfree;
    wolfssl_linuxkm_pie_redirect_table.ksize = ksize;
    wolfssl_linuxkm_pie_redirect_table.krealloc = krealloc;
#ifdef HAVE_KVMALLOC
    wolfssl_linuxkm_pie_redirect_table.kvmalloc_node = kvmalloc_node;
    wolfssl_linuxkm_pie_redirect_table.kvfree = kvfree;
#endif
    wolfssl_linuxkm_pie_redirect_table.is_vmalloc_addr = is_vmalloc_addr;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        wolfssl_linuxkm_pie_redirect_table.kmalloc_trace =
            kmalloc_trace;
    #else
        wolfssl_linuxkm_pie_redirect_table.kmem_cache_alloc_trace =
            kmem_cache_alloc_trace;
        wolfssl_linuxkm_pie_redirect_table.kmalloc_order_trace =
            kmalloc_order_trace;
    #endif

    wolfssl_linuxkm_pie_redirect_table.get_random_bytes = get_random_bytes;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.getnstimeofday =
            getnstimeofday;
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.current_kernel_time64 =
            current_kernel_time64;
    #else
        wolfssl_linuxkm_pie_redirect_table.ktime_get_coarse_real_ts64 =
            ktime_get_coarse_real_ts64;
    #endif

    wolfssl_linuxkm_pie_redirect_table.get_current = my_get_current_thread;
    wolfssl_linuxkm_pie_redirect_table.preempt_count = my_preempt_count;

#ifdef WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS

    #if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
        wolfssl_linuxkm_pie_redirect_table.cpu_number = &cpu_number;
    #else
        wolfssl_linuxkm_pie_redirect_table.pcpu_hot = &pcpu_hot;
    #endif
    wolfssl_linuxkm_pie_redirect_table.nr_cpu_ids = &nr_cpu_ids;

    #if defined(CONFIG_SMP) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)) && \
        !defined(WOLFSSL_COMMERCIAL_LICENSE)
        wolfssl_linuxkm_pie_redirect_table.migrate_disable = &migrate_disable;
        wolfssl_linuxkm_pie_redirect_table.migrate_enable = &migrate_enable;
    #endif

#ifdef WOLFSSL_LINUXKM_SIMD_X86
    wolfssl_linuxkm_pie_redirect_table.irq_fpu_usable = irq_fpu_usable;
    #ifdef WOLFSSL_COMMERCIAL_LICENSE
        wolfssl_linuxkm_pie_redirect_table.fpregs_lock = my_fpregs_lock;
        wolfssl_linuxkm_pie_redirect_table.fpregs_unlock = my_fpregs_unlock;
    #else /* !defined(WOLFSSL_COMMERCIAL_LICENSE) */
        #ifdef kernel_fpu_begin
        wolfssl_linuxkm_pie_redirect_table.kernel_fpu_begin_mask =
            kernel_fpu_begin_mask;
        #else
        wolfssl_linuxkm_pie_redirect_table.kernel_fpu_begin =
            kernel_fpu_begin;
        #endif
        wolfssl_linuxkm_pie_redirect_table.kernel_fpu_end = kernel_fpu_end;
    #endif /* !defined(WOLFSSL_COMMERCIAL_LICENSE) */
#endif /* WOLFSSL_LINUXKM_SIMD_X86 */

#endif /* WOLFSSL_LINUXKM_USE_SAVE_VECTOR_REGISTERS */

    wolfssl_linuxkm_pie_redirect_table.__mutex_init = __mutex_init;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.mutex_lock_nested = mutex_lock_nested;
    #else
        wolfssl_linuxkm_pie_redirect_table.mutex_lock = mutex_lock;
    #endif
    wolfssl_linuxkm_pie_redirect_table.mutex_unlock = mutex_unlock;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.mutex_destroy = mutex_destroy;
    #endif

#ifdef HAVE_FIPS
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_first =
        wolfCrypt_FIPS_first;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_last =
        wolfCrypt_FIPS_last;
#endif

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS)
    wolfssl_linuxkm_pie_redirect_table.GetCA = GetCA;
#ifndef NO_SKID
    wolfssl_linuxkm_pie_redirect_table.GetCAByName = GetCAByName;
#endif
#endif

    /* runtime assert that the table has no null slots after initialization. */
    {
        unsigned long *i;
        for (i = (unsigned long *)&wolfssl_linuxkm_pie_redirect_table;
             i < (unsigned long *)&wolfssl_linuxkm_pie_redirect_table._last_slot;
             ++i)
            if (*i == 0) {
                pr_err("wolfCrypt container redirect table initialization was incomplete.\n");
                return -EFAULT;
            }
    }

    return 0;
}

#endif /* USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE */


#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE

#include <wolfssl/wolfcrypt/coding.h>

PRAGMA_GCC_DIAG_PUSH
PRAGMA_GCC("GCC diagnostic ignored \"-Wnested-externs\"")
PRAGMA_GCC("GCC diagnostic ignored \"-Wpointer-arith\"")
#include <crypto/hash.h>
PRAGMA_GCC_DIAG_POP

extern char verifyCore[WC_SHA256_DIGEST_SIZE*2 + 1];
extern const char coreKey[WC_SHA256_DIGEST_SIZE*2 + 1];
extern const unsigned int wolfCrypt_FIPS_ro_start[];
extern const unsigned int wolfCrypt_FIPS_ro_end[];

#define FIPS_IN_CORE_KEY_SZ 32
#define FIPS_IN_CORE_VERIFY_SZ FIPS_IN_CORE_KEY_SZ
typedef int (*fips_address_function)(void);
#define MAX_FIPS_DATA_SZ  100000
#define MAX_FIPS_CODE_SZ 1000000
extern int GenBase16_Hash(const byte* in, int length, char* out, int outSz);

static int updateFipsHash(void)
{
    struct crypto_shash *tfm = NULL;
    struct shash_desc *desc = NULL;
    word32 verifySz  = FIPS_IN_CORE_VERIFY_SZ;
    word32 binCoreSz  = FIPS_IN_CORE_KEY_SZ;
    int ret;
    byte *hash = NULL;
    char *base16_hash = NULL;
    byte *binCoreKey = NULL;
    byte *binVerify = NULL;

    fips_address_function first = wolfCrypt_FIPS_first;
    fips_address_function last  = wolfCrypt_FIPS_last;

    char* start = (char*)wolfCrypt_FIPS_ro_start;
    char* end   = (char*)wolfCrypt_FIPS_ro_end;

    unsigned long code_sz = (unsigned long)last - (unsigned long)first;
    unsigned long data_sz = (unsigned long)end - (unsigned long)start;

    if (data_sz == 0 || data_sz > MAX_FIPS_DATA_SZ)
        return BAD_FUNC_ARG;  /* bad fips data size */

    if (code_sz == 0 || code_sz > MAX_FIPS_CODE_SZ)
        return BAD_FUNC_ARG;  /* bad fips code size */

    hash = XMALLOC(WC_SHA256_DIGEST_SIZE, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash == NULL) {
        ret = MEMORY_E;
        goto out;
    }
    base16_hash = XMALLOC(WC_SHA256_DIGEST_SIZE*2 + 1, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (base16_hash == NULL) {
        ret = MEMORY_E;
        goto out;
    }
    binCoreKey = XMALLOC(binCoreSz, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (binCoreKey == NULL) {
        ret = MEMORY_E;
        goto out;
    }
    binVerify = XMALLOC(verifySz, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (binVerify == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    {
        word32 base16_out_len = binCoreSz;
        ret = Base16_Decode((const byte *)coreKey, sizeof coreKey - 1, binCoreKey, &base16_out_len);
        if (ret != 0) {
            pr_err("Base16_Decode for coreKey: %s\n", wc_GetErrorString(ret));
            goto out;
        }
        if (base16_out_len != binCoreSz) {
            pr_err("unexpected output length %u for coreKey from Base16_Decode.\n",base16_out_len);
            ret = BAD_STATE_E;
            goto out;
        }
    }

    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm)) {
        if (PTR_ERR(tfm) == -ENOMEM) {
            pr_err("crypto_alloc_shash failed: out of memory\n");
            ret = MEMORY_E;
        } else if (PTR_ERR(tfm) == -ENOENT) {
            pr_err("crypto_alloc_shash failed: kernel is missing hmac(sha256) implementation\n");
            pr_err("check for CONFIG_CRYPTO_SHA256 and CONFIG_CRYPTO_HMAC.\n");
            ret = NOT_COMPILED_IN;
        } else {
            pr_err("crypto_alloc_shash failed with ret %ld\n",PTR_ERR(tfm));
            ret = HASH_TYPE_E;
        }
        tfm = NULL;
        goto out;
    }

    {
        size_t desc_size = crypto_shash_descsize(tfm) + sizeof *desc;
        desc = XMALLOC(desc_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (desc == NULL) {
            pr_err("failed allocating desc.");
            ret = MEMORY_E;
            goto out;
        }
        XMEMSET(desc, 0, desc_size);
    }

    ret = crypto_shash_setkey(tfm, binCoreKey, binCoreSz);
    if (ret) {
        pr_err("crypto_ahash_setkey failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret) {
        pr_err("crypto_shash_init failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    ret = crypto_shash_update(desc, (byte *)(wc_ptr_t)first, (word32)code_sz);
    if (ret) {
        pr_err("crypto_shash_update failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    /* don't hash verifyCore or changing verifyCore will change hash */
    if (verifyCore >= start && verifyCore < end) {
        data_sz = (unsigned long)verifyCore - (unsigned long)start;
        ret = crypto_shash_update(desc, (byte*)start, (word32)data_sz);
        if (ret) {
                pr_err("crypto_shash_update failed: err %d\n", ret);
                ret = BAD_STATE_E;
                goto out;
        }
        start   = (char*)verifyCore + sizeof(verifyCore);
        data_sz = (unsigned long)end - (unsigned long)start;
    }
    ret = crypto_shash_update(desc, (byte*)start, (word32)data_sz);
    if (ret) {
        pr_err("crypto_shash_update failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    ret = crypto_shash_final(desc, hash);
    if (ret) {
        pr_err("crypto_shash_final failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    ret = GenBase16_Hash(hash, WC_SHA256_DIGEST_SIZE, base16_hash, WC_SHA256_DIGEST_SIZE*2 + 1);
    if (ret != 0) {
        pr_err("GenBase16_Hash failed: %s\n", wc_GetErrorString(ret));
        goto out;
    }

    {
        word32 base16_out_len = verifySz;
        ret = Base16_Decode((const byte *)verifyCore, sizeof verifyCore - 1, binVerify, &base16_out_len);
        if (ret != 0) {
            pr_err("Base16_Decode for verifyCore: %s\n", wc_GetErrorString(ret));
            goto out;
        }
        if (base16_out_len != binCoreSz) {
            pr_err("unexpected output length %u for verifyCore from Base16_Decode.\n",base16_out_len);
            ret = BAD_STATE_E;
            goto out;
        }
    }

    if (XMEMCMP(hash, binVerify, WC_SHA256_DIGEST_SIZE) == 0)
        pr_info("updateFipsHash: verifyCore already matches.\n");
    else {
        XMEMCPY(verifyCore, base16_hash, WC_SHA256_DIGEST_SIZE*2 + 1);
        pr_info("updateFipsHash: verifyCore updated.\n");
    }

    ret = 0;

  out:

    if (tfm != NULL)
        crypto_free_shash(tfm);
    if (desc != NULL)
        XFREE(desc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash != NULL)
        XFREE(hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (base16_hash != NULL)
        XFREE(base16_hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (binCoreKey != NULL)
        XFREE(binCoreKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (binVerify != NULL)
        XFREE(binVerify, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif /* WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE */


#if defined(LINUXKM_REGISTER_ALG) && !defined(NO_AES)
#include <linux/crypto.h>

PRAGMA_GCC_DIAG_PUSH;
PRAGMA_GCC("GCC diagnostic ignored \"-Wnested-externs\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wpointer-arith\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wpointer-sign\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wbad-function-cast\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wunused-parameter\"");
#include <linux/scatterlist.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
PRAGMA_GCC_DIAG_POP;

/* km_AesX(): wrappers to wolfcrypt wc_AesX functions and
 * structures.  */

struct km_AesCtx {
    Aes          aes;
    u8           key[AES_MAX_KEY_SIZE / 8];
    unsigned int keylen;
};

static inline void km_ForceZero(struct km_AesCtx * ctx)
{
    memzero_explicit(ctx->key, sizeof(ctx->key));
    ctx->keylen = 0;
}

static int km_AesInitCommon(struct km_AesCtx * ctx, const char * name)
{
    int err = wc_AesInit(&ctx->aes, NULL, INVALID_DEVID);

    if (unlikely(err)) {
        pr_err("error: km_AesInitCommon %s failed: %d\n", name, err);
        return err;
    }

    return 0;
}

static void km_AesExitCommon(struct km_AesCtx * ctx)
{
    wc_AesFree(&ctx->aes);
    km_ForceZero(ctx);
}

static int km_AesSetKeyCommon(struct km_AesCtx * ctx, const u8 *in_key,
                              unsigned int key_len, const char * name)
{
    int err = wc_AesSetKey(&ctx->aes, in_key, key_len, NULL, 0);

    if (unlikely(err)) {
        pr_err("error: km_AesSetKeyCommon %s failed: %d\n", name, err);
        return err;
    }

    XMEMCPY(ctx->key, in_key, key_len);
    ctx->keylen = key_len;

    return 0;
}

static int km_AesInit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_CBC_DRIVER);
}

static void km_AesExit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    km_AesExitCommon(ctx);
}

static int km_AesSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_CBC_DRIVER);
}

#if defined(HAVE_AES_CBC)
static int km_AesCbcEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_ENCRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed: %d\n", err);
            return err;
        }

        err = wc_AesCbcEncrypt(&ctx->aes, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes);

        if (unlikely(err)) {
            pr_err("wc_AesCbcEncrypt failed %d\n", err);
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    return err;
}

static int km_AesCbcDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_DECRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed");
            return err;
        }

        err = wc_AesCbcDecrypt(&ctx->aes, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes);

        if (unlikely(err)) {
            pr_err("wc_AesCbcDecrypt failed");
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    return err;
}
#endif /* endif HAVE_AES_CBC */

#if defined(WOLFSSL_AES_CFB)
static int km_AesCfbEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_ENCRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed: %d\n", err);
            return err;
        }

        err = wc_AesCfbEncrypt(&ctx->aes, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes);

        if (unlikely(err)) {
            pr_err("wc_AesCfbEncrypt failed %d\n", err);
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    return err;
}

static int km_AesCfbDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_ENCRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed");
            return err;
        }

        err = wc_AesCfbDecrypt(&ctx->aes, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes);

        if (unlikely(err)) {
            pr_err("wc_AesCfbDecrypt failed");
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    return err;
}
#endif /* endif WOLFSSL_AES_CFB */


#if defined(HAVE_AESGCM)
static int km_AesGcmInit(struct crypto_aead * tfm)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    km_ForceZero(ctx);
    return km_AesInitCommon(ctx, WOLFKM_GCM_DRIVER);
}

static void km_AesGcmExit(struct crypto_aead * tfm)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    km_AesExitCommon(ctx);
}

static int km_AesGcmSetKey(struct crypto_aead *tfm, const u8 *in_key,
                           unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_GCM_DRIVER);
}

static int km_AesGcmSetAuthsize(struct crypto_aead *tfm, unsigned int authsize)
{
    (void)tfm;
    if (authsize > AES_BLOCK_SIZE ||
        authsize < WOLFSSL_MIN_AUTH_TAG_SZ) {
        pr_err("error: invalid authsize: %d\n", authsize);
        return -EINVAL;
    }
    return 0;
}

/*
 * aead ciphers recieve data in scatterlists in following order:
 *   encrypt
 *     req->src: aad||plaintext
 *     req->dst: aad||ciphertext||tag
 *   decrypt
 *     req->src: aad||ciphertext||tag
 *     req->dst: aad||plaintext, return 0 or -EBADMSG
 */

static int km_AesGcmEncrypt(struct aead_request *req)
{
    struct crypto_aead * tfm = NULL;
    struct km_AesCtx *   ctx = NULL;
    struct skcipher_walk walk;
    struct scatter_walk  assocSgWalk;
    unsigned int         nbytes = 0;
    u8                   authTag[AES_BLOCK_SIZE];
    int                  err = 0;
    unsigned int         assocLeft = 0;
    unsigned int         cryptLeft = 0;
    u8 *                 assoc = NULL;

    tfm = crypto_aead_reqtfm(req);
    ctx = crypto_aead_ctx(tfm);
    assocLeft = req->assoclen;
    cryptLeft = req->cryptlen;

    scatterwalk_start(&assocSgWalk, req->src);

    err = skcipher_walk_aead_encrypt(&walk, req, false);
    if (unlikely(err)) {
        pr_err("error: skcipher_walk_aead_encrypt: %d\n", err);
        return -1;
    }

    err = wc_AesGcmInit(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                        AES_BLOCK_SIZE);
    if (unlikely(err)) {
        pr_err("error: wc_AesGcmInit failed with return code %d.\n", err);
        return err;
    }

    assoc = scatterwalk_map(&assocSgWalk);
    if (unlikely(IS_ERR(assoc))) {
        pr_err("error: scatterwalk_map failed %ld\n", PTR_ERR(assoc));
        return err;
    }

    err = wc_AesGcmEncryptUpdate(&ctx->aes, NULL, NULL, 0, assoc, assocLeft);
    assocLeft -= assocLeft;
    scatterwalk_unmap(assoc);
    assoc = NULL;

    if (unlikely(err)) {
        pr_err("error: wc_AesGcmEncryptUpdate failed %d\n", err);
        return err;
    }

    while ((nbytes = walk.nbytes)) {
        int n = nbytes;

        if (likely(cryptLeft && nbytes)) {
            n = cryptLeft < nbytes ? cryptLeft : nbytes;

            err = wc_AesGcmEncryptUpdate(&ctx->aes, walk.dst.virt.addr,
                                         walk.src.virt.addr, cryptLeft, NULL, 0);
            nbytes -= n;
            cryptLeft -= n;
        }

        if (unlikely(err)) {
            pr_err("wc_AesGcmEncryptUpdate failed %d\n", err);
            return err;
        }

        err = skcipher_walk_done(&walk, nbytes);
    }

    err = wc_AesGcmEncryptFinal(&ctx->aes, authTag, tfm->authsize);
    if (unlikely(err)) {
        pr_err("error: wc_AesGcmEncryptFinal failed with return code %d\n", err);
        return err;
    }

    /* Now copy the auth tag into request scatterlist. */
    scatterwalk_map_and_copy(authTag, req->dst,
                             req->assoclen + req->cryptlen,
                             tfm->authsize, 1);

    return err;
}

static int km_AesGcmDecrypt(struct aead_request *req)
{
    struct crypto_aead * tfm = NULL;
    struct km_AesCtx *   ctx = NULL;
    struct skcipher_walk walk;
    struct scatter_walk  assocSgWalk;
    unsigned int         nbytes = 0;
    u8                   origAuthTag[AES_BLOCK_SIZE];
    int                  err = 0;
    unsigned int         assocLeft = 0;
    unsigned int         cryptLeft = 0;
    u8 *                 assoc = NULL;

    tfm = crypto_aead_reqtfm(req);
    ctx = crypto_aead_ctx(tfm);
    assocLeft = req->assoclen;
    cryptLeft = req->cryptlen - tfm->authsize;

    /* Copy out original auth tag from req->src. */
    scatterwalk_map_and_copy(origAuthTag, req->src,
                             req->assoclen + req->cryptlen - tfm->authsize,
                             tfm->authsize, 0);

    scatterwalk_start(&assocSgWalk, req->src);

    err = skcipher_walk_aead_decrypt(&walk, req, false);
    if (unlikely(err)) {
        pr_err("error: skcipher_walk_aead_decrypt: %d\n", err);
        return -1;
    }

    err = wc_AesGcmInit(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                        AES_BLOCK_SIZE);
    if (unlikely(err)) {
        pr_err("error: wc_AesGcmInit failed with return code %d.\n", err);
        return err;
    }

    assoc = scatterwalk_map(&assocSgWalk);
    if (unlikely(IS_ERR(assoc))) {
        pr_err("error: scatterwalk_map failed %ld\n", PTR_ERR(assoc));
        return err;
    }

    err = wc_AesGcmDecryptUpdate(&ctx->aes, NULL, NULL, 0, assoc, assocLeft);
    assocLeft -= assocLeft;
    scatterwalk_unmap(assoc);
    assoc = NULL;

    if (unlikely(err)) {
        pr_err("error: wc_AesGcmDecryptUpdate failed %d\n", err);
        return err;
    }

    while ((nbytes = walk.nbytes)) {
        int n = nbytes;

        if (likely(cryptLeft && nbytes)) {
            n = cryptLeft < nbytes ? cryptLeft : nbytes;

            err = wc_AesGcmDecryptUpdate(&ctx->aes, walk.dst.virt.addr,
                                         walk.src.virt.addr, cryptLeft, NULL, 0);
            nbytes -= n;
            cryptLeft -= n;
        }

        if (unlikely(err)) {
            pr_err("wc_AesGcmDecryptUpdate failed %d\n", err);
            return err;
        }

        err = skcipher_walk_done(&walk, nbytes);
    }

    err = wc_AesGcmDecryptFinal(&ctx->aes, origAuthTag, tfm->authsize);
    if (unlikely(err)) {
        pr_err("error: wc_AesGcmDecryptFinal failed with return code %d\n", err);

        if (err == AES_GCM_AUTH_E) {
            return -EBADMSG;
        }
        else {
            return err;
        }
    }

    return err;
}
#endif /* endif HAVE_AESGCM */

#if defined(HAVE_AES_CBC)
static struct skcipher_alg cbcAesAlg = {
    .base.cra_name        = WOLFKM_CBC_NAME,
    .base.cra_driver_name = WOLFKM_CBC_DRIVER,
    .base.cra_priority    = WOLFKM_ALG_PRIORITY,
    .base.cra_blocksize   = AES_BLOCK_SIZE,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesInit,
    .exit                 = km_AesExit,
    .min_keysize          = (128 / 8),
    .max_keysize          = (AES_MAX_KEY_SIZE / 8),
    .ivsize               = AES_BLOCK_SIZE,
    .setkey               = km_AesSetKey,
    .encrypt              = km_AesCbcEncrypt,
    .decrypt              = km_AesCbcDecrypt,
};
#endif

#if defined(WOLFSSL_AES_CFB)
static struct skcipher_alg cfbAesAlg = {
    .base.cra_name        = WOLFKM_CFB_NAME,
    .base.cra_driver_name = WOLFKM_CFB_DRIVER,
    .base.cra_priority    = WOLFKM_ALG_PRIORITY,
    .base.cra_blocksize   = AES_BLOCK_SIZE,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesInit,
    .exit                 = km_AesExit,
    .min_keysize          = (128 / 8),
    .max_keysize          = (AES_MAX_KEY_SIZE / 8),
    .ivsize               = AES_BLOCK_SIZE,
    .setkey               = km_AesSetKey,
    .encrypt              = km_AesCfbEncrypt,
    .decrypt              = km_AesCfbDecrypt,
};
#endif

#if defined(HAVE_AESGCM)
static struct aead_alg gcmAesAead = {
    .base.cra_name        = WOLFKM_GCM_NAME,
    .base.cra_driver_name = WOLFKM_GCM_DRIVER,
    .base.cra_priority    = WOLFKM_ALG_PRIORITY,
    .base.cra_blocksize   = 1,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesGcmInit,
    .exit                 = km_AesGcmExit,
    .setkey               = km_AesGcmSetKey,
    .setauthsize          = km_AesGcmSetAuthsize,
    .encrypt              = km_AesGcmEncrypt,
    .decrypt              = km_AesGcmDecrypt,
    .ivsize               = AES_BLOCK_SIZE,
    .maxauthsize          = AES_BLOCK_SIZE,
    .chunksize            = AES_BLOCK_SIZE,
};
#endif

static int linuxkm_register_alg(void)
{
    int ret = 0;
#if defined(HAVE_AES_CBC)
    ret =  crypto_register_skcipher(&cbcAesAlg);

    if (ret) {
        pr_err("crypto_register_skcipher failed with return code %d.\n", ret);
        return ret;
    }
#endif

#if defined(WOLFSSL_AES_CFB)
    ret =  crypto_register_skcipher(&cfbAesAlg);

    if (ret) {
        pr_err("crypto_register_skcipher failed with return code %d.\n", ret);
        return ret;
    }
#endif

#if defined(HAVE_AESGCM)
    ret =  crypto_register_aead(&gcmAesAead);

    if (ret) {
        pr_err("crypto_register_aead failed with return code %d.\n", ret);
        return ret;
    }
#endif

    return 0;
}

static void linuxkm_unregister_alg(void)
{
#if defined(HAVE_AES_CBC)
    crypto_unregister_skcipher(&cbcAesAlg);
#endif
#if defined(WOLFSSL_AES_CFB)
    crypto_unregister_skcipher(&cfbAesAlg);
#endif
#if defined(HAVE_AESGCM)
    crypto_unregister_aead(&gcmAesAead);
#endif
}

/* Given registered wolfcrypt kernel crypto, sanity test against
 * direct wolfcrypt calls. */

static int linuxkm_test_alg(void)
{
    int ret = 0;

    ret = linuxkm_test_cbc();
    if (ret) { return ret; }

    ret = linuxkm_test_cfb();
    if (ret) { return ret; }

    ret = linuxkm_test_gcm();
    if (ret) { return ret; }

    return 0;
}

static int linuxkm_test_cbc(void)
{
    int     ret = 0;
#if defined(HAVE_AES_CBC)
    struct crypto_skcipher *  tfm = NULL;
    struct skcipher_request * req = NULL;
    struct scatterlist        src, dst;
    Aes     aes;
    byte    key32[] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte    vector[] = /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    byte    iv[]    = "1234567890abcdef";
    byte    enc[sizeof(vector)];
    byte    dec[sizeof(vector)];
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;

    XMEMSET(enc, 0, sizeof(enc));
    XMEMSET(dec, 0, sizeof(enc));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesSetKey(&aes, key32, AES_BLOCK_SIZE * 2, iv, AES_ENCRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d\n", ret);
        return -1;
    }

    ret = wc_AesCbcEncrypt(&aes, enc, vector, sizeof(vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCbcEncrypt failed with return code %d\n", ret);
        return -1;
    }

    /* Re init for decrypt and set flag. */
    wc_AesFree(&aes);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesSetKey(&aes, key32, AES_BLOCK_SIZE * 2, iv, AES_DECRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesCbcDecrypt(&aes, dec, enc, sizeof(vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCbcDecrypt failed with return code %d\n", ret);
        return -1;
    }

    ret = XMEMCMP(vector, dec, sizeof(vector));
    if (ret) {
        pr_err("error: vector and dec do not match: %d\n", ret);
        return -1;
    }

    /* now the kernel crypto part */
    enc2 = kmalloc(sizeof(vector), GFP_KERNEL);
    if (!enc2) {
        pr_err("error: kmalloc failed\n");
        goto test_cbc_end;
    }

    dec2 = kmalloc(sizeof(vector), GFP_KERNEL);
    if (!dec2) {
        pr_err("error: kmalloc failed\n");
        goto test_cbc_end;
    }

    memcpy(dec2, vector, sizeof(vector));

    tfm = crypto_alloc_skcipher(WOLFKM_CBC_DRIVER, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating AES skcipher algorithm %s failed: %ld\n",
               WOLFKM_CBC_DRIVER, PTR_ERR(tfm));
        goto test_cbc_end;
    }

    ret = crypto_skcipher_setkey(tfm, key32, AES_BLOCK_SIZE * 2);
    if (ret) {
        pr_err("error: crypto_skcipher_setkey returned: %d\n", ret);
        goto test_cbc_end;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating AES skcipher request %s failed\n",
               WOLFKM_CBC_DRIVER);
        goto test_cbc_end;
    }

    sg_init_one(&src, dec2, sizeof(vector));
    sg_init_one(&dst, enc2, sizeof(vector));

    skcipher_request_set_crypt(req, &src, &dst, sizeof(vector), iv);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_cbc_end;
    }

    ret = XMEMCMP(enc, enc2, sizeof(vector));
    if (ret) {
        pr_err("error: enc and enc2 do not match: %d\n", ret);
        goto test_cbc_end;
    }

    memset(dec2, 0, sizeof(vector));
    sg_init_one(&src, enc2, sizeof(vector));
    sg_init_one(&dst, dec2, sizeof(vector));

    skcipher_request_set_crypt(req, &src, &dst, sizeof(vector), iv);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_decrypt returned: %d\n", ret);
        goto test_cbc_end;
    }

    ret = XMEMCMP(dec, dec2, sizeof(vector));
    if (ret) {
        pr_err("error: dec and dec2 do not match: %d\n", ret);
        goto test_cbc_end;
    }

    pr_info("info: test driver %s: good\n", WOLFKM_CBC_DRIVER);

test_cbc_end:

    if (enc2) { kfree(enc2); enc2 = NULL; }
    if (dec2) { kfree(dec2); dec2 = NULL; }
    if (req) { skcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_skcipher(tfm); tfm = NULL; }

#endif /* if defined HAVE_AES_CBC */
    return ret;
}

static int linuxkm_test_cfb(void)
{
    int ret = 0;
#if defined(WOLFSSL_AES_CFB)
    struct crypto_skcipher *  tfm = NULL;
    struct skcipher_request * req = NULL;
    struct scatterlist        src, dst;
    Aes     aes;
    byte    key32[] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte    vector[] = /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    byte    iv[]    = "1234567890abcdef";
    byte    enc[sizeof(vector)];
    byte    dec[sizeof(vector)];
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;

    XMEMSET(enc, 0, sizeof(enc));
    XMEMSET(dec, 0, sizeof(enc));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesSetKey(&aes, key32, AES_BLOCK_SIZE * 2, iv, AES_ENCRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d\n", ret);
        return -1;
    }

    ret = wc_AesCfbEncrypt(&aes, enc, vector, sizeof(vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCfbEncrypt failed with return code %d\n", ret);
        return -1;
    }

    /* Re init for decrypt and set flag. */
    wc_AesFree(&aes);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesSetKey(&aes, key32, AES_BLOCK_SIZE * 2, iv, AES_ENCRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesCfbDecrypt(&aes, dec, enc, sizeof(vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCfbDecrypt failed with return code %d\n", ret);
        return -1;
    }

    ret = XMEMCMP(vector, dec, sizeof(vector));
    if (ret) {
        pr_err("error: vector and dec do not match: %d\n", ret);
        return -1;
    }

    /* now the kernel crypto part */
    enc2 = kmalloc(sizeof(vector), GFP_KERNEL);
    if (!enc2) {
        pr_err("error: kmalloc failed\n");
        goto test_cfb_end;
    }

    dec2 = kmalloc(sizeof(vector), GFP_KERNEL);
    if (!dec2) {
        pr_err("error: kmalloc failed\n");
        goto test_cfb_end;
    }

    memcpy(dec2, vector, sizeof(vector));

    tfm = crypto_alloc_skcipher(WOLFKM_CFB_DRIVER, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating AES skcipher algorithm %s failed: %ld\n",
               WOLFKM_CFB_DRIVER, PTR_ERR(tfm));
        goto test_cfb_end;
    }

    ret = crypto_skcipher_setkey(tfm, key32, AES_BLOCK_SIZE * 2);
    if (ret) {
        pr_err("error: crypto_skcipher_setkey returned: %d\n", ret);
        goto test_cfb_end;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating AES skcipher request %s failed\n",
               WOLFKM_CFB_DRIVER);
        goto test_cfb_end;
    }

    sg_init_one(&src, dec2, sizeof(vector));
    sg_init_one(&dst, enc2, sizeof(vector));

    skcipher_request_set_crypt(req, &src, &dst, sizeof(vector), iv);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_cfb_end;
    }

    ret = XMEMCMP(enc, enc2, sizeof(vector));
    if (ret) {
        pr_err("error: enc and enc2 do not match: %d\n", ret);
        goto test_cfb_end;
    }

    memset(dec2, 0, sizeof(vector));
    sg_init_one(&src, enc2, sizeof(vector));
    sg_init_one(&dst, dec2, sizeof(vector));

    skcipher_request_set_crypt(req, &src, &dst, sizeof(vector), iv);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_decrypt returned: %d\n", ret);
        goto test_cfb_end;
    }

    ret = XMEMCMP(dec, dec2, sizeof(vector));
    if (ret) {
        pr_err("error: dec and dec2 do not match: %d\n", ret);
        goto test_cfb_end;
    }

    pr_info("info: test driver %s: good\n", WOLFKM_CFB_DRIVER);

test_cfb_end:

    if (enc2) { kfree(enc2); enc2 = NULL; }
    if (dec2) { kfree(dec2); dec2 = NULL; }
    if (req) { skcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_skcipher(tfm); tfm = NULL; }
#endif /* if defined WOLFSSL_AES_CFB */

    return ret;
}

static int linuxkm_test_gcm(void)
{
    int     ret = 0;
#if defined(HAVE_AESGCM)
    struct crypto_aead *  tfm = NULL;
    struct aead_request * req = NULL;
    struct scatterlist *  src = NULL;
    struct scatterlist *  dst = NULL;
    Aes     aes;
    byte    key32[] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte    vector[] = /* Now is the time for all w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    const byte assoc[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    byte    ivstr[] = "1234567890abcdef";
    byte    enc[sizeof(vector)];
    byte    authTag[AES_BLOCK_SIZE];
    byte    dec[sizeof(vector)];
    u8 *    assoc2 = NULL;
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;
    u8 *    iv = NULL;
    size_t  encryptLen = sizeof(vector);
    size_t  decryptLen = sizeof(vector) + sizeof(authTag);

    /* Init stack variables. */
    XMEMSET(enc, 0, sizeof(vector));
    XMEMSET(dec, 0, sizeof(vector));
    XMEMSET(authTag, 0, AES_BLOCK_SIZE);

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("error: wc_AesInit failed with return code %d.\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmInit(&aes, key32, sizeof(key32)/sizeof(byte), ivstr,
                        AES_BLOCK_SIZE);
    if (ret) {
        pr_err("error: wc_AesGcmInit failed with return code %d.\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmEncryptUpdate(&aes, NULL, NULL, 0, assoc, sizeof(assoc));
    if (ret) {
        pr_err("error: wc_AesGcmEncryptUpdate failed with return code %d\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmEncryptUpdate(&aes, enc, vector, sizeof(vector), NULL, 0);
    if (ret) {
        pr_err("error: wc_AesGcmEncryptUpdate failed with return code %d\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmEncryptFinal(&aes, authTag, AES_BLOCK_SIZE);
    if (ret) {
        pr_err("error: wc_AesGcmEncryptFinal failed with return code %d\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmInit(&aes, key32, sizeof(key32)/sizeof(byte), ivstr,
                        AES_BLOCK_SIZE);
    if (ret) {
        pr_err("error: wc_AesGcmInit failed with return code %d.\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmDecryptUpdate(&aes, dec, enc, sizeof(vector), assoc, sizeof(assoc));
    if (ret) {
        pr_err("error: wc_AesGcmDecryptUpdate failed with return code %d\n", ret);
        goto test_gcm_end;
    }

    ret = wc_AesGcmDecryptFinal(&aes, authTag, AES_BLOCK_SIZE);
    if (ret) {
        pr_err("error: wc_AesGcmEncryptFinal failed with return code %d\n", ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(vector, dec, sizeof(vector));
    if (ret) {
        pr_err("error: gcm: vector and dec do not match: %d\n", ret);
        goto test_gcm_end;
    }

    /* now the kernel crypto part */
    assoc2 = kmalloc(sizeof(assoc), GFP_KERNEL);
    if (IS_ERR(assoc2)) {
        pr_err("error: kmalloc failed\n");
        goto test_gcm_end;
    }
    memset(assoc2, 0, sizeof(assoc));
    memcpy(assoc2, assoc, sizeof(assoc));

    iv = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
    if (IS_ERR(iv)) {
        pr_err("error: kmalloc failed\n");
        goto test_gcm_end;
    }
    memset(iv, 0, AES_BLOCK_SIZE);
    memcpy(iv, ivstr, AES_BLOCK_SIZE);

    enc2 = kmalloc(decryptLen, GFP_KERNEL);
    if (IS_ERR(enc2)) {
        pr_err("error: kmalloc failed\n");
        goto test_gcm_end;
    }

    dec2 = kmalloc(decryptLen, GFP_KERNEL);
    if (IS_ERR(dec2)) {
        pr_err("error: kmalloc failed\n");
        goto test_gcm_end;
    }

    memset(enc2, 0, decryptLen);
    memset(dec2, 0, decryptLen);
    memcpy(dec2, vector, sizeof(vector));

    tfm = crypto_alloc_aead(WOLFKM_GCM_DRIVER, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("error: allocating AES skcipher algorithm %s failed: %ld\n",
               WOLFKM_GCM_DRIVER, PTR_ERR(tfm));
        goto test_gcm_end;
    }

    ret = crypto_aead_setkey(tfm, key32, AES_BLOCK_SIZE * 2);
    if (ret) {
        pr_err("error: crypto_aead_setkey returned: %d\n", ret);
        goto test_gcm_end;
    }

    ret = crypto_aead_setauthsize(tfm, sizeof(authTag));
    if (ret) {
        pr_err("error: crypto_aead_setauthsize returned: %d\n", ret);
        goto test_gcm_end;
    }

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (IS_ERR(req)) {
        pr_err("error: allocating AES aead request %s failed: %ld\n",
               WOLFKM_CBC_DRIVER, PTR_ERR(req));
        goto test_gcm_end;
    }

    src = kmalloc(sizeof(struct scatterlist) * 2, GFP_KERNEL);
    dst = kmalloc(sizeof(struct scatterlist) * 2, GFP_KERNEL);

    if (IS_ERR(src) || IS_ERR(dst)) {
        pr_err("error: kmalloc src or dst failed: %ld, %ld\n",
               PTR_ERR(src), PTR_ERR(dst));
        goto test_gcm_end;
    }

    sg_init_table(src, 2);
    sg_set_buf(src, assoc2, sizeof(assoc));
    sg_set_buf(&src[1], dec2, sizeof(vector));

    sg_init_table(dst, 2);
    sg_set_buf(dst, assoc2, sizeof(assoc));
    sg_set_buf(&dst[1], enc2, decryptLen);

    aead_request_set_callback(req, 0, NULL, NULL);
    aead_request_set_ad(req, sizeof(assoc));
    aead_request_set_crypt(req, src, dst, sizeof(vector), iv);

    ret = crypto_aead_encrypt(req);

    if (ret) {
        pr_err("error: crypto_aead_encrypt returned: %d\n", ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(enc, enc2, sizeof(vector));
    if (ret) {
        pr_err("error: enc and enc2 do not match: %d\n", ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(authTag, enc2 + encryptLen, sizeof(authTag));
    if (ret) {
        pr_err("error: authTags do not match: %d\n", ret);
        goto test_gcm_end;
    }

    /* Now decrypt crypto request. Reverse src and dst. */
    memset(dec2, 0, decryptLen);
    aead_request_set_ad(req, sizeof(assoc));
    aead_request_set_crypt(req, dst, src, decryptLen, iv);

    ret = crypto_aead_decrypt(req);

    if (ret) {
        pr_err("error: crypto_aead_decrypt returned: %d\n", ret);
        goto test_gcm_end;
    }

    ret = XMEMCMP(dec, dec2, sizeof(vector));
    if (ret) {
        pr_err("error: dec and dec2 do not match: %d\n", ret);
        goto test_gcm_end;
    }

    pr_info("info: test driver %s: good\n", WOLFKM_GCM_DRIVER);

test_gcm_end:
    if (req) { aead_request_free(req); req = NULL; }
    if (tfm) { crypto_free_aead(tfm); tfm = NULL; }

    if (src) { kfree(src); src = NULL; }
    if (dst) { kfree(dst); dst = NULL; }

    if (dec2) { kfree(dec2); dec2 = NULL; }
    if (enc2) { kfree(enc2); enc2 = NULL; }

    if (assoc2) { kfree(assoc2); assoc2 = NULL; }
    if (iv) { kfree(iv); iv = NULL; }
#endif /* if defined HAVE_AESGCM */

    return 0;
}

#endif /* LINUXKM_REGISTER_ALG && !defined(NO_AES) */
