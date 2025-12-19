/* user_settings_renode.h - wolfSSL/wolfCrypt configuration for STM32H753 under Renode
 *
 * Minimal, semihosting-friendly build for Cortex-M7 / STM32H753.
 * Hardware RNG and CRYPTO (AES-GCM only) are enabled via Renode's STM32H753 emulation.
 * HASH is disabled as Renode doesn't implement the HASH peripheral.
 */

#ifndef USER_SETTINGS_RENODE_H
#define USER_SETTINGS_RENODE_H

/* -------------------------  Platform  ------------------------------------- */
#define WOLFSSL_ARM_CORTEX_M
#define WOLFSSL_STM32H7  /* STM32H7 series (includes H753) */
#define WOLFSSL_STM32_CUBEMX  /* Use STM32 HAL for CRYPTO */
/* NO_STM32_CRYPTO is NOT defined, so CRYPTO will be enabled */
/* Disable HASH - Renode doesn't implement HASH peripheral */
#define NO_STM32_HASH

/* Required for consistent math library settings (CTC_SETTINGS) */
#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8

/* -------------------------  Threading / OS  ------------------------------- */
#define SINGLE_THREADED

/* -------------------------  Filesystem / I/O  ----------------------------- */
#define WOLFSSL_NO_CURRDIR
#define NO_FILESYSTEM
#define NO_WRITEV

/* -------------------------  wolfCrypt Only  ------------------------------- */
#define WOLFCRYPT_ONLY
#define NO_DH
#define NO_DSA
/* Disable DES/3DES - Renode CRYPTO only supports AES_GCM */
#define NO_DES
#define NO_DES3

/* -------------------------  AES Mode Configuration  ----------------------- */
/* Disable all AES modes except GCM - Renode CRYPTO only supports AES_GCM */
/* NO_AES_CBC prevents HAVE_AES_CBC from being defined in settings.h */
#define NO_AES_CBC

/* -------------------------  RNG Configuration  ---------------------------- */
/* Enable STM32 hardware RNG (emulated by Renode) using direct register access */
#define WOLFSSL_STM32_RNG_NOLIB
/* NO_STM32_RNG is NOT defined, so STM32_RNG will be auto-enabled */
#define NO_DEV_RANDOM
#define HAVE_HASHDRBG

/* -------------------------  Math Library  --------------------------------- */
/* Use SP Math (Single Precision) - modern, efficient, and secure */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define SP_WORD_SIZE 32

/* -------------------------  Crypto Hardening  ----------------------------- */
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT

/* -------------------------  Size Optimization  ---------------------------- */
#define WOLFSSL_SMALL_STACK

/* -------------------------  Test Configuration  --------------------------- */
/* Use smaller key sizes for faster test runs in emulation */
#define BENCH_EMBEDDED

/* Use our own main() instead of the one in test.c */
#define NO_MAIN_DRIVER

/* -------------------------  Post-options.h cleanup  ----------------------- */
/* Ensure unsupported AES modes stay disabled even after options.h processing */
/* These undefs will be processed after options.h includes, preventing
 * Renode-unsupported modes from being used */
#ifdef HAVE_AES_CBC
#undef HAVE_AES_CBC
#endif
#ifdef HAVE_AES_ECB
#undef HAVE_AES_ECB
#endif
#ifdef HAVE_AES_CTR
#undef HAVE_AES_CTR
#endif
#ifdef HAVE_AES_CFB
#undef HAVE_AES_CFB
#endif
#ifdef HAVE_AES_OFB
#undef HAVE_AES_OFB
#endif

#endif /* USER_SETTINGS_RENODE_H */

