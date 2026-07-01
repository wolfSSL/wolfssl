#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_ASM
#define WC_NO_HARDEN
#define CUSTOM_RAND_GENERATE_BLOCK custom_rand_generate_block

/* Native Falcon, verify-only (no sign/keygen), experimental. The verify path
 * needs SHA-3 / SHAKE256 for hash-to-point. The DSP NTT auto-enables on
 * Cortex-M33 (__ARM_FEATURE_DSP). */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define HAVE_FALCON
#define WOLFSSL_FALCON_VERIFY_ONLY
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256

/* Trim everything else. */
#define NO_AES
#define NO_DES3
#define NO_DH
#define NO_DSA
#define NO_ERROR_STRINGS
#define NO_HC128
#define NO_MD4
#define NO_MD5
#define NO_OLD_TLS
#define NO_PSK
#define NO_PWDBASED
#define NO_RABBIT
#define NO_RC4
#define NO_RSA
#define NO_SHA
#define NO_SIG_WRAPPER

int custom_rand_generate_block(unsigned char* output, unsigned int sz);

#endif /* WOLFSSL_USER_SETTINGS_H */
