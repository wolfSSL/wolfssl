#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFSSL_GENERAL_ALIGNMENT 8
#define SINGLE_THREADED
#define WOLFSSL_USER_IO
#define WOLFSSL_NO_SOCK
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_WOLFSSL_DIR
#define WC_NO_HARDEN
#define WOLFSSL_NO_ASM
#define CUSTOM_RAND_GENERATE_BLOCK custom_rand_generate_block

/* Native Falcon (full: keygen + sign + verify), experimental. Signing/keygen
 * run over the inline-double fpr backend with the AArch64 NEON FFT. */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define HAVE_FALCON
#define WOLFSSL_FALCON_FPR_DOUBLE
#define WOLFSSL_FALCON_FFT_NEON
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256

/* Trim. */
#define NO_AES
#define NO_DES3
#define NO_DH
#define NO_DSA
#define NO_ERROR_STRINGS
#define NO_MD4
#define NO_MD5
#define NO_OLD_TLS
#define NO_PSK
#define NO_PWDBASED
#define NO_RC4
#define NO_RSA
#define NO_SHA
#define NO_SIG_WRAPPER

int custom_rand_generate_block(unsigned char* output, unsigned int sz);

#endif /* WOLFSSL_USER_SETTINGS_H */
