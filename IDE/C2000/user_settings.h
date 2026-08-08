/* user_settings.h - minimal wolfCrypt config for the TI C2000 (C28x,
 * CHAR_BIT==16) compile-only CI guard.
 *
 * This is NOT a board config: it has no BSP/device dependencies.  Its only job
 * is to enable the wolfCrypt subset that carries the CHAR_BIT != 8 gated code
 * (SHA-1/2/3/SHAKE, ML-DSA-87 verify, ECDSA/ECDH P-256 via SP math, AES and its
 * modes, ChaCha20-Poly1305, X25519/Ed25519, X448/Ed448) so that
 * IDE/C2000/compile.sh can compile them with cl2000 and catch regressions.
 * cl2000 predefines __TMS320C28XX__, so types.h auto-enables WOLFSSL_WIDE_BYTE;
 * we do not set it here. */
#ifndef TI_C2000_CI_USER_SETTINGS_H
#define TI_C2000_CI_USER_SETTINGS_H

#define WOLFCRYPT_ONLY              /* crypto only - no TLS (no MD5/SHA1 dep) */
#define WOLFSSL_GENERAL_ALIGNMENT 2
#define HAVE_LIMITS_H
#define WOLFSSL_NO_ASM
#define NO_INLINE
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define WOLFSSL_IGNORE_FILE_WARN
#define BENCH_EMBEDDED
#define NO_WOLFSSL_MEMORY
#define WOLFSSL_GENSEED_FORTEST     /* dev-only seed; no TRNG on this part */

/* Hashes (SHA-1 is on by default - NO_SHA is not set) */
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* AES + modes (block/key/keystream octet I/O and the XTS tweak carry) */
#define HAVE_AES_CBC
#define HAVE_AES_DECRYPT
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_OFB
#define HAVE_AESGCM
#define GCM_SMALL
#define HAVE_AESCCM
#define WOLFSSL_CMAC
#define WOLFSSL_AES_XTS
#define WOLFSSL_AES_SIV
#define WOLFSSL_AES_EAX
#define WOLFSSL_AES_DIRECT

/* ChaCha20-Poly1305 (chunk size, keystream and Poly1305 length octet I/O) */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* Curve25519/Ed25519 + Curve448/Ed448 (field serialization octet I/O).  448
 * uses the SMALL byte-array backend (no __uint128_t on this toolchain). */
#define HAVE_CURVE25519
#define HAVE_ED25519
#define HAVE_CURVE448
#define CURVE448_SMALL
#define HAVE_ED448
#define ED448_SMALL

/* ML-DSA-87 verify (smallest-mem streaming verifier) */
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_NO_ML_DSA_44
#define WOLFSSL_NO_ML_DSA_65
#define WOLFSSL_MLDSA_NO_ASN1
#define WOLFSSL_MLDSA_VERIFY_ONLY
#define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
#define WOLFSSL_MLDSA_VERIFY_NO_MALLOC
#define WOLFSSL_MLDSA_VERIFY_SMALLEST_MEM
#undef  WOLFSSL_MLDSA_ALIGNMENT
#define WOLFSSL_MLDSA_ALIGNMENT 16
#define WOLFSSL_SMALL_STACK

/* ECDSA / ECDH P-256 via SP single-precision math (sp_c32.c) */
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define HAVE_ECC_VERIFY
#define HAVE_ECC_SIGN
#define HAVE_ECC_DHE
#define ECC_TIMING_RESISTANT
#define WOLFSSL_SP_MATH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_NO_MALLOC
#define WOLFSSL_SP_SMALL
#define SP_WORD_SIZE 32
#define WOLFSSL_SP_ALLOW_16BIT_CPU

/* Off: big-int/ASN and legacy algorithms not part of the CHAR_BIT != 8 surface.
 * (RSA/DH are validated on hardware but their CHAR_BIT != 8 fixes live in
 * sp_int.c/sp_c32.c, already compiled here via ECC.) */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_ASN
#define NO_CERTS
#define NO_PWDBASED
#define NO_PKCS7
#define NO_PKCS12
#define NO_SIG_WRAPPER
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_ASN_TIME
#define WOLFSSL_USER_CURRTIME

#endif /* TI_C2000_CI_USER_SETTINGS_H */
