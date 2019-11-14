#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define HAVE_ECC
#define FP_ECC

#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT
#ifdef HAVE_ECC
	#define ECC_TIMING_RESISTANT
#endif
#ifndef NO_RSA
	#define WC_RSA_BLINDING
#endif

#if 1
	#define WOLFSSL_HAVE_SP_RSA
	#define WOLFSSL_HAVE_SP_ECC
	#if 1
		#define WOLFSSL_SP_ARM64_ASM
	#endif
#endif

/* Tracking memory usage */
#if 0
	#define WOLFSSL_TRACK_MEMORY
	#define HAVE_STACK_SIZE
	#define WOLFSSL_DEBUG_MEMORY
	#define WOLFSSL_DEBUG_MEMORY_PRINT
#endif

#endif
