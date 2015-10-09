/* Configuration */
#define IPHONE	/* Needed for Xcode */
#define HAVE_HASHDRBG
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384

#ifdef HAVE_FIPS
#define NO_MD4
#define NO_HC128
#define NO_RABBIT
#define NO_DSA
#define NO_PWDBASED
#else
#define USE_FAST_MATH
#endif
