/* asn1.h for openssl */

#ifndef WOLFSSL_ASN1_H_
#define WOLFSSL_ASN1_H_

# include <limits.h>

struct WOLFSSL_ASN1_BIT_STRING {
    int length;
    int type;
    char* data;
    long flags;
};

struct WOLFSSL_ASN1_STRING {
    int length;
    int type;
    char* data;
    long flags;
};

WOLFSSL_API long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER* i);
WOLFSSL_API int wolfSSL_ASN1_INTEGER_get_int64(signed_word64 *p,
                                          const WOLFSSL_ASN1_INTEGER *i);

#define ASN1_INTEGER WOLFSSL_ASN1_INTEGER
#define int64_t signed_word64
#define uint64_t word64

#define ASN1_INTEGER_get wolfSSL_ASN1_INTEGER_get
#define ASN1_INTEGER_get_int64 wolfSSL_ASN1_INTEGER_get_int64

# define WOLFSSL_V_ASN1_NEG                      0x100
# define WOLFSSL_V_ASN1_NEG_INTEGER              (2 | WOLFSSL_V_ASN1_NEG)
# define WOLFSSL_V_ASN1_INTEGER                  2

# ifndef INT64_MAX

#  define INT64_MIN -9223372036854775808LL
#  define INT64_MAX 9223372036854775807LL
#  define UINT64_MAX 18446744073709551615ULL

# endif

# define WOLFSSL_INT64_MAX       INT64_MAX
# define WOLFSSL_ABS_INT64_MIN ((uint64_t)INT64_MAX + (uint64_t)(-(INT64_MIN + INT64_MAX)))

#endif /* WOLFSSL_ASN1_H_ */
