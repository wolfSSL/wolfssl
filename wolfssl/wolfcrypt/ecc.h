/* ecc.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

#ifndef WOLF_CRYPT_ECC_H
#define WOLF_CRYPT_ECC_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_ECC

#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_X963_KDF
    #include <wolfssl/wolfcrypt/hash.h>
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
    #ifdef WOLFSSL_CERT_GEN
        #include <wolfssl/wolfcrypt/asn.h>
    #endif
#endif

#ifdef WOLFSSL_ATECC508A
    #include <wolfssl/wolfcrypt/port/atmel/atmel.h>
#endif /* WOLFSSL_ATECC508A */


#ifdef __cplusplus
    extern "C" {
#endif


/* Enable curve B parameter if needed */
#if defined(HAVE_COMP_KEY) || defined(ECC_CACHE_CURVE)
    #ifndef USE_ECC_B_PARAM /* Allow someone to force enable */
        #define USE_ECC_B_PARAM
    #endif
#endif


/* Use this as the key->idx if a custom ecc_set is used for key->dp */
#define ECC_CUSTOM_IDX    (-1)


/* Determine max ECC bits based on enabled curves */
#if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
    #define MAX_ECC_BITS    521
#elif defined(HAVE_ECC512)
    #define MAX_ECC_BITS    512
#elif defined(HAVE_ECC384)
    #define MAX_ECC_BITS    384
#elif defined(HAVE_ECC320)
    #define MAX_ECC_BITS    320
#elif defined(HAVE_ECC239)
    #define MAX_ECC_BITS    239
#elif defined(HAVE_ECC224)
    #define MAX_ECC_BITS    224
#elif !defined(NO_ECC256)
    #define MAX_ECC_BITS    256
#elif defined(HAVE_ECC192)
    #define MAX_ECC_BITS    192
#elif defined(HAVE_ECC160)
    #define MAX_ECC_BITS    160
#elif defined(HAVE_ECC128)
    #define MAX_ECC_BITS    128
#elif defined(HAVE_ECC112)
    #define MAX_ECC_BITS    112
#endif

/* calculate max ECC bytes */
#if ((MAX_ECC_BITS * 2) % 8) == 0
    #define MAX_ECC_BYTES     (MAX_ECC_BITS / 8)
#else
    /* add byte if not aligned */
    #define MAX_ECC_BYTES     ((MAX_ECC_BITS / 8) + 1)
#endif


enum {
    ECC_PUBLICKEY       = 1,
    ECC_PRIVATEKEY      = 2,
    ECC_PRIVATEKEY_ONLY = 3,
    ECC_MAXNAME     = 16,   /* MAX CURVE NAME LENGTH */
    SIG_HEADER_SZ   =  6,   /* ECC signature header size */
    ECC_BUFSIZE     = 256,  /* for exported keys temp buffer */
    ECC_MINSIZE     = 20,   /* MIN Private Key size */
    ECC_MAXSIZE     = 66,   /* MAX Private Key size */
    ECC_MAXSIZE_GEN = 74,   /* MAX Buffer size required when generating ECC keys*/
    ECC_MAX_PAD_SZ  = 4,    /* ECC maximum padding size */
    ECC_MAX_OID_LEN = 16,
    ECC_MAX_SIG_SIZE= ((MAX_ECC_BYTES * 2) + ECC_MAX_PAD_SZ + SIG_HEADER_SZ)
};

/* Curve Types */
typedef enum ecc_curve_id {
    ECC_CURVE_INVALID = -1,
    ECC_CURVE_DEF = 0, /* NIST or SECP */

    /* NIST Prime Curves */
    ECC_SECP192R1,
    ECC_PRIME192V2,
    ECC_PRIME192V3,
    ECC_PRIME239V1,
    ECC_PRIME239V2,
    ECC_PRIME239V3,
    ECC_SECP256R1,

    /* SECP Curves */
    ECC_SECP112R1,
    ECC_SECP112R2,
    ECC_SECP128R1,
    ECC_SECP128R2,
    ECC_SECP160R1,
    ECC_SECP160R2,
    ECC_SECP224R1,
    ECC_SECP384R1,
    ECC_SECP521R1,

    /* Koblitz */
    ECC_SECP160K1,
    ECC_SECP192K1,
    ECC_SECP224K1,
    ECC_SECP256K1,

    /* Brainpool Curves */
    ECC_BRAINPOOLP160R1,
    ECC_BRAINPOOLP192R1,
    ECC_BRAINPOOLP224R1,
    ECC_BRAINPOOLP256R1,
    ECC_BRAINPOOLP320R1,
    ECC_BRAINPOOLP384R1,
    ECC_BRAINPOOLP512R1,

    /* Twisted Edwards Curves */
#ifdef HAVE_CURVE25519
    ECC_X25519,
#endif
#ifdef HAVE_X448
    ECC_X448,
#endif
} ecc_curve_id;

#ifdef HAVE_OID_ENCODING
typedef word16 ecc_oid_t;
#else
typedef byte   ecc_oid_t;
    /* OID encoded with ASN scheme:
        first element = (oid[0] * 40) + oid[1]
        if any element > 127 then MSB 0x80 indicates additional byte */
#endif

/* ECC set type defined a GF(p) curve */
typedef struct ecc_set_type {
    int size;             /* The size of the curve in octets */
    int id;               /* id of this curve */
    const char* name;     /* name of this curve */
    const char* prime;    /* prime that defines the field, curve is in (hex) */
    const char* Af;       /* fields A param (hex) */
    const char* Bf;       /* fields B param (hex) */
    const char* order;    /* order of the curve (hex) */
    const char* Gx;       /* x coordinate of the base point on curve (hex) */
    const char* Gy;       /* y coordinate of the base point on curve (hex) */
    const ecc_oid_t* oid;
    word32      oidSz;
    word32      oidSum;    /* sum of encoded OID bytes */
    int         cofactor;
} ecc_set_type;


#ifdef ALT_ECC_SIZE

/* Note on ALT_ECC_SIZE:
 * The fast math code uses an array of a fixed size to store the big integers.
 * By default, the array is big enough for RSA keys. There is a size,
 * FP_MAX_BITS which can be used to make the array smaller when one wants ECC
 * but not RSA. Some people want fast math sized for both RSA and ECC, where
 * ECC won't use as much as RSA. The flag ALT_ECC_SIZE switches in an alternate
 * ecc_point structure that uses an alternate fp_int that has a shorter array
 * of fp_digits.
 *
 * Now, without ALT_ECC_SIZE, the ecc_point has three single item arrays of
 * mp_ints for the components of the point. With ALT_ECC_SIZE, the components
 * of the point are pointers that are set to each of a three item array of
 * alt_fp_ints. While an mp_int will have 4096 bits of digit inside the
 * structure, the alt_fp_int will only have 528 bits. A size value was added
 * in the ALT case, as well, and is set by mp_init() and alt_fp_init(). The
 * functions fp_zero() and fp_copy() use the size parameter. An int needs to
 * be initialized before using it instead of just fp_zeroing it, the init will
 * call zero. FP_MAX_BITS_ECC defaults to 528, but can be set to change the
 * number of bits used in the alternate FP_INT.
 *
 * Do not enable ALT_ECC_SIZE and disable fast math in the configuration.
 */

#ifndef USE_FAST_MATH
    #error USE_FAST_MATH must be defined to use ALT_ECC_SIZE
#endif

/* determine max bits required for ECC math */
#ifndef FP_MAX_BITS_ECC
    /* check alignment */
    #if ((MAX_ECC_BITS * 2) % DIGIT_BIT) == 0
        /* max bits is double */
        #define FP_MAX_BITS_ECC     (MAX_ECC_BITS * 2)
    #else
        /* max bits is doubled, plus one digit of fudge */
        #define FP_MAX_BITS_ECC     ((MAX_ECC_BITS * 2) + DIGIT_BIT)
    #endif
#else
    /* verify alignment */
    #if FP_MAX_BITS_ECC % CHAR_BIT
       #error FP_MAX_BITS_ECC must be a multiple of CHAR_BIT
    #endif
#endif

/* determine buffer size */
#define FP_SIZE_ECC    (FP_MAX_BITS_ECC/DIGIT_BIT)


/* This needs to match the size of the fp_int struct, except the
 * fp_digit array will be shorter. */
typedef struct alt_fp_int {
    int used, sign, size;
    fp_digit dp[FP_SIZE_ECC];
} alt_fp_int;
#endif /* ALT_ECC_SIZE */


/* A point on an ECC curve, stored in Jacbobian format such that (x,y,z) =>
   (x/z^2, y/z^3, 1) when interpreted as affine */
typedef struct {
#ifndef ALT_ECC_SIZE
    mp_int x[1];        /* The x coordinate */
    mp_int y[1];        /* The y coordinate */
    mp_int z[1];        /* The z coordinate */
#else
    mp_int* x;        /* The x coordinate */
    mp_int* y;        /* The y coordinate */
    mp_int* z;        /* The z coordinate */
    alt_fp_int xyz[3];
#endif
} ecc_point;

/* ECC Flags */
enum {
    WC_ECC_FLAG_NONE = 0x00,
#ifdef HAVE_ECC_CDH
    WC_ECC_FLAG_COFACTOR = 0x01,
#endif
};

/* An ECC Key */
struct ecc_key {
    int type;           /* Public or Private */
    int idx;            /* Index into the ecc_sets[] for the parameters of
                           this curve if -1, this key is using user supplied
                           curve in dp */
    int    state;
    word32 flags;
    const ecc_set_type* dp;     /* domain parameters, either points to NIST
                                   curves (idx >= 0) or user supplied */
    void* heap;         /* heap hint */
#ifdef WOLFSSL_ATECC508A
    int  slot;        /* Key Slot Number (-1 unknown) */
    byte pubkey[PUB_KEY_SIZE];
#else
    ecc_point pubkey;   /* public key */
    mp_int    k;        /* private key */
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    mp_int* r;          /* sign/verify temps */
    mp_int* s;
    WC_ASYNC_DEV asyncDev;
    #ifdef WOLFSSL_CERT_GEN
        CertSignCtx certSignCtx; /* context info for cert sign (MakeSignature) */
    #endif
#endif /* WOLFSSL_ASYNC_CRYPT */
};

#ifndef WC_ECCKEY_TYPE_DEFINED
    typedef struct ecc_key ecc_key;
    #define WC_ECCKEY_TYPE_DEFINED
#endif


/* ECC predefined curve sets  */
extern const ecc_set_type ecc_sets[];

WOLFSSL_API
const char* wc_ecc_get_name(int curve_id);

#ifndef WOLFSSL_ATECC508A

#ifdef WOLFSSL_PUBLIC_ECC_ADD_DBL
    #define ECC_API    WOLFSSL_API
#else
    #define ECC_API    WOLFSSL_LOCAL
#endif

ECC_API int ecc_map(ecc_point*, mp_int*, mp_digit);
ECC_API int ecc_projective_add_point(ecc_point* P, ecc_point* Q, ecc_point* R,
                                     mp_int* a, mp_int* modulus, mp_digit mp);
ECC_API int ecc_projective_dbl_point(ecc_point* P, ecc_point* R, mp_int* a,
                                     mp_int* modulus, mp_digit mp);

#endif

/*!
    \ingroup ECC
    
    \brief This function generates a new ecc_key and stores it in key.
    
    \return 0 Returned on success.
    \return ECC_BAD_ARG_E Returned if rng or key evaluate to NULL
    \return BAD_FUNC_ARG Returned if the specified key size is not in the correct range of supported keys
    \return MEMORY_E Returned if there is an error allocating memory while computing the ecc key
    \return MP_INIT_E may be returned if there is an error while computing the ecc key
    \return MP_READ_E may be returned if there is an error while computing the ecc key
    \return MP_CMP_E may be returned if there is an error while computing the ecc key
    \return MP_INVMOD_E may be returned if there is an error while computing the ecc key
    \return MP_EXPTMOD_E may be returned if there is an error while computing the ecc key
    \return MP_MOD_E may be returned if there is an error while computing the ecc key
    \return MP_MUL_E may be returned if there is an error while computing the ecc key
    \return MP_ADD_E may be returned if there is an error while computing the ecc key
    \return MP_MULMOD_E may be returned if there is an error while computing the ecc key
    \return MP_TO_E may be returned if there is an error while computing the ecc key
    \return MP_MEM may be returned if there is an error while computing the ecc key
    
    \param rng pointer to an initialized RNG object with which to generate the key
    \param keysize desired length for the ecc_key
    \param key pointer to the ecc_key for which to generate a key

    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key); // initialize 32 byte ecc key
    \endcode
    
    \sa wc_ecc_init
    \sa wc_ecc_shared_secret
*/
WOLFSSL_API
int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key);
WOLFSSL_API
int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key,
    int curve_id);
/*!
    \ingroup ECC
    
    \brief Perform sanity checks on ecc key validity.
    
    \return MP_OKAY Success, key is OK.
    \return BAD_FUNC_ARG Returns if key is NULL.
    \return ECC_INF_E Returns if wc_ecc_point_is_at_infinity returns 1.
    
    \param key Pointer to key to check.
    
    _Example_
    \code
    ecc_key key;
    RNG rng;
    int check_result;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    check_result = wc_ecc_check_key(&key);

    if (check_result == MP_OKAY)
    {
        // key check succeeded
    }
    else
    {
        // key check failed
    }
    \endcode
    
    \sa wc_ecc_point_is_at_infinity
*/
WOLFSSL_API
int wc_ecc_make_pub(ecc_key* key, ecc_point* pubOut);
WOLFSSL_API
int wc_ecc_check_key(ecc_key* key);
WOLFSSL_API
int wc_ecc_is_point(ecc_point* ecp, mp_int* a, mp_int* b, mp_int* prime);

#ifdef HAVE_ECC_DHE
/*!
    \ingroup ECC
    
    \brief This function generates a new secret key using a local private key and a received public key. It stores this shared secret key in the buffer out and updates outlen to hold the number of bytes written to the output buffer.
    
    \return 0 Returned upon successfully generating a shared secret key
    \return BAD_FUNC_ARG Returned if any of the input parameters evaluate to NULL
    \return ECC_BAD_ARG_E Returned if the type of the private key given as argument, private_key, is not ECC_PRIVATEKEY, or if the public and private key types (given by ecc->dp) are not equivalent
    \return MEMORY_E Returned if there is an error generating a new ecc point
    \return BUFFER_E Returned if the generated shared secret key is too long to store in the provided buffer
    \return MP_INIT_E may be returned if there is an error while computing the shared key
    \return MP_READ_E may be returned if there is an error while computing the shared key
    \return MP_CMP_E may be returned if there is an error while computing the shared key
    \return MP_INVMOD_E may be returned if there is an error while computing the shared key
    \return MP_EXPTMOD_E may be returned if there is an error while computing the shared key
    \return MP_MOD_E may be returned if there is an error while computing the shared key
    \return MP_MUL_E may be returned if there is an error while computing the shared key
    \return MP_ADD_E may be returned if there is an error while computing the shared key
    \return MP_MULMOD_E may be returned if there is an error while computing the shared key
    \return MP_TO_E may be returned if there is an error while computing the shared key
    \return MP_MEM may be returned if there is an error while computing the shared key
    
    \param private_key pointer to the ecc_key structure containing the local private key
    \param public_key pointer to the ecc_key structure containing the received public key
    \param out pointer to an output buffer in which to store the generated shared secret key
    \param outlen pointer to the word32 object containing the length of the output buffer. Will be overwritten with the length written to the output buffer upon successfully generating a shared secret key

    _Example_
    \code
    ecc_key priv, pub;
    RNG rng;
    byte secret[1024]; // can hold 1024 byte shared secret key
    word32 secretSz = sizeof(secret);
    int ret;

    wc_InitRng(&rng); // initialize rng
    wc_ecc_init(&priv); // initialize key
    wc_ecc_make_key(&rng, 32, &priv); // make public/private key pair
    // receive public key, and initialise into pub
    ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretSz); // generate secret key
    if ( ret != 0 ) {
    	// error generating shared secret key
    }
    \endcode
    
    \sa wc_ecc_init
    \sa wc_ecc_make_key
*/
WOLFSSL_API
int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
                      word32* outlen);
WOLFSSL_LOCAL
int wc_ecc_shared_secret_gen(ecc_key* private_key, ecc_point* point,
                             byte* out, word32 *outlen);
/*!
    \ingroup ECC
    
    \brief Create an ECC shared secret between private key and public point.
    
    \return MP_OKAY Indicates success.
    \return BAD_FUNC_ARG Error returned when any arguments are null.
    \return ECC_BAD_ARG_E Error returned if private_key->type is not ECC_PRIVATEKEY or private_key->idx fails to validate.
    \return BUFFER_E Error when outlen is too small.
    \return MEMORY_E Error to create a new point.
    \return MP_VAL possible when an initialization failure occurs.
    \return MP_MEM possible when an initialization failure occurs.
    
    \param private_key The private ECC key.
    \param point The point to use (public key).
    \param out Output destination of the shared secret. Conforms to EC-DH from ANSI X9.63.
    \param outlen Input the max size and output the resulting size of the shared secret.

    _Example_
    \code
    ecc_key key;
    ecc_point* point;
    byte shared_secret[];
    int secret_size;
    int result;

    point = wc_ecc_new_point();

    result = wc_ecc_shared_secret_ssh(&key, point, &shared_secret, &secret_size);

    if (result != MP_OKAY)
    {
        // Handle error
    }
    \endcode
    
    \sa wc_ecc_verify_hash_ex
*/
WOLFSSL_API
int wc_ecc_shared_secret_ex(ecc_key* private_key, ecc_point* point,
                             byte* out, word32 *outlen);
#define wc_ecc_shared_secret_ssh wc_ecc_shared_secret_ex /* For backwards compat */
#endif /* HAVE_ECC_DHE */

#ifdef HAVE_ECC_SIGN
/*!
    \ingroup ECC
    
    \brief This function signs a message digest using an ecc_key object to guarantee authenticity.
    
    \return 0 Returned upon successfully generating a signature for the message digest
    \return BAD_FUNC_ARG Returned if any of the input parameters evaluate to NULL, or if the output buffer is too small to store the generated signature
    \return ECC_BAD_ARG_E Returned if the input key is not a private key, or if the ECC OID is invalid
    \return RNG_FAILURE_E Returned if the rng cannot successfully generate a satisfactory key
    \return MP_INIT_E may be returned if there is an error while computing the message signature
    \return MP_READ_E may be returned if there is an error while computing the message signature
    \return MP_CMP_E may be returned if there is an error while computing the message signature
    \return MP_INVMOD_E may be returned if there is an error while computing the message signature
    \return MP_EXPTMOD_E may be returned if there is an error while computing the message signature
    \return MP_MOD_E may be returned if there is an error while computing the message signature
    \return MP_MUL_E may be returned if there is an error while computing the message signature
    \return MP_ADD_E may be returned if there is an error while computing the message signature
    \return MP_MULMOD_E may be returned if there is an error while computing the message signature
    \return MP_TO_E may be returned if there is an error while computing the message signature
    \return MP_MEM may be returned if there is an error while computing the message signature

    \param in pointer to the buffer containing the message hash to sign
    \param inlen length of the message hash to sign
    \param out buffer in which to store the generated signature
    \param outlen max length of the output buffer. Will store the bytes written to out upon successfully generating a message signature
    \param key pointer to a private ECC key with which to generate the signature
    
    _Example_
    \code
    ecc_key key;
    RNG rng;
    int ret, sigSz;

    byte sig[512]; // will hold generated signature
    sigSz = sizeof(sig);
    byte digest[] = { // initialize with message hash };
    wc_InitRng(&rng); // initialize rng
    wc_ecc_init(&key); // initialize key
    wc_ecc_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sigSz, &key);
    if ( ret != 0 ) {
	    // error generating message signature
    }
    \endcode
    
    \sa wc_ecc_verify_hash
*/
WOLFSSL_API
int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
                     WC_RNG* rng, ecc_key* key);
/*!
    \ingroup ECC
    
    \brief Sign a message digest.
    
    \return MP_OKAY Returned upon successfully generating a signature for the message digest
    \return ECC_BAD_ARG_E Returned if the input key is not a private key, or if the ECC IDX is invalid, or if any of the input parameters evaluate to NULL, or if the output buffer is too small to store the generated signature
    \return RNG_FAILURE_E Returned if the rng cannot successfully generate a satisfactory key
    \return MP_INIT_E may be returned if there is an error while computing the message signature
    \return MP_READ_E may be returned if there is an error while computing the message signature
    \return MP_CMP_E may be returned if there is an error while computing the message signature
    \return MP_INVMOD_E may be returned if there is an error while computing the message signature
    \return MP_EXPTMOD_E may be returned if there is an error while computing the message signature
    \return MP_MOD_E may be returned if there is an error while computing the message signature
    \return MP_MUL_E may be returned if there is an error while computing the message signature
    \return MP_ADD_E may be returned if there is an error while computing the message signature
    \return MP_MULMOD_E may be returned if there is an error while computing the message signature
    \return MP_TO_E may be returned if there is an error while computing the message signature
    \return MP_MEM may be returned if there is an error while computing the message signature
    
    \param in The message digest to sign.
    \param inlen The length of the digest.
    \param rng Pointer to WC_RNG struct.
    \param key A private ECC key.
    \param r The destination for r component of the signature.
    \param s The destination for s component of the signature.

    _Example_
    \code
    ecc_key key;
    WC_RNG rng;
    int ret, sigSz;
    mp_int r; // destination for r component of signature.
    mp_int s; // destination for s component of signature.

    byte sig[512]; // will hold generated signature
    sigSz = sizeof(sig);
    byte digest[] = { /* initialize with message hash };
    wc_InitRng(&rng); // initialize rng
    wc_ecc_init(&key); // initialize key
    wc_ecc_make_key(&rng, 32, &key); // make public/private key pair
    ret = wc_ecc_sign_hash_ex(digest, sizeof(digest), &rng, &key, &r, &s);

    if ( ret != MP_OKAY ) {
    	// error generating message signature
    }
    \endcode
    
    \sa wc_ecc_verify_hash_ex
*/
WOLFSSL_API
int wc_ecc_sign_hash_ex(const byte* in, word32 inlen, WC_RNG* rng,
                        ecc_key* key, mp_int *r, mp_int *s);
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
/*!
    \ingroup ECC
    
    \brief This function verifies the ECC signature of a hash to ensure authenticity. It returns the answer through stat, with 1 corresponding to a valid signature, and 0 corresponding to an invalid signature.
    
    \return 0 Returned upon successfully performing the signature verification. Note: This does not mean that the signature is verified. The authenticity information is stored instead in stat
    \return BAD_FUNC_ARG Returned any of the input parameters evaluate to NULL
    \return MEMORY_E Returned if there is an error allocating memory
    \return MP_INIT_E  may be returned if there is an error while computing the message signature
    \return MP_READ_E  may be returned if there is an error while computing the message signature
    \return MP_CMP_E  may be returned if there is an error while computing the message signature
    \return MP_INVMOD_E  may be returned if there is an error while computing the message signature
    \return MP_EXPTMOD_E  may be returned if there is an error while computing the message signature
    \return MP_MOD_E  may be returned if there is an error while computing the message signature
    \return MP_MUL_E  may be returned if there is an error while computing the message signature
    \return MP_ADD_E  may be returned if there is an error while computing the message signature
    \return MP_MULMOD_E  may be returned if there is an error while computing the message signature
    \return MP_TO_E  may be returned if there is an error while computing the message signature
    \return MP_MEM may be returned if there is an error while computing the message signature

    \param sig pointer to the buffer containing the signature to verify
    \param siglen length of the signature to verify
    \param hash pointer to the buffer containing the hash of the message verified
    \param hashlen length of the hash of the message verified
    \param stat pointer to the result of the verification. 1 indicates the message was successfully verified
    \param key pointer to a public ECC key with which to verify the signature

    _Example_
    \code
    ecc_key key;
    int ret, verified = 0;

    byte sig[1024] { // initialize with received signature };
    byte digest[] = { // initialize with message hash };
    // initialize key with received public key
    ret = wc_ecc_verify_hash(sig, sizeof(sig), digest,sizeof(digest), &verified, &key);
    if ( ret != 0 ) {
	    // error performing verification
    } else if ( verified == 0 ) {
	    // the signature is invalid
    }
    \endcode
    
    \sa wc_ecc_sign_hash
    \sa wc_ecc_verify_hash_ex
*/
WOLFSSL_API
int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                    word32 hashlen, int* stat, ecc_key* key);
/*!
    \ingroup ECC
    
    \brief Verify an ECC signature.  Result is written to stat.  1 is valid, 0 is invalid.
Note: Do not use the return value to test for valid.  Only use stat.

    \return MP_OKAY If successful (even if the signature is not valid)
    \return ECC_BAD_ARG_E Returns if arguments are null or if key-idx is invalid.
    \return MEMORY_E Error allocating ints or points.

    \param r The signature R component to verify
    \param s The signature S component to verify
    \param hash The hash (message digest) that was signed
    \param hashlen The length of the hash (octets)
    \param stat Result of signature, 1==valid, 0==invalid
    \param key The corresponding public ECC key

    _Example_
    \code
    mp_int r;
    mp_int s;
    int stat;
    byte hash[] = { // Some hash }
    ecc_key key;

    if(wc_ecc_verify_hash_ex(&r, &s, hash, hashlen, &stat, &key) == MP_OKAY)
    {
        // Check stat
    }
    \endcode
    
    \sa wc_ecc_verify_hash
*/
WOLFSSL_API
int wc_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                          word32 hashlen, int* stat, ecc_key* key);
#endif /* HAVE_ECC_VERIFY */

/*!
    \ingroup ECC
    
    \brief This function initializes an ecc_key object for future use with message verification or key negotiation.
    
    \return 0 Returned upon successfully initializing the ecc_key object
    \return MEMORY_E Returned if there is an error allocating memory
    
    \param key pointer to the ecc_key object to initialize
    
    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    \endcode
    
    \sa wc_ecc_make_key
    \sa wc_ecc_free
*/
WOLFSSL_API
int wc_ecc_init(ecc_key* key);
WOLFSSL_API
int wc_ecc_init_ex(ecc_key* key, void* heap, int devId);
/*!
    \ingroup ECC
    
    \brief This function frees an ecc_key object after it has been used.
    
    \return none No returns.
    
    \param key pointer to the ecc_key object to free
    
    _Example_
    \code
    // initialize key and perform secure exchanges
    ...
    wc_ecc_free(&key);
    \endcode
    
    \sa wc_ecc_init
*/
WOLFSSL_API
void wc_ecc_free(ecc_key* key);
WOLFSSL_API
int wc_ecc_set_flags(ecc_key* key, word32 flags);
/*!
    \ingroup ECC
    
    \brief This function frees the fixed-point cache, which can be used with ecc to speed up computation times. To use this functionality, FP_ECC (fixed-point ecc), should be defined.
    
    \return none No returns.
    
    \param none No parameters.
    
    _Example_
    \code
    ecc_key key;
    // initialize key and perform secure exchanges
    ...

    wc_ecc_fp_free();
    \endcode
    
    \sa wc_ecc_free
*/
WOLFSSL_API
void wc_ecc_fp_free(void);

WOLFSSL_API
int wc_ecc_set_curve(ecc_key* key, int keysize, int curve_id);

/*!
    \ingroup ECC
    
    \brief Checks if an ECC idx is valid.
    
    \return 1 Return if valid.
    \return 0 Return if not valid.
    
    \param n The idx number to check.
    
    _Example_
    \code
    ecc_key key;
    RNG rng;
    int is_valid;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    is_valid = wc_ecc_is_valid_idx(key.idx);
    if (is_valid == 1)
    {
        // idx is valid
    }
    else if (is_valid == 0)
    {
        // idx is not valid
    }
    \endcode
    
    \sa none
*/
WOLFSSL_API
int wc_ecc_is_valid_idx(int n);
WOLFSSL_API
int wc_ecc_get_curve_idx(int curve_id);
WOLFSSL_API
int wc_ecc_get_curve_id(int curve_idx);
#define wc_ecc_get_curve_name_from_id wc_ecc_get_name
WOLFSSL_API
int wc_ecc_get_curve_size_from_id(int curve_id);

WOLFSSL_API
int wc_ecc_get_curve_idx_from_name(const char* curveName);
WOLFSSL_API
int wc_ecc_get_curve_size_from_name(const char* curveName);
WOLFSSL_API
int wc_ecc_get_curve_id_from_name(const char* curveName);
WOLFSSL_API
int wc_ecc_get_curve_id_from_params(int fieldSize,
        const byte* prime, word32 primeSz, const byte* Af, word32 AfSz,
        const byte* Bf, word32 BfSz, const byte* order, word32 orderSz,
        const byte* Gx, word32 GxSz, const byte* Gy, word32 GySz, int cofactor);

#ifndef WOLFSSL_ATECC508A

/*!
    \ingroup ECC
    
    \brief Allocate a new ECC point.
    
    \return p A newly allocated point.
    \return NULL Returns NULL on error.
    
    \param none No parameters.
    
    _Example_
    \code
    ecc_point* point;
    point = wc_ecc_new_point();
    if (point == NULL)
    {
        // Handle point creation error
    }
    // Do stuff with point
    \endcode
    
    \sa wc_ecc_del_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_copy_point
*/
WOLFSSL_API
ecc_point* wc_ecc_new_point(void);
WOLFSSL_API
ecc_point* wc_ecc_new_point_h(void* h);
/*!
    \ingroup ECC
    
    \brief Free an ECC point from memory.
    
    \return none No returns.
    
    \param p The point to free.
    
    _Example_
    \code
    ecc_point* point;
    point = wc_ecc_new_point();
    if (point == NULL)
    {
        // Handle point creation error
    }
    // Do stuff with point
    wc_ecc_del_point(point);
    \endcode
    
    \sa wc_ecc_new_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_copy_point
*/
WOLFSSL_API
void wc_ecc_del_point(ecc_point* p);
WOLFSSL_API
void wc_ecc_del_point_h(ecc_point* p, void* h);
/*!
    \ingroup ECC
    
    \brief Copy the value of one point to another one.
    
    \return ECC_BAD_ARG_E Error thrown when p or r is null.
    \return MP_OKAY Point copied successfully
    \return ret Error from internal functions.  Can be...
    
    \param p The point to copy.
    \param r The created point.
    
    _Example_
    \code
    ecc_point* point;
    ecc_point* copied_point;
    int copy_return;

    point = wc_ecc_new_point();
    copy_return = wc_ecc_copy_point(point, copied_point);
    if (copy_return != MP_OKAY)
    {
        // Handle error
    }
    \endcode
    
    \sa wc_ecc_new_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_del_point
*/
WOLFSSL_API
int wc_ecc_copy_point(ecc_point* p, ecc_point *r);
/*!
    \ingroup ECC
    
    \brief Compare the value of a point with another one.
    
    \return BAD_FUNC_ARG One or both arguments are NULL.
    \return MP_EQ The points are equal.
    \return ret Either MP_LT or MP_GT and signifies that the points are not equal.
    
    \param a First point to compare.
    \param b Second point to compare.
    
    _Example_
    \code
    ecc_point* point;
    ecc_point* point_to_compare;
    int cmp_result;

    point = wc_ecc_new_point();
    point_to_compare = wc_ecc_new_point();
    cmp_result = wc_ecc_cmp_point(point, point_to_compare);
    if (cmp_result == BAD_FUNC_ARG)
    {
        // arguments are invalid
    }
    else if (cmp_result == MP_EQ)
    {
        // Points are equal
    }
    else
    {
        // Points are not equal
    }
    \endcode
    
    \sa wc_ecc_new_point
    \sa wc_ecc_del_point
    \sa wc_ecc_copy_point
*/
WOLFSSL_API
int wc_ecc_cmp_point(ecc_point* a, ecc_point *b);
/*!
    \ingroup ECC
    
    \brief Checks if a point is at infinity.  Returns 1 if point is at infinity, 0 if not, < 0 on error

    \return 1 p is at infinity.
    \return 0 p is not at infinity.
    \return <0 Error.
    
    \param p The point to check.
    
    _Example_
    \code
    ecc_point* point;
    int is_infinity;
    point = wc_ecc_new_point();

    is_infinity = wc_ecc_point_is_at_infinity(point);
    if (is_infinity < 0)
    {
        // Handle error
    }
    else if (is_infinity == 0)
    {
        // Point is not at infinity
    }
    else if (is_infinity == 1)
    {
        // Point is at infinity
    }
    \endcode
    
    \sa wc_ecc_new_point
    \sa wc_ecc_del_point
    \sa wc_ecc_cmp_point
    \sa wc_ecc_copy_point
*/
WOLFSSL_API
int wc_ecc_point_is_at_infinity(ecc_point *p);
/*!
    \ingroup ECC
    
    \brief Perform ECC Fixed Point multiplication.
    
    \return MP_OKAY Returns on successful operation.
    \return MP_INIT_E Returned if there is an error initializing an integer for use with the multiple precision integer (mp_int) library.
    
    \param k The multiplicand.
    \param G Base point to multiply.
    \param R Destination of product.
    \param modulus The modulus for the curve.
    \param map If non-zero maps the point back to affine coordinates, otherwise it's left in jacobian-montgomery form.
    
    _Example_
    \code
    ecc_point* base;
    ecc_point* destination;
    // Initialize points
    base = wc_ecc_new_point();
    destination = wc_ecc_new_point();
    // Setup other arguments
    mp_int multiplicand;
    mp_int modulus;
    int map;

    if(wc_ecc_mulmod(&multiplicand, base, destination, &modulus, map) == MP_OKAY)
    {
        // Successful operation
    }
    \endcode
    
    \sa none
*/
WOLFSSL_API
int wc_ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R,
                  mp_int* a, mp_int* modulus, int map);
WOLFSSL_LOCAL
int wc_ecc_mulmod_ex(mp_int* k, ecc_point *G, ecc_point *R,
                  mp_int* a, mp_int* modulus, int map, void* heap);
#endif /* !WOLFSSL_ATECC508A */


#ifdef HAVE_ECC_KEY_EXPORT
/* ASN key helpers */
/*!
    \ingroup ECC
    
    \brief This function exports the ECC key from the ecc_key structure, storing the result in out. The key will be stored in ANSI X9.63 format. It stores the bytes written to the output buffer in outLen.
    
    \return 0 Returned on successfully exporting the ecc_key
    \return LENGTH_ONLY_E Returned if the output buffer evaluates to NULL, but the other two input parameters are valid. Indicates that the function is only returning the length required to store the key
    \return ECC_BAD_ARG_E Returned if any of the input parameters are NULL, or the key is unsupported (has an invalid index)
    \return BUFFER_E Returned if the output buffer is too small to store the ecc key. If the output buffer is too small, the size needed will be returned in outLen
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return MP_INIT_E may be returned if there is an error processing the ecc_key
    \return MP_READ_E may be returned if there is an error processing the ecc_key
    \return MP_CMP_E may be returned if there is an error processing the ecc_key
    \return MP_INVMOD_E may be returned if there is an error processing the ecc_key
    \return MP_EXPTMOD_E may be returned if there is an error processing the ecc_key
    \return MP_MOD_E may be returned if there is an error processing the ecc_key
    \return MP_MUL_E may be returned if there is an error processing the ecc_key
    \return MP_ADD_E may be returned if there is an error processing the ecc_key
    \return MP_MULMOD_E may be returned if there is an error processing the ecc_key
    \return MP_TO_E may be returned if there is an error processing the ecc_key
    \return MP_MEM may be returned if there is an error processing the ecc_key
    
    \param key pointer to the ecc_key object to export
    \param out pointer to the buffer in which to store the ANSI X9.63 formatted key
    \param outLen size of the output buffer. On successfully storing the key, will hold the bytes written to the output buffer
    
    _Example_
    \code
    int ret;
    byte buff[1024];
    word32 buffSz = sizeof(buff);

    ecc_key key;
    // initialize key, make key
    ret = wc_ecc_export_x963(&key, buff, &buffSz);
    if ( ret != 0) {
    	// error exporting key
    }
    \endcode
    
    \sa wc_ecc_export_x963_ex
    \sa wc_ecc_import_x963
*/
WOLFSSL_API
int wc_ecc_export_x963(ecc_key*, byte* out, word32* outLen);
/*!
    \ingroup ECC
    
    \brief This function exports the ECC key from the ecc_key structure, storing the result in out. The key will be stored in ANSI X9.63 format. It stores the bytes written to the output buffer in outLen. This function allows the additional option of compressing the certificate through the compressed parameter. When this parameter is true, the key will be stored in ANSI X9.63 compressed format.
    
    \return 0 Returned on successfully exporting the ecc_key
    \return NOT_COMPILED_IN Returned if the HAVE_COMP_KEY was not enabled at compile time, but the key was requested in compressed format
    \return LENGTH_ONLY_E Returned if the output buffer evaluates to NULL, but the other two input parameters are valid. Indicates that the function is only returning the length required to store the key
    \return ECC_BAD_ARG_E Returned if any of the input parameters are NULL, or the key is unsupported (has an invalid index)
    \return BUFFER_E Returned if the output buffer is too small to store the ecc key. If the output buffer is too small, the size needed will be returned in outLen
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return MP_INIT_E may be returned if there is an error processing the ecc_key
    \return MP_READ_E may be returned if there is an error processing the ecc_key
    \return MP_CMP_E may be returned if there is an error processing the ecc_key
    \return MP_INVMOD_E may be returned if there is an error processing the ecc_key
    \return MP_EXPTMOD_E may be returned if there is an error processing the ecc_key
    \return MP_MOD_E may be returned if there is an error processing the ecc_key
    \return MP_MUL_E may be returned if there is an error processing the ecc_key
    \return MP_ADD_E may be returned if there is an error processing the ecc_key
    \return MP_MULMOD_E may be returned if there is an error processing the ecc_key
    \return MP_TO_E may be returned if there is an error processing the ecc_key
    \return MP_MEM may be returned if there is an error processing the ecc_key

    \param key pointer to the ecc_key object to export
    \param out pointer to the buffer in which to store the ANSI X9.63 formatted key
    \param outLen size of the output buffer. On successfully storing the key, will hold the bytes written to the output buffer
    \param compressed indicator of whether to store the key in compressed format. 1==compressed, 0==uncompressed
    
    _Example_
    \code
    int ret;
    byte buff[1024];
    word32 buffSz = sizeof(buff);
    ecc_key key;
    // initialize key, make key
    ret = wc_ecc_export_x963_ex(&key, buff, &buffSz, 1);
    if ( ret != 0) {
	    // error exporting key
    }
    \endcode

    \sa wc_ecc_export_x963
    \sa wc_ecc_import_x963
*/
WOLFSSL_API
int wc_ecc_export_x963_ex(ecc_key*, byte* out, word32* outLen, int compressed);
    /* extended functionality with compressed option */
#endif /* HAVE_ECC_KEY_EXPORT */

#ifdef HAVE_ECC_KEY_IMPORT
/*!
    \ingroup ECC
    
    \brief This function imports a public ECC key from a buffer containing the key stored in ANSI X9.63 format. This function will handle both compressed and uncompressed keys, as long as compressed keys are enabled at compile time through the HAVE_COMP_KEY option.
    
    \return 0 Returned on successfully importing the ecc_key
    \return NOT_COMPILED_IN Returned if the HAVE_COMP_KEY was not enabled at compile time, but the key is stored in compressed format
    \return ECC_BAD_ARG_E Returned if in or key evaluate to NULL, or the inLen is even (according to the x9.63 standard, the key must be odd)
    \return MEMORY_E Returned if there is an error allocating memory
    \return ASN_PARSE_E Returned if there is an error parsing the ECC key; may indicate that the ECC key is not stored in valid ANSI X9.63 format
    \return IS_POINT_E Returned if the public key exported is not a point on the ECC curve
    \return MP_INIT_E may be returned if there is an error processing the ecc_key
    \return MP_READ_E may be returned if there is an error processing the ecc_key
    \return MP_CMP_E may be returned if there is an error processing the ecc_key
    \return MP_INVMOD_E may be returned if there is an error processing the ecc_key
    \return MP_EXPTMOD_E may be returned if there is an error processing the ecc_key
    \return MP_MOD_E may be returned if there is an error processing the ecc_key
    \return MP_MUL_E may be returned if there is an error processing the ecc_key
    \return MP_ADD_E may be returned if there is an error processing the ecc_key
    \return MP_MULMOD_E may be returned if there is an error processing the ecc_key
    \return MP_TO_E may be returned if there is an error processing the ecc_key
    \return MP_MEM may be returned if there is an error processing the ecc_key
    
    \param in pointer to the buffer containing the ANSI x9.63 formatted ECC key
    \param inLen length of the input buffer
    \param key pointer to the ecc_key object in which to store the imported key
    
    _Example_
    \code
    int ret;
    byte buff[] = { // initialize with ANSI X9.63 formatted key };

    ecc_key pubKey;
    wc_ecc_init_key(&pubKey);

    ret = wc_ecc_import_x963(buff, sizeof(buff), &pubKey);
    if ( ret != 0) {
    	// error importing key
    }
    \endcode
    
    \sa wc_ecc_export_x963
    \sa wc_ecc_import_private_key
*/
WOLFSSL_API
int wc_ecc_import_x963(const byte* in, word32 inLen, ecc_key* key);
WOLFSSL_API
int wc_ecc_import_x963_ex(const byte* in, word32 inLen, ecc_key* key,
                          int curve_id);
/*!
    \ingroup ECC
    
    \brief This function imports a public/private ECC key pair from a buffer containing the raw private key, and a second buffer containing the ANSI X9.63 formatted public key. This function will handle both compressed and uncompressed keys, as long as compressed keys are enabled at compile time through the HAVE_COMP_KEY option.
    
    \return 0 Returned on successfully importing the ecc_key
NOT_COMPILED_IN Returned if the HAVE_COMP_KEY was not enabled at compile time, but the key is stored in compressed format
    \return ECC_BAD_ARG_E Returned if in or key evaluate to NULL, or the inLen is even (according to the x9.63 standard, the key must be odd)
    \return MEMORY_E Returned if there is an error allocating memory
    \return ASN_PARSE_E Returned if there is an error parsing the ECC key; may indicate that the ECC key is not stored in valid ANSI X9.63 format
    \return IS_POINT_E Returned if the public key exported is not a point on the ECC curve
    \return MP_INIT_E may be returned if there is an error processing the ecc_key
    \return MP_READ_E may be returned if there is an error processing the ecc_key
    \return MP_CMP_E may be returned if there is an error processing the ecc_key
    \return MP_INVMOD_E may be returned if there is an error processing the ecc_key
    \return MP_EXPTMOD_E may be returned if there is an error processing the ecc_key
    \return MP_MOD_E may be returned if there is an error processing the ecc_key
    \return MP_MUL_E may be returned if there is an error processing the ecc_key
    \return MP_ADD_E may be returned if there is an error processing the ecc_key
    \return MP_MULMOD_E may be returned if there is an error processing the ecc_key
    \return MP_TO_E may be returned if there is an error processing the ecc_key
    \return MP_MEM may be returned if there is an error processing the ecc_key
    
    \param priv pointer to the buffer containing the raw private key
    \param privSz size of the private key buffer
    \param pub pointer to the buffer containing the ANSI x9.63 formatted ECC public key
    \param pubSz length of the public key input buffer
    \param key pointer to the ecc_key object in which to store the imported private/public key pair
    
    _Example_
    \code
    int ret;
    byte pub[] = { // initialize with ANSI X9.63 formatted key };
    byte priv[] = { // initialize with the raw private key };

    ecc_key key;
    wc_ecc_init_key(&key);
    ret = wc_ecc_import_private_key(priv, sizeof(priv), pub, sizeof(pub), &key);
    if ( ret != 0) {
    	// error importing key
    }
    \endcode
    
    \sa wc_ecc_export_x963
    \sa wc_ecc_import_private_key
*/
WOLFSSL_API
int wc_ecc_import_private_key(const byte* priv, word32 privSz, const byte* pub,
                           word32 pubSz, ecc_key* key);
WOLFSSL_API
int wc_ecc_import_private_key_ex(const byte* priv, word32 privSz,
                const byte* pub, word32 pubSz, ecc_key* key, int curve_id);
/*!
    \ingroup ECC
    
    \brief This function converts the R and S portions of an ECC signature into a DER-encoded ECDSA signature. This function also stores the length written to the output buffer, out, in outlen.
    
    \return 0 Returned on successfully converting the signature
    \return ECC_BAD_ARG_E Returned if any of the input parameters evaluate to NULL, or if the input buffer is not large enough to hold the DER-encoded ECDSA signature
    \return MP_INIT_E may be returned if there is an error processing the ecc_key
    \return MP_READ_E may be returned if there is an error processing the ecc_key
    \return MP_CMP_E may be returned if there is an error processing the ecc_key
    \return MP_INVMOD_E may be returned if there is an error processing the ecc_key
    \return MP_EXPTMOD_E may be returned if there is an error processing the ecc_key
    \return MP_MOD_E may be returned if there is an error processing the ecc_key
    \return MP_MUL_E may be returned if there is an error processing the ecc_key
    \return MP_ADD_E may be returned if there is an error processing the ecc_key
    \return MP_MULMOD_E may be returned if there is an error processing the ecc_key
    \return MP_TO_E may be returned if there is an error processing the ecc_key
    \return MP_MEM may be returned if there is an error processing the ecc_key
    
    \param r pointer to the buffer containing the R portion of the signature as a string
    \param s pointer to the buffer containing the S portion of the signature as a string
    \param out pointer to the buffer in which to store the DER-encoded ECDSA signature
    \param outlen length of the output buffer available. Will store the bytes written to the buffer after successfully converting the signature to ECDSA format

    _Example_
    \code
    int ret;
    ecc_key key;
    // initialize key, generate R and S

    char r[] = { // initialize with R };
    char s[] = { // initialize with S };
    byte sig[wc_ecc_sig_size(key)]; 
    // signature size will be 2 * ECC key size + ~10 bytes for ASN.1 overhead
    word32 sigSz = sizeof(sig);
    ret = wc_ecc_rs_to_sig(r, s, sig, &sigSz);
    if ( ret != 0) {
    	// error converting parameters to signature
    }
    \endcode
    
    \sa wc_ecc_sign_hash
    \sa wc_ecc_sig_size
*/
WOLFSSL_API
int wc_ecc_rs_to_sig(const char* r, const char* s, byte* out, word32* outlen);
WOLFSSL_API
int wc_ecc_sig_to_rs(const byte* sig, word32 sigLen, byte* r, word32* rLen,
                   byte* s, word32* sLen);
/*!
    \ingroup ECC
    
    \brief This function fills an ecc_key structure with the raw components of an ECC signature.
    
    \return 0 Returned upon successfully importing into the ecc_key structure
    \return ECC_BAD_ARG_E Returned if any of the input values evaluate to NULL
    \return MEMORY_E Returned if there is an error initializing space to store the parameters of the ecc_key
    \return ASN_PARSE_E Returned if the input curveName is not defined in ecc_sets
    \return MP_INIT_E may be returned if there is an error processing the input parameters
    \return MP_READ_E may be returned if there is an error processing the input parameters
    \return MP_CMP_E may be returned if there is an error processing the input parameters
    \return MP_INVMOD_E may be returned if there is an error processing the input parameters
    \return MP_EXPTMOD_E may be returned if there is an error processing the input parameters
    \return MP_MOD_E may be returned if there is an error processing the input parameters
    \return MP_MUL_E may be returned if there is an error processing the input parameters
    \return MP_ADD_E may be returned if there is an error processing the input parameters
    \return MP_MULMOD_E may be returned if there is an error processing the input parameters
    \return MP_TO_E may be returned if there is an error processing the input parameters
    \return MP_MEM may be returned if there is an error processing the input parameters
    
    \param key pointer to an ecc_key structure to fill
    \param qx pointer to a buffer containing the x component of the base point as an ASCII hex string
    \param qy pointer to a buffer containing the y component of the base point as an ASCII hex string
    \param d pointer to a buffer containing the private key as an ASCII hex string
    \param curveName pointer to a string containing the ECC curve name, as found in ecc_sets

    _Example_
    \code
    int ret;
    ecc_key key;
    wc_ecc_init(&key);

    char qx[] = { // initialize with x component of base point };
    char qy[] = { // initialize with y component of base point };
    char d[]  = { // initialize with private key };
    ret = wc_ecc_import_raw(&key,qx, qy, d, "ECC-256");
    if ( ret != 0) {
    	// error initializing key with given inputs
    }
    \endcode
    
    \sa wc_ecc_import_private_key
*/
WOLFSSL_API
int wc_ecc_import_raw(ecc_key* key, const char* qx, const char* qy,
                   const char* d, const char* curveName);
WOLFSSL_API
int wc_ecc_import_raw_ex(ecc_key* key, const char* qx, const char* qy,
                   const char* d, int curve_id);
#endif /* HAVE_ECC_KEY_IMPORT */

#ifdef HAVE_ECC_KEY_EXPORT
/*!
    \ingroup ECC
    
    \brief This function exports only the private key from an ecc_key structure. It stores the private key in the buffer out, and sets the bytes written to this buffer in outLen.
    
    \return 0 Returned upon successfully exporting the private key
    \return ECC_BAD_ARG_E Returned if any of the input values evaluate to NULL
    \return MEMORY_E Returned if there is an error initializing space to store the parameters of the ecc_key
    \return ASN_PARSE_E Returned if the input curveName is not defined in ecc_sets
    \return MP_INIT_E may be returned if there is an error processing the input parameters
    \return MP_READ_E may be returned if there is an error processing the input parameters
    \return MP_CMP_E may be returned if there is an error processing the input parameters
    \return MP_INVMOD_E may be returned if there is an error processing the input parameters
    \return MP_EXPTMOD_E may be returned if there is an error processing the input parameters
    \return MP_MOD_E may be returned if there is an error processing the input parameters
    \return MP_MUL_E may be returned if there is an error processing the input parameters
    \return MP_ADD_E may be returned if there is an error processing the input parameters
    \return MP_MULMOD_E may be returned if there is an error processing the input parameters
    \return MP_TO_E may be returned if there is an error processing the input parameters
    \return MP_MEM may be returned if there is an error processing the input parameters
    
    \param key pointer to an ecc_key structure from which to export the private key
    \param out pointer to the buffer in which to store the private key
    \param outLen pointer to a word32 object with the size available in out. Set with the number of bytes written to out after successfully exporting the private key
    
    _Example_
    \code
    int ret;
    ecc_key key;
    // initialize key, make key

    char priv[ECC_KEY_SIZE];
    word32 privSz = sizeof(priv);
    ret = wc_ecc_export_private_only(&key, priv, &privSz);
    if ( ret != 0) {
    	// error exporting private key
    }
    \endcode
    
    \sa wc_ecc_import_private_key
*/
WOLFSSL_API
int wc_ecc_export_private_only(ecc_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_ecc_export_public_raw(ecc_key* key, byte* qx, word32* qxLen,
                             byte* qy, word32* qyLen);
WOLFSSL_API
int wc_ecc_export_private_raw(ecc_key* key, byte* qx, word32* qxLen,
                            byte* qy, word32* qyLen, byte* d, word32* dLen);
#endif /* HAVE_ECC_KEY_EXPORT */

#ifdef HAVE_ECC_KEY_EXPORT

/*!
    \ingroup ECC
    
    \brief Export point to der.
    
    \return 0 Returned on success.
    \return ECC_BAD_ARG_E Returns if curve_idx is less than 0 or invalid.  Also returns when 
    \return LENGTH_ONLY_E outLen is set but nothing else.
    \return BUFFER_E Returns if outLen is less than 1 + 2 * the curve size.
    \return MEMORY_E Returns if there is a problem allocating memory.

    \param curve_idx Index of the curve used from ecc_sets.
    \param point Point to export to der.
    \param out Destination for the output.
    \param outLen Maxsize allowed for output, destination for final size of output

    _Example_
    \code
    int curve_idx;
    ecc_point* point;
    byte out[];
    word32 outLen;
    wc_ecc_export_point_der(curve_idx, point, out, &outLen);
    \endcode
    
    \sa wc_ecc_import_point_der
*/
WOLFSSL_API
int wc_ecc_export_point_der(const int curve_idx, ecc_point* point,
                            byte* out, word32* outLen);
#endif /* HAVE_ECC_KEY_EXPORT */


#ifdef HAVE_ECC_KEY_IMPORT
/*!
    \ingroup ECC
    
    \brief Import point from der format.
    
    \return ECC_BAD_ARG_E Returns if any arguments are null or if inLen is even.
    \return MEMORY_E Returns if there is an error initializing 
    \return NOT_COMPILED_IN Returned if HAVE_COMP_KEY is not true and in is a compressed cert
    \return MP_OKAY Successful operation.
    
    \param in der buffer to import point from.
    \param inLen Length of der buffer.
    \param curve_idx Index of curve.
    \param point Destination for point.

    _Example_
    \code
    byte in[];
    word32 inLen;
    int curve_idx;
    ecc_point* point;
    wc_ecc_import_point_der(in, inLen, curve_idx, point);
    \endcode
    
    \sa wc_ecc_export_point_der
*/
WOLFSSL_API
int wc_ecc_import_point_der(byte* in, word32 inLen, const int curve_idx,
                            ecc_point* point);
#endif /* HAVE_ECC_KEY_IMPORT */

/* size helper */
/*!
    \ingroup ECC
    
    \brief This function returns the key size of an ecc_key structure in octets.
    
    \return Given a valid key, returns the key size in octets
    \return 0 Returned if the given key is NULL
    
    \param key pointer to an ecc_key structure for which to get the key size
    
    _Example_
    \code
    int keySz;
    ecc_key key;
    // initialize key, make key
    keySz = wc_ecc_size(&key);
    if ( keySz == 0) {
    	// error determining key size
    }
    \endcode
    
    \sa wc_ecc_make_key
*/
WOLFSSL_API
int wc_ecc_size(ecc_key* key);
/*!
    \ingroup ECC
    
    \brief This function returns the worst case size for an ECC signature, given by: keySz * 2 + SIG_HEADER_SZ + 4 The actual signature size can be computed with wc_ecc_sign_hash.
    
    \return Success Given a valid key, returns the maximum signature size, in octets
    \return 0 Returned if the given key is NULL
    
    \param key pointer to an ecc_key structure for which to get the signature size
    
    _Example_
    \code
    int sigSz;
    ecc_key key;
    // initialize key, make key

    sigSz = wc_ecc_sig_size(&key);
    if ( sigSz == 0) {
    	// error determining sig size
    }
    \endcode

    \sa wc_ecc_sign_hash
*/
WOLFSSL_API
int wc_ecc_sig_size(ecc_key* key);

WOLFSSL_API
int wc_ecc_get_oid(word32 oidSum, const byte** oid, word32* oidSz);

#ifdef WOLFSSL_CUSTOM_CURVES
    WOLFSSL_API
    int wc_ecc_set_custom_curve(ecc_key* key, const ecc_set_type* dp);
#endif

#ifdef HAVE_ECC_ENCRYPT
/* ecc encrypt */

enum ecEncAlgo {
    ecAES_128_CBC = 1,  /* default */
    ecAES_256_CBC = 2
};

enum ecKdfAlgo {
    ecHKDF_SHA256 = 1,  /* default */
    ecHKDF_SHA1   = 2
};

enum ecMacAlgo {
    ecHMAC_SHA256 = 1,  /* default */
    ecHMAC_SHA1   = 2
};

enum {
    KEY_SIZE_128     = 16,
    KEY_SIZE_256     = 32,
    IV_SIZE_64       =  8,
    IV_SIZE_128      = 16,
    EXCHANGE_SALT_SZ = 16,
    EXCHANGE_INFO_SZ = 23
};

enum ecFlags {
    REQ_RESP_CLIENT = 1,
    REQ_RESP_SERVER = 2
};


typedef struct ecEncCtx ecEncCtx;

/*!
    \ingroup ECC
    
    \brief This function allocates and initializes space for a new ECC context object to allow secure message exchange with ECC.
    
    \return Success On successfully generating a new ecEncCtx object, returns a pointer to that object
    \return NULL Returned if the function fails to generate a new ecEncCtx object
    
    \param flags indicate whether this is a server or client context Options are: REQ_RESP_CLIENT, and REQ_RESP_SERVER
    \param rng pointer to a RNG object with which to generate a salt
    
    _Example_
    \code
    ecEncCtx* ctx;
    RNG rng;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    if(ctx == NULL) {
	    // error generating new ecEncCtx object
    }
    \endcode
    
    \sa wc_ecc_encrypt
    \sa wc_ecc_decrypt
*/
WOLFSSL_API
ecEncCtx* wc_ecc_ctx_new(int flags, WC_RNG* rng);
WOLFSSL_API
ecEncCtx* wc_ecc_ctx_new_ex(int flags, WC_RNG* rng, void* heap);
/*!
    \ingroup ECC
    
    \brief This function frees the ecEncCtx object used for encrypting and decrypting messages.
    
    \return none Returns.
    
    \param ctx pointer to the ecEncCtx object to free
    
    _Example_
    \code
    ecEncCtx* ctx;
    RNG rng;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    // do secure communication
    ...
    wc_ecc_ctx_free(&ctx);
    \endcode

    \sa wc_ecc_ctx_new
*/
WOLFSSL_API
void wc_ecc_ctx_free(ecEncCtx*);
/*!
    \ingroup ECC
    
    \brief This function resets an ecEncCtx structure to avoid having to free and allocate a new context object.
    
    \return 0 Returned if the ecEncCtx structure is successfully reset
    \return BAD_FUNC_ARG Returned if either rng or ctx is NULL
    \return RNG_FAILURE_E Returned if there is an error generating a new salt for the ECC object

    \param ctx pointer to the ecEncCtx object to reset
    \param rng pointer to an RNG object with which to generate a new salt
    
    _Example_
    \code
    ecEncCtx* ctx;
    RNG rng;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    // do secure communication
    ...
    wc_ecc_ctx_reset(&ctx, &rng);
    // do more secure communication
    \endcode
    
    \sa wc_ecc_ctx_new
*/
WOLFSSL_API
int wc_ecc_ctx_reset(ecEncCtx*, WC_RNG*);  /* reset for use again w/o alloc/free */

/*!
    \ingroup ECC
    
    \brief This function returns the salt of an ecEncCtx object. This function should only be called when the ecEncCtx's state is ecSRV_INIT or ecCLI_INIT.
    
    \return Success On success, returns the ecEncCtx salt
    \return NULL Returned if the ecEncCtx object is NULL, or the ecEncCtx's state is not ecSRV_INIT or ecCLI_INIT. In the latter two cases, this function also sets the ecEncCtx's state to ecSRV_BAD_STATE or ecCLI_BAD_STATE, respectively
    
    \param ctx pointer to the ecEncCtx object from which to get the salt
    
    _Example_
    \code
    ecEncCtx* ctx;
    RNG rng;
    const byte* salt;
    wc_InitRng(&rng);
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    salt = wc_ecc_ctx_get_own_salt(&ctx);
    if(salt == NULL) {
    	// error getting salt
    }
    \endcode
    
    \sa wc_ecc_ctx_new
    \sa wc_ecc_ctx_set_peer_salt
*/
WOLFSSL_API
const byte* wc_ecc_ctx_get_own_salt(ecEncCtx*);
/*!
    \ingroup ECC
    
    \brief This function sets the peer salt of an ecEncCtx object. 
    
    \return 0 Returned upon successfully setting the peer salt for the ecEncCtx object.
    \return BAD_FUNC_ARG Returned if the given ecEncCtx object is NULL or has an invalid protocol, or if the given salt is NULL
    \return BAD_ENC_STATE_E Returned if the ecEncCtx's state is ecSRV_SALT_GET or ecCLI_SALT_GET. In the latter two cases, this function also sets the ecEncCtx's state to ecSRV_BAD_STATE or ecCLI_BAD_STATE, respectively

    \param ctx pointer to the ecEncCtx for which to set the salt
    \param salt pointer to the peer's salt
    
    _Example_
    \code
    ecEncCtx* cliCtx, srvCtx;
    RNG rng;
    const byte* cliSalt, srvSalt;
    int ret;

    wc_InitRng(&rng);
    cliCtx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    srvCtx = wc_ecc_ctx_new(REQ_RESP_SERVER, &rng);

    cliSalt = wc_ecc_ctx_get_own_salt(&cliCtx);
    srvSalt = wc_ecc_ctx_get_own_salt(&srvCtx);
    ret = wc_ecc_ctx_set_peer_salt(&cliCtx, srvSalt);
    \endcode
    
    \sa wc_ecc_ctx_get_own_salt
*/
WOLFSSL_API
int wc_ecc_ctx_set_peer_salt(ecEncCtx*, const byte* salt);
/*!
    \ingroup ECC
    
    \brief This function can optionally be called before or after wc_ecc_ctx_set_peer_salt. It sets optional information for an ecEncCtx object.

    \return 0 Returned upon successfully setting the information for the ecEncCtx object.
    \return BAD_FUNC_ARG Returned if the given ecEncCtx object is NULL, the input info is NULL or it's size is invalid
    
    \param ctx pointer to the ecEncCtx for which to set the info
    \param info pointer to a buffer containing the info to set
    \param sz size of the info buffer
    
    _Example_
    \code
    ecEncCtx* ctx;
    byte info[] = { // initialize with information };
    // initialize ctx, get salt,
    if(wc_ecc_ctx_set_info(&ctx, info, sizeof(info))) {
	    // error setting info
    }
    \endcode
    
    \sa wc_ecc_ctx_new
*/
WOLFSSL_API
int wc_ecc_ctx_set_info(ecEncCtx*, const byte* info, int sz);

/*!
    \ingroup ECC
    
    \brief This function encrypts the given input message from msg to out. This function takes an optional ctx object as parameter. When supplied, encryption proceeds based on the ecEncCtx's encAlgo, kdfAlgo, and macAlgo. If ctx is not supplied, processing completes with the default algorithms, ecAES_128_CBC, ecHKDF_SHA256 and ecHMAC_SHA256. This function requires that the messages are padded according to the encryption type specified by ctx.
    
    \return 0 Returned upon successfully encrypting the input message
    \return BAD_FUNC_ARG Returned if privKey, pubKey, msg, msgSz, out, or outSz are NULL, or the ctx object specifies an unsupported encryption type
    \return BAD_ENC_STATE_E Returned if the ctx object given is in a state that is not appropriate for encryption
    \return BUFFER_E Returned if the supplied output buffer is too small to store the encrypted ciphertext
    \return MEMORY_E Returned if there is an error allocating memory for the shared secret key

    \param privKey pointer to the ecc_key object containing the private key to use for encryption
    \param pubKey pointer to the ecc_key object containing the public key of the peer with whom one wishes to communicate
    \param msg pointer to the buffer holding the message to encrypt
    \param msgSz size of the buffer to encrypt
    \param out pointer to the buffer in which to store the encrypted ciphertext 
    \param outSz pointer to a word32 object containing the available size in the out buffer. Upon successfully encrypting the message, holds the number of bytes written to the output buffer
    \param ctx Optional: pointer to an ecEncCtx object specifying different encryption algorithms to use

    _Example_
    \code
    byte msg[] = { // initialize with msg to encrypt. Ensure padded to block size };
    byte out[sizeof(msg)];
    word32 outSz = sizeof(out);
    int ret;
    ecc_key cli, serv;
    // initialize cli with private key
    // initialize serv with received public key

    ecEncCtx* cliCtx, servCtx;
    // initialize cliCtx and servCtx
    // exchange salts
    ret = wc_ecc_encrypt(&cli, &serv, msg, sizeof(msg), out, &outSz, cliCtx);
    if(ret != 0) { 
    	// error encrypting message 
    }
    \endcode
    
    \sa wc_ecc_decrypt
*/
WOLFSSL_API
int wc_ecc_encrypt(ecc_key* privKey, ecc_key* pubKey, const byte* msg,
                word32 msgSz, byte* out, word32* outSz, ecEncCtx* ctx);
/*!
    \ingroup ECC
    
    \brief This function decrypts the ciphertext from msg to out. This function takes an optional ctx object as parameter. When supplied, encryption proceeds based on the ecEncCtx's encAlgo, kdfAlgo, and macAlgo. If ctx is not supplied, processing completes with the default algorithms, ecAES_128_CBC, ecHKDF_SHA256 and ecHMAC_SHA256. This function requires that the messages are padded according to the encryption type specified by ctx.
    
    \return 0 Returned upon successfully decrypting the input message
    \return BAD_FUNC_ARG Returned if privKey, pubKey, msg, msgSz, out, or outSz are NULL, or the ctx object specifies an unsupported encryption type
    \return BAD_ENC_STATE_E Returned if the ctx object given is in a state that is not appropriate for decryption
    \return BUFFER_E Returned if the supplied output buffer is too small to store the decrypted plaintext
    \return MEMORY_E Returned if there is an error allocating memory for the shared secret key
    
    \param privKey pointer to the ecc_key object containing the private key to use for decryption
    \param pubKey pointer to the ecc_key object containing the public key of the peer with whom one wishes to communicate
    \param msg pointer to the buffer holding the ciphertext to decrypt
    \param msgSz size of the buffer to decrypt
    \param out pointer to the buffer in which to store the decrypted plaintext
    \param outSz pointer to a word32 object containing the available size in the out buffer. Upon successfully decrypting the ciphertext, holds the number of bytes written to the output buffer
    \param ctx Optional: pointer to an ecEncCtx object specifying different decryption algorithms to use
    
    _Example_
    \code
    byte cipher[] = { // initialize with ciphertext to decrypt. Ensure padded to block size };
    byte plain[sizeof(cipher)];
    word32 plainSz = sizeof(plain);
    int ret;
    ecc_key cli, serv;
    // initialize cli with private key
    // initialize serv with received public key
    ecEncCtx* cliCtx, servCtx;
    // initialize cliCtx and servCtx
    // exchange salts
    ret = wc_ecc_decrypt(&cli, &serv, cipher, sizeof(cipher), plain, &plainSz, cliCtx);

    if(ret != 0) { 
    	// error decrypting message 
    }
    \endcode
    
    \sa Wc_ecc_encrypt
*/
WOLFSSL_API
int wc_ecc_decrypt(ecc_key* privKey, ecc_key* pubKey, const byte* msg,
                word32 msgSz, byte* out, word32* outSz, ecEncCtx* ctx);

#endif /* HAVE_ECC_ENCRYPT */

#ifdef HAVE_X963_KDF
WOLFSSL_API int wc_X963_KDF(enum wc_HashType type, const byte* secret,
                word32 secretSz, const byte* sinfo, word32 sinfoSz,
                byte* out, word32 outSz);
#endif

#ifdef ECC_CACHE_CURVE
WOLFSSL_API int wc_ecc_curve_cache_init(void);
WOLFSSL_API void wc_ecc_curve_cache_free(void);
#endif


#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_ECC */
#endif /* WOLF_CRYPT_ECC_H */
