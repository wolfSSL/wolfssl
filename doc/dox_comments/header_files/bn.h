/*!
    \ingroup openSSL

    \brief This function performs the following math “r = (a^p) % m”.

    \return SSL_SUCCESS On successfully performing math operation.
    \return SSL_FAILURE If an error case was encountered.

    \param r structure to hold result.
    \param a value to be raised by a power.
    \param p power to raise a by.
    \param m modulus to use.
    \param ctx currently not used with wolfSSL can be NULL.

    _Example_
    \code
    WOLFSSL_BIGNUM r,a,p,m;
    int ret;
    // set big number values
    ret  = wolfSSL_BN_mod_exp(r, a, p, m, NULL);
    // check ret value
    \endcode

    \sa wolfSSL_BN_new
    \sa wolfSSL_BN_free
*/
int wolfSSL_BN_mod_exp(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
        const WOLFSSL_BIGNUM *p, const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Creates new BIGNUM context.

    \return WOLFSSL_BN_CTX pointer on success
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BN_CTX* ctx = wolfSSL_BN_CTX_new();
    if (ctx == NULL) {
        // handle error
    }
    \endcode

    \sa wolfSSL_BN_CTX_free
*/
WOLFSSL_BN_CTX* wolfSSL_BN_CTX_new(void);

/*!
    \ingroup openSSL
    \brief Initializes BIGNUM context.

    \return none No returns

    \param ctx BIGNUM context to initialize

    _Example_
    \code
    WOLFSSL_BN_CTX ctx;
    wolfSSL_BN_CTX_init(&ctx);
    \endcode

    \sa wolfSSL_BN_CTX_new
*/
void wolfSSL_BN_CTX_init(WOLFSSL_BN_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Frees BIGNUM context.

    \return none No returns

    \param ctx BIGNUM context to free

    _Example_
    \code
    WOLFSSL_BN_CTX* ctx = wolfSSL_BN_CTX_new();
    // use ctx
    wolfSSL_BN_CTX_free(ctx);
    \endcode

    \sa wolfSSL_BN_CTX_new
*/
void wolfSSL_BN_CTX_free(WOLFSSL_BN_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Creates new BIGNUM.

    \return WOLFSSL_BIGNUM pointer on success
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    if (bn == NULL) {
        // handle error
    }
    \endcode

    \sa wolfSSL_BN_free
*/
WOLFSSL_BIGNUM* wolfSSL_BN_new(void);

/*!
    \ingroup openSSL
    \brief Initializes BIGNUM.

    \return none No returns

    \param bn BIGNUM to initialize

    _Example_
    \code
    WOLFSSL_BIGNUM bn;
    wolfSSL_BN_init(&bn);
    \endcode

    \sa wolfSSL_BN_new
*/
void wolfSSL_BN_init(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Frees BIGNUM.

    \return none No returns

    \param bn BIGNUM to free

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    // use bn
    wolfSSL_BN_free(bn);
    \endcode

    \sa wolfSSL_BN_new
*/
void wolfSSL_BN_free(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Clears and frees BIGNUM.

    \return none No returns

    \param bn BIGNUM to clear and free

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    // use bn
    wolfSSL_BN_clear_free(bn);
    \endcode

    \sa wolfSSL_BN_free
*/
void wolfSSL_BN_clear_free(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Clears BIGNUM value.

    \return none No returns

    \param bn BIGNUM to clear

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    wolfSSL_BN_clear(bn);
    \endcode

    \sa wolfSSL_BN_clear_free
*/
void wolfSSL_BN_clear(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Subtracts two BIGNUMs (r = a - b).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a First operand
    \param b Second operand

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *a, *b;
    int ret = wolfSSL_BN_sub(r, a, b);
    \endcode

    \sa wolfSSL_BN_add
*/
int wolfSSL_BN_sub(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* a,
    const WOLFSSL_BIGNUM* b);

/*!
    \ingroup openSSL
    \brief Multiplies two BIGNUMs (r = a * b).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a First operand
    \param b Second operand
    \param ctx BIGNUM context (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *a, *b;
    int ret = wolfSSL_BN_mul(r, a, b, NULL);
    \endcode

    \sa wolfSSL_BN_div
*/
int wolfSSL_BN_mul(WOLFSSL_BIGNUM *r, WOLFSSL_BIGNUM *a,
    WOLFSSL_BIGNUM *b, WOLFSSL_BN_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Divides two BIGNUMs (dv = a / d, rem = a % d).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param dv Quotient result (can be NULL)
    \param rem Remainder result (can be NULL)
    \param a Dividend
    \param d Divisor
    \param ctx BIGNUM context (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM *dv, *rem, *a, *d;
    int ret = wolfSSL_BN_div(dv, rem, a, d, NULL);
    \endcode

    \sa wolfSSL_BN_mul
*/
int wolfSSL_BN_div(WOLFSSL_BIGNUM* dv, WOLFSSL_BIGNUM* rem,
    const WOLFSSL_BIGNUM* a, const WOLFSSL_BIGNUM* d,
    WOLFSSL_BN_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Computes greatest common divisor.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a First operand
    \param b Second operand
    \param ctx BIGNUM context (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *a, *b;
    int ret = wolfSSL_BN_gcd(r, a, b, NULL);
    \endcode

    \sa wolfSSL_BN_mod
*/
int wolfSSL_BN_gcd(WOLFSSL_BIGNUM* r, WOLFSSL_BIGNUM* a,
    WOLFSSL_BIGNUM* b, WOLFSSL_BN_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Computes modulus (r = a % b).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a Dividend
    \param b Modulus
    \param c BIGNUM context (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *a, *b;
    int ret = wolfSSL_BN_mod(r, a, b, NULL);
    \endcode

    \sa wolfSSL_BN_div
*/
int wolfSSL_BN_mod(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* a,
    const WOLFSSL_BIGNUM* b, const WOLFSSL_BN_CTX* c);

/*!
    \ingroup openSSL
    \brief Computes modular multiplication (r = (a * p) % m).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a First operand
    \param p Second operand
    \param m Modulus
    \param ctx BIGNUM context (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *a, *p, *m;
    int ret = wolfSSL_BN_mod_mul(r, a, p, m, NULL);
    \endcode

    \sa wolfSSL_BN_mod_exp
*/
int wolfSSL_BN_mod_mul(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
    const WOLFSSL_BIGNUM *p, const WOLFSSL_BIGNUM *m,
    WOLFSSL_BN_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Returns constant BIGNUM with value 1.

    \return WOLFSSL_BIGNUM pointer to constant value 1

    _Example_
    \code
    const WOLFSSL_BIGNUM* one = wolfSSL_BN_value_one();
    \endcode

    \sa wolfSSL_BN_one
*/
const WOLFSSL_BIGNUM* wolfSSL_BN_value_one(void);

/*!
    \ingroup openSSL
    \brief Returns number of bytes in BIGNUM.

    \return Number of bytes on success
    \return 0 on failure

    \param bn BIGNUM to query

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int bytes = wolfSSL_BN_num_bytes(bn);
    \endcode

    \sa wolfSSL_BN_num_bits
*/
int wolfSSL_BN_num_bytes(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Returns number of bits in BIGNUM.

    \return Number of bits on success
    \return 0 on failure

    \param bn BIGNUM to query

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int bits = wolfSSL_BN_num_bits(bn);
    \endcode

    \sa wolfSSL_BN_num_bytes
*/
int wolfSSL_BN_num_bits(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Sets BIGNUM to zero.

    \return none No returns

    \param bn BIGNUM to set to zero

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    wolfSSL_BN_zero(bn);
    \endcode

    \sa wolfSSL_BN_one
*/
void wolfSSL_BN_zero(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Sets BIGNUM to one.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to set to one

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    int ret = wolfSSL_BN_one(bn);
    \endcode

    \sa wolfSSL_BN_zero
*/
int wolfSSL_BN_one(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Checks if BIGNUM is zero.

    \return 1 if zero
    \return 0 if not zero

    \param bn BIGNUM to check

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    if (wolfSSL_BN_is_zero(bn)) {
        // bn is zero
    }
    \endcode

    \sa wolfSSL_BN_is_one
*/
int wolfSSL_BN_is_zero(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Checks if BIGNUM is one.

    \return 1 if one
    \return 0 if not one

    \param bn BIGNUM to check

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    if (wolfSSL_BN_is_one(bn)) {
        // bn is one
    }
    \endcode

    \sa wolfSSL_BN_is_zero
*/
int wolfSSL_BN_is_one(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Checks if BIGNUM is odd.

    \return 1 if odd
    \return 0 if even

    \param bn BIGNUM to check

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    if (wolfSSL_BN_is_odd(bn)) {
        // bn is odd
    }
    \endcode

    \sa wolfSSL_BN_is_zero
*/
int wolfSSL_BN_is_odd(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Checks if BIGNUM is negative.

    \return 1 if negative
    \return 0 if non-negative

    \param bn BIGNUM to check

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    if (wolfSSL_BN_is_negative(bn)) {
        // bn is negative
    }
    \endcode

    \sa wolfSSL_BN_is_zero
*/
int wolfSSL_BN_is_negative(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Checks if BIGNUM equals word value.

    \return 1 if equal
    \return 0 if not equal

    \param bn BIGNUM to check
    \param w Word value to compare

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    if (wolfSSL_BN_is_word(bn, 42)) {
        // bn equals 42
    }
    \endcode

    \sa wolfSSL_BN_get_word
*/
int wolfSSL_BN_is_word(const WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);

/*!
    \ingroup openSSL
    \brief Compares two BIGNUMs.

    \return 0 if equal
    \return 1 if a > b
    \return -1 if a < b

    \param a First BIGNUM
    \param b Second BIGNUM

    _Example_
    \code
    WOLFSSL_BIGNUM *a, *b;
    int cmp = wolfSSL_BN_cmp(a, b);
    \endcode

    \sa wolfSSL_BN_ucmp
*/
int wolfSSL_BN_cmp(const WOLFSSL_BIGNUM* a, const WOLFSSL_BIGNUM* b);

/*!
    \ingroup openSSL
    \brief Compares absolute values of two BIGNUMs.

    \return 0 if equal
    \return 1 if |a| > |b|
    \return -1 if |a| < |b|

    \param a First BIGNUM
    \param b Second BIGNUM

    _Example_
    \code
    WOLFSSL_BIGNUM *a, *b;
    int cmp = wolfSSL_BN_ucmp(a, b);
    \endcode

    \sa wolfSSL_BN_cmp
*/
int wolfSSL_BN_ucmp(const WOLFSSL_BIGNUM* a, const WOLFSSL_BIGNUM* b);

/*!
    \ingroup openSSL
    \brief Converts BIGNUM to binary.

    \return Number of bytes written on success
    \return negative on failure

    \param bn BIGNUM to convert
    \param r Output buffer

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    unsigned char buf[256];
    int len = wolfSSL_BN_bn2bin(bn, buf);
    \endcode

    \sa wolfSSL_BN_bin2bn
*/
int wolfSSL_BN_bn2bin(const WOLFSSL_BIGNUM* bn, unsigned char* r);

/*!
    \ingroup openSSL
    \brief Converts binary to BIGNUM.

    \return WOLFSSL_BIGNUM pointer on success
    \return NULL on failure

    \param str Binary data
    \param len Length of binary data
    \param ret BIGNUM to store result (can be NULL)

    _Example_
    \code
    unsigned char buf[256];
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_bin2bn(buf, sizeof(buf),
                                           NULL);
    \endcode

    \sa wolfSSL_BN_bn2bin
*/
WOLFSSL_BIGNUM* wolfSSL_BN_bin2bn(const unsigned char* str, int len,
    WOLFSSL_BIGNUM* ret);

/*!
    \ingroup openSSL
    \brief Masks bits in BIGNUM.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to mask
    \param n Number of bits to keep

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_mask_bits(bn, 128);
    \endcode

    \sa wolfSSL_BN_num_bits
*/
int wolfSSL_mask_bits(WOLFSSL_BIGNUM* bn, int n);

/*!
    \ingroup openSSL
    \brief Generates pseudo-random BIGNUM.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to store result
    \param bits Number of bits
    \param top Top bit constraints
    \param bottom Bottom bit constraints

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    int ret = wolfSSL_BN_pseudo_rand(bn, 256, 0, 0);
    \endcode

    \sa wolfSSL_BN_rand
*/
int wolfSSL_BN_pseudo_rand(WOLFSSL_BIGNUM* bn, int bits, int top,
    int bottom);

/*!
    \ingroup openSSL
    \brief Generates random BIGNUM in range.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r BIGNUM to store result
    \param range Upper bound (exclusive)

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *range;
    int ret = wolfSSL_BN_rand_range(r, range);
    \endcode

    \sa wolfSSL_BN_rand
*/
int wolfSSL_BN_rand_range(WOLFSSL_BIGNUM *r,
    const WOLFSSL_BIGNUM *range);

/*!
    \ingroup openSSL
    \brief Generates random BIGNUM.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to store result
    \param bits Number of bits
    \param top Top bit constraints
    \param bottom Bottom bit constraints

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    int ret = wolfSSL_BN_rand(bn, 256, 0, 0);
    \endcode

    \sa wolfSSL_BN_pseudo_rand
*/
int wolfSSL_BN_rand(WOLFSSL_BIGNUM* bn, int bits, int top,
    int bottom);

/*!
    \ingroup openSSL
    \brief Checks if bit is set in BIGNUM.

    \return 1 if bit is set
    \return 0 if bit is not set

    \param bn BIGNUM to check
    \param n Bit position

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    if (wolfSSL_BN_is_bit_set(bn, 5)) {
        // bit 5 is set
    }
    \endcode

    \sa wolfSSL_BN_set_bit
*/
int wolfSSL_BN_is_bit_set(const WOLFSSL_BIGNUM* bn, int n);

/*!
    \ingroup openSSL
    \brief Converts hex string to BIGNUM.

    \return Number of hex digits processed on success
    \return 0 on failure

    \param bn Pointer to BIGNUM pointer
    \param str Hex string

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = NULL;
    int ret = wolfSSL_BN_hex2bn(&bn, "1234ABCD");
    \endcode

    \sa wolfSSL_BN_dec2bn
*/
int wolfSSL_BN_hex2bn(WOLFSSL_BIGNUM** bn, const char* str);

/*!
    \ingroup openSSL
    \brief Duplicates BIGNUM.

    \return WOLFSSL_BIGNUM pointer on success
    \return NULL on failure

    \param bn BIGNUM to duplicate

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    WOLFSSL_BIGNUM* dup = wolfSSL_BN_dup(bn);
    \endcode

    \sa wolfSSL_BN_copy
*/
WOLFSSL_BIGNUM* wolfSSL_BN_dup(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Copies BIGNUM.

    \return WOLFSSL_BIGNUM pointer on success
    \return NULL on failure

    \param r Destination BIGNUM
    \param bn Source BIGNUM

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *bn;
    WOLFSSL_BIGNUM* ret = wolfSSL_BN_copy(r, bn);
    \endcode

    \sa wolfSSL_BN_dup
*/
WOLFSSL_BIGNUM* wolfSSL_BN_copy(WOLFSSL_BIGNUM* r,
    const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Converts decimal string to BIGNUM.

    \return Number of decimal digits processed on success
    \return 0 on failure

    \param bn Pointer to BIGNUM pointer
    \param str Decimal string

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = NULL;
    int ret = wolfSSL_BN_dec2bn(&bn, "12345");
    \endcode

    \sa wolfSSL_BN_bn2dec
*/
int wolfSSL_BN_dec2bn(WOLFSSL_BIGNUM** bn, const char* str);

/*!
    \ingroup openSSL
    \brief Converts BIGNUM to decimal string.

    \return Decimal string on success (must be freed)
    \return NULL on failure

    \param bn BIGNUM to convert

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    char* str = wolfSSL_BN_bn2dec(bn);
    XFREE(str, NULL, DYNAMIC_TYPE_OPENSSL);
    \endcode

    \sa wolfSSL_BN_dec2bn
*/
char* wolfSSL_BN_bn2dec(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Left shifts BIGNUM (r = bn << n).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param bn Source BIGNUM
    \param n Number of bits to shift

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *bn;
    int ret = wolfSSL_BN_lshift(r, bn, 8);
    \endcode

    \sa wolfSSL_BN_rshift
*/
int wolfSSL_BN_lshift(WOLFSSL_BIGNUM* r, const WOLFSSL_BIGNUM* bn,
    int n);

/*!
    \ingroup openSSL
    \brief Adds word to BIGNUM (bn += w).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to modify
    \param w Word value to add

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_BN_add_word(bn, 100);
    \endcode

    \sa wolfSSL_BN_sub_word
*/
int wolfSSL_BN_add_word(WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);

/*!
    \ingroup openSSL
    \brief Subtracts word from BIGNUM (bn -= w).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to modify
    \param w Word value to subtract

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_BN_sub_word(bn, 100);
    \endcode

    \sa wolfSSL_BN_add_word
*/
int wolfSSL_BN_sub_word(WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);

/*!
    \ingroup openSSL
    \brief Multiplies BIGNUM by word (bn *= w).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to modify
    \param w Word value to multiply

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_BN_mul_word(bn, 100);
    \endcode

    \sa wolfSSL_BN_div_word
*/
int wolfSSL_BN_mul_word(WOLFSSL_BIGNUM *bn, WOLFSSL_BN_ULONG w);

/*!
    \ingroup openSSL
    \brief Divides BIGNUM by word (bn /= w).

    \return Remainder on success
    \return WOLFSSL_BN_ULONG_MAX on failure

    \param bn BIGNUM to modify
    \param w Word value to divide by

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    WOLFSSL_BN_ULONG rem = wolfSSL_BN_div_word(bn, 100);
    \endcode

    \sa wolfSSL_BN_mul_word
*/
int wolfSSL_BN_div_word(WOLFSSL_BIGNUM *bn, WOLFSSL_BN_ULONG w);

/*!
    \ingroup openSSL
    \brief Sets bit in BIGNUM.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to modify
    \param n Bit position to set

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_BN_set_bit(bn, 5);
    \endcode

    \sa wolfSSL_BN_clear_bit
*/
int wolfSSL_BN_set_bit(WOLFSSL_BIGNUM* bn, int n);

/*!
    \ingroup openSSL
    \brief Clears bit in BIGNUM.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to modify
    \param n Bit position to clear

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_BN_clear_bit(bn, 5);
    \endcode

    \sa wolfSSL_BN_set_bit
*/
int wolfSSL_BN_clear_bit(WOLFSSL_BIGNUM* bn, int n);

/*!
    \ingroup openSSL
    \brief Sets BIGNUM to word value.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bn BIGNUM to modify
    \param w Word value

    _Example_
    \code
    WOLFSSL_BIGNUM* bn = wolfSSL_BN_new();
    int ret = wolfSSL_BN_set_word(bn, 42);
    \endcode

    \sa wolfSSL_BN_get_word
*/
int wolfSSL_BN_set_word(WOLFSSL_BIGNUM* bn, WOLFSSL_BN_ULONG w);

/*!
    \ingroup openSSL
    \brief Gets word value from BIGNUM.

    \return Word value on success
    \return WOLFSSL_BN_ULONG_MAX on failure

    \param bn BIGNUM to query

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    WOLFSSL_BN_ULONG w = wolfSSL_BN_get_word(bn);
    \endcode

    \sa wolfSSL_BN_set_word
*/
WOLFSSL_BN_ULONG wolfSSL_BN_get_word(const WOLFSSL_BIGNUM* bn);

/*!
    \ingroup openSSL
    \brief Adds two BIGNUMs (r = a + b).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a First operand
    \param b Second operand

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *a, *b;
    int ret = wolfSSL_BN_add(r, a, b);
    \endcode

    \sa wolfSSL_BN_sub
*/
int wolfSSL_BN_add(WOLFSSL_BIGNUM* r, WOLFSSL_BIGNUM* a,
    WOLFSSL_BIGNUM* b);

/*!
    \ingroup openSSL
    \brief Computes modular addition (r = (a + b) % m).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a First operand
    \param b Second operand
    \param m Modulus
    \param ctx BIGNUM context (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *a, *b, *m;
    int ret = wolfSSL_BN_mod_add(r, a, b, m, NULL);
    \endcode

    \sa wolfSSL_BN_mod_mul
*/
int wolfSSL_BN_mod_add(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a,
    const WOLFSSL_BIGNUM *b, const WOLFSSL_BIGNUM *m,
    WOLFSSL_BN_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Generates prime number.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param prime BIGNUM to store prime
    \param bits Number of bits
    \param safe Generate safe prime flag
    \param add Additional constraint (can be NULL)
    \param rem Remainder constraint (can be NULL)
    \param cb Callback (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM* prime = wolfSSL_BN_new();
    int ret = wolfSSL_BN_generate_prime_ex(prime, 256, 0, NULL,
                                           NULL, NULL);
    \endcode

    \sa wolfSSL_BN_is_prime_ex
*/
int wolfSSL_BN_generate_prime_ex(WOLFSSL_BIGNUM* prime, int bits,
    int safe, const WOLFSSL_BIGNUM* add, const WOLFSSL_BIGNUM* rem,
    WOLFSSL_BN_GENCB* cb);

/*!
    \ingroup openSSL
    \brief Tests if BIGNUM is prime.

    \return 1 if probably prime
    \return 0 if composite
    \return negative on error

    \param bn BIGNUM to test
    \param nbchecks Number of Miller-Rabin checks
    \param ctx BIGNUM context (can be NULL)
    \param cb Callback (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_BN_is_prime_ex(bn, 64, NULL, NULL);
    \endcode

    \sa wolfSSL_BN_generate_prime_ex
*/
int wolfSSL_BN_is_prime_ex(const WOLFSSL_BIGNUM *bn, int nbchecks,
    WOLFSSL_BN_CTX *ctx, WOLFSSL_BN_GENCB *cb);

/*!
    \ingroup openSSL
    \brief Computes BIGNUM modulo word (result = bn % w).

    \return Remainder on success
    \return WOLFSSL_BN_ULONG_MAX on failure

    \param bn BIGNUM
    \param w Word divisor

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    WOLFSSL_BN_ULONG rem = wolfSSL_BN_mod_word(bn, 100);
    \endcode

    \sa wolfSSL_BN_div_word
*/
WOLFSSL_BN_ULONG wolfSSL_BN_mod_word(const WOLFSSL_BIGNUM *bn,
    WOLFSSL_BN_ULONG w);

/*!
    \ingroup openSSL
    \brief Prints BIGNUM to file.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param fp File pointer
    \param bn BIGNUM to print

    _Example_
    \code
    WOLFSSL_BIGNUM* bn;
    int ret = wolfSSL_BN_print_fp(stdout, bn);
    \endcode

    \sa wolfSSL_BN_bn2dec
*/
int wolfSSL_BN_print_fp(XFILE fp, const WOLFSSL_BIGNUM *bn);

/*!
    \ingroup openSSL
    \brief Right shifts BIGNUM (r = bn >> n).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param bn Source BIGNUM
    \param n Number of bits to shift

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *bn;
    int ret = wolfSSL_BN_rshift(r, bn, 8);
    \endcode

    \sa wolfSSL_BN_lshift
*/
int wolfSSL_BN_rshift(WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *bn,
    int n);

/*!
    \ingroup openSSL
    \brief Starts BIGNUM context scope.

    \return none No returns

    \param ctx BIGNUM context

    _Example_
    \code
    WOLFSSL_BN_CTX* ctx = wolfSSL_BN_CTX_new();
    wolfSSL_BN_CTX_start(ctx);
    \endcode

    \sa wolfSSL_BN_CTX_new
*/
void wolfSSL_BN_CTX_start(WOLFSSL_BN_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Creates new Montgomery context.

    \return WOLFSSL_BN_MONT_CTX pointer on success
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BN_MONT_CTX* mont = wolfSSL_BN_MONT_CTX_new();
    \endcode

    \sa wolfSSL_BN_MONT_CTX_free
*/
WOLFSSL_BN_MONT_CTX* wolfSSL_BN_MONT_CTX_new(void);

/*!
    \ingroup openSSL
    \brief Frees Montgomery context.

    \return none No returns

    \param mont Montgomery context to free

    _Example_
    \code
    WOLFSSL_BN_MONT_CTX* mont = wolfSSL_BN_MONT_CTX_new();
    // use mont
    wolfSSL_BN_MONT_CTX_free(mont);
    \endcode

    \sa wolfSSL_BN_MONT_CTX_new
*/
void wolfSSL_BN_MONT_CTX_free(WOLFSSL_BN_MONT_CTX *mont);

/*!
    \ingroup openSSL
    \brief Sets Montgomery context modulus.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param mont Montgomery context
    \param mod Modulus BIGNUM
    \param ctx BIGNUM context (can be NULL)

    _Example_
    \code
    WOLFSSL_BN_MONT_CTX* mont;
    WOLFSSL_BIGNUM* mod;
    int ret = wolfSSL_BN_MONT_CTX_set(mont, mod, NULL);
    \endcode

    \sa wolfSSL_BN_MONT_CTX_new
*/
int wolfSSL_BN_MONT_CTX_set(WOLFSSL_BN_MONT_CTX *mont,
    const WOLFSSL_BIGNUM *mod, WOLFSSL_BN_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Computes modular exponentiation with Montgomery (r = a^p % m).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param r Result BIGNUM
    \param a Base word value
    \param p Exponent BIGNUM
    \param m Modulus BIGNUM
    \param ctx BIGNUM context (can be NULL)
    \param mont Montgomery context (can be NULL)

    _Example_
    \code
    WOLFSSL_BIGNUM *r, *p, *m;
    int ret = wolfSSL_BN_mod_exp_mont_word(r, 5, p, m, NULL,
                                           NULL);
    \endcode

    \sa wolfSSL_BN_mod_exp
*/
int wolfSSL_BN_mod_exp_mont_word(WOLFSSL_BIGNUM *r,
    WOLFSSL_BN_ULONG a, const WOLFSSL_BIGNUM *p,
    const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx,
    WOLFSSL_BN_MONT_CTX *mont);
