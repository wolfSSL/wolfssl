/*!
    \ingroup openSSL

    \brief This function writes a key into a WOLFSSL_BIO structure
    in PEM format.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE upon failure.

    \param bio WOLFSSL_BIO structure to get PEM buffer from.
    \param key key to convert to PEM format.
    \param cipher EVP cipher structure.
    \param passwd password.
    \param len length of password.
    \param cb password callback.
    \param arg optional argument.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_EVP_PKEY* key;
    int ret;
    // create bio and setup key
    ret = wolfSSL_PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    //check ret value
    \endcode

    \sa wolfSSL_PEM_read_bio_X509_AUX
*/

int wolfSSL_PEM_write_bio_PrivateKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int len,
                                        wc_pem_password_cb* cb, void* arg);

/*!
    \ingroup openSSL
    \brief Writes RSA private key to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param rsa RSA key
    \param cipher Cipher for encryption (NULL for no encryption)
    \param passwd Password for encryption
    \param len Password length
    \param cb Password callback
    \param arg Callback argument

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0,
                                                  NULL, NULL);
    \endcode

    \sa wolfSSL_PEM_read_bio_RSAPrivateKey
*/
int wolfSSL_PEM_write_bio_RSAPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int len,
                                        wc_pem_password_cb* cb, void* arg);

/*!
    \ingroup openSSL
    \brief Reads RSA private key from BIO in PEM format.

    \return Pointer to RSA key on success
    \return NULL on error

    \param bio BIO to read from
    \param rsa Pointer to RSA pointer (can be NULL)
    \param cb Password callback
    \param pass Password or callback argument

    _Example_
    \code
    WOLFSSL_RSA* rsa = wolfSSL_PEM_read_bio_RSAPrivateKey(bio, NULL, NULL,
                                                          NULL);
    \endcode

    \sa wolfSSL_PEM_write_bio_RSAPrivateKey
*/
WOLFSSL_RSA* wolfSSL_PEM_read_bio_RSAPrivateKey(WOLFSSL_BIO* bio,
                                                WOLFSSL_RSA** rsa,
                                                wc_pem_password_cb* cb,
                                                void* pass);

/*!
    \ingroup openSSL
    \brief Writes RSA public key to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param rsa RSA key

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_RSA_PUBKEY(bio, rsa);
    \endcode

    \sa wolfSSL_PEM_write_bio_RSAPrivateKey
*/
int wolfSSL_PEM_write_bio_RSA_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa);

/*!
    \ingroup openSSL
    \brief Reads EC parameters from BIO in PEM format.

    \return Pointer to EC group on success
    \return NULL on error

    \param bio BIO to read from
    \param group Pointer to EC group pointer (can be NULL)
    \param cb Password callback
    \param pass Password or callback argument

    _Example_
    \code
    WOLFSSL_EC_GROUP* grp = wolfSSL_PEM_read_bio_ECPKParameters(bio, NULL,
                                                                NULL, NULL);
    \endcode

    \sa wolfSSL_i2d_ECPKParameters
*/
WOLFSSL_EC_GROUP* wolfSSL_PEM_read_bio_ECPKParameters(WOLFSSL_BIO* bio,
                                                      WOLFSSL_EC_GROUP** group,
                                                      wc_pem_password_cb* cb,
                                                      void* pass);

/*!
    \ingroup openSSL
    \brief Encodes EC parameters to DER.

    \return Length on success
    \return negative on error

    \param grp EC group
    \param pp Pointer to output buffer pointer

    _Example_
    \code
    unsigned char* der = NULL;
    int len = wolfSSL_i2d_ECPKParameters(grp, &der);
    \endcode

    \sa wolfSSL_PEM_read_bio_ECPKParameters
*/
int wolfSSL_i2d_ECPKParameters(const WOLFSSL_EC_GROUP* grp,
                               unsigned char** pp);

/*!
    \ingroup openSSL
    \brief Writes RSA private key to memory in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param rsa RSA key
    \param cipher Cipher for encryption (NULL for no encryption)
    \param passwd Password for encryption
    \param len Password length
    \param pem Pointer to output buffer pointer
    \param plen Pointer to output length

    _Example_
    \code
    unsigned char* pem = NULL;
    int plen = 0;
    int ret = wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, NULL, NULL, 0, &pem,
                                                  &plen);
    \endcode

    \sa wolfSSL_PEM_write_bio_RSAPrivateKey
*/
int wolfSSL_PEM_write_mem_RSAPrivateKey(WOLFSSL_RSA* rsa,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int len,
                                        unsigned char **pem, int *plen);

/*!
    \ingroup openSSL
    \brief Writes RSA private key to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param rsa RSA key
    \param enc Cipher for encryption (NULL for no encryption)
    \param kstr Password
    \param klen Password length
    \param cb Password callback
    \param u Callback argument

    _Example_
    \code
    FILE* fp = fopen("key.pem", "wb");
    int ret = wolfSSL_PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL,
                                              NULL);
    \endcode

    \sa wolfSSL_PEM_read_RSAPrivateKey
*/
int wolfSSL_PEM_write_RSAPrivateKey(XFILE fp, WOLFSSL_RSA *rsa,
                                    const WOLFSSL_EVP_CIPHER *enc,
                                    unsigned char *kstr, int klen,
                                    wc_pem_password_cb *cb, void *u);

/*!
    \ingroup openSSL
    \brief Reads RSA private key from file in PEM format.

    \return Pointer to RSA key on success
    \return NULL on error

    \param fp File pointer
    \param rsa Pointer to RSA pointer (can be NULL)
    \param cb Password callback
    \param pass Password or callback argument

    _Example_
    \code
    FILE* fp = fopen("key.pem", "rb");
    WOLFSSL_RSA* rsa = wolfSSL_PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    \endcode

    \sa wolfSSL_PEM_write_RSAPrivateKey
*/
WOLFSSL_RSA* wolfSSL_PEM_read_RSAPrivateKey(XFILE fp, WOLFSSL_RSA** rsa,
                                            wc_pem_password_cb* cb,
                                            void* pass);

/*!
    \ingroup openSSL
    \brief Writes RSA public key to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param key RSA key

    _Example_
    \code
    FILE* fp = fopen("pubkey.pem", "wb");
    int ret = wolfSSL_PEM_write_RSAPublicKey(fp, rsa);
    \endcode

    \sa wolfSSL_PEM_write_RSA_PUBKEY
*/
int wolfSSL_PEM_write_RSAPublicKey(XFILE fp, WOLFSSL_RSA* key);

/*!
    \ingroup openSSL
    \brief Writes RSA public key to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param x RSA key

    _Example_
    \code
    FILE* fp = fopen("pubkey.pem", "wb");
    int ret = wolfSSL_PEM_write_RSA_PUBKEY(fp, rsa);
    \endcode

    \sa wolfSSL_PEM_write_RSAPublicKey
*/
int wolfSSL_PEM_write_RSA_PUBKEY(XFILE fp, WOLFSSL_RSA *x);

/*!
    \ingroup openSSL
    \brief Writes DSA private key to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param dsa DSA key
    \param cipher Cipher for encryption (NULL for no encryption)
    \param passwd Password for encryption
    \param len Password length
    \param cb Password callback
    \param arg Callback argument

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_DSAPrivateKey(bio, dsa, NULL, NULL, 0,
                                                  NULL, NULL);
    \endcode

    \sa wolfSSL_PEM_read_bio_DSAPrivateKey
*/
int wolfSSL_PEM_write_bio_DSAPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_DSA* dsa,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int len,
                                        wc_pem_password_cb* cb, void* arg);

/*!
    \ingroup openSSL
    \brief Reads DSA private key from BIO in PEM format.

    \return Pointer to DSA key on success
    \return NULL on error

    \param bio BIO to read from
    \param dsa Pointer to DSA pointer (can be NULL)
    \param cb Password callback
    \param pass Password or callback argument

    _Example_
    \code
    WOLFSSL_DSA* dsa = wolfSSL_PEM_read_bio_DSAPrivateKey(bio, NULL, NULL,
                                                          NULL);
    \endcode

    \sa wolfSSL_PEM_write_bio_DSAPrivateKey
*/
WOLFSSL_DSA* wolfSSL_PEM_read_bio_DSAPrivateKey(WOLFSSL_BIO* bio,
                                                WOLFSSL_DSA** dsa,
                                                wc_pem_password_cb* cb,
                                                void *pass);

/*!
    \ingroup openSSL
    \brief Writes DSA public key to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param dsa DSA key

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_DSA_PUBKEY(bio, dsa);
    \endcode

    \sa wolfSSL_PEM_write_bio_DSAPrivateKey
*/
int wolfSSL_PEM_write_bio_DSA_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_DSA* dsa);

/*!
    \ingroup openSSL
    \brief Writes DSA private key to memory in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param dsa DSA key
    \param cipher Cipher for encryption (NULL for no encryption)
    \param passwd Password for encryption
    \param len Password length
    \param pem Pointer to output buffer pointer
    \param plen Pointer to output length

    _Example_
    \code
    unsigned char* pem = NULL;
    int plen = 0;
    int ret = wolfSSL_PEM_write_mem_DSAPrivateKey(dsa, NULL, NULL, 0, &pem,
                                                  &plen);
    \endcode

    \sa wolfSSL_PEM_write_bio_DSAPrivateKey
*/
int wolfSSL_PEM_write_mem_DSAPrivateKey(WOLFSSL_DSA* dsa,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int len,
                                        unsigned char **pem, int *plen);

/*!
    \ingroup openSSL
    \brief Writes DSA private key to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param dsa DSA key
    \param enc Cipher for encryption (NULL for no encryption)
    \param kstr Password
    \param klen Password length
    \param cb Password callback
    \param u Callback argument

    _Example_
    \code
    FILE* fp = fopen("dsa.pem", "wb");
    int ret = wolfSSL_PEM_write_DSAPrivateKey(fp, dsa, NULL, NULL, 0, NULL,
                                              NULL);
    \endcode

    \sa wolfSSL_PEM_write_bio_DSAPrivateKey
*/
int wolfSSL_PEM_write_DSAPrivateKey(XFILE fp, WOLFSSL_DSA *dsa,
                                    const WOLFSSL_EVP_CIPHER *enc,
                                    unsigned char *kstr, int klen,
                                    wc_pem_password_cb *cb, void *u);

/*!
    \ingroup openSSL
    \brief Writes DSA public key to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param x DSA key

    _Example_
    \code
    FILE* fp = fopen("dsa_pub.pem", "wb");
    int ret = wolfSSL_PEM_write_DSA_PUBKEY(fp, dsa);
    \endcode

    \sa wolfSSL_PEM_write_bio_DSA_PUBKEY
*/
int wolfSSL_PEM_write_DSA_PUBKEY(XFILE fp, WOLFSSL_DSA *x);

/*!
    \ingroup openSSL
    \brief Writes EC private key to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param ec EC key
    \param cipher Cipher for encryption (NULL for no encryption)
    \param passwd Password for encryption
    \param len Password length
    \param cb Password callback
    \param arg Callback argument

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0,
                                                 NULL, NULL);
    \endcode

    \sa wolfSSL_PEM_read_bio_ECPrivateKey
*/
int wolfSSL_PEM_write_bio_ECPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_EC_KEY* ec,
                                       const WOLFSSL_EVP_CIPHER* cipher,
                                       unsigned char* passwd, int len,
                                       wc_pem_password_cb* cb, void* arg);

/*!
    \ingroup openSSL
    \brief Reads EC private key from BIO in PEM format.

    \return Pointer to EC key on success
    \return NULL on error

    \param bio BIO to read from
    \param ec Pointer to EC key pointer (can be NULL)
    \param cb Password callback
    \param pass Password or callback argument

    _Example_
    \code
    WOLFSSL_EC_KEY* ec = wolfSSL_PEM_read_bio_ECPrivateKey(bio, NULL, NULL,
                                                           NULL);
    \endcode

    \sa wolfSSL_PEM_write_bio_ECPrivateKey
*/
WOLFSSL_EC_KEY* wolfSSL_PEM_read_bio_ECPrivateKey(WOLFSSL_BIO* bio,
                                                  WOLFSSL_EC_KEY** ec,
                                                  wc_pem_password_cb* cb,
                                                  void *pass);

/*!
    \ingroup openSSL
    \brief Writes EC public key to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param ec EC key

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_EC_PUBKEY(bio, ec);
    \endcode

    \sa wolfSSL_PEM_write_bio_ECPrivateKey
*/
int wolfSSL_PEM_write_bio_EC_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_EC_KEY* ec);

/*!
    \ingroup openSSL
    \brief Writes EC private key to memory in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param key EC key
    \param cipher Cipher for encryption (NULL for no encryption)
    \param passwd Password for encryption
    \param len Password length
    \param pem Pointer to output buffer pointer
    \param plen Pointer to output length

    _Example_
    \code
    unsigned char* pem = NULL;
    int plen = 0;
    int ret = wolfSSL_PEM_write_mem_ECPrivateKey(ec, NULL, NULL, 0, &pem,
                                                 &plen);
    \endcode

    \sa wolfSSL_PEM_write_bio_ECPrivateKey
*/
int wolfSSL_PEM_write_mem_ECPrivateKey(WOLFSSL_EC_KEY* key,
                                       const WOLFSSL_EVP_CIPHER* cipher,
                                       unsigned char* passwd, int len,
                                       unsigned char **pem, int *plen);

/*!
    \ingroup openSSL
    \brief Writes EC private key to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param key EC key
    \param enc Cipher for encryption (NULL for no encryption)
    \param kstr Password
    \param klen Password length
    \param cb Password callback
    \param u Callback argument

    _Example_
    \code
    FILE* fp = fopen("ec.pem", "wb");
    int ret = wolfSSL_PEM_write_ECPrivateKey(fp, ec, NULL, NULL, 0, NULL,
                                             NULL);
    \endcode

    \sa wolfSSL_PEM_read_bio_ECPrivateKey
*/
int wolfSSL_PEM_write_ECPrivateKey(XFILE fp, WOLFSSL_EC_KEY *key,
                                   const WOLFSSL_EVP_CIPHER *enc,
                                   unsigned char *kstr, int klen,
                                   wc_pem_password_cb *cb, void *u);

/*!
    \ingroup openSSL
    \brief Writes EC public key to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param key EC key

    _Example_
    \code
    FILE* fp = fopen("ec_pub.pem", "wb");
    int ret = wolfSSL_PEM_write_EC_PUBKEY(fp, ec);
    \endcode

    \sa wolfSSL_PEM_write_bio_EC_PUBKEY
*/
int wolfSSL_PEM_write_EC_PUBKEY(XFILE fp, WOLFSSL_EC_KEY* key);

/*!
    \ingroup openSSL
    \brief Reads EC public key from BIO in PEM format.

    \return Pointer to EC key on success
    \return NULL on error

    \param bio BIO to read from
    \param ec Pointer to EC key pointer (can be NULL)
    \param cb Password callback
    \param pass Password or callback argument

    _Example_
    \code
    WOLFSSL_EC_KEY* ec = wolfSSL_PEM_read_bio_EC_PUBKEY(bio, NULL, NULL,
                                                        NULL);
    \endcode

    \sa wolfSSL_PEM_write_bio_EC_PUBKEY
*/
WOLFSSL_EC_KEY* wolfSSL_PEM_read_bio_EC_PUBKEY(WOLFSSL_BIO* bio,
                                               WOLFSSL_EC_KEY** ec,
                                               wc_pem_password_cb* cb,
                                               void *pass);

/*!
    \ingroup openSSL
    \brief Reads private key from BIO in PEM format.

    \return Pointer to EVP_PKEY on success
    \return NULL on error

    \param bio BIO to read from
    \param key Pointer to EVP_PKEY pointer (can be NULL)
    \param cb Password callback
    \param pass Password or callback argument

    _Example_
    \code
    WOLFSSL_EVP_PKEY* key = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, NULL,
                                                            NULL);
    \endcode

    \sa wolfSSL_PEM_write_bio_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_PEM_read_bio_PrivateKey(WOLFSSL_BIO* bio,
                                                  WOLFSSL_EVP_PKEY** key,
                                                  wc_pem_password_cb* cb,
                                                  void* pass);

/*!
    \ingroup openSSL
    \brief Reads PKCS8 private key info from BIO in PEM format.

    \return Pointer to PKCS8_PRIV_KEY_INFO on success
    \return NULL on error

    \param bio BIO to read from
    \param key Pointer to PKCS8_PRIV_KEY_INFO pointer (can be NULL)
    \param cb Password callback
    \param arg Callback argument

    _Example_
    \code
    WOLFSSL_PKCS8_PRIV_KEY_INFO* p8 =
        wolfSSL_PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio, NULL, NULL, NULL);
    \endcode

    \sa wolfSSL_PEM_read_bio_PrivateKey
*/
WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_PEM_read_bio_PKCS8_PRIV_KEY_INFO(WOLFSSL_BIO* bio,
                                                                       WOLFSSL_PKCS8_PRIV_KEY_INFO** key,
                                                                       wc_pem_password_cb* cb,
                                                                       void* arg);

/*!
    \ingroup openSSL
    \brief Writes public key to BIO in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param key EVP_PKEY

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_PUBKEY(bio, key);
    \endcode

    \sa wolfSSL_PEM_write_bio_PrivateKey
*/
int wolfSSL_PEM_write_bio_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key);

/*!
    \ingroup openSSL
    \brief Reads PEM data from BIO.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to read from
    \param name Pointer to store PEM name
    \param header Pointer to store PEM header
    \param data Pointer to store PEM data
    \param len Pointer to store data length

    _Example_
    \code
    char *name, *header;
    unsigned char *data;
    long len;
    int ret = wolfSSL_PEM_read_bio(bio, &name, &header, &data, &len);
    \endcode

    \sa wolfSSL_PEM_write_bio
*/
int wolfSSL_PEM_read_bio(WOLFSSL_BIO* bio, char **name, char **header,
                         unsigned char **data, long *len);

/*!
    \ingroup openSSL
    \brief Writes PEM data to BIO.

    \return 1 on success
    \return 0 or negative on error

    \param bio BIO to write to
    \param name PEM name
    \param header PEM header
    \param data PEM data
    \param len Data length

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio(bio, "CERTIFICATE", "", data, len);
    \endcode

    \sa wolfSSL_PEM_read_bio
*/
int wolfSSL_PEM_write_bio(WOLFSSL_BIO *bio, const char *name,
                          const char *header, const unsigned char *data,
                          long len);

/*!
    \ingroup openSSL
    \brief Reads PEM data from file.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param name Pointer to store PEM name
    \param header Pointer to store PEM header
    \param data Pointer to store PEM data
    \param len Pointer to store data length

    _Example_
    \code
    FILE* fp = fopen("cert.pem", "rb");
    char *name, *header;
    unsigned char *data;
    long len;
    int ret = wolfSSL_PEM_read(fp, &name, &header, &data, &len);
    \endcode

    \sa wolfSSL_PEM_write
*/
int wolfSSL_PEM_read(XFILE fp, char **name, char **header,
                     unsigned char **data, long *len);

/*!
    \ingroup openSSL
    \brief Writes PEM data to file.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param name PEM name
    \param header PEM header
    \param data PEM data
    \param len Data length

    _Example_
    \code
    FILE* fp = fopen("cert.pem", "wb");
    int ret = wolfSSL_PEM_write(fp, "CERTIFICATE", "", data, len);
    \endcode

    \sa wolfSSL_PEM_read
*/
int wolfSSL_PEM_write(XFILE fp, const char *name, const char *header,
                      const unsigned char *data, long len);

/*!
    \ingroup openSSL
    \brief Writes X509 certificate to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param x X509 certificate

    _Example_
    \code
    FILE* fp = fopen("cert.pem", "wb");
    int ret = wolfSSL_PEM_write_X509(fp, x509);
    \endcode

    \sa wolfSSL_PEM_write_bio
*/
int wolfSSL_PEM_write_X509(XFILE fp, WOLFSSL_X509 *x);

/*!
    \ingroup openSSL
    \brief Writes DH parameters to file in PEM format.

    \return 1 on success
    \return 0 or negative on error

    \param fp File pointer
    \param dh DH parameters

    _Example_
    \code
    FILE* fp = fopen("dhparams.pem", "wb");
    int ret = wolfSSL_PEM_write_DHparams(fp, dh);
    \endcode

    \sa wolfSSL_PEM_write_bio
*/
int wolfSSL_PEM_write_DHparams(XFILE fp, WOLFSSL_DH* dh);
