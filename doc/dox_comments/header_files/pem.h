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

    \brief Reads a PEM private key from a file and returns it as an
    WOLFSSL_EVP_PKEY. The key may be in the traditional form for its algorithm
    or wrapped in PKCS#8, and may be encrypted, in which case the password
    callback is used to obtain the passphrase. RSA, DSA, ECDSA, DH, Ed25519,
    Ed448, X25519, X448 and ML-DSA keys are recognized, subject to the build.

    The X25519 and X448 encodings of RFC 8410 carry the key as the
    little-endian value of RFC 7748, and it is read back that way, so a key
    written by another implementation is read unchanged.

    \return pointer WOLFSSL_EVP_PKEY holding the key on success.
    \return NULL on failure, including a key type this build does not have.

    \param fp file to read the PEM key from.
    \param key optional. When not NULL and pointing at a key, that key is
    filled in rather than a new one created; on success it also receives the
    returned pointer.
    \param cb optional password callback for an encrypted key.
    \param arg optional user data handed to the password callback.

    _Example_
    \code
    XFILE fp = XFOPEN("./key.pem", "rb");
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    XFCLOSE(fp);
    if (pkey == NULL) {
        // could not read the key
    }
    \endcode

    \sa wolfSSL_PEM_read_bio_PrivateKey
    \sa wolfSSL_PEM_read_PUBKEY
    \sa wolfSSL_EVP_PKEY_free
*/
WOLFSSL_EVP_PKEY *wolfSSL_PEM_read_PrivateKey(XFILE fp, WOLFSSL_EVP_PKEY **x,
                                          wc_pem_password_cb *cb, void *u);

/*!
    \ingroup openSSL

    \brief Reads a PEM private key from a BIO. The same encodings and key
    types are accepted as by wolfSSL_PEM_read_PrivateKey().

    \return pointer WOLFSSL_EVP_PKEY holding the key on success.
    \return NULL on failure, including a key type this build does not have.

    \param bio BIO to read the PEM key from.
    \param key optional. When not NULL and pointing at a key, that key is
    filled in rather than a new one created.
    \param cb optional password callback for an encrypted key.
    \param arg optional user data handed to the password callback.

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_file("./key.pem", "rb");
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, NULL,
        NULL);
    wolfSSL_BIO_free(bio);
    \endcode

    \sa wolfSSL_PEM_read_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_PEM_read_bio_PrivateKey(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY** key, wc_pem_password_cb* cb, void* arg);

/*!
    \ingroup openSSL

    \brief Reads a PEM SubjectPublicKeyInfo public key from a file. The key
    types wolfSSL_PEM_read_PrivateKey() accepts are accepted here in their
    public form, X25519 and X448 included.

    \return pointer WOLFSSL_EVP_PKEY holding the key on success.
    \return NULL on failure, including a key type this build does not have.

    \param fp file to read the PEM key from.
    \param key optional. When not NULL and pointing at a key, that key is
    filled in rather than a new one created.
    \param cb optional password callback, unused for a public key.
    \param arg optional user data handed to the password callback.

    \sa wolfSSL_PEM_read_PrivateKey
*/
WOLFSSL_EVP_PKEY *wolfSSL_PEM_read_PUBKEY(XFILE fp, WOLFSSL_EVP_PKEY **x,
                                          wc_pem_password_cb *cb, void *u);
