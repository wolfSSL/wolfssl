/*!
    \ingroup IoTSafe
    \brief This function enables the IoT-Safe support on the given context.

    \param ctx pointer to the WOLFSSL_CTX object on which the IoT-safe support must be enabled
    \return 0 on success
    \return WC_HW_E on hardware error

    _Example_
    \code
    WOLFSSL_CTX *ctx;
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx)
        return NULL;
    wolfSSL_CTX_iotsafe_enable(ctx);
    \endcode

    \sa wolfSSL_iotsafe_on
    \sa wolfIoTSafe_SetCSIM_read_cb
    \sa wolfIoTSafe_SetCSIM_write_cb
*/
WOLFSSL_API int wolfSSL_CTX_iotsafe_enable(WOLFSSL_CTX *ctx);


/*!
    \ingroup IoTSafe
    \brief This function connects the IoT-Safe TLS callbacks to the given SSL session.

    \param ssl pointer to the WOLFSSL object where the callbacks will be enabled
    \param privkey_id id of the iot-safe applet slot containing the private key for the host
    \param ecdh_keypair_slot id of the iot-safe applet slot to store the ECDH keypair
    \param peer_pubkey_slot id of the iot-safe applet slot to store the other endpoint's public key for ECDH
    \param peer_cert_slot id of the iot-safe applet slot to store the other endpoint's public key for verification
    \return 0 upon success
    \return NOT_COMPILED_IN if HAVE_PK_CALLBACKS is disabled
    \return BAD_FUNC_ARG if the ssl pointer is invalid

    _Example_
    \code
    // Define key ids for IoT-Safe
    #define PRIVKEY_ID 0x02
    #define ECDH_KEYPAIR_ID 0x03
    #define PEER_PUBKEY_ID 0x04
    #define PEER_CERT_ID 0x05
    // Create new ssl session
    WOLFSSL *ssl;
    ssl = wolfSSL_new(ctx);
    if (!ssl)
        return NULL;
    // Enable IoT-Safe and associate key slots
    ret = wolfSSL_CTX_iotsafe_on(ssl, PRIVKEY_ID, ECDH_KEYPAIR_ID, PEER_PUBKEY_ID, PEER_CERT_ID);
    \endcode

    \sa wolfSSL_CTX_iotsafe_enable
*/
WOLFSSL_API int wolfSSL_iotsafe_on(WOLFSSL *ssl, byte privkey_id,
       byte ecdh_keypair_slot, byte peer_pubkey_slot, byte peer_cert_slot);


/*!
    \ingroup IoTSafe
    \brief Associates a read callback for the AT+CSIM commands. This input function is
    usually associated to a read event of a UART channel communicating with the modem.
    The read callback associated is global and changes for all the contexts that use
    IoT-safe support at the same time.
    \param rf Read callback associated to a UART read event. The callback function takes
    two arguments (buf, len) and return the number of characters read, up to len. When a
    newline is encountered, the callback should return the number of characters received
    so far, including the newline character.

    _Example_
    \code

    // USART read function, defined elsewhere
    int usart_read(char *buf, int len);

    wolfIoTSafe_SetCSIM_read_cb(usart_read);

    \endcode

    \sa wolfIoTSafe_SetCSIM_write_cb
*/
WOLFSSL_API void wolfIoTSafe_SetCSIM_read_cb(wolfSSL_IOTSafe_CSIM_read_cb rf);

/*!
    \ingroup IoTSafe
    \brief Associates a write callback for the AT+CSIM commands. This output function is
    usually associated to a write event on a UART channel communicating with the modem.
    The write callback associated is global and changes for all the contexts that use
    IoT-safe support at the same time.
    \param rf Write callback associated to a UART write event. The callback function takes
    two arguments (buf, len) and return the number of characters written, up to len.

    _Example_
    \code
    // USART write function, defined elsewhere
    int usart_write(const char *buf, int len);
    wolfIoTSafe_SetCSIM_write_cb(usart_write);
    \endcode

    \sa wolfIoTSafe_SetCSIM_read_cb
*/
WOLFSSL_API void wolfIoTSafe_SetCSIM_write_cb(wolfSSL_IOTSafe_CSIM_write_cb wf);



/*!
    \ingroup IoTSafe
    \brief Generate a random buffer of given size, using the IoT-Safe function
    GetRandom. This function is automatically used by the wolfCrypt RNG object.

    \param out the buffer where the random sequence of bytes is stored.
    \param sz the size of the random sequence to generate, in bytes
    \return 0 upon success

*/
WOLFSSL_API int wolfIoTSafe_GetRandom(unsigned char* out, word32 sz);


/*!
    \ingroup IoTSafe
    \brief Import a certificate stored in a file on IoT-Safe applet, and
    store it locally in memory.

    \param id The file id in the IoT-Safe applet where the certificate is stored
    \param output the buffer where the certificate will be imported
    \param sz the maximum size available in the buffer output
    \return the length of the certificate imported
    \return < 0 in case of failure
    
    _Example_
    \code
    #define CRT_CLIENT_FILE_ID 0x03
    unsigned char cert_buffer[2048];
    // Get the certificate into the buffer
    cert_buffer_size = wolfIoTSafe_GetCert(CRT_CLIENT_FILE_ID, cert_buffer, 2048);
    if (cert_buffer_size < 1) {
        printf("Bad cli cert\n");
        return -1;
    }
    printf("Loaded Client certificate from IoT-Safe, size = %lu\n", cert_buffer_size);
    
    // Use the certificate buffer as identity for the TLS client context
    if (wolfSSL_CTX_use_certificate_buffer(cli_ctx, cert_buffer,
                cert_buffer_size, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        printf("Cannot load client cert\n");
        return -1;
    }
    printf("Client certificate successfully imported.\n");
    \endcode

*/
WOLFSSL_API int wolfIoTSafe_GetCert(uint8_t id, unsigned char *output, unsigned long sz);



/*!
    \ingroup IoTSafe
    \brief Import an ECC 256-bit public key, stored in the IoT-Safe applet, into an ecc_key
    object.

    \param key the ecc_key object that will contain the key imported from the IoT-Safe applet
    \param id The key id in the IoT-Safe applet where the public key is stored
    \return 0 upon success
    \return < 0 in case of failure
    

    \sa wc_iotsafe_ecc_export_public
    \sa wc_iotsafe_ecc_export_private

*/
WOLFSSL_API int wc_iotsafe_ecc_import_public(ecc_key *key, byte key_id);

/*!
    \ingroup IoTSafe
    \brief Export an ECC 256-bit public key, from ecc_key object to a writable public-key slot into the IoT-Safe applet.
    \param key the ecc_key object containing the key to be exported
    \param id The key id in the IoT-Safe applet where the public key will be stored
    \return 0 upon success
    \return < 0 in case of failure
    

    \sa wc_iotsafe_ecc_import_public
    \sa wc_iotsafe_ecc_export_private

*/
WOLFSSL_API int wc_iotsafe_ecc_export_public(ecc_key *key, byte key_id);

/*!
    \ingroup IoTSafe
    \brief Export an ECC 256-bit key, from ecc_key object to a writable private-key slot into the IoT-Safe applet.
    \param key the ecc_key object containing the key to be exported
    \param id The key id in the IoT-Safe applet where the private key will be stored
    \return 0 upon success
    \return < 0 in case of failure
    

    \sa wc_iotsafe_ecc_import_public
    \sa wc_iotsafe_ecc_export_public

*/
WOLFSSL_API int wc_iotsafe_ecc_export_private(ecc_key *key, byte key_id);

/*!
    \ingroup IoTSafe
    \brief Sign a pre-computed 256-bit HASH, using a private key previously stored, or pre-provisioned,
    in the IoT-Safe applet.

    \param in pointer to the buffer containing the message hash to sign
    \param inlen length of the message hash to sign
    \param out buffer in which to store the generated signature
    \param outlen max length of the output buffer. Will store the bytes
    \param id key id in the IoT-Safe applet for the slot containing the private key to sign the payload
    written to out upon successfully generating a message signature
    \return 0 upon success
    \return < 0 in case of failure
    
    \sa wc_iotsafe_ecc_verify_hash
    \sa wc_iotsafe_ecc_gen_k

*/
WOLFSSL_API int wc_iotsafe_ecc_sign_hash(byte *in, word32 inlen, byte *out, word32 *outlen, byte key_id);

/*!
    \ingroup IoTSafe
    \brief Verify an ECC signature against a pre-computed 256-bit HASH, using a public key previously stored, or pre-provisioned,
    in the IoT-Safe applet. Result is written to res. 1 is valid, 0 is invalid.
Note: Do not use the return value to test for valid. Only use res.
    
    \return 0 upon success (even if the signature is not valid)
    \return < 0 in case of failure.

    \param sig  buffer containing the signature to verify
    \param hash The hash (message digest) that was signed
    \param hashlen The length of the hash (octets)
    \param res Result of signature, 1==valid, 0==invalid
    \param key_id The id of the slot where the public ECC key is stored in the IoT-Safe applet
    
    \sa wc_iotsafe_ecc_sign_hash
    \sa wc_iotsafe_ecc_gen_k

*/
WOLFSSL_API int wc_iotsafe_ecc_verify_hash(byte *sig, word32 siglen, byte *hash, word32 hashlen, int *res, byte key_id);

/*!
    \ingroup IoTSafe
    \brief Generate an ECC 256-bit keypair and store it in a (writable) slot into the IoT-Safe applet.
    \param key_id The id of the slot where the ECC key pair is stored in the IoT-Safe applet.
    \return 0 upon success
    \return < 0 in case of failure.

    \sa wc_iotsafe_ecc_sign_hash
    \sa wc_iotsafe_ecc_verify_hash
*/
WOLFSSL_API int wc_iotsafe_ecc_gen_k(byte key_id);

