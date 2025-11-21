/*!
    \brief This function initializes the DTLS v1.2 client method.

    \return pointer This function returns a pointer to a new
    WOLFSSL_METHOD structure.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    …
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    \endcode

    \sa wolfSSL_Init
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_client_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function returns a WOLFSSL_METHOD similar to
    wolfSSLv23_client_method except that it is not determined
    which side yet (server/client).

    \return WOLFSSL_METHOD* On successful creations returns a WOLFSSL_METHOD
    pointer
    \return NULL Null if memory allocation error or failure to create method

    \param none No parameters.

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfSSLv23_method());
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfSSLv23_method(void);

/*!
    \ingroup Setup

    \brief Returns WOLFSSL_METHOD for SSLv23 client with version flexibility.

    \return WOLFSSL_METHOD* Pointer to newly created method structure
    \return NULL on memory allocation failure

    \param none No parameters

    _Example_
    \code
    WOLFSSL_METHOD* method = wolfSSLv23_client_method();
    if (method == NULL) {
        // handle error
    }
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    \endcode

    \sa wolfSSLv23_server_method
    \sa wolfSSLv23_method
*/
WOLFSSL_METHOD* wolfSSLv23_client_method(void);

/*!
    \ingroup Setup

    \brief Returns WOLFSSL_METHOD for SSLv2 client (deprecated).

    \return WOLFSSL_METHOD* Pointer to newly created method structure
    \return NULL on memory allocation failure

    \param none No parameters

    _Example_
    \code
    WOLFSSL_METHOD* method = wolfSSLv2_client_method();
    if (method == NULL) {
        // handle error
    }
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    \endcode

    \sa wolfSSLv2_server_method
*/
WOLFSSL_METHOD* wolfSSLv2_client_method(void);

/*!
    \ingroup Setup

    \brief Returns WOLFSSL_METHOD for SSLv2 server (deprecated).

    \return WOLFSSL_METHOD* Pointer to newly created method structure
    \return NULL on memory allocation failure

    \param none No parameters

    _Example_
    \code
    WOLFSSL_METHOD* method = wolfSSLv2_server_method();
    if (method == NULL) {
        // handle error
    }
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    \endcode

    \sa wolfSSLv2_client_method
*/
WOLFSSL_METHOD* wolfSSLv2_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfSSLv3_server_method() function is used to indicate
    that the application is a server and will only support the SSL 3.0
    protocol.  This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the
    failure value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new

*/
WOLFSSL_METHOD *wolfSSLv3_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfSSLv3_client_method() function is used to indicate
    that the application is a client and will only support the SSL 3.0
    protocol.  This function allocates memory for and initializes a
    new wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the
    failure value of the underlying malloc() implementation will be
    returned (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_server_method() function is used to indicate that the
    application is a server and will only support the TLS 1.0 protocol. This
    function allocates memory for and initializes a new wolfSSL_METHOD
    structure to be used when creating the SSL/TLS context with
    wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_client_method() function is used to indicate
    that the application is a client and will only support the TLS 1.0
    protocol.  This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC,
    the failure value of the underlying malloc() implementation
    will be returned (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_1_server_method() function is used to indicate
    that the application is a server and will only support the TLS 1.1
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_server_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_1_client_method() function is used to indicate
    that the application is a client and will only support the TLS 1.0
    protocol. This function allocates memory for and initializes a
    new wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the
    newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_client_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_2_server_method() function is used to indicate
    that the application is a server and will only support the TLS 1.2
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_2_client_method() function is used to indicate
    that the application is a client and will only support the TLS 1.2
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfDTLSv1_client_method() function is used to indicate that
    the application is a client and will only support the DTLS 1.0 protocol.
    This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new(). This function is only available when wolfSSL has
    been compiled with DTLS support (--enable-dtls,
    or by defining wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfDTLSv1_server_method() function is used to indicate
    that the application is a server and will only support the DTLS 1.0
    protocol.  This function allocates memory for and initializes a
    new wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new(). This function is only available
    when wolfSSL has been compiled with DTLS support (--enable-dtls,
    or by defining wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_server_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLSv1_3_server_method() function is used to indicate that
    the application is a server and will only support the DTLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context with
    wolfSSL_CTX_new(). This function is only available when wolfSSL has been
    compiled with DTLSv1.3 support (--enable-dtls13, or by defining
    wolfSSL_DTLS13).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_client_method
*/

WOLFSSL_METHOD *wolfDTLSv1_3_server_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLSv1_3_client_method() function is used to indicate that
    the application is a client and will only support the DTLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context with
    wolfSSL_CTX_new(). This function is only available when wolfSSL has been
    compiled with DTLSv1.3 support (--enable-dtls13, or by defining
    wolfSSL_DTLS13).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_server_method
*/
WOLFSSL_METHOD* wolfDTLSv1_3_client_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLS_server_method() function is used to indicate that the
    application is a server and will support the highest version of DTLS
    available and all the version up to the minimum version allowed.  The
    default minimum version allowed is based on the define
    WOLFSSL_MIN_DTLS_DOWNGRADE and can be changed at runtime using
    wolfSSL_SetMinVersion(). This function allocates memory for and initializes
    a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new(). This function is only available when wolfSSL has
    been compiled with DTLS support (--enable-dtls, or by defining
    wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLS_client_method
    \sa wolfSSL_SetMinVersion
*/
WOLFSSL_METHOD *wolfDTLS_server_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLS_client_method() function is used to indicate that the
    application is a client and will support the highest version of DTLS
    available and all the version up to the minimum version allowed.  The
    default minimum version allowed is based on the define
    WOLFSSL_MIN_DTLS_DOWNGRADE and can be changed at runtime using
    wolfSSL_SetMinVersion(). This function allocates memory for and initializes
    a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new(). This function is only available when wolfSSL has
    been compiled with DTLS support (--enable-dtls, or by defining
    wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLS_server_method
    \sa wolfSSL_SetMinVersion
*/
WOLFSSL_METHOD *wolfDTLS_client_method(void);
/*!
    \brief This function creates and initializes a WOLFSSL_METHOD for the
    server side.

    \return This function returns a WOLFSSL_METHOD pointer.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);

/*!
    \ingroup Setup

    \brief Since there is some differences between the first release and
    newer versions of chacha-poly AEAD construction we have added an option
    to communicate with servers/clients using the older version. By default
    wolfSSL uses the new version.

    \return 0 upon success

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param value whether or not to use the older version of setting up the
    information for poly1305. Passing a flag value of 1 indicates yes use the
    old poly AEAD, to switch back to using the new version pass a flag value
    of 0.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_use_old_poly(ssl, 1);
    if (ret != 0) {
        // failed to set poly1305 AEAD version
    }
    \endcode

    \sa none
*/
int wolfSSL_use_old_poly(WOLFSSL* ssl, int value);

/*!
    \brief The wolfSSL_dtls_import() function is used to parse in a serialized
    session state. This allows for picking up the connection after the
    handshake has been completed.

    \return Success If successful, the amount of the buffer read will be
    returned.
    \return Failure All unsuccessful return values will be less than 0.
    \return VERSION_ERROR If a version mismatch is found ie DTLS v1 and ctx
    was set up for DTLS v1.2 then VERSION_ERROR is returned.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf serialized session to import.
    \param sz size of serialized session buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    //get information sent from wc_dtls_export function and place it in buf
    fread(buf, 1, bufSz, input);
    ret = wolfSSL_dtls_import(ssl, buf, bufSz);
    if (ret < 0) {
    // handle error case
    }
    // no wolfSSL_accept needed since handshake was already done
    ...
    ret = wolfSSL_write(ssl) and wolfSSL_read(ssl);
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
int wolfSSL_dtls_import(WOLFSSL* ssl, unsigned char* buf,
                                                               unsigned int sz);


/*!
    \brief Used to import a serialized TLS session. This function is for
    importing the state of the connection.
    WARNING: buf contains sensitive information about the state and is best to
    be encrypted before storing if stored.
    Additional debug info can be displayed with the macro
    WOLFSSL_SESSION_EXPORT_DEBUG defined.

    \return the number of bytes read from buffer 'buf'

    \param ssl WOLFSSL structure to import the session into
    \param buf serialized session
    \param sz  size of buffer 'buf'

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_export
 */
int wolfSSL_tls_import(WOLFSSL* ssl, const unsigned char* buf,
        unsigned int sz);

/*!
    \brief The wolfSSL_CTX_dtls_set_export() function is used to set
    the callback function for exporting a session. It is allowed to
    pass in NULL as the parameter func to clear the export function
    previously stored. Used on the server side and is called immediately
    after handshake is completed.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG If null or not expected arguments are passed in

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param func wc_dtls_export function to use when exporting a session.

    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passes
    // buf (serialized session) to destination
    WOLFSSL_CTX* ctx;
    int ret;
    ...
    ret = wolfSSL_CTX_dtls_set_export(ctx, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_dtls_set_export
    \sa Static buffer use
*/
int wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx,
                                                           wc_dtls_export func);

/*!
    \brief The wolfSSL_dtls_set_export() function is used to set the callback
    function for exporting a session. It is allowed to pass in NULL as the
    parameter func to clear the export function previously stored. Used on
    the server side and is called immediately after handshake is completed.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG If null or not expected arguments are passed in

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param func wc_dtls_export function to use when exporting a session.

    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passes
    // buf (serialized session) to destination
    WOLFSSL* ssl;
    int ret;
    ...
    ret = wolfSSL_dtls_set_export(ssl, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
int wolfSSL_dtls_set_export(WOLFSSL* ssl, wc_dtls_export func);

/*!
    \brief The wolfSSL_dtls_export() function is used to serialize a
    WOLFSSL session into the provided buffer. Allows for less memory
    overhead than using a function callback for sending a session and
    choice over when the session is serialized. If buffer is NULL when
    passed to function then sz will be set to the size of buffer needed
    for serializing the WOLFSSL session.

    \return Success If successful, the amount of the buffer used will
    be returned.
    \return Failure All unsuccessful return values will be less than 0.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf buffer to hold serialized session.
    \param sz size of buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    ret = wolfSSL_dtls_export(ssl, buf, bufSz);
    if (ret < 0) {
        // handle error case
    }
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
    \sa wolfSSL_dtls_import
*/
int wolfSSL_dtls_export(WOLFSSL* ssl, unsigned char* buf,
                                                              unsigned int* sz);

/*!
    \brief Used to export a serialized TLS session. This function is for
    exporting a serialized state of the connection.
    In most cases wolfSSL_get1_session should be used instead of
    wolfSSL_tls_export.
    Additional debug info can be displayed with the macro
    WOLFSSL_SESSION_EXPORT_DEBUG defined.
    WARNING: buf contains sensitive information about the state and is best to
             be encrypted before storing if stored.

    \return the number of bytes written into buffer 'buf'

    \param ssl WOLFSSL structure to export the session from
    \param buf output of serialized session
    \param sz  size in bytes set in 'buf'

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_import
 */
int wolfSSL_tls_export(WOLFSSL* ssl, unsigned char* buf,
        unsigned int* sz);

/*!
    \brief This function is used to set aside static memory for a CTX. Memory
    set aside is then used for the CTX’s lifetime and for any SSL objects
    created from the CTX. By passing in a NULL ctx pointer and a
    wolfSSL_method_func function the creation of the CTX itself will also
    use static memory. wolfSSL_method_func has the function signature of
    WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);. Passing in 0 for max
    makes it behave as if not set and no max concurrent use restrictions is
    in place. The flag value passed in determines how the memory is used and
    behavior while operating. Available flags are the following: 0 - default
    general memory, WOLFMEM_IO_POOL - used for input/output buffer when
    sending receiving messages and overrides general memory, so all memory
    in buffer passed in is used for IO, WOLFMEM_IO_FIXED - same as
    WOLFMEM_IO_POOL but each SSL now keeps two buffers to themselves for
    their lifetime, WOLFMEM_TRACK_STATS - each SSL keeps track of memory
    stats while running.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE upon failure.

    \param ctx address of pointer to a WOLFSSL_CTX structure.
    \param method function to create protocol. (should be NULL if ctx is not
    also NULL)
    \param buf memory to use for all operations.
    \param sz size of memory buffer being passed in.
    \param flag type of memory.
    \param max max concurrent operations.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    unsigned char IO[MAX];
    int IOSz = MAX;
    int flag = WOLFMEM_IO_FIXED | WOLFMEM_TRACK_STATS;
    ...
    // create ctx also using static memory, start with general memory to use
    ctx = NULL:
    ret = wolfSSL_CTX_load_static_memory(&ctx, wolfSSLv23_server_method_ex,
    memory, memorySz, 0,    MAX_CONCURRENT_HANDSHAKES);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    // load in memory for use with IO
    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL, IO, IOSz, flag,
    MAX_CONCURRENT_IO);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    ...
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_is_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx,
                                            wolfSSL_method_func method,
                                            unsigned char* buf, unsigned int sz,
                                            int flag, int max);

/*!
    \brief This function does not change any of the connections behavior
    and is used only for gathering information about the static memory usage.

    \return 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param mem_stats structure to hold information about static memory usage.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int ret;
    WOLFSSL_MEM_STATS mem_stats;
    ...
    //get information about static memory with CTX
    ret = wolfSSL_CTX_is_static_memory(ctx, &mem_stats);
    if (ret == 1) {
        // handle case of is using static memory
        // print out or inspect elements of mem_stats
    }
    if (ret == 0) {
        //handle case of ctx not using static memory
    }
    …
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_load_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx,
                                                 WOLFSSL_MEM_STATS* mem_stats);

/*!
    \brief wolfSSL_is_static_memory is used to gather information about
    a SSL’s static memory usage. The return value indicates if static
    memory is being used and WOLFSSL_MEM_CONN_STATS will be filled out
    if and only if the flag WOLFMEM_TRACK_STATS was passed to the parent
    CTX when loading in static memory.

    \return 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param mem_stats structure to contain static memory usage.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    WOLFSSL_MEM_CONN_STATS mem_stats;
    ...
    ret = wolfSSL_is_static_memory(ssl, mem_stats);
    if (ret == 1) {
        // handle case when is static memory
        // investigate elements in mem_stats if WOLFMEM_TRACK_STATS flag
    }
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_is_static_memory
*/
int wolfSSL_is_static_memory(WOLFSSL* ssl,
                                            WOLFSSL_MEM_CONN_STATS* mem_stats);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate file into the SSL context
    (WOLFSSL_CTX).  The file is provided by the file argument. The
    format argument specifies the format type of the file, either
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please see the examples
    for proper usage.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes might
    include the file is in the wrong format, or the wrong format has been
    given using the “format” argument, file doesn’t exist, can’t be read,
    or is corrupted, an out of memory condition occurs, Base16 decoding
    fails on the file.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the certificate
    to be loaded into the wolfSSL SSL context.
    \param format - format of the certificates pointed to by file. Possible
    options are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_file(ctx, “./client-cert.pem”,
                                     SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX* ctx, const char* file,
                                     int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a private key file into the SSL context
    (WOLFSSL_CTX). The file is provided by the file argument. The format
    argument specifies the format type of the file - SSL_FILETYPE_ASN1or
    SSL_FILETYPE_PEM.  Please see the examples for proper usage.

    If using an external key store and do not have the private key you can
    instead provide the public key and register the crypro callback to handle
    the signing. For this you can build with either build with crypto callbacks
    or PK callbacks. To enable crypto callbacks use --enable-cryptocb
    or WOLF_CRYPTO_CB and register a crypto callback using
    wc_CryptoCb_RegisterDevice and set the associated devId using
    wolfSSL_CTX_SetDevId.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE The file is in the wrong format, or the wrong format
    has been given using the “format” argument. The file doesn’t exist, can’t
    be read, or is corrupted. An out of memory condition occurs. Base16
    decoding fails on the file. The key file is encrypted but no password
    is provided.

    \param none No parameters.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, “./server-key.pem”,
                                    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wc_CryptoCb_RegisterDevice
    \sa wolfSSL_CTX_SetDevId
*/
int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX* ctx, const char* file, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads PEM-formatted CA certificate files into the SSL
    context (WOLFSSL_CTX).  These certificates will be treated as trusted root
    certificates and used to verify certs received from peers during the SSL
    handshake. The root certificate file, provided by the file argument, may
    be a single certificate or a file containing multiple certificates.
    If multiple CA certs are included in the same file, wolfSSL will load them
    in the same order they are presented in the file.  The path argument is
    a pointer to the name of a directory that contains certificates of
    trusted root CAs. If the value of file is not NULL, path may be specified
    as NULL if not needed.  If path is specified and NO_WOLFSSL_DIR was not
    defined when building the library, wolfSSL will load all CA certificates
    located in the given directory. This function will attempt to load all
    files in the directory. This function expects PEM formatted CERT_TYPE
    file with header “-----BEGIN CERTIFICATE-----”.

    \return SSL_SUCCESS up success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    path are NULL.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before the
    before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after the
    after date.
    \return BUFFER_E will be returned if a chain buffer is bigger than the
    receiving buffer.
    \return BAD_PATH_ERROR will be returned if opendir() fails when trying
    to open path.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing PEM-formatted CA
    certificates.
    \param path pointer to the name of a directory to load PEM-formatted
    certificates from.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations(ctx, “./ca-cert.pem”, NULL);
    if (ret != WOLFSSL_SUCCESS) {
    	// error loading CA certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations_ex
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX* ctx, const char* file,
                                                const char* path);

/*!
    \ingroup CertsKeys

    \brief This function loads PEM-formatted CA certificate files into the SSL
    context (WOLFSSL_CTX).  These certificates will be treated as trusted root
    certificates and used to verify certs received from peers during the SSL
    handshake. The root certificate file, provided by the file argument, may
    be a single certificate or a file containing multiple certificates.
    If multiple CA certs are included in the same file, wolfSSL will load them
    in the same order they are presented in the file.  The path argument is
    a pointer to the name of a directory that contains certificates of
    trusted root CAs. If the value of file is not NULL, path may be specified
    as NULL if not needed.  If path is specified and NO_WOLFSSL_DIR was not
    defined when building the library, wolfSSL will load all CA certificates
    located in the given directory. This function will attempt to load all
    files in the directory based on flags specified. This function expects PEM
    formatted CERT_TYPE files with header “-----BEGIN CERTIFICATE-----”.

    \return SSL_SUCCESS up success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    path are NULL. This will also be returned if at least one cert is loaded
    successfully but there is one or more that failed. Check error stack for reason.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than the
    receiving buffer.
    \return BAD_PATH_ERROR will be returned if opendir() fails when trying
    to open path.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing PEM-formatted CA
    certificates.
    \param path pointer to the name of a directory to load PEM-formatted
    certificates from.
    \param flags possible mask values are: WOLFSSL_LOAD_FLAG_IGNORE_ERR,
    WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY and WOLFSSL_LOAD_FLAG_PEM_CA_ONLY

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations_ex(ctx, NULL, “./certs/external",
        WOLFSSL_LOAD_FLAG_PEM_CA_ONLY);
    if (ret != WOLFSSL_SUCCESS) {
        // error loading CA certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_load_verify_locations_ex(WOLFSSL_CTX* ctx, const char* file,
                                         const char* path, unsigned int flags);

/*!
    \ingroup CertsKeys

    \brief This function returns a pointer to an array of strings representing
    directories wolfSSL will search for system CA certs when
    wolfSSL_CTX_load_system_CA_certs is called. On systems that don't store
    certificates in an accessible system directory (such as Apple platforms),
    this function will always return NULL.

    \return Valid pointer on success.
    \return NULL pointer on failure.

    \param num pointer to a word32 that will be populated with the length of the
    array of strings.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    const char** dirs;
    word32 numDirs;

    dirs = wolfSSL_get_system_CA_dirs(&numDirs);
    for (int i = 0; i < numDirs; ++i) {
        printf("Potential system CA dir: %s\n", dirs[i]);
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_system_CA_certs
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_locations_ex
*/
const char** wolfSSL_get_system_CA_dirs(word32* num);

/*!
    \ingroup CertsKeys

    \brief On most platforms (including Linux and Windows), this function
    attempts to load CA certificates into a WOLFSSL_CTX from an OS-dependent
    CA certificate store. Loaded certificates will be trusted.

    On Apple platforms (excluding macOS), certificates can't be obtained from
    the system, and therefore cannot be loaded into the wolfSSL certificate
    manager. For these platforms, this function enables TLS connections bound to
    the WOLFSSL_CTX to use the native system trust APIs to verify authenticity
    of the peer certificate chain if the authenticity of the peer cannot first
    be authenticated against certificates loaded by the user.

    The platforms supported and tested are: Linux (Debian, Ubuntu,
    Gentoo, Fedora, RHEL), Windows 10/11, Android, macOS, and iOS.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_BAD_PATH if no system CA certs were loaded.
    \return WOLFSSL_FAILURE for other failure types (e.g. Windows cert store
    wasn't properly closed).

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_system_CA_certs(ctx,);
    if (ret != WOLFSSL_SUCCESS) {
        // error loading system CA certs
    }
    ...
    \endcode

    \sa wolfSSL_get_system_CA_dirs
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_locations_ex
*/
int wolfSSL_CTX_load_system_CA_certs(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function loads a certificate to use for verifying a peer
    when performing a TLS/SSL handshake. The peer certificate sent during the
    handshake is compared by using the SKID when available and the signature.
    If these two things do not match then any loaded CAs are used. Feature is
    enabled by defining the macro WOLFSSL_TRUST_PEER_CERT. Please see the
    examples for proper usage.

    \return SSL_SUCCES upon success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    type are invalid.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing certificates
    \param type type of certificate being loaded ie SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    ...

    ret = wolfSSL_CTX_trust_peer_cert(ctx, “./peer-cert.pem”,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        // error loading trusted peer cert
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_trust_peer_cert(WOLFSSL_CTX* ctx, const char* file, int type);

/*!
    \ingroup CertsKeys

    \brief This function loads a chain of certificates into the SSL
    context (WOLFSSL_CTX).  The file containing the certificate chain
    is provided by the file argument, and must contain PEM-formatted
    certificates. This function will process up to MAX_CHAIN_DEPTH
    (default = 9, defined in internal.h) certificates, plus the subject cert.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might
    include the file is in the wrong format, or the wrong format has been
    given using the “format” argument, file doesn’t exist, can’t be read,
    or is corrupted, an out of memory condition occurs.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the chain of
    certificates to be loaded into the wolfSSL SSL context.  Certificates
    must be in PEM format.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *ctx,
                                                     const char *file);

/*!
    \ingroup CertsKeys

    \brief Loads certificate chain file with specified format.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx WOLFSSL_CTX to load certificate chain into
    \param file Path to certificate chain file
    \param format Format of certificate file (SSL_FILETYPE_PEM or
    SSL_FILETYPE_ASN1)

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_use_certificate_chain_file_format(ctx,
                                                             "chain.der",
                                                             SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        // error loading certificate chain
    }
    \endcode

    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_chain_file_format
*/
int wolfSSL_CTX_use_certificate_chain_file_format(WOLFSSL_CTX* ctx,
                                                    const char* file,
                                                    int format);

/*!
    \ingroup CertsKeys

    \brief Loads certificate chain file with specified format for SSL object.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ssl WOLFSSL object to load certificate chain into
    \param file Path to certificate chain file
    \param format Format of certificate file (SSL_FILETYPE_PEM or
    SSL_FILETYPE_ASN1)

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ret = wolfSSL_use_certificate_chain_file_format(ssl, "chain.pem",
                                                          SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        // error loading certificate chain
    }
    \endcode

    \sa wolfSSL_use_certificate_chain_file
    \sa wolfSSL_CTX_use_certificate_chain_file_format
*/
int wolfSSL_use_certificate_chain_file_format(WOLFSSL* ssl,
                                                const char* file,
                                                int format);

/*!
    \ingroup openSSL

    \brief This function loads the private RSA key used in the SSL connection
    into the SSL context (WOLFSSL_CTX).  This function is only available when
    wolfSSL has been compiled with the OpenSSL compatibility layer enabled
    (--enable-opensslExtra, #define OPENSSL_EXTRA), and is identical to the
    more-typically used wolfSSL_CTX_use_PrivateKey_file() function. The file
    argument contains a pointer to the RSA private key file, in the format
    specified by format.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE  If the function call fails, possible causes might
    include: The input key file is in the wrong format, or the wrong format
    has been given using the “format” argument, file doesn’t exist, can’t
    be read, or is corrupted, an out of memory condition occurs.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the RSA private
    key to be loaded into the wolfSSL SSL context, with format as specified
    by format.
    \param format the encoding type of the RSA private key specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_RSAPrivateKey_file(ctx, “./server-key.pem”,
                                       SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_RSAPrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX* ctx, const char* file, int format);

/*!
    \ingroup IO

    \brief This function returns the maximum chain depth allowed, which is 9 by
    default, for a valid session i.e. there is a non-null session object (ssl).

    \return MAX_CHAIN_DEPTH returned if the WOLFSSL structure is not
    NULL. By default the value is 9.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    long sslDep = wolfSSL_get_verify_depth(ssl);

    if(sslDep > EXPECTED){
    	// The verified depth is greater than what was expected
    } else {
    	// The verified depth is smaller or equal to the expected value
    }
    \endcode

    \sa wolfSSL_CTX_get_verify_depth
*/
long wolfSSL_get_verify_depth(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function gets the certificate chaining depth using the
    CTX structure.

    \return MAX_CHAIN_DEPTH returned if the CTX struct is not NULL. The
    constant representation of the max certificate chain peer depth.
    \return BAD_FUNC_ARG returned if the CTX structure is NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_METHOD method; // protocol method
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    long ret = wolfSSL_CTX_get_verify_depth(ctx);

    if(ret == EXPECTED){
    	//  You have the expected value
    } else {
    	//  Handle an unexpected depth
    }
    \endcode

    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_get_verify_depth
*/
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief This function loads a certificate file into the SSL session
    (WOLFSSL structure).  The certificate file is provided by the file
    argument.  The format argument specifies the format type of the file -
    either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might
    include: The file is in the wrong format, or the wrong format has been
    given using the “format” argument, file doesn’t exist, can’t be read,
    or is corrupted, an out of memory condition occurs, Base16 decoding
    fails on the file

    \param ssl a pointer to a WOLFSSL structure, created with wolfSSL_new().
    \param file a pointer to the name of the file containing the certificate to
    be loaded into the wolfSSL SSL session, with format as specified by format.
    \param format the encoding type of the certificate specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_certificate_file(ssl, “./client-cert.pem”,
                                 SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup openSSL

    \brief This function loads a private key file into the SSL session
    (WOLFSSL structure).  The key file is provided by the file argument.
    The format argument specifies the format type of the file -
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    If using an external key store and do not have the private key you can
    instead provide the public key and register the crypro callback to handle
    the signing. For this you can build with either build with crypto callbacks
    or PK callbacks. To enable crypto callbacks use --enable-cryptocb or
    WOLF_CRYPTO_CB and register a crypto callback using
    wc_CryptoCb_RegisterDevice and set the associated devId using
    wolfSSL_SetDevId.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes might
    include: The file is in the wrong format, or the wrong format has been
    given using the “format” argument, The file doesn’t exist, can’t be read,
    or is corrupted, An out of memory condition occurs, Base16 decoding
    fails on the file, The key file is encrypted but no password is provided

    \param ssl a pointer to a WOLFSSL structure, created with wolfSSL_new().
    \param file a pointer to the name of the file containing the key file to
    be loaded into the wolfSSL SSL session, with format as specified by format.
    \param format the encoding type of the key specified by file.  Possible
    values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_PrivateKey_file(ssl, “./server-key.pem”,
                                SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wc_CryptoCb_RegisterDevice
    \sa wolfSSL_SetDevId
*/
int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup openSSL

    \brief This function loads a chain of certificates into the SSL
    session (WOLFSSL structure).  The file containing the certificate
    chain is provided by the file argument, and must contain PEM-formatted
    certificates.  This function will process up to MAX_CHAIN_DEPTH
    (default = 9, defined in internal.h) certificates, plus the
    subject certificate.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes
    might include: The file is in the wrong format, or the wrong format
    has been given using the “format” argument, file doesn’t exist,
    can’t be read, or is corrupted, an out of memory condition occurs

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new()
    \param file a pointer to the name of the file containing the chain
    of certificates to be loaded into the wolfSSL SSL session.
    Certificates must be in PEM format.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ctx;
    ...
    ret = wolfSSL_use_certificate_chain_file(ssl, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_certificate_chain_file(WOLFSSL* ssl, const char *file);

/*!
    \ingroup openSSL

    \brief This function loads the private RSA key used in the SSL
    connection into the SSL session (WOLFSSL structure). This
    function is only available when wolfSSL has been compiled with
    the OpenSSL compatibility layer enabled (--enable-opensslExtra,
    #define OPENSSL_EXTRA), and is identical to the more-typically
    used wolfSSL_use_PrivateKey_file() function. The file argument
    contains a pointer to the RSA private key file, in the format
    specified by format.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might
    include: The input key file is in the wrong format, or the wrong format
    has been given using the “format” argument, file doesn’t exist, can’t
    be read, or is corrupted, an out of memory condition occurs

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new()
    \param file a pointer to the name of the file containing the RSA private
    key to be loaded into the wolfSSL SSL session, with format as specified
    by format.
    \param format the encoding type of the RSA private key specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_RSAPrivateKey_file(ssl, “./server-key.pem”,
                                   SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_RSAPrivateKey_file
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
int wolfSSL_use_RSAPrivateKey_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup CertsKeys

    \brief This function is similar to wolfSSL_CTX_load_verify_locations,
    but allows the loading of DER-formatted CA files into the SSL context
    (WOLFSSL_CTX).  It may still be used to load PEM-formatted CA files as
    well. These certificates will be treated as trusted root certificates
    and used to verify certs received from peers during the SSL handshake.
    The root certificate file, provided by the file argument, may be a single
    certificate or a file containing multiple certificates.  If multiple CA
    certs are included in the same file, wolfSSL will load them in the same
    order they are presented in the file.  The format argument specifies the
    format which the certificates are in either, SSL_FILETYPE_PEM or
    SSL_FILETYPE_ASN1 (DER). Unlike wolfSSL_CTX_load_verify_locations,
    this function does not allow the loading of CA certificates from a given
    directory path. Note that this function is only available when the wolfSSL
    library was compiled with WOLFSSL_DER_LOAD defined.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE upon failure.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the CA
    certificates to be loaded into the wolfSSL SSL context, with format
    as specified by format.
    \param format the encoding type of the certificates specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_der_load_verify_locations(ctx, “./ca-cert.der”,
                                          SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
	    // error loading CA certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_buffer
*/
int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX* ctx,
                                          const char* file, int format);

/*!
    \ingroup Setup

    \brief This function creates a new SSL context, taking a desired
    SSL/TLS protocol method for input.

    \return pointer If successful the call will return a pointer to the
    newly-created WOLFSSL_CTX.
    \return NULL upon failure.

    \param method pointer to the desired WOLFSSL_METHOD to use for the SSL
    context. This is created using one of the wolfSSLvXX_XXXX_method()
    functions to specify SSL/TLS/DTLS protocol level.

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    WOLFSSL_METHOD* method = 0;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
    	// context creation failed
    }
    \endcode

    \sa wolfSSL_new
*/
WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);

/*!
    \ingroup Setup

    \brief Creates new SSL context with custom heap.

    \return WOLFSSL_CTX* Pointer to newly created context
    \return NULL on failure

    \param method WOLFSSL_METHOD to use for context
    \param heap Custom heap hint for memory allocation

    _Example_
    \code
    WOLFSSL_METHOD* method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new_ex(method, NULL);
    if (ctx == NULL) {
        // context creation failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_CTX* wolfSSL_CTX_new_ex(WOLFSSL_METHOD* method, void* heap);

/*!
    \ingroup Setup

    \brief Increments reference count for SSL context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx WOLFSSL_CTX to increment reference count

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_up_ref(ctx);
    if (ret != SSL_SUCCESS) {
        // failed to increment reference count
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
int wolfSSL_CTX_up_ref(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function creates a new SSL session, taking an already
    created SSL context as input.

    \return * If successful the call will return a pointer to the
    newly-created wolfSSL structure.
    \return NULL Upon failure.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL*     ssl = NULL;
    WOLFSSL_CTX* ctx = 0;

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
	    // context creation failed
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
	    // SSL object creation failed
    }
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief Gets the WOLFSSL_CTX associated with an SSL session.

    \return WOLFSSL_CTX* Pointer to the context
    \return NULL if ssl is NULL

    \param ssl WOLFSSL object to get context from

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_CTX* ctx_ptr = wolfSSL_get_SSL_CTX(ssl);
    if (ctx_ptr == NULL) {
        // error getting context
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
*/
WOLFSSL_CTX* wolfSSL_get_SSL_CTX(const WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Gets X509 verification parameters for context.

    \return WOLFSSL_X509_VERIFY_PARAM* Pointer to verification parameters
    \return NULL on failure

    \param ctx WOLFSSL_CTX to get parameters from

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_CTX_get0_param(ctx);
    if (param != NULL) {
        // configure verification parameters
    }
    \endcode

    \sa wolfSSL_get0_param
    \sa wolfSSL_CTX_set1_param
*/
WOLFSSL_X509_VERIFY_PARAM* wolfSSL_CTX_get0_param(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Gets X509 verification parameters for SSL session.

    \return WOLFSSL_X509_VERIFY_PARAM* Pointer to verification parameters
    \return NULL on failure

    \param ssl WOLFSSL object to get parameters from

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_get0_param(ssl);
    if (param != NULL) {
        // configure verification parameters
    }
    \endcode

    \sa wolfSSL_CTX_get0_param
    \sa wolfSSL_CTX_set1_param
*/
WOLFSSL_X509_VERIFY_PARAM* wolfSSL_get0_param(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Sets X509 verification parameters for context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx WOLFSSL_CTX to set parameters for
    \param vpm Verification parameters to copy

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_CTX_set1_param(ctx, param);
    if (ret != SSL_SUCCESS) {
        // failed to set parameters
    }
    \endcode

    \sa wolfSSL_CTX_get0_param
    \sa wolfSSL_get0_param
*/
int wolfSSL_CTX_set1_param(WOLFSSL_CTX* ctx,
                            WOLFSSL_X509_VERIFY_PARAM* vpm);

/*!
    \ingroup Setup

    \brief This function assigns a file descriptor (fd) as the
    input/output facility for the SSL connection. Typically this will be
    a socket file descriptor.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG upon failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param fd file descriptor to use with SSL/TLS connection.

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
    	// failed to set SSL file descriptor
    }
    \endcode

    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
*/
int  wolfSSL_set_fd(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief Sets the write file descriptor for SSL connection.

    \return SSL_SUCCESS on success
    \return BAD_FUNC_ARG on failure

    \param ssl WOLFSSL object to set write fd for
    \param fd File descriptor for writing

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int write_fd = socket(AF_INET, SOCK_STREAM, 0);
    int ret = wolfSSL_set_write_fd(ssl, write_fd);
    if (ret != SSL_SUCCESS) {
        // failed to set write fd
    }
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_read_fd
*/
int wolfSSL_set_write_fd(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief Sets the read file descriptor for SSL connection.

    \return SSL_SUCCESS on success
    \return BAD_FUNC_ARG on failure

    \param ssl WOLFSSL object to set read fd for
    \param fd File descriptor for reading

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int read_fd = socket(AF_INET, SOCK_STREAM, 0);
    int ret = wolfSSL_set_read_fd(ssl, read_fd);
    if (ret != SSL_SUCCESS) {
        // failed to set read fd
    }
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_write_fd
*/
int wolfSSL_set_read_fd(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief Checks if SSL session is configured as server.

    \return 1 if ssl is server
    \return 0 if ssl is client or NULL

    \param ssl WOLFSSL object to check

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (wolfSSL_is_server(ssl)) {
        // handle server-side logic
    } else {
        // handle client-side logic
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_accept
    \sa wolfSSL_connect
*/
int wolfSSL_is_server(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Creates a duplicate SSL session for writing.

    \return WOLFSSL* Pointer to duplicated SSL object
    \return NULL on failure

    \param ssl WOLFSSL object to duplicate

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL* write_dup = wolfSSL_write_dup(ssl);
    if (write_dup == NULL) {
        // failed to create write duplicate
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL* wolfSSL_write_dup(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function assigns a file descriptor (fd) as the
    input/output facility for the SSL connection. Typically this will be
    a socket file descriptor. This is a DTLS specific API because it marks that
    the socket is connected. recvfrom and sendto calls on this fd will have the
    addr and addr_len parameters set to NULL.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG upon failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param fd file descriptor to use with SSL/TLS connection.

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    if (connect(sockfd, peer_addr, peer_addr_len) != 0) {
        // handle connect error
    }
    ...
    ret = wolfSSL_set_dtls_fd_connected(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        // failed to set SSL file descriptor
    }
    \endcode

    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
    \sa wolfDTLS_SetChGoodCb
*/
int wolfSSL_set_dtls_fd_connected(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief Allows setting a callback for a correctly processed and verified DTLS
           client hello. When using a cookie exchange mechanism (either the
           HelloVerifyRequest in DTLS 1.2 or the HelloRetryRequest with a cookie
           extension in DTLS 1.3) this callback is called after the cookie
           exchange has succeeded. This is useful to use one WOLFSSL object as
           the listener for new connections and being able to isolate the
           WOLFSSL object once the ClientHello is verified (either through a
           cookie exchange or just checking if the ClientHello had the correct
           format).
           DTLS 1.2:
           https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
           DTLS 1.3:
           https://www.rfc-editor.org/rfc/rfc8446#section-4.2.2

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG upon failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param fd file descriptor to use with SSL/TLS connection.

    _Example_
    \code

    // Called when we have verified a connection
    static int chGoodCb(WOLFSSL* ssl, void* arg)
    {
        // setup peer and file descriptors

    }

    if (wolfDTLS_SetChGoodCb(ssl, chGoodCb, NULL) != WOLFSSL_SUCCESS) {
         // error setting callback
    }
    \endcode

    \sa wolfSSL_set_dtls_fd_connected
*/
int wolfDTLS_SetChGoodCb(WOLFSSL* ssl, ClientHelloGoodCb cb, void* user_ctx);

/*!
    \ingroup IO

    \brief Get the name of cipher at priority level passed in.

    \return string Success
    \return 0 Priority is either out of bounds or not valid.

    \param priority Integer representing the priority level of a cipher.

    _Example_
    \code
    printf("The cipher at 1 is %s", wolfSSL_get_cipher_list(1));
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
char* wolfSSL_get_cipher_list(int priority);

/*!
    \ingroup IO

    \brief This function gets the ciphers enabled in wolfSSL.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the buf parameter was NULL or if the
    len argument was less than or equal to zero.
    \return BUFFER_E returned if the buffer is not large enough and
    will overflow.

    \param buf a char pointer representing the buffer.
    \param len the length of the buffer.

    _Example_
    \code
    static void ShowCiphers(void){
	char* ciphers;
	int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

	if(ret == SSL_SUCCES){
	    	printf(“%s\n”, ciphers);
	    }
    }
    \endcode

    \sa GetCipherNames
    \sa wolfSSL_get_cipher_list
    \sa ShowCiphers
*/
int  wolfSSL_get_ciphers(char* buf, int len);

/*!
    \ingroup IO

    \brief This function gets the cipher name in the format DHE-RSA by
    passing through argument to wolfSSL_get_cipher_name_internal.

    \return string This function returns the string representation of the
    cipher suite that was matched.
    \return NULL error or cipher not found.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    char* cipherS = wolfSSL_get_cipher_name(ssl);

    if(cipher == NULL){
	    // There was not a cipher suite matched
    } else {
	    // There was a cipher suite matched
	    printf(“%s\n”, cipherS);
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
*/
const char* wolfSSL_get_cipher_name(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief Gets cipher name at priority level for specific SSL session.

    \return string Cipher name on success
    \return NULL on failure or invalid priority

    \param ssl WOLFSSL object to get cipher from
    \param priority Priority level of cipher to retrieve

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* cipher = wolfSSL_get_cipher_list_ex(ssl, 0);
    if (cipher != NULL) {
        printf("First cipher: %s\n", cipher);
    }
    \endcode

    \sa wolfSSL_get_cipher_list
    \sa wolfSSL_get_cipher_name
*/
char* wolfSSL_get_cipher_list_ex(WOLFSSL* ssl, int priority);

/*!
    \ingroup IO

    \brief Gets list of IANA cipher names.

    \return SSL_SUCCESS on success
    \return BAD_FUNC_ARG if buf is NULL or len <= 0
    \return BUFFER_E if buffer too small

    \param buf Buffer to store cipher names
    \param len Length of buffer

    _Example_
    \code
    char ciphers[4096];
    int ret = wolfSSL_get_ciphers_iana(ciphers, sizeof(ciphers));
    if (ret == SSL_SUCCESS) {
        printf("IANA ciphers: %s\n", ciphers);
    }
    \endcode

    \sa wolfSSL_get_ciphers
    \sa wolfSSL_get_cipher_list
*/
int wolfSSL_get_ciphers_iana(char* buf, int len);

/*!
    \ingroup IO

    \brief Gets cipher name from cipher suite bytes.

    \return string Cipher name on success
    \return NULL on failure

    \param cipherSuite0 First byte of cipher suite
    \param cipherSuite Second byte of cipher suite

    _Example_
    \code
    const char* name = wolfSSL_get_cipher_name_from_suite(0x00, 0x2F);
    if (name != NULL) {
        printf("Cipher: %s\n", name);
    }
    \endcode

    \sa wolfSSL_get_cipher_name
    \sa wolfSSL_get_cipher_name_iana_from_suite
*/
const char* wolfSSL_get_cipher_name_from_suite(unsigned char cipherSuite0,
                                                 unsigned char cipherSuite);

/*!
    \ingroup IO

    \brief Gets IANA cipher name from cipher suite bytes.

    \return string IANA cipher name on success
    \return NULL on failure

    \param cipherSuite0 First byte of cipher suite
    \param cipherSuite Second byte of cipher suite

    _Example_
    \code
    const char* name = wolfSSL_get_cipher_name_iana_from_suite(0x13, 0x01);
    if (name != NULL) {
        printf("IANA cipher: %s\n", name);
    }
    \endcode

    \sa wolfSSL_get_cipher_name_from_suite
    \sa wolfSSL_get_ciphers_iana
*/
const char* wolfSSL_get_cipher_name_iana_from_suite(
    unsigned char cipherSuite0, unsigned char cipherSuite);

/*!
    \ingroup IO

    \brief Gets cipher suite bytes from cipher name.

    \return SSL_SUCCESS on success
    \return BAD_FUNC_ARG on invalid arguments
    \return SSL_FAILURE if cipher not found

    \param name Cipher name to look up
    \param cipherSuite0 Pointer to store first byte
    \param cipherSuite Pointer to store second byte
    \param flags Pointer to store cipher flags

    _Example_
    \code
    unsigned char suite0, suite;
    int flags;
    int ret = wolfSSL_get_cipher_suite_from_name("AES128-SHA", &suite0,
                                                   &suite, &flags);
    if (ret == SSL_SUCCESS) {
        printf("Suite: 0x%02X 0x%02X\n", suite0, suite);
    }
    \endcode

    \sa wolfSSL_get_cipher_name_from_suite
*/
int wolfSSL_get_cipher_suite_from_name(const char* name,
                                        unsigned char* cipherSuite0,
                                        unsigned char* cipherSuite,
                                        int* flags);

/*!
    \ingroup IO

    \brief Gets shared ciphers between client and server.

    \return string Colon-separated list of shared ciphers
    \return NULL on failure

    \param ssl WOLFSSL object
    \param buf Buffer to store cipher list
    \param len Length of buffer

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char shared[1024];
    const char* ciphers = wolfSSL_get_shared_ciphers(ssl, shared,
                                                       sizeof(shared));
    if (ciphers != NULL) {
        printf("Shared ciphers: %s\n", ciphers);
    }
    \endcode

    \sa wolfSSL_get_ciphers
    \sa wolfSSL_get_cipher_list
*/
const char* wolfSSL_get_shared_ciphers(WOLFSSL* ssl, char* buf, int len);

/*!
    \ingroup IO

    \brief Gets the curve name used in the connection.

    \return string Curve name on success
    \return NULL if no curve used or on failure

    \param ssl WOLFSSL object to get curve from

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    // after handshake
    const char* curve = wolfSSL_get_curve_name(ssl);
    if (curve != NULL) {
        printf("Curve: %s\n", curve);
    }
    \endcode

    \sa wolfSSL_get_cipher_name
    \sa wolfSSL_UseSupportedCurve
*/
const char* wolfSSL_get_curve_name(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function returns the read file descriptor (fd) used as the
    input facility for the SSL connection.  Typically this
    will be a socket file descriptor.

    \return fd If successful the call will return the SSL session file
    descriptor.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_fd(ssl);
    ...
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_read_fd
    \sa wolfSSL_set_write_fd
*/
int  wolfSSL_get_fd(const WOLFSSL*);

/*!
    \ingroup IO

    \brief This function returns the write file descriptor (fd) used as the
    output facility for the SSL connection.  Typically this
    will be a socket file descriptor.

    \return fd If successful the call will return the SSL session file
    descriptor.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_wfd(ssl);
    ...
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_read_fd
    \sa wolfSSL_set_write_fd
*/
int  wolfSSL_get_wfd(const WOLFSSL*);

/*!
    \ingroup Setup

    \brief This function informs the WOLFSSL object that the underlying
     I/O is non-blocking. After an application creates a WOLFSSL object,
     if it will be used with a non-blocking socket, call
    wolfSSL_set_using_nonblock() on it. This lets the WOLFSSL object know
     that receiving EWOULDBLOCK means that the recvfrom call would
    block rather than that it timed out.

    \return none No return.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param nonblock value used to set non-blocking flag on WOLFSSL object.
    Use 1 to specify non-blocking, otherwise 0.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_using_nonblock(ssl, 1);
    \endcode

    \sa wolfSSL_get_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
void wolfSSL_set_using_nonblock(WOLFSSL* ssl, int nonblock);

/*!
    \ingroup IO

    \brief This function allows the application to determine if wolfSSL is
    using non-blocking I/O.  If wolfSSL is using non-blocking I/O, this
    function will return 1, otherwise 0. After an application creates a
    WOLFSSL object, if it will be used with a non-blocking socket, call
    wolfSSL_set_using_nonblock() on it. This lets the WOLFSSL object know
    that receiving EWOULDBLOCK means that the recvfrom call would block
    rather than that it timed out.

    \return 0 underlying I/O is blocking.
    \return 1 underlying I/O is non-blocking.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_get_using_nonblock(ssl);
    if (ret == 1) {
    	// underlying I/O is non-blocking
    }
    ...
    \endcode

    \sa wolfSSL_set_session
*/
int  wolfSSL_get_using_nonblock(WOLFSSL*);

/*!
    \ingroup IO

    \brief This function writes sz bytes from the buffer, data, to the SSL
    connection, ssl. If necessary, wolfSSL_write() will negotiate an SSL/TLS
    session if the handshake has not already been performed yet by
    wolfSSL_connect() or wolfSSL_accept(). When using (D)TLSv1.3 and early data
    feature is compiled in, this function progresses the handshake only up to
    the point when it is possible to send data. Next invocations of
    wolfSSL_Connect()/wolfSSL_Accept()/wolfSSL_read() will complete the
    handshake. wolfSSL_write() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_write() will return when
    the underlying I/O could not satisfy the needs of wolfSSL_write() to
    continue.  In this case, a call to wolfSSL_get_error() will yield either
    SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then
    repeat the call to wolfSSL_write() when the underlying I/O is ready. If the
    underlying I/O is blocking, wolfSSL_write() will only return once the buffer
    data of size sz has been completely written or an error occurred.

    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for
    the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_write() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data data buffer which will be sent to peer.
    \param sz size, in bytes, of data to send to the peer (data).

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags;
    int ret;
    ...

    ret = wolfSSL_write(ssl, msg, msgSz);
    if (ret <= 0) {
    	// wolfSSL_write() failed, call wolfSSL_get_error()
    }
    \endcode

    \sa wolfSSL_send
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_write(WOLFSSL* ssl, const void* data, int sz);

/*!
    \ingroup IO

    \brief Writes data to SSL connection with size_t parameters.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ssl WOLFSSL object to write to
    \param data Buffer containing data to write
    \param sz Number of bytes to write
    \param wr Pointer to store number of bytes written

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* msg = "Hello";
    size_t written;
    int ret = wolfSSL_write_ex(ssl, msg, strlen(msg), &written);
    if (ret == SSL_SUCCESS) {
        printf("Wrote %zu bytes\n", written);
    }
    \endcode

    \sa wolfSSL_write
    \sa wolfSSL_read_ex
*/
int wolfSSL_write_ex(WOLFSSL* ssl, const void* data, size_t sz,
                      size_t* wr);

/*!
    \ingroup IO

    \brief This function reads sz bytes from the SSL session (ssl)
    internal read buffer into the buffer data.The bytes read are removed
    from the internal receive buffer. If necessary wolfSSL_read() will
    negotiate an SSL/TLS session if the handshake has not already been
    performed yet by wolfSSL_connect() or wolfSSL_accept(). The SSL/TLS
    protocol uses SSL records which have a maximum size of 16kB (the max
    record size can be controlled by the MAX_RECORD_SIZE define in
    <wolfssl_root>/wolfssl/internal.h).  As such, wolfSSL needs to read an
    entire SSL record internally before it is able to process and decrypt the
    record.  Because of this, a call to wolfSSL_read() will only be able to
    return the maximum buffer size which has been decrypted at the time of
    calling.  There may be additional not-yet-decrypted data waiting in the
    internal wolfSSL receive buffer which will be retrieved and decrypted with
    the next call to wolfSSL_read(). If sz is larger than the number of bytes
    in the internal read buffer, SSL_read() will return the bytes available in
    the internal read buffer.  If no bytes are buffered in the internal read
    buffer yet, a call to wolfSSL_read() will trigger processing of the next
    record.

    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure.  This may be caused by a either a
    clean (close notify alert) shutdown or just that the peer closed the
    connection.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_read() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_read() will place data read.
    \param sz number of bytes to read into data.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }

    See wolfSSL examples (client, server, echoclient, echoserver) for more
    complete examples of wolfSSL_read().
    \endcode

    \sa wolfSSL_recv
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
int  wolfSSL_read(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO

    \brief Reads data from SSL connection with size_t parameters.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ssl WOLFSSL object to read from
    \param data Buffer to store read data
    \param sz Maximum number of bytes to read
    \param rd Pointer to store number of bytes read

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char buffer[1024];
    size_t bytes_read;
    int ret = wolfSSL_read_ex(ssl, buffer, sizeof(buffer), &bytes_read);
    if (ret == SSL_SUCCESS) {
        printf("Read %zu bytes\n", bytes_read);
    }
    \endcode

    \sa wolfSSL_read
    \sa wolfSSL_write_ex
*/
int wolfSSL_read_ex(WOLFSSL* ssl, void* data, size_t sz, size_t* rd);

/*!
    \ingroup IO

    \brief This function copies sz bytes from the SSL session (ssl) internal
    read buffer into the buffer data. This function is identical to
    wolfSSL_read() except that the data in the internal SSL session
    receive buffer is not removed or modified.If necessary, like
    wolfSSL_read(), wolfSSL_peek() will negotiate an SSL/TLS session if
    the handshake has not already been performed yet by wolfSSL_connect()
    or wolfSSL_accept(). The SSL/TLS protocol uses SSL records which have a
    maximum size of 16kB (the max record size can be controlled by the
    MAX_RECORD_SIZE define in <wolfssl_root>/wolfssl/internal.h).  As such,
    wolfSSL needs to read an entire SSL record internally before it is able
    to process and decrypt the record.  Because of this, a call to
    wolfSSL_peek() will only be able to return the maximum buffer size which
    has been decrypted at the time of calling.  There may be additional
    not-yet-decrypted data waiting in the internal wolfSSL receive buffer
    which will be retrieved and decrypted with the next call to
    wolfSSL_peek() / wolfSSL_read(). If sz is larger than the number of bytes
    in the internal read buffer, SSL_peek() will return the bytes available
    in the internal read buffer.  If no bytes are buffered in the internal
    read buffer yet, a call to wolfSSL_peek() will trigger processing of the
    next record.

    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure.  This may be caused by a either
    a clean (close notify alert) shutdown or just that the peer closed the
    connection.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an
    error occurred or, when using non-blocking sockets, the
    SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and
    the application needs to call wolfSSL_peek() again. Use
    wolfSSL_get_error() to get a specific error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_peek() will place data read.
    \param sz number of bytes to read into data.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_peek(ssl, reply, sizeof(reply));
    if (input > 0) {
	    // “input” number of bytes returned into buffer “reply”
    }
    \endcode

    \sa wolfSSL_read
*/
int  wolfSSL_peek(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO

    \brief This function is called on the server side and waits for an SSL
    client to initiate the SSL/TLS handshake.  When this function is called,
    the underlying communication channel has already been set up.
    wolfSSL_accept() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_accept() will return
    when the underlying I/O could not satisfy the needs of wolfSSL_accept
    to continue the handshake.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
    The calling process must then repeat the call to wolfSSL_accept when
    data is available to read and wolfSSL will pick up where it left off.
    When using a non-blocking socket, nothing needs to be done, but select()
    can be used to check for the required condition. If the underlying I/O
    is blocking, wolfSSL_accept() will only return once the handshake has
    been finished or an error occurred.

    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
int  wolfSSL_accept(WOLFSSL*);

/*!
    \ingroup IO

    \brief This function is called on the server side and statelessly listens
    for an SSL client to initiate the DTLS handshake.

    \return WOLFSSL_SUCCESS ClientHello containing a valid cookie was received.
    The connection can be continued with wolfSSL_accept().
    \return WOLFSSL_FAILURE The I/O layer returned WANT_READ. This is either
    because there is no data to read and we are using non-blocking sockets or
    we sent a cookie request and we are waiting for a reply. The user should
    call wolfDTLS_accept_stateless again after data becomes available in
    the I/O layer.
    \return WOLFSSL_FATAL_ERROR A fatal error occurred. The ssl object should be
    free'd and allocated again to continue.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    ...
    do {
        ret = wolfDTLS_accept_stateless(ssl);
        if (ret == WOLFSSL_FATAL_ERROR)
            // re-allocate the ssl object with wolfSSL_free() and wolfSSL_new()
    } while (ret != WOLFSSL_SUCCESS);
    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_accept
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
int  wolfDTLS_accept_stateless(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function frees an allocated WOLFSSL_CTX object.  This
    function decrements the CTX reference count and only frees the context
    when the reference count has reached 0.

    \return none No return.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_free(ctx);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
void wolfSSL_CTX_free(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief This function frees an allocated wolfSSL object.

    \return none No return.

    \param ssl pointer to the SSL object, created with wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL* ssl = 0;
    ...
    wolfSSL_free(ssl);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_CTX_free
*/
void wolfSSL_free(WOLFSSL*);

/*!
    \ingroup TLS

    \brief This function shuts down an active SSL/TLS connection using
    the SSL session, ssl.  This function will try to send a “close notify”
    alert to the peer. The calling application can choose to wait for the
    peer to send its “close notify” alert in response or just go ahead
    and shut down the underlying connection after directly calling
    wolfSSL_shutdown (to save resources).  Either option is allowed by
    the TLS specification.  If the underlying connection will be used
    again in the future, the complete two-directional shutdown procedure
    must be performed to keep synchronization intact between the peers.
    wolfSSL_shutdown() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_shutdown() will
    return an error if the underlying I/O could not satisfy the needs of
    wolfSSL_shutdown() to continue. In this case, a call to
    wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call
    to wolfSSL_shutdown() when the underlying I/O is ready.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_SHUTDOWN_NOT_DONE will be returned when shutdown has not
    finished, and the function should be called again.
    \return SSL_FATAL_ERROR will be returned upon failure. Call
    wolfSSL_get_error() for a more specific error code.

    \param ssl pointer to the SSL session created with wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_shutdown(ssl);
    if (ret != 0) {
	    // failed to shut down SSL connection
    }
    \endcode

    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
int  wolfSSL_shutdown(WOLFSSL*);

/*!
    \ingroup IO

    \brief This function writes sz bytes from the buffer, data, to the SSL
    connection, ssl, using the specified flags for the underlying write
    operation. If necessary wolfSSL_send() will negotiate an SSL/TLS session
    if the handshake has not already been performed yet by wolfSSL_connect()
    or wolfSSL_accept(). wolfSSL_send() works with both blocking and
    non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_send()
    will return when the underlying I/O could not satisfy the needs of
    wolfSSL_send to continue.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
    The calling process must then repeat the call to wolfSSL_send() when
    the underlying I/O is ready. If the underlying I/O is blocking,
    wolfSSL_send() will only return once the buffer data of size sz has
    been completely written or an error occurred.

    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for
    the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_send() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data data buffer to send to peer.
    \param sz size, in bytes, of data to be sent to peer.
    \param flags the send flags to use for the underlying send operation.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags = ... ;
    ...

    input = wolfSSL_send(ssl, msg, msgSz, flags);
    if (input != msgSz) {
    	// wolfSSL_send() failed
    }
    \endcode

    \sa wolfSSL_write
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags);

/*!
    \ingroup IO

    \brief This function reads sz bytes from the SSL session (ssl) internal
    read buffer into the buffer data using the specified flags for the
    underlying recv operation.  The bytes read are removed from the internal
    receive buffer.  This function is identical to wolfSSL_read() except
    that it allows the application to set the recv flags for the underlying
    read operation. If necessary wolfSSL_recv() will negotiate an SSL/TLS
    session if the handshake has not already been performed yet by
    wolfSSL_connect() or wolfSSL_accept(). The SSL/TLS protocol uses
    SSL records which have a maximum size of 16kB (the max record size
    can be controlled by the MAX_RECORD_SIZE define in
    <wolfssl_root>/wolfssl/internal.h). As such, wolfSSL needs to read an
    entire SSL record internally before it is able to process and decrypt
    the record. Because of this, a call to wolfSSL_recv() will only be
    able to return the maximum buffer size which has been decrypted at
    the time of calling.  There may be additional not-yet-decrypted data
    waiting in the internal wolfSSL receive buffer which will be
    retrieved and decrypted with the next call to wolfSSL_recv(). If sz
    is larger than the number of bytes in the internal read buffer,
    SSL_recv() will return the bytes available in the internal read buffer.
    If no bytes are buffered in the internal read buffer yet, a call to
    wolfSSL_recv() will trigger processing of the next record.

    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure. This may be caused by a either
    a clean (close notify alert) shutdown or just that the peer closed the
    connection. Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_recv() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_recv() will place data read.
    \param sz number of bytes to read into data.
    \param flags the recv flags to use for the underlying recv operation.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    int flags = ... ;
    ...

    input = wolfSSL_recv(ssl, reply, sizeof(reply), flags);
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }
    \endcode

    \sa wolfSSL_read
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
int  wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags);

/*!
    \ingroup Debug

    \brief This function returns a unique error code describing why the
    previous API function call (wolfSSL_connect, wolfSSL_accept, wolfSSL_read,
    wolfSSL_write, etc.) resulted in an error return code (SSL_FAILURE).
    The return value of the previous function is passed to wolfSSL_get_error
    through ret. After wolfSSL_get_error is called and returns the unique
    error code, wolfSSL_ERR_error_string() may be called to get a
    human-readable error string.  See wolfSSL_ERR_error_string() for more
    information.

    \return On successful completion, this function will return the
    unique error code describing why the previous API function failed.
    \return SSL_ERROR_NONE will be returned if ret > 0. For ret <= 0, there are
    some cases when this value can also be returned when a previous API appeared
    to return an error code but no error actually occurred. An example is
    calling wolfSSL_read() with a zero sz parameter. A 0 return from
    wolfSSL_read() usually indicates an error but in this case no error
    occurred. If wolfSSL_get_error() is called afterwards, SSL_ERROR_NONE will
    be returned.

    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param ret return value of the previous function that resulted in an error
    return code.

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode

    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
int  wolfSSL_get_error(WOLFSSL* ssl, int ret);

/*!
    \ingroup IO

    \brief This function gets the alert history.

    \return SSL_SUCCESS returned when the function completed successfully.
    Either there was alert history or there wasn’t, either way, the
    return value is SSL_SUCCESS.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param h a pointer to a WOLFSSL_ALERT_HISTORY structure that will hold the
    WOLFSSL struct’s alert_history member’s value.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_ALERT_HISTORY* h;
    ...
    wolfSSL_get_alert_history(ssl, h);
    // h now has a copy of the ssl->alert_history  contents
    \endcode

    \sa wolfSSL_get_error
*/
int  wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h);

/*!
    \ingroup Setup

    \brief This function sets the session to be used when the SSL object,
    ssl, is used to establish a SSL/TLS connection. For session resumption,
    before calling wolfSSL_shutdown() with your session object, an application
    should save the session ID from the object with a call to
    wolfSSL_get1_session(), which returns a pointer to the session.
    Later, the application should create a new WOLFSSL object and assign
    the saved session with wolfSSL_set_session().  At this point, the
    application may call wolfSSL_connect() and wolfSSL will try to resume
    the session.  The wolfSSL server code allows session resumption by default.
    The object returned by wolfSSL_get1_session() needs to be freed after the
    application is done with it by calling wolfSSL_SESSION_free() on it.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return SSL_FAILURE will be returned on failure.  This could be caused
    by the session cache being disabled, or if the session has timed out.

    \return When OPENSSL_EXTRA and WOLFSSL_ERROR_CODE_OPENSSL are defined,
    SSL_SUCCESS will be returned even if the session has timed out.

    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param session pointer to the WOLFSSL_SESSION used to set the session
    for ssl.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get1_session(ssl);
    if (session == NULL) {
        // failed to get session object from ssl object
    }
    ...
    ret = wolfSSL_set_session(ssl, session);
    if (ret != SSL_SUCCESS) {
    	// failed to set the SSL session
    }
    wolfSSL_SESSION_free(session);
    ...
    \endcode

    \sa wolfSSL_get1_session
*/
int        wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session);

/*!
    \ingroup IO

    \brief When NO_SESSION_CACHE_REF is defined this function returns a pointer
    to the current session (WOLFSSL_SESSION) used in ssl. This function returns
    a non-persistent pointer to the WOLFSSL_SESSION object. The pointer returned
    will be freed when wolfSSL_free is called. This call should only be used to
    inspect or modify the current session. For session resumption it is
    recommended to use wolfSSL_get1_session(). For backwards compatibility when
    NO_SESSION_CACHE_REF is not defined this function returns a persistent
    session object pointer that is stored in the local cache. The cache size is
    finite and there is a risk that the session object will be overwritten by
    another ssl connection by the time the application calls
    wolfSSL_set_session() on it. It is recommended to define
    NO_SESSION_CACHE_REF in your application and to use wolfSSL_get1_session()
    for session resumption.

    \return pointer If successful the call will return a pointer to the the
    current SSL session object.
    \return NULL will be returned if ssl is NULL, the SSL session cache is
    disabled, wolfSSL doesn’t have the Session ID available, or mutex
    functions fail.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get_session(ssl);
    if (session == NULL) {
	    // failed to get session pointer
    }
    ...
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function flushes session from the session cache which
    have expired. The time, tm, is used for the time comparison. Note
    that wolfSSL currently uses a static table for sessions, so no flushing
    is needed. As such, this function is currently just a stub. This
    function provides OpenSSL compatibility (SSL_flush_sessions) when
    wolfSSL is compiled with the OpenSSL compatibility layer.

    \return none No returns.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param tm time used in session expiration comparison.

    _Example_
    \code
    WOLFSSL_CTX* ssl;
    ...
    wolfSSL_flush_sessions(ctx, time(0));
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
void       wolfSSL_flush_sessions(WOLFSSL_CTX* ctx, long tm);

/*!
    \ingroup TLS

    \brief This function associates the client session with the server id.
    If the newSession flag is on, an existing session won’t be reused.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct or id parameter
    is NULL or if len is not greater than zero.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param id a constant byte pointer that will be copied to the
    serverID member of the WOLFSSL_SESSION structure.
    \param len an int type representing the length of the session id parameter.
    \param newSession an int type representing the flag to denote whether
    to reuse a session or not.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    const byte id[MAX_SIZE];  // or dynamically create space
    int len = 0; // initialize length
    int newSession = 0; // flag to allow
    …
    int ret = wolfSSL_SetServerID(ssl, id, len, newSession);

    if (ret == WOLFSSL_SUCCESS) {
	    // The Id was successfully set
    }
    \endcode

    \sa wolfSSL_set_session
*/
int        wolfSSL_SetServerID(WOLFSSL* ssl, const unsigned char* id,
                                         int len, int newSession);

/*!
    \ingroup IO

    \brief This function gets the session index of the WOLFSSL structure.

    \return int The function returns an int type representing the
    sessionIndex within the WOLFSSL struct.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int sesIdx = wolfSSL_GetSessionIndex(ssl);

    if(sesIdx < 0 || sesIdx > sizeof(ssl->sessionIndex)/sizeof(int)){
    	// You have an out of bounds index number and something is not right.
    }
    \endcode

    \sa wolfSSL_GetSessionAtIndex
*/
int wolfSSL_GetSessionIndex(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function gets the session at specified index of the session
    cache and copies it into memory. The WOLFSSL_SESSION structure holds
    the session information.

    \return SSL_SUCCESS returned if the function executed successfully and
    no errors were thrown.
    \return BAD_MUTEX_E returned if there was an unlock or lock mutex error.
    \return SSL_FAILURE returned if the function did not execute successfully.

    \param idx an int type representing the session index.
    \param session a pointer to the WOLFSSL_SESSION structure.

    _Example_
    \code
    int idx; // The index to locate the session.
    WOLFSSL_SESSION* session;  // Buffer to copy to.
    ...
    if(wolfSSL_GetSessionAtIndex(idx, session) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode

    \sa UnLockMutex
    \sa LockMutex
    \sa wolfSSL_GetSessionIndex
*/
int wolfSSL_GetSessionAtIndex(int idx, WOLFSSL_SESSION* session);

/*!
    \ingroup IO

    \brief Returns the peer certificate chain from the WOLFSSL_SESSION struct.

    \return pointer A pointer to a WOLFSSL_X509_CHAIN structure that
    contains the peer certification chain.

    \param session a pointer to a WOLFSSL_SESSION structure.

    _Example_
    \code
    WOLFSSL_SESSION* session;
    WOLFSSL_X509_CHAIN* chain;
    ...
    chain = wolfSSL_SESSION_get_peer_chain(session);
    if(!chain){
    	// There was no chain. Failure case.
    }
    \endcode

    \sa wolfSSL_GetSessionAtIndex
    \sa wolfSSL_GetSessionIndex
    \sa AddSession
*/

    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);

/*!
    \ingroup Setup

    \brief This function sets the verification method for remote peers and
    also allows a verify callback to be registered with the SSL context.
    The verify callback will be called only when a verification failure has
    occurred.  If no verify callback is desired, the NULL pointer can be used
    for verify_callback. The verification mode of peer certificates is a
    logically OR’d list of flags.  The possible flag values include:
    SSL_VERIFY_NONE Client mode: the client will not verify the certificate
    received from the server and the handshake will continue as normal.
    Server mode: the server will not send a certificate request to the client.
    As such, client verification will not be enabled. SSL_VERIFY_PEER Client
    mode: the client will verify the certificate received from the server
    during the handshake.  This is turned on by default in wolfSSL, therefore,
    using this option has no effect. Server mode: the server will send a
    certificate request to the client and verify the client certificate
    received. SSL_VERIFY_FAIL_IF_NO_PEER_CERT Client mode: no effect when
    used on the client side. Server mode: the verification will fail on the
    server side if the client fails to send a certificate when requested to
    do so (when using SSL_VERIFY_PEER on the SSL server).
    SSL_VERIFY_FAIL_EXCEPT_PSK Client mode: no effect when used on the client
    side. Server mode: the verification is the same as
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT except in the case of a PSK connection.
    If a PSK connection is being made then the connection will go through
    without a peer cert.

    \return none No return.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode flags indicating verification mode for peer's cert.
    \param verify_callback callback to be called when verification fails.
    If no callback is desired, the NULL pointer can be used for
    verify_callback.

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    wolfSSL_CTX_set_verify(ctx, (WOLFSSL_VERIFY_PEER |
                           WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT), NULL);
    \endcode

    \sa wolfSSL_set_verify
*/
void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode,
                                      VerifyCallback verify_callback);

/*!
    \ingroup Setup

    \brief This function sets the verification method for remote peers and
    also allows a verify callback to be registered with the SSL session.
    The verify callback will be called only when a verification failure has
    occurred. If no verify callback is desired, the NULL pointer can be used
    for verify_callback. The verification mode of peer certificates is a
    logically OR’d list of flags.  The possible flag values include:
    SSL_VERIFY_NONE Client mode: the client will not verify the certificate
    received from the server and the handshake will continue as normal. Server
    mode: the server will not send a certificate request to the client.
    As such, client verification will not be enabled. SSL_VERIFY_PEER Client
    mode: the client will verify the certificate received from the server
    during the handshake. This is turned on by default in wolfSSL, therefore,
    using this option has no effect. Server mode: the server will send a
    certificate request to the client and verify the client certificate
    received. SSL_VERIFY_FAIL_IF_NO_PEER_CERT Client mode: no effect when
    used on the client side. Server mode: the verification will fail on the
    server side if the client fails to send a certificate when requested to do
    so (when using SSL_VERIFY_PEER on the SSL server).
    SSL_VERIFY_FAIL_EXCEPT_PSK Client mode: no effect when used on the client
    side. Server mode: the verification is the same as
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT except in the case of a PSK connection.
    If a PSK connection is being made then the connection will go through
    without a peer cert.

    \return none No return.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param mode flags indicating verification mode for peer's cert.
    \param verify_callback callback to be called when verification fails.
    If no callback is desired, the NULL pointer can
    be used for verify_callback.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    \endcode

    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback verify_callback);

/*!
    \ingroup CertsKeys

    \brief This function stores user CTX object information for verify callback.

    \return none No return.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx a void pointer that is set to WOLFSSL structure’s verifyCbCtx
    member’s value.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    (void*)ctx;
    ...
    if(ssl != NULL){
    wolfSSL_SetCertCbCtx(ssl, ctx);
    } else {
	    // Error case, the SSL is not initialized properly.
    }
    \endcode

    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx);

/*!
    \ingroup CertsKeys

    \brief This function stores user CTX object information for verify callback.

    \return none No return.

    \param ctx a pointer to a WOLFSSL_CTX structure.
    \param userCtx a void pointer that is used to set WOLFSSL_CTX structure’s
    verifyCbCtx member’s value.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    void* userCtx = NULL; // Assign some user defined context
    ...
    if(ctx != NULL){
        wolfSSL_SetCertCbCtx(ctx, userCtx);
    } else {
        // Error case, the SSL is not initialized properly.
    }
    \endcode

    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx);

/*!
    \ingroup IO

    \brief This function returns the number of bytes which are buffered and
    available in the SSL object to be read by wolfSSL_read().

    \return int This function returns the number of bytes pending.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int pending = 0;
    WOLFSSL* ssl = 0;
    ...

    pending = wolfSSL_pending(ssl);
    printf(“There are %d bytes buffered and available for reading”, pending);
    \endcode

    \sa wolfSSL_recv
    \sa wolfSSL_read
    \sa wolfSSL_peek
*/
int  wolfSSL_pending(WOLFSSL*);

/*!
    \ingroup Debug

    \brief This function is for OpenSSL compatibility (SSL_load_error_string)
    only and takes no action.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_load_error_strings();
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
void wolfSSL_load_error_strings(void);

/*!
    \ingroup TLS

    \brief This function is called internally in wolfSSL_CTX_new(). This
    function is a wrapper around wolfSSL_Init() and exists for OpenSSL
    compatibility (SSL_library_init) when wolfSSL has been compiled with
    OpenSSL compatibility layer.  wolfSSL_Init() is the more typically-used
    wolfSSL initialization function.

    \return SSL_SUCCESS If successful the call will return.
    \return SSL_FATAL_ERROR is returned upon failure.

    \param none No parameters.

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_library_init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL
    }
    ...
    \endcode

    \sa wolfSSL_Init
    \sa wolfSSL_Cleanup
*/
int  wolfSSL_library_init(void);

/*!
    \brief This function sets the Device Id at the WOLFSSL session level.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    WOLFSSL* ssl;
    int DevId = -2;

    wolfSSL_SetDevId(ssl, devId);

    \endcode

    \sa wolfSSL_CTX_SetDevId
    \sa wolfSSL_CTX_GetDevId
*/
int wolfSSL_SetDevId(WOLFSSL* ssl, int devId);

/*!
    \brief This function sets the Device Id at the WOLFSSL_CTX context level.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int DevId = -2;

    wolfSSL_CTX_SetDevId(ctx, devId);

    \endcode

    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_GetDevId
*/
int wolfSSL_CTX_SetDevId(WOLFSSL_CTX* ctx, int devId);

/*!
    \brief This function retrieves the Device Id.

    \return devId upon success.
    \return INVALID_DEVID if both ssl and ctx are NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param ssl pointer to a SSL object, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx;

    wolfSSL_CTX_GetDevId(ctx, ssl);

    \endcode

    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_SetDevId

*/
int wolfSSL_CTX_GetDevId(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function enables or disables SSL session caching.
    Behavior depends on the value used for mode. The following values
    for mode are available: SSL_SESS_CACHE_OFF- disable session caching.
    Session caching is turned on by default. SSL_SESS_CACHE_NO_AUTO_CLEAR -
    Disable auto-flushing of the session cache. Auto-flushing is turned on
    by default.

    \return SSL_SUCCESS will be returned upon success.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode modifier used to change behavior of the session cache.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (ret != SSL_SUCCESS) {
    	// failed to turn SSL session caching off
    }
    \endcode

    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_timeout
*/
long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX* ctx, long mode);

/*!
    \brief This function sets the session secret callback function. The
    SessionSecretCb type has the signature: int (*SessionSecretCb)(WOLFSSL* ssl,
    void* secret, int* secretSz, void* ctx). The sessionSecretCb member of
    the WOLFSSL struct is set to the parameter cb.

    \return SSL_SUCCESS returned if the execution of the function did not
    return an error.
    \return SSL_FATAL_ERROR returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a SessionSecretCb type that is a function pointer with the above
    signature.
    \param ctx a pointer to the user context to be stored

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    // Signature of SessionSecretCb
    int SessionSecretCB (WOLFSSL* ssl, void* secret, int* secretSz,
    void* ctx) = SessionSecretCb;
    …
    int wolfSSL_set_session_secret_cb(ssl, SessionSecretCB, (void*)ssl->ctx){
	    // Function body.
    }
    \endcode

    \sa SessionSecretCb
*/
int  wolfSSL_set_session_secret_cb(WOLFSSL* ssl, SessionSecretCb cb, void* ctx);

/*!
    \ingroup IO

    \brief This function persists the session cache to file. It doesn’t use
    memsave because of additional memory use.

    \return SSL_SUCCESS returned if the function executed without error.
    The session cache has been written to a file.
    \return SSL_BAD_FILE returned if fname cannot be opened or is otherwise
    corrupt.
    \return FWRITE_ERROR returned if XFWRITE failed to write to the file.
    \return BAD_MUTEX_E returned if there was a mutex lock failure.

    \param fname is a constant char pointer that points to a file for writing.

    _Example_
    \code
    const char* fname;
    ...
    if(wolfSSL_save_session_cache(fname) != SSL_SUCCESS){
    	// Fail to write to file.
    }
    \endcode

    \sa XFWRITE
    \sa wolfSSL_restore_session_cache
    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_save_session_cache(const char* fname);

/*!
    \ingroup IO

    \brief This function restores the persistent session cache from file. It
    does not use memstore because of additional memory use.

    \return SSL_SUCCESS returned if the function executed without error.
    \return SSL_BAD_FILE returned if the file passed into the function was
    corrupted and could not be opened by XFOPEN.
    \return FREAD_ERROR returned if the file had a read error from XFREAD.
    \return CACHE_MATCH_ERROR returned if the session cache header match
    failed.
    \return BAD_MUTEX_E returned if there was a mutex lock failure.

    \param fname a constant char pointer file input that will be read.

    _Example_
    \code
    const char *fname;
    ...
    if(wolfSSL_restore_session_cache(fname) != SSL_SUCCESS){
        // Failure case. The function did not return SSL_SUCCESS.
    }
    \endcode

    \sa XFREAD
    \sa XFOPEN
*/
int  wolfSSL_restore_session_cache(const char* fname);

/*!
    \ingroup IO

    \brief This function persists session cache to memory.

    \return SSL_SUCCESS returned if the function executed without error.
    The session cache has been successfully persisted to memory.
    \return BAD_MUTEX_E returned if there was a mutex lock error.
    \return BUFFER_E returned if the buffer size was too small.

    \param mem a void pointer representing the destination for the memory
    copy, XMEMCPY().
    \param sz an int type representing the size of mem.

    _Example_
    \code
    void* mem;
    int sz; // Max size of the memory buffer.
    …
    if(wolfSSL_memsave_session_cache(mem, sz) != SSL_SUCCESS){
    	// Failure case, you did not persist the session cache to memory
    }
    \endcode

    \sa XMEMCPY
    \sa wolfSSL_get_session_cache_memsize
*/
int  wolfSSL_memsave_session_cache(void* mem, int sz);

/*!
    \ingroup IO

    \brief This function restores the persistent session cache from memory.

    \return SSL_SUCCESS returned if the function executed without an error.
    \return BUFFER_E returned if the memory buffer is too small.
    \return BAD_MUTEX_E returned if the session cache mutex lock failed.
    \return CACHE_MATCH_ERROR returned if the session cache header match
    failed.

    \param mem a constant void pointer containing the source of the
    restoration.
    \param sz an integer representing the size of the memory buffer.

    _Example_
    \code
    const void* memoryFile;
    int szMf;
    ...
    if(wolfSSL_memrestore_session_cache(memoryFile, szMf) != SSL_SUCCESS){
    	// Failure case. SSL_SUCCESS was not returned.
    }
    \endcode

    \sa wolfSSL_save_session_cache
*/
int  wolfSSL_memrestore_session_cache(const void* mem, int sz);

/*!
    \ingroup IO

    \brief This function returns how large the session cache save buffer
    should be.

    \return int This function returns an integer that represents the size of
    the session cache save buffer.

    \param none No parameters.

    _Example_
    \code
    int sz = // Minimum size for error checking;
    ...
    if(sz < wolfSSL_get_session_cache_memsize()){
        // Memory buffer is too small
    }
    \endcode

    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_get_session_cache_memsize(void);

/*!
    \ingroup CertsKeys

    \brief This function writes the cert cache from memory to file.

    \return SSL_SUCCESS if CM_SaveCertCache exits normally.
    \return BAD_FUNC_ARG is returned if either of the arguments are NULL.
    \return SSL_BAD_FILE if the cert cache save file could not be opened.
    \return BAD_MUTEX_E if the lock mutex failed.
    \return MEMORY_E the allocation of memory failed.
    \return FWRITE_ERROR Certificate cache file write failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, holding the
    certificate information.
    \param fname  a constant char pointer that points to a file for writing.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    const char* fname;
    ...
    if(wolfSSL_CTX_save_cert_cache(ctx, fname)){
	    // file was written.
    }
    \endcode

    \sa CM_SaveCertCache
    \sa DoMemSaveCertCache
*/
int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys

    \brief This function persistes certificate cache from a file.

    \return SSL_SUCCESS returned if the function, CM_RestoreCertCache,
    executes normally.
    \return SSL_BAD_FILE returned if XFOPEN returns XBADFILE. The file is
    corrupted.
    \return MEMORY_E returned if the allocated memory for the temp buffer
    fails.
    \return BAD_FUNC_ARG returned if fname or ctx have a NULL value.

    \param ctx a pointer to a WOLFSSL_CTX structure, holding the certificate
    information.
    \param fname a constant char pointer that points to a file for reading.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* fname = "path to file";
    ...
    if(wolfSSL_CTX_restore_cert_cache(ctx, fname)){
    	// check to see if the execution was successful
    }
    \endcode

    \sa CM_RestoreCertCache
    \sa XFOPEN
*/
int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys

    \brief This function persists the certificate cache to memory.

    \return SSL_SUCCESS returned on successful execution of the function.
    No errors were thrown.
    \return BAD_MUTEX_E mutex error where the WOLFSSL_CERT_MANAGER member
    caLock was not 0 (zero).
    \return BAD_FUNC_ARG returned if ctx, mem, or used is NULL or if sz
    is less than or equal to 0 (zero).
    \return BUFFER_E output buffer mem was too small.

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    using wolfSSL_CTX_new().
    \param mem a void pointer to the destination (output buffer).
    \param sz the size of the output buffer.
    \param used a pointer to size of the cert cache header.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol );
    void* mem;
    int sz;
    int* used;
    ...
    if(wolfSSL_CTX_memsave_cert_cache(ctx, mem, sz, used) != SSL_SUCCESS){
	    // The function returned with an error
    }
    \endcode

    \sa DoMemSaveCertCache
    \sa GetCertCacheMemSize
    \sa CM_MemRestoreCertCache
    \sa CM_GetCertCacheMemSize
*/
int  wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem, int sz, int* used);

/*!
    \ingroup Setup

    \brief This function restores the certificate cache from memory.

    \return SSL_SUCCESS returned if the function and subroutines
    executed without an error.
    \return BAD_FUNC_ARG returned if the ctx or mem parameters are
    NULL or if the sz parameter is less than or equal to zero.
    \return BUFFER_E returned if the cert cache memory buffer is too small.
    \return CACHE_MATCH_ERROR returned if there was a cert cache
    header mismatch.
    \return BAD_MUTEX_E returned if the lock mutex on failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param mem a void pointer with a value that will be restored to
    the certificate cache.
    \param sz an int type that represents the size of the mem parameter.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    void* mem;
    int sz = (*int) sizeof(mem);
    …
    if(wolfSSL_CTX_memrestore_cert_cache(ssl->ctx, mem, sz)){
    	// The success case
    }
    \endcode

    \sa CM_MemRestoreCertCache
*/
int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz);

/*!
    \ingroup CertsKeys

    \brief Returns the size the certificate cache save buffer needs to be.

    \return int integer value returned representing the memory size
    upon success.
    \return BAD_FUNC_ARG is returned if the WOLFSSL_CTX struct is NULL.
    \return BAD_MUTEX_E - returned if there was a mutex lock error.

    \param ctx a pointer to a wolfSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol);
    ...
    int certCacheSize = wolfSSL_CTX_get_cert_cache_memsize(ctx);

    if(certCacheSize != BAD_FUNC_ARG || certCacheSize != BAD_MUTEX_E){
	// Successfully retrieved the memory size.
    }
    \endcode

    \sa CM_GetCertCacheMemSize
*/
int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function sets cipher suite list for a given WOLFSSL_CTX.
    This cipher suite list becomes the default list for any new SSL sessions
    (WOLFSSL) created using this context.  The ciphers in the list should be
    sorted in order of preference from highest to lowest.  Each call to
    wolfSSL_CTX_set_cipher_list() resets the cipher suite list for the
    specific SSL context to the provided list each time the function is
    called. The cipher suite list, list, is a null-terminated text string,
    and a colon-delimited list.  For example, one value for list may be
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256" Valid cipher
    values are the full name values from the cipher_names[] array in
    src/internal.c (for a definite list of valid cipher values check
    src/internal.c)

    \return SSL_SUCCESS will be returned upon successful function completion.
    \return SSL_FAILURE will be returned on failure.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param list null-terminated text string and a colon-delimited list of
    cipher suites to use with the specified SSL context.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_cipher_list(ctx,
    “DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256”);
    if (ret != SSL_SUCCESS) {
    	// failed to set cipher suite list
    }
    \endcode

    \sa wolfSSL_set_cipher_list
    \sa wolfSSL_CTX_new
*/
int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);

/*!
    \ingroup Setup

    \brief This function sets cipher suite list for a given WOLFSSL object
    (SSL session).  The ciphers in the list should be sorted in order of
    preference from highest to lowest.  Each call to wolfSSL_set_cipher_list()
    resets the cipher suite list for the specific SSL session to the provided
    list each time the function is called. The cipher suite list, list, is a
    null-terminated text string, and a colon-delimited list. For example, one
    value for list may be
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256".
    Valid cipher values are the full name values from the cipher_names[]
    array in src/internal.c (for a definite list of valid cipher values
    check src/internal.c)

    \return SSL_SUCCESS will be returned upon successful function completion.
    \return SSL_FAILURE will be returned on failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param list null-terminated text string and a colon-delimited list of
    cipher suites to use with the specified SSL session.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_cipher_list(ssl,
    “DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256”);
    if (ret != SSL_SUCCESS) {
    	// failed to set cipher suite list
    }
    \endcode

    \sa wolfSSL_CTX_set_cipher_list
    \sa wolfSSL_new
*/
int  wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list);

/*!
    \brief This function informs the WOLFSSL DTLS object that the underlying
     UDP I/O is non-blocking. After an application creates a WOLFSSL object,
     if it will be used with a non-blocking UDP socket, call
    wolfSSL_dtls_set_using_nonblock() on it. This lets the WOLFSSL object know
     that receiving EWOULDBLOCK means that the recvfrom call would
    block rather than that it timed out.

    \return none No return.

    \param ssl pointer to the DTLS session, created with wolfSSL_new().
    \param nonblock value used to set non-blocking flag on WOLFSSL object.
    Use 1 to specify non-blocking, otherwise 0.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    \endcode

    \sa wolfSSL_dtls_get_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
void wolfSSL_dtls_set_using_nonblock(WOLFSSL* ssl, int nonblock);
/*!
    \brief This function allows the application to determine if wolfSSL is
    using non-blocking I/O with UDP. If wolfSSL is using non-blocking I/O, this
    function will return 1, otherwise 0. After an application creates a
    WOLFSSL object, if it will be used with a non-blocking UDP socket, call
    wolfSSL_dtls_set_using_nonblock() on it. This lets the WOLFSSL object know
    that receiving EWOULDBLOCK means that the recvfrom call would block
    rather than that it timed out. This function is only meaningful to DTLS
    sessions.

    \return 0 underlying I/O is blocking.
    \return 1 underlying I/O is non-blocking.

    \param ssl pointer to the DTLS session, created with wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_dtls_get_using_nonblock(ssl);
    if (ret == 1) {
    	// underlying I/O is non-blocking
    }
    ...
    \endcode

    \sa wolfSSL_dtls_set_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_using_nonblock
*/
int  wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl);
/*!
    \brief This function returns the current timeout value in seconds for
    the WOLFSSL object. When using non-blocking sockets, something in the user
    code needs to decide when to check for available recv data and how long
    it has been waiting. The value returned by this function indicates how
    long the application should wait.

    \return seconds The current DTLS timeout value in seconds
    \return NOT_COMPILED_IN if wolfSSL was not built with DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int timeout = 0;
    WOLFSSL* ssl;
    ...
    timeout = wolfSSL_get_dtls_current_timeout(ssl);
    printf(“DTLS timeout (sec) = %d\n”, timeout);
    \endcode

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);
/*!
    \brief This function returns true if the application should setup a quicker
    timeout. When using non-blocking sockets, something in the user code needs
    to decide when to check for available data and how long it needs to wait. If
    this function returns true, it means that the library already detected some
    disruption in the communication, but it wants to wait for a little longer in
    case some messages from the other peers are still in flight. Is up to the
    application to fine tune the value of this timer, a good one may be
    dtls_get_current_timeout() / 4.

    \return true if the application code should setup a quicker timeout

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_set_send_more_acks
*/
int  wolfSSL_dtls13_use_quick_timeout(WOLFSSL *ssl);
/*!
  \ingroup Setup

    \brief This function sets whether the library should send ACKs to the other
    peer immediately when detecting disruption or not. Sending ACKs immediately
    assures minimum latency but it may consume more bandwidth than necessary. If
    the application manages the timer by itself and this option is set to 0 then
    application code can use wolfSSL_dtls13_use_quick_timeout() to determine if
    it should setup a quicker timeout to send those delayed ACKs.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param value 1 to set the option, 0 to disable the option

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_use_quick_timeout
*/
void  wolfSSL_dtls13_set_send_more_acks(WOLFSSL *ssl, int value);

/*!
    \ingroup Setup

    \brief This function sets the dtls timeout.

    \return SSL_SUCCESS returned if the function executes without an error.
    The dtls_timeout_init and the dtls_timeout members of SSL have been set.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if
    the timeout is not greater than 0. It will also return if the timeout
    argument exceeds the maximum value allowed.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param timeout an int type that will be set to the dtls_timeout_init
    member of the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUT;
    ...
    if(wolfSSL_dtls_set_timeout_init(ssl, timeout)){
    	// the dtls timeout was set
    } else {
    	// Failed to set DTLS timeout.
    }
    \endcode

    \sa wolfSSL_dtls_set_timeout_max
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int);

/*!
    \brief This function sets the maximum dtls timeout.

    \return SSL_SUCCESS returned if the function executed without an error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if
    the timeout argument is not greater than zero or is less than the
    dtls_timeout_init member of the WOLFSSL structure.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param timeout an int type representing the dtls maximum timeout.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUTVAL;
    ...
    int ret = wolfSSL_dtls_set_timeout_max(ssl);
    if(!ret){
    	// Failed to set the max timeout
    }
    \endcode

    \sa wolfSSL_dtls_set_timeout_init
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int);

/*!
    \brief When using non-blocking sockets with DTLS, this function should
    be called on the WOLFSSL object when the controlling code thinks the
    transmission has timed out. It performs the actions needed to retry
    the last transmit, including adjusting the timeout value. If it
    has been too long, this will return a failure.

    \return SSL_SUCCESS will be returned upon success
    \return SSL_FATAL_ERROR will be returned if there have been too many
    retransmissions/timeouts without getting a response from the peer.
    \return NOT_COMPILED_IN will be returned if wolfSSL was not compiled with
    DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    See the following files for usage examples:
    <wolfssl_root>/examples/client/client.c
    <wolfssl_root>/examples/server/server.c
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_got_timeout(WOLFSSL* ssl);

/*!
    \brief When using non-blocking sockets with DTLS, this function retransmits
    the last handshake flight ignoring the expected timeout value and
    retransmit count. It is useful for applications that are using DTLS and
    need to manage even the timeout and retry count.

    \return SSL_SUCCESS will be returned upon success
    \return SSL_FATAL_ERROR will be returned if there have been too many
    retransmissions/timeouts without getting a response from the peer.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls_retransmit(ssl);
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int wolfSSL_dtls_retransmit(WOLFSSL* ssl);

/*!
    \brief This function is used to determine if the SSL session has been
    configured to use DTLS.

    \return 1 If the SSL session (ssl) has been configured to use DTLS, this
    function will return 1.
    \return 0 otherwise.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls(ssl);
    if (ret) {
    	// SSL session has been configured to use DTLS
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls(WOLFSSL* ssl);

/*!
    \brief This function sets the DTLS peer, peer (sockaddr_in) with size of
    peerSz.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl    a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer   pointer to peer’s sockaddr_in structure. If NULL then the peer
                  information in ssl is cleared.
    \param peerSz size of the sockaddr_in structure pointed to by peer. If 0
                  then the peer information in ssl is cleared.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to set DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_set_pending_peer
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz);

/*!
    \brief This function sets the pending DTLS peer, peer (sockaddr_in) with
    size of peerSz. This sets the pending peer that will be upgraded to a
    regular peer when we successfully de-protect the next record. This is useful
    in scenarios where the peer's address can change to avoid off-path attackers
    from changing the peer address. This should be used with Connection ID's to
    allow seamless and safe transition to a new peer address.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl    a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer   pointer to peer’s sockaddr_in structure. If NULL then the peer
                  information in ssl is cleared.
    \param peerSz size of the sockaddr_in structure pointed to by peer. If 0
                  then the peer information in ssl is cleared.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_pending_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to set DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer,
                                   unsigned int peerSz);

/*!
    \brief This function gets the sockaddr_in (of size peerSz) of the current
    DTLS peer.  The function will compare peerSz to the actual DTLS peer size
    stored in the SSL session.  If the peer will fit into peer, the peer’s
    sockaddr_in will be copied into peer, with peerSz set to the size of peer.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer pointer to memory location to store peer’s sockaddr_in
    structure.
    \param peerSz input/output size. As input, the size of the allocated memory
    pointed to by peer.  As output, the size of the actual sockaddr_in structure
    pointed to by peer.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_get_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to get DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz);

/*!
    \brief This function gets the sockaddr_in (of size peerSz) of the current
    DTLS peer.  This is a zero-copy alternative to wolfSSL_dtls_get_peer().

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer pointer to return the internal buffer holding the peer address
    \param peerSz output the size of the actual sockaddr_in structure
    pointed to by peer.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in* addr;
    unsigned int addrSz;
    ...
    ret = wolfSSL_dtls_get_peer(ssl, &addr, &addrSz);
    if (ret != SSL_SUCCESS) {
	    // failed to get DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_get0_peer(WOLFSSL* ssl, const void** peer,
                            unsigned int* peerSz);

/*!
    \ingroup Debug

    \brief This function converts an error code returned by
    wolfSSL_get_error() into a more human-readable error string.
    errNumber is the error code returned by wolfSSL_get_error() and data
    is the storage buffer which the error string will be placed in.
    The maximum length of data is 80 characters by default, as defined by
    MAX_ERROR_SZ is wolfssl/wolfcrypt/error.h.

    \return success On successful completion, this function returns the same
    string as is returned in data.
    \return failure Upon failure, this function returns a string with the
    appropriate failure reason, msg.

    \param errNumber error code returned by wolfSSL_get_error().
    \param data output buffer containing human-readable error string matching
    errNumber.

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data);

/*!
    \ingroup Debug

    \brief This function is a version of wolfSSL_ERR_error_string() where
    len specifies the maximum number of characters that may be written to buf.
    Like wolfSSL_ERR_error_string(), this function converts an error code
    returned from wolfSSL_get_error() into a more human-readable error string.
    The human-readable string is placed in buf.

    \return none No returns.

    \param e error code returned by wolfSSL_get_error().
    \param buff output buffer containing human-readable error string matching e.
    \param len maximum length in characters which may be written to buf.

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string_n(err, buffer, 80);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long len);

/*!
    \ingroup TLS

    \brief This function checks the shutdown conditions in closeNotify or
    connReset or sentNotify members of the Options structure. The Options
    structure is within the WOLFSSL structure.

    \return 1 SSL_SENT_SHUTDOWN is returned.
    \return 2 SSL_RECEIVED_SHUTDOWN is returned.

    \param ssl a constant pointer to a WOLFSSL structure, created using
    wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    int ret;
    ret = wolfSSL_get_shutdown(ssl);

    if(ret == 1){
	    SSL_SENT_SHUTDOWN
    } else if(ret == 2){
	    SSL_RECEIVED_SHUTDOWN
    } else {
	    Fatal error.
    }
    \endcode

    \sa wolfSSL_SESSION_free
*/
int  wolfSSL_get_shutdown(const WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function returns the resuming member of the options struct. The
    flag indicates whether or not to reuse a session. If not, a new session must
    be established.

    \return This function returns an int type held in the Options structure
    representing the flag for session reuse.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(!wolfSSL_session_reused(sslResume)){
	    // No session reuse allowed.
    }
    \endcode

    \sa wolfSSL_SESSION_free
    \sa wolfSSL_GetSessionIndex
    \sa wolfSSL_memsave_session_cache
*/
int  wolfSSL_session_reused(WOLFSSL* ssl);

/*!
    \ingroup TLS

    \brief This function checks to see if the connection is established.

    \return 0 returned if the connection is not established, i.e. the WOLFSSL
    struct is NULL or the handshake is not done.
    \return 1 returned if the connection is established i.e. the WOLFSSL
    handshake is done.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _EXAMPLE_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_is_init_finished(ssl)){
	    Handshake is done and connection is established
    }
    \endcode

    \sa wolfSSL_set_accept_state
    \sa wolfSSL_get_keys
    \sa wolfSSL_set_shutdown
*/
int  wolfSSL_is_init_finished(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief Returns the SSL version being used as a string.

    \return "SSLv3" Using SSLv3
    \return "TLSv1" Using TLSv1
    \return "TLSv1.1" Using TLSv1.1
    \return "TLSv1.2" Using TLSv1.2
    \return "TLSv1.3" Using TLSv1.3
    \return "DTLS": Using DTLS
    \return "DTLSv1.2" Using DTLSv1.2
    \return "unknown" There was a problem determining which version of TLS
    being used.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);
    printf(wolfSSL_get_version("Using version: %s", ssl));
    \endcode

    \sa wolfSSL_lib_version
*/
const char*  wolfSSL_get_version(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief Returns the current cipher suit an ssl session is using.

    \return ssl->options.cipherSuite An integer representing the current
    cipher suite.
    \return 0 The ssl session provided is null.

    \param ssl The SSL session to check.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_get_current_cipher_suite(ssl) == 0)
    {
        // Error getting cipher suite
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_list
*/
int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function returns a pointer to the current cipher in the
    ssl session.

    \return The function returns the address of the cipher member of the
    WOLFSSL struct. This is a pointer to the WOLFSSL_CIPHER structure.
    \return NULL returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    WOLFSSL_CIPHER* cipherCurr = wolfSSL_get_current_cipher;

    if(!cipherCurr){
    	// Failure case.
    } else {
    	// The cipher was returned to cipherCurr
    }
    \endcode

    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function matches the cipher suite in the SSL object with
    the available suites and returns the string representation.

    \return string This function returns the string representation of the
    matched cipher suite.
    \return none It will return “None” if there are no suites matched.

    \param cipher a constant pointer to a WOLFSSL_CIPHER structure.

    _Example_
    \code
    // gets cipher name in the format DHE_RSA ...
    const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl){
	WOLFSSL_CIPHER* cipher;
	const char* fullName;
    …
	cipher = wolfSSL_get_curent_cipher(ssl);
	fullName = wolfSSL_CIPHER_get_name(cipher);

	if(fullName){
		// sanity check on returned cipher
	}
    \endcode

    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
const char*  wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup IO

    \brief This function matches the cipher suite in the SSL object with
    the available suites.

    \return This function returns the string value of the suite matched. It
    will return “None” if there are no suites matched.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    #ifdef WOLFSSL_DTLS
    …
    // make sure a valid suite is used
    if(wolfSSL_get_cipher(ssl) == NULL){
	    WOLFSSL_MSG(“Can not match cipher suite imported”);
	    return MATCH_SUITE_ERROR;
    }
    …
    #endif // WOLFSSL_DTLS
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
const char*  wolfSSL_get_cipher(WOLFSSL*);

/*!
    \ingroup Setup

    \brief This function returns the WOLFSSL_SESSION from the WOLFSSL structure
    as a reference type. This requires calling wolfSSL_SESSION_free to release
    the session reference. The WOLFSSL_SESSION pointed to contains all the
    necessary information required to perform a session resumption and
    reestablish the connection without a new handshake. For
    session resumption, before calling wolfSSL_shutdown() with your session
    object, an application should save the session ID from the object with a
    call to wolfSSL_get1_session(), which returns a pointer to the session.
    Later, the application should create a new WOLFSSL object and assign the
    saved session with wolfSSL_set_session().  At this point, the application
    may call wolfSSL_connect() and wolfSSL will try to resume the session.
    The wolfSSL server code allows session resumption by default. The object
    returned by wolfSSL_get1_session() needs to be freed after the application
    is done with it by calling wolfSSL_SESSION_free() on it.

    \return WOLFSSL_SESSION On success return session pointer.
    \return NULL will be returned if ssl is NULL, the SSL session cache is
    disabled, wolfSSL doesn’t have the Session ID available, or mutex
    functions fail.

    \param ssl WOLFSSL structure to get session from.

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* ses;
    // attempt/complete handshake
    wolfSSL_connect(ssl);
    ses  = wolfSSL_get1_session(ssl);
    // check ses information
    // disconnect / setup new SSL instance
    wolfSSL_set_session(ssl, ses);
    // attempt/resume handshake
    wolfSSL_SESSION_free(ses);
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_SESSION_free
*/
WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief The wolfSSLv23_client_method() function is used to indicate that
    the application is a client and will support the highest protocol
    version supported by the server between SSL 3.0 - TLS 1.3.  This function
    allocates memory for and initializes a new WOLFSSL_METHOD structure
    to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    Both wolfSSL clients and servers have robust version downgrade capability.
    If a specific protocol version method is used on either side, then only
    that version will be negotiated or an error will be returned.  For
    example, a client that uses TLSv1 and tries to connect to a SSLv3 only
    server will fail, likewise connecting to a TLSv1.1 will fail as well.
    To resolve this issue, a client that uses the wolfSSLv23_client_method()
    function will use the highest protocol version supported by the server and
    downgrade to SSLv3 if needed. In this case, the client will be able to
    connect to a server running SSLv3 - TLSv1.3.

    \return pointer upon success a pointer to a WOLFSSL_METHOD.
    \return Failure If memory allocation fails when calling XMALLOC,
    the failure value of the underlying malloc() implementation will be
    returned (typically NULL with errno will be set to ENOMEM).

    \param none No parameters

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;
    method = wolfSSLv23_client_method();
    if (method == NULL) {
	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD* wolfSSLv23_client_method(void);

/*!
    \ingroup IO

    \brief This is used to set a byte pointer to the start of the
    internal memory buffer.

    \return size On success the size of the buffer is returned
    \return SSL_FATAL_ERROR If an error case was encountered.

    \param bio WOLFSSL_BIO structure to get memory buffer of.
    \param p byte pointer to set to memory buffer.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    const byte* p;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_get_mem_data(bio, &p);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,void* p);

/*!
    \ingroup IO

    \brief Sets the file descriptor for bio to use.

    \return SSL_SUCCESS(1) upon success.

    \param bio WOLFSSL_BIO structure to set fd.
    \param fd file descriptor to use.
    \param closeF flag for behavior when closing fd.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int fd;
    // setup bio
    wolfSSL_BIO_set_fd(bio, fd, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int flag);

/*!
    \ingroup IO

    \brief Sets the close flag, used to indicate that the i/o stream should be
     closed when the BIO is freed

    \return SSL_SUCCESS(1) upon success.

    \param bio WOLFSSL_BIO structure.
    \param flag flag for behavior when closing i/o stream.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // setup bio
    wolfSSL_BIO_set_close(bio, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_set_close(WOLFSSL_BIO *b, long flag);

/*!
    \ingroup IO

    \brief This is used to get a BIO_SOCKET type WOLFSSL_BIO_METHOD.

    \return WOLFSSL_BIO_METHOD pointer to a WOLFSSL_BIO_METHOD structure
    that is a socket type

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void);

/*!
    \ingroup IO

    \brief This is used to set the size of write buffer for a
    WOLFSSL_BIO. If write buffer has been previously set this
    function will free it when resetting the size. It is similar to
    wolfSSL_BIO_reset in that it resets read and write indexes to 0.

    \return SSL_SUCCESS On successfully setting the write buffer.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set fd.
    \param size size of buffer to allocate.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret = wolfSSL_BIO_set_write_buf_size(bio, 15000);
    // check return value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size);

/*!
    \ingroup IO

    \brief This is used to pair two bios together. A pair of bios acts
    similar to a two way pipe writing to one can be read by the other
    and vice versa. It is expected that both bios be in the same thread,
    this function is not thread safe. Freeing one of the two bios removes
    both from being paired. If a write buffer size was not previously
    set for either of the bios it is set to a default size of 17000
    (WOLFSSL_BIO_SIZE) before being paired.

    \return SSL_SUCCESS On successfully pairing the two bios.
    \return SSL_FAILURE If an error case was encountered.

    \param b1 WOLFSSL_BIO structure to set pair.
    \param b2 second WOLFSSL_BIO structure to complete pair.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BIO* bio2;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    ret = wolfSSL_BIO_make_bio_pair(bio, bio2);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2);

/*!
    \ingroup IO

    \brief This is used to set the read request flag back to 0.

    \return SSL_SUCCESS On successfully setting value.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set read request flag.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    ...
    ret = wolfSSL_BIO_ctrl_reset_read_request(bio);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new, wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_new, wolfSSL_BIO_free
*/
int  wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief This is used to get a buffer pointer for reading from. Unlike
    wolfSSL_BIO_nread the internal read index is not advanced by the number
    returned from the function call. Reading past the value returned can
    result in reading out of array bounds.

    \return >=0 on success return the number of bytes to read

    \param bio WOLFSSL_BIO structure to read from.
    \param buf pointer to set at beginning of read array.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nread0(bio, &bufPt); // read as many bytes as possible
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite0
*/
int  wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf);

/*!
    \ingroup IO

    \brief This is used to get a buffer pointer for reading from. The internal
    read index is advanced by the number returned from the function call with
    buf being pointed to the beginning of the buffer to read from. In the
    case that less bytes are in the read buffer than the value requested with
    num the lesser value is returned. Reading past the value returned can
    result in reading out of array bounds.

    \return >=0 on success return the number of bytes to read
    \return WOLFSSL_BIO_ERROR(-1) on error case with nothing to read return -1

    \param bio WOLFSSL_BIO structure to read from.
    \param buf pointer to set at beginning of read array.
    \param num number of bytes to try and read.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;

    // set up bio
    ret = wolfSSL_BIO_nread(bio, &bufPt, 10); // try to read 10 bytes
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite
*/
int  wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO

    \brief Gets a pointer to the buffer for writing as many bytes as returned by
    the function. Writing more bytes to the pointer returned then the value
    returned can result in writing out of bounds.

    \return int Returns the number of bytes that can be written to the buffer
    pointer returned.
    \return WOLFSSL_BIO_UNSET(-2) in the case that is not part of a bio pair
    \return WOLFSSL_BIO_ERROR(-1) in the case that there is no more room to
    write to

    \param bio WOLFSSL_BIO structure to write to.
    \param buf pointer to buffer to write to.
    \param num number of bytes desired to be written.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nwrite(bio, &bufPt, 10); // try to write 10 bytes
    // handle negative ret check
    // write ret bytes to bufPt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_nread
*/
int  wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO

    \brief Resets bio to an initial state. As an example for type BIO_BIO
    this resets the read and write index.

    \return 0 On successfully resetting the bio.
    \return WOLFSSL_BIO_ERROR(-1) Returned on bad input or unsuccessful reset.

    \param bio WOLFSSL_BIO structure to reset.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // setup bio
    wolfSSL_BIO_reset(bio);
    //use pt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_reset(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief This function adjusts the file pointer to the offset given. This
    is the offset from the head of the file.

    \return 0 On successfully seeking.
    \return -1 If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set.
    \param ofs offset into file.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, &fp);
    // check ret value
    ret  = wolfSSL_BIO_seek(bio, 3);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs);

/*!
    \ingroup IO

    \brief This is used to set and write to a file. WIll overwrite any data
    currently in the file and is set to close the file when the bio is freed.

    \return SSL_SUCCESS On successfully opening and setting file.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set file.
    \param name name of file to write to.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_write_filename(bio, “test.txt”);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_file
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name);

/*!
    \ingroup IO

    \brief This is used to set the end of file value. Common value is -1 so
    as not to get confused with expected positive values.

    \return 0 returned on completion

    \param bio WOLFSSL_BIO structure to set end of file value.
    \param v value to set in bio.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_set_mem_eof_return(bio, -1);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v);

/*!
    \ingroup IO

    \brief This is a getter function for WOLFSSL_BIO memory pointer.

    \return SSL_SUCCESS On successfully getting the pointer SSL_SUCCESS is
    returned (currently value of 1).
    \return SSL_FAILURE Returned if NULL arguments are passed in (currently
    value of 0).

    \param bio pointer to the WOLFSSL_BIO structure for getting memory pointer.
    \param ptr structure that is currently a char*. Is set to point to
    bio’s memory.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BUF_MEM* pt;
    // setup bio
    wolfSSL_BIO_get_mem_ptr(bio, &pt);
    //use pt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **m);

/*!
    \ingroup CertsKeys

    \brief This function copies the name of the x509 into a buffer.

    \return A char pointer to the buffer with the WOLFSSL_X509_NAME structures
    name member’s data is returned if the function executed normally.

    \param name a pointer to a WOLFSSL_X509 structure.
    \param in a buffer to hold the name copied from the
    WOLFSSL_X509_NAME structure.
    \param sz the maximum size of the buffer.

    _Example_
    \code
    WOLFSSL_X509 x509;
    char* name;
    ...
    name = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(name <= 0){
    	// There’s nothing in the buffer.
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
char*       wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME* name, char* in, int sz);

/*!
    \ingroup CertsKeys

    \brief This function returns the name of the certificate issuer.

    \return point a pointer to the WOLFSSL_X509 struct’s issuer member is
    returned.
    \return NULL if the cert passed in is NULL.

    \param cert a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509;
    WOLFSSL_X509_NAME issuer;
    ...
    issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(!issuer){
    	// NULL was returned
    } else {
    	// issuer hods the name of the certificate issuer.
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_NAME_oneline
*/
WOLFSSL_X509_NAME*  wolfSSL_X509_get_issuer_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief This function returns the subject member of the WOLFSSL_X509
    structure.

    \return pointer a pointer to the WOLFSSL_X509_NAME structure. The pointer
    may be NULL if the WOLFSSL_X509 struct is NULL or if the subject member of
    the structure is NULL.

    \param cert a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* cert;
    WOLFSSL_X509_NAME name;
    …
    name = wolfSSL_X509_get_subject_name(cert);
    if(name == NULL){
	    // Deal with the NULL cacse
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_X509_NAME*  wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief Checks the isCa member of the WOLFSSL_X509 structure and returns
    the value.

    \return isCA returns the value in the isCA member of the WOLFSSL_X509
    structure is returned.
    \return 0 returned if there is not a valid x509 structure passed in.

    \param cert a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_X509_get_isCA(ssl)){
    	// This is the CA
    }else {
    	// Failure case
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
*/
int  wolfSSL_X509_get_isCA(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief This function gets the text related to the passed in NID value.

    \return int returns the size of the text buffer.

    \param name WOLFSSL_X509_NAME to search for text.
    \param nid NID to search for.
    \param buf buffer to hold text when found.
    \param len length of buffer.

    _Example_
    \code
    WOLFSSL_X509_NAME* name;
    char buffer[100];
    int bufferSz;
    int ret;
    // get WOLFSSL_X509_NAME
    ret = wolfSSL_X509_NAME_get_text_by_NID(name, NID_commonName,
    buffer, bufferSz);

    //check ret value
    \endcode

    \sa none
*/
int wolfSSL_X509_NAME_get_text_by_NID(WOLFSSL_X509_NAME* name, int nid,
                                      char* buf, int len);

/*!
    \ingroup CertsKeys

    \brief This function returns the value stored in the sigOID
    member of the WOLFSSL_X509 structure.

    \return 0 returned if the WOLFSSL_X509 structure is NULL.
    \return int an integer value is returned which was retrieved from
    the x509 object.

    \param cert a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509SigType = wolfSSL_X509_get_signature_type(x509);

    if(x509SigType != EXPECTED){
	// Deal with an unexpected value
    }
    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_notAfter
    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_get_signature_type(WOLFSSL_X509* cert);

/*!
    \brief This function frees a WOLFSSL_X509 structure.


    \param x509 a pointer to the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;

    wolfSSL_X509_free(x509);

    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_notAfter

*/
void wolfSSL_X509_free(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets the X509 signature and stores it in the buffer.

    \return SSL_SUCCESS returned if the function successfully executes.
    The signature is loaded into the buffer.
    \return SSL_FATAL_ERRROR returns if the x509 struct or the bufSz member
    is NULL. There is also a check for the length member of the sig structure
    (sig is a member of x509).

    \param x509 pointer to a WOLFSSL_X509 structure.
    \param buf a char pointer to the buffer.
    \param bufSz an integer pointer to the size of the buffer.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    unsigned char* buf; // Initialize
    int* bufSz = sizeof(buf)/sizeof(unsigned char);
    ...
    if(wolfSSL_X509_get_signature(x509, buf, bufSz) != SSL_SUCCESS){
	    // The function did not execute successfully.
    } else{
	    // The buffer was written to correctly.
    }
    \endcode

    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_get_signature_type
    \sa wolfSSL_X509_get_device_type
*/
int wolfSSL_X509_get_signature(WOLFSSL_X509* x509, unsigned char* buf, int* bufSz);

/*!
    \ingroup CertsKeys

    \brief This function adds a certificate to the WOLFSSL_X509_STRE structure.

    \return SSL_SUCCESS If certificate is added successfully.
    \return SSL_FATAL_ERROR: If certificate is not added successfully.

    \param str certificate store to add the certificate to.
    \param x509 certificate to add.

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    WOLFSSL_X509* x509;
    int ret;
    ret = wolfSSL_X509_STORE_add_cert(str, x509);
    //check ret value
    \endcode

    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_STORE_add_cert(WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief This function is a getter function for chain variable
    in WOLFSSL_X509_STORE_CTX structure. Currently chain is not populated.

    \return pointer if successful returns WOLFSSL_STACK
    (same as STACK_OF(WOLFSSL_X509)) pointer
    \return Null upon failure

    \param ctx certificate store ctx to get parse chain from.

    _Example_
    \code
    WOLFSSL_STACK* sk;
    WOLFSSL_X509_STORE_CTX* ctx;
    sk = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode

    \sa wolfSSL_sk_X509_free
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief This function takes in a flag to change the behavior of the
    WOLFSSL_X509_STORE structure passed in. An example of a flag used
    is WOLFSSL_CRL_CHECK.

    \return SSL_SUCCESS If no errors were encountered when setting the flag.
    \return <0 a negative value will be returned upon failure.

    \param str certificate store to set flag in.
    \param flag flag for behavior.

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    int ret;
    // create and set up str
    ret = wolfSSL_X509_STORE_set_flags(str, WOLFSSL_CRL_CHECKALL);
    If (ret != SSL_SUCCESS) {
    	//check ret value and handle error case
    }
    \endcode

    \sa wolfSSL_X509_STORE_new
    \sa wolfSSL_X509_STORE_free
*/
int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store,
                                                            unsigned long flag);

/*!
    \ingroup CertsKeys

    \brief This function the certificate "not before" validity encoded as
    a byte array.


    \return NULL returned if the WOLFSSL_X509 structure is NULL.
    \return byte is returned that contains the notBeforeData.

    \param x509 pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    byte* notBeforeData = wolfSSL_X509_notBefore(x509);


    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notAfter
    \sa wolfSSL_X509_free
*/
const byte* wolfSSL_X509_notBefore(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief This function the certificate "not after" validity encoded as
    a byte array.

    \return NULL returned if the WOLFSSL_X509 structure is NULL.
    \return byte is returned that contains the notAfterData.

    \param x509 pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    byte* notAfterData = wolfSSL_X509_notAfter(x509);


    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_free
*/
const byte* wolfSSL_X509_notAfter(WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief This function is used to copy a WOLFSSL_ASN1_INTEGER
    value to a WOLFSSL_BIGNUM structure.

    \return pointer On successfully copying the WOLFSSL_ASN1_INTEGER
    value a WOLFSSL_BIGNUM pointer is returned.
    \return Null upon failure.

    \param ai WOLFSSL_ASN1_INTEGER structure to copy from.
    \param bn if wanting to copy into an already existing
    WOLFSSL_BIGNUM struct then pass in a pointer to it.
    Optionally this can be NULL and a new WOLFSSL_BIGNUM
    structure will be created.

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* ai;
    WOLFSSL_BIGNUM* bn;
    // create ai
    bn = wolfSSL_ASN1_INTEGER_to_BN(ai, NULL);

    // or if having already created bn and wanting to reuse structure
    // wolfSSL_ASN1_INTEGER_to_BN(ai, bn);
    // check bn is or return value is not NULL
    \endcode

    \sa none
*/
WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
                                       WOLFSSL_BIGNUM *bn);

/*!
    \ingroup Setup

    \brief This function adds the certificate to the internal chain
    being built in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS after successfully adding the certificate.
    \return SSL_FAILURE if failing to add the certificate to the chain.

    \param ctx WOLFSSL_CTX structure to add certificate to.
    \param x509 certificate to add to the chain.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL_X509* x509;
    int ret;
    // create ctx
    ret = wolfSSL_CTX_add_extra_chain_cert(ctx, x509);
    // check ret value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief This function returns the get read ahead flag from a
    WOLFSSL_CTX structure.

    \return flag On success returns the read ahead flag.
    \return SSL_FAILURE If ctx is NULL then SSL_FAILURE is returned.

    \param ctx WOLFSSL_CTX structure to get read ahead flag from.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    // setup ctx
    flag = wolfSSL_CTX_get_read_ahead(ctx);
    //check flag
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_read_ahead
*/
int  wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function sets the read ahead flag in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS If ctx read ahead flag set.
    \return SSL_FAILURE If ctx is NULL then SSL_FAILURE is returned.

    \param ctx WOLFSSL_CTX structure to set read ahead flag.
    \param v read ahead flag

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_read_ahead(ctx, flag);
    // check return value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_get_read_ahead
*/
int  wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX* ctx, int v);

/*!
    \ingroup Setup

    \brief This function sets the options argument to use with OCSP.

    \return SSL_FAILURE If ctx or it’s cert manager is NULL.
    \return SSL_SUCCESS If successfully set.

    \param ctx WOLFSSL_CTX structure to set user argument.
    \param arg user argument.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_status_arg(ctx, data);

    //check ret value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup CertsKeys

    \brief Sets a callback to select the client certificate and private key.

    This function allows the application to register a callback that will be invoked
    when a client certificate is requested during the handshake. The callback can
    select and provide the certificate and key to use.

    \param ctx The WOLFSSL_CTX object.
    \param cb  The callback function to select the client certificate and key.

    \return void

    _Example_
    \code
    int my_client_cert_cb(WOLFSSL *ssl, WOLFSSL_X509 **x509, WOLFSSL_EVP_PKEY **pkey) { ... }
    wolfSSL_CTX_set_client_cert_cb(ctx, my_client_cert_cb);
    \endcode

    \sa wolfSSL_CTX_set_cert_cb
*/
void wolfSSL_CTX_set_client_cert_cb(WOLFSSL_CTX *ctx, client_cert_cb cb);

/*!
    \ingroup CertsKeys

    \brief Sets a generic certificate setup callback.

    This function allows the application to register a callback that will be invoked
    during certificate setup. The callback can perform custom certificate selection
    or loading logic.

    \param ctx The WOLFSSL_CTX object.
    \param cb  The callback function for certificate setup.
    \param arg User argument to pass to the callback.

    \return void

    _Example_
    \code
    int my_cert_setup_cb(WOLFSSL* ssl, void* arg) { ... }
    wolfSSL_CTX_set_cert_cb(ctx, my_cert_setup_cb, NULL);
    \endcode

    \sa wolfSSL_CTX_set_client_cert_cb
*/
void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx, CertSetupCallback cb, void *arg);

/*!
    \ingroup OCSP

    \brief Sets the callback to be used for handling OCSP status requests (OCSP stapling).

    This function allows the application to register a callback that will be invoked
    when an OCSP status request is received during the TLS handshake. The callback
    can provide an OCSP response to be stapled to the handshake. This API is only
    useful on the server side.

    \param ctx The WOLFSSL_CTX object.
    \param cb  The callback function to handle OCSP status requests.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    _Example_
    \code
    int my_ocsp_status_cb(WOLFSSL* ssl, void* arg) { ... }
    wolfSSL_CTX_set_tlsext_status_cb(ctx, my_ocsp_status_cb);
    \endcode

    \sa wolfSSL_CTX_get_tlsext_status_cb
    \sa wolfSSL_CTX_set_tlsext_status_arg
*/
int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb);

/*!
    \ingroup OCSP

    \brief Gets the currently set OCSP status callback for the context.

    \param ctx The WOLFSSL_CTX object.
    \param cb  Pointer to receive the callback function.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    \sa wolfSSL_CTX_set_tlsext_status_cb
*/
int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb);

/*!
    \ingroup OCSP

    \brief Sets the argument to be passed to the OCSP status callback.

    \param ctx The WOLFSSL_CTX object.
    \param arg The user argument to pass to the callback.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    \sa wolfSSL_CTX_set_tlsext_status_cb
*/
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup OCSP

    \brief Gets the OCSP response that will be sent (stapled) to the peer.

    \param ssl The WOLFSSL session.
    \param resp Pointer to receive the response buffer.

    \return Length of the response, or negative value on error.

    \sa wolfSSL_set_tlsext_status_ocsp_resp
*/
long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char **resp);

/*!
    \ingroup OCSP

    \brief Sets the OCSP response to be sent (stapled) to the peer.

    The buffer in resp becomes owned by wolfSSL and will be freed by
    wolfSSL. The application must not free the buffer after calling this
    function.

    \param ssl The WOLFSSL session.
    \param resp Pointer to the response buffer.
    \param len  Length of the response buffer.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    \sa wolfSSL_get_tlsext_status_ocsp_resp
*/
long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char *resp, int len);

/*!
    \ingroup OCSP

    \brief Sets multiple OCSP responses for TLS multi-certificate chains.

    The buffer in resp becomes owned by wolfSSL and will be freed by
    wolfSSL. The application must not free the buffer after calling this
    function.

    \param ssl The WOLFSSL session.
    \param resp Pointer to the response buffer.
    \param len  Length of the response buffer.
    \param idx  Index of the certificate chain.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.
*/
int wolfSSL_set_tlsext_status_ocsp_resp_multi(WOLFSSL* ssl, unsigned char *resp, int len, word32 idx);

/*!
    \ingroup OCSP

    \brief Sets a callback to verify the OCSP status response.

    It is recommended to enable SESSION_CERTS in order to have access to the
    peer's certificate chain during OCSP verification.

    \param ctx   The WOLFSSL_CTX object.
    \param cb    The callback function.
    \param cbArg User argument to pass to the callback.

    \return void

    _Example_
    \code
    void my_ocsp_verify_cb(WOLFSSL* ssl, int err, byte* resp, word32 respSz, word32 idx, void* arg)
    {
        (void)arg;
        if (err == 0 && staple && stapleSz > 0) {
            printf("Client: OCSP staple received, size=%u\n", stapleSz);
            return 0;
        }
        // Manual OCSP staple verification if err != 0
        if (err != 0 && staple && stapleSz > 0) {
            WOLFSSL_CERT_MANAGER* cm = NULL;
            DecodedCert cert;
            byte certInit = 0;
            WOLFSSL_OCSP* ocsp = NULL;
            WOLFSSL_X509_CHAIN* peerCerts;
            int i;

            cm = wolfSSL_CertManagerNew();
            if (cm == NULL)
                goto cleanup;
            if (wolfSSL_CertManagerLoadCA(cm, CA_CERT, NULL) != WOLFSSL_SUCCESS)
                goto cleanup;

            peerCerts = wolfSSL_get_peer_chain(ssl);
            if (peerCerts == NULL || wolfSSL_get_chain_count(peerCerts) <= (int)idx)
                goto cleanup;

            for (i = idx + 1; i < wolfSSL_get_chain_count(peerCerts); i++) {
                if (wolfSSL_CertManagerLoadCABuffer(cm, wolfSSL_get_chain_cert(peerCerts, i),
                        wolfSSL_get_chain_length(peerCerts, i), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
                    goto cleanup;
            }

            wc_InitDecodedCert(&cert, wolfSSL_get_chain_cert(peerCerts, idx), wolfSSL_get_chain_length(peerCerts, idx), NULL);
            certInit = 1;
            if (wc_ParseCert(&cert, CERT_TYPE, VERIFY, cm) != 0)
                goto cleanup;
            if ((ocsp = wc_NewOCSP(cm)) == NULL)
                goto cleanup;
            if (wc_CheckCertOcspResponse(ocsp, &cert, staple, stapleSz, NULL) != 0)
                goto cleanup;

            printf("Client: Manual OCSP staple verification succeeded for idx=%u\n", idx);
            err = 0;
    cleanup:
            wc_FreeOCSP(ocsp);
            if (certInit)
                wc_FreeDecodedCert(&cert);
            wolfSSL_CertManagerFree(cm);
            if (err == 0)
                return 0;
            printf("Client: Manual OCSP staple verification failed for idx=%u\n", idx);
        }
        printf("Client: OCSP staple verify error=%d\n", err);
        return err;
    }
    wolfSSL_CTX_set_ocsp_status_verify_cb(ctx, my_ocsp_verify_cb, NULL);
    \endcode
*/
void wolfSSL_CTX_set_ocsp_status_verify_cb(WOLFSSL_CTX* ctx, ocspVerifyStatusCb cb, void* cbArg);

/*!
    \ingroup Setup

    \brief This function sets the optional argument to be passed to
    the PRF callback.

    \return SSL_FAILURE If ctx is NULL.
    \return SSL_SUCCESS If successfully set.

    \param ctx WOLFSSL_CTX structure to set user argument.
    \param arg user argument.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_opaques_prf_input_callback_arg(ctx, data);
    //check ret value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(
        WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup Setup

    \brief This function sets the options mask in the ssl.
    Some valid options are, SSL_OP_ALL, SSL_OP_COOKIE_EXCHANGE,
    SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3, SSL_OP_NO_TLSv1,
    SSL_OP_NO_TLSv1_1, SSL_OP_NO_TLSv1_2, SSL_OP_NO_COMPRESSION.

    \return val Returns the updated options mask value stored in ssl.

    \param s WOLFSSL structure to set options mask.
    \param op This function sets the options mask in the ssl.
    Some valid options are:
    SSL_OP_ALL
    SSL_OP_COOKIE_EXCHANGE
    SSL_OP_NO_SSLv2
    SSL_OP_NO_SSLv3
    SSL_OP_NO_TLSv1
    SSL_OP_NO_TLSv1_1
    SSL_OP_NO_TLSv1_2
    SSL_OP_NO_COMPRESSION

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask = SSL_OP_NO_TLSv1
    mask  = wolfSSL_set_options(ssl, mask);
    // check mask
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_get_options
*/
long wolfSSL_set_options(WOLFSSL *s, long op);

/*!
    \ingroup Setup

    \brief This function returns the current options mask.

    \return val Returns the mask value stored in ssl.

    \param ssl WOLFSSL structure to get options mask from.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask  = wolfSSL_get_options(ssl);
    // check mask
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_set_options
*/
long wolfSSL_get_options(const WOLFSSL *ssl);

/*!
    \ingroup Setup

    \brief This is used to set the debug argument passed around.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If an NULL ssl passed in.

    \param ssl WOLFSSL structure to set argument in.
    \param arg argument to use.

    _Example_
    \code
    WOLFSSL* ssl;
    void* args;
    int ret;
    // create ssl object
    ret  = wolfSSL_set_tlsext_debug_arg(ssl, args);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_set_tlsext_debug_arg(WOLFSSL *ssl, void *arg);

/*!
    \ingroup openSSL

    \brief This function is called when the client application request
    that a server send back an OCSP status response (also known as
    OCSP stapling).Currently, the only supported type is
    TLSEXT_STATUSTYPE_ocsp.

    \return 1 upon success.
    \return 0 upon error.

    \param s pointer to WOLFSSL struct which is created by SSL_new() function
    \param type ssl extension type which TLSEXT_STATUSTYPE_ocsp is
    only supported.

    _Example_
    \code
    WOLFSSL *ssl;
    WOLFSSL_CTX *ctx;
    int ret;
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    ssl = wolfSSL_new(ctx);
    ret = WolfSSL_set_tlsext_status_type(ssl,TLSEXT_STATUSTYPE_ocsp);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type);

/*!
    \ingroup Setup

    \brief This is used to get the results after trying to verify the peer's
    certificate.

    \return X509_V_OK On successful verification.
    \return SSL_FAILURE If an NULL ssl passed in.

    \param ssl WOLFSSL structure to get verification results from.

    _Example_
    \code
    WOLFSSL* ssl;
    long ret;
    // attempt/complete handshake
    ret  = wolfSSL_get_verify_result(ssl);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_get_verify_result(const WOLFSSL *ssl);

/*!
    \ingroup Debug

    \brief This function converts an error code returned by
    wolfSSL_get_error() into a more human-readable error string
    and prints that string to the output file - fp.  err is the
    error code returned by wolfSSL_get_error() and fp is the
    file which the error string will be placed in.

    \return none No returns.

    \param fp output file for human-readable error string to be written to.
    \param err error code returned by wolfSSL_get_error().

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    FILE* fp = ...
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_print_errors_fp(fp, err);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_print_errors_fp(XFILE fp, int err);

/*!
    \ingroup Debug

    \brief This function uses the provided callback to handle error reporting.
    The callback function is executed for each error line. The string, length,
    and userdata are passed into the callback parameters.

    \return none No returns.

    \param cb the callback function.
    \param u userdata to pass into the callback function.

    _Example_
    \code
    int error_cb(const char *str, size_t len, void *u)
    { fprintf((FILE*)u, "%-*.*s\n", (int)len, (int)len, str); return 0; }
    ...
    FILE* fp = ...
    wolfSSL_ERR_print_errors_cb(error_cb, fp);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_print_errors_cb (
        int (*cb)(const char *str, size_t len, void *u), void *u);

/*!
    \brief The function sets the client_psk_cb member of the
    WOLFSSL_CTX structure.

    \return none No returns.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param cb wc_psk_client_callback is a function pointer that will be
    stored in the WOLFSSL_CTX structure. Return value is the key length on
    success or zero on error.
    unsigned int (*wc_psk_client_callback)
    PSK client callback parameters:
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    const char* hint - A stored string that could be displayed to provide a
                        hint to the user.
    char* identity - The ID will be stored here.
    unsigned int id_max_len - Size of the ID buffer.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    …
    static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    Unsigned int key_max_len){
    …
    wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
    \endcode

    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx,
                                                    wc_psk_client_callback cb);

/*!
    \brief Sets the PSK client side callback.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to type wc_psk_client_callback. Return value
    is the key length on success or zero on error.
    unsigned int (*wc_psk_client_callback)
    PSK client callback parameters:
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    const char* hint - A stored string that could be displayed to provide a
                        hint to the user.
    char* identity - The ID will be stored here.
    unsigned int id_max_len - Size of the ID buffer.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.

    _Example_
    \code
    WOLFSSL* ssl;
    static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    Unsigned int key_max_len){
    …
    if(ssl){
    wolfSSL_set_psk_client_callback(ssl, my_psk_client_cb);
    } else {
    	// could not set callback
    }
    \endcode

    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_set_psk_server_callback
*/
void wolfSSL_set_psk_client_callback(WOLFSSL* ssl,
                                                    wc_psk_client_callback);

/*!
    \ingroup CertsKeys

    \brief This function returns the psk identity hint.

    \return pointer a const char pointer to the value that was stored in
    the arrays member of the WOLFSSL structure is returned.
    \return NULL returned if the WOLFSSL or Arrays structures are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* idHint;
    ...
    idHint = wolfSSL_get_psk_identity_hint(ssl);
    if(idHint){
    	// The hint was retrieved
    	return idHint;
    } else {
    	// Hint wasn’t successfully retrieved
    }
    \endcode

    \sa wolfSSL_get_psk_identity
*/
const char* wolfSSL_get_psk_identity_hint(const WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief The function returns a constant pointer to the client_identity
    member of the Arrays structure.

    \return string the string value of the client_identity member of the
    Arrays structure.
    \return NULL if the WOLFSSL structure is NULL or if the Arrays member of
    the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* pskID;
    ...
    pskID = wolfSSL_get_psk_identity(ssl);

    if(pskID == NULL){
	    // There is not a value in pskID
    }
    \endcode

    \sa wolfSSL_get_psk_identity_hint
    \sa wolfSSL_use_psk_identity_hint
*/
const char* wolfSSL_get_psk_identity(const WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief This function stores the hint argument in the server_hint
    member of the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned for successful execution of the function.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param hint a constant char pointer that will be copied to the
    WOLFSSL_CTX structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    const char* hint;
    int ret;
    …
    ret = wolfSSL_CTX_use_psk_identity_hint(ctx, hint);
    if(ret == SSL_SUCCESS){
    	// Function was successful.
	return ret;
    } else {
    	// Failure case.
    }
    \endcode

    \sa wolfSSL_use_psk_identity_hint
*/
int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint);

/*!
    \ingroup CertsKeys

    \brief This function stores the hint argument in the server_hint member
    of the Arrays structure within the WOLFSSL structure.

    \return SSL_SUCCESS returned if the hint was successfully stored in the
    WOLFSSL structure.
    \return SSL_FAILURE returned if the WOLFSSL or Arrays structures are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param hint a constant character pointer that holds the hint to be saved
    in memory.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* hint;
    ...
    if(wolfSSL_use_psk_identity_hint(ssl, hint) != SSL_SUCCESS){
    	// Handle failure case.
    }
    \endcode

    \sa wolfSSL_CTX_use_psk_identity_hint
*/
int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint);

/*!
    \brief This function sets the psk callback for the server side in
    the WOLFSSL_CTX structure.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer for the callback and will be stored in
    the WOLFSSL_CTX structure. Return value is the key length on success or
    zero on error.
    unsigned int (*wc_psk_server_callback)
    PSK server callback parameters
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    char* identity - The ID will be stored here.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // Function body.
    }
    …
    if(ctx != NULL){
        wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    } else {
    	// The CTX object was not properly initialized.
    }
    \endcode

    \sa wc_psk_server_callback
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx,
                                                    wc_psk_server_callback cb);

/*!
    \brief Sets the psk callback for the server side by setting the
    WOLFSSL structure options members.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer for the callback and will be stored in
    the WOLFSSL structure. Return value is the key length on success or  zero
    on error.
    unsigned int (*wc_psk_server_callback)
    PSK server callback parameters
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    char* identity - The ID will be stored here.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.


    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // Function body.
    }
    …
    if(ssl != NULL && cb != NULL){
        wolfSSL_set_psk_server_callback(ssl, my_psk_server_cb);
    }
    \endcode

    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_get_psk_identity_hint
    \sa wc_psk_server_callback
    \sa InitSuites
*/
void wolfSSL_set_psk_server_callback(WOLFSSL* ssl,
                                                    wc_psk_server_callback cb);


/*!
    \brief Sets a PSK user context in the WOLFSSL structure options member.

    \return WOLFSSL_SUCCESS or WOLFSSL_FAILURE

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param psk_ctx void pointer to user PSK context

    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_set_psk_callback_ctx(WOLFSSL* ssl, void* psk_ctx);

/*!
    \brief Sets a PSK user context in the WOLFSSL_CTX structure.

    \return WOLFSSL_SUCCESS or WOLFSSL_FAILURE

    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param psk_ctx void pointer to user PSK context

    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_CTX_set_psk_callback_ctx(WOLFSSL_CTX* ctx, void* psk_ctx);

/*!
    \brief Get a PSK user context in the WOLFSSL structure options member.

    \return void pointer to user PSK context

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl);

/*!
    \brief Get a PSK user context in the WOLFSSL_CTX structure.

    \return void pointer to user PSK context

    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().

    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
*/
void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function enables the havAnon member of the CTX structure if
    HAVE_ANON is defined during compilation.

    \return SSL_SUCCESS returned if the function executed successfully and the
    haveAnnon member of the CTX is set to 1.
    \return SSL_FAILURE returned if the CTX structure was NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    #ifdef HAVE_ANON
	if(cipherList == NULL){
	    wolfSSL_CTX_allow_anon_cipher(ctx);
	    if(wolfSSL_CTX_set_cipher_list(ctx, “ADH_AES128_SHA”) != SSL_SUCCESS){
		    // failure case
	    }
    }
    #endif
    \endcode

    \sa none
*/
int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief The wolfSSLv23_server_method() function is used to indicate
    that the application is a server and will support clients connecting
    with protocol version from SSL 3.0 - TLS 1.3.  This function allocates
    memory for and initializes a new WOLFSSL_METHOD structure to be used when
    creating the SSL/TLS context with wolfSSL_CTX_new().

    \return pointer If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return Failure If memory allocation fails when calling XMALLOC, the
    failure value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv23_server_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv23_server_method(void);

/*!
    \ingroup Setup

    \brief This is used to get the internal error state of the WOLFSSL structure.

    \return wolfssl_error returns ssl error state, usually a negative
    \return BAD_FUNC_ARG if ssl is NULL.

    \return ssl WOLFSSL structure to get state from.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create ssl object
    ret  = wolfSSL_state(ssl);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int  wolfSSL_state(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief This function gets the peer’s certificate.

    \return pointer a pointer to the peerCert member of the WOLFSSL_X509
    structure if it exists.
    \return 0 returned if the peer certificate issuer size is not defined.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    WOLFSSL_X509* peerCert = wolfSSL_get_peer_certificate(ssl);

    if(peerCert){
    	// You have a pointer peerCert to the peer certification
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);

/*!
    \ingroup Debug

    \brief This function is similar to calling wolfSSL_get_error() and
    getting SSL_ERROR_WANT_READ in return.  If the underlying error state
    is SSL_ERROR_WANT_READ, this function will return 1, otherwise, 0.

    \return 1 wolfSSL_get_error() would return SSL_ERROR_WANT_READ, the
    underlying I/O has data available for reading.
    \return 0 There is no SSL_ERROR_WANT_READ error state.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_want_read(ssl);
    if (ret == 1) {
    	// underlying I/O has data available for reading (SSL_ERROR_WANT_READ)
    }
    \endcode

    \sa wolfSSL_want_write
    \sa wolfSSL_get_error
*/
int wolfSSL_want_read(WOLFSSL*);

/*!
    \ingroup Debug

    \brief This function is similar to calling wolfSSL_get_error() and getting
    SSL_ERROR_WANT_WRITE in return. If the underlying error state is
    SSL_ERROR_WANT_WRITE, this function will return 1, otherwise, 0.

    \return 1 wolfSSL_get_error() would return SSL_ERROR_WANT_WRITE, the
    underlying I/O needs data to be written in order for progress to be
    made in the underlying SSL connection.
    \return 0 There is no SSL_ERROR_WANT_WRITE error state.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_want_write(ssl);
    if (ret == 1) {
    	// underlying I/O needs data to be written (SSL_ERROR_WANT_WRITE)
    }
    \endcode

    \sa wolfSSL_want_read
    \sa wolfSSL_get_error
*/
int wolfSSL_want_write(WOLFSSL*);

/*!
    \ingroup Setup

    \brief wolfSSL by default checks the peer certificate for a valid date
    range and a verified signature.  Calling this function before
    wolfSSL_connect() or wolfSSL_accept() will add a domain name check to
    the list of checks to perform.  dn holds the domain name to check
    against the peer certificate when it’s received.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE will be returned if a memory error was encountered.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param dn domain name to check against the peer certificate when received.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    char* domain = (char*) “www.yassl.com”;
    ...

    ret = wolfSSL_check_domain_name(ssl, domain);
    if (ret != SSL_SUCCESS) {
       // failed to enable domain name check
    }
    \endcode

    \sa none
*/
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn);

/*!
    \ingroup TLS

    \brief Initializes the wolfSSL library for use.  Must be called once per
    application and before any other call to the library.

    \return SSL_SUCCESS If successful the call will return.
    \return BAD_MUTEX_E is an error that may be returned.
    \return WC_INIT_E wolfCrypt initialization error returned.

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL library
    }

    \endcode

    \sa wolfSSL_Cleanup
*/
int wolfSSL_Init(void);

/*!
    \ingroup TLS

    \brief Un-initializes the wolfSSL library from further use. Doesn’t have
    to be called, though it will free any resources used by the library.

    \return SSL_SUCCESS return no errors.
    \return BAD_MUTEX_E a mutex error return.]

    _Example_
    \code
    wolfSSL_Cleanup();
    \endcode

    \sa wolfSSL_Init
*/
int wolfSSL_Cleanup(void);

/*!
    \ingroup IO

    \brief This function returns the current library version.

    \return LIBWOLFSSL_VERSION_STRING a const char pointer defining the
    version.

    \param none No parameters.

    _Example_
    \code
    char version[MAXSIZE];
    version = wolfSSL_KeepArrays();
    …
    if(version != ExpectedVersion){
	    // Handle the mismatch case
    }
    \endcode

    \sa word32_wolfSSL_lib_version_hex
*/
const char* wolfSSL_lib_version(void);

/*!
    \ingroup IO

    \brief This function returns the current library version in hexadecimal
    notation.

    \return LILBWOLFSSL_VERSION_HEX returns the hexadecimal version defined in
     wolfssl/version.h.

    \param none No parameters.

    _Example_
    \code
    word32 libV;
    libV = wolfSSL_lib_version_hex();

    if(libV != EXPECTED_HEX){
	    // How to handle an unexpected value
    } else {
	    // The expected result for libV
    }
    \endcode

    \sa wolfSSL_lib_version
*/
word32 wolfSSL_lib_version_hex(void);

/*!
    \ingroup IO

    \brief Performs the actual connect or accept based on the side of the SSL
    method.  If called from the client side then an wolfSSL_connect() is done
    while a wolfSSL_accept() is performed if called from the server side.

    \return SSL_SUCCESS will be returned if successful. (Note, older versions
    will return 0.)
    \return SSL_FATAL_ERROR will be returned if the underlying call resulted
    in an error. Use wolfSSL_get_error() to get a specific error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret = SSL_FATAL_ERROR;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_negotiate(ssl);
    if (ret == SSL_FATAL_ERROR) {
    	// SSL establishment failed
	int error_code = wolfSSL_get_error(ssl);
	...
    }
    ...
    \endcode

    \sa SSL_connect
    \sa SSL_accept
*/
int wolfSSL_negotiate(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Turns on the ability to use compression for the SSL connection.
    Both sides must have compression turned on otherwise compression will not be
    used. The zlib library performs the actual data compression. To compile
    into the library use --with-libz for the configure system and define
    HAVE_LIBZ otherwise. Keep in mind that while compressing data before
    sending decreases the actual size of the messages being sent and received,
    the amount of data saved by compression usually takes longer in time to
    analyze than it does to send it raw on all but the slowest of networks.

    \return SSL_SUCCESS upon success.
    \return NOT_COMPILED_IN will be returned if compression support wasn’t
    built into the library.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_compression(ssl);
    if (ret == SSL_SUCCESS) {
    	// successfully enabled compression for SSL session
    }
    \endcode

    \sa none
*/
int wolfSSL_set_compression(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the SSL session timeout value in seconds.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned if ssl is NULL.

    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param to value, in seconds, used to set the SSL session timeout.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_timeout(ssl, 500);
    if (ret != SSL_SUCCESS) {
    	// failed to set session timeout value
    }
    ...
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
int wolfSSL_set_timeout(WOLFSSL* ssl, unsigned int to);

/*!
    \ingroup Setup

    \brief This function sets the timeout value for SSL sessions, in seconds,
    for the specified SSL context.

    \return the previous timeout value, if WOLFSSL_ERROR_CODE_OPENSSL is
    \return defined on success. If not defined, SSL_SUCCESS will be returned.
    \return BAD_FUNC_ARG will be returned when the input context (ctx) is null.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param to session timeout value in seconds.

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    ret = wolfSSL_CTX_set_timeout(ctx, 500);
    if (ret != SSL_SUCCESS) {
	    // failed to set session timeout value
    }
    \endcode

    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_session_cache_mode
*/
int wolfSSL_CTX_set_timeout(WOLFSSL_CTX* ctx, unsigned int to);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s certificate chain.

    \return chain If successful the call will return the peer’s
    certificate chain.
    \return 0 will be returned if an invalid WOLFSSL pointer is passed to the
    function.

    \param ssl pointer to a valid WOLFSSL structure.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Retrieve's the peers certificate chain count.

    \return Success If successful the call will return the peer’s certificate
    chain count.
    \return 0 will be returned if an invalid chain pointer is passed to
    the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
int  wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s ASN1.DER certificate length in bytes
    at index (idx).

    \return Success If successful the call will return the peer’s
    certificate length in bytes by index.
    \return 0 will be returned if an invalid chain pointer is passed
    to the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx index to start of chain.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
int  wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s ASN1.DER certificate at index (idx).

    \return Success If successful the call will return the peer’s
    certificate by index.
    \return 0 will be returned if an invalid chain pointer is passed
    to the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx index to start of chain.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert_pem
*/
unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup CertsKeys

    \brief This function gets the peer’s wolfSSL_X509_certificate at
    index (idx) from the chain of certificates.

    \return pointer returns a pointer to a WOLFSSL_X509 structure.

    \param chain a pointer to the WOLFSSL_X509_CHAIN used for no dynamic
    memory SESSION_CACHE.
    \param idx the index of the WOLFSSL_X509 certificate.

    Note that it is the user's responsibility to free the returned memory
    by calling wolfSSL_FreeX509().

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = &session->chain;
    int idx = 999; // set idx
    ...
    WOLFSSL_X509_CHAIN ptr;
    prt = wolfSSL_get_chain_X509(chain, idx);

    if(ptr != NULL){
        // ptr contains the cert at the index specified
        wolfSSL_FreeX509(ptr);
    } else {
        // ptr is NULL
    }
    \endcode

    \sa InitDecodedCert
    \sa ParseCertRelative
    \sa CopyDecodedToX509
*/
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s PEM certificate at index (idx).

    \return Success If successful the call will return the peer’s
    certificate by index.
    \return 0 will be returned if an invalid chain pointer is passed to
    the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx indexto start of chain.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
*/
int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx,
                                unsigned char* buf, int inLen, int* outLen);

/*!
    \ingroup openSSL

    \brief Retrieves the session’s ID.  The session ID is always 32 bytes long.

    \return id The session ID.

    \param session pointer to a valid wolfssl session.

    _Example_
    \code
    none
    \endcode

    \sa SSL_get_session
*/
const unsigned char* wolfSSL_get_sessionID(const WOLFSSL_SESSION* s);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s certificate serial number. The serial
    number buffer (in) should be at least 32 bytes long and be provided
    as the *inOutSz argument as input. After calling the function *inOutSz
    will hold the actual length in bytes written to the in buffer.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if a bad function argument
    was encountered.

    \param in The serial number buffer and should be at least 32 bytes long
    \param inOutSz will hold the actual length in bytes written to the
    in buffer.

    _Example_
    \code
    none
    \endcode

    \sa SSL_get_peer_certificate
*/
int  wolfSSL_X509_get_serial_number(WOLFSSL_X509* x509, unsigned char* in,
                                    int* inOutSz);

/*!
    \ingroup CertsKeys

    \brief Returns the common name of the subject from the certificate.

    \return NULL returned if the x509 structure is null
    \return string a string representation of the subject's common
    name is returned upon success

    \param x509 a pointer to a WOLFSSL_X509 structure containing
    certificate information.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509Cn = wolfSSL_X509_get_subjectCN(x509);
    if(x509Cn == NULL){
	    // Deal with NULL case
    } else {
	    // x509Cn contains the common name
    }
    \endcode

    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name

*/
char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief This function gets the DER encoded certificate in the
    WOLFSSL_X509 struct.

    \return buffer This function returns the DerBuffer structure’s
    buffer member, which is of type byte.
    \return NULL returned if the x509 or outSz parameter is NULL.

    \param x509 a pointer to a WOLFSSL_X509 structure containing
    certificate information.
    \param outSz length of the derBuffer member of the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    int* outSz; // initialize
    ...
    byte* x509Der = wolfSSL_X509_get_der(x509, outSz);
    if(x509Der == NULL){
	    // Failure case one of the parameters was NULL
    }
    \endcode

    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz);

/*!
    \ingroup CertsKeys

    \brief This function checks to see if x509 is NULL and if it’s not,
    it returns the notAfter member of the x509 struct.

    \return pointer to struct with ASN1_TIME to the notAfter
    member of the x509 struct.
    \return NULL returned if the x509 object is NULL.

    \param x509 a pointer to the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    ...
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notAfter(x509);
    if(notAfter == NULL){
        // Failure case, the x509 object is null.
    }
    \endcode

    \sa wolfSSL_X509_get_notBefore
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief This function retrieves the version of the X509 certificate.

    \return 0 returned if the x509 structure is NULL.
    \return version the version stored in the x509 structure will be returned.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_X509* x509;
    int version;
    ...
    version = wolfSSL_X509_version(x509);
    if(!version){
	    // The function returned 0, failure case.
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
int wolfSSL_X509_version(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief If NO_STDIO_FILESYSTEM is defined this function will allocate
    heap memory, initialize a WOLFSSL_X509 structure and return a pointer to it.

    \return *WOLFSSL_X509 WOLFSSL_X509 structure pointer is returned if
    the function executes successfully.
    \return NULL if the call to XFTELL macro returns a negative value.

    \param x509 a pointer to a WOLFSSL_X509 pointer.
    \param file a defined type that is a pointer to a FILE.

    _Example_
    \code
    WOLFSSL_X509* x509a = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    WOLFSSL_X509** x509 = x509a;
    XFILE file;  (mapped to struct fs_file*)
    ...
    WOLFSSL_X509* newX509 = wolfSSL_X509_d2i_fp(x509, file);
    if(newX509 == NULL){
	    // The function returned NULL
    }
    \endcode

    \sa wolfSSL_X509_d2i
    \sa XFTELL
    \sa XREWIND
    \sa XFSEEK
*/
WOLFSSL_X509*
        wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, FILE* file);

/*!
    \ingroup CertsKeys

    \brief The function loads the x509 certificate into memory.

    \return pointer a successful execution returns pointer to a
    WOLFSSL_X509 structure.
    \return NULL returned if the certificate was not able to be written.

    \param fname the certificate file to be loaded.
    \param format the format of the certificate.

    _Example_
    \code
    #define cliCert    “certs/client-cert.pem”
    …
    X509* x509;
    …
    x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM);
    AssertNotNull(x509);
    \endcode

    \sa InitDecodedCert
    \sa PemToDer
    \sa wolfSSL_get_certificate
    \sa AssertNotNull
*/
WOLFSSL_X509*
    wolfSSL_X509_load_certificate_file(const char* fname, int format);

/*!
    \ingroup CertsKeys

    \brief This function copies the device type from the x509 structure
    to the buffer.

    \return pointer returns a byte pointer holding the device type from
    the x509 structure.
    \return NULL returned if the buffer size is NULL.

    \param x509 pointer to a WOLFSSL_X509 structure, created with
    WOLFSSL_X509_new().
    \param in a pointer to a byte type that will hold the device type
    (the buffer).
    \param inOutSz the minimum of either the parameter inOutSz or the
    deviceTypeSz member of the x509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    byte* in;
    int* inOutSz;
    ...
    byte* deviceType = wolfSSL_X509_get_device_type(x509, in, inOutSz);

    if(!deviceType){
	    // Failure case, NULL was returned.
    }
    \endcode

    \sa wolfSSL_X509_get_hw_type
    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_d2i
*/
unsigned char*
           wolfSSL_X509_get_device_type(WOLFSSL_X509* x509, unsigned char* in,
                                        int* inOutSz);

/*!
    \ingroup CertsKeys

    \brief The function copies the hwType member of the WOLFSSL_X509
    structure to the buffer.

    \return byte The function returns a byte type of the data previously held
    in the hwType member of the WOLFSSL_X509 structure.
    \return NULL returned if  inOutSz is NULL.

    \param x509 a pointer to a WOLFSSL_X509 structure containing certificate
    information.
    \param in pointer to type byte that represents the buffer.
    \param inOutSz pointer to type int that represents the size of the buffer.

    _Example_
    \code
    WOLFSSL_X509* x509;  // X509 certificate
    byte* in;  // initialize the buffer
    int* inOutSz;  // holds the size of the buffer
    ...
    byte* hwType = wolfSSL_X509_get_hw_type(x509, in, inOutSz);

    if(hwType == NULL){
	    // Failure case function returned NULL.
    }
    \endcode

    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_get_device_type
*/
unsigned char*
           wolfSSL_X509_get_hw_type(WOLFSSL_X509* x509, unsigned char* in,
                                    int* inOutSz);

/*!
    \ingroup CertsKeys

    \brief This function returns the hwSerialNum member of the x509 object.

    \return pointer the function returns a byte pointer to the in buffer that
    will contain the serial number loaded from the x509 object.

    \param x509 pointer to a WOLFSSL_X509 structure containing certificate
    information.
    \param in a pointer to the buffer that will be copied to.
    \param inOutSz a pointer to the size of the buffer.

    _Example_
    \code
    char* serial;
    byte* in;
    int* inOutSz;
    WOLFSSL_X509 x509;
    ...
    serial = wolfSSL_X509_get_hw_serial_number(x509, in, inOutSz);

    if(serial == NULL || serial <= 0){
    	// Failure case
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
unsigned char*
           wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509* x509,
                                             unsigned char* in, int* inOutSz);

/*!
    \ingroup IO

    \brief This function is called on the client side and initiates an
    SSL/TLS handshake with a server only long enough to get the peer’s
    certificate chain.  When this function is called, the underlying
    communication channel has already been set up. wolfSSL_connect_cert()
    works with both blocking and non-blocking I/O.  When the underlying I/O
    is non-blocking, wolfSSL_connect_cert() will return when the underlying
    I/O could not satisfy the needs of wolfSSL_connect_cert() to continue the
    handshake.  In this case, a call to wolfSSL_get_error() will yield either
    SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then
    repeat the call to wolfSSL_connect_cert() when the underlying I/O is ready
    and wolfSSL will pick up where it left off. When using a non-blocking
    socket, nothing needs to be done, but select() can be used to check for
    the required condition. If the underlying I/O is blocking,
    wolfSSL_connect_cert() will only return once the peer’s certificate chain
    has been received.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE will be returned if the SSL session parameter is NULL.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a more
    detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    ret = wolfSSL_connect_cert(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept
*/
int  wolfSSL_connect_cert(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief wolfSSL_d2i_PKCS12_bio (d2i_PKCS12_bio) copies in the PKCS12
    information from WOLFSSL_BIO to the structure WC_PKCS12. The information
    is divided up in the structure as a list of Content Infos along with a
    structure to hold optional MAC information. After the information has been
    divided into chunks (but not decrypted) in the structure WC_PKCS12, it can
    then be parsed and decrypted by calling.

    \return WC_PKCS12 pointer to a WC_PKCS12 structure.
    \return Failure If function failed it will return NULL.

    \param bio WOLFSSL_BIO structure to read PKCS12 buffer from.
    \param pkcs12 WC_PKCS12 structure pointer for new PKCS12 structure created.
    Can be NULL

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode

    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12** pkcs12);

/*!
    \ingroup openSSL

    \brief wolfSSL_i2d_PKCS12_bio (i2d_PKCS12_bio) copies in the cert
    information from the structure WC_PKCS12 to WOLFSSL_BIO.

    \return 1 for success.
    \return Failure 0.

    \param bio WOLFSSL_BIO structure to write PKCS12 buffer to.
    \param pkcs12 WC_PKCS12 structure for PKCS12 structure as input.

    _Example_
    \code
    WC_PKCS12 pkcs12;
    FILE *f;
    byte buffer[5300];
    char file[] = "./test.p12";
    int bytes;
    WOLFSSL_BIO* bio;
    pkcs12 = wc_PKCS12_new();
    f = fopen(file, "rb");
    bytes = (int)fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    //convert the DER file into an internal structure
    wc_d2i_PKCS12(buffer, bytes, pkcs12);
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    //convert PKCS12 structure into bio
    wolfSSL_i2d_PKCS12_bio(bio, pkcs12);
    wc_PKCS12_free(pkcs)
    //use bio
    \endcode

    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12* pkcs12);

/*!
    \ingroup openSSL

    \brief PKCS12 can be enabled with adding –enable-opensslextra to the
    configure command. It can use triple DES and RC4 for decryption so would
    recommend also enabling these features when enabling opensslextra
    (--enable-des3 –enable-arc4). wolfSSL does not currently support RC2 so
    decryption with RC2 is currently not available. This may be noticeable
    with default encryption schemes used by OpenSSL command line to create
    .p12 files. wolfSSL_PKCS12_parse (PKCS12_parse). The first thing this
    function does is check the MAC is correct if present. If the MAC fails
    then the function returns and does not try to decrypt any of the stored
    Content Infos. This function then parses through each Content Info
    looking for a bag type, if the bag type is known it is decrypted as
    needed and either stored in the list of certificates being built or as
    a key found. After parsing through all bags the key found is then
    compared with the certificate list until a matching pair is found.
    This matching pair is then returned as the key and certificate,
    optionally the certificate list found is returned as a STACK_OF
    certificates. At the moment a CRL, Secret or SafeContents bag will be
    skipped over and not parsed. It can be seen if these or other “Unknown”
    bags are skipped over by viewing the debug print out. Additional attributes
    such as friendly name are skipped over when parsing a PKCS12 file.

    \return SSL_SUCCESS On successfully parsing PKCS12.
    \return SSL_FAILURE If an error case was encountered.

    \param pkcs12 WC_PKCS12 structure to parse.
    \param paswd password for decrypting PKCS12.
    \param pkey structure to hold private key decoded from PKCS12.
    \param cert structure to hold certificate decoded from PKCS12.
    \param stack optional stack of extra certificates.

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode

    \sa wolfSSL_d2i_PKCS12_bio
    \sa wc_PKCS12_free
*/
int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
     WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert, WOLF_STACK_OF(WOLFSSL_X509)** ca);

/*!
    \ingroup CertsKeys

    \brief Server Diffie-Hellman Ephemeral parameters setting. This function
    sets up the group parameters to be used if the server negotiates a cipher
    suite that uses DHE.

    \return SSL_SUCCESS upon success.
    \return MEMORY_ERROR will be returned if a memory error was encountered.
    \return SIDE_ERROR will be returned if this function is called on an SSL
    client instead of an SSL server.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param p Diffie-Hellman prime number parameter.
    \param pSz size of p.
    \param g Diffie-Hellman “generator” parameter.
    \param gSz size of g.

    _Example_
    \code
    WOLFSSL* ssl;
    static unsigned char p[] = {...};
    static unsigned char g[] = {...};
    ...
    wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
    \endcode

    \sa SSL_accept
*/
int  wolfSSL_SetTmpDH(WOLFSSL* ssl, const unsigned char* p, int pSz,
                                const unsigned char* g, int gSz);

/*!
    \ingroup CertsKeys

    \brief The function calls the wolfSSL_SetTMpDH_buffer_wrapper,
    which is a wrapper for Diffie-Hellman parameters.

    \return SSL_SUCCESS on successful execution.
    \return SSL_BAD_FILETYPE if the file type is not PEM and is not
    ASN.1. It will also be returned if the wc_DhParamsLoad does not
    return normally.
    \return SSL_NO_PEM_HEADER returns from PemToDer if there is not
    a PEM header.
    \return SSL_BAD_FILE returned if there is a file error in PemToDer.
    \return SSL_FATAL_ERROR returned from PemToDer if there was a copy error.
    \return MEMORY_E - if there was a memory allocation error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if
    there was otherwise a NULL argument passed to a subroutine.
    \return DH_KEY_SIZE_E is returned if their is a key size error in
    wolfSSL_SetTmpDH() or in wolfSSL_CTX_SetTmpDH().
    \return SIDE_ERROR returned if it is not the server side
    in wolfSSL_SetTmpDH.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf allocated buffer passed in from wolfSSL_SetTMpDH_file_wrapper.
    \param sz a long int that holds the size of the file
    (fname within wolfSSL_SetTmpDH_file_wrapper).
    \param format an integer type passed through from
    wolfSSL_SetTmpDH_file_wrapper() that is a representation of the certificate
    format.

    _Example_
    \code
    Static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    long sz = 0;
    byte* myBuffer = staticBuffer[FILE_BUFFER_SIZE];
    …
    if(ssl)
    ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    \endcode

    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wc_DhParamsLoad
    \sa wolfSSL_SetTmpDH
    \sa PemToDer
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int  wolfSSL_SetTmpDH_buffer(WOLFSSL* ssl, const unsigned char* b, long sz,
                                       int format);

/*!
    \ingroup CertsKeys

    \brief This function calls wolfSSL_SetTmpDH_file_wrapper to set server
    Diffie-Hellman parameters.

    \return SSL_SUCCESS returned on successful completion of this function
    and its subroutines.
    \return MEMORY_E returned if a memory allocation failed in this function
    or a subroutine.
    \return SIDE_ERROR if the side member of the Options structure found
    in the WOLFSSL struct is not the server side.
    \return SSL_BAD_FILETYPE returns if the certificate fails a set of checks.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is less than
    the value of the minDhKeySz member in the WOLFSSL struct.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is greater
    than the value of the maxDhKeySz member in the WOLFSSL struct.
    \return BAD_FUNC_ARG returns if an argument value is NULL that is not
    permitted such as, the WOLFSSL structure.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param fname a constant char pointer holding the certificate.
    \param format an integer type that holds the format of the certification.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* dhParam;
    …
    AssertIntNE(SSL_SUCCESS,
    wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM));
    \endcode

    \sa wolfSSL_CTX_SetTmpDH_file
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
*/
int  wolfSSL_SetTmpDH_file(WOLFSSL* ssl, const char* f, int format);

/*!
    \ingroup CertsKeys

    \brief Sets the parameters for the server CTX Diffie-Hellman.

    \return SSL_SUCCESS returned if the function and all subroutines
    return without error.
    \return BAD_FUNC_ARG returned if the CTX, p or g parameters are NULL.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is less than
    the value of the minDhKeySz member of the WOLFSSL_CTX struct.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is greater
    than the value of the maxDhKeySz member of the WOLFSSL_CTX struct.
    \return MEMORY_E returned if the allocation of memory failed in this
    function or a subroutine.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param p a constant unsigned char pointer loaded into the buffer
    member of the serverDH_P struct.
    \param pSz an int type representing the size of p, initialized
    to MAX_DH_SIZE.
    \param g a constant unsigned char pointer loaded into the buffer
    member of the serverDH_G struct.
    \param gSz an int type representing the size of g, initialized to
    MAX_DH_SIZE.

    _Exmaple_
    \code
    WOLFSSL_CTX* ctx =  WOLFSSL_CTX_new( protocol );
    byte* p;
    byte* g;
    word32 pSz = (word32)sizeof(p)/sizeof(byte);
    word32 gSz = (word32)sizeof(g)/sizeof(byte);
    …
    int ret =  wolfSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);

    if(ret != SSL_SUCCESS){
    	// Failure case
    }
    \endcode

    \sa wolfSSL_SetTmpDH
    \sa wc_DhParamsLoad
*/
int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);

/*!
    \ingroup CertsKeys

    \brief A wrapper function that calls wolfSSL_SetTmpDH_buffer_wrapper

    \return 0 returned for a successful execution.
    \return BAD_FUNC_ARG returned if the ctx or buf parameters are NULL.
    \return MEMORY_E if there is a memory allocation error.
    \return SSL_BAD_FILETYPE returned if format is not correct.

    \param ctx a pointer to a WOLFSSL structure, created using
    wolfSSL_CTX_new().
    \param buf a pointer to a constant unsigned char type that is
    allocated as the buffer and passed through to
    wolfSSL_SetTmpDH_buffer_wrapper.
    \param sz a long integer type that is derived from the fname parameter
    in wolfSSL_SetTmpDH_file_wrapper().
    \param format an integer type passed through from
    wolfSSL_SetTmpDH_file_wrapper().

    _Example_
    \code
    static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    #ifdef WOLFSSL_SMALL_STACK
    byte staticBuffer[1]; // force heap usage
    #else
    byte* staticBuffer;
    long sz = 0;
    …
    if(ssl){
    	ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    } else {
    ret = wolfSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }
    \endcode

    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTMpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int  wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX* ctx, const unsigned char* b,
                                           long sz, int format);

/*!
    \ingroup CertsKeys

    \brief The function calls wolfSSL_SetTmpDH_file_wrapper to set the server
    Diffie-Hellman parameters.

    \return SSL_SUCCESS returned if the wolfSSL_SetTmpDH_file_wrapper or any
    of its subroutines return successfully.
    \return MEMORY_E returned if an allocation of dynamic memory fails in a
    subroutine.
    \return BAD_FUNC_ARG returned if the ctx or fname parameters are NULL or
    if
    a subroutine is passed a NULL argument.
    \return SSL_BAD_FILE returned if the certificate file is unable to open or
    if the a set of checks on the file fail from wolfSSL_SetTmpDH_file_wrapper.
    \return SSL_BAD_FILETYPE returned if the format is not PEM or ASN.1 from
    wolfSSL_SetTmpDH_buffer_wrapper().
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is less than
    the value of the minDhKeySz member of the WOLFSSL_CTX struct.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is greater
    than the value of the maxDhKeySz member of the WOLFSSL_CTX struct.
    \return SIDE_ERROR returned in wolfSSL_SetTmpDH() if the side is not the
    server end.
    \return SSL_NO_PEM_HEADER returned from PemToDer if there is no PEM header.
    \return SSL_FATAL_ERROR returned from PemToDer if there is a memory copy
    failure.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param fname a constant character pointer to a certificate file.
    \param format an integer type passed through from
    wolfSSL_SetTmpDH_file_wrapper() that is a representation of
    the certificate format.

    _Example_
    \code
    #define dhParam     “certs/dh2048.pem”
    #DEFINE aSSERTiNTne(x, y)     AssertInt(x, y, !=, ==)
    WOLFSSL_CTX* ctx;
    …
    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()))
    …
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(NULL, dhParam,
    SSL_FILETYPE_PEM));
    \endcode

    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa AllocDer
    \sa PemToDer
*/
int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* f,
                                             int format);

/*!
    \ingroup CertsKeys

    \brief This function sets the minimum size (in bits) of the Diffie Hellman
    key size by accessing the minDhKeySz member in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned if the function completes successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if
    the keySz_bits is greater than 16,000 or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz_bits a word16 type used to set the minimum DH key size in bits.
    The WOLFSSL_CTX struct holds this information in the minDhKeySz member.

    _Example_
    \code
    public static int CTX_SetMinDhKey_Sz(IntPtr ctx, short minDhKey){
    …
    return wolfSSL_CTX_SetMinDhKey_Sz(local_ctx, minDhKeyBits);
    \endcode

    \sa wolfSSL_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetMaxDhKey_Sz
    \sa wolfSSL_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
    \sa wolfSSL_CTX_SetTMpDH_file
*/
int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX* ctx, word16);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum size (in bits) for a Diffie-Hellman key in the
    WOLFSSL structure.

    \return SSL_SUCCESS the minimum size was successfully set.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL or if the keySz_bits is
    greater than 16,000 or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz_bits a word16 type used to set the minimum DH key size in bits.
    The WOLFSSL_CTX struct holds this information in the minDhKeySz member.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz_bits;
    ...
    if(wolfSSL_SetMinDhKey_Sz(ssl, keySz_bits) != SSL_SUCCESS){
	    // Failed to set.
    }
    \endcode

    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief This function sets the maximum size (in bits) of the Diffie Hellman
    key size by accessing the maxDhKeySz member in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned if the function completes successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if
    the keySz_bits is greater than 16,000 or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz_bits a word16 type used to set the maximum DH key size in bits.
    The WOLFSSL_CTX struct holds this information in the maxDhKeySz member.

    _Example_
    \code
    public static int CTX_SetMaxDhKey_Sz(IntPtr ctx, short maxDhKey){
    …
    return wolfSSL_CTX_SetMaxDhKey_Sz(local_ctx, keySz_bits);
    \endcode

    \sa wolfSSL_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
    \sa wolfSSL_CTX_SetTMpDH_file
*/
int wolfSSL_CTX_SetMaxDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief Sets the maximum size (in bits) for a Diffie-Hellman key in the
    WOLFSSL structure.

    \return SSL_SUCCESS the maximum size was successfully set.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL or the keySz parameter
    was greater than the allowable size or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz a word16 type representing the bit size of the maximum DH key.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz;
    ...
    if(wolfSSL_SetMaxDhKey(ssl, keySz) != SSL_SUCCESS){
	    // Failed to set.
    }
    \endcode

    \sa wolfSSL_CTX_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMaxDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief Returns the value of dhKeySz (in bits) that is a member of the
    options structure. This value represents the Diffie-Hellman key size in
    bytes.

    \return dhKeySz returns the value held in ssl->options.dhKeySz which is an
    integer value representing a size in bits.
    \return BAD_FUNC_ARG returns if the WOLFSSL struct is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int dhKeySz;
    ...
    dhKeySz = wolfSSL_GetDhKey_Sz(ssl);

    if(dhKeySz == BAD_FUNC_ARG || dhKeySz <= 0){
    	// Failure case
    } else {
    	// dhKeySz holds the size of the key.
    }
    \endcode

    \sa wolfSSL_SetMinDhKey_sz
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int wolfSSL_GetDhKey_Sz(WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum RSA key size in both the WOLFSSL_CTX structure
    and the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the ctx structure is NULL or the keySz
    is less than zero or not divisible by 8.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param keySz a short integer type stored in minRsaKeySz in the ctx
    structure and the cm structure converted to bytes.

    _Example_
    \code
    WOLFSSL_CTX* ctx = SSL_CTX_new(method);
    (void)minDhKeyBits;
    ourCert = myoptarg;
    …
    minDhKeyBits = atoi(myoptarg);
    …
    if(wolfSSL_CTX_SetMinRsaKey_Sz(ctx, minRsaKeyBits) != SSL_SUCCESS){
    …
    \endcode

    \sa wolfSSL_SetMinRsaKey_Sz
*/
int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX* ctx, short keySz);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum allowable key size in bits for RSA located in the
    WOLFSSL structure.

    \return SSL_SUCCESS the minimum was set successfully.
    \return BAD_FUNC_ARG returned if the ssl structure is NULL or if the ksySz
    is less than zero or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz a short integer value representing the the minimum key in bits.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    short keySz;
    …

    int isSet =  wolfSSL_SetMinRsaKey_Sz(ssl, keySz);
    if(isSet != SSL_SUCCESS){
	    Failed to set.
    }
    \endcode

    \sa wolfSSL_CTX_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinRsaKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum size in bits for the ECC key in the WOLF_CTX
    structure and the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned for a successful execution and the minEccKeySz
    member is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if
    the keySz is negative or not divisible by 8.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param keySz a short integer type that represents the minimum ECC key
    size in bits.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    short keySz; // minimum key size
    …
    if(wolfSSL_CTX_SetMinEccKey(ctx, keySz) != SSL_SUCCESS){
	    // Failed to set min key size
    }
    \endcode

    \sa wolfSSL_SetMinEccKey_Sz
*/
int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief Sets the value of the minEccKeySz member of the options structure.
    The options struct is a member of the WOLFSSL structure and is
    accessed through the ssl parameter.

    \return SSL_SUCCESS if the function successfully set the minEccKeySz
    member of the options structure.
    \return BAD_FUNC_ARG if the WOLFSSL_CTX structure is NULL or if the
    key size (keySz) is less than 0 (zero) or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz value used to set the minimum ECC key size. Sets
    value in the options structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx); // New session
    short keySz = 999; // should be set to min key size allowable
    ...
    if(wolfSSL_SetMinEccKey_Sz(ssl, keySz) != SSL_SUCCESS){
	    // Failure case.
    }
    \endcode

    \sa wolfSSL_CTX_SetMinEccKey_Sz
    \sa wolfSSL_CTX_SetMinRsaKey_Sz
    \sa wolfSSL_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinEccKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief This function is used by EAP_TLS and EAP-TTLS to derive
    keying material from the master secret.

    \return BUFFER_E returned if the actual size of the buffer exceeds
    the maximum size allowable.
    \return MEMORY_E returned if there is an error with memory allocation.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param key a void pointer variable that will hold the result
    of the p_hash function.
    \param len an unsigned integer that represents the length of
    the key variable.
    \param label a constant char pointer that is copied from in wc_PRF().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);;
    void* key;
    unsigned int len;
    const char* label;
    …
    return wolfSSL_make_eap_keys(ssl, key, len, label);
    \endcode

    \sa wc_PRF
    \sa wc_HmacFinal
    \sa wc_HmacUpdate
*/
int wolfSSL_make_eap_keys(WOLFSSL* ssl, void* key, unsigned int len,
                                                             const char* label);

/*!
    \ingroup IO

    \brief Simulates writev semantics but doesn’t actually do block at a time
    because of SSL_write() behavior and because front adds may be small.
    Makes porting into software that uses writev easier.

    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for
    the specific error code.
    \return MEMORY_ERROR will be returned if a memory error was encountered.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_write() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param iov array of I/O vectors to write
    \param iovcnt number of vectors in iov array.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char *bufA = “hello\n”;
    char *bufB = “hello world\n”;
    int iovcnt;
    struct iovec iov[2];

    iov[0].iov_base = buffA;
    iov[0].iov_len = strlen(buffA);
    iov[1].iov_base = buffB;
    iov[1].iov_len = strlen(buffB);
    iovcnt = 2;
    ...
    ret = wolfSSL_writev(ssl, iov, iovcnt);
    // wrote “ret” bytes, or error if <= 0.
    \endcode

    \sa wolfSSL_write
*/
int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);

/*!
    \ingroup Setup

    \brief This function unloads the CA signer list and frees
    the whole signer table.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or there
    are otherwise unpermitted argument values passed in a subroutine.
    \return BAD_MUTEX_E returned if there was a mutex error. The LockMutex()
    did not return 0.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    if(wolfSSL_CTX_UnloadCAs(ctx) != SSL_SUCCESS){
    	// The function did not unload CAs
    }
    \endcode

    \sa wolfSSL_CertManagerUnloadCAs
    \sa LockMutex
    \sa UnlockMutex
*/
int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX*);


/*!
    \ingroup Setup

    \brief This function unloads intermediate certificates added to the CA
    signer list and frees them.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or there
    are otherwise unpermitted argument values passed in a subroutine.
    \return BAD_STATE_E returned if the WOLFSSL_CTX has a reference count > 1.
    \return BAD_MUTEX_E returned if there was a mutex error. The LockMutex()
    did not return 0.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    if(wolfSSL_CTX_UnloadIntermediateCerts(ctx) != NULL){
        // The function did not unload CAs
    }
    \endcode

    \sa wolfSSL_CTX_UnloadCAs
    \sa wolfSSL_CertManagerUnloadIntermediateCerts
*/
int wolfSSL_CTX_UnloadIntermediateCerts(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is used to unload all previously loaded trusted peer
    certificates. Feature is enabled by defining the macro
    WOLFSSL_TRUST_PEER_CERT.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if ctx is NULL.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_Unload_trust_peers(ctx);
    if (ret != SSL_SUCCESS) {
        // error unloading trusted peer certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_trust_peer_cert
*/
int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief This function loads a certificate to use for verifying a peer
    when performing a TLS/SSL handshake. The peer certificate sent during
    the handshake is compared by using the SKID when available and the
    signature. If these two things do not match then any loaded CAs are used.
    Is the same functionality as wolfSSL_CTX_trust_peer_cert except is from
    a buffer instead of a file. Feature is enabled by defining the macro
    WOLFSSL_TRUST_PEER_CERT Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    type are invalid.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param buffer pointer to the buffer containing certificates.
    \param sz length of the buffer input.
    \param type type of certificate being loaded i.e. SSL_FILETYPE_ASN1 or
    SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...

    ret = wolfSSL_CTX_trust_peer_buffer(ctx, bufferPtr, bufferSz,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    // error loading trusted peer cert
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_cert
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                  long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a CA certificate buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz. format specifies
    the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    More than one CA certificate may be loaded per buffer as long as the
    format is in PEM.  Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in pointer to the CA certificate buffer.
    \param sz size of the input CA certificate buffer, in.
    \param format format of the buffer certificate, either SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    ret = wolfSSL_CTX_load_verify_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                   long sz, int format);


/*!
    \ingroup CertsKeys

    \brief This function loads a CA certificate buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz. format specifies
    the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    More than one CA certificate may be loaded per buffer as long as the
    format is in PEM.  The _ex version was added in PR 2413 and supports
    additional arguments for userChain and flags.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in pointer to the CA certificate buffer.
    \param sz size of the input CA certificate buffer, in.
    \param format format of the buffer certificate, either SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.
    \param userChain If using format WOLFSSL_FILETYPE_ASN1 this set to non-zero
    indicates a chain of DER's is being presented.
    \param flags: See ssl.h around WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    // Example for force loading an expired certificate
    ret = wolfSSL_CTX_load_verify_buffer_ex(ctx, certBuff, sz, SSL_FILETYPE_PEM,
        0, (WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY));
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX* ctx,
                                      const unsigned char* in, long sz,
                                      int format, int userChain, word32 flags);

/*!
    \ingroup CertsKeys

    \brief This function loads a CA certificate chain buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz. format specifies
    the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    More than one CA certificate may be loaded per buffer as long as the
    format is in PEM.  Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in pointer to the CA certificate buffer.
    \param sz size of the input CA certificate buffer, in.
    \param format format of the buffer certificate, either SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    ret = wolfSSL_CTX_load_verify_chain_buffer_format(ctx,
                         certBuff, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        // error loading CA certs from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_chain_buffer_format(WOLFSSL_CTX* ctx,
                                               const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate buffer into the WOLFSSL Context.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file.  The buffer is
    provided by the in argument of size sz.  format specifies the format
    type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please
    see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the certificate to be loaded.
    \param sz the size of the input buffer.
    \param format the format of the certificate located in the input
    buffer (in).  Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading certificate from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
                                       const unsigned char* in, long sz,
                                       int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a private key buffer into the SSL Context.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file.  The buffer is
    provided by the in argument of size sz.  format specifies the format type
    of the buffer; SSL_FILETYPE_ASN1or SSL_FILETYPE_PEM.  Please see the
    examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return NO_PASSWORD will be returned if the key file is encrypted but no
    password is provided.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the private key to be loaded.
    \param sz the size of the input buffer.
    \param format the format of the private key located in the input
    buffer (in).  Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte keyBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, keyBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading private key from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx,
                                      const unsigned char* in, long sz,
                                      int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate chain buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz.  The buffer must
    be in PEM format and start with the subject’s certificate, ending with
    the root certificate. Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the PEM-formatted certificate
    chain to be loaded.
    \param sz the size of the input buffer.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certChainBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx, certChainBuff, sz);
    if (ret != SSL_SUCCESS) {
    	// error loading certificate chain from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX* ctx,
                                             const unsigned char* in, long sz);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate buffer into the WOLFSSL object.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file. The buffer
    is provided by the in argument of size sz.  format specifies the format
    type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    Please see the examples for proper usage.

    \return SSL_SUCCESS upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t
    be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing certificate to load.
    \param sz size of the certificate located in buffer.
    \param format format of the certificate to be loaded.
    Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret;
    byte certBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...

    ret = wolfSSL_use_certificate_buffer(ssl, certBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate from buffer
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_certificate_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a private key buffer into the WOLFSSL object.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file.  The buffer is
    provided by the in argument of size sz. format specifies the format
    type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please
    see the examples for proper usage.

    \return SSL_SUCCESS upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return NO_PASSWORD will be returned if the key file is encrypted but no
    password is provided.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing private key to load.
    \param sz size of the private key located in buffer.
    \param format format of the private key to be loaded.  Possible values are
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret;
    byte keyBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...
    ret = wolfSSL_use_PrivateKey_buffer(ssl, keyBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load private key from buffer
    }
    \endcode

    \sa wolfSSL_use_PrivateKey
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate chain buffer into the WOLFSSL
    object.  It behaves like the non-buffered version, only differing in its
    ability to be called with a buffer as input instead of a file. The buffer
    is provided by the in argument of size sz.  The buffer must be in PEM format
    and start with the subject’s certificate, ending with the root certificate.
    Please see the examples for proper usage.

    \return SSL_SUCCES upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing certificate to load.
    \param sz size of the certificate located in buffer.

    _Example_
    \code
    int ret;
    byte certChainBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...
    ret = wolfSSL_use_certificate_chain_buffer(ssl, certChainBuff, buffSz);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate chain from buffer
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
*/
int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl,
                                         const unsigned char* in, long sz);

/*!
    \ingroup CertsKeys

    \brief This function unloads any certificates or keys that SSL owns.

    \return SSL_SUCCESS - returned if the function executed successfully.
    \return BAD_FUNC_ARG - returned if the WOLFSSL object is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    int unloadKeys = wolfSSL_UnloadCertsKeys(ssl);
    if(unloadKeys != SSL_SUCCESS){
	    // Failure case.
    }
    \endcode

    \sa wolfSSL_CTX_UnloadCAs
*/
int wolfSSL_UnloadCertsKeys(WOLFSSL*);

/*!
    \ingroup Setup

    \brief This function turns on grouping of handshake messages where possible.

    \return SSL_SUCCESS will be returned upon success.
    \return BAD_FUNC_ARG will be returned if the input context is null.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_group_messages(ctx);
    if (ret != SSL_SUCCESS) {
	    // failed to set handshake message grouping
    }
    \endcode

    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_new
*/
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief This function turns on grouping of handshake messages where possible.

    \return SSL_SUCCESS will be returned upon success.
    \return BAD_FUNC_ARG will be returned if the input context is null.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_group_messages(ssl);
    if (ret != SSL_SUCCESS) {
	// failed to set handshake message grouping
    }
    \endcode

    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_new
*/
int wolfSSL_set_group_messages(WOLFSSL*);

/*!
    \brief This function sets the fuzzer callback.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cbf a CallbackFuzzer type that is a function pointer of the form:
    int (*CallbackFuzzer)(WOLFSSL* ssl, const unsigned char* buf, int sz, int
    type, void* fuzzCtx);
    \param fCtx a void pointer type that will be set to the fuzzerCtx member of
    the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* fCtx;

    int callbackFuzzerCB(WOLFSSL* ssl, const unsigned char* buf, int sz,
				int type, void* fuzzCtx){
    // function definition
    }
    …
    wolfSSL_SetFuzzerCb(ssl, callbackFuzzerCB, fCtx);
    \endcode

    \sa CallbackFuzzer
*/
void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx);

/*!
    \brief This function sets a new dtls cookie secret.

    \return 0 returned if the function executed without an error.
    \return BAD_FUNC_ARG returned if there was an argument passed
    to the function with an unacceptable value.
    \return COOKIE_SECRET_SZ returned if the secret size is 0.
    \return MEMORY_ERROR returned if there was a problem allocating
    memory for a new cookie secret.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param secret a constant byte pointer representing the secret buffer.
    \param secretSz the size of the buffer.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const* byte secret;
    word32 secretSz; // size of secret
    …
    if(!wolfSSL_DTLS_SetCookieSecret(ssl, secret, secretSz)){
    	// Code block for failure to set DTLS cookie secret
    } else {
    	// Success! Cookie secret is set.
    }
    \endcode

    \sa ForceZero
    \sa wc_RNG_GenerateBlock
*/
int   wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl,
                                               const unsigned char* secret,
                                               unsigned int secretSz);

/*!
    \brief This function retrieves the random number.

    \return rng upon success.
    \return NULL if ssl is NULL.

    \param ssl pointer to a SSL object, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;

    wolfSSL_GetRNG(ssl);

    \endcode

    \sa  wolfSSL_CTX_new_rng

*/
WC_RNG* wolfSSL_GetRNG(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the minimum downgrade version allowed.
    Applicable only when the connection allows downgrade using
    (wolfSSLv23_client_method or wolfSSLv23_server_method).

    \return SSL_SUCCESS returned if the function returned without
    error and the minimum version is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure was
    NULL or if the minimum version is not supported.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param version an integer representation of the version to be set as the
    minimum: WOLFSSL_SSLV3 = 0, WOLFSSL_TLSV1 = 1, WOLFSSL_TLSV1_1 = 2 or
    WOLFSSL_TLSV1_2 = 3.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version; // macrop representation
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
    	// Failed to set min version
    }
    \endcode

    \sa SetMinVersionHelper
*/
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup TLS

    \brief This function sets the minimum downgrade version allowed.
    Applicable only when the connection allows downgrade using
    (wolfSSLv23_client_method or wolfSSLv23_server_method).

    \return SSL_SUCCESS returned if this function and its subroutine executes
    without error.
    \return BAD_FUNC_ARG returned if the SSL object is NULL.  In
    the subroutine this error is thrown if there is not a good version match.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param version an integer representation of the version to be set as the
    minimum: WOLFSSL_SSLV3 = 0, WOLFSSL_TLSV1 = 1, WOLFSSL_TLSV1_1 = 2 or
    WOLFSSL_TLSV1_2 = 3.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol method);
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version;  macro representation
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
	    Failed to set min version
    }
    \endcode

    \sa SetMinVersionHelper
*/
int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version);

/*!
    \brief This function returns the size of the WOLFSSL object and will be
    dependent on build options and settings.  If SHOW_SIZES has been defined
    when building wolfSSL, this function will also print the sizes of individual
    objects within the WOLFSSL object (Suites, Ciphers, etc.) to stdout.

    \return size This function returns the size of the WOLFSSL object.

    \param none No parameters.

    _Example_
    \code
    int size = 0;
    size = wolfSSL_GetObjectSize();
    printf(“sizeof(WOLFSSL) = %d\n”, size);
    \endcode

    \sa wolfSSL_new
*/
int wolfSSL_GetObjectSize(void);  /* object size based on build */
/*!
    \brief Returns the record layer size of the plaintext input. This is helpful
    when an application wants to know how many bytes will be sent across the
    Transport layer, given a specified plaintext input size. This function
    must be called after the SSL/TLS handshake has been completed.

    \return size Upon success, the requested size will be returned
    \return INPUT_SIZE_E will be returned if the input size is greater than the
    maximum TLS fragment size (see wolfSSL_GetMaxOutputSize())
    \return BAD_FUNC_ARG will be returned upon invalid function argument, or if
    the SSL/TLS handshake has not been completed yet

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param inSz size of plaintext data.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetMaxOutputSize
*/
int wolfSSL_GetOutputSize(WOLFSSL* ssl, int inSz);

/*!
    \brief Returns the maximum record layer size for plaintext data.  This
    will correspond to either the maximum SSL/TLS record size as specified
    by the protocol standard, the maximum TLS fragment size as set by the
    TLS Max Fragment Length extension. This function is helpful when the
    application has called wolfSSL_GetOutputSize() and received a INPUT_SIZE_E
    error. This function must be called after the SSL/TLS handshake has been
    completed.

    \return size Upon success, the maximum output size will be returned
    \return BAD_FUNC_ARG will be returned upon invalid function argument,
    or if the SSL/TLS handshake has not been completed yet.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetOutputSize
*/
int wolfSSL_GetMaxOutputSize(WOLFSSL*);

/*!
    \ingroup Setup

    \brief This function sets the SSL/TLS protocol version for the specified
    SSL session (WOLFSSL object) using the version as specified by version.
    This will override the protocol setting for the SSL session (ssl) -
    originally defined and set by the SSL context (wolfSSL_CTX_new())
    method type.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if the input SSL object is
    NULL or an incorrect protocol version is given for version.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param version SSL/TLS protocol version.  Possible values include
    WOLFSSL_SSLV3, WOLFSSL_TLSV1, WOLFSSL_TLSV1_1, WOLFSSL_TLSV1_2.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_SetVersion(ssl, WOLFSSL_TLSV1);
    if (ret != SSL_SUCCESS) {
        // failed to set SSL session protocol version
    }
    \endcode

    \sa wolfSSL_CTX_new
*/
int wolfSSL_SetVersion(WOLFSSL* ssl, int version);

/*!
    \brief Allows caller to set the Atomic User Record Processing
    Mac/Encrypt Callback.  The callback should return 0 for success
    or < 0 for an error.  The ssl and ctx pointers are available
    for the user’s convenience.  macOut is the output buffer where
    the result of the mac should be stored.  macIn is the mac input
    buffer and macInSz notes the size of the buffer.  macContent
    and macVerify are needed for wolfSSL_SetTlsHmacInner() and be
    passed along as is.  encOut is the output buffer where the result
    on the encryption should be stored.  encIn is the input buffer to
    encrypt while encSz is the size of the input.  An example callback
    can be found wolfssl/test.h myMacEncryptCb().

    \return none No return.

    \param No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX* ctx, CallbackMacEncrypti cb);

/*!
    \brief Allows caller to set the Atomic User Record Processing Mac/Encrypt
    Callback Context to ctx.

    \return none No return.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Atomic User Record Processing
    Mac/Encrypt Callback Context previously stored with
    wolfSSL_SetMacEncryptCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_SetMacEncryptCtx
*/
void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Atomic User Record Processing
    Decrypt/Verify Callback.  The callback should return 0 for success
    or < 0 for an error.  The ssl and ctx pointers are available for
    the user’s convenience.  decOut is the output buffer where the result
    of the decryption should be stored.  decIn is the encrypted input
    buffer and decInSz notes the size of the buffer.  content and verify
    are needed for wolfSSL_SetTlsHmacInner() and be passed along as is.
    padSz is an output variable that should be set with the total value
    of the padding.  That is, the mac size plus any padding and pad bytes.
    An example callback can be found wolfssl/test.h myDecryptVerifyCb().

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX* ctx,
                                               CallbackDecryptVerify cb);

/*!
    \brief Allows caller to set the Atomic User Record Processing
    Decrypt/Verify Callback Context to ctx.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_GetDecryptVerifyCtx
*/
void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Atomic User Record Processing
    Decrypt/Verify Callback Context previously stored with
    wolfSSL_SetDecryptVerifyCtx().

    \return pointer If successful the call will return a valid pointer to the
    context.
    \return NULL will be returned for a blank context.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_SetDecryptVerifyCtx
*/
void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

/*!
    \brief Allows retrieval of the Hmac/Mac secret from the handshake process.
    The verify parameter specifies whether this is for verification of a
    peer message.

    \return pointer If successful the call will return a valid pointer to the
    secret.  The size of the secret can be obtained from wolfSSL_GetHmacSize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param verify specifies whether this is for verification of a peer message.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetHmacSize
*/
const unsigned char* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify);

/*!
    \brief Allows retrieval of the client write key from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    key. The size of the key can be obtained from wolfSSL_GetKeySize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
*/
const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL*);

/*!
    \brief Allows retrieval of the client write IV (initialization vector)
    from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    IV.  The size of the IV can be obtained from wolfSSL_GetCipherBlockSize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetCipherBlockSize()
    \sa wolfSSL_GetClientWriteKey()
*/
const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL*);

/*!
    \brief Allows retrieval of the server write key from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    key.  The size of the key can be obtained from wolfSSL_GetKeySize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetServerWriteIV
*/
const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL*);

/*!
    \brief Allows retrieval of the server write IV (initialization vector)
    from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    IV.  The size of the IV can be obtained from wolfSSL_GetCipherBlockSize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetClientWriteKey
*/
const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL*);

/*!
    \brief Allows retrieval of the key size from the handshake process.

    \return size If successful the call will return the key size in bytes.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
int                  wolfSSL_GetKeySize(WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief Returns the iv_size member of the specs structure
    held in the WOLFSSL struct.

    \return iv_size returns the value held in ssl->specs.iv_size.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ivSize;
    ...
    ivSize = wolfSSL_GetIVSize(ssl);

    if(ivSize > 0){
    	// ivSize holds the specs.iv_size value.
    }
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
    \sa wolfSSL_GetServerWriteIV
*/
int                  wolfSSL_GetIVSize(WOLFSSL*);

/*!
    \brief Allows retrieval of the side of this WOLFSSL connection.

    \return success If successful the call will return either
    WOLFSSL_SERVER_END or WOLFSSL_CLIENT_END depending on the
    side of WOLFSSL object.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
int                  wolfSSL_GetSide(WOLFSSL*);

/*!
    \brief Allows caller to determine if the negotiated protocol version
    is at least TLS version 1.1 or greater.

    \return true/false If successful the call will return 1 for true or
    0 for false.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetSide
*/
int                  wolfSSL_IsTLSv1_1(WOLFSSL*);

/*!
    \brief Allows caller to determine the negotiated bulk cipher algorithm
    from the handshake.

    \return If successful the call will return one of the following:
    wolfssl_cipher_null, wolfssl_des, wolfssl_triple_des, wolfssl_aes,
    wolfssl_aes_gcm, wolfssl_aes_ccm, wolfssl_camellia.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetBulkCipher(WOLFSSL*);

/*!
    \brief Allows caller to determine the negotiated cipher block size from
    the handshake.

    \return size If successful the call will return the size in bytes of the
    cipher block size.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetCipherBlockSize(WOLFSSL*);

/*!
    \brief Allows caller to determine the negotiated aead mac size from the
    handshake.  For cipher type WOLFSSL_AEAD_TYPE.

    \return size If successful the call will return the size in bytes of the
    aead mac size.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetAeadMacSize(WOLFSSL*);

/*!
    \brief Allows caller to determine the negotiated (h)mac size from the
    handshake. For cipher types except WOLFSSL_AEAD_TYPE.

    \return size If successful the call will return the size in bytes of
    the (h)mac size.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetHmacSize(WOLFSSL*);

/*!
    \brief Allows caller to determine the negotiated (h)mac type from the
    handshake.  For cipher types except WOLFSSL_AEAD_TYPE.

    \return If successful the call will return one of the following:
    MD5, SHA, SHA256, SHA384.
    \return BAD_FUNC_ARG may be returned for an error state.
    \return SSL_FATAL_ERROR may also be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacSize
*/
int                  wolfSSL_GetHmacType(WOLFSSL*);

/*!
    \brief Allows caller to determine the negotiated cipher type
    from the handshake.

    \return If successful the call will return one of the following:
    WOLFSSL_BLOCK_TYPE, WOLFSSL_STREAM_TYPE, WOLFSSL_AEAD_TYPE.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetCipherType(WOLFSSL*);

/*!
    \brief Allows caller to set the Hmac Inner vector for message
    sending/receiving.  The result is written to inner which should
    be at least wolfSSL_GetHmacSize() bytes.  The size of the message
    is specified by sz, content is the type of message, and verify
    specifies whether this is a verification of a peer message. Valid
    for cipher types excluding WOLFSSL_AEAD_TYPE.

    \return 1 upon success.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int wolfSSL_SetTlsHmacInner(WOLFSSL* ssl, byte* inner,
                            word32 sz, int content, int verify);

/*!
    \brief Allows caller to set the Public Key Callback for ECC Signing.
    The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    in is the input buffer to sign while inSz denotes the length of the input.
    out is the output buffer where the result of the signature should be stored.
    outSz is an input/output variable that specifies the size of the output
    buffer upon invocation and the actual size of the signature should be stored
    there before returning.  keyDer is the ECC Private key in ASN1 format and
    keySz is the length of the key in bytes.  An example callback can be found
    wolfssl/test.h myEccSign().

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetEccSignCtx
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx, CallbackEccSign cb);

/*!
    \brief Allows caller to set the Public Key Ecc Signing Callback
    Context to ctx.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param ctx a pointer to the user context to be stored

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key Ecc Signing Callback
    Context previously stored with wolfSSL_SetEccSignCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_SetEccSignCtx
*/
void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Ecc Signing Callback
    Context to ctx.

    \return none No returns.

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param ctx a pointer to the user context to be stored

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx);

/*!
    \brief Allows caller to retrieve the Public Key Ecc Signing Callback
    Context previously stored with wolfSSL_SetEccSignCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_SetEccSignCtx
*/
void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx);

/*!
    \brief Allows caller to set the Public Key Callback for ECC Verification.
    The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    sig is the signature to verify and sigSz denotes the length of the
    signature. hash is an input buffer containing the digest of the message
    and hashSz denotes the length in bytes of the hash.  result is an output
    variable where the result of the verification should be stored, 1 for
    success and 0 for failure.  keyDer is the ECC Private key in ASN1
    format and keySz is the length of the key in bytes.  An example
    callback can be found wolfssl/test.h myEccVerify().

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetEccVerifyCtx
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb);

/*!
    \brief Allows caller to set the Public Key Ecc Verification Callback
    Context to ctx.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key Ecc Verification Callback
    Context previously stored with wolfSSL_SetEccVerifyCtx().

    \return pointer If successful the call will return a valid pointer to the
    context.
    \return NULL will be returned for a blank context.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_SetEccVerifyCtx
*/
void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Signing.
    The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    in is the input buffer to sign while inSz denotes the length of the input.
    out is the output buffer where the result of the signature should be stored.
    outSz is an input/output variable that specifies the size of the output
    buffer upon invocation and the actual size of the signature should be
    stored there before returning.  keyDer is the RSA Private key in ASN1 format
    and keySz is the length of the key in bytes.  An example callback can be
    found wolfssl/test.h myRsaSign().

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaSignCtx
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb);

/*!
    \brief Allows caller to set the Public Key RSA Signing Callback Context
    to ctx.

    \return none No Returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Signing Callback
    Context previously stored with wolfSSL_SetRsaSignCtx().

    \return pointer If successful the call will return a valid pointer to the
    context.
    \return NULL will be returned for a blank context.

    \param none No parameters.
    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_SetRsaSignCtx
*/
void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Verification.
    The callback should return the number of plaintext bytes for success or
    < 0 for an error.  The ssl and ctx pointers are available for the user’s
    convenience.  sig is the signature to verify and sigSz denotes the length
    of the signature.  out should be set to the beginning of the verification
    buffer after the decryption process and any padding.  keyDer is the RSA
    Public key in ASN1 format and keySz is the length of the key in bytes.
    An example callback can be found wolfssl/test.h myRsaVerify().

    \return none No returns.

    \param none No parameters.

    \sa wolfSSL_SetRsaVerifyCtx
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);

/*!
    \brief Allows caller to set the Public Key RSA Verification Callback
    Context to ctx.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Verification Callback
    Context previously stored with wolfSSL_SetRsaVerifyCtx().

    \return pointer If successful the call will return a valid pointer to
    the context.
    \return NULL will be returned for a blank context.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_SetRsaVerifyCtx
*/
void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Public
    Encrypt.  The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    in is the input buffer to encrypt while inSz denotes the length of
    the input.  out is the output buffer where the result of the encryption
    should be stored.  outSz is an input/output variable that specifies
    the size of the output buffer upon invocation and the actual size of
    the encryption should be stored there before returning.  keyDer is the
    RSA Public key in ASN1 format and keySz is the length of the key in
    bytes. An example callback can be found wolfssl/test.h myRsaEnc().

    \return none No returns.

    \param none No parameters.

    _Examples_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaEncCtx
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb);

/*!
    \brief Allows caller to set the Public Key RSA Public Encrypt
    Callback Context to ctx.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Public Encrypt
    Callback Context previously stored with wolfSSL_SetRsaEncCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_SetRsaEncCtx
*/
void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Private
    Decrypt.  The callback should return the number of plaintext bytes
    for success or < 0 for an error.  The ssl and ctx pointers are available
    for the user’s convenience.  in is the input buffer to decrypt and inSz
    denotes the length of the input.  out should be set to the beginning
    of the decryption buffer after the decryption process and any padding.
    keyDer is the RSA Private key in ASN1 format and keySz is the length
    of the key in bytes.  An example callback can be found
    wolfssl/test.h myRsaDec().

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaDecCtx
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb);

/*!
    \brief Allows caller to set the Public Key RSA Private Decrypt
    Callback Context to ctx.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Private Decrypt
    Callback Context previously stored with wolfSSL_SetRsaDecCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_SetRsaDecCtx
*/
void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);

/*!
    \brief This function registers a callback with the SSL context
    (WOLFSSL_CTX) to be called when a new CA certificate is loaded
    into wolfSSL.  The callback is given a buffer with the DER-encoded
    certificate.

    \return none No return.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param callback function to be registered as the CA callback for the
    wolfSSL context, ctx. The signature of this function must follow that
    as shown above in the Synopsis section.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;

    // CA callback prototype
    int MyCACallback(unsigned char *der, int sz, int type);

    // Register the custom CA callback with the SSL context
    wolfSSL_CTX_SetCACb(ctx, MyCACallback);

    int MyCACallback(unsigned char* der, int sz, int type)
    {
    	// custom CA callback function, DER-encoded cert
        // located in “der” of size “sz” with type “type”
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
*/
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb);

/*!
    \ingroup CertManager
    \brief Allocates and initializes a new Certificate Manager context.
    This context may be used independent of SSL needs.  It may be used to
    load certificates, verify certificates, and check the revocation status.

    \return WOLFSSL_CERT_MANAGER If successful the call will return a valid
    WOLFSSL_CERT_MANAGER pointer.
    \return NULL will be returned for an error state.

    \param none No parameters.

    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);

/*!
    \ingroup CertManager
    \brief Allocates and initializes a new Certificate Manager context.
    This context may be used independent of SSL needs.  It may be used to
    load certificates, verify certificates, and check the revocation status.

    \return WOLFSSL_CERT_MANAGER If successful the call will return a
    valid WOLFSSL_CERT_MANAGER pointer.
    \return NULL will be returned for an error state.

    \param none No parameters.

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
	// error creating new cert manager
    }
    \endcode

    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);

/*!
    \ingroup CertManager
    \brief Frees all resources associated with the Certificate Manager
    context.  Call this when you no longer need to use the Certificate Manager.

    \return none

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    ...
    wolfSSL_CertManagerFree(cm);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief Specifies the locations for CA certificate loading into the
    manager context.  The PEM certificate CAfile may contain several
    trusted CA certificates.  If CApath is not NULL it specifies a
    directory containing CA certificates in PEM format.

    \return SSL_SUCCESS If successful the call will return.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a
    pointer is not provided.
    \return SSL_FATAL_ERROR - will be returned upon failure.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created
    using wolfSSL_CertManagerNew().
    \param file pointer to the name of the file containing CA
    certificates to load.
    \param path pointer to the name of a directory path containing CA c
    ertificates to load.  The NULL pointer may be used if no
    certificate directory is desired.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerLoadCA(cm, “path/to/cert-file.pem”, 0);
    if (ret != SSL_SUCCESS) {
	// error loading CA certs into cert manager
    }
    \endcode

    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                 const char* d);

/*!
    \ingroup CertManager
    \brief Loads the CA Buffer by calling wolfSSL_CTX_load_verify_buffer and
    returning that result using a temporary cm so as not to lose the information
    in the cm passed into the function.

    \return SSL_FATAL_ERROR is returned if the WOLFSSL_CERT_MANAGER struct is
    NULL or if wolfSSL_CTX_new() returns NULL.
    \return SSL_SUCCESS is returned for a successful execution.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param in buffer for cert information.
    \param sz length of the buffer.
    \param format certificate format, either PEM or DER.

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    …
    const unsigned char* in;
    long sz;
    int format;
    …
    if(wolfSSL_CertManagerLoadCABuffer(vp, sz, format) != SSL_SUCCESS){
	    Error returned. Failure case code block.
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa ProcessChainBuffer
    \sa ProcessBuffer
    \sa cm_pick_method
*/
int wolfSSL_CertManagerLoadCABuffer(WOLFSSL_CERT_MANAGER* cm,
                                  const unsigned char* in, long sz, int format);

/*!
    \ingroup CertManager
    \brief This function unloads the CA signer list.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E returned if there was a mutex error.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure,
    created using wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    ...
    if(wolfSSL_CertManagerUnloadCAs(cm) != SSL_SUCCESS){
        Failure case.
    }
    \endcode

    \sa UnlockMutex
*/
int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief This function unloads intermediate certificates add to the CA
    signer list.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E returned if there was a mutex error.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure,
    created using wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    ...
    if(wolfSSL_CertManagerUnloadIntermediateCerts(cm) != SSL_SUCCESS){
    	Failure case.
    }
    \endcode

    \sa UnlockMutex
*/
int wolfSSL_CertManagerUnloadIntermediateCerts(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief The function will free the Trusted Peer linked list and unlocks
    the trusted peer list.

    \return SSL_SUCCESS if the function completed normally.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E mutex  error if tpLock, a member of the
    WOLFSSL_CERT_MANAGER struct, is 0 (nill).

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    if(wolfSSL_CertManagerUnload_trust_peers(cm) != SSL_SUCCESS){
	    The function did not execute successfully.
    }
    \endcode

    \sa UnLockMutex
*/
int wolfSSL_CertManagerUnload_trust_peers(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief Specifies the certificate to verify with the Certificate Manager
    context.  The format can be SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.

    \return SSL_SUCCESS If successful.
    \return ASN_SIG_CONFIRM_E will be returned if the signature could not be
    verified.
    \return ASN_SIG_OID_E will be returned if the signature type is not
    supported.
    \return CRL_CERT_REVOKED is an error that is returned if this certificate
    has been revoked.
    \return CRL_MISSING is an error that is returned if a current issuer CRL is
    not available.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before the
    before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after the
    after date.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer is
    not provided.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param fname pointer to the name of the file containing the certificates
    to verify.
    \param format format of the certificate to verify - either
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerVerify(cm, “path/to/cert-file.pem”,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    error verifying certificate
    }
    \endcode

    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerifyBuffer
*/
int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                    int format);

/*!
    \ingroup CertManager
    \brief Specifies the certificate buffer to verify with the Certificate
    Manager context.  The format can be SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.

    \return SSL_SUCCESS If successful.
    \return ASN_SIG_CONFIRM_E will be returned if the signature could not
    be verified.
    \return ASN_SIG_OID_E will be returned if the signature type is not
    supported.
    \return CRL_CERT_REVOKED is an error that is returned if this certificate
    has been revoked.
    \return CRL_MISSING is an error that is returned if a current issuer CRL
    is not available.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before
    the before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after
    the after date.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t
    be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer
    is not provided.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param buff buffer containing the certificates to verify.
    \param sz size of the buffer, buf.
    \param format format of the certificate to verify, located in buf - either
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    int sz = 0;
    WOLFSSL_CERT_MANAGER* cm;
    byte certBuff[...];
    ...

    ret = wolfSSL_CertManagerVerifyBuffer(cm, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	error verifying certificate
    }

    \endcode

    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* buff, long sz, int format);

/*!
    \ingroup CertManager
    \brief The function sets the verifyCallback function in the Certificate
    Manager. If present, it will be called for each cert loaded. If there is
    a verification error, the verify callback can be used to over-ride the
    error.

    \return none No return.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param verify_callback a VerifyCallback function pointer to the callback
    routine

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
    { // do custom verification of certificate }

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    wolfSSL_CertManagerSetVerify(cm, myVerify);

    \endcode

    \sa wolfSSL_CertManagerVerify
*/
void wolfSSL_CertManagerSetVerify(WOLFSSL_CERT_MANAGER* cm,
        VerifyCallback verify_callback);

/*!
    \brief Check CRL if the option is enabled and compares the cert to the
    CRL list.

    \return SSL_SUCCESS returns if the function returned as expected. If
    the crlEnabled member of the WOLFSSL_CERT_MANAGER struct is turned on.
    \return MEMORY_E returns if the allocated memory failed.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER is NULL.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER struct.
    \param der pointer to a DER formatted certificate.
    \param sz size of the certificate.

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm;
    byte* der;
    int sz; // size of der
    ...
    if(wolfSSL_CertManagerCheckCRL(cm, der, sz) != SSL_SUCCESS){
    	// Error returned. Deal with failure case.
    }
    \endcode

    \sa CheckCertCRL
    \sa ParseCertRelative
    \sa wolfSSL_CertManagerSetCRL_CB
    \sa InitDecodedCert
*/
int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER* cm,
                                unsigned char* der, int sz);

/*!
    \ingroup CertManager
    \brief Turns on Certificate Revocation List checking when verifying
    certificates with the Certificate Manager.  By default, CRL checking
    is off.  options include WOLFSSL_CRL_CHECKALL which performs CRL
    checking on each certificate in the chain versus the Leaf certificate
    only which is the default.

    \return SSL_SUCCESS If successful the call will return.
    \return NOT_COMPILED_IN will be returned if wolfSSL was not built with
    CRL enabled.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer
    is not provided.
    \return SSL_FAILURE will be returned if the CRL context cannot be
    initialized properly.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param options options to use when enabling the Certification Manager, cm.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerEnableCRL(cm, 0);
    if (ret != SSL_SUCCESS) {
    	error enabling cert manager
    }

    ...
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief Turns off Certificate Revocation List checking when verifying
    certificates with the Certificate Manager.  By default, CRL checking is
    off.  You can use this function to temporarily or permanently disable CRL
    checking with this Certificate Manager context that previously had CRL
    checking enabled.

    \return SSL_SUCCESS If successful the call will return.
    \return BAD_FUNC_ARG is the error that will be returned if a function
    pointer is not provided.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerDisableCRL(cm);
    if (ret != SSL_SUCCESS) {
    	error disabling cert manager
    }
    ...
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
*/
int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief Error checks and passes through to LoadCRL() in order to load the
    cert into the CRL for revocation checking. An updated CRL can be loaded by
    first calling wolfSSL_CertManagerFreeCRL, then loading the new CRL.

    \return SSL_SUCCESS if there is no error in wolfSSL_CertManagerLoadCRL and
    if LoadCRL returns successfully.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER struct is NULL.
    \return SSL_FATAL_ERROR if wolfSSL_CertManagerEnableCRL returns anything
    other than SSL_SUCCESS.
    \return BAD_PATH_ERROR if the path is NULL.
    \return MEMORY_E if LoadCRL fails to allocate heap memory.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param path a constant char pointer holding the CRL path.
    \param type type of certificate to be loaded.
    \param monitor requests monitoring in LoadCRL().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type,
    int monitor);
    …
    wolfSSL_CertManagerLoadCRL(SSL_CM(ssl), path, type, monitor);
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa wolfSSL_LoadCRL
    \sa wolfSSL_CertManagerFreeCRL
*/
int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER* cm,
                               const char* path, int type, int monitor);

/*!
    \ingroup CertManager
    \brief The function loads the CRL file by calling BufferLoadCRL.

    \return SSL_SUCCESS returned if the function completed without errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return SSL_FATAL_ERROR returned if there is an error associated
    with the WOLFSSL_CERT_MANAGER.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure.
    \param buff a constant byte type and is the buffer.
    \param sz a long int representing the size of the buffer.
    \param type a long integer that holds the certificate type.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    const unsigned char* buff;
    long sz; size of buffer
    int type;  cert type
    ...
    int ret = wolfSSL_CertManagerLoadCRLBuffer(cm, buff, sz, type);
    if(ret == SSL_SUCCESS){
	return ret;
    } else {
    	Failure case.
    }
    \endcode

    \sa BufferLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
*/
int wolfSSL_CertManagerLoadCRLBuffer(WOLFSSL_CERT_MANAGER* cm,
                                     const unsigned char* buff, long sz,
                                     int type);

/*!
    \ingroup CertManager
    \brief This function sets the CRL Certificate Manager callback. If
    HAVE_CRL is defined and a matching CRL record is not found then the
    cbMissingCRL is called (set via wolfSSL_CertManagerSetCRL_Cb). This
    allows you to externally retrieve the CRL and load it.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm the WOLFSSL_CERT_MANAGER structure holding the information for
    the certificate.
    \param cb a function pointer to (*CbMissingCRL) that is set to the
    cbMissingCRL member of the WOLFSSL_CERT_MANAGER.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url){
	    Function body.
    }
    …
    CbMissingCRL cb = CbMissingCRL;
    …
    if(ctx){
        return wolfSSL_CertManagerSetCRL_Cb(SSL_CM(ssl), cb);
    }
    \endcode

    \sa CbMissingCRL
    \sa wolfSSL_SetCRL_Cb
*/
int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER* cm,
                                 CbMissingCRL cb);

/*!
    \ingroup CertManager
    \brief This function sets the CRL Update callback. If
    HAVE_CRL and HAVE_CRL_UPDATE_CB is defined , and an entry with the same
    issuer and a lower CRL number exists when a CRL is added, then the
    CbUpdateCRL is called with the details of the existing entry and the
    new one replacing it.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm the WOLFSSL_CERT_MANAGER structure holding the information for
    the certificate.
    \param cb a function pointer to (*CbUpdateCRL) that is set to the
    cbUpdateCRL member of the WOLFSSL_CERT_MANAGER.
    Signature requirement:
	void (*CbUpdateCRL)(CrlInfo *old, CrlInfo *new);

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(CrlInfo *old, CrlInfo *new){
	    Function body.
    }
    …
    CbUpdateCRL cb = CbUpdateCRL;
    …
    if(ctx){
        return wolfSSL_CertManagerSetCRLUpdate_Cb(SSL_CM(ssl), cb);
    }
    \endcode

    \sa CbUpdateCRL
*/
int wolfSSL_CertManagerSetCRLUpdate_Cb(WOLFSSL_CERT_MANAGER* cm,
                                       CbUpdateCRL cb);

/*!
    \ingroup CertManager
    \brief This function yields a structure with parsed CRL information from
    an encoded CRL buffer.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm   the WOLFSSL_CERT_MANAGER structure..
    \param info pointer to caller managed CrlInfo structure that will receive
                the CRL information.
    \param buff input buffer containing encoded CRL.
    \param sz   the length in bytes of the input CRL data in buff.
    \param type WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_DER

    _Example_
    \code
    #include <wolfssl/ssl.h>

    CrlInfo info;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    cm = wolfSSL_CertManagerNew();

    // Read crl data from file into buffer

    wolfSSL_CertManagerGetCRLInfo(cm, &info, crlData, crlDataLen,
                                  WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa CbUpdateCRL
    \sa wolfSSL_SetCRL_Cb
*/
int wolfSSL_CertManagerGetCRLInfo(WOLFSSL_CERT_MANAGER* cm, CrlInfo* info,
    const byte* buff, long sz, int type)

/*!
    \ingroup CertManager
    \brief This function frees the CRL stored in the Cert Manager. An
    application can update the CRL by calling wolfSSL_CertManagerFreeCRL
    and then loading the new CRL.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    const char* crl1     = "./certs/crl/crl.pem";
    WOLFSSL_CERT_MANAGER* cm = NULL;

    cm = wolfSSL_CertManagerNew();
    wolfSSL_CertManagerLoadCRL(cm, crl1, WOLFSSL_FILETYPE_PEM, 0);
    …
    wolfSSL_CertManagerFreeCRL(cm);
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
*/
int wolfSSL_CertManagerFreeCRL(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief The function enables the WOLFSSL_CERT_MANAGER’s member, ocspEnabled
    to signify that the OCSP check option is enabled.

    \return SSL_SUCCESS returned on successful execution of the function. The
    ocspEnabled member of the WOLFSSL_CERT_MANAGER is enabled.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is
    NULL or if an argument value that is not allowed is passed to a subroutine.
    \return MEMORY_E returned if there is an error allocating memory within
    this function or a subroutine.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param der a byte pointer to the certificate.
    \param sz an int type representing the size of the DER cert.

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* der;
    int sz; size of der
    ...
    if(wolfSSL_CertManagerCheckOCSP(cm, der, sz) != SSL_SUCCESS){
	 Failure case.
    }
    \endcode

    \sa ParseCertRelative
    \sa CheckCertOCSP
*/
int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER* cm,
                                 unsigned char* der, int sz);

/*!
    \ingroup CertManager
    \brief Turns on OCSP if it’s turned off and if compiled with the
    set option available.

    \return SSL_SUCCESS returned if the function call is successful.
    \return BAD_FUNC_ARG if cm struct is NULL.
    \return MEMORY_E if WOLFSSL_OCSP struct value is NULL.
    \return SSL_FAILURE initialization of WOLFSSL_OCSP struct fails
    to initialize.
    \return NOT_COMPILED_IN build not compiled with correct feature enabled.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param options used to set values in WOLFSSL_CERT_MANAGER struct.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    int options;
    …
    if(wolfSSL_CertManagerEnableOCSP(SSL_CM(ssl), options) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode

    \sa wolfSSL_CertManagerNew
*/
int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief Disables OCSP certificate revocation.

    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRL successfully disabled the
    crlEnabled member of the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL.

    \param ssl - a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CertManagerDisableOCSP(ssl) != SSL_SUCCESS){
	    Fail case.
    }
    \endcode

    \sa wolfSSL_DisableCRL
*/
int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER*);

/*!
    \ingroup CertManager
    \brief The function copies the url to the ocspOverrideURL member of the
    WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS the function was able to execute as expected.
    \return BAD_FUNC_ARG the WOLFSSL_CERT_MANAGER struct is NULL.
    \return MEMEORY_E Memory was not able to be allocated for the
    ocspOverrideURL member of the certificate manager.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    const char* url;
    …
    int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
    …
    if(wolfSSL_CertManagerSetOCSPOverrideURL(SSL_CM(ssl), url) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode

    \sa ocspOverrideURL
    \sa wolfSSL_SetOCSP_OverrideURL
*/
int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER* cm,
                                          const char* url);

/*!
    \ingroup CertManager
    \brief The function sets the OCSP callback in the WOLFSSL_CERT_MANAGER.

    \return SSL_SUCCESS returned on successful execution. The arguments are
    saved in the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure.
    \param ioCb a function pointer of type CbOCSPIO.
    \param respFreeCb - a function pointer of type CbOCSPRespFree.
    \param ioCbCtx - a void pointer variable to the I/O callback user
    registered context.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb,
    CbOCSPRespFree respFreeCb, void* ioCbCtx){
    …
    return wolfSSL_CertManagerSetOCSP_Cb(SSL_CM(ssl), ioCb, respFreeCb, ioCbCtx);
    \endcode

    \sa wolfSSL_CertManagerSetOCSPOverrideURL
    \sa wolfSSL_CertManagerCheckOCSP
    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa wolfSSL_EnableOCSP
    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_SetOCSP_Cb
*/
int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER* cm,
                                  CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                                  void* ioCbCtx);

/*!
    \ingroup CertManager
    \brief This function turns on OCSP stapling if it is not turned on as well
    as set the options.

    \return SSL_SUCCESS returned if there were no errors and the function
    executed successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is
    NULL or otherwise if there was a unpermitted argument value passed to
    a subroutine.
    \return MEMORY_E returned if there was an issue allocating memory.
    \return SSL_FAILURE returned if the initialization of the OCSP
    structure failed.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with
    HAVE_CERTIFICATE_STATUS_REQUEST option.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, a member of the
    WOLFSSL_CTX structure.

    _Example_
    \code
    int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx){
    …
    return wolfSSL_CertManagerEnableOCSPStapling(ctx->cm);
    \endcode

    \sa wolfSSL_CTX_EnableOCSPStapling
*/
int wolfSSL_CertManagerEnableOCSPStapling(
                                                      WOLFSSL_CERT_MANAGER* cm);

/*!
    \brief Enables CRL certificate revocation.

    \return SSL_SUCCESS the function and subroutines returned with no errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.
    \return MEMORY_E returned if the allocation of memory failed.
    \return SSL_FAILURE returned if the InitCRL function does not return
    successfully.
    \return NOT_COMPILED_IN HAVE_CRL was not enabled during the compiling.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param options an integer that is used to determine the setting of
    crlCheckAll member of the WOLFSSL_CERT_MANAGER structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_EnableCRL(ssl, WOLFSSL_CRL_CHECKALL) != SSL_SUCCESS){
	    // Failure case. SSL_SUCCESS was not returned by this function or
    a subroutine
    }
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
*/
int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);

/*!
    \brief Disables CRL certificate revocation.

    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRL successfully disabled
    the crlEnabled member of the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_DisableCRL(ssl) != SSL_SUCCESS){
    	// Failure case
    }
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableCRL(WOLFSSL* ssl);

/*!
    \brief A wrapper function that ends up calling LoadCRL to load the
    certificate for revocation checking.

    \return WOLFSSL_SUCCESS returned if the function and all of the
    subroutines executed without error.
    \return SSL_FATAL_ERROR returned if one of the subroutines does not
    return successfully.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER or the WOLFSSL
    structure are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param path a constant character pointer that holds the path to the
    crl file.
    \param type an integer representing the type of certificate.
    \param monitor an integer variable used to verify the monitor path if
    requested.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* crlPemDir;
    …
    if(wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS){
    	// Failure case. Did not return SSL_SUCCESS.
    }
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
    \sa LoadCRL
*/
int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor);

/*!
    \brief Sets the CRL callback in the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned if the function or subroutine executes
    without error. The cbMissingCRL member of the WOLFSSL_CERT_MANAGER is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL or WOLFSSL_CERT_MANAGER
    structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to CbMissingCRL.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url) // required signature
    {
    	// Function body
    }
    …
    int crlCb = wolfSSL_SetCRL_Cb(ssl, cb);
    if(crlCb != SSL_SUCCESS){
    	// The callback was not set properly
    }
    \endcode

    \sa CbMissingCRL
    \sa wolfSSL_CertManagerSetCRL_Cb
*/
int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb);

/*!
    \brief This function enables OCSP certificate verification. The value of
    options if formed by or’ing one or more of the following options:
    WOLFSSL_OCSP_URL_OVERRIDE - use the override URL instead of the URL in
     certificates. The override URL is specified using the
     wolfSSL_CTX_SetOCSP_OverrideURL() function.
    WOLFSSL_OCSP_CHECKALL - Set all OCSP checks on
    WOLFSSL_OCSP_NO_NONCE - Set nonce option for creating OCSP requests

    \return SSL_SUCCESS returned if the function and subroutines executes
    without errors.
    \return BAD_FUNC_ARG returned if an argument in this function or any
    subroutine receives an invalid argument value.
    \return MEMORY_E returned if there was an error allocating memory for
    a structure or other variable.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with the
    HAVE_OCSP option.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param options an integer type passed to wolfSSL_CertMangerENableOCSP()
    used for settings check.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int options; // initialize to option constant
    …
    int ret = wolfSSL_EnableOCSP(ssl, options);
    if(ret != SSL_SUCCESS){
    	// OCSP is not enabled
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSP
*/
int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options);

/*!
    \brief Disables the OCSP certificate revocation option.

    \return SSL_SUCCESS returned if the function and its subroutine return with
    no errors. The ocspEnabled member of the WOLFSSL_CERT_MANAGER structure was
    successfully set.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(wolfSSL_DisableOCSP(ssl) != SSL_SUCCESS){
	    // Returned with an error. Failure case in this block.
    }
    \endcode

    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableOCSP(WOLFSSL*);

/*!
    \brief This function sets the ocspOverrideURL member in the
    WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if a
    unpermitted argument was passed to a subroutine.
    \return MEMORY_E returned if there was an error allocating memory in the
    subroutine.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param url a constant char pointer to the url that will be stored in the
    ocspOverrideURL member of the WOLFSSL_CERT_MANAGER structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char url[URLSZ];
    ...
    if(wolfSSL_SetOCSP_OverrideURL(ssl, url)){
    	// The override url is set to the new value
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSPOverrideURL
*/
int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url);

/*!
    \brief This function sets the OCSP callback in the
    WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned if the function executes without error.
    The ocspIOCb, ocspRespFreeCb, and ocspIOCtx members of the CM are set.
    \return BAD_FUNC_ARG returned if the WOLFSSL or WOLFSSL_CERT_MANAGER
    structures are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ioCb a function pointer to type CbOCSPIO.
    \param respFreeCb a function pointer to type CbOCSPRespFree which is the
    call to free the response memory.
    \param ioCbCtx a void pointer that will be held in the ocspIOCtx member
    of the CM.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int OCSPIO_CB(void* , const char*, int , unsigned char* , int,
    unsigned char**){  // must have this signature
    // Function Body
    }
    …
    void OCSPRespFree_CB(void* , unsigned char* ){ // must have this signature
    	// function body
    }
    …
    void* ioCbCtx;
    CbOCSPRespFree CB_OCSPRespFree;

    if(wolfSSL_SetOCSP_Cb(ssl, OCSPIO_CB( pass args ), CB_OCSPRespFree,
				ioCbCtx) != SSL_SUCCESS){
	    // Callback not set
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                       void* ioCbCtx);

/*!
    \brief Enables CRL certificate verification through the CTX.

    \return SSL_SUCCESS returned if this function and it’s subroutines
    execute without errors.
    \return BAD_FUNC_ARG returned if the CTX struct is NULL or there
    was otherwise an invalid argument passed in a subroutine.
    \return MEMORY_E returned if there was an error allocating
    memory during execution of the function.
    \return SSL_FAILURE returned if the crl member of the
    WOLFSSL_CERT_MANAGER fails to initialize correctly.
    \return NOT_COMPILED_IN wolfSSL was not compiled with the HAVE_CRL option.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_EnableCRL(ssl->ctx, options) != SSL_SUCCESS){
    	// The function failed
    }
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
    \sa wolfSSL_CTX_DisableCRL
*/
int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);

/*!
    \brief This function disables CRL verification in the CTX structure.

    \return SSL_SUCCESS returned if the function executes without error.
    The crlEnabled member of the WOLFSSL_CERT_MANAGER struct is set to 0.
    \return BAD_FUNC_ARG returned if either the CTX struct or the CM
    struct has a NULL value.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_DisableCRL(ssl->ctx) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);

/*!
    \brief This function loads CRL into the WOLFSSL_CTX structure through
    wolfSSL_CertManagerLoadCRL().

    \return SSL_SUCCESS - returned if the function and its subroutines
    execute without error.
    \return BAD_FUNC_ARG - returned if this function or any subroutines
    are passed NULL structures.
    \return BAD_PATH_ERROR - returned if the path variable opens as NULL.
    \return MEMORY_E - returned if an allocation of memory failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param path the path to the certificate.
    \param type an integer variable holding the type of certificate.
    \param monitor an integer variable used to determine if the monitor
    path is requested.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    const char* path;
    …
    return wolfSSL_CTX_LoadCRL(ctx, path, SSL_FILETYPE_PEM, 0);
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
    \sa LoadCRL
*/
int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path, int type, int monitor);

/*!
    \brief This function will set the callback argument to the cbMissingCRL
    member of the WOLFSSL_CERT_MANAGER structure by calling
    wolfSSL_CertManagerSetCRL_Cb.

    \return SSL_SUCCESS returned for a successful execution. The
    WOLFSSL_CERT_MANAGER structure’s member cbMssingCRL was successfully
    set to cb.
    \return BAD_FUNC_ARG returned if WOLFSSL_CTX or WOLFSSL_CERT_MANAGER
    are NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created with
    wolfSSL_CTX_new().
    \param cb a pointer to a callback function of type CbMissingCRL.
    Signature requirement:
	void (*CbMissingCRL)(const char* url);

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    void cb(const char* url) // Required signature
    {
    	// Function body
    }
    …
    if (wolfSSL_CTX_SetCRL_Cb(ctx, cb) != SSL_SUCCESS){
    	// Failure case, cb was not set correctly.
    }
    \endcode

    \sa wolfSSL_CertManagerSetCRL_Cb
    \sa CbMissingCRL
*/
int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb);

/*!
    \brief This function sets options to configure behavior of OCSP
    functionality in wolfSSL.  The value of options if formed by or’ing
    one or more of the following options:
    WOLFSSL_OCSP_URL_OVERRIDE - use the override URL instead of the URL in
     certificates. The override URL is specified using the
     wolfSSL_CTX_SetOCSP_OverrideURL() function.
    WOLFSSL_OCSP_CHECKALL - Set all OCSP checks on
    WOLFSSL_OCSP_NO_NONCE - Set nonce option for creating OCSP requests

    This function only sets the OCSP options when wolfSSL has been compiled with
    OCSP support (--enable-ocsp, #define HAVE_OCSP).

    \return SSL_SUCCESS is returned upon success.
    \return SSL_FAILURE is returned upon failure.
    \return NOT_COMPILED_IN is returned when this function has been called,
    but OCSP support was not enabled when wolfSSL was compiled.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param options value used to set the OCSP options.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    int options; // initialize to option constant
    …
    int ret = wolfSSL_CTX_EnableOCSP(ctx, options);
    if(ret != SSL_SUCCESS){
        // OCSP is not enabled
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSP
    \sa wolfSSL_EnableOCSP
*/
int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options);

/*!
    \brief This function disables OCSP certificate revocation checking by
    affecting the ocspEnabled member of the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned if the function executes without error.
    The ocspEnabled member of the CM has been disabled.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(!wolfSSL_CTX_DisableOCSP(ssl->ctx)){
    	// OCSP is not disabled
    }
    \endcode

    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX*);

/*!
    \brief This function manually sets the URL for OCSP to use. By default,
    OCSP will use the URL found in the individual certificate unless the
    WOLFSSL_OCSP_URL_OVERRIDE option is set using the wolfSSL_CTX_EnableOCSP.

    \return SSL_SUCCESS is returned upon success.
    \return SSL_FAILURE is returned upon failure.
    \return NOT_COMPILED_IN is returned when this function has been called,
    but OCSP support was not enabled when wolfSSL was compiled.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param url pointer to the OCSP URL for wolfSSL to use.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_OCSP_set_override_url(ctx, “custom-url-here”);
    \endcode

    \sa wolfSSL_CTX_OCSP_set_options
*/
int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url);

/*!
    \brief Sets the callback for the OCSP in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned if the function executed successfully. The
    ocspIOCb, ocspRespFreeCb, and ocspIOCtx members in the CM were
    successfully set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX or
    WOLFSSL_CERT_MANAGER structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ioCb a CbOCSPIO type that is a function pointer.
    \param respFreeCb a CbOCSPRespFree type that is a function pointer.
    \param ioCbCtx a void pointer that will be held in the WOLFSSL_CERT_MANAGER.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    CbOCSPIO ocspIOCb;
    CbOCSPRespFree ocspRespFreeCb;
    …
    void* ioCbCtx;

    int isSetOCSP = wolfSSL_CTX_SetOCSP_Cb(ctx, ocspIOCb,
    ocspRespFreeCb, ioCbCtx);

    if(isSetOCSP != SSL_SUCCESS){
    	// The function did not return successfully.
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx,
                           CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                           void* ioCbCtx);

/*!
    \brief This function enables OCSP stapling by calling
    wolfSSL_CertManagerEnableOCSPStapling().

    \return SSL_SUCCESS returned if there were no errors and the function
    executed successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or
    otherwise if there was a unpermitted argument value passed to a subroutine.
    \return MEMORY_E returned if there was an issue allocating memory.
    \return SSL_FAILURE returned if the initialization of the OCSP
    structure failed.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with
    HAVE_CERTIFICATE_STATUS_REQUEST option.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL* ssl = WOLFSSL_new();
    ssl->method.version; // set to desired protocol
    ...
    if(!wolfSSL_CTX_EnableOCSPStapling(ssl->ctx)){
    	// OCSP stapling is not enabled
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa InitOCSP
*/
int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX*);

/*!
    \ingroup CertsKeys

    \brief Normally, at the end of the SSL handshake, wolfSSL frees
    temporary arrays.  Calling this function before the handshake begins
    will prevent wolfSSL from freeing temporary arrays.  Temporary arrays
    may be needed for things such as wolfSSL_get_keys() or PSK hints.
    When the user is done with temporary arrays, either wolfSSL_FreeArrays()
    may be called to free the resources immediately, or alternatively the
    resources will be freed when the associated SSL object is freed.

    \return none No return.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_KeepArrays(ssl);
    \endcode

    \sa wolfSSL_FreeArrays
*/
void wolfSSL_KeepArrays(WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief Normally, at the end of the SSL handshake, wolfSSL frees temporary
    arrays.  If wolfSSL_KeepArrays() has been called before the handshake,
    wolfSSL will not free temporary arrays.  This function explicitly frees
    temporary arrays and should be called when the user is done with temporary
    arrays and does not want to wait for the SSL object to be freed to free
    these resources.

    \return none No return.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_FreeArrays(ssl);
    \endcode

    \sa wolfSSL_KeepArrays
*/
void wolfSSL_FreeArrays(WOLFSSL*);

/*!
    \brief This function enables the use of Server Name Indication in the SSL
    object passed in the 'ssl' parameter. It means that the SNI extension will
    be sent on ClientHello by wolfSSL client and wolfSSL server will respond
    ClientHello + SNI with either ServerHello + blank SNI or alert fatal in
    case of SNI mismatch.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ssl is NULL, data is NULL, type is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the server name data.
    \param size size of the server name data.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseSNI
*/
int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief This function enables the use of Server Name Indication for SSL
    objects created from the SSL context passed in the 'ctx' parameter. It
    means that the SNI extension will be sent on ClientHello by wolfSSL
    clients and wolfSSL servers will respond ClientHello + SNI with either
    ServerHello + blank SNI or alert fatal in case of SNI mismatch.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ctx is NULL, data is NULL, type is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the server name data.
    \param size size of the server name data.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSNI
*/
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief This function is called on the server side to configure the
    behavior of the SSL session using Server Name Indication in the SSL
    object passed in the 'ssl' parameter. The options are explained below.

    \return none No returns.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param options a bitwise semaphore with the chosen options. The available
    options are: enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01,
    WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }; Normally the server will abort the
    handshake by sending a fatal-level unrecognized_name(112) alert if the
    hostname provided by the client mismatch with the servers.
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH With this option set, the server
    will not send a SNI response instead of aborting the session.
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH - With this option set, the server
    will send a SNI response as if the host names match instead of aborting
    the session.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
        WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_SNI_SetOptions
*/
void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, unsigned char type,
                                                         unsigned char options);

/*!
    \brief This function is called on the server side to configure the behavior
    of the SSL sessions using Server Name Indication for SSL objects created
    from the SSL context passed in the 'ctx' parameter. The options are
    explained below.

    \return none No returns.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param options a bitwise semaphore with the chosen options. The available
    options are: enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01,
    WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }; Normally the server will abort
    the handshake by sending a fatal-level unrecognized_name(112) alert if the
    hostname provided by the client mismatch with the servers.
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH With this option set, the
    server will not send a SNI response instead of aborting the session.
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH With this option set, the server
    will send a SNI response as if the host names match instead of aborting
    the session.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
       // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME,
    WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_SetOptions
*/
void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx,
                                     unsigned char type, unsigned char options);

/*!
    \brief This function is called on the server side to retrieve the Server
    Name Indication provided by the client from the Client Hello message sent
    by the client to start a session. It does not requires context or session
    setup to retrieve the SNI.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of this
    cases: buffer is NULL, bufferSz <= 0, sni is NULL, inOutSz is NULL or <= 0
    \return BUFFER_ERROR is the error returned when there is a malformed
    Client Hello message.
    \return INCOMPLETE_DATA is the error returned when there is not enough
    data to complete the extraction.

    \param buffer pointer to the data provided by the client (Client Hello).
    \param bufferSz size of the Client Hello message.
    \param type indicates which type of server name is been retrieved
    from the buffer. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param sni pointer to where the output is going to be stored.
    \param inOutSz pointer to the output size, this value will be updated
    to MIN("SNI's length", inOutSz).

    _Example_
    \code
    unsigned char buffer[1024] = {0};
    unsigned char result[32]   = {0};
    int           length       = 32;
    // read Client Hello to buffer...
    ret = wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer), 0, result, &length));
    if (ret != WOLFSSL_SUCCESS) {
        // sni retrieve failed
    }
    \endcode

    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_GetRequest
*/
int wolfSSL_SNI_GetFromBuffer(
                 const unsigned char* clientHello, unsigned int helloSz,
                 unsigned char type, unsigned char* sni, unsigned int* inOutSz);

/*!
    \ingroup IO

    \brief This function gets the status of an SNI object.

    \return value This function returns the byte value of the SNI struct’s
    status member if the SNI is not NULL.
    \return 0 if the SNI object is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param type the SNI type.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
    …
    Byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = (char*)&type;
    AssertIntEQ(WOLFSSL_SNI_NO_MATCH, wolfSSL_SNI_Status(ssl, type));
    …
    \endcode

    \sa TLSX_SNI_Status
    \sa TLSX_SNI_find
    \sa TLSX_Find
*/
unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type);

/*!
    \brief This function is called on the server side to retrieve the
    Server Name Indication provided by the client in a SSL session.

    \return size the size of the provided SNI data.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been retrieved in
    data. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the data provided by the client.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    if (wolfSSL_accept(ssl) == SSL_SUCCESS) {
        void *data = NULL;
        unsigned short size = wolfSSL_SNI_GetRequest(ssl, 0, &data);
    }
    \endcode

    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
*/
unsigned short wolfSSL_SNI_GetRequest(WOLFSSL *ssl,
                                               unsigned char type, void** data);

/*!
    \ingroup Setup

    \brief Setup ALPN use for a wolfSSL session.

    \return WOLFSSL_SUCCESS: upon success.
    \return BAD_FUNC_ARG Returned if ssl or protocol_name_list
    is null or protocol_name_listSz is too large or options
    contain something not supported.
    \return MEMORY_ERROR Error allocating memory for protocol list.
    \return SSL_FAILURE upon failure.

    \param ssl The wolfSSL session to use.
    \param protocol_name_list List of protocol names to use.
    Comma delimited string is required.
    \param protocol_name_listSz Size of the list of protocol names.
    \param options WOLFSSL_ALPN_CONTINUE_ON_MISMATCH or
    WOLFSSL_ALPN_FAILED_ON_MISMATCH.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    char alpn_list[] = {};

    if (wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
        WOLFSSL_APN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
       // Error setting session ticket
    }
    \endcode

    \sa TLSX_UseALPN
*/
int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
                                unsigned int protocol_name_listSz,
                                unsigned char options);

/*!
    \ingroup TLS

    \brief This function gets the protocol name set by the server.

    \return SSL_SUCCESS returned on successful execution where no
    errors were thrown.
    \return SSL_FATAL_ERROR returned if the extension was not found or
    if there was no protocol match with peer. There will also be an
    error thrown if there is more than one protocol name accepted.
    \return SSL_ALPN_NOT_FOUND returned signifying that no protocol
    match with peer was found.
    \return BAD_FUNC_ARG returned if there was a NULL argument passed
    into the function.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param protocol_name a pointer to a char that represents the protocol
    name and will be held in the ALPN structure.
    \param size a word16 type that represents the size of the protocol_name.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int err;
    char* protocol_name = NULL;
    Word16 protocol_nameSz = 0;
    err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);

    if(err == SSL_SUCCESS){
	    // Sent ALPN protocol
    }
    \endcode

    \sa TLSX_ALPN_GetRequest
    \sa TLSX_Find
*/
int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name,
                                         unsigned short *size);

/*!
    \ingroup TLS

    \brief This function copies the alpn_client_list data from the SSL
    object to the buffer.

    \return SSL_SUCCESS returned if the function executed without error. The
    alpn_client_list member of the SSL object has been copied to the
    list parameter.
    \return BAD_FUNC_ARG returned if the list or listSz parameter is NULL.
    \return BUFFER_ERROR returned if there will be a problem with the
    list buffer (either it’s NULL or the size is 0).
    \return MEMORY_ERROR returned if there was a problem dynamically
    allocating memory.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param list a pointer to the buffer. The data from the SSL object will
    be copied into it.
    \param listSz the buffer size.

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #ifdef HAVE_ALPN
    char* list = NULL;
    word16 listSz = 0;
    …
    err = wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz);

    if(err == SSL_SUCCESS){
	    List of protocols names sent by client
    }
    \endcode

    \sa wolfSSL_UseALPN
*/
int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list,
                                             unsigned short *listSz);

/*!
    \brief This function is called on the client side to enable the use of
    Maximum Fragment Length in the SSL object passed in the 'ssl' parameter.
    It means that the Maximum Fragment Length extension will be sent on
    ClientHello by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ssl is NULL, mfl is out of range.
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param mfl indicates which is the Maximum Fragment Length requested for the
    session. The available options are: enum { WOLFSSL_MFL_2_9  = 1, 512 bytes
    WOLFSSL_MFL_2_10 = 2, 1024 bytes WOLFSSL_MFL_2_11 = 3, 2048 bytes
    WOLFSSL_MFL_2_12 = 4, 4096 bytes WOLFSSL_MFL_2_13 = 5, 8192
    bytes wolfSSL ONLY!!! };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseMaxFragment(WOLFSSL* ssl, unsigned char mfl);

/*!
    \brief This function is called on the client side to enable the use
    of Maximum Fragment Length for SSL objects created from the SSL context
    passed in the 'ctx' parameter. It means that the Maximum Fragment Length
    extension will be sent on ClientHello by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ctx is NULL, mfl is out of range.
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param mfl indicates which is the Maximum Fragment Length requested
    for the session. The available options are:
    enum { WOLFSSL_MFL_2_9  = 1 512 bytes, WOLFSSL_MFL_2_10 = 2 1024 bytes,
           WOLFSSL_MFL_2_11 = 3 2048 bytes WOLFSSL_MFL_2_12 = 4 4096 bytes,
           WOLFSSL_MFL_2_13 = 5 8192 bytes wolfSSL ONLY!!!,
           WOLFSSL_MFL_2_13 = 6  256 bytes wolfSSL ONLY!!!
    };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, unsigned char mfl);

/*!
    \brief This function is called on the client side to enable the use of
    Truncated HMAC in the SSL object passed in the 'ssl' parameter. It
    means that the Truncated HMAC extension will be sent on ClientHello
    by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ssl is NULL
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new()

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseTruncatedHMAC(ssl);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl);

/*!
    \brief This function is called on the client side to enable the use of
    Truncated HMAC for SSL objects created from the SSL context passed in
    the 'ctx' parameter. It means that the Truncated HMAC extension will
    be sent on ClientHello by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ctx is NULL
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseTruncatedHMAC(ctx);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx);

/*!
    \brief Stapling eliminates the need to contact the CA. Stapling
    lowers the cost of certificate revocation check presented in OCSP.

    \return SSL_SUCCESS returned if TLSX_UseCertificateStatusRequest
    executes without error.
    \return MEMORY_E returned if there is an error with the allocation
    of memory.
    \return BAD_FUNC_ARG returned if there is an argument that has a
    NULL or otherwise unacceptable value passed into the function.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param status_type a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.
    \param options a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR2_OCSP,
    WOLFSSL_CSR2_OCSP_USE_NONCE) != SSL_SUCCESS){
	    // Failed case.
    }
    \endcode

    \sa TLSX_UseCertificateStatusRequest
    \sa wolfSSL_CTX_UseOCSPStapling
*/
int wolfSSL_UseOCSPStapling(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief This function requests the certificate status during the handshake.

    \return SSL_SUCCESS returned if the function and subroutines execute
    without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or
    otherwise if a unpermitted value is passed to a subroutine.
    \return MEMORY_E returned if the function or subroutine failed to properly
    allocate memory.

    \param ctx a pointer to a WOLFSSL_CTX structure,
    created using wolfSSL_CTX_new().
    \param status_type a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.
    \param options a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte statusRequest = 0; // Initialize status request
    …
    switch(statusRequest){
    	case WOLFSSL_CSR_OCSP:
    		if(wolfSSL_CTX_UseOCSPStapling(ssl->ctx, WOLFSSL_CSR_OCSP,
    WOLF_CSR_OCSP_USE_NONCE) != SSL_SUCCESS){
    // UseCertificateStatusRequest failed
    }
    // Continue switch cases
    \endcode

    \sa wolfSSL_UseOCSPStaplingV2
    \sa wolfSSL_UseOCSPStapling
    \sa TLSX_UseCertificateStatusRequest
*/
int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief The function sets the status type and options for OCSP.

    \return SSL_SUCCESS - returned if the function and subroutines
    executed without error.
    \return MEMORY_E - returned if there was an allocation of memory error.
    \return BAD_FUNC_ARG - returned if a NULL or otherwise unaccepted
    argument was passed to the function or a subroutine.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param status_type a byte type that loads the OCSP status type.
    \param options a byte type that holds the OCSP options, set in
    wolfSSL_SNI_SetOptions() and wolfSSL_CTX_SNI_SetOptions().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if (wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP_MULTI, 0) != SSL_SUCCESS){
    	// Did not execute properly. Failure case code block.
    }
    \endcode

    \sa TLSX_UseCertificatStatusRequestV2
    \sa wolfSSL_SNI_SetOptions
    \sa wolfSSL_CTX_SNI_SetOptions
*/
int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief Creates and initializes the certificate status request
    for OCSP Stapling.

    \return SSL_SUCCESS if the function and subroutines executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or if
    the side variable is not client side.
    \return MEMORY_E returned if the allocation of memory failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param status_type a byte type that is located in the
    CertificatStatusRequest structure and must be either WOLFSSL_CSR2_OCSP
    or WOLFSSL_CSR2_OCSP_MULTI.
    \param options a byte type that will be held in
    CertificateStatusRequestItemV2 struct.

    _Example_
    \code
    WOLFSSL_CTX* ctx  = wolfSSL_CTX_new( protocol method );
    byte status_type;
    byte options;
    ...
    if(wolfSSL_CTX_UseOCSPStaplingV2(ctx, status_type, options); != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode

    \sa TLSX_UseCertificateStatusRequestV2
    \sa wc_RNG_GenerateBlock
    \sa TLSX_Push
*/
int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief This function is called on the client side to enable the use of
    Supported Elliptic Curves Extension in the SSL object passed in the 'ssl'
    parameter. It means that the supported curves enabled will be sent on
    ClientHello by wolfSSL clients. This function can be called more than
    one time to enable multiple curves.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ssl is NULL, name is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param name indicates which curve will be supported for the session. The
    available options are: enum { WOLFSSL_ECC_SECP160R1 = 0x10,
    WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15,
    WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18,
    WOLFSSL_ECC_SECP521R1 = 0x19 };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSupportedCurve
*/
int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name);

/*!
    \brief This function is called on the client side to enable the use of
    Supported Elliptic Curves Extension for SSL objects created from the SSL
    context passed in the 'ctx' parameter. It means that the supported curves
    enabled will be sent on ClientHello by wolfSSL clients. This function can
    be called more than one time to enable multiple curves.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ctx is NULL, name is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param name indicates which curve will be supported for the session.
    The available options are: enum { WOLFSSL_ECC_SECP160R1 = 0x10,
    WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15,
    WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18,
    WOLFSSL_ECC_SECP521R1 = 0x19 };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSupportedCurve
*/
int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           word16 name);

/*!
    \ingroup IO

    \brief This function forces secure renegotiation for the supplied
    WOLFSSL structure.  This is not recommended.

    \return SSL_SUCCESS Successfully set secure renegotiation.
    \return BAD_FUNC_ARG Returns error if ssl is null.
    \return MEMORY_E Returns error if unable to allocate memory for secure
    renegotiation.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS)
    {
        // Error setting secure renegotiation
    }
    \endcode

    \sa TLSX_Find
    \sa TLSX_UseSecureRenegotiation
*/
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function executes a secure renegotiation handshake; this is user
    forced as wolfSSL discourages this functionality.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure was NULL or otherwise
    if an unacceptable argument was passed in a subroutine.
    \return SECURE_RENEGOTIATION_E returned if there was an error with
    renegotiating the handshake.
    \return SSL_FATAL_ERROR returned if there was an error with the
    server or client configuration and the renegotiation could
    not be completed. See wolfSSL_negotiate().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_Rehandshake(ssl) != SSL_SUCCESS){
	    // There was an error and the rehandshake is not successful.
    }
    \endcode

    \sa wolfSSL_negotiate
    \sa wc_InitSha512
    \sa wc_InitSha384
    \sa wc_InitSha256
    \sa wc_InitSha
    \sa wc_InitMd5
*/
int wolfSSL_Rehandshake(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief Force provided WOLFSSL structure to use session ticket. The
    constant HAVE_SESSION_TICKET should be defined and the constant
    NO_WOLFSSL_CLIENT should not be defined to use this function.

    \return SSL_SUCCESS Successfully set use session ticket.
    \return BAD_FUNC_ARG Returned if ssl is null.
    \return MEMORY_E Error allocating memory for setting session ticket.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSessionTicket(ssl) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode

    \sa TLSX_UseSessionTicket
*/
int wolfSSL_UseSessionTicket(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets wolfSSL context to use a session ticket.

    \return SSL_SUCCESS Function executed successfully.
    \return BAD_FUNC_ARG Returned if ctx is null.
    \return MEMORY_E Error allocating memory in internal function.

    \param ctx The WOLFSSL_CTX structure to use.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL_METHOD method = // Some wolfSSL method ;
    ctx = wolfSSL_CTX_new(method);

    if(wolfSSL_CTX_UseSessionTicket(ctx) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode

    \sa TLSX_UseSessionTicket
*/
int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief This function copies the ticket member of the Session structure to
    the buffer. If buf is NULL and bufSz is non-NULL, bufSz will be set to the
    ticket length.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if ssl or bufSz is NULL, or if bufSz
    is non-NULL and buf is NULL


    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a byte pointer representing the memory buffer.
    \param bufSz a word32 pointer representing the buffer size.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buf;
    word32 bufSz;  // Initialize with buf size
    …
    if(wolfSSL_get_SessionTicket(ssl, buf, bufSz) <= 0){
	    // Nothing was written to the buffer
    } else {
	    // the buffer holds the content from ssl->session->ticket
    }
    \endcode

    \sa wolfSSL_UseSessionTicket
    \sa wolfSSL_set_SessionTicket
*/
int wolfSSL_get_SessionTicket(WOLFSSL* ssl, unsigned char* buf, word32* bufSz);

/*!
    \ingroup IO

    \brief This function sets the ticket member of the WOLFSSL_SESSION
    structure within the WOLFSSL struct. The buffer passed into the function
    is copied to memory.

    \return SSL_SUCCESS returned on successful execution of the function.
    The function returned without errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL. This will
    also be thrown if the buf argument is NULL but the bufSz argument
    is not zero.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a byte pointer that gets loaded into the ticket member
    of the session structure.
    \param bufSz a word32 type that represents the size of the buffer.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buffer; // File to load
    word32 bufSz;
    ...
    if(wolfSSL_KeepArrays(ssl, buffer, bufSz) != SSL_SUCCESS){
    	// There was an error loading the buffer to memory.
    }
    \endcode

    \sa wolfSSL_set_SessionTicket_cb
*/
int wolfSSL_set_SessionTicket(WOLFSSL* ssl, const unsigned char* buf,
                              word32 bufSz);

/*!
    \brief This function sets the session ticket callback. The type
    CallbackSessionTicket is a function pointer with the signature of:
    int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*)

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to the type CallbackSessionTicket.
    \param ctx a void pointer to the session_ticket_ctx member of the
    WOLFSSL structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int sessionTicketCB(WOLFSSL* ssl, const unsigned char* ticket, int ticketSz,
				void* ctx){ … }
    wolfSSL_set_SessionTicket_cb(ssl, sessionTicketCB, (void*)”initial session”);
    \endcode

    \sa wolfSSL_get_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
*/
int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                 CallbackSessionTicket cb, void* ctx);

/*!
    \brief This function sends a session ticket to the client after a TLS v1.3
    handhsake has been established.

    \return WOLFSSL_SUCCESS returned if a new session ticket was sent.
    \return BAD_FUNC_ARG returned if WOLFSSL structure is NULL, or not using
    TLS v1.3.
    \return SIDE_ERROR returned if not a server.
    \return NOT_READY_ERROR returned if the handshake has not completed.
    \return WOLFSSL_FATAL_ERROR returned if creating or sending message fails.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    ret = wolfSSL_send_SessionTicket(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // New session ticket not sent.
    }
    \endcode

    \sa wolfSSL_get_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
 */
int wolfSSL_send_SessionTicket(WOLFSSL* ssl);

/*!
    \brief This function sets the session ticket key encrypt callback function
    for a server to support session tickets as specified in RFC 5077.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure. This is caused by passing
    invalid arguments to the function.

    \param ctx pointer to the WOLFSSL_CTX object, created with wolfSSL_CTX_new().
    \param cb user callback function to encrypt/decrypt session tickets
    \param ssl(Callback) pointer to the WOLFSSL object, created with
    wolfSSL_new()
    \param key_name(Callback) unique key name for this ticket context, should
    be randomly generated
    \param iv(Callback) unique IV for this ticket, up to 128 bits, should
    be randomly generated
    \param mac(Callback) up to 256 bit mac for this ticket
    \param enc(Callback) if this encrypt parameter is true the user should fill
    in key_name, iv, mac, and encrypt the ticket in-place of length inLen and
    set the resulting output length in *outLen.  Returning WOLFSSL_TICKET_RET_OK
    tells wolfSSL that the encryption was successful. If this encrypt parameter
    is false, the user should perform a decrypt of the ticket in-place of length
    inLen using key_name, iv, and mac. The resulting decrypt length should be
    set in *outLen. Returning WOLFSSL_TICKET_RET_OK tells wolfSSL to proceed
    using the decrypted ticket. Returning WOLFSSL_TICKET_RET_CREATE tells
    wolfSSL to use the decrypted ticket but also to generate a new one to
    send to the client, helpful if recently rolled keys and don’t want to
    force a full handshake.  Returning WOLFSSL_TICKET_RET_REJECT tells
    wolfSSL to reject this ticket, perform a full handshake, and create
    a new standard session ID for normal session resumption. Returning
    WOLFSSL_TICKET_RET_FATAL tells wolfSSL to end the connection
    attempt with a fatal error.
    \param ticket(Callback) the input/output buffer for the encrypted ticket.
    See the enc parameter
    \param inLen(Callback) the input length of the ticket parameter
    \param outLen(Callback) the resulting output length of the ticket parameter.
    When entering the callback outLen will indicate the maximum size available
    in the ticket buffer.
    \param userCtx(Callback) the user context set with
    wolfSSL_CTX_set_TicketEncCtx()

    _Example_
    \code
    See wolfssl/test.h myTicketEncCb() used by the example
    server and example echoserver.
    \endcode

    \sa wolfSSL_CTX_set_TicketHint
    \sa wolfSSL_CTX_set_TicketEncCtx
*/
int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb);

/*!
    \brief This function sets the session ticket hint relayed to the client.
    For server side use.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure.  This is caused by passing
    invalid arguments to the function.

    \param ctx pointer to the WOLFSSL_CTX object, created with wolfSSL_CTX_new().
    \param hint number of seconds the ticket might be valid for.  Hint to client.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCb
*/
int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int);

/*!
    \brief This function sets the session ticket encrypt user context for the
    callback.  For server side use.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure.  This is caused by
    passing invalid arguments to the function.

    \param ctx pointer to the WOLFSSL_CTX object, created
    with wolfSSL_CTX_new().
    \param userCtx the user context for the callback

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCb
*/
int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void*);

/*!
    \brief This function gets the session ticket encrypt user context for the
    callback.  For server side use.

    \return userCtx will be returned upon successfully getting the session.
    \return NULL will be returned on failure.  This is caused by
    passing invalid arguments to the function, or when the user context has
    not been set.

    \param ctx pointer to the WOLFSSL_CTX object, created
    with wolfSSL_CTX_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCtx
*/
void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx);

/*!
    \brief This function sets the handshake done callback. The hsDoneCb and
    hsDoneCtx members of the WOLFSSL structure are set in this function.

    \return SSL_SUCCESS returned if the function executed without an error.
    The hsDoneCb and hsDoneCtx members of the WOLFSSL struct are set.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer of type HandShakeDoneCb with the signature of
    the form: int (*HandShakeDoneCb)(WOLFSSL*, void*);
    \param user_ctx a void pointer to the user registered context.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int myHsDoneCb(WOLFSSL* ssl, void* user_ctx){
        // callback function
    }
    …
    wolfSSL_SetHsDoneCb(ssl, myHsDoneCb, NULL);
    \endcode

    \sa HandShakeDoneCb
*/
int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx);

/*!
    \ingroup IO

    \brief This function prints the statistics from the session.

    \return SSL_SUCCESS returned if the function and subroutines return without
    error. The session stats have been successfully retrieved and printed.
    \return BAD_FUNC_ARG returned if the subroutine wolfSSL_get_session_stats()
    was passed an unacceptable argument.
    \return BAD_MUTEX_E returned if there was a mutex error in the subroutine.

    \param none No parameters.

    _Example_
    \code
    // You will need to have a session object to retrieve stats from.
    if(wolfSSL_PrintSessionStats(void) != SSL_SUCCESS	){
        // Did not print session stats
    }

    \endcode

    \sa wolfSSL_get_session_stats
*/
int wolfSSL_PrintSessionStats(void);

/*!
    \ingroup IO

    \brief This function gets the statistics for the session.

    \return SSL_SUCCESS returned if the function and subroutines return without
    error. The session stats have been successfully retrieved and printed.
    \return BAD_FUNC_ARG returned if the subroutine wolfSSL_get_session_stats()
    was passed an unacceptable argument.
    \return BAD_MUTEX_E returned if there was a mutex error in the subroutine.

    \param active a word32 pointer representing the total current sessions.
    \param total a word32 pointer representing the total sessions.
    \param peak a word32 pointer representing the peak sessions.
    \param maxSessions a word32 pointer representing the maximum sessions.

    _Example_
    \code
    int wolfSSL_PrintSessionStats(void){
    …
    ret = wolfSSL_get_session_stats(&totalSessionsNow,
    &totalSessionsSeen, &peak, &maxSessions);
    …
    return ret;
    \endcode

    \sa wolfSSL_PrintSessionStats
*/
int wolfSSL_get_session_stats(unsigned int* active,
                                          unsigned int* total,
                                          unsigned int* peak,
                                          unsigned int* maxSessions);

/*!
    \ingroup TLS

    \brief This function copies the values of cr and sr then passes through to
    wc_PRF (pseudo random function) and returns that value.

    \return 0 on success
    \return BUFFER_E returned if there will be an error
    with the size of the buffer.
    \return MEMORY_E returned if a subroutine failed
    to allocate dynamic memory.

    \param ms the master secret held in the Arrays structure.
    \param msLen the length of the master secret.
    \param pms the pre-master secret held in the Arrays structure.
    \param pmsLen the length of the pre-master secret.
    \param cr the client random.
    \param sr the server random.
    \param tls1_2 signifies that the version is at least tls version 1.2.
    \param hash_type signifies the hash type.

    _Example_
    \code
    WOLFSSL* ssl;

    called in MakeTlsMasterSecret and retrieves the necessary
    information as follows:

    int MakeTlsMasterSecret(WOLFSSL* ssl){
	int ret;
	ret = wolfSSL_makeTlsMasterSecret(ssl->arrays->masterSecret, SECRET_LEN,
    ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
    ssl->arrays->clientRandom, ssl->arrays->serverRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    return ret;

    }
    \endcode

    \sa wc_PRF
    \sa MakeTlsMasterSecret
*/

int wolfSSL_MakeTlsMasterSecret(unsigned char* ms, word32 msLen,
                               const unsigned char* pms, word32 pmsLen,
                               const unsigned char* cr, const unsigned char* sr,
                               int tls1_2, int hash_type);

/*!
    \ingroup CertsKeys

    \brief An external facing wrapper to derive TLS Keys.

    \return 0 returned on success.
    \return BUFFER_E returned if the sum of labLen and
    seedLen (computes total size) exceeds the maximum size.
    \return MEMORY_E returned if the allocation of memory failed.

    \param key_data a byte pointer that is allocateded in DeriveTlsKeys
    and passed through to wc_PRF to hold the final hash.
    \param keyLen a word32 type that is derived in DeriveTlsKeys
    from the WOLFSSL structure’s specs member.
    \param ms a constant pointer type holding the master secret
    held in the arrays structure within the WOLFSSL structure.
    \param msLen a word32 type that holds the length of the
    master secret in an enumerated define, SECRET_LEN.
    \param sr a constant byte pointer to the serverRandom
    member of the arrays structure within the WOLFSSL structure.
    \param cr a constant byte pointer to the clientRandom
    member of the arrays structure within the WOLFSSL structure.
    \param tls1_2 an integer type returned from IsAtLeastTLSv1_2().
    \param hash_type an integer type held in the WOLFSSL structure.

    _Example_
    \code
    int DeriveTlsKeys(WOLFSSL* ssl){
    int ret;
    …
    ret = wolfSSL_DeriveTlsKeys(key_data, length, ssl->arrays->masterSecret,
    SECRET_LEN, ssl->arrays->clientRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    }
    \endcode

    \sa wc_PRF
    \sa DeriveTlsKeys
    \sa IsAtLeastTLSv1_2
*/

int wolfSSL_DeriveTlsKeys(unsigned char* key_data, word32 keyLen,
                               const unsigned char* ms, word32 msLen,
                               const unsigned char* sr, const unsigned char* cr,
                               int tls1_2, int hash_type);

/*!
    \brief wolfSSL_connect_ex() is an extension that allows
    a HandShake Callback to be set. This can be useful in
    embedded systems for debugging support when a debugger isn’t
    available and sniffing is impractical. The HandShake Callback
    will be called whether or not a handshake error occurred.
    No dynamic memory is used since the maximum number of SSL
    packets is known.  Packet names can be accessed through packetNames[].
    The connect extension also allows a Timeout Callback to be set along
    with a timeout value.  This is useful if the user doesn’t want
    to wait for the TCP stack to timeout. This extension can be called
    with either, both, or neither callbacks.

    \return SSL_SUCCESS upon success.
    \return GETTIME_ERROR will be returned if gettimeofday()
    encountered an error.
    \return SETITIMER_ERROR will be returned if setitimer()
    encountered an error.
    \return SIGACT_ERROR will be returned if sigaction() encountered an error.
    \return SSL_FATAL_ERROR will be returned if the underlying SSL_connect()
    call encountered an error.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_accept_ex
*/
int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                       TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

/*!
    \brief wolfSSL_accept_ex() is an extension that allows a HandShake Callback
    to be set. This can be useful in embedded systems for debugging support
    when a debugger isn’t available and sniffing is impractical. The HandShake
    Callback will be called whether or not a handshake error occurred.
    No dynamic memory is used since the maximum number of SSL packets is known.
    Packet names can be accessed through packetNames[]. The connect extension
    also allows a Timeout Callback to be set along with a timeout value.
    This is useful if the user doesn’t want to wait for the TCP stack to timeout.
    This extension can be called with either, both, or neither callbacks.

    \return SSL_SUCCESS upon success.
    \return GETTIME_ERROR will be returned if gettimeofday()
    encountered an error.
    \return SETITIMER_ERROR will be returned if setitimer()
    encountered an error.
    \return SIGACT_ERROR will be returned if sigaction() encountered an error.
    \return SSL_FATAL_ERROR will be returned if the underlying
    SSL_accept() call encountered an error.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_connect_ex
*/
int wolfSSL_accept_ex(WOLFSSL* ssl, HandShakeCallBacki hsCb,
                      TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

/*!
    \ingroup IO

    \brief This is used to set the internal file pointer for a BIO.

    \return SSL_SUCCESS On successfully setting file pointer.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set pair.
    \param fp file pointer to set in bio.
    \param c close file behavior flag.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, fp, BIO_CLOSE);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_get_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c);

/*!
    \ingroup IO

    \brief This is used to get the internal file pointer for a BIO.

    \return SSL_SUCCESS On successfully getting file pointer.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set pair.
    \param fp file pointer to set in bio.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_get_fp(bio, &fp);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp);

/*!
    \ingroup Setup

    \brief This function checks that the private key is a match
    with the certificate being used.

    \return SSL_SUCCESS On successfully match.
    \return SSL_FAILURE If an error case was encountered.
    \return <0 All error cases other than SSL_FAILURE are negative values.

    \param ssl WOLFSSL structure to check.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create and set up ssl
    ret  = wolfSSL_check_private_key(ssl);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_check_private_key(const WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief This function looks for and returns the extension index
    matching the passed in NID value.

    \return >= 0 If successful the extension index is returned.
    \return -1 If extension is not found or error is encountered.

    \param x509 certificate to get parse through for extension.
    \param nid extension OID to be found.
    \param lastPos start search from extension after lastPos.
                   Set to -1 initially.

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int lastPos = -1;
    int idx;

    idx = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints, lastPos);
    \endcode

*/
int wolfSSL_X509_get_ext_by_NID(const WOLFSSL_X509* x509,
                                             int nid, int lastPos);

/*!
    \ingroup CertsKeys

    \brief This function looks for and returns the extension
    matching the passed in NID value.

    \return pointer If successful a STACK_OF(WOLFSSL_ASN1_OBJECT)
    pointer is returned.
    \return NULL If extension is not found or error is encountered.

    \param x509 certificate to get parse through for extension.
    \param nid extension OID to be found.
    \param c if not NULL is set to -2 for multiple extensions found -1
    if not found, 0 if found and not critical and 1 if found and critical.
    \param idx if NULL return first extension matched otherwise if not
    stored in x509 start at idx.

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int c;
    int idx = 0;
    STACK_OF(WOLFSSL_ASN1_OBJECT)* sk;

    sk = wolfSSL_X509_get_ext_d2i(x509, NID_basic_constraints, &c, &idx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode

    \sa wolfSSL_sk_ASN1_OBJECT_free
*/
void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509,
                                                     int nid, int* c, int* idx);

/*!
    \ingroup CertsKeys

    \brief This function returns the hash of the DER certificate.

    \return SSL_SUCCESS On successfully creating a hash.
    \return SSL_FAILURE Returned on bad input or unsuccessful hash.

    \param x509 certificate to get the hash of.
    \param digest the hash algorithm to use.
    \param buf buffer to hold hash.
    \param len length of buffer.

    _Example_
    \code
    WOLFSSL_X509* x509;
    unsigned char buffer[64];
    unsigned int bufferSz;
    int ret;

    ret = wolfSSL_X509_digest(x509, wolfSSL_EVP_sha256(), buffer, &bufferSz);
    //check ret value
    \endcode

    \sa none
*/
int wolfSSL_X509_digest(const WOLFSSL_X509* x509,
        const WOLFSSL_EVP_MD* digest, unsigned char* buf, unsigned int* len);

/*!
    \ingroup Setup

    \brief his is used to set the certificate for WOLFSSL structure to use
    during a handshake.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL argument passed in.

    \param ssl WOLFSSL structure to set certificate in.
    \param x509 certificate to use.

    _Example_
    \code WOLFSSL* ssl;
    WOLFSSL_X509* x509
    int ret;
    // create ssl object and x509
    ret  = wolfSSL_use_certificate(ssl, x509);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief This is used to set the certificate for WOLFSSL structure
    to use during a handshake. A DER formatted buffer is expected.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL argument passed in.

    \param ssl WOLFSSL structure to set certificate in.
    \param der DER certificate to use.
    \param derSz size of the DER buffer passed in.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* der;
    int derSz;
    int ret;
    // create ssl object and set DER variables
    ret  = wolfSSL_use_certificate_ASN1(ssl, der, derSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                     int derSz);

/*!
    \ingroup CertsKeys

    \brief This is used to set the private key for the WOLFSSL structure.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL ssl passed in. All error
    cases will be negative values.

    \param ssl WOLFSSL structure to set argument in.
    \param pkey private key to use.

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_EVP_PKEY* pkey;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey(ssl, pkey);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_PrivateKey(WOLFSSL* ssl, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief This is used to set the private key for the WOLFSSL
    structure. A DER formatted key buffer is expected.

    \return SSL_SUCCESS On successful setting parsing and
    setting the private key.
    \return SSL_FAILURE If an NULL ssl passed in. All error cases
    will be negative values.

    \param pri type of private key.
    \param ssl WOLFSSL structure to set argument in.
    \param der buffer holding DER key.
    \param derSz size of der buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey_ASN1(1, ssl, pkey, pkeySz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_PrivateKey_ASN1(int pri, WOLFSSL* ssl,
                                            unsigned char* der, long derSz);

/*!
    \ingroup CertsKeys

    \brief This is used to set the private key for the WOLFSSL
    structure. A DER formatted RSA key buffer is expected.

    \return SSL_SUCCESS On successful setting parsing and setting
    the private key.
    \return SSL_FAILURE If an NULL ssl passed in. All error cases
    will be negative values.

    \param ssl WOLFSSL structure to set argument in.
    \param der buffer holding DER key.
    \param derSz size of der buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up RSA private key
    ret  = wolfSSL_use_RSAPrivateKey_ASN1(ssl, pkey, pkeySz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_RSAPrivateKey_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                long derSz);

/*!
    \ingroup CertsKeys

    \brief This function duplicates the parameters in dsa to a
    newly created WOLFSSL_DH structure.

    \return WOLFSSL_DH If duplicated returns WOLFSSL_DH structure
    \return NULL upon failure

    \param dsa WOLFSSL_DSA structure to duplicate.

    _Example_
    \code
    WOLFSSL_DH* dh;
    WOLFSSL_DSA* dsa;
    // set up dsa
    dh = wolfSSL_DSA_dup_DH(dsa);

    // check dh is not null
    \endcode

    \sa none
*/
WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *r);

/*!
    \ingroup Setup

    \brief This is used to get the master key after completing a handshake.

    \return >0 On successfully getting data returns a value greater than 0
    \return 0  If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer
    size needed is returned

    \param ses WOLFSSL_SESSION structure to get master secret buffer from.
    \param out buffer to hold data.
    \param outSz size of out buffer passed in. (if 0 function will
    return max buffer size needed)

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret(ses, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_SESSION_get_master_secret(ses, buffer, bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key(const WOLFSSL_SESSION* ses,
        unsigned char* out, int outSz);

/*!
    \ingroup Setup

    \brief This is used to get the master secret key length.

    \return size Returns master secret key size.

    \param ses WOLFSSL_SESSION structure to get master secret buffer from.

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret_length(ses);
    buffer = malloc(bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key_length(const WOLFSSL_SESSION* ses);

/*!
    \ingroup Setup

    \brief This is a setter function for the WOLFSSL_X509_STORE
    structure in ctx.

    \return none No return.

    \param ctx pointer to the WOLFSSL_CTX structure for setting
    cert store pointer.
    \param str pointer to the WOLFSSL_X509_STORE to set in ctx.

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx and st
    st = wolfSSL_CTX_set_cert_store(ctx, st);
    //use st
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);

/*!
    \ingroup CertsKeys

    \brief This function get the DER buffer from bio and converts it
    to a WOLFSSL_X509 structure.

    \return pointer returns a WOLFSSL_X509 structure pointer on success.
    \return Null returns NULL on failure

    \param bio pointer to the WOLFSSL_BIO structure that has the DER
    certificate buffer.
    \param x509 pointer that get set to new WOLFSSL_X509 structure created.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // load DER into bio
    x509 = wolfSSL_d2i_X509_bio(bio, NULL);
    Or
    wolfSSL_d2i_X509_bio(bio, &x509);
    // use x509 returned (check for NULL)
    \endcode

    \sa none
*/
WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509** x509);

/*!
    \ingroup Setup

    \brief This is a getter function for the WOLFSSL_X509_STORE
    structure in ctx.

    \return WOLFSSL_X509_STORE* On successfully getting the pointer.
    \return NULL Returned if NULL arguments are passed in.

    \param ctx pointer to the WOLFSSL_CTX structure for getting cert
    store pointer.

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx
    st = wolfSSL_CTX_get_cert_store(ctx);
    //use st
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_cert_store
*/
WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief Gets the number of pending bytes to read. If BIO type is BIO_BIO
    then is the number to read from pair. If BIO contains an SSL object then
    is pending data from SSL object (wolfSSL_pending(ssl)). If is BIO_MEMORY
    type then returns the size of memory buffer.

    \return >=0 number of pending bytes.

    \param bio pointer to the WOLFSSL_BIO structure that has already
    been created.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int pending;
    bio = wolfSSL_BIO_new();
    …
    pending = wolfSSL_BIO_ctrl_pending(bio);
    \endcode

    \sa wolfSSL_BIO_make_bio_pair
    \sa wolfSSL_BIO_new
*/
size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *b);

/*!
    \ingroup Setup

    \brief This is used to get the random data sent by the server
    during the handshake.

    \return >0 On successfully getting data returns a value greater than 0
    \return 0  If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer size
    needed is returned

    \param ssl WOLFSSL structure to get clients random data buffer from.
    \param out buffer to hold random data.
    \param outSz size of out buffer passed in. (if 0 function will return max
    buffer size needed)

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_server_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_server_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_server_random(const WOLFSSL *ssl,
                                             unsigned char *out, size_t outlen);

/*!
    \ingroup Setup

    \brief This is used to get the random data sent by the client during
    the handshake.

    \return >0 On successfully getting data returns a value greater than 0
    \return 0 If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer size needed
    is returned

    \param ssl WOLFSSL structure to get clients random data buffer from.
    \param out buffer to hold random data.
    \param outSz size of out buffer passed in. (if 0 function will return max
    buffer size needed)

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_client_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_client_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_client_random(const WOLFSSL* ssl,
                                              unsigned char* out, size_t outSz);

/*!
    \ingroup Setup

    \brief This is a getter function for the password callback set in ctx.

    \return func On success returns the callback function.
    \return NULL If ctx is NULL then NULL is returned.

    \param ctx WOLFSSL_CTX structure to get call back from.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    wc_pem_password_cb cb;
    // setup ctx
    cb = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use cb
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX*
                                                                  ctx);

/*!
    \ingroup Setup

    \brief This is a getter function for the password callback user
    data set in ctx.

    \return pointer On success returns the user data pointer.
    \return NULL If ctx is NULL then NULL is returned.

    \param ctx WOLFSSL_CTX structure to get user data from.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    // setup ctx
    data = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use data
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void *wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx);

/*!
    \ingroup CertsKeys

    \brief This function behaves the same as wolfSSL_PEM_read_bio_X509.
    AUX signifies containing extra information such as trusted/rejected use
    cases and friendly name for human readability.

    \return WOLFSSL_X509 on successfully parsing the PEM buffer a WOLFSSL_X509
    structure is returned.
    \return Null if failed to parse PEM buffer.

    \param bp WOLFSSL_BIO structure to get PEM buffer from.
    \param x if setting WOLFSSL_X509 by function side effect.
    \param cb password callback.
    \param u NULL terminated user password.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // setup bio
    X509 = wolfSSL_PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    //check x509 is not null and then use it
    \endcode

    \sa wolfSSL_PEM_read_bio_X509
*/
WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_AUX
        (WOLFSSL_BIO *bp, WOLFSSL_X509 **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup CertsKeys

    \brief Initializes the WOLFSSL_CTX structure’s dh member with the
    Diffie-Hellman parameters.

    \return SSL_SUCCESS returned if the function executed successfully.
    \return BAD_FUNC_ARG returned if the ctx or dh structures are NULL.
    \return SSL_FATAL_ERROR returned if there was an error setting a
    structure value.
    \return MEMORY_E returned if their was a failure to allocate memory.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param dh a pointer to a WOLFSSL_DH structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL_DH* dh;
    …
    return wolfSSL_CTX_set_tmp_dh(ctx, dh);
    \endcode

    \sa wolfSSL_BN_bn2bin
*/
long wolfSSL_CTX_set_tmp_dh(WOLFSSL_CTX* ctx, WOLFSSL_DH* dh);

/*!
    \ingroup CertsKeys

    \brief This function get the DSA parameters from a PEM buffer in bio.

    \return WOLFSSL_DSA on successfully parsing the PEM buffer a WOLFSSL_DSA
    structure is created and returned.
    \return Null if failed to parse PEM buffer.

    \param bio pointer to the WOLFSSL_BIO structure for getting PEM
    memory pointer.
    \param x pointer to be set to new WOLFSSL_DSA structure.
    \param cb password callback function.
    \param u null terminated password string.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_DSA* dsa;
    // setup bio
    dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL);

    // check dsa is not NULL and then use dsa
    \endcode

    \sa none
*/
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp,
    WOLFSSL_DSA **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup Debug

    \brief This function returns the absolute value of the last error from
    WOLFSSL_ERROR encountered.

    \return error Returns absolute value of last error.

    \param none No parameters.

    _Example_
    \code
    unsigned long err;
    ...
    err = wolfSSL_ERR_peek_last_error();
    // inspect err value
    \endcode

    \sa wolfSSL_ERR_print_errors_fp
*/
unsigned long wolfSSL_ERR_peek_last_error(void);

/*!
    \ingroup CertsKeys

    \brief This function gets the peer’s certificate chain.

    \return pointer returns a pointer to the peer’s Certificate stack.
    \return NULL returned if no peer certificate.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    wolfSSL_connect(ssl);
    STACK_OF(WOLFSSL_X509)* chain = wolfSSL_get_peer_cert_chain(ssl);
    ifchain){
	    // You have a pointer to the peer certificate chain
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL*);

/*!
    \ingroup Setup

    \brief This function resets option bits of WOLFSSL_CTX object.

    \return option new option bits

    \param ctx pointer to the SSL context.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_CTX_clear_options(WOLFSSL_CTX* ctx, long opt);

/*!
    \ingroup IO

    \brief This function sets the jObjectRef member of the WOLFSSL structure.

    \return SSL_SUCCESS returned if jObjectRef is properly set to objPtr.
    \return SSL_FAILURE returned if the function did not properly execute and
    jObjectRef is not set.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param objPtr a void pointer that will be set to jObjectRef.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new();
    void* objPtr = &obj;
    ...
    if(wolfSSL_set_jobject(ssl, objPtr)){
    	// The success case
    }
    \endcode

    \sa wolfSSL_get_jobject
*/
int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr);

/*!
    \ingroup IO

    \brief This function returns the jObjectRef member of the WOLFSSL structure.

    \return value If the WOLFSSL struct is not NULL, the function returns the
    jObjectRef value.
    \return NULL returned if the WOLFSSL struct is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL(ctx);
    ...
    void* jobject = wolfSSL_get_jobject(ssl);

    if(jobject != NULL){
    	// Success case
    }
    \endcode

    \sa wolfSSL_set_jobject
*/
void* wolfSSL_get_jobject(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets a callback in the ssl. The callback is to
    observe handshake messages. NULL value of cb resets the callback.

    \return SSL_SUCCESS On success.
    \return SSL_FAILURE If an NULL ssl passed in.

    \param ssl WOLFSSL structure to set callback argument.

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    \endcode

    \sa wolfSSL_set_msg_callback_arg
*/
int wolfSSL_set_msg_callback(WOLFSSL *ssl, SSL_Msg_Cb cb);

/*!
    \ingroup Setup

    \brief This function sets associated callback context value in the ssl.
    The value is handed over to the callback argument.

    \return none No return.

    \param ssl WOLFSSL structure to set callback argument.

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    wolfSSL_set_msg_callback(ssl, arg);
    \endcode

    \sa wolfSSL_set_msg_callback
*/
int wolfSSL_set_msg_callback_arg(WOLFSSL *ssl, void* arg);

/*!
    \ingroup CertsKeys

    \brief This function returns the next, if any, altname from the peer certificate.

    \return NULL if there is not a next altname.
    \return cert->altNamesNext->name from the WOLFSSL_X509 structure that is a
    string value from the altName list is returned if it exists.

    \param cert a pointer to the wolfSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
                                                        DYNAMIC_TYPE_X509);
    …
    int x509NextAltName = wolfSSL_X509_get_next_altname(x509);
    if(x509NextAltName == NULL){
            //There isn’t another alt name
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
char* wolfSSL_X509_get_next_altname(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief The function checks to see if x509 is NULL and if it’s not, it
    returns the notBefore member of the x509 struct.

    \return pointer to struct with ASN1_TIME to the notBefore
        member of the x509 struct.
    \return NULL the function returns NULL if the x509 structure is NULL.

    \param x509 a pointer to the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    …
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notBefore(x509);
    if(notAfter == NULL){
            //The x509 object was NULL
    }
    \endcode

    \sa wolfSSL_X509_get_notAfter
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(WOLFSSL_X509*);

/*!
    \ingroup IO

    \brief This function is called on the client side and initiates an SSL/TLS
    handshake with a server.  When this function is called, the underlying
    communication channel has already been set up.
    wolfSSL_connect() works with both blocking and non-blocking I/O.  When the
    underlying I/O is non-blocking, wolfSSL_connect() will return when the
    underlying I/O could not satisfy the needs of wolfSSL_connect to continue
    the handshake.  In this case, a call to wolfSSL_get_error() will yield
    either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process
    must then repeat the call to wolfSSL_connect() when the underlying I/O is
    ready and wolfSSL will pick up where it left off. When using a non-blocking
    socket, nothing needs to be done, but select() can be used to check for the
    required condition.
    If the underlying I/O is blocking, wolfSSL_connect() will only return once
    the handshake has been finished or an error occurred.
    wolfSSL takes a different approach to certificate verification than OpenSSL
    does.  The default policy for the client is to verify the server, this
    means that if you don't load CAs to verify the server you'll get a connect
    error, unable to verify (-155).  It you want to mimic OpenSSL behavior of
    having SSL_connect succeed even if verifying the server fails and reducing
    security you can do this by calling:
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); before calling SSL_new();
    Though it's not recommended.

    \return SSL_SUCCESS If successful.
    \return SSL_FATAL_ERROR will be returned if an error occurred.  To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
    err = wolfSSL_get_error(ssl, ret);
    printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_accept
*/
int  wolfSSL_connect(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is called on the server side to indicate that a
    HelloRetryRequest message must contain a Cookie and, in case of using
    protocol DTLS v1.3, that the handshake will always include a cookie
    exchange. Please note that when using protocol DTLS v1.3, the cookie
    exchange is enabled by default. The Cookie holds a hash of the current
    transcript so that another server process can handle the ClientHello in
    reply.  The secret is used when generating the integrity check on the Cookie
    data.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] secret a pointer to a buffer holding the secret.
    Passing NULL indicates to generate a new random secret.
    \param [in] secretSz Size of the secret in bytes.
    Passing 0 indicates to use the default size: WC_SHA256_DIGEST_SIZE (or WC_SHA_DIGEST_SIZE when SHA-256 not available).

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a client.
    \return WOLFSSL_SUCCESS if successful.
    \return MEMORY_ERROR if allocating dynamic memory for storing secret failed.
    \return Another -ve value on internal error.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    char secret[32];
    ...
    ret = wolfSSL__send_hrr_cookie(ssl, secret, sizeof(secret));
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set use of Cookie and secret
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_disable_hrr_cookie
*/
int  wolfSSL_send_hrr_cookie(WOLFSSL* ssl,
    const unsigned char* secret, unsigned int secretSz);

/*!

    \ingroup Setup

    \brief This function is called on the server side to indicate that a
    HelloRetryRequest message must NOT contain a Cookie and that, if using
    protocol DTLS v1.3, a cookie exchange will not be included in the
    handshake. Please note that not doing a cookie exchange when using protocol
    DTLS v1.3 can make the server susceptible to DoS/Amplification attacks.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return WOLFSSL_SUCCESS if successful
    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3
    \return SIDE_ERROR if invoked on client

    \sa wolfSSL_send_hrr_cookie
*/
int wolfSSL_disable_hrr_cookie(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is called on the server to stop it from sending
    a resumption session ticket once the handshake is complete.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a client.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_ticket_TLSv13(ctx);
    if (ret != 0) {
        // failed to set no ticket
    }
    \endcode

    \sa wolfSSL_no_ticket_TLSv13
*/
int  wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is called on the server to stop it from sending
    a resumption session ticket once the handshake is complete.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a client.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_ticket_TLSv13(ssl);
    if (ret != 0) {
        // failed to set no ticket
    }
    \endcode

    \sa wolfSSL_CTX_no_ticket_TLSv13
*/
int  wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 wolfSSL context to disallow
    Diffie-Hellman (DH) style key exchanges when handshakes are using
    pre-shared keys for authentication.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_dhe_psk(ctx);
    if (ret != 0) {
        // failed to set no DHE for PSK handshakes
    }
    \endcode

    \sa wolfSSL_no_dhe_psk
*/
int  wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 client or server wolfSSL to
    disallow Diffie-Hellman (DH) style key exchanges when handshakes are using
    pre-shared keys for authentication.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_dhe_psk(ssl);
    if (ret != 0) {
        // failed to set no DHE for PSK handshakes
    }
    \endcode

    \sa wolfSSL_CTX_no_dhe_psk
*/
int  wolfSSL_no_dhe_psk(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function is called on a TLS v1.3 client or server wolfSSL to
    force the rollover of keys. A KeyUpdate message is sent to the peer and
    new keys are calculated for encryption. The peer will send back a KeyUpdate
    message and the new decryption keys will then be calculated.
    This function can only be called after a handshake has been completed.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return WANT_WRITE if the writing is not ready.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_update_keys(ssl);
    if (ret == WANT_WRITE) {
        // need to call again when I/O ready
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // failed to send key update
    }
    \endcode

    \sa wolfSSL_write
*/
int  wolfSSL_update_keys(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function is called on a TLS v1.3 client or server wolfSSL to
    determine whether a rollover of keys is in progress. When
    wolfSSL_update_keys() is called, a KeyUpdate message is sent and the
    encryption key is updated. The decryption key is updated when the response
    is received.

    \param [in] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [out] required   0 when no key update response required. 1 when no key update response required.

    \return 0 on successful.
    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int required;
    ...
    ret = wolfSSL_key_update_response(ssl, &required);
    if (ret != 0) {
        // bad parameters
    }
    if (required) {
        // encrypt Key updated, awaiting response to change decrypt key
    }
    \endcode

    \sa wolfSSL_update_keys
*/
int  wolfSSL_key_update_response(WOLFSSL* ssl, int* required);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 client wolfSSL context to allow
    a client certificate to be sent post handshake upon request from server.
    This is useful when connecting to a web server that has some pages that
    require client authentication and others that don't.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a server.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ctx);
    if (ret != 0) {
        // failed to allow post handshake authentication
    }
    \endcode

    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_CTX_allow_post_handshake_auth(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 client wolfSSL to allow
    a client certificate to be sent post handshake upon request from server.
    A Post-Handshake Client Authentication extension is sent in the ClientHello.
    This is useful when connecting to a web server that has some pages that
    require client authentication and others that don't.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a server.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ssl);
    if (ret != 0) {
        // failed to allow post handshake authentication
    }
    \endcode

    \sa wolfSSL_CTX_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_allow_post_handshake_auth(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function requests a client certificate from the TLS v1.3 client.
    This is useful when a web server is serving some pages that require client
    authentication and others that don't.
    A maximum of 256 requests can be sent on a connection.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return WANT_WRITE if the writing is not ready.
    \return SIDE_ERROR if called with a client.
    \return NOT_READY_ERROR if called when the handshake is not finished.
    \return POST_HAND_AUTH_ERROR if posthandshake authentication is disallowed.
    \return MEMORY_E if dynamic memory allocation fails.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_request_certificate(ssl);
    if (ret == WANT_WRITE) {
        // need to call again when I/O ready
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // failed to request a client certificate
    }
    \endcode

    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_write
*/
int  wolfSSL_request_certificate(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the list of elliptic curve groups to allow on
    a wolfSSL context in order of preference.
    The list is a null-terminated text string, and a colon-delimited list.
    Call this function to set the key exchange elliptic curve parameters to
    use with the TLS v1.3 connections.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] list a string that is a colon-delimited list of elliptic curve
    groups.

    \return WOLFSSL_FAILURE if pointer parameters are NULL, there are more than
    WOLFSSL_MAX_GROUP_COUNT groups, a group name is not recognized or not
    using TLS v1.3.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ctx, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_CTX_set1_groups_list(WOLFSSL_CTX *ctx, char *list);

/*!
    \ingroup Setup

    \brief This function sets the list of elliptic curve groups to allow on
    a wolfSSL in order of preference.
    The list is a null-terminated text string, and a colon-delimited list.
    Call this function to set the key exchange elliptic curve parameters to
    use with the TLS v1.3 connections.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] list a string that is a colon separated list of key exchange
    groups.

    \return WOLFSSL_FAILURE if pointer parameters are NULL, there are more than
    WOLFSSL_MAX_GROUP_COUNT groups, a group name is not recognized or not
    using TLS v1.3.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_set1_groups_list(WOLFSSL *ssl, char *list);

/*!
    \ingroup TLS

    \brief This function returns the key exchange group the client prefers to
    use in the TLS v1.3 handshake.
    Call this function to after a handshake is complete to determine which
    group the server prefers so that this information can be used in future
    connections to pre-generate a key pair for key exchange.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a server.
    \return NOT_READY_ERROR if called before handshake is complete.
    \return Group identifier if successful.

    _Example_
    \code
    int ret;
    int group;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl)
    if (ret < 0) {
        // failed to get group
    }
    group = ret;
    \endcode

    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
*/
int  wolfSSL_preferred_group(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the list of elliptic curve groups to allow on
    a wolfSSL context in order of preference.
    The list is an array of group identifiers with the number of identifiers
    specified in count.
    Call this function to set the key exchange elliptic curve parameters to
    use with the TLS v1.3 connections.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] groups a list of key exchange groups by identifier.
    \param [in] count the number of key exchange groups in groups.

    \return BAD_FUNC_ARG if a pointer parameter is null, the number of groups
    exceeds WOLFSSL_MAX_GROUP_COUNT or not using TLS v1.3.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    int* groups = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = 2;
    ...
    ret = wolfSSL_CTX_set1_groups_list(ctx, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_CTX_set_groups(WOLFSSL_CTX* ctx, int* groups,
    int count);

/*!
    \ingroup Setup

    \brief This function sets the list of elliptic curve groups to allow on
    a wolfSSL.
    The list is an array of group identifiers with the number of identifiers
    specified in count.
    Call this function to set the key exchange elliptic curve parameters to
    use with the TLS v1.3 connections.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] groups a list of key exchange groups by identifier.
    \param [in] count the number of key exchange groups in groups.

    \return BAD_FUNC_ARG if a pointer parameter is null, the number of groups
    exceeds WOLFSSL_MAX_GROUP_COUNT, any of the identifiers are unrecognized or
    not using TLS v1.3.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int* groups = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = 2;
    ...
    ret = wolfSSL_set_groups(ssl, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_set_groups(WOLFSSL* ssl, int* groups, int count);

/*!
    \ingroup IO

    \brief This function is called on the client side and initiates a
    TLS v1.3 handshake with a server.  When this function is called, the
    underlying communication channel has already been set up.
    wolfSSL_connect() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_connect() will return
    when the underlying I/O could not satisfy the needs of wolfSSL_connect
    to continue the handshake.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE. The
    calling process must then repeat the call to wolfSSL_connect() when
    the underlying I/O is ready and wolfSSL will pick up where it left off.
    When using a non-blocking socket, nothing needs to be done, but select()
    can be used to check for the required condition. If the underlying I/O is
    blocking, wolfSSL_connect() will only return once the handshake has been
    finished or an error occurred. wolfSSL takes a different approach to
    certificate verification than OpenSSL does.  The default policy for the
    client is to verify the server, this means that if you don't load CAs to
    verify the server you'll get a connect error, unable to verify (-155). It
    you want to mimic OpenSSL behavior of having SSL_connect succeed even if
    verifying the server fails and reducing security you can do this by
    calling: SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); before calling
    SSL_new();  Though it's not recommended.

    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred.  To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_connect_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept_TLSv13
    \sa wolfSSL_accept
*/
int  wolfSSL_connect_TLSv13(WOLFSSL*);

/*!
    \ingroup IO

    \brief This function is called on the server side and waits for a SSL/TLS
    client to initiate the SSL/TLS handshake.  When this function is called,
    the underlying communication channel has already been set up.
    wolfSSL_accept() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_accept() will return
    when the underlying I/O could not satisfy the needs of wolfSSL_accept
    to continue the handshake.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
    The calling process must then repeat the call to wolfSSL_accept when
    data is available to read and wolfSSL will pick up where it left off.
    When using a non-blocking socket, nothing needs to be done, but select()
    can be used to check for the required condition. If the underlying I/O
    is blocking, wolfSSL_accept() will only return once the handshake has
    been finished or an error occurred.
    Call this function when expecting a TLS v1.3 connection though older
    version ClientHello messages are supported.

    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_accept_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect_TLSv13
    \sa wolfSSL_connect
    \sa wolfSSL_accept_TLSv13
    \sa wolfSSL_accept
*/
wolfSSL_accept_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the maximum amount of early data that a
    TLS v1.3 client or server is willing to exchange using the wolfSSL context.
    Call this function to limit the amount of early data to process to mitigate
    replay attacks. Early data is protected by keys derived from those of the
    connection that the session ticket was sent and therefore will be the same
    every time a session ticket is used in resumption.
    The value is included in the session ticket for resumption.
    A server value of zero indicates no early data is to be sent by client using
    session tickets. A client value of zero indicates that the client will
    not send any early data.
    It is recommended that the number of early data bytes be kept as low as
    practically possible in the application.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] sz the amount of early data to accept in bytes.

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_set_max_early_data(ctx, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_CTX_set_max_early_data(WOLFSSL_CTX* ctx,
    unsigned int sz);

/*!
    \ingroup Setup

    \brief This function sets the maximum amount of early data that a
    TLS v1.3 client or server is willing to exchange.
    Call this function to limit the amount of early data to process to mitigate
    replay attacks. Early data is protected by keys derived from those of the
    connection that the session ticket was sent and therefore will be the same
    every time a session ticket is used in resumption.
    The value is included in the session ticket for resumption.
    A server value of zero indicates no early data is to be sent by client using
    session tickets. A client value of zero indicates that the client will
    not send any early data.
    It is recommended that the number of early data bytes be kept as low as
    practically possible in the application.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] sz the amount of early data to accept from client in bytes.

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_set_max_early_data(ssl, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_CTX_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_set_max_early_data(WOLFSSL* ssl, unsigned int sz);

/*!
    \ingroup IO

    \brief This function writes early data to the server on resumption.
    Call this function instead of wolfSSL_connect() or wolfSSL_connect_TLSv13()
    to connect to the server and send the data in the handshake.
    This function is only used with clients.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] data the buffer holding the early data to write to server.
    \param [in] sz the amount of early data to write in bytes.
    \param [out] outSz the amount of early data written in bytes.

    \return BAD_FUNC_ARG if a pointer parameter is NULL, sz is less than 0 or
    not using TLSv1.3.
    \return SIDE_ERROR if called with a server.
    \return WOLFSSL_FATAL_ERROR if the connection is not made.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    byte earlyData[] = { early data };
    int outSz;
    char buffer[80];
    ...

    ret = wolfSSL_write_early_data(ssl, earlyData, sizeof(earlyData), &outSz);
    if (ret != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
        goto err_label;
    }
    if (outSz < sizeof(earlyData)) {
        // not all early data was sent
    }
    ret = wolfSSL_connect_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_read_early_data
    \sa wolfSSL_connect
    \sa wolfSSL_connect_TLSv13
*/
int  wolfSSL_write_early_data(WOLFSSL* ssl, const void* data,
    int sz, int* outSz);

/*!
    \ingroup IO

    \brief This function reads any early data from a client on resumption.
    Call this function instead of wolfSSL_accept() or wolfSSL_accept_TLSv13()
    to accept a client and read any early data in the handshake. The function
    should be invoked until wolfSSL_is_init_finished() returns true. Early data
    may be sent by the client in multiple messages. If there is no early data
    then the handshake will be processed as normal. This function is only used
    with servers.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [out] data a buffer to hold the early data read from client.
    \param [in] sz size of the buffer in bytes.
    \param [out] outSz number of bytes of early data read.

    \return BAD_FUNC_ARG if a pointer parameter is NULL, sz is less than 0 or
    not using TLSv1.3.
    \return SIDE_ERROR if called with a client.
    \return WOLFSSL_FATAL_ERROR if accepting a connection fails.
    \return Number of early data bytes read (may be zero).

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    byte earlyData[128];
    int outSz;
    char buffer[80];
    ...

    do {
        ret = wolfSSL_read_early_data(ssl, earlyData, sizeof(earlyData), &outSz);
        if (ret < 0) {
            err = wolfSSL_get_error(ssl, ret);
            printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
        }
        if (outSz > 0) {
            // early data available
        }
    } while (!wolfSSL_is_init_finished(ssl));
    \endcode

    \sa wolfSSL_write_early_data
    \sa wolfSSL_accept
    \sa wolfSSL_accept_TLSv13
*/
int  wolfSSL_read_early_data(WOLFSSL* ssl, void* data, int sz,
    int* outSz);

/*!
    \ingroup IO

    \brief This function is called to inject data into the WOLFSSL object. This
    is useful when data needs to be read from a single place and demultiplexed
    into multiple connections. The caller should then call wolfSSL_read() to
    extract the plaintext data from the WOLFSSL object.

    \param [in] ssl a pointer to a WOLFSSL structure, created using
                    wolfSSL_new().
    \param [in] data data to inject into the ssl object.
    \param [in] sz number of bytes of data to inject.

    \return BAD_FUNC_ARG if any pointer parameter is NULL or sz <= 0
    \return APP_DATA_READY if there is application data left to read
    \return MEMORY_E if allocation fails
    \return WOLFSSL_SUCCESS on success

    _Example_
    \code
    byte buf[2000]
    sz = recv(fd, buf, sizeof(buf), 0);
    if (sz <= 0)
        // error
    if (wolfSSL_inject(ssl, buf, sz) != WOLFSSL_SUCCESS)
        // error
    sz = wolfSSL_read(ssl, buf, sizeof(buf);
    \endcode

    \sa wolfSSL_read
*/
int wolfSSL_inject(WOLFSSL* ssl, const void* data, int sz);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) client side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the client_psk_tls13_cb member of the
    WOLFSSL_CTX structure.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 client.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    ...
    wolfSSL_CTX_set_psk_client_tls13_callback(ctx, my_psk_client_tls13_cb);
    \endcode

    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_CTX_set_psk_client_tls13_callback(WOLFSSL_CTX* ctx,
    wc_psk_client_tls13_callback cb);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) client side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the client_psk_tls13_cb member of the options field in
    WOLFSSL structure.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 client.

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_set_psk_client_tls13_callback(ssl, my_psk_client_tls13_cb);
    \endcode

    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_set_psk_client_tls13_callback(WOLFSSL* ssl,
    wc_psk_client_tls13_callback cb);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) server side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the server_psk_tls13_cb member of the
    WOLFSSL_CTX structure.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 server.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    ...
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, my_psk_client_tls13_cb);
    \endcode

    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_CTX_set_psk_server_tls13_callback(WOLFSSL_CTX* ctx,
    wc_psk_server_tls13_callback cb);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) server side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the server_psk_tls13_cb member of the options field in
    WOLFSSL structure.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 server.

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_set_psk_server_tls13_callback(ssl, my_psk_server_tls13_cb);
    \endcode

    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
*/
void wolfSSL_set_psk_server_tls13_callback(WOLFSSL* ssl,
    wc_psk_server_tls13_callback cb);

/*!
    \ingroup Setup

    \brief This function creates a key share entry from the group including
    generating a key pair.
    The KeyShare extension contains all the generated public keys for key
    exchange. If this function is called, then only the groups specified will
    be included.
    Call this function when a preferred group has been previously established
    for the server.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] group a key exchange group identifier.

    \return BAD_FUNC_ARG if ssl is NULL.
    \return MEMORY_E when dynamic memory allocation fails.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set key share
    }
    \endcode

    \sa wolfSSL_preferred_group
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_NoKeyShares
*/
int wolfSSL_UseKeyShare(WOLFSSL* ssl, word16 group);

/*!
    \ingroup Setup

    \brief This function is called to ensure no key shares are sent in the
    ClientHello. This will force the server to respond with a HelloRetryRequest
    if a key exchange is required in the handshake.
    Call this function when the expected key exchange group is not known and
    to avoid the generation of keys unnecessarily.
    Note that an extra round-trip will be required to complete the handshake
    when a key exchange is required.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL.
    \return SIDE_ERROR if called with a server.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_NoKeyShares(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set no key shares
    }
    \endcode

    \sa wolfSSL_UseKeyShare
*/
int wolfSSL_NoKeyShares(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a server and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \param [in] heap a pointer to a buffer that the static memory allocator will use during dynamic memory allocation.

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method_ex(NULL);
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_server_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a client and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \param [in] heap a pointer to a buffer that the static memory allocator will use during dynamic memory allocation.

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_client_method_ex(NULL);
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_client_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a server and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method_ex
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_server_method(void);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a client and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_client_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method_ex
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_client_method(void);

/*!
    \ingroup Setup

    \brief This function returns a WOLFSSL_METHOD similar to
    wolfTLSv1_3_client_method except that it is not determined
    which side yet (server/client).

    \param [in] heap a pointer to a buffer that the static memory allocator will use during dynamic memory allocation.

    \return WOLFSSL_METHOD On successful creations returns a WOLFSSL_METHOD
    pointer
    \return NULL Null if memory allocation error or failure to create method

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method_ex(NULL));
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function returns a WOLFSSL_METHOD similar to
    wolfTLSv1_3_client_method except that it is not determined
    which side yet (server/client).

    \return WOLFSSL_METHOD On successful creations returns a WOLFSSL_METHOD
    pointer
    \return NULL Null if memory allocation error or failure to create method

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method());
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method(void);

/*!
 \ingroup SSL
 \brief This function sets a fixed / static ephemeral key for testing only
 \return 0 Key loaded successfully
 \param ctx A WOLFSSL_CTX context pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key file path (if keySz == 0) or actual key buffer (PEM or ASN.1)
 \param keySz key size (should be 0 for "key" arg is file path)
 \param format WOLFSSL_FILETYPE_ASN1 or WOLFSSL_FILETYPE_PEM
 \sa wolfSSL_CTX_get_ephemeral_key
 */
int wolfSSL_CTX_set_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief This function sets a fixed / static ephemeral key for testing only
 \return 0 Key loaded successfully
 \param ssl A WOLFSSL object pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key file path (if keySz == 0) or actual key buffer (PEM or ASN.1)
 \param keySz key size (should be 0 for "key" arg is file path)
 \param format WOLFSSL_FILETYPE_ASN1 or WOLFSSL_FILETYPE_PEM
 \sa wolfSSL_get_ephemeral_key
 */
int wolfSSL_set_ephemeral_key(WOLFSSL* ssl, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief This function returns pointer to loaded key as ASN.1/DER
 \return 0 Key returned successfully
 \param ctx A WOLFSSL_CTX context pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key buffer pointer
 \param keySz key size pointer
 \sa wolfSSL_CTX_set_ephemeral_key
 */
int wolfSSL_CTX_get_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief This function returns pointer to loaded key as ASN.1/DER
 \return 0 Key returned successfully
 \param ssl A WOLFSSL object pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key buffer pointer
 \param keySz key size pointer
 \sa wolfSSL_set_ephemeral_key
 */
int wolfSSL_get_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief Sign a message with the chosen message digest, padding, and RSA key
 \return WOLFSSL_SUCCESS on success and c on error
 \param type      Hash NID
 \param m         Message to sign. Most likely this will be the digest of
                  the message to sign
 \param mLen      Length of message to sign
 \param sigRet    Output buffer
 \param sigLen    On Input: length of sigRet buffer
                  On Output: length of data written to sigRet
 \param rsa       RSA key used to sign the input
 \param flag      1: Output the signature
                  0: Output the value that the unpadded signature should be
                     compared to. Note: for RSA_PKCS1_PSS_PADDING the
                     wc_RsaPSS_CheckPadding_ex function should be used to check
                     the output of a *Verify* function.
 \param padding   Padding to use. Only RSA_PKCS1_PSS_PADDING and
                  RSA_PKCS1_PADDING are currently supported for signing.
 */
int wolfSSL_RSA_sign_generic_padding(int type, const unsigned char* m,
                               unsigned int mLen, unsigned char* sigRet,
                               unsigned int* sigLen, WOLFSSL_RSA* rsa,
                               int flag, int padding);
/*!

\brief checks if DTLSv1.3 stack has some messages sent but not yet acknowledged
 by the other peer

 \return 1 if there are pending messages, 0 otherwise
 \param ssl A WOLFSSL object pointer
*/
int wolfSSL_dtls13_has_pending_msg(WOLFSSL *ssl);

/*!
    \ingroup SSL
    \brief Get the maximum size of Early Data from a session.

    \param [in] s  the WOLFSSL_SESSION instance.

    \return the value of max_early_data that was configured in the WOLFSSL* the session
    was derived from.

    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
 */
unsigned int wolfSSL_SESSION_get_max_early_data(const WOLFSSL_SESSION *s);

/*!
    \ingroup SSL
    \brief Get a new index for external data. This entry applies also for the
           following API:
           - wolfSSL_CTX_get_ex_new_index
           - wolfSSL_get_ex_new_index
           - wolfSSL_SESSION_get_ex_new_index
           - wolfSSL_X509_get_ex_new_index

    \param [in] All input parameters are ignored. The callback functions are not
                supported with wolfSSL.

    \return The new index value to be used with the external data API for this
            object class.
 */
int wolfSSL_CRYPTO_get_ex_new_index(int, void*, void*, void*, void*);

/*!
 \ingroup Setup
 \brief  In case this function is called in a client side, set certificate types
 that can be sent to its peer. In case called in a server side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_CLIENT_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ctx  WOLFSSL_CTX object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_CTX_set_client_cert_type(ctx, buf, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_CTX_set_client_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  In case this function is called in a server side, set certificate types
 that can be sent to its peer. In case called in a client side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_SERVER_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ctx  WOLFSSL_CTX object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_CTX_set_server_cert_type(ctx, buf, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_CTX_set_server_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  In case this function is called in a client side, set certificate types
 that can be sent to its peer. In case called in a server side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_CLIENT_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ssl  WOLFSSL object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_set_client_cert_type(ssl, buf, len);
 \endcode
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_set_client_cert_type(WOLFSSL* ssl, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  In case this function is called in a server side, set certificate types
 that can be sent to its peer. In case called in a client side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_SERVER_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ctx  WOLFSSL_CTX object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_set_server_cert_type(ssl, buf, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_set_server_cert_type(WOLFSSL* ssl, const char* buf, int len);

/*!
    \ingroup Setup

    \brief Enables handshake message grouping for the given WOLFSSL_CTX context.

    This function turns on handshake message grouping for all SSL objects created from the specified context.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ctx is NULL.

    \param ctx Pointer to the WOLFSSL_CTX structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_set_group_messages(ctx);
    \endcode

    \sa wolfSSL_CTX_clear_group_messages
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_clear_group_messages
*/
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Disables handshake message grouping for the given WOLFSSL_CTX context.

    This function turns off handshake message grouping for all SSL objects created from the specified context.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ctx is NULL.

    \param ctx Pointer to the WOLFSSL_CTX structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_clear_group_messages(ctx);
    \endcode

    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_clear_group_messages
*/
int wolfSSL_CTX_clear_group_messages(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Enables handshake message grouping for the given WOLFSSL object.

    This function turns on handshake message grouping for the specified SSL object.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl Pointer to the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_set_group_messages(ssl);
    \endcode

    \sa wolfSSL_clear_group_messages
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_CTX_clear_group_messages
*/
int wolfSSL_set_group_messages(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Disables handshake message grouping for the given WOLFSSL object.

    This function turns off handshake message grouping for the specified SSL object.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl Pointer to the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_clear_group_messages(ssl);
    \endcode

    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_CTX_clear_group_messages
*/
int wolfSSL_clear_group_messages(WOLFSSL* ssl);

/*!
 \ingroup SSL
 \brief  This function returns the result of the client certificate type
 negotiation done in ClientHello and ServerHello. WOLFSSL_SUCCESS is returned as
  a return value if no negotiation occurs and WOLFSSL_CERT_TYPE_UNKNOWN is
  returned as the certificate type.

 \return WOLFSSL_SUCCESS if a negotiated certificate type could be got
 \return BAD_FUNC_ARG if NULL was passed for ctx or tp
 \param ssl  WOLFSSL object pointer
 \param tp  A buffer where a certificate type is to be returned. One of three
 certificate types will be returned: WOLFSSL_CERT_TYPE_RPK,
 WOLFSSL_CERT_TYPE_X509 or WOLFSSL_CERT_TYPE_UNKNOWN.

    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  int tp;
  ...

  ret = wolfSSL_get_negotiated_client_cert_type(ssl, &tp);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_get_negotiated_client_cert_type(WOLFSSL* ssl, int* tp);

/*!
 \ingroup SSL
 \brief  This function returns the result of the server certificate type
 negotiation done in ClientHello and ServerHello. WOLFSSL_SUCCESS is returned as
  a return value if no negotiation occurs and WOLFSSL_CERT_TYPE_UNKNOWN is
  returned as the certificate type.

 \return WOLFSSL_SUCCESS if a negotiated certificate type could be got
 \return BAD_FUNC_ARG if NULL was passed for ctx or tp
 \param ssl  WOLFSSL object pointer
 \param tp  A buffer where a certificate type is to be returned. One of three
 certificate types will be returned: WOLFSSL_CERT_TYPE_RPK,
 WOLFSSL_CERT_TYPE_X509 or WOLFSSL_CERT_TYPE_UNKNOWN.
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  int tp;
　...

  ret = wolfSSL_get_negotiated_server_cert_type(ssl, &tp);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 */
int wolfSSL_get_negotiated_server_cert_type(WOLFSSL* ssl, int* tp);

/*!

\brief Enable use of ConnectionID extensions for the SSL object. See RFC 9146
and RFC 9147

 \return WOLFSSL_SUCCESS on success, error code otherwise

 \param ssl A WOLFSSL object pointer

 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_use(WOLFSSL* ssl);

/*!

\brief If invoked after the handshake is complete it checks if ConnectionID was
successfully negotiated for the SSL object. See RFC 9146 and RFC 9147

 \return 1 if ConnectionID was correctly negotiated, 0 otherwise

 \param ssl A WOLFSSL object pointer

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_is_enabled(WOLFSSL* ssl);

/*!

\brief Set the ConnectionID used by the other peer to send records in this
connection. See RFC 9146 and RFC 9147. The ConnectionID must be at maximum
DTLS_CID_MAX_SIZE, that is an tunable compile time define, and it can't
never be bigger than 255 bytes.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly set, error code otherwise

 \param ssl A WOLFSSL object pointern
 \param cid the ConnectionID to be used
 \param size of the ConnectionID provided

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid,
    unsigned int size);

/*!

\brief Get the size of the ConnectionID used by the other peer to send records
in this connection. See RFC 9146 and RFC 9147. The size is stored in the
parameter size.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly negotiated, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param size a pointer to an unsigned int where the size will be stored

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_rx_size(WOLFSSL* ssl,
    unsigned int* size);

/*!

\brief Copy the ConnectionID used by the other peer to send records in this
connection into the buffer pointed by the parameter buffer. See RFC 9146 and RFC
9147. The available space in the buffer need to be provided in bufferSz.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly copied, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param buffer A buffer where the ConnectionID will be copied
 \param bufferSz available space in buffer

 \sa wolfSSL_dtls_cid_get0_rx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_rx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);

/*!

\brief Get the ConnectionID used by the other peer. See RFC 9146 and RFC
9147.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly set in cid.

 \param ssl A WOLFSSL object pointern
 \param cid Pointer that will be set to the internal memory that holds the CID

 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get0_rx(WOLFSSL* ssl, unsigned char** cid);

/*!

\brief Get the size of the ConnectionID used to send records in this
connection. See RFC 9146 and RFC 9147. The size is stored in the parameter size.

 \return WOLFSSL_SUCCESS if ConnectionID size was correctly stored, error
 code otherwise

 \param ssl A WOLFSSL object pointern
 \param size a pointer to an unsigned int where the size will be stored

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_tx_size(WOLFSSL* ssl, unsigned int* size);

/*!

\brief Copy the ConnectionID used when sending records in this connection into
the buffer pointer by the parameter buffer. See RFC 9146 and RFC 9147. The
available size need to be provided in bufferSz.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly copied, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param buffer A buffer where the ConnectionID will be copied
 \param bufferSz available space in buffer

 \sa wolfSSL_dtls_cid_get0_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
int wolfSSL_dtls_cid_get_tx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);

/*!

\brief Get the ConnectionID used when sending records in this connection. See
RFC 9146 and RFC 9147.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly retrieved, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param cid Pointer that will be set to the internal memory that holds the CID

 \sa wolfSSL_dtls_cid_get_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
int wolfSSL_dtls_cid_get0_tx(WOLFSSL* ssl, unsigned char** cid);

/*!

\brief Extract the ConnectionID from a record datagram/message. See
RFC 9146 and RFC 9147.

 \param msg buffer holding the datagram read from the network
 \param msgSz size of msg in bytes
 \param cid pointer to the start of the CID inside the msg buffer
 \param cidSz the expected size of the CID. The record layer does not have a CID
 size field so we have to know beforehand the size of the CID. It is recommended
 to use a constant CID for all connections.

 \sa wolfSSL_dtls_cid_get_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
const unsigned char* wolfSSL_dtls_cid_parse(const unsigned char* msg,
        unsigned int msgSz, unsigned int cidSz);

/*!
    \ingroup TLS
    \brief On the server, this sets a list of CA names to be sent to clients in
    certificate requests as a hint for which CA's are supported by the server.

    On the client, this function has no effect.

    \param [in] ctx Pointer to the wolfSSL context
    \param [in] names List of names to be set

    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX* ctx,
                                    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief This retrieves the list previously set via
     wolfSSL_CTX_set_client_CA_list, or NULL if no list has been set.

    \param [in] ctx Pointer to the wolfSSL context
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_CTX_get_client_CA_list(
        const WOLFSSL_CTX *ctx);

/*!
    \ingroup TLS
    \brief Same as wolfSSL_CTX_set_client_CA_list, but specific to a session.
    If a CA list is set on both the context and the session, the list on the
    session is used.

    \param [in] ssl Pointer to the WOLFSSL object
    \param [in] names List of names to be set.

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_set_client_CA_list(WOLFSSL* ssl,
                                    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief On the server, this retrieves the list previously set via
    wolfSSL_set_client_CA_list. If none was set, returns the list previously
    set via wolfSSL_CTX_set_client_CA_list. If no list at all was set, returns
    NULL.

    On the client, this retrieves the list that was received from the server,
    or NULL if none was received. wolfSSL_CTX_set_cert_cb can be used to
    register a callback to dynamically load certificates when a certificate
    request is received from the server.

    \param [in] ssl Pointer to the WOLFSSL object
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_cert_cb
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK* wolfSSL_get_client_CA_list(
            const WOLFSSL* ssl);

/*!
    \ingroup TLS
    \brief This function sets a list of CA names to be sent to the peer as a
    hint for which CA's are supported for its authentication.

    In TLS >= 1.3, this is supported in both directions between the client and
    the server. On the server, the CA names will be sent as part of a
    CertificateRequest, making this function an equivalent of *_set_client_CA_list;
    on the client, these are sent as part of ClientHello.

    In TLS < 1.3, sending CA names from the client to the server is not
    supported, therefore this function is equivalent to
    wolfSSL_CTX_set_client_CA_list.

    Note that the lists set via *_set_client_CA_list and *_set0_CA_list are
    separate internally, i.e. calling *_get_client_CA_list will not retrieve a
    list set via *_set0_CA_list and vice versa. If both are set, the server will
    ignore *_set0_CA_list when sending CA names to the client.

    \param [in] ctx Pointer to the wolfSSL context
    \param [in] names List of names to be set

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_CTX_set0_CA_list(WOLFSSL_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief This retrieves the list previously set via
    wolfSSL_CTX_set0_CA_list, or NULL if no list has been set.

    \param [in] ctx Pointer to the wolfSSL context
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_CTX_get0_CA_list(
        const WOLFSSL_CTX *ctx);

/*!
    \ingroup TLS
    \brief Same as wolfSSL_CTX_set0_CA_list, but specific to a session.
    If a CA list is set on both the context and the session, the list on the
    session is used.

    \param [in] ssl Pointer to the WOLFSSL object
    \param [in] names List of names to be set.

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_set0_CA_list(WOLFSSL *ssl,
        WOLF_STACK_OF(WOLFSSL_X509_NAME) *names);

/*!
    \ingroup TLS
    \brief This retrieves the list previously set via wolfSSL_set0_CA_list. If
    none was set, returns the list previously set via
    wolfSSL_CTX_set0_CA_list. If no list at all was set, returns NULL.

    \param [in] ssl Pointer to the WOLFSSL object
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_get0_CA_list(
        const WOLFSSL *ssl);

/*!
    \ingroup TLS
    \brief This returns the CA list received from the peer.

    On the client, this is the list sent by the server in a CertificateRequest,
    and this function is equivalent to wolfSSL_get_client_CA_list.

    On the server, this is the list sent by the client in the ClientHello message
    in TLS >= 1.3; in TLS < 1.3, the function always returns NULL on the server
    side.

    wolfSSL_CTX_set_cert_cb can be used to register a callback to dynamically
    load certificates when a CA list is received from the peer.

    \param [in] ssl Pointer to the WOLFSSL object
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_cert_cb
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
*/
WOLFSSL_STACK *wolfSSL_get0_peer_CA_list(const WOLFSSL *ssl);

/*!
    \ingroup TLS
    \brief This function sets a callback that will be called whenever a
    certificate is about to be used, to allow the application to inspect, set
    or clear any certificates, for example to react to a CA list sent from the
    peer.

    \param [in] ctx Pointer to the wolfSSL context
    \param [in] cb Function pointer to the callback
    \param [in] arg Pointer that will be passed to the callback

    \sa wolfSSL_get0_peer_CA_list
    \sa wolfSSL_get_client_CA_list
*/
void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx,
    int (*cb)(WOLFSSL *, void *), void *arg);

/*!
    \ingroup TLS

    \brief This function returns the raw list of ciphersuites and signature
    algorithms offered by the client. The lists are only stored and returned
    inside a callback setup with wolfSSL_CTX_set_cert_cb(). This is useful to
    be able to dynamically load certificates and keys based on the available
    ciphersuites and signature algorithms.

    \param [in] ssl The WOLFSSL object to extract the lists from.
    \param [out] optional suites Raw and unfiltered list of client ciphersuites
    \param [out] optional suiteSz Size of suites in bytes
    \param [out] optional hashSigAlgo Raw and unfiltered list of client
                          signature algorithms
    \param [out] optional hashSigAlgoSz Size of hashSigAlgo in bytes
    \return WOLFSSL_SUCCESS when suites available
    \return WOLFSSL_FAILURE when suites not available

    _Example_
    \code
    int certCB(WOLFSSL* ssl, void* arg)
    {
        const byte* suites = NULL;
        word16 suiteSz = 0;
        const byte* hashSigAlgo = NULL;
        word16 hashSigAlgoSz = 0;

        wolfSSL_get_client_suites_sigalgs(ssl, &suites, &suiteSz, &hashSigAlgo,
                &hashSigAlgoSz);

        // Choose certificate to load based on ciphersuites and sigalgs
    }

    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method_ex(NULL));
    wolfSSL_CTX_set_cert_cb(ctx, certCB, NULL);
    \endcode

    \sa wolfSSL_get_ciphersuite_info
    \sa wolfSSL_get_sigalg_info
*/
int wolfSSL_get_client_suites_sigalgs(const WOLFSSL* ssl,
        const byte** suites, word16* suiteSz,
        const byte** hashSigAlgo, word16* hashSigAlgoSz);

/*!
    \ingroup TLS

    \brief This returns information about the ciphersuite directly from the
    raw ciphersuite bytes.

    \param [in] first First byte of the ciphersuite
    \param [in] second Second byte of the ciphersuite

    \return WOLFSSL_CIPHERSUITE_INFO A struct containing information about the
    type of authentication used in the ciphersuite.

    _Example_
    \code
    WOLFSSL_CIPHERSUITE_INFO info =
            wolfSSL_get_ciphersuite_info(suites[0], suites[1]);
    if (info.rsaAuth)
        haveRSA = 1;
    else if (info.eccAuth)
        haveECC = 1;
    \endcode

    \sa wolfSSL_get_client_suites_sigalgs
    \sa wolfSSL_get_sigalg_info
*/
WOLFSSL_CIPHERSUITE_INFO wolfSSL_get_ciphersuite_info(byte first,
        byte second);

/*!
    \ingroup TLS

    \brief This returns information about the hash and signature algorithm
    directly from the raw ciphersuite bytes.

    \param [in] first First byte of the hash and signature algorithm
    \param [in] second Second byte of the hash and signature algorithm
    \param [out] hashAlgo The enum wc_HashType of the MAC algorithm
    \param [out] sigAlgo The enum Key_Sum of the authentication algorithm

    \return 0            when info was correctly set
    \return BAD_FUNC_ARG when either input parameters are NULL or the bytes
                         are not a recognized sigalg suite

    _Example_
    \code
    enum wc_HashType hashAlgo;
    enum Key_Sum sigAlgo;

    wolfSSL_get_sigalg_info(hashSigAlgo[idx+0], hashSigAlgo[idx+1],
            &hashAlgo, &sigAlgo);

    if (sigAlgo == RSAk || sigAlgo == RSAPSSk)
        haveRSA = 1;
    else if (sigAlgo == ECDSAk)
        haveECC = 1;
    \endcode

    \sa wolfSSL_get_client_suites_sigalgs
    \sa wolfSSL_get_ciphersuite_info
*/
int wolfSSL_get_sigalg_info(byte first, byte second,
        int* hashAlgo, int* sigAlgo);

/*!
    \ingroup Setup

    \brief Gets extra data associated with an SSL session.

    \return void* Pointer to the data
    \return NULL if ssl is NULL or idx is invalid

    \param ssl WOLFSSL object to get data from
    \param idx Index of the data to retrieve

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* data = wolfSSL_get_ex_data(ssl, 0);
    if (data != NULL) {
        // use the data
    }
    \endcode

    \sa wolfSSL_set_ex_data
    \sa wolfSSL_get_ex_new_index
*/
void* wolfSSL_get_ex_data(const WOLFSSL* ssl, int idx);

/*!
    \ingroup Setup

    \brief Sets extra data associated with an SSL session.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ssl WOLFSSL object to set data for
    \param idx Index of the data to set
    \param data Pointer to the data to store

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* myData = malloc(sizeof(MyData));
    int ret = wolfSSL_set_ex_data(ssl, 0, myData);
    if (ret != SSL_SUCCESS) {
        // failed to set data
    }
    \endcode

    \sa wolfSSL_get_ex_data
    \sa wolfSSL_set_ex_data_with_cleanup
*/
int wolfSSL_set_ex_data(WOLFSSL* ssl, int idx, void* data);

/*!
    \ingroup Setup

    \brief Sets extra data with cleanup callback for an SSL session.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ssl WOLFSSL object to set data for
    \param idx Index of the data to set
    \param data Pointer to the data to store
    \param cleanup_routine Callback to free data when SSL is freed

    _Example_
    \code
    void myCleanup(void* data) {
        free(data);
    }
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* myData = malloc(sizeof(MyData));
    int ret = wolfSSL_set_ex_data_with_cleanup(ssl, 0, myData,
                                                 myCleanup);
    \endcode

    \sa wolfSSL_set_ex_data
    \sa wolfSSL_get_ex_data
*/
int wolfSSL_set_ex_data_with_cleanup(WOLFSSL* ssl, int idx, void* data,
                                       wolfSSL_ex_data_cleanup_routine_t
                                       cleanup_routine);

/*!
    \ingroup Setup

    \brief Allocates a new index for extra data storage.

    \return int New index on success
    \return -1 on failure

    \param argValue Unused argument value
    \param arg Unused argument pointer
    \param a Callback for new data allocation
    \param b Callback for data duplication
    \param c Callback for data cleanup

    _Example_
    \code
    int idx = wolfSSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (idx < 0) {
        // failed to get new index
    }
    \endcode

    \sa wolfSSL_set_ex_data
    \sa wolfSSL_get_ex_data
*/
int wolfSSL_get_ex_new_index(long argValue, void* arg,
                               WOLFSSL_CRYPTO_EX_new* a,
                               WOLFSSL_CRYPTO_EX_dup* b,
                               WOLFSSL_CRYPTO_EX_free* c);

/*!
    \ingroup Setup

    \brief Gets extra data associated with an SSL context.

    \return void* Pointer to the data
    \return NULL if ctx is NULL or idx is invalid

    \param ctx WOLFSSL_CTX object to get data from
    \param idx Index of the data to retrieve

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    void* data = wolfSSL_CTX_get_ex_data(ctx, 0);
    if (data != NULL) {
        // use the data
    }
    \endcode

    \sa wolfSSL_CTX_set_ex_data
    \sa wolfSSL_CTX_get_ex_new_index
*/
void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX* ctx, int idx);

/*!
    \ingroup Setup

    \brief Sets extra data associated with an SSL context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx WOLFSSL_CTX object to set data for
    \param idx Index of the data to set
    \param data Pointer to the data to store

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    void* myData = malloc(sizeof(MyData));
    int ret = wolfSSL_CTX_set_ex_data(ctx, 0, myData);
    if (ret != SSL_SUCCESS) {
        // failed to set data
    }
    \endcode

    \sa wolfSSL_CTX_get_ex_data
    \sa wolfSSL_CTX_set_ex_data_with_cleanup
*/
int wolfSSL_CTX_set_ex_data(WOLFSSL_CTX* ctx, int idx, void* data);

/*!
    \ingroup Setup

    \brief Sets extra data with cleanup callback for an SSL context.

    \return SSL_SUCCESS on success
    \return SSL_FAILURE on failure

    \param ctx WOLFSSL_CTX object to set data for
    \param idx Index of the data to set
    \param data Pointer to the data to store
    \param cleanup_routine Callback to free data when CTX is freed

    _Example_
    \code
    void myCleanup(void* data) {
        free(data);
    }
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    void* myData = malloc(sizeof(MyData));
    int ret = wolfSSL_CTX_set_ex_data_with_cleanup(ctx, 0, myData,
                                                     myCleanup);
    \endcode

    \sa wolfSSL_CTX_set_ex_data
    \sa wolfSSL_CTX_get_ex_data
*/
int wolfSSL_CTX_set_ex_data_with_cleanup(WOLFSSL_CTX* ctx, int idx,
                                           void* data,
                                           wolfSSL_ex_data_cleanup_routine_t
                                           cleanup_routine);

/*!
    \ingroup Setup

    \brief Allocates a new index for CTX extra data storage.

    \return int New index on success
    \return -1 on failure

    \param idx Unused index value
    \param arg Unused argument pointer
    \param new_func Callback for new data allocation
    \param dup_func Callback for data duplication
    \param free_func Callback for data cleanup

    _Example_
    \code
    int idx = wolfSSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (idx < 0) {
        // failed to get new index
    }
    \endcode

    \sa wolfSSL_CTX_set_ex_data
    \sa wolfSSL_CTX_get_ex_data
*/
int wolfSSL_CTX_get_ex_new_index(long idx, void* arg,
                                   WOLFSSL_CRYPTO_EX_new* new_func,
                                   WOLFSSL_CRYPTO_EX_dup* dup_func,
                                   WOLFSSL_CRYPTO_EX_free* free_func);

/*!
    \ingroup Setup

    \brief Checks if SSL connection has pending data to read.

    \return 1 if data is pending
    \return 0 if no data is pending

    \param ssl WOLFSSL object to check

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (wolfSSL_has_pending(ssl)) {
        // read the pending data
        wolfSSL_read(ssl, buffer, sizeof(buffer));
    }
    \endcode

    \sa wolfSSL_pending
    \sa wolfSSL_read
*/
int wolfSSL_has_pending(const WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Sets certificate verification callback for context.

    \return none

    \param ctx WOLFSSL_CTX object to set callback for
    \param cb Callback function for certificate verification
    \param arg User argument passed to callback

    _Example_
    \code
    int verifyCb(int ok, WOLFSSL_X509_STORE_CTX* store) {
        // custom verification logic
        return ok;
    }
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    wolfSSL_CTX_set_cert_verify_callback(ctx, verifyCb, NULL);
    \endcode

    \sa wolfSSL_CTX_set_verify
    \sa wolfSSL_set_verify
*/
void wolfSSL_CTX_set_cert_verify_callback(WOLFSSL_CTX* ctx,
                                            CertVerifyCallback cb,
                                            void* arg);

/*!
    \ingroup Setup

    \brief Sets the verification result for an SSL session.

    \return none

    \param ssl WOLFSSL object to set result for
    \param v Verification result value

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_set_verify_result(ssl, X509_V_OK);
    \endcode

    \sa wolfSSL_get_verify_result
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_set_verify_result(WOLFSSL* ssl, long v);

/*!
    \ingroup TLS

    \brief Requests client certificate after handshake (TLS 1.3).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object for the connection

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    // complete handshake first
    wolfSSL_accept(ssl);
    // request client certificate
    int ret = wolfSSL_verify_client_post_handshake(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to request certificate
    }
    \endcode

    \sa wolfSSL_CTX_set_post_handshake_auth
    \sa wolfSSL_set_post_handshake_auth
*/
int wolfSSL_verify_client_post_handshake(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Enables post-handshake authentication for context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx WOLFSSL_CTX object to configure
    \param val 1 to enable, 0 to disable

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_set_post_handshake_auth(ctx, 1);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to enable post-handshake auth
    }
    \endcode

    \sa wolfSSL_set_post_handshake_auth
    \sa wolfSSL_verify_client_post_handshake
*/
int wolfSSL_CTX_set_post_handshake_auth(WOLFSSL_CTX* ctx, int val);

/*!
    \ingroup Setup

    \brief Enables post-handshake authentication for session.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object to configure
    \param val 1 to enable, 0 to disable

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ret = wolfSSL_set_post_handshake_auth(ssl, 1);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to enable post-handshake auth
    }
    \endcode

    \sa wolfSSL_CTX_set_post_handshake_auth
    \sa wolfSSL_verify_client_post_handshake
*/
int wolfSSL_set_post_handshake_auth(WOLFSSL* ssl, int val);

/*!
    \ingroup DTLS

    \brief Gets the current DTLS timeout value.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object for DTLS connection
    \param timeleft Pointer to store timeout value

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_TIMEVAL timeout;
    int ret = wolfSSL_DTLSv1_get_timeout(ssl, &timeout);
    if (ret == WOLFSSL_SUCCESS) {
        // use timeout value
    }
    \endcode

    \sa wolfSSL_DTLSv1_set_initial_timeout_duration
    \sa wolfSSL_DTLSv1_handle_timeout
*/
int wolfSSL_DTLSv1_get_timeout(WOLFSSL* ssl, WOLFSSL_TIMEVAL* timeleft);

/*!
    \ingroup DTLS

    \brief Sets the initial DTLS timeout duration.

    \return none

    \param ssl WOLFSSL object for DTLS connection
    \param duration_ms Timeout duration in milliseconds

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_DTLSv1_set_initial_timeout_duration(ssl, 1000);
    \endcode

    \sa wolfSSL_DTLSv1_get_timeout
    \sa wolfSSL_DTLSv1_handle_timeout
*/
void wolfSSL_DTLSv1_set_initial_timeout_duration(WOLFSSL* ssl,
                                                   word32 duration_ms);

/*!
    \ingroup DTLS

    \brief Handles DTLS timeout and retransmits if needed.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object for DTLS connection

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ret = wolfSSL_DTLSv1_handle_timeout(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // timeout handling failed
    }
    \endcode

    \sa wolfSSL_DTLSv1_get_timeout
    \sa wolfSSL_DTLSv1_set_initial_timeout_duration
*/
int wolfSSL_DTLSv1_handle_timeout(WOLFSSL* ssl);

/*!
    \ingroup DTLS

    \brief Creates a peer address structure for DTLS.

    \return void* Pointer to peer address structure
    \return NULL on failure

    \param port Port number
    \param ip IP address string

    _Example_
    \code
    void* peer = wolfSSL_dtls_create_peer(11111, "192.168.1.1");
    if (peer != NULL) {
        // use peer address
        wolfSSL_dtls_free_peer(peer);
    }
    \endcode

    \sa wolfSSL_dtls_free_peer
    \sa wolfSSL_dtls_set_peer
*/
void* wolfSSL_dtls_create_peer(int port, char* ip);

/*!
    \ingroup DTLS

    \brief Frees a peer address structure.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param addr Peer address structure to free

    _Example_
    \code
    void* peer = wolfSSL_dtls_create_peer(11111, "192.168.1.1");
    int ret = wolfSSL_dtls_free_peer(peer);
    \endcode

    \sa wolfSSL_dtls_create_peer
*/
int wolfSSL_dtls_free_peer(void* addr);

/*!
    \ingroup DTLS

    \brief Checks if connection is stateful.

    \return 1 if stateful
    \return 0 if stateless

    \param ssl WOLFSSL object to check

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (wolfSSL_is_stateful(ssl)) {
        // connection is stateful
    }
    \endcode

    \sa wolfSSL_dtls_set_peer
*/
byte wolfSSL_is_stateful(WOLFSSL* ssl);

/*!
    \ingroup DTLS

    \brief Enables SCTP mode for DTLS context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx WOLFSSL_CTX object to configure

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_dtls_set_sctp(ctx);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to enable SCTP
    }
    \endcode

    \sa wolfSSL_dtls_set_sctp
*/
int wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX* ctx);

/*!
    \ingroup DTLS

    \brief Enables SCTP mode for DTLS session.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object to configure

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ret = wolfSSL_dtls_set_sctp(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to enable SCTP
    }
    \endcode

    \sa wolfSSL_CTX_dtls_set_sctp
*/
int wolfSSL_dtls_set_sctp(WOLFSSL* ssl);

/*!
    \ingroup DTLS

    \brief Sets MTU size for DTLS context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx WOLFSSL_CTX object to configure
    \param mtu Maximum transmission unit size

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_dtls_set_mtu(ctx, 1400);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set MTU
    }
    \endcode

    \sa wolfSSL_dtls_set_mtu
*/
int wolfSSL_CTX_dtls_set_mtu(WOLFSSL_CTX* ctx, unsigned short mtu);

/*!
    \ingroup DTLS

    \brief Sets MTU size for DTLS session.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object to configure
    \param mtu Maximum transmission unit size

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ret = wolfSSL_dtls_set_mtu(ssl, 1400);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set MTU
    }
    \endcode

    \sa wolfSSL_CTX_dtls_set_mtu
    \sa wolfSSL_set_mtu_compat
*/
int wolfSSL_dtls_set_mtu(WOLFSSL* ssl, unsigned short mtu);

/*!
    \ingroup DTLS

    \brief Sets MTU size with compatibility mode.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object to configure
    \param mtu Maximum transmission unit size

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ret = wolfSSL_set_mtu_compat(ssl, 1400);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set MTU
    }
    \endcode

    \sa wolfSSL_dtls_set_mtu
*/
int wolfSSL_set_mtu_compat(WOLFSSL* ssl, unsigned short mtu);

/*!
    \ingroup DTLS

    \brief Gets DTLS packet drop statistics.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl WOLFSSL object to query
    \param macDropCount Pointer to store MAC drop count
    \param replayDropCount Pointer to store replay drop count

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    unsigned int macDrops, replayDrops;
    int ret = wolfSSL_dtls_get_drop_stats(ssl, &macDrops,
                                           &replayDrops);
    if (ret == WOLFSSL_SUCCESS) {
        printf("MAC drops: %u, Replay drops: %u\n", macDrops,
               replayDrops);
    }
    \endcode

    \sa wolfSSL_dtls_set_mtu
*/
int wolfSSL_dtls_get_drop_stats(WOLFSSL* ssl, unsigned int* macDropCount,
                                  unsigned int* replayDropCount);

/*!
    \ingroup Setup

    \brief Gets error code from library component.

    \return int Library component code

    \param err Error code

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    int lib = wolfSSL_ERR_GET_LIB(err);
    \endcode

    \sa wolfSSL_ERR_GET_REASON
    \sa wolfSSL_ERR_get_error
*/
int wolfSSL_ERR_GET_LIB(unsigned long err);

/*!
    \ingroup Setup

    \brief Gets error reason code.

    \return int Error reason code

    \param err Error code

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    int reason = wolfSSL_ERR_GET_REASON(err);
    \endcode

    \sa wolfSSL_ERR_GET_LIB
    \sa wolfSSL_ERR_get_error
*/
int wolfSSL_ERR_GET_REASON(unsigned long err);

/*!
    \ingroup Setup

    \brief Converts error code to string.

    \return char* Error string
    \return NULL on failure

    \param errNumber Error code
    \param data Buffer to store error string (can be NULL)

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    char buffer[80];
    char* errStr = wolfSSL_ERR_error_string(err, buffer);
    printf("Error: %s\n", errStr);
    \endcode

    \sa wolfSSL_ERR_reason_error_string
    \sa wolfSSL_ERR_error_string_n
*/
char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data);

/*!
    \ingroup Setup

    \brief Gets error reason string.

    \return const char* Error reason string
    \return NULL on failure

    \param e Error code

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    const char* reason = wolfSSL_ERR_reason_error_string(err);
    printf("Reason: %s\n", reason);
    \endcode

    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_func_error_string
*/
const char* wolfSSL_ERR_reason_error_string(unsigned long e);

/*!
    \ingroup Setup

    \brief Gets error function string.

    \return const char* Error function string
    \return NULL on failure

    \param e Error code

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    const char* func = wolfSSL_ERR_func_error_string(err);
    printf("Function: %s\n", func);
    \endcode

    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_reason_error_string
*/
const char* wolfSSL_ERR_func_error_string(unsigned long e);

/*!
    \ingroup Setup

    \brief Gets error library string.

    \return const char* Error library string
    \return NULL on failure

    \param e Error code

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    const char* lib = wolfSSL_ERR_lib_error_string(err);
    printf("Library: %s\n", lib);
    \endcode

    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_reason_error_string
*/
const char* wolfSSL_ERR_lib_error_string(unsigned long e);

/*!
    \ingroup CertsKeys

    \brief Gets error from X509 store context.

    \return int Error code

    \param ctx X509 store context

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx;
    int err = wolfSSL_X509_STORE_CTX_get_error(ctx);
    printf("Verification error: %d\n", err);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error_depth
*/
int wolfSSL_X509_STORE_CTX_get_error(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets error depth from X509 store context.

    \return int Error depth

    \param ctx X509 store context

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx;
    int depth = wolfSSL_X509_STORE_CTX_get_error_depth(ctx);
    printf("Error at depth: %d\n", depth);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error
*/
int wolfSSL_X509_STORE_CTX_get_error_depth(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup Setup

    \brief Prints errors to BIO.

    \return none

    \param bio BIO to write errors to

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    wolfSSL_BIO_set_fp(bio, stderr, BIO_NOCLOSE);
    wolfSSL_ERR_print_errors(bio);
    wolfSSL_BIO_free(bio);
    \endcode

    \sa wolfSSL_ERR_print_errors_cb
    \sa wolfSSL_ERR_error_string
*/
void wolfSSL_ERR_print_errors(WOLFSSL_BIO* bio);

/*!
    \ingroup openSSL

    \brief Creates a new stack node.

    \return WOLFSSL_STACK* Pointer to new stack node
    \return NULL on failure

    \param heap Heap hint for memory allocation

    _Example_
    \code
    WOLFSSL_STACK* node = wolfSSL_sk_new_node(NULL);
    if (node != NULL) {
        // use the node
        wolfSSL_sk_free_node(node);
    }
    \endcode

    \sa wolfSSL_sk_free_node
    \sa wolfSSL_sk_push_node
*/
WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap);

/*!
    \ingroup openSSL

    \brief Frees a stack node.

    \return none

    \param in Stack node to free

    _Example_
    \code
    WOLFSSL_STACK* node = wolfSSL_sk_new_node(NULL);
    wolfSSL_sk_free_node(node);
    \endcode

    \sa wolfSSL_sk_new_node
*/
void wolfSSL_sk_free_node(WOLFSSL_STACK* in);

/*!
    \ingroup openSSL

    \brief Gets a node from stack at index.

    \return WOLFSSL_STACK* Pointer to stack node
    \return NULL if index is invalid

    \param sk Stack to get node from
    \param idx Index of node to retrieve

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    WOLFSSL_STACK* node = wolfSSL_sk_get_node(sk, 0);
    \endcode

    \sa wolfSSL_sk_new_node
    \sa wolfSSL_sk_push_node
*/
WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* sk, int idx);

/*!
    \ingroup openSSL

    \brief Pushes a node onto stack.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param stack Pointer to stack pointer
    \param in Node to push

    _Example_
    \code
    WOLFSSL_STACK* sk = NULL;
    WOLFSSL_STACK* node = wolfSSL_sk_new_node(NULL);
    int ret = wolfSSL_sk_push_node(&sk, node);
    \endcode

    \sa wolfSSL_sk_new_node
    \sa wolfSSL_sk_get_node
*/
int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* in);

/*!
    \ingroup openSSL

    \brief Frees a stack and all its elements.

    \return none

    \param sk Stack to free

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    wolfSSL_sk_free(sk);
    \endcode

    \sa wolfSSL_sk_new_null
    \sa wolfSSL_sk_pop_free
*/
void wolfSSL_sk_free(WOLFSSL_STACK* sk);

/*!
    \ingroup openSSL

    \brief Duplicates a stack.

    \return WOLFSSL_STACK* Pointer to duplicated stack
    \return NULL on failure

    \param sk Stack to duplicate

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    WOLFSSL_STACK* dup = wolfSSL_sk_dup(sk);
    if (dup != NULL) {
        wolfSSL_sk_free(dup);
    }
    wolfSSL_sk_free(sk);
    \endcode

    \sa wolfSSL_shallow_sk_dup
    \sa wolfSSL_sk_new_null
*/
WOLFSSL_STACK* wolfSSL_sk_dup(WOLFSSL_STACK* sk);

/*!
    \ingroup openSSL

    \brief Creates shallow duplicate of stack.

    \return WOLFSSL_STACK* Pointer to duplicated stack
    \return NULL on failure

    \param sk Stack to duplicate

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    WOLFSSL_STACK* dup = wolfSSL_shallow_sk_dup(sk);
    if (dup != NULL) {
        wolfSSL_sk_free(dup);
    }
    wolfSSL_sk_free(sk);
    \endcode

    \sa wolfSSL_sk_dup
*/
WOLFSSL_STACK* wolfSSL_shallow_sk_dup(WOLFSSL_STACK* sk);

/*!
    \ingroup openSSL

    \brief Pushes data onto stack.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param st Stack to push onto
    \param data Data to push

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    void* data = malloc(100);
    int ret = wolfSSL_sk_push(sk, data);
    \endcode

    \sa wolfSSL_sk_pop
    \sa wolfSSL_sk_insert
*/
int wolfSSL_sk_push(WOLFSSL_STACK* st, const void* data);

/*!
    \ingroup openSSL

    \brief Inserts data into stack at index.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sk Stack to insert into
    \param data Data to insert
    \param idx Index to insert at

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    void* data = malloc(100);
    int ret = wolfSSL_sk_insert(sk, data, 0);
    \endcode

    \sa wolfSSL_sk_push
*/
int wolfSSL_sk_insert(WOLFSSL_STACK* sk, const void* data, int idx);

/*!
    \ingroup openSSL

    \brief Pops data from stack.

    \return void* Pointer to popped data
    \return NULL if stack is empty

    \param sk Stack to pop from

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    wolfSSL_sk_push(sk, data);
    void* popped = wolfSSL_sk_pop(sk);
    \endcode

    \sa wolfSSL_sk_push
*/
void* wolfSSL_sk_pop(WOLFSSL_STACK* sk);

/*!
    \ingroup openSSL

    \brief Gets number of elements in stack.

    \return int Number of elements
    \return 0 if stack is NULL

    \param sk Stack to query

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    int count = wolfSSL_sk_num(sk);
    printf("Stack has %d elements\n", count);
    \endcode

    \sa wolfSSL_sk_value
*/
int wolfSSL_sk_num(const WOLFSSL_STACK* sk);

/*!
    \ingroup openSSL

    \brief Gets value from stack at index.

    \return void* Pointer to value
    \return NULL if index is invalid

    \param sk Stack to get value from
    \param i Index of value to retrieve

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    void* val = wolfSSL_sk_value(sk, 0);
    \endcode

    \sa wolfSSL_sk_num
*/
void* wolfSSL_sk_value(const WOLFSSL_STACK* sk, int i);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 CRL stack.

    \return WOLFSSL_STACK* Pointer to new stack
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_STACK* crl_stack = wolfSSL_sk_X509_CRL_new();
    if (crl_stack != NULL) {
        // use the stack
        wolfSSL_sk_free(crl_stack);
    }
    \endcode

    \sa wolfSSL_sk_new_null
*/
WOLFSSL_STACK* wolfSSL_sk_X509_CRL_new(void);

/*!
    \ingroup CertsKeys

    \brief Creates new GENERAL_NAME structure.

    \return WOLFSSL_GENERAL_NAME* Pointer to new structure
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    if (gn != NULL) {
        wolfSSL_GENERAL_NAME_free(gn);
    }
    \endcode

    \sa wolfSSL_GENERAL_NAME_free
    \sa wolfSSL_GENERAL_NAME_dup
*/
WOLFSSL_GENERAL_NAME* wolfSSL_GENERAL_NAME_new(void);

/*!
    \ingroup CertsKeys

    \brief Frees GENERAL_NAME structure.

    \return none

    \param gn GENERAL_NAME to free

    _Example_
    \code
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    wolfSSL_GENERAL_NAME_free(gn);
    \endcode

    \sa wolfSSL_GENERAL_NAME_new
*/
void wolfSSL_GENERAL_NAME_free(WOLFSSL_GENERAL_NAME* gn);

/*!
    \ingroup CertsKeys

    \brief Duplicates GENERAL_NAME structure.

    \return WOLFSSL_GENERAL_NAME* Pointer to duplicated structure
    \return NULL on failure

    \param gn GENERAL_NAME to duplicate

    _Example_
    \code
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    WOLFSSL_GENERAL_NAME* dup = wolfSSL_GENERAL_NAME_dup(gn);
    if (dup != NULL) {
        wolfSSL_GENERAL_NAME_free(dup);
    }
    wolfSSL_GENERAL_NAME_free(gn);
    \endcode

    \sa wolfSSL_GENERAL_NAME_new
    \sa wolfSSL_GENERAL_NAMES_dup
*/
WOLFSSL_GENERAL_NAME* wolfSSL_GENERAL_NAME_dup(WOLFSSL_GENERAL_NAME* gn);

/*!
    \ingroup CertsKeys

    \brief Sets type for GENERAL_NAME.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param name GENERAL_NAME to set type for
    \param typ Type value to set

    _Example_
    \code
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    int ret = wolfSSL_GENERAL_NAME_set_type(gn, GEN_DNS);
    \endcode

    \sa wolfSSL_GENERAL_NAME_new
*/
int wolfSSL_GENERAL_NAME_set_type(WOLFSSL_GENERAL_NAME* name, int typ);

/*!
    \ingroup CertsKeys

    \brief Duplicates GENERAL_NAMES structure.

    \return WOLFSSL_GENERAL_NAMES* Pointer to duplicated structure
    \return NULL on failure

    \param gns GENERAL_NAMES to duplicate

    _Example_
    \code
    WOLFSSL_GENERAL_NAMES* gns = wolfSSL_sk_GENERAL_NAME_new(NULL);
    WOLFSSL_GENERAL_NAMES* dup = wolfSSL_GENERAL_NAMES_dup(gns);
    if (dup != NULL) {
        wolfSSL_GENERAL_NAMES_free(dup);
    }
    wolfSSL_GENERAL_NAMES_free(gns);
    \endcode

    \sa wolfSSL_GENERAL_NAME_dup
*/
WOLFSSL_GENERAL_NAMES* wolfSSL_GENERAL_NAMES_dup(
    WOLFSSL_GENERAL_NAMES* gns);

/*!
    \ingroup CertsKeys

    \brief Sets othername for GENERAL_NAME.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param gen GENERAL_NAME to set othername for
    \param oid OID for othername
    \param value Value for othername

    _Example_
    \code
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    WOLFSSL_ASN1_OBJECT* oid = wolfSSL_OBJ_txt2obj("1.2.3.4", 1);
    WOLFSSL_ASN1_TYPE* val = wolfSSL_ASN1_TYPE_new();
    int ret = wolfSSL_GENERAL_NAME_set0_othername(gn, oid, val);
    \endcode

    \sa wolfSSL_GENERAL_NAME_set0_value
*/
int wolfSSL_GENERAL_NAME_set0_othername(WOLFSSL_GENERAL_NAME* gen,
                                          WOLFSSL_ASN1_OBJECT* oid,
                                          WOLFSSL_ASN1_TYPE* value);

/*!
    \ingroup CertsKeys

    \brief Sets value for GENERAL_NAME.

    \return none

    \param a GENERAL_NAME to set value for
    \param type Type of value
    \param value Value to set

    _Example_
    \code
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    wolfSSL_GENERAL_NAME_set0_value(gn, GEN_DNS, str);
    \endcode

    \sa wolfSSL_GENERAL_NAME_set0_othername
*/
void wolfSSL_GENERAL_NAME_set0_value(WOLFSSL_GENERAL_NAME* a, int type,
                                      void* value);

/*!
    \ingroup CertsKeys

    \brief Creates new GENERAL_NAME stack.

    \return WOLFSSL_STACK* Pointer to new stack
    \return NULL on failure

    \param cmpFunc Comparison function (can be NULL)

    _Example_
    \code
    WOLFSSL_STACK* gn_stack = wolfSSL_sk_GENERAL_NAME_new(NULL);
    if (gn_stack != NULL) {
        wolfSSL_sk_GENERAL_NAME_free(gn_stack);
    }
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_free
*/
WOLFSSL_STACK* wolfSSL_sk_GENERAL_NAME_new(void* cmpFunc);

/*!
    \ingroup CertsKeys

    \brief Pushes GENERAL_NAME onto stack.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sk Stack to push onto
    \param gn GENERAL_NAME to push

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_GENERAL_NAME_new(NULL);
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    int ret = wolfSSL_sk_GENERAL_NAME_push(sk, gn);
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_value
*/
int wolfSSL_sk_GENERAL_NAME_push(WOLFSSL_GENERAL_NAMES* sk,
                                   WOLFSSL_GENERAL_NAME* gn);

/*!
    \ingroup CertsKeys

    \brief Gets GENERAL_NAME from stack at index.

    \return WOLFSSL_GENERAL_NAME* Pointer to GENERAL_NAME
    \return NULL if index is invalid

    \param sk Stack to get from
    \param i Index of element to retrieve

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_GENERAL_NAME_new(NULL);
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_sk_GENERAL_NAME_value(sk, 0);
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_push
    \sa wolfSSL_sk_GENERAL_NAME_num
*/
WOLFSSL_GENERAL_NAME* wolfSSL_sk_GENERAL_NAME_value(WOLFSSL_STACK* sk,
                                                      int i);

/*!
    \ingroup CertsKeys

    \brief Gets number of GENERAL_NAMEs in stack.

    \return int Number of elements
    \return 0 if stack is NULL

    \param sk Stack to query

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_GENERAL_NAME_new(NULL);
    int count = wolfSSL_sk_GENERAL_NAME_num(sk);
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_value
*/
int wolfSSL_sk_GENERAL_NAME_num(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys

    \brief Frees GENERAL_NAME stack.

    \return none

    \param sk Stack to free

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_GENERAL_NAME_new(NULL);
    wolfSSL_sk_GENERAL_NAME_free(sk);
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_new
*/
void wolfSSL_sk_GENERAL_NAME_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys

    \brief Frees GENERAL_NAMES structure.

    \return none

    \param name GENERAL_NAMES to free

    _Example_
    \code
    WOLFSSL_GENERAL_NAMES* gns = wolfSSL_sk_GENERAL_NAME_new(NULL);
    wolfSSL_GENERAL_NAMES_free(gns);
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_free
*/
void wolfSSL_GENERAL_NAMES_free(WOLFSSL_GENERAL_NAMES* name);

/*!
    \ingroup CertsKeys

    \brief Prints GENERAL_NAME to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param out BIO to write to
    \param name GENERAL_NAME to print

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    WOLFSSL_GENERAL_NAME* gn = wolfSSL_GENERAL_NAME_new();
    int ret = wolfSSL_GENERAL_NAME_print(bio, gn);
    \endcode

    \sa wolfSSL_GENERAL_NAME_new
*/
int wolfSSL_GENERAL_NAME_print(WOLFSSL_BIO* out,
                                 WOLFSSL_GENERAL_NAME* name);

/*!
    \ingroup CertsKeys

    \brief Frees EXTENDED_KEY_USAGE stack.

    \return none

    \param sk Stack to free

    _Example_
    \code
    WOLFSSL_STACK* eku = wolfSSL_X509_get_ext_d2i(x509,
                                                    NID_ext_key_usage,
                                                    NULL, NULL);
    wolfSSL_EXTENDED_KEY_USAGE_free(eku);
    \endcode

    \sa wolfSSL_X509_get_ext_d2i
*/
void wolfSSL_EXTENDED_KEY_USAGE_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys

    \brief Creates new DIST_POINT structure.

    \return WOLFSSL_DIST_POINT* Pointer to new structure
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_DIST_POINT* dp = wolfSSL_DIST_POINT_new();
    if (dp != NULL) {
        // use the distribution point
    }
    \endcode

    \sa wolfSSL_DIST_POINT_free
*/
WOLFSSL_DIST_POINT* wolfSSL_DIST_POINT_new(void);

/*!
    \ingroup CertsKeys

    \brief Frees DIST_POINT structure.

    \return none

    \param dp DIST_POINT to free

    _Example_
    \code
    WOLFSSL_DIST_POINT* dp = wolfSSL_DIST_POINT_new();
    wolfSSL_DIST_POINT_free(dp);
    \endcode

    \sa wolfSSL_DIST_POINT_new
*/
void wolfSSL_DIST_POINT_free(WOLFSSL_DIST_POINT* dp);

/*!
    \ingroup CertsKeys

    \brief Pushes DIST_POINT onto stack.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sk Stack to push onto
    \param dp DIST_POINT to push

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    WOLFSSL_DIST_POINT* dp = wolfSSL_DIST_POINT_new();
    int ret = wolfSSL_sk_DIST_POINT_push(sk, dp);
    \endcode

    \sa wolfSSL_sk_DIST_POINT_value
*/
int wolfSSL_sk_DIST_POINT_push(WOLFSSL_DIST_POINTS* sk,
                                 WOLFSSL_DIST_POINT* dp);

/*!
    \ingroup CertsKeys

    \brief Gets DIST_POINT from stack at index.

    \return WOLFSSL_DIST_POINT* Pointer to DIST_POINT
    \return NULL if index is invalid

    \param sk Stack to get from
    \param i Index of element to retrieve

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    WOLFSSL_DIST_POINT* dp = wolfSSL_sk_DIST_POINT_value(sk, 0);
    \endcode

    \sa wolfSSL_sk_DIST_POINT_push
    \sa wolfSSL_sk_DIST_POINT_num
*/
WOLFSSL_DIST_POINT* wolfSSL_sk_DIST_POINT_value(WOLFSSL_STACK* sk, int i);

/*!
    \ingroup CertsKeys

    \brief Gets number of DIST_POINTs in stack.

    \return int Number of elements
    \return 0 if stack is NULL

    \param sk Stack to query

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    int count = wolfSSL_sk_DIST_POINT_num(sk);
    \endcode

    \sa wolfSSL_sk_DIST_POINT_value
*/
int wolfSSL_sk_DIST_POINT_num(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys

    \brief Frees DIST_POINT stack.

    \return none

    \param sk Stack to free

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_null();
    wolfSSL_sk_DIST_POINT_free(sk);
    \endcode

    \sa wolfSSL_sk_DIST_POINT_push
*/
void wolfSSL_sk_DIST_POINT_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys

    \brief Frees DIST_POINTS structure.

    \return none

    \param dp DIST_POINTS to free

    _Example_
    \code
    WOLFSSL_DIST_POINTS* dp = wolfSSL_X509_get_ext_d2i(x509,
                                                         NID_crl_dist_points,
                                                         NULL, NULL);
    wolfSSL_DIST_POINTS_free(dp);
    \endcode

    \sa wolfSSL_sk_DIST_POINT_free
*/
void wolfSSL_DIST_POINTS_free(WOLFSSL_DIST_POINTS* dp);

/*!
    \ingroup CertsKeys

    \brief Gets number of ACCESS_DESCRIPTIONs in stack.

    \return int Number of elements
    \return 0 if stack is NULL

    \param sk Stack to query

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_X509_get_ext_d2i(x509,
                                                   NID_info_access,
                                                   NULL, NULL);
    int count = wolfSSL_sk_ACCESS_DESCRIPTION_num(sk);
    \endcode

    \sa wolfSSL_sk_ACCESS_DESCRIPTION_value
*/
int wolfSSL_sk_ACCESS_DESCRIPTION_num(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys

    \brief Gets ACCESS_DESCRIPTION from stack at index.

    \return WOLFSSL_ACCESS_DESCRIPTION* Pointer to ACCESS_DESCRIPTION
    \return NULL if index is invalid

    \param sk Stack to get from
    \param idx Index of element to retrieve

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_X509_get_ext_d2i(x509,
                                                   NID_info_access,
                                                   NULL, NULL);
    WOLFSSL_ACCESS_DESCRIPTION* ad =
        wolfSSL_sk_ACCESS_DESCRIPTION_value(sk, 0);
    \endcode

    \sa wolfSSL_sk_ACCESS_DESCRIPTION_num
*/
WOLFSSL_ACCESS_DESCRIPTION* wolfSSL_sk_ACCESS_DESCRIPTION_value(
    WOLFSSL_STACK* sk, int idx);

/*!
    \ingroup CertsKeys

    \brief Frees ACCESS_DESCRIPTION stack.

    \return none

    \param sk Stack to free

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_X509_get_ext_d2i(x509,
                                                   NID_info_access,
                                                   NULL, NULL);
    wolfSSL_sk_ACCESS_DESCRIPTION_free(sk);
    \endcode

    \sa wolfSSL_ACCESS_DESCRIPTION_free
*/
void wolfSSL_sk_ACCESS_DESCRIPTION_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys

    \brief Frees ACCESS_DESCRIPTION structure.

    \return none

    \param a ACCESS_DESCRIPTION to free

    _Example_
    \code
    WOLFSSL_ACCESS_DESCRIPTION* ad =
        wolfSSL_sk_ACCESS_DESCRIPTION_value(sk, 0);
    wolfSSL_ACCESS_DESCRIPTION_free(ad);
    \endcode

    \sa wolfSSL_sk_ACCESS_DESCRIPTION_free
*/
void wolfSSL_ACCESS_DESCRIPTION_free(WOLFSSL_ACCESS_DESCRIPTION* a);

/*!
    \ingroup ASN

    \brief Creates new ASN1_OBJECT structure.

    \return WOLFSSL_ASN1_OBJECT* Pointer to new structure
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_ASN1_OBJECT_new();
    if (obj != NULL) {
        wolfSSL_ASN1_OBJECT_free(obj);
    }
    \endcode

    \sa wolfSSL_ASN1_OBJECT_free
    \sa wolfSSL_ASN1_OBJECT_dup
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_new(void);

/*!
    \ingroup ASN

    \brief Duplicates ASN1_OBJECT structure.

    \return WOLFSSL_ASN1_OBJECT* Pointer to duplicated structure
    \return NULL on failure

    \param obj ASN1_OBJECT to duplicate

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_ASN1_OBJECT_new();
    WOLFSSL_ASN1_OBJECT* dup = wolfSSL_ASN1_OBJECT_dup(obj);
    if (dup != NULL) {
        wolfSSL_ASN1_OBJECT_free(dup);
    }
    wolfSSL_ASN1_OBJECT_free(obj);
    \endcode

    \sa wolfSSL_ASN1_OBJECT_new
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_dup(WOLFSSL_ASN1_OBJECT* obj);

/*!
    \ingroup ASN

    \brief Frees ASN1_OBJECT structure.

    \return none

    \param obj ASN1_OBJECT to free

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_ASN1_OBJECT_new();
    wolfSSL_ASN1_OBJECT_free(obj);
    \endcode

    \sa wolfSSL_ASN1_OBJECT_new
*/
void wolfSSL_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT* obj);

/*!
    \ingroup ASN

    \brief Creates new ASN1_OBJECT stack.

    \return WOLFSSL_STACK* Pointer to new stack
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_asn1_obj();
    if (sk != NULL) {
        wolfSSL_sk_free(sk);
    }
    \endcode

    \sa wolfSSL_sk_free
*/
WOLFSSL_STACK* wolfSSL_sk_new_asn1_obj(void);

/*!
    \ingroup ASN

    \brief Converts ASN1_STRING to UTF8.

    \return int Length of UTF8 string on success
    \return negative value on failure

    \param out Pointer to store UTF8 string (allocated by function)
    \param in ASN1_STRING to convert

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_X509_NAME_ENTRY_get_data(entry);
    unsigned char* utf8 = NULL;
    int len = wolfSSL_ASN1_STRING_to_UTF8(&utf8, str);
    if (len > 0) {
        printf("UTF8: %s\n", utf8);
        OPENSSL_free(utf8);
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_data
*/
int wolfSSL_ASN1_STRING_to_UTF8(unsigned char** out,
                                 WOLFSSL_ASN1_STRING* in);

/*!
    \ingroup ASN

    \brief Converts UNIVERSALSTRING to string.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s ASN1_STRING to convert

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    int ret = wolfSSL_ASN1_UNIVERSALSTRING_to_string(str);
    \endcode

    \sa wolfSSL_ASN1_STRING_to_UTF8
*/
int wolfSSL_ASN1_UNIVERSALSTRING_to_string(WOLFSSL_ASN1_STRING* s);

/*!
    \ingroup CertsKeys

    \brief Increments RSA reference count.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param rsa RSA structure to increment reference count for

    _Example_
    \code
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    int ret = wolfSSL_RSA_up_ref(rsa);
    if (ret == WOLFSSL_SUCCESS) {
        // reference count incremented
    }
    \endcode

    \sa wolfSSL_RSA_free
*/
int wolfSSL_RSA_up_ref(WOLFSSL_RSA* rsa);

/*!
    \ingroup CertsKeys

    \brief Increments X509 reference count.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 X509 structure to increment reference count for

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    int ret = wolfSSL_X509_up_ref(x509);
    if (ret == WOLFSSL_SUCCESS) {
        // reference count incremented
    }
    \endcode

    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_up_ref(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Increments EVP_PKEY reference count.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param pkey EVP_PKEY structure to increment reference count for

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    int ret = wolfSSL_EVP_PKEY_up_ref(pkey);
    if (ret == WOLFSSL_SUCCESS) {
        // reference count incremented
    }
    \endcode

    \sa wolfSSL_EVP_PKEY_free
*/
int wolfSSL_EVP_PKEY_up_ref(WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief Parses OCSP URL into components.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param url URL to parse
    \param host Pointer to store host (allocated by function)
    \param port Pointer to store port (allocated by function)
    \param path Pointer to store path (allocated by function)
    \param ssl Pointer to store SSL flag

    _Example_
    \code
    const char* url = "http://ocsp.example.com:80/status";
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;
    int ssl_flag;
    int ret = wolfSSL_OCSP_parse_url(url, &host, &port, &path,
                                      &ssl_flag);
    if (ret == WOLFSSL_SUCCESS) {
        printf("Host: %s, Port: %s, Path: %s\n", host, port, path);
        XFREE(host, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(port, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(path, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_OCSP_cert_to_id
*/
int wolfSSL_OCSP_parse_url(const char* url, char** host, char** port,
                             char** path, int* ssl);

/*!
    \ingroup BIO

    \brief Creates new BIO with specified method.

    \return WOLFSSL_BIO* Pointer to new BIO
    \return NULL on failure

    \param method BIO method to use

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
    }
    \endcode

    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_s_mem
*/
WOLFSSL_BIO* wolfSSL_BIO_new(const WOLFSSL_BIO_METHOD* method);

/*!
    \ingroup BIO

    \brief Frees BIO structure.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to free

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_BIO_free(bio);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free_all
*/
int wolfSSL_BIO_free(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Frees BIO structure (void return).

    \return none

    \param bio BIO to free

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_vfree(bio);
    \endcode

    \sa wolfSSL_BIO_free
*/
void wolfSSL_BIO_vfree(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Frees BIO chain.

    \return none

    \param bio BIO chain to free

    _Example_
    \code
    WOLFSSL_BIO* bio1 = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BIO* bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_push(bio1, bio2);
    wolfSSL_BIO_free_all(bio1);
    \endcode

    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_push
*/
void wolfSSL_BIO_free_all(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Reads a line from BIO.

    \return int Number of bytes read on success
    \return negative value on failure

    \param bio BIO to read from
    \param buf Buffer to store data
    \param sz Size of buffer

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    char buffer[256];
    int ret = wolfSSL_BIO_gets(bio, buffer, sizeof(buffer));
    if (ret > 0) {
        printf("Read: %s\n", buffer);
    }
    \endcode

    \sa wolfSSL_BIO_read
    \sa wolfSSL_BIO_write
*/
int wolfSSL_BIO_gets(WOLFSSL_BIO* bio, char* buf, int sz);

/*!
    \ingroup BIO

    \brief Writes a string to BIO.

    \return int Number of bytes written on success
    \return negative value on failure

    \param bio BIO to write to
    \param buf String to write

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_BIO_puts(bio, "Hello World");
    if (ret > 0) {
        printf("Wrote %d bytes\n", ret);
    }
    \endcode

    \sa wolfSSL_BIO_write
    \sa wolfSSL_BIO_gets
*/
int wolfSSL_BIO_puts(WOLFSSL_BIO* bio, const char* buf);

/*!
    \ingroup BIO

    \brief Gets next BIO in chain.

    \return WOLFSSL_BIO* Pointer to next BIO
    \return NULL if no next BIO

    \param bio BIO to get next from

    _Example_
    \code
    WOLFSSL_BIO* bio1 = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BIO* bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_push(bio1, bio2);
    WOLFSSL_BIO* next = wolfSSL_BIO_next(bio1);
    \endcode

    \sa wolfSSL_BIO_push
*/
WOLFSSL_BIO* wolfSSL_BIO_next(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Finds BIO of specified type in chain.

    \return WOLFSSL_BIO* Pointer to BIO of specified type
    \return NULL if not found

    \param bio BIO chain to search
    \param type BIO type to find

    _Example_
    \code
    WOLFSSL_BIO* chain = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BIO* found = wolfSSL_BIO_find_type(chain, BIO_TYPE_MEM);
    \endcode

    \sa wolfSSL_BIO_next
*/
WOLFSSL_BIO* wolfSSL_BIO_find_type(WOLFSSL_BIO* bio, int type);

/*!
    \ingroup BIO

    \brief Reads data from BIO.

    \return int Number of bytes read on success
    \return negative value on failure

    \param bio BIO to read from
    \param buf Buffer to store data
    \param len Maximum bytes to read

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    char buffer[256];
    int ret = wolfSSL_BIO_read(bio, buffer, sizeof(buffer));
    if (ret > 0) {
        printf("Read %d bytes\n", ret);
    }
    \endcode

    \sa wolfSSL_BIO_write
    \sa wolfSSL_BIO_gets
*/
int wolfSSL_BIO_read(WOLFSSL_BIO* bio, void* buf, int len);

/*!
    \ingroup BIO

    \brief Writes data to BIO.

    \return int Number of bytes written on success
    \return negative value on failure

    \param bio BIO to write to
    \param data Data to write
    \param len Number of bytes to write

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    const char* msg = "Hello";
    int ret = wolfSSL_BIO_write(bio, msg, strlen(msg));
    if (ret > 0) {
        printf("Wrote %d bytes\n", ret);
    }
    \endcode

    \sa wolfSSL_BIO_read
    \sa wolfSSL_BIO_puts
*/
int wolfSSL_BIO_write(WOLFSSL_BIO* bio, const void* data, int len);

/*!
    \ingroup BIO

    \brief Pushes BIO onto chain.

    \return WOLFSSL_BIO* Pointer to top of chain
    \return NULL on failure

    \param top Top of BIO chain
    \param append BIO to append

    _Example_
    \code
    WOLFSSL_BIO* bio1 = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BIO* bio2 = wolfSSL_BIO_new(wolfSSL_BIO_f_base64());
    WOLFSSL_BIO* chain = wolfSSL_BIO_push(bio1, bio2);
    \endcode

    \sa wolfSSL_BIO_pop
*/
WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO* top, WOLFSSL_BIO* append);

/*!
    \ingroup BIO

    \brief Pops BIO from chain.

    \return WOLFSSL_BIO* Pointer to next BIO in chain
    \return NULL if no next BIO

    \param bio BIO to pop

    _Example_
    \code
    WOLFSSL_BIO* bio1 = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BIO* bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_push(bio1, bio2);
    WOLFSSL_BIO* next = wolfSSL_BIO_pop(bio1);
    \endcode

    \sa wolfSSL_BIO_push
*/
WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Flushes BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to flush

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_write(bio, "data", 4);
    int ret = wolfSSL_BIO_flush(bio);
    \endcode

    \sa wolfSSL_BIO_write
*/
int wolfSSL_BIO_flush(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Gets number of pending bytes in BIO.

    \return int Number of pending bytes
    \return 0 if no pending data

    \param bio BIO to query

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_write(bio, "data", 4);
    int pending = wolfSSL_BIO_pending(bio);
    printf("Pending: %d bytes\n", pending);
    \endcode

    \sa wolfSSL_BIO_read
*/
int wolfSSL_BIO_pending(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Sets BIO callback function.

    \return none

    \param bio BIO to set callback for
    \param callback_func Callback function to set

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_set_callback(bio, my_callback);
    \endcode

    \sa wolfSSL_BIO_get_callback
*/
void wolfSSL_BIO_set_callback(WOLFSSL_BIO* bio,
                               wolf_bio_info_cb callback_func);

/*!
    \ingroup BIO

    \brief Gets BIO callback function.

    \return wolf_bio_info_cb Callback function
    \return NULL if no callback set

    \param bio BIO to get callback from

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolf_bio_info_cb cb = wolfSSL_BIO_get_callback(bio);
    \endcode

    \sa wolfSSL_BIO_set_callback
*/
wolf_bio_info_cb wolfSSL_BIO_get_callback(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Sets BIO callback argument.

    \return none

    \param bio BIO to set callback argument for
    \param arg Callback argument to set

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_set_callback_arg(bio, "my_arg");
    \endcode

    \sa wolfSSL_BIO_get_callback_arg
*/
void wolfSSL_BIO_set_callback_arg(WOLFSSL_BIO* bio, char* arg);

/*!
    \ingroup BIO

    \brief Gets BIO callback argument.

    \return char* Callback argument
    \return NULL if no argument set

    \param bio BIO to get callback argument from

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    char* arg = wolfSSL_BIO_get_callback_arg(bio);
    \endcode

    \sa wolfSSL_BIO_set_callback_arg
*/
char* wolfSSL_BIO_get_callback_arg(const WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Gets message digest BIO method.

    \return WOLFSSL_BIO_METHOD* Pointer to BIO method
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_f_md();
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(method);
    \endcode

    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_md(void);

/*!
    \ingroup BIO

    \brief Gets message digest context from BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to get context from
    \param mdcp Pointer to store context pointer

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_md());
    WOLFSSL_EVP_MD_CTX* ctx = NULL;
    int ret = wolfSSL_BIO_get_md_ctx(bio, &ctx);
    \endcode

    \sa wolfSSL_BIO_f_md
*/
int wolfSSL_BIO_get_md_ctx(WOLFSSL_BIO* bio, WOLFSSL_EVP_MD_CTX** mdcp);

/*!
    \ingroup BIO

    \brief Gets buffer BIO method.

    \return WOLFSSL_BIO_METHOD* Pointer to BIO method
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_f_buffer();
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(method);
    \endcode

    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void);

/*!
    \ingroup BIO

    \brief Sets write buffer size for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to set buffer size for
    \param size Buffer size to set

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_buffer());
    long ret = wolfSSL_BIO_set_write_buffer_size(bio, 8192);
    \endcode

    \sa wolfSSL_BIO_f_buffer
*/
long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO* bio, long size);

/*!
    \ingroup BIO

    \brief Gets SSL BIO method.

    \return WOLFSSL_BIO_METHOD* Pointer to BIO method
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_f_ssl();
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(method);
    \endcode

    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void);

/*!
    \ingroup BIO

    \brief Creates new socket BIO.

    \return WOLFSSL_BIO* Pointer to new BIO
    \return NULL on failure

    \param sfd Socket file descriptor
    \param flag Close flag

    _Example_
    \code
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_socket(sockfd, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO* wolfSSL_BIO_new_socket(int sfd, int flag);

/*!
    \ingroup BIO

    \brief Creates new datagram BIO.

    \return WOLFSSL_BIO* Pointer to new BIO
    \return NULL on failure

    \param fd File descriptor
    \param closeF Close flag

    _Example_
    \code
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_dgram(sockfd, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_new_socket
*/
WOLFSSL_BIO* wolfSSL_BIO_new_dgram(int fd, int closeF);

/*!
    \ingroup BIO

    \brief Checks if BIO is at end of file.

    \return 1 if at EOF
    \return 0 if not at EOF

    \param b BIO to check

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    if (wolfSSL_BIO_eof(bio)) {
        printf("At end of file\n");
    }
    \endcode

    \sa wolfSSL_BIO_read
*/
int wolfSSL_BIO_eof(WOLFSSL_BIO* b);

/*!
    \ingroup BIO

    \brief Gets memory BIO method.

    \return WOLFSSL_BIO_METHOD* Pointer to BIO method
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_s_mem();
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(method);
    \endcode

    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void);

/*!
    \ingroup BIO

    \brief Gets base64 BIO method.

    \return WOLFSSL_BIO_METHOD* Pointer to BIO method
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_f_base64();
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(method);
    \endcode

    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void);

/*!
    \ingroup BIO

    \brief Sets BIO flags.

    \return none

    \param bio BIO to set flags for
    \param flags Flags to set

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    \endcode

    \sa wolfSSL_BIO_clear_flags
*/
void wolfSSL_BIO_set_flags(WOLFSSL_BIO* bio, int flags);

/*!
    \ingroup BIO

    \brief Clears BIO flags.

    \return none

    \param bio BIO to clear flags for
    \param flags Flags to clear

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_clear_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    \endcode

    \sa wolfSSL_BIO_set_flags
*/
void wolfSSL_BIO_clear_flags(WOLFSSL_BIO* bio, int flags);

/*!
    \ingroup BIO

    \brief Gets file descriptor from BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to get file descriptor from
    \param fd Pointer to store file descriptor

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    int fd;
    int ret = wolfSSL_BIO_get_fd(bio, &fd);
    if (ret == WOLFSSL_SUCCESS) {
        printf("File descriptor: %d\n", fd);
    }
    \endcode

    \sa wolfSSL_BIO_new_socket
*/
int wolfSSL_BIO_get_fd(WOLFSSL_BIO* bio, int* fd);

/*!
    \ingroup BIO

    \brief Sets extra data on BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to set data on
    \param idx Index for data
    \param data Data to set

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_BIO_set_ex_data(bio, 0, my_data);
    \endcode

    \sa wolfSSL_BIO_get_ex_data
*/
int wolfSSL_BIO_set_ex_data(WOLFSSL_BIO* bio, int idx, void* data);

/*!
    \ingroup BIO

    \brief Sets extra data on BIO with cleanup callback.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to set data on
    \param idx Index for data
    \param data Data to set
    \param cleanup_routine Cleanup callback function

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_BIO_set_ex_data_with_cleanup(bio, 0, my_data,
                                                     my_cleanup);
    \endcode

    \sa wolfSSL_BIO_set_ex_data
*/
int wolfSSL_BIO_set_ex_data_with_cleanup(WOLFSSL_BIO* bio, int idx,
    void* data, wolfSSL_ex_data_cleanup_routine_t cleanup_routine);

/*!
    \ingroup BIO

    \brief Sets non-blocking mode for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to set mode for
    \param on Non-zero to enable non-blocking

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_socket(sockfd, BIO_CLOSE);
    long ret = wolfSSL_BIO_set_nbio(bio, 1);
    \endcode

    \sa wolfSSL_BIO_new_socket
*/
long wolfSSL_BIO_set_nbio(WOLFSSL_BIO* bio, long on);

/*!
    \ingroup BIO

    \brief Sets BIO initialization flag.

    \return none

    \param bio BIO to set flag for
    \param init Initialization flag value

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_set_init(bio, 1);
    \endcode

    \sa wolfSSL_BIO_set_data
*/
void wolfSSL_BIO_set_init(WOLFSSL_BIO* bio, int init);

/*!
    \ingroup BIO

    \brief Sets BIO data pointer.

    \return none

    \param bio BIO to set data for
    \param ptr Data pointer to set

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_set_data(bio, my_data);
    \endcode

    \sa wolfSSL_BIO_get_data
*/
void wolfSSL_BIO_set_data(WOLFSSL_BIO* bio, void* ptr);

/*!
    \ingroup BIO

    \brief Gets BIO data pointer.

    \return void* Data pointer
    \return NULL if no data set

    \param bio BIO to get data from

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    void* data = wolfSSL_BIO_get_data(bio);
    \endcode

    \sa wolfSSL_BIO_set_data
*/
void* wolfSSL_BIO_get_data(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Sets BIO shutdown flag.

    \return none

    \param bio BIO to set flag for
    \param shut Shutdown flag value

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_socket(sockfd, BIO_NOCLOSE);
    wolfSSL_BIO_set_shutdown(bio, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_get_shutdown
*/
void wolfSSL_BIO_set_shutdown(WOLFSSL_BIO* bio, int shut);

/*!
    \ingroup BIO

    \brief Gets BIO shutdown flag.

    \return int Shutdown flag value

    \param bio BIO to get flag from

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_socket(sockfd, BIO_CLOSE);
    int shut = wolfSSL_BIO_get_shutdown(bio);
    \endcode

    \sa wolfSSL_BIO_set_shutdown
*/
int wolfSSL_BIO_get_shutdown(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Clears BIO retry flags.

    \return none

    \param bio BIO to clear flags for

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    wolfSSL_BIO_clear_retry_flags(bio);
    \endcode

    \sa wolfSSL_BIO_should_retry
*/
void wolfSSL_BIO_clear_retry_flags(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Checks if BIO should retry operation.

    \return 1 if should retry
    \return 0 if should not retry

    \param bio BIO to check

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    int ret = wolfSSL_BIO_read(bio, buf, len);
    if (ret < 0 && wolfSSL_BIO_should_retry(bio)) {
        // retry the operation
    }
    \endcode

    \sa wolfSSL_BIO_should_read
    \sa wolfSSL_BIO_should_write
*/
int wolfSSL_BIO_should_retry(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Checks if BIO should retry read.

    \return 1 if should retry read
    \return 0 if should not retry

    \param bio BIO to check

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    if (wolfSSL_BIO_should_read(bio)) {
        // retry read operation
    }
    \endcode

    \sa wolfSSL_BIO_should_retry
*/
int wolfSSL_BIO_should_read(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Checks if BIO should retry write.

    \return 1 if should retry write
    \return 0 if should not retry

    \param bio BIO to check

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    if (wolfSSL_BIO_should_write(bio)) {
        // retry write operation
    }
    \endcode

    \sa wolfSSL_BIO_should_retry
*/
int wolfSSL_BIO_should_write(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Frees BIO method.

    \return none

    \param biom BIO method to free

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    wolfSSL_BIO_meth_free(method);
    \endcode

    \sa wolfSSL_BIO_meth_new
*/
void wolfSSL_BIO_meth_free(WOLFSSL_BIO_METHOD* biom);

/*!
    \ingroup BIO

    \brief Sets write callback for BIO method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param biom BIO method to set callback for
    \param biom_write Write callback function

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    int ret = wolfSSL_BIO_meth_set_write(method, my_write_cb);
    \endcode

    \sa wolfSSL_BIO_meth_set_read
*/
int wolfSSL_BIO_meth_set_write(WOLFSSL_BIO_METHOD* biom,
                                 wolfSSL_BIO_meth_write_cb biom_write);

/*!
    \ingroup BIO

    \brief Sets read callback for BIO method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param biom BIO method to set callback for
    \param biom_read Read callback function

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    int ret = wolfSSL_BIO_meth_set_read(method, my_read_cb);
    \endcode

    \sa wolfSSL_BIO_meth_set_write
*/
int wolfSSL_BIO_meth_set_read(WOLFSSL_BIO_METHOD* biom,
                                wolfSSL_BIO_meth_read_cb biom_read);

/*!
    \ingroup BIO

    \brief Sets puts callback for BIO method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param biom BIO method to set callback for
    \param biom_puts Puts callback function

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    int ret = wolfSSL_BIO_meth_set_puts(method, my_puts_cb);
    \endcode

    \sa wolfSSL_BIO_meth_set_gets
*/
int wolfSSL_BIO_meth_set_puts(WOLFSSL_BIO_METHOD* biom,
                                wolfSSL_BIO_meth_puts_cb biom_puts);

/*!
    \ingroup BIO

    \brief Sets gets callback for BIO method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param biom BIO method to set callback for
    \param biom_gets Gets callback function

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    int ret = wolfSSL_BIO_meth_set_gets(method, my_gets_cb);
    \endcode

    \sa wolfSSL_BIO_meth_set_puts
*/
int wolfSSL_BIO_meth_set_gets(WOLFSSL_BIO_METHOD* biom,
                                wolfSSL_BIO_meth_gets_cb biom_gets);

/*!
    \ingroup BIO

    \brief Sets control callback for BIO method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param biom BIO method to set callback for
    \param biom_ctrl Control callback function

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    int ret = wolfSSL_BIO_meth_set_ctrl(method, my_ctrl_cb);
    \endcode

    \sa wolfSSL_BIO_meth_set_create
*/
int wolfSSL_BIO_meth_set_ctrl(WOLFSSL_BIO_METHOD* biom,
                                wolfSSL_BIO_meth_ctrl_get_cb biom_ctrl);

/*!
    \ingroup BIO

    \brief Sets create callback for BIO method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param biom BIO method to set callback for
    \param biom_create Create callback function

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    int ret = wolfSSL_BIO_meth_set_create(method, my_create_cb);
    \endcode

    \sa wolfSSL_BIO_meth_set_destroy
*/
int wolfSSL_BIO_meth_set_create(WOLFSSL_BIO_METHOD* biom,
                                  wolfSSL_BIO_meth_create_cb biom_create);

/*!
    \ingroup BIO

    \brief Sets destroy callback for BIO method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param biom BIO method to set callback for
    \param biom_destroy Destroy callback function

    _Example_
    \code
    WOLFSSL_BIO_METHOD* method = wolfSSL_BIO_meth_new(BIO_TYPE_MEM,
                                                       "my_bio");
    int ret = wolfSSL_BIO_meth_set_destroy(method, my_destroy_cb);
    \endcode

    \sa wolfSSL_BIO_meth_set_create
*/
int wolfSSL_BIO_meth_set_destroy(WOLFSSL_BIO_METHOD* biom,
                                   wolfSSL_BIO_meth_destroy_cb biom_destroy);

/*!
    \ingroup BIO

    \brief Creates new memory BIO from buffer.

    \return WOLFSSL_BIO* Pointer to new BIO
    \return NULL on failure

    \param buf Buffer to use
    \param len Length of buffer (-1 for null-terminated string)

    _Example_
    \code
    const char* data = "Hello World";
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_mem_buf(data, -1);
    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
    }
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(const void* buf, int len);

/*!
    \ingroup BIO

    \brief Sets SSL object for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO to set SSL for
    \param ssl SSL object to set
    \param flag Close flag

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    WOLFSSL* ssl = wolfSSL_new(ctx);
    long ret = wolfSSL_BIO_set_ssl(bio, ssl, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_get_ssl
*/
long wolfSSL_BIO_set_ssl(WOLFSSL_BIO* b, WOLFSSL* ssl, int flag);

/*!
    \ingroup BIO

    \brief Gets SSL object from BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to get SSL from
    \param ssl Pointer to store SSL object

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    WOLFSSL* ssl = NULL;
    long ret = wolfSSL_BIO_get_ssl(bio, &ssl);
    \endcode

    \sa wolfSSL_BIO_set_ssl
*/
long wolfSSL_BIO_get_ssl(WOLFSSL_BIO* bio, WOLFSSL** ssl);

/*!
    \ingroup Setup

    \brief Sets BIO objects for SSL connection.

    \return none

    \param ssl SSL object to set BIOs for
    \param rd Read BIO
    \param wr Write BIO

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_BIO* rbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BIO* wbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_set_bio(ssl, rbio, wbio);
    \endcode

    \sa wolfSSL_get_rbio
    \sa wolfSSL_get_wbio
*/
void wolfSSL_set_bio(WOLFSSL* ssl, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr);

/*!
    \ingroup Setup

    \brief Sets read BIO for SSL connection.

    \return none

    \param ssl SSL object to set BIO for
    \param rd Read BIO

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_BIO* rbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_set_rbio(ssl, rbio);
    \endcode

    \sa wolfSSL_set_bio
    \sa wolfSSL_set_wbio
*/
void wolfSSL_set_rbio(WOLFSSL* ssl, WOLFSSL_BIO* rd);

/*!
    \ingroup Setup

    \brief Sets write BIO for SSL connection.

    \return none

    \param ssl SSL object to set BIO for
    \param wr Write BIO

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_BIO* wbio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_set_wbio(ssl, wbio);
    \endcode

    \sa wolfSSL_set_bio
    \sa wolfSSL_set_rbio
*/
void wolfSSL_set_wbio(WOLFSSL* ssl, WOLFSSL_BIO* wr);

/*!
    \ingroup BIO

    \brief Gets BIO method type.

    \return int BIO type
    \return 0 on failure

    \param b BIO to get type from

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int type = wolfSSL_BIO_method_type(bio);
    if (type == BIO_TYPE_MEM) {
        printf("Memory BIO\n");
    }
    \endcode

    \sa wolfSSL_BIO_new
*/
int wolfSSL_BIO_method_type(const WOLFSSL_BIO* b);

/*!
    \ingroup BIO

    \brief Sets connection hostname for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO to set hostname for
    \param name Hostname to connect to

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_connect());
    long ret = wolfSSL_BIO_set_conn_hostname(bio, "example.com:443");
    \endcode

    \sa wolfSSL_BIO_set_conn_port
    \sa wolfSSL_BIO_do_connect
*/
long wolfSSL_BIO_set_conn_hostname(WOLFSSL_BIO* b, char* name);

/*!
    \ingroup BIO

    \brief Sets connection port for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO to set port for
    \param port Port to connect to

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_connect());
    long ret = wolfSSL_BIO_set_conn_port(bio, "443");
    \endcode

    \sa wolfSSL_BIO_set_conn_hostname
*/
long wolfSSL_BIO_set_conn_port(WOLFSSL_BIO* b, char* port);

/*!
    \ingroup BIO

    \brief Initiates connection for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO to connect

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_connect());
    wolfSSL_BIO_set_conn_hostname(bio, "example.com:443");
    long ret = wolfSSL_BIO_do_connect(bio);
    \endcode

    \sa wolfSSL_BIO_set_conn_hostname
*/
long wolfSSL_BIO_do_connect(WOLFSSL_BIO* b);

/*!
    \ingroup BIO

    \brief Accepts connection for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO to accept on

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_accept("8080");
    int ret = wolfSSL_BIO_do_accept(bio);
    \endcode

    \sa wolfSSL_BIO_do_connect
*/
int wolfSSL_BIO_do_accept(WOLFSSL_BIO* b);

/*!
    \ingroup BIO

    \brief Creates new SSL BIO.

    \return WOLFSSL_BIO* Pointer to new BIO
    \return NULL on failure

    \param ctx SSL context to use
    \param client 1 for client mode, 0 for server mode

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_ssl(ctx, 1);
    \endcode

    \sa wolfSSL_BIO_new_ssl_connect
*/
WOLFSSL_BIO* wolfSSL_BIO_new_ssl(WOLFSSL_CTX* ctx, int client);

/*!
    \ingroup BIO

    \brief Creates new SSL connect BIO.

    \return WOLFSSL_BIO* Pointer to new BIO
    \return NULL on failure

    \param ctx SSL context to use

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_ssl_connect(ctx);
    \endcode

    \sa wolfSSL_BIO_new_ssl
*/
WOLFSSL_BIO* wolfSSL_BIO_new_ssl_connect(WOLFSSL_CTX* ctx);

/*!
    \ingroup BIO

    \brief Performs SSL handshake on BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO to perform handshake on

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_ssl_connect(ctx);
    wolfSSL_BIO_set_conn_hostname(bio, "example.com:443");
    long ret = wolfSSL_BIO_do_handshake(bio);
    \endcode

    \sa wolfSSL_BIO_new_ssl_connect
*/
long wolfSSL_BIO_do_handshake(WOLFSSL_BIO* b);

/*!
    \ingroup BIO

    \brief Shuts down SSL connection on BIO.

    \return none

    \param b BIO to shutdown

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_ssl_connect(ctx);
    wolfSSL_BIO_ssl_shutdown(bio);
    \endcode

    \sa wolfSSL_BIO_do_handshake
*/
void wolfSSL_BIO_ssl_shutdown(WOLFSSL_BIO* b);

/*!
    \ingroup BIO

    \brief Performs control operation on BIO.

    \return long Result of control operation
    \return negative value on failure

    \param bp BIO to control
    \param cmd Control command
    \param larg Long argument
    \param parg Pointer argument

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    long ret = wolfSSL_BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL);
    \endcode

    \sa wolfSSL_BIO_int_ctrl
*/
long wolfSSL_BIO_ctrl(WOLFSSL_BIO* bp, int cmd, long larg, void* parg);

/*!
    \ingroup BIO

    \brief Performs integer control operation on BIO.

    \return long Result of control operation
    \return negative value on failure

    \param bp BIO to control
    \param cmd Control command
    \param larg Long argument
    \param iarg Integer argument

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    long ret = wolfSSL_BIO_int_ctrl(bio, BIO_C_SET_BUF_MEM_EOF_RETURN,
                                     0, -1);
    \endcode

    \sa wolfSSL_BIO_ctrl
*/
long wolfSSL_BIO_int_ctrl(WOLFSSL_BIO* bp, int cmd, long larg, int iarg);

/*!
    \ingroup BIO

    \brief Increments BIO reference count.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO to increment reference count for

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_BIO_up_ref(bio);
    \endcode

    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_up_ref(WOLFSSL_BIO* b);

/*!
    \ingroup BIO

    \brief Gets number of bytes read from BIO.

    \return word64 Number of bytes read

    \param bio BIO to query

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    word64 read = wolfSSL_BIO_number_read(bio);
    printf("Read %llu bytes\n", read);
    \endcode

    \sa wolfSSL_BIO_number_written
*/
word64 wolfSSL_BIO_number_read(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Gets number of bytes written to BIO.

    \return word64 Number of bytes written

    \param bio BIO to query

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    word64 written = wolfSSL_BIO_number_written(bio);
    printf("Written %llu bytes\n", written);
    \endcode

    \sa wolfSSL_BIO_number_read
*/
word64 wolfSSL_BIO_number_written(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Gets current position in BIO.

    \return int Current position
    \return negative value on failure

    \param bio BIO to query

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int pos = wolfSSL_BIO_tell(bio);
    printf("Position: %d\n", pos);
    \endcode

    \sa wolfSSL_BIO_read
*/
int wolfSSL_BIO_tell(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Sets memory buffer for BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to set buffer for
    \param bufMem Buffer to set
    \param closeFlag Close flag

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_BUF_MEM* mem = wolfSSL_BUF_MEM_new();
    int ret = wolfSSL_BIO_set_mem_buf(bio, mem, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_new_mem_buf
*/
int wolfSSL_BIO_set_mem_buf(WOLFSSL_BIO* bio, WOLFSSL_BUF_MEM* bufMem,
                              int closeFlag);

/*!
    \ingroup BIO

    \brief Gets length of data in BIO.

    \return int Length of data
    \return 0 if no data

    \param bio BIO to query

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_write(bio, "data", 4);
    int len = wolfSSL_BIO_get_len(bio);
    printf("Length: %d\n", len);
    \endcode

    \sa wolfSSL_BIO_pending
*/
int wolfSSL_BIO_get_len(WOLFSSL_BIO* bio);

/*!
    \ingroup BIO

    \brief Frees BIO_ADDR structure.

    \return none

    \param addr BIO_ADDR to free

    _Example_
    \code
    WOLFSSL_BIO_ADDR* addr = wolfSSL_BIO_ADDR_new();
    wolfSSL_BIO_ADDR_free(addr);
    \endcode

    \sa wolfSSL_BIO_ADDR_clear
*/
void wolfSSL_BIO_ADDR_free(WOLFSSL_BIO_ADDR* addr);

/*!
    \ingroup BIO

    \brief Clears BIO_ADDR structure.

    \return none

    \param addr BIO_ADDR to clear

    _Example_
    \code
    WOLFSSL_BIO_ADDR* addr = wolfSSL_BIO_ADDR_new();
    wolfSSL_BIO_ADDR_clear(addr);
    \endcode

    \sa wolfSSL_BIO_ADDR_free
*/
void wolfSSL_BIO_ADDR_clear(WOLFSSL_BIO_ADDR* addr);

/*!
    \ingroup openSSL

    \brief Seeds random number generator from screen (Windows only).

    \return none

    _Example_
    \code
    wolfSSL_RAND_screen();
    \endcode

    \sa wolfSSL_RAND_seed
*/
void wolfSSL_RAND_screen(void);

/*!
    \ingroup openSSL

    \brief Gets default random file name.

    \return const char* File name
    \return NULL on failure

    \param fname Buffer to store file name
    \param len Length of buffer

    _Example_
    \code
    char fname[256];
    const char* name = wolfSSL_RAND_file_name(fname, sizeof(fname));
    if (name != NULL) {
        printf("RAND file: %s\n", name);
    }
    \endcode

    \sa wolfSSL_RAND_load_file
*/
const char* wolfSSL_RAND_file_name(char* fname, unsigned long len);

/*!
    \ingroup openSSL

    \brief Writes random seed to file.

    \return int Number of bytes written on success
    \return negative value on failure

    \param fname File name to write to

    _Example_
    \code
    int ret = wolfSSL_RAND_write_file("rand.dat");
    if (ret > 0) {
        printf("Wrote %d bytes\n", ret);
    }
    \endcode

    \sa wolfSSL_RAND_load_file
*/
int wolfSSL_RAND_write_file(const char* fname);

/*!
    \ingroup openSSL

    \brief Loads random seed from file.

    \return int Number of bytes read on success
    \return negative value on failure

    \param fname File name to read from
    \param len Maximum bytes to read (-1 for all)

    _Example_
    \code
    int ret = wolfSSL_RAND_load_file("rand.dat", -1);
    if (ret > 0) {
        printf("Loaded %d bytes\n", ret);
    }
    \endcode

    \sa wolfSSL_RAND_write_file
*/
int wolfSSL_RAND_load_file(const char* fname, long len);

/*!
    \ingroup openSSL

    \brief Seeds random number generator from EGD socket.

    \return int Number of bytes read on success
    \return negative value on failure

    \param nm EGD socket path

    _Example_
    \code
    int ret = wolfSSL_RAND_egd("/var/run/egd-pool");
    if (ret > 0) {
        printf("Seeded %d bytes from EGD\n", ret);
    }
    \endcode

    \sa wolfSSL_RAND_seed
*/
int wolfSSL_RAND_egd(const char* nm);

/*!
    \ingroup openSSL

    \brief Seeds random number generator.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param seed Seed data
    \param len Length of seed data

    _Example_
    \code
    unsigned char seed[32];
    // fill seed with random data
    int ret = wolfSSL_RAND_seed(seed, sizeof(seed));
    \endcode

    \sa wolfSSL_RAND_add
*/
int wolfSSL_RAND_seed(const void* seed, int len);

/*!
    \ingroup openSSL

    \brief Cleans up random number generator.

    \return none

    _Example_
    \code
    wolfSSL_RAND_Cleanup();
    \endcode

    \sa wolfSSL_RAND_seed
*/
void wolfSSL_RAND_Cleanup(void);

/*!
    \ingroup openSSL

    \brief Adds entropy to random number generator.

    \return none

    \param add Entropy data to add
    \param len Length of entropy data
    \param entropy Entropy estimate (unused)

    _Example_
    \code
    unsigned char entropy_data[32];
    // fill entropy_data
    wolfSSL_RAND_add(entropy_data, sizeof(entropy_data), 32.0);
    \endcode

    \sa wolfSSL_RAND_seed
*/
void wolfSSL_RAND_add(const void* add, int len, double entropy);

/*!
    \ingroup openSSL

    \brief Polls for entropy.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    _Example_
    \code
    int ret = wolfSSL_RAND_poll();
    if (ret == WOLFSSL_SUCCESS) {
        printf("Successfully polled for entropy\n");
    }
    \endcode

    \sa wolfSSL_RAND_seed
*/
int wolfSSL_RAND_poll(void);

/*!
    \ingroup openSSL

    \brief Gets zlib compression method.

    \return WOLFSSL_COMP_METHOD* Pointer to compression method
    \return NULL if not supported

    _Example_
    \code
    WOLFSSL_COMP_METHOD* method = wolfSSL_COMP_zlib();
    \endcode

    \sa wolfSSL_COMP_rle
*/
WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void);

/*!
    \ingroup openSSL

    \brief Gets RLE compression method.

    \return WOLFSSL_COMP_METHOD* Pointer to compression method
    \return NULL if not supported

    _Example_
    \code
    WOLFSSL_COMP_METHOD* method = wolfSSL_COMP_rle();
    \endcode

    \sa wolfSSL_COMP_zlib
*/
WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void);

/*!
    \ingroup openSSL

    \brief Adds compression method.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param method Compression method ID
    \param data Compression method data

    _Example_
    \code
    int ret = wolfSSL_COMP_add_compression_method(1, NULL);
    \endcode

    \sa wolfSSL_COMP_zlib
*/
int wolfSSL_COMP_add_compression_method(int method, void* data);

/*!
    \ingroup openSSL

    \brief Gets current compression method.

    \return const WOLFSSL_COMP_METHOD* Pointer to compression method
    \return NULL if no compression

    \param ssl SSL object to query

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const WOLFSSL_COMP_METHOD* comp = 
        wolfSSL_get_current_compression(ssl);
    \endcode

    \sa wolfSSL_get_current_expansion
*/
const WOLFSSL_COMP_METHOD* wolfSSL_get_current_compression(
    const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets current expansion method.

    \return const WOLFSSL_COMP_METHOD* Pointer to expansion method
    \return NULL if no expansion

    \param ssl SSL object to query

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const WOLFSSL_COMP_METHOD* exp = 
        wolfSSL_get_current_expansion(ssl);
    \endcode

    \sa wolfSSL_get_current_compression
*/
const WOLFSSL_COMP_METHOD* wolfSSL_get_current_expansion(
    const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets current thread ID.

    \return unsigned long Thread ID

    _Example_
    \code
    unsigned long tid = wolfSSL_thread_id();
    printf("Thread ID: %lu\n", tid);
    \endcode

    \sa wolfSSL_set_locking_callback
*/
unsigned long wolfSSL_thread_id(void);

/*!
    \ingroup openSSL

    \brief Sets locking callback for thread safety.

    \return none

    \param f Locking callback function

    _Example_
    \code
    wolfSSL_set_locking_callback(my_locking_callback);
    \endcode

    \sa wolfSSL_get_locking_callback
*/
void wolfSSL_set_locking_callback(mutex_cb* f);

/*!
    \ingroup openSSL

    \brief Gets locking callback.

    \return mutex_cb* Locking callback function
    \return NULL if not set

    _Example_
    \code
    mutex_cb* cb = wolfSSL_get_locking_callback();
    \endcode

    \sa wolfSSL_set_locking_callback
*/
mutex_cb* wolfSSL_get_locking_callback(void);

/*!
    \ingroup openSSL

    \brief Gets number of locks.

    \return int Number of locks

    _Example_
    \code
    int num = wolfSSL_num_locks();
    printf("Number of locks: %d\n", num);
    \endcode

    \sa wolfSSL_set_locking_callback
*/
int wolfSSL_num_locks(void);

/*!
    \ingroup CertsKeys

    \brief Gets current certificate from store context.

    \return WOLFSSL_X509* Pointer to current certificate
    \return NULL if no current certificate

    \param ctx Store context to query

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_X509* cert = wolfSSL_X509_STORE_CTX_get_current_cert(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error
*/
WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get_current_cert(
    WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Sets verify callback for store context.

    \return none

    \param ctx Store context to set callback for
    \param verify_cb Verify callback function

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    wolfSSL_X509_STORE_CTX_set_verify_cb(ctx, my_verify_cb);
    \endcode

    \sa wolfSSL_X509_STORE_set_verify_cb
*/
void wolfSSL_X509_STORE_CTX_set_verify_cb(WOLFSSL_X509_STORE_CTX* ctx,
    WOLFSSL_X509_STORE_CTX_verify_cb verify_cb);

/*!
    \ingroup CertsKeys

    \brief Sets verify callback for store.

    \return none

    \param st Store to set callback for
    \param verify_cb Verify callback function

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    wolfSSL_X509_STORE_set_verify_cb(store, my_verify_cb);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_set_verify_cb
*/
void wolfSSL_X509_STORE_set_verify_cb(WOLFSSL_X509_STORE* st,
    WOLFSSL_X509_STORE_CTX_verify_cb verify_cb);

/*!
    \ingroup CertsKeys

    \brief Sets get CRL callback for store.

    \return none

    \param st Store to set callback for
    \param get_cb Get CRL callback function

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    wolfSSL_X509_STORE_set_get_crl(store, my_get_crl_cb);
    \endcode

    \sa wolfSSL_X509_STORE_set_check_crl
*/
void wolfSSL_X509_STORE_set_get_crl(WOLFSSL_X509_STORE* st,
    WOLFSSL_X509_STORE_CTX_get_crl_cb get_cb);

/*!
    \ingroup CertsKeys

    \brief Sets check CRL callback for store.

    \return none

    \param st Store to set callback for
    \param check_crl Check CRL callback function

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    wolfSSL_X509_STORE_set_check_crl(store, my_check_crl_cb);
    \endcode

    \sa wolfSSL_X509_STORE_set_get_crl
*/
void wolfSSL_X509_STORE_set_check_crl(WOLFSSL_X509_STORE* st,
    WOLFSSL_X509_STORE_CTX_check_crl_cb check_crl);

/*!
    \ingroup CertsKeys

    \brief Converts X509_NAME to DER format.

    \return int Length of DER encoding on success
    \return negative value on failure

    \param n X509_NAME to convert
    \param out Pointer to store DER data (allocated by function)

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    unsigned char* der = NULL;
    int len = wolfSSL_i2d_X509_NAME(name, &der);
    if (len > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_X509_NAME
*/
int wolfSSL_i2d_X509_NAME(WOLFSSL_X509_NAME* n, unsigned char** out);

/*!
    \ingroup CertsKeys

    \brief Converts X509_NAME to canonical DER format.

    \return int Length of DER encoding on success
    \return negative value on failure

    \param name X509_NAME to convert
    \param out Pointer to store DER data (allocated by function)

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    unsigned char* der = NULL;
    int len = wolfSSL_i2d_X509_NAME_canon(name, &der);
    if (len > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_i2d_X509_NAME
*/
int wolfSSL_i2d_X509_NAME_canon(WOLFSSL_X509_NAME* name,
                                  unsigned char** out);

/*!
    \ingroup CertsKeys

    \brief Prints RSA key to file.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param fp File pointer to write to
    \param rsa RSA key to print
    \param indent Indentation level

    _Example_
    \code
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    FILE* fp = fopen("rsa_key.txt", "w");
    int ret = wolfSSL_RSA_print_fp(fp, rsa, 0);
    fclose(fp);
    \endcode

    \sa wolfSSL_RSA_print
*/
int wolfSSL_RSA_print_fp(XFILE fp, WOLFSSL_RSA* rsa, int indent);

/*!
    \ingroup CertsKeys

    \brief Prints RSA key to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param rsa RSA key to print
    \param offset Offset for indentation

    _Example_
    \code
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_RSA_print(bio, rsa, 0);
    \endcode

    \sa wolfSSL_RSA_print_fp
*/
int wolfSSL_RSA_print(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa, int offset);

/*!
    \ingroup CertsKeys

    \brief Prints X509 certificate to BIO with flags.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param x509 Certificate to print
    \param nmflags Name flags
    \param cflag Certificate flags

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_X509_print_ex(bio, x509, 0, 0);
    \endcode

    \sa wolfSSL_X509_print
*/
int wolfSSL_X509_print_ex(WOLFSSL_BIO* bio, WOLFSSL_X509* x509,
                           unsigned long nmflags, unsigned long cflag);

/*!
    \ingroup CertsKeys

    \brief Prints X509 certificate to file.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param fp File pointer to write to
    \param x509 Certificate to print

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    FILE* fp = fopen("cert.txt", "w");
    int ret = wolfSSL_X509_print_fp(fp, x509);
    fclose(fp);
    \endcode

    \sa wolfSSL_X509_print
*/
int wolfSSL_X509_print_fp(XFILE fp, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Prints X509 signature to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bp BIO to write to
    \param sigalg Signature algorithm
    \param sig Signature data

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    const WOLFSSL_X509_ALGOR* alg = NULL;
    const WOLFSSL_ASN1_BIT_STRING* sig = NULL;
    wolfSSL_X509_get0_signature(&sig, &alg, x509);
    int ret = wolfSSL_X509_signature_print(bio, alg, sig);
    \endcode

    \sa wolfSSL_X509_get0_signature
*/
int wolfSSL_X509_signature_print(WOLFSSL_BIO* bp,
    const WOLFSSL_X509_ALGOR* sigalg, const WOLFSSL_ASN1_STRING* sig);

/*!
    \ingroup CertsKeys

    \brief Gets signature from X509 certificate.

    \return none

    \param psig Pointer to store signature
    \param palg Pointer to store algorithm
    \param x509 Certificate to get signature from

    _Example_
    \code
    const WOLFSSL_ASN1_BIT_STRING* sig = NULL;
    const WOLFSSL_X509_ALGOR* alg = NULL;
    wolfSSL_X509_get0_signature(&sig, &alg, x509);
    \endcode

    \sa wolfSSL_X509_signature_print
*/
void wolfSSL_X509_get0_signature(const WOLFSSL_ASN1_BIT_STRING** psig,
    const WOLFSSL_X509_ALGOR** palg, const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Prints X509 certificate to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param x509 Certificate to print

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_X509_print(bio, x509);
    \endcode

    \sa wolfSSL_X509_print_fp
*/
int wolfSSL_X509_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Prints X509 request to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param x509 Request to print

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_X509_REQ_new();
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    int ret = wolfSSL_X509_REQ_print(bio, req);
    \endcode

    \sa wolfSSL_X509_print
*/
int wolfSSL_X509_REQ_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Computes hash of X509_NAME.

    \return unsigned long Hash value

    \param name X509_NAME to hash

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    unsigned long hash = wolfSSL_X509_NAME_hash(name);
    printf("Name hash: %lu\n", hash);
    \endcode

    \sa wolfSSL_X509_issuer_name_hash
*/
unsigned long wolfSSL_X509_NAME_hash(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys

    \brief Gets X509_NAME as one-line string.

    \return char* Pointer to name string
    \return NULL on failure

    \param name X509_NAME to convert
    \param in Buffer to store string (NULL to allocate)
    \param sz Size of buffer

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    char* str = wolfSSL_X509_get_name_oneline(name, NULL, 0);
    if (str != NULL) {
        printf("Name: %s\n", str);
        XFREE(str, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_X509_NAME_oneline
*/
char* wolfSSL_X509_get_name_oneline(WOLFSSL_X509_NAME* name, char* in,
                                      int sz);

/*!
    \ingroup CertsKeys

    \brief Computes hash of issuer name.

    \return unsigned long Hash value

    \param x509 Certificate to get issuer from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    unsigned long hash = wolfSSL_X509_issuer_name_hash(x509);
    printf("Issuer hash: %lu\n", hash);
    \endcode

    \sa wolfSSL_X509_subject_name_hash
*/
unsigned long wolfSSL_X509_issuer_name_hash(const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Computes hash of subject name.

    \return unsigned long Hash value

    \param x509 Certificate to get subject from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    unsigned long hash = wolfSSL_X509_subject_name_hash(x509);
    printf("Subject hash: %lu\n", hash);
    \endcode

    \sa wolfSSL_X509_issuer_name_hash
*/
unsigned long wolfSSL_X509_subject_name_hash(const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Checks if extension is set by NID.

    \return 1 if extension is set
    \return 0 if extension is not set

    \param x509 Certificate to check
    \param nid NID of extension

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    if (wolfSSL_X509_ext_isSet_by_NID(x509, NID_basic_constraints)) {
        printf("Basic constraints extension is set\n");
    }
    \endcode

    \sa wolfSSL_X509_ext_get_critical_by_NID
*/
int wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509* x509, int nid);

/*!
    \ingroup CertsKeys

    \brief Gets critical flag for extension by NID.

    \return 1 if extension is critical
    \return 0 if extension is not critical
    \return negative value on error

    \param x509 Certificate to check
    \param nid NID of extension

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    int crit = wolfSSL_X509_ext_get_critical_by_NID(x509,
                                                      NID_key_usage);
    if (crit == 1) {
        printf("Key usage extension is critical\n");
    }
    \endcode

    \sa wolfSSL_X509_ext_isSet_by_NID
*/
int wolfSSL_X509_ext_get_critical_by_NID(WOLFSSL_X509* x509, int nid);

/*!
    \ingroup CertsKeys

    \brief Sets critical flag for extension.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ex Extension to modify
    \param crit Critical flag value

    _Example_
    \code
    WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_EXTENSION_new();
    int ret = wolfSSL_X509_EXTENSION_set_critical(ext, 1);
    \endcode

    \sa wolfSSL_X509_ext_get_critical_by_NID
*/
int wolfSSL_X509_EXTENSION_set_critical(WOLFSSL_X509_EXTENSION* ex,
                                          int crit);

/*!
    \ingroup CertsKeys

    \brief Checks if pathLength is set.

    \return 1 if pathLength is set
    \return 0 if pathLength is not set

    \param x509 Certificate to check

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    if (wolfSSL_X509_get_isSet_pathLength(x509)) {
        unsigned int len = wolfSSL_X509_get_pathLength(x509);
        printf("Path length: %u\n", len);
    }
    \endcode

    \sa wolfSSL_X509_get_pathLength
*/
int wolfSSL_X509_get_isSet_pathLength(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets pathLength from certificate.

    \return unsigned int Path length value

    \param x509 Certificate to get pathLength from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    if (wolfSSL_X509_get_isSet_pathLength(x509)) {
        unsigned int len = wolfSSL_X509_get_pathLength(x509);
        printf("Path length: %u\n", len);
    }
    \endcode

    \sa wolfSSL_X509_get_isSet_pathLength
*/
unsigned int wolfSSL_X509_get_pathLength(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets key usage from certificate.

    \return unsigned int Key usage value

    \param x509 Certificate to get key usage from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    unsigned int usage = wolfSSL_X509_get_keyUsage(x509);
    if (usage & KEYUSE_DIGITAL_SIG) {
        printf("Digital signature allowed\n");
    }
    \endcode

    \sa wolfSSL_X509_get_extended_key_usage
*/
unsigned int wolfSSL_X509_get_keyUsage(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets authority key identifier.

    \return unsigned char* Pointer to key ID
    \return NULL on failure

    \param x509 Certificate to get key ID from
    \param dst Buffer to store key ID
    \param dstLen Pointer to buffer size (updated with actual size)

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    unsigned char buf[256];
    int len = sizeof(buf);
    unsigned char* keyid = wolfSSL_X509_get_authorityKeyID(x509, buf,
                                                             &len);
    if (keyid != NULL) {
        printf("Authority key ID length: %d\n", len);
    }
    \endcode

    \sa wolfSSL_X509_get_subjectKeyID
*/
unsigned char* wolfSSL_X509_get_authorityKeyID(WOLFSSL_X509* x509,
    unsigned char* dst, int* dstLen);

/*!
    \ingroup CertsKeys

    \brief Gets subject key identifier.

    \return unsigned char* Pointer to key ID
    \return NULL on failure

    \param x509 Certificate to get key ID from
    \param dst Buffer to store key ID
    \param dstLen Pointer to buffer size (updated with actual size)

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    unsigned char buf[256];
    int len = sizeof(buf);
    unsigned char* keyid = wolfSSL_X509_get_subjectKeyID(x509, buf,
                                                           &len);
    if (keyid != NULL) {
        printf("Subject key ID length: %d\n", len);
    }
    \endcode

    \sa wolfSSL_X509_get_authorityKeyID
*/
unsigned char* wolfSSL_X509_get_subjectKeyID(WOLFSSL_X509* x509,
    unsigned char* dst, int* dstLen);

/*!
    \ingroup CertsKeys

    \brief Verifies X509 certificate signature.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to verify
    \param pkey Public key to verify with

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_X509_get_pubkey(x509);
    int ret = wolfSSL_X509_verify(x509, pkey);
    if (ret == WOLFSSL_SUCCESS) {
        printf("Certificate signature verified\n");
    }
    \endcode

    \sa wolfSSL_X509_REQ_verify
*/
int wolfSSL_X509_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief Verifies X509 request signature.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Request to verify
    \param pkey Public key to verify with

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_X509_REQ_new();
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    int ret = wolfSSL_X509_REQ_verify(req, pkey);
    \endcode

    \sa wolfSSL_X509_verify
*/
int wolfSSL_X509_REQ_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief Sets subject name for certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cert Certificate to modify
    \param name Subject name to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_X509_NAME* name = wolfSSL_X509_NAME_new();
    int ret = wolfSSL_X509_set_subject_name(cert, name);
    \endcode

    \sa wolfSSL_X509_set_issuer_name
*/
int wolfSSL_X509_set_subject_name(WOLFSSL_X509* cert,
                                    WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys

    \brief Sets issuer name for certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cert Certificate to modify
    \param name Issuer name to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_X509_NAME* name = wolfSSL_X509_NAME_new();
    int ret = wolfSSL_X509_set_issuer_name(cert, name);
    \endcode

    \sa wolfSSL_X509_set_subject_name
*/
int wolfSSL_X509_set_issuer_name(WOLFSSL_X509* cert,
                                   WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys

    \brief Sets public key for certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cert Certificate to modify
    \param pkey Public key to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    int ret = wolfSSL_X509_set_pubkey(cert, pkey);
    \endcode

    \sa wolfSSL_X509_get_pubkey
*/
int wolfSSL_X509_set_pubkey(WOLFSSL_X509* cert, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief Sets notAfter time for certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param t Time to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    int ret = wolfSSL_X509_set_notAfter(cert, time);
    \endcode

    \sa wolfSSL_X509_set_notBefore
*/
int wolfSSL_X509_set_notAfter(WOLFSSL_X509* x509,
                                const WOLFSSL_ASN1_TIME* t);

/*!
    \ingroup CertsKeys

    \brief Sets notAfter time for certificate (version 1).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param t Time to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    int ret = wolfSSL_X509_set1_notAfter(cert, time);
    \endcode

    \sa wolfSSL_X509_set_notAfter
*/
int wolfSSL_X509_set1_notAfter(WOLFSSL_X509* x509,
                                 const WOLFSSL_ASN1_TIME* t);

/*!
    \ingroup CertsKeys

    \brief Sets notBefore time for certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param t Time to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    int ret = wolfSSL_X509_set_notBefore(cert, time);
    \endcode

    \sa wolfSSL_X509_set_notAfter
*/
int wolfSSL_X509_set_notBefore(WOLFSSL_X509* x509,
                                 const WOLFSSL_ASN1_TIME* t);

/*!
    \ingroup CertsKeys

    \brief Sets notBefore time for certificate (version 1).

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param t Time to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    int ret = wolfSSL_X509_set1_notBefore(cert, time);
    \endcode

    \sa wolfSSL_X509_set_notBefore
*/
int wolfSSL_X509_set1_notBefore(WOLFSSL_X509* x509,
                                  const WOLFSSL_ASN1_TIME* t);

/*!
    \ingroup CertsKeys

    \brief Gets notBefore time from certificate.

    \return WOLFSSL_ASN1_TIME* Pointer to notBefore time
    \return NULL on failure

    \param x509 Certificate to get time from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    WOLFSSL_ASN1_TIME* before = wolfSSL_X509_get_notBefore(x509);
    if (before != NULL) {
        printf("Certificate valid from: %s\n", before->data);
    }
    \endcode

    \sa wolfSSL_X509_get_notAfter
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets notAfter time from certificate.

    \return WOLFSSL_ASN1_TIME* Pointer to notAfter time
    \return NULL on failure

    \param x509 Certificate to get time from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    WOLFSSL_ASN1_TIME* after = wolfSSL_X509_get_notAfter(x509);
    if (after != NULL) {
        printf("Certificate valid until: %s\n", after->data);
    }
    \endcode

    \sa wolfSSL_X509_get_notBefore
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Sets serial number for certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param s Serial number to set

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_ASN1_INTEGER* serial = wolfSSL_ASN1_INTEGER_new();
    wolfSSL_ASN1_INTEGER_set(serial, 12345);
    int ret = wolfSSL_X509_set_serialNumber(cert, serial);
    \endcode

    \sa wolfSSL_X509_get_serialNumber
*/
int wolfSSL_X509_set_serialNumber(WOLFSSL_X509* x509,
                                    WOLFSSL_ASN1_INTEGER* s);

/*!
    \ingroup CertsKeys

    \brief Sets version for certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param v Version number (0=v1, 1=v2, 2=v3)

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    int ret = wolfSSL_X509_set_version(cert, 2);
    \endcode

    \sa wolfSSL_X509_get_version
*/
int wolfSSL_X509_set_version(WOLFSSL_X509* x509, long v);

/*!
    \ingroup CertsKeys

    \brief Signs X509 certificate with private key.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to sign
    \param pkey Private key to sign with
    \param md Message digest algorithm

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_sha256();
    int ret = wolfSSL_X509_sign(cert, pkey, md);
    \endcode

    \sa wolfSSL_X509_sign_ctx
*/
int wolfSSL_X509_sign(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey,
                       const WOLFSSL_EVP_MD* md);

/*!
    \ingroup CertsKeys

    \brief Signs X509 certificate using digest context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to sign
    \param ctx Digest context with key and algorithm

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    WOLFSSL_EVP_MD_CTX* ctx = wolfSSL_EVP_MD_CTX_new();
    int ret = wolfSSL_X509_sign_ctx(cert, ctx);
    \endcode

    \sa wolfSSL_X509_sign
*/
int wolfSSL_X509_sign_ctx(WOLFSSL_X509* x509, WOLFSSL_EVP_MD_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets entry count in X509_NAME.

    \return int Number of entries

    \param name X509_NAME to count entries in

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    int count = wolfSSL_X509_NAME_entry_count(name);
    printf("Name has %d entries\n", count);
    \endcode

    \sa wolfSSL_X509_NAME_get_entry
*/
int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys

    \brief Gets size of X509_NAME.

    \return int Size in bytes

    \param name X509_NAME to get size of

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    int sz = wolfSSL_X509_NAME_get_sz(name);
    printf("Name size: %d bytes\n", sz);
    \endcode

    \sa wolfSSL_X509_NAME_entry_count
*/
int wolfSSL_X509_NAME_get_sz(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys

    \brief Gets index of entry by NID in X509_NAME.

    \return int Index of entry
    \return negative value if not found

    \param name X509_NAME to search
    \param nid NID to search for
    \param pos Starting position for search

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    int idx = wolfSSL_X509_NAME_get_index_by_NID(name, NID_commonName,
                                                   -1);
    if (idx >= 0) {
        WOLFSSL_X509_NAME_ENTRY* entry;
        entry = wolfSSL_X509_NAME_get_entry(name, idx);
    }
    \endcode

    \sa wolfSSL_X509_NAME_get_entry
*/
int wolfSSL_X509_NAME_get_index_by_NID(WOLFSSL_X509_NAME* name, int nid,
                                         int pos);

/*!
    \ingroup CertsKeys

    \brief Gets data from X509_NAME_ENTRY.

    \return WOLFSSL_ASN1_STRING* Pointer to entry data
    \return NULL on failure

    \param in X509_NAME_ENTRY to get data from

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    WOLFSSL_X509_NAME_ENTRY* entry = wolfSSL_X509_NAME_get_entry(name,
                                                                   0);
    WOLFSSL_ASN1_STRING* data = wolfSSL_X509_NAME_ENTRY_get_data(entry);
    if (data != NULL) {
        printf("Entry data: %s\n", data->data);
    }
    \endcode

    \sa wolfSSL_X509_NAME_get_entry
*/
WOLFSSL_ASN1_STRING* wolfSSL_X509_NAME_ENTRY_get_data(
    WOLFSSL_X509_NAME_ENTRY* in);

/*!
    \ingroup CertsKeys

    \brief Creates new ASN1_STRING.

    \return WOLFSSL_ASN1_STRING* Pointer to new string
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    if (str != NULL) {
        wolfSSL_ASN1_STRING_set(str, "test", 4);
        wolfSSL_ASN1_STRING_free(str);
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_free
*/
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_new(void);

/*!
    \ingroup CertsKeys

    \brief Duplicates ASN1_STRING.

    \return WOLFSSL_ASN1_STRING* Pointer to duplicated string
    \return NULL on failure

    \param asn1 ASN1_STRING to duplicate

    _Example_
    \code
    WOLFSSL_ASN1_STRING* orig = wolfSSL_ASN1_STRING_new();
    WOLFSSL_ASN1_STRING* dup = wolfSSL_ASN1_STRING_dup(orig);
    if (dup != NULL) {
        wolfSSL_ASN1_STRING_free(dup);
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_new
*/
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_dup(WOLFSSL_ASN1_STRING* asn1);

/*!
    \ingroup CertsKeys

    \brief Creates new ASN1_STRING with type.

    \return WOLFSSL_ASN1_STRING* Pointer to new string
    \return NULL on failure

    \param type ASN1 type

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_type_new(V_ASN1_IA5STRING);
    if (str != NULL) {
        wolfSSL_ASN1_STRING_set(str, "test", 4);
        wolfSSL_ASN1_STRING_free(str);
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_new
*/
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_type_new(int type);

/*!
    \ingroup CertsKeys

    \brief Gets type of ASN1_STRING.

    \return int ASN1 type

    \param asn1 ASN1_STRING to get type from

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    int type = wolfSSL_ASN1_STRING_type(str);
    printf("ASN1 type: %d\n", type);
    \endcode

    \sa wolfSSL_ASN1_STRING_type_new
*/
int wolfSSL_ASN1_STRING_type(const WOLFSSL_ASN1_STRING* asn1);

/*!
    \ingroup CertsKeys

    \brief Decodes DISPLAYTEXT from DER.

    \return WOLFSSL_ASN1_STRING* Pointer to decoded string
    \return NULL on failure

    \param asn Pointer to store result
    \param in Pointer to DER data
    \param len Length of DER data

    _Example_
    \code
    const unsigned char* der = buffer;
    WOLFSSL_ASN1_STRING* str = wolfSSL_d2i_DISPLAYTEXT(NULL, &der, len);
    if (str != NULL) {
        printf("Display text: %s\n", str->data);
        wolfSSL_ASN1_STRING_free(str);
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_new
*/
WOLFSSL_ASN1_STRING* wolfSSL_d2i_DISPLAYTEXT(WOLFSSL_ASN1_STRING** asn,
    const unsigned char** in, long len);

/*!
    \ingroup CertsKeys

    \brief Compares two ASN1_STRINGs.

    \return 0 if equal
    \return non-zero if different

    \param a First string
    \param b Second string

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str1 = wolfSSL_ASN1_STRING_new();
    WOLFSSL_ASN1_STRING* str2 = wolfSSL_ASN1_STRING_new();
    int cmp = wolfSSL_ASN1_STRING_cmp(str1, str2);
    if (cmp == 0) {
        printf("Strings are equal\n");
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_new
*/
int wolfSSL_ASN1_STRING_cmp(const WOLFSSL_ASN1_STRING* a,
                              const WOLFSSL_ASN1_STRING* b);

/*!
    \ingroup CertsKeys

    \brief Frees ASN1_STRING.

    \return none

    \param asn1 ASN1_STRING to free

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    wolfSSL_ASN1_STRING_free(str);
    \endcode

    \sa wolfSSL_ASN1_STRING_new
*/
void wolfSSL_ASN1_STRING_free(WOLFSSL_ASN1_STRING* asn1);

/*!
    \ingroup CertsKeys

    \brief Sets data in ASN1_STRING.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param asn1 ASN1_STRING to set data in
    \param data Data to set
    \param dataSz Size of data

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    int ret = wolfSSL_ASN1_STRING_set(str, "test", 4);
    \endcode

    \sa wolfSSL_ASN1_STRING_data
*/
int wolfSSL_ASN1_STRING_set(WOLFSSL_ASN1_STRING* asn1, const void* data,
                              int dataSz);

/*!
    \ingroup CertsKeys

    \brief Gets data pointer from ASN1_STRING.

    \return unsigned char* Pointer to data

    \param asn ASN1_STRING to get data from

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    unsigned char* data = wolfSSL_ASN1_STRING_data(str);
    \endcode

    \sa wolfSSL_ASN1_STRING_get0_data
*/
unsigned char* wolfSSL_ASN1_STRING_data(WOLFSSL_ASN1_STRING* asn);

/*!
    \ingroup CertsKeys

    \brief Gets const data pointer from ASN1_STRING.

    \return const unsigned char* Pointer to data

    \param asn ASN1_STRING to get data from

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    const unsigned char* data = wolfSSL_ASN1_STRING_get0_data(str);
    \endcode

    \sa wolfSSL_ASN1_STRING_data
*/
const unsigned char* wolfSSL_ASN1_STRING_get0_data(
    const WOLFSSL_ASN1_STRING* asn);

/*!
    \ingroup CertsKeys

    \brief Gets length of ASN1_STRING.

    \return int Length in bytes

    \param asn ASN1_STRING to get length from

    _Example_
    \code
    WOLFSSL_ASN1_STRING* str = wolfSSL_ASN1_STRING_new();
    int len = wolfSSL_ASN1_STRING_length(str);
    printf("String length: %d\n", len);
    \endcode

    \sa wolfSSL_ASN1_STRING_data
*/
int wolfSSL_ASN1_STRING_length(const WOLFSSL_ASN1_STRING* asn);

/*!
    \ingroup CertsKeys

    \brief Copies ASN1_STRING.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param dst Destination string
    \param src Source string

    _Example_
    \code
    WOLFSSL_ASN1_STRING* src = wolfSSL_ASN1_STRING_new();
    WOLFSSL_ASN1_STRING* dst = wolfSSL_ASN1_STRING_new();
    int ret = wolfSSL_ASN1_STRING_copy(dst, src);
    \endcode

    \sa wolfSSL_ASN1_STRING_dup
*/
int wolfSSL_ASN1_STRING_copy(WOLFSSL_ASN1_STRING* dst,
                               const WOLFSSL_ASN1_STRING* src);

/*!
    \ingroup CertsKeys

    \brief Verifies certificate chain.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_STORE_CTX with certificate and store

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL);
    int ret = wolfSSL_X509_verify_cert(ctx);
    if (ret == WOLFSSL_SUCCESS) {
        printf("Certificate verified\n");
    }
    \endcode

    \sa wolfSSL_X509_STORE_CTX_init
*/
int wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets error string for verification error.

    \return const char* Error string

    \param err Error code

    _Example_
    \code
    long err = wolfSSL_X509_STORE_CTX_get_error(ctx);
    const char* errStr = wolfSSL_X509_verify_cert_error_string(err);
    printf("Verification error: %s\n", errStr);
    \endcode

    \sa wolfSSL_X509_verify_cert
*/
const char* wolfSSL_X509_verify_cert_error_string(long err);

/*!
    \ingroup CertsKeys

    \brief Adds directory to X509_LOOKUP.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param lookup X509_LOOKUP to add directory to
    \param dir Directory path
    \param type File type

    _Example_
    \code
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                        wolfSSL_X509_LOOKUP_file());
    int ret = wolfSSL_X509_LOOKUP_add_dir(lookup, "/etc/ssl/certs",
                                           WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_STORE_add_lookup
*/
int wolfSSL_X509_LOOKUP_add_dir(WOLFSSL_X509_LOOKUP* lookup,
                                  const char* dir, long type);

/*!
    \ingroup CertsKeys

    \brief Loads certificate file into X509_LOOKUP.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param lookup X509_LOOKUP to load file into
    \param file Certificate file path
    \param type File type

    _Example_
    \code
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                        wolfSSL_X509_LOOKUP_file());
    int ret = wolfSSL_X509_LOOKUP_load_file(lookup, "cert.pem",
                                              WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_LOOKUP_add_dir
*/
int wolfSSL_X509_LOOKUP_load_file(WOLFSSL_X509_LOOKUP* lookup,
                                    const char* file, long type);

/*!
    \ingroup CertsKeys

    \brief Gets hash directory lookup method.

    \return WOLFSSL_X509_LOOKUP_METHOD* Pointer to lookup method

    _Example_
    \code
    WOLFSSL_X509_LOOKUP_METHOD* method = wolfSSL_X509_LOOKUP_hash_dir();
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                                                  method);
    \endcode

    \sa wolfSSL_X509_LOOKUP_file
*/
WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_hash_dir(void);

/*!
    \ingroup CertsKeys

    \brief Gets file lookup method.

    \return WOLFSSL_X509_LOOKUP_METHOD* Pointer to lookup method

    _Example_
    \code
    WOLFSSL_X509_LOOKUP_METHOD* method = wolfSSL_X509_LOOKUP_file();
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                                                  method);
    \endcode

    \sa wolfSSL_X509_LOOKUP_hash_dir
*/
WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_file(void);

/*!
    \ingroup CertsKeys

    \brief Controls X509_LOOKUP behavior.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_LOOKUP to control
    \param cmd Command to execute
    \param argc String argument
    \param argl Long argument
    \param ret Return value pointer

    _Example_
    \code
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                        wolfSSL_X509_LOOKUP_file());
    int ret = wolfSSL_X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD,
                                        "cert.pem", 0, NULL);
    \endcode

    \sa wolfSSL_X509_LOOKUP_load_file
*/
int wolfSSL_X509_LOOKUP_ctrl(WOLFSSL_X509_LOOKUP* ctx, int cmd,
                               const char* argc, long argl, char** ret);

/*!
    \ingroup CertsKeys

    \brief Adds lookup method to X509_STORE.

    \return WOLFSSL_X509_LOOKUP* Pointer to new lookup
    \return NULL on failure

    \param store X509_STORE to add lookup to
    \param m Lookup method

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                        wolfSSL_X509_LOOKUP_file());
    \endcode

    \sa wolfSSL_X509_LOOKUP_file
*/
WOLFSSL_X509_LOOKUP* wolfSSL_X509_STORE_add_lookup(
    WOLFSSL_X509_STORE* store, WOLFSSL_X509_LOOKUP_METHOD* m);

/*!
    \ingroup CertsKeys

    \brief Creates new X509_STORE.

    \return WOLFSSL_X509_STORE* Pointer to new store
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    if (store != NULL) {
        wolfSSL_X509_STORE_free(store);
    }
    \endcode

    \sa wolfSSL_X509_STORE_free
*/
WOLFSSL_X509_STORE* wolfSSL_X509_STORE_new(void);

/*!
    \ingroup CertsKeys

    \brief Frees X509_STORE.

    \return none

    \param store X509_STORE to free

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    wolfSSL_X509_STORE_free(store);
    \endcode

    \sa wolfSSL_X509_STORE_new
*/
void wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE* store);

/*!
    \ingroup CertsKeys

    \brief Increments reference count for X509_STORE.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param store X509_STORE to increment reference count

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    int ret = wolfSSL_X509_STORE_up_ref(store);
    \endcode

    \sa wolfSSL_X509_STORE_free
*/
int wolfSSL_X509_STORE_up_ref(WOLFSSL_X509_STORE* store);

/*!
    \ingroup CertsKeys

    \brief Sets verification parameters for X509_STORE.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_STORE to set parameters for
    \param param Verification parameters

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_X509_STORE_set1_param(store, param);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_new
*/
int wolfSSL_X509_STORE_set1_param(WOLFSSL_X509_STORE* ctx,
                                    WOLFSSL_X509_VERIFY_PARAM* param);

/*!
    \ingroup CertsKeys

    \brief Gets certificate chain from store context.

    \return WOLFSSL_STACK* Pointer to certificate chain
    \return NULL on failure

    \param ctx X509_STORE_CTX to get chain from

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_STACK* chain = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get1_chain
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
    WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets copy of certificate chain from store context.

    \return WOLFSSL_STACK* Pointer to certificate chain copy
    \return NULL on failure

    \param ctx X509_STORE_CTX to get chain from

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_STACK* chain = wolfSSL_X509_STORE_CTX_get1_chain(ctx);
    if (chain != NULL) {
        wolfSSL_sk_X509_pop_free(chain, NULL);
    }
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_chain
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get1_chain(
    WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets certificate from store by subject name.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_STORE_CTX to search
    \param idx Index type
    \param name Subject name to search for
    \param obj Object to store result

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_X509_NAME* name = wolfSSL_X509_NAME_new();
    WOLFSSL_X509_OBJECT obj;
    int ret = wolfSSL_X509_STORE_get_by_subject(ctx, 0, name, &obj);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_init
*/
int wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX* ctx,
    int idx, WOLFSSL_X509_NAME* name, WOLFSSL_X509_OBJECT* obj);

/*!
    \ingroup CertsKeys

    \brief Cleans up X509_STORE_CTX.

    \return none

    \param ctx X509_STORE_CTX to clean up

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    wolfSSL_X509_STORE_CTX_init(ctx, store, cert, NULL);
    wolfSSL_X509_verify_cert(ctx);
    wolfSSL_X509_STORE_CTX_cleanup(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_init
*/
void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets lastUpdate time from CRL.

    \return WOLFSSL_ASN1_TIME* Pointer to lastUpdate time
    \return NULL on failure

    \param crl CRL to get time from

    _Example_
    \code
    WOLFSSL_X509_CRL* crl = wolfSSL_d2i_X509_CRL(NULL, &der, len);
    WOLFSSL_ASN1_TIME* last = wolfSSL_X509_CRL_get_lastUpdate(crl);
    if (last != NULL) {
        printf("CRL last update: %s\n", last->data);
    }
    \endcode

    \sa wolfSSL_X509_CRL_get_nextUpdate
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_lastUpdate(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys

    \brief Gets nextUpdate time from CRL.

    \return WOLFSSL_ASN1_TIME* Pointer to nextUpdate time
    \return NULL on failure

    \param crl CRL to get time from

    _Example_
    \code
    WOLFSSL_X509_CRL* crl = wolfSSL_d2i_X509_CRL(NULL, &der, len);
    WOLFSSL_ASN1_TIME* next = wolfSSL_X509_CRL_get_nextUpdate(crl);
    if (next != NULL) {
        printf("CRL next update: %s\n", next->data);
    }
    \endcode

    \sa wolfSSL_X509_CRL_get_lastUpdate
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_nextUpdate(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys

    \brief Gets public key from certificate.

    \return WOLFSSL_EVP_PKEY* Pointer to public key
    \return NULL on failure

    \param x509 Certificate to get public key from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_X509_get_pubkey(x509);
    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    \endcode

    \sa wolfSSL_X509_set_pubkey
*/
WOLFSSL_EVP_PKEY* wolfSSL_X509_get_pubkey(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Verifies CRL signature.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param crl CRL to verify
    \param pkey Public key to verify with

    _Example_
    \code
    WOLFSSL_X509_CRL* crl = wolfSSL_d2i_X509_CRL(NULL, &der, len);
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_X509_get_pubkey(issuer);
    int ret = wolfSSL_X509_CRL_verify(crl, pkey);
    \endcode

    \sa wolfSSL_X509_verify
*/
int wolfSSL_X509_CRL_verify(WOLFSSL_X509_CRL* crl, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief Frees contents of X509_OBJECT.

    \return none

    \param obj X509_OBJECT to free contents

    _Example_
    \code
    WOLFSSL_X509_OBJECT obj;
    wolfSSL_X509_STORE_get_by_subject(ctx, 0, name, &obj);
    wolfSSL_X509_OBJECT_free_contents(&obj);
    \endcode

    \sa wolfSSL_X509_STORE_get_by_subject
*/
void wolfSSL_X509_OBJECT_free_contents(WOLFSSL_X509_OBJECT* obj);

/*!
    \ingroup CertsKeys

    \brief Decodes PKCS8 private key from BIO.

    \return WOLFSSL_PKCS8_PRIV_KEY_INFO* Pointer to private key info
    \return NULL on failure

    \param bio BIO to read from
    \param pkey Pointer to store result

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_file("key.p8", "rb");
    WOLFSSL_PKCS8_PRIV_KEY_INFO* p8 = wolfSSL_d2i_PKCS8_PKEY_bio(bio,
                                                                   NULL);
    if (p8 != NULL) {
        wolfSSL_PKCS8_PRIV_KEY_INFO_free(p8);
    }
    \endcode

    \sa wolfSSL_d2i_PKCS8_PKEY
*/
WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY_bio(WOLFSSL_BIO* bio,
    WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey);

/*!
    \ingroup CertsKeys

    \brief Decodes PKCS8 private key from buffer.

    \return WOLFSSL_PKCS8_PRIV_KEY_INFO* Pointer to private key info
    \return NULL on failure

    \param pkey Pointer to store result
    \param keyBuf Pointer to key buffer
    \param keyLen Length of key buffer

    _Example_
    \code
    const unsigned char* buf = keyData;
    WOLFSSL_PKCS8_PRIV_KEY_INFO* p8 = wolfSSL_d2i_PKCS8_PKEY(NULL, &buf,
                                                               keyLen);
    if (p8 != NULL) {
        wolfSSL_PKCS8_PRIV_KEY_INFO_free(p8);
    }
    \endcode

    \sa wolfSSL_d2i_PKCS8_PKEY_bio
*/
WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY(
    WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey, const unsigned char** keyBuf,
    long keyLen);

/*!
    \ingroup CertsKeys

    \brief Encodes PKCS8 private key to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param key Private key info to encode
    \param pp Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_PKCS8_PRIV_KEY_INFO* p8 = wolfSSL_d2i_PKCS8_PKEY(NULL, &buf,
                                                               len);
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_PKCS8_PKEY(p8, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_PKCS8_PKEY
*/
int wolfSSL_i2d_PKCS8_PKEY(WOLFSSL_PKCS8_PRIV_KEY_INFO* key,
                            unsigned char** pp);

/*!
    \ingroup CertsKeys

    \brief Decodes public key from BIO.

    \return WOLFSSL_EVP_PKEY* Pointer to public key
    \return NULL on failure

    \param bio BIO to read from
    \param out Pointer to store result

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_file("pubkey.der", "rb");
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PUBKEY_bio(bio, NULL);
    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    \endcode

    \sa wolfSSL_d2i_PUBKEY
*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY_bio(WOLFSSL_BIO* bio,
                                          WOLFSSL_EVP_PKEY** out);

/*!
    \ingroup CertsKeys

    \brief Decodes public key from buffer.

    \return WOLFSSL_EVP_PKEY* Pointer to public key
    \return NULL on failure

    \param key Pointer to store result
    \param in Pointer to key buffer
    \param inSz Length of key buffer

    _Example_
    \code
    const unsigned char* buf = keyData;
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PUBKEY(NULL, &buf, keyLen);
    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    \endcode

    \sa wolfSSL_d2i_PUBKEY_bio
*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY(WOLFSSL_EVP_PKEY** key,
                                      const unsigned char** in, long inSz);

/*!
    \ingroup CertsKeys

    \brief Encodes public key to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param key Public key to encode
    \param der Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PUBKEY(NULL, &buf, len);
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_PUBKEY(pkey, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_PUBKEY
*/
int wolfSSL_i2d_PUBKEY(const WOLFSSL_EVP_PKEY* key, unsigned char** der);

/*!
    \ingroup CertsKeys

    \brief Encodes X509_PUBKEY to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param x509_PubKey X509_PUBKEY to encode
    \param der Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_X509_PUBKEY* pubkey = wolfSSL_X509_get_X509_PUBKEY(x509);
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_X509_PUBKEY(pubkey, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_X509_get_X509_PUBKEY
*/
int wolfSSL_i2d_X509_PUBKEY(WOLFSSL_X509_PUBKEY* x509_PubKey,
                             unsigned char** der);

/*!
    \ingroup CertsKeys

    \brief Decodes public key from buffer with type.

    \return WOLFSSL_EVP_PKEY* Pointer to public key
    \return NULL on failure

    \param type Key type
    \param pkey Pointer to store result
    \param in Pointer to key buffer
    \param inSz Length of key buffer

    _Example_
    \code
    const unsigned char* buf = keyData;
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PublicKey(EVP_PKEY_RSA, NULL,
                                                     &buf, keyLen);
    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    \endcode

    \sa wolfSSL_d2i_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PublicKey(int type, WOLFSSL_EVP_PKEY** pkey,
                                         const unsigned char** in,
                                         long inSz);

/*!
    \ingroup CertsKeys

    \brief Decodes private key from buffer with type.

    \return WOLFSSL_EVP_PKEY* Pointer to private key
    \return NULL on failure

    \param type Key type
    \param out Pointer to store result
    \param in Pointer to key buffer
    \param inSz Length of key buffer

    _Example_
    \code
    const unsigned char* buf = keyData;
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
                                                      &buf, keyLen);
    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    \endcode

    \sa wolfSSL_d2i_PublicKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey(int type, WOLFSSL_EVP_PKEY** out,
                                          const unsigned char** in,
                                          long inSz);

/*!
    \ingroup CertsKeys

    \brief Decodes private key with heap and device ID.

    \return WOLFSSL_EVP_PKEY* Pointer to private key
    \return NULL on failure

    \param type Key type
    \param out Pointer to store result
    \param heap Heap hint
    \param devId Device ID

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PrivateKey_id(EVP_PKEY_RSA,
                                                         NULL, NULL,
                                                         INVALID_DEVID);
    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    \endcode

    \sa wolfSSL_d2i_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_id(int type,
                                              WOLFSSL_EVP_PKEY** out,
                                              void* heap, int devId);

/*!
    \ingroup CertsKeys

    \brief Decodes private key from EVP format.

    \return WOLFSSL_EVP_PKEY* Pointer to private key
    \return NULL on failure

    \param key Pointer to store result
    \param in Pointer to key buffer
    \param inSz Length of key buffer

    _Example_
    \code
    unsigned char* buf = keyData;
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PrivateKey_EVP(NULL, &buf,
                                                          keyLen);
    if (pkey != NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
    }
    \endcode

    \sa wolfSSL_d2i_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_EVP(WOLFSSL_EVP_PKEY** key,
                                               unsigned char** in,
                                               long inSz);

/*!
    \ingroup CertsKeys

    \brief Encodes private key to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param key Private key to encode
    \param der Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL,
                                                      &buf, len);
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_PrivateKey(pkey, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_PrivateKey
*/
int wolfSSL_i2d_PrivateKey(const WOLFSSL_EVP_PKEY* key,
                            unsigned char** der);

/*!
    \ingroup CertsKeys

    \brief Encodes public key to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param key Public key to encode
    \param der Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_d2i_PublicKey(EVP_PKEY_RSA, NULL,
                                                     &buf, len);
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_PublicKey(pkey, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_PublicKey
*/
int wolfSSL_i2d_PublicKey(const WOLFSSL_EVP_PKEY* key,
                           unsigned char** der);

/*!
    \ingroup CertsKeys

    \brief Writes private key to BIO in DER format.

    \return int Length written
    \return negative value on failure

    \param bio BIO to write to
    \param key Private key to write

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_file("key.der", "wb");
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    int ret = wolfSSL_i2d_PrivateKey_bio(bio, pkey);
    \endcode

    \sa wolfSSL_i2d_PrivateKey
*/
int wolfSSL_i2d_PrivateKey_bio(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key);

/*!
    \ingroup CertsKeys

    \brief Prints public key to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param out BIO to write to
    \param pkey Public key to print
    \param indent Indentation level
    \param pctx Print context

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_X509_get_pubkey(x509);
    int ret = wolfSSL_EVP_PKEY_print_public(bio, pkey, 0, NULL);
    \endcode

    \sa wolfSSL_X509_get_pubkey
*/
int wolfSSL_EVP_PKEY_print_public(WOLFSSL_BIO* out,
                                    const WOLFSSL_EVP_PKEY* pkey,
                                    int indent, WOLFSSL_ASN1_PCTX* pctx);

/*!
    \ingroup CertsKeys

    \brief Compares ASN1_TIME with current time.

    \return negative if time is before current time
    \return 0 if time equals current time
    \return positive if time is after current time

    \param asnTime ASN1_TIME to compare

    _Example_
    \code
    WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notAfter(x509);
    int cmp = wolfSSL_X509_cmp_current_time(notAfter);
    if (cmp < 0) {
        printf("Certificate has expired\n");
    }
    \endcode

    \sa wolfSSL_X509_cmp_time
*/
int wolfSSL_X509_cmp_current_time(const WOLFSSL_ASN1_TIME* asnTime);

/*!
    \ingroup CertsKeys

    \brief Compares ASN1_TIME with specified time.

    \return negative if asnTime is before cmpTime
    \return 0 if times are equal
    \return positive if asnTime is after cmpTime

    \param asnTime ASN1_TIME to compare
    \param cmpTime Time to compare against

    _Example_
    \code
    WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notAfter(x509);
    time_t checkTime = time(NULL) + 86400;
    int cmp = wolfSSL_X509_cmp_time(notAfter, &checkTime);
    \endcode

    \sa wolfSSL_X509_cmp_current_time
*/
int wolfSSL_X509_cmp_time(const WOLFSSL_ASN1_TIME* asnTime,
                           time_t* cmpTime);

/*!
    \ingroup CertsKeys

    \brief Adjusts ASN1_TIME by offset.

    \return WOLFSSL_ASN1_TIME* Pointer to adjusted time
    \return NULL on failure

    \param s ASN1_TIME to adjust (NULL to allocate new)
    \param adj Adjustment in seconds

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_X509_gmtime_adj(NULL, 86400);
    if (time != NULL) {
        printf("Time 24 hours from now\n");
        wolfSSL_ASN1_TIME_free(time);
    }
    \endcode

    \sa wolfSSL_X509_cmp_current_time
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_gmtime_adj(WOLFSSL_ASN1_TIME* s,
                                             long adj);

/*!
    \ingroup CertsKeys

    \brief Gets count of revoked certificates.

    \return int Number of revoked certificates

    \param revoked Revoked certificate stack

    _Example_
    \code
    WOLFSSL_X509_REVOKED* revoked = wolfSSL_X509_CRL_get_REVOKED(crl);
    int count = wolfSSL_sk_X509_REVOKED_num(revoked);
    printf("CRL has %d revoked certificates\n", count);
    \endcode

    \sa wolfSSL_X509_CRL_get_REVOKED
*/
int wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED* revoked);

/*!
    \ingroup CertsKeys

    \brief Sets verification time for store context.

    \return none

    \param ctx X509_STORE_CTX to set time for
    \param flags Flags
    \param t Time to set

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    time_t checkTime = time(NULL) - 86400;
    wolfSSL_X509_STORE_CTX_set_time(ctx, 0, checkTime);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_init
*/
void wolfSSL_X509_STORE_CTX_set_time(WOLFSSL_X509_STORE_CTX* ctx,
                                       unsigned long flags, time_t t);

/*!
    \ingroup CertsKeys

    \brief Creates new X509_VERIFY_PARAM.

    \return WOLFSSL_X509_VERIFY_PARAM* Pointer to new param
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    if (param != NULL) {
        wolfSSL_X509_VERIFY_PARAM_free(param);
    }
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_free
*/
WOLFSSL_X509_VERIFY_PARAM* wolfSSL_X509_VERIFY_PARAM_new(void);

/*!
    \ingroup CertsKeys

    \brief Frees X509_VERIFY_PARAM.

    \return none

    \param param X509_VERIFY_PARAM to free

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    wolfSSL_X509_VERIFY_PARAM_free(param);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_new
*/
void wolfSSL_X509_VERIFY_PARAM_free(WOLFSSL_X509_VERIFY_PARAM* param);

/*!
    \ingroup CertsKeys

    \brief Sets verification flags.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param param X509_VERIFY_PARAM to modify
    \param flags Flags to set

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_X509_VERIFY_PARAM_set_flags(param,
                                                    X509_V_FLAG_CRL_CHECK);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_get_flags
*/
int wolfSSL_X509_VERIFY_PARAM_set_flags(WOLFSSL_X509_VERIFY_PARAM* param,
                                          unsigned long flags);

/*!
    \ingroup CertsKeys

    \brief Gets verification flags.

    \return int Verification flags

    \param param X509_VERIFY_PARAM to get flags from

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    int flags = wolfSSL_X509_VERIFY_PARAM_get_flags(param);
    printf("Flags: 0x%x\n", flags);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set_flags
*/
int wolfSSL_X509_VERIFY_PARAM_get_flags(WOLFSSL_X509_VERIFY_PARAM* param);

/*!
    \ingroup CertsKeys

    \brief Clears verification flags.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param param X509_VERIFY_PARAM to modify
    \param flags Flags to clear

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_X509_VERIFY_PARAM_clear_flags(param,
                                                      X509_V_FLAG_CRL_CHECK);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set_flags
*/
int wolfSSL_X509_VERIFY_PARAM_clear_flags(
    WOLFSSL_X509_VERIFY_PARAM* param, unsigned long flags);

/*!
    \ingroup CertsKeys

    \brief Sets host flags for verification.

    \return none

    \param param X509_VERIFY_PARAM to modify
    \param flags Host flags to set

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    wolfSSL_X509_VERIFY_PARAM_set_hostflags(param,
                                              X509_CHECK_FLAG_NO_WILDCARDS);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set1_host
*/
void wolfSSL_X509_VERIFY_PARAM_set_hostflags(
    WOLFSSL_X509_VERIFY_PARAM* param, unsigned int flags);

/*!
    \ingroup Setup

    \brief Sets expected hostname for verification.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object to set hostname for
    \param name Hostname to verify

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ret = wolfSSL_set1_host(ssl, "www.example.com");
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set1_host
*/
int wolfSSL_set1_host(WOLFSSL* ssl, const char* name);

/*!
    \ingroup CertsKeys

    \brief Sets expected hostname in verify param.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param pParam X509_VERIFY_PARAM to modify
    \param name Hostname to verify
    \param nameSz Length of hostname

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_X509_VERIFY_PARAM_set1_host(param,
                                                    "www.example.com", 0);
    \endcode

    \sa wolfSSL_set1_host
*/
int wolfSSL_X509_VERIFY_PARAM_set1_host(WOLFSSL_X509_VERIFY_PARAM* pParam,
                                          const char* name,
                                          unsigned int nameSz);

/*!
    \ingroup CertsKeys

    \brief Sets expected IP address from ASCII string.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param param X509_VERIFY_PARAM to modify
    \param ipasc IP address string

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(param,
                                                      "192.168.1.1");
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set1_ip
*/
int wolfSSL_X509_VERIFY_PARAM_set1_ip_asc(WOLFSSL_X509_VERIFY_PARAM* param,
                                            const char* ipasc);

/*!
    \ingroup CertsKeys

    \brief Sets expected IP address from binary.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param param X509_VERIFY_PARAM to modify
    \param ip IP address bytes
    \param iplen Length of IP address

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param = wolfSSL_X509_VERIFY_PARAM_new();
    unsigned char ip[4] = {192, 168, 1, 1};
    int ret = wolfSSL_X509_VERIFY_PARAM_set1_ip(param, ip, 4);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set1_ip_asc
*/
int wolfSSL_X509_VERIFY_PARAM_set1_ip(WOLFSSL_X509_VERIFY_PARAM* param,
                                        const unsigned char* ip,
                                        size_t iplen);

/*!
    \ingroup CertsKeys

    \brief Copies verification parameters.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param to Destination param
    \param from Source param

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param1 = wolfSSL_X509_VERIFY_PARAM_new();
    WOLFSSL_X509_VERIFY_PARAM* param2 = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_X509_VERIFY_PARAM_set1(param1, param2);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_inherit
*/
int wolfSSL_X509_VERIFY_PARAM_set1(WOLFSSL_X509_VERIFY_PARAM* to,
                                     const WOLFSSL_X509_VERIFY_PARAM* from);

/*!
    \ingroup CertsKeys

    \brief Inherits verification parameters.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param to Destination param
    \param from Source param

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* param1 = wolfSSL_X509_VERIFY_PARAM_new();
    WOLFSSL_X509_VERIFY_PARAM* param2 = wolfSSL_X509_VERIFY_PARAM_new();
    int ret = wolfSSL_X509_VERIFY_PARAM_inherit(param1, param2);
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set1
*/
int wolfSSL_X509_VERIFY_PARAM_inherit(WOLFSSL_X509_VERIFY_PARAM* to,
                                        const WOLFSSL_X509_VERIFY_PARAM* from);

/*!
    \ingroup CertsKeys

    \brief Loads CRL file into X509_LOOKUP.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_LOOKUP to load CRL into
    \param file CRL file path
    \param type File type

    _Example_
    \code
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                        wolfSSL_X509_LOOKUP_file());
    int ret = wolfSSL_X509_load_crl_file(lookup, "crl.pem",
                                          WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_load_cert_crl_file
*/
int wolfSSL_X509_load_crl_file(WOLFSSL_X509_LOOKUP* ctx,
                                 const char* file, int type);

/*!
    \ingroup CertsKeys

    \brief Loads certificate and CRL file into X509_LOOKUP.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_LOOKUP to load into
    \param file File path
    \param type File type

    _Example_
    \code
    WOLFSSL_X509_LOOKUP* lookup = wolfSSL_X509_STORE_add_lookup(store,
                                        wolfSSL_X509_LOOKUP_file());
    int ret = wolfSSL_X509_load_cert_crl_file(lookup, "bundle.pem",
                                                WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_load_crl_file
*/
int wolfSSL_X509_load_cert_crl_file(WOLFSSL_X509_LOOKUP* ctx,
                                      const char* file, int type);

/*!
    \ingroup CertsKeys

    \brief Gets revoked certificates from CRL.

    \return WOLFSSL_X509_REVOKED* Pointer to revoked stack
    \return NULL on failure

    \param crl CRL to get revoked from

    _Example_
    \code
    WOLFSSL_X509_CRL* crl = wolfSSL_d2i_X509_CRL(NULL, &der, len);
    WOLFSSL_X509_REVOKED* revoked = wolfSSL_X509_CRL_get_REVOKED(crl);
    if (revoked != NULL) {
        int count = wolfSSL_sk_X509_REVOKED_num(revoked);
        printf("CRL has %d revoked certificates\n", count);
    }
    \endcode

    \sa wolfSSL_sk_X509_REVOKED_num
*/
WOLFSSL_X509_REVOKED* wolfSSL_X509_CRL_get_REVOKED(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys

    \brief Gets revoked certificate by index.

    \return WOLFSSL_X509_REVOKED* Pointer to revoked certificate
    \return NULL on failure

    \param revoked Revoked certificate stack
    \param value Index

    _Example_
    \code
    WOLFSSL_X509_REVOKED* revoked = wolfSSL_X509_CRL_get_REVOKED(crl);
    int count = wolfSSL_sk_X509_REVOKED_num(revoked);
    for (int i = 0; i < count; i++) {
        WOLFSSL_X509_REVOKED* rev;
        rev = wolfSSL_sk_X509_REVOKED_value(revoked, i);
    }
    \endcode

    \sa wolfSSL_X509_CRL_get_REVOKED
*/
WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
    WOLFSSL_X509_REVOKED* revoked, int value);

/*!
    \ingroup CertsKeys

    \brief Gets serial number from certificate.

    \return WOLFSSL_ASN1_INTEGER* Pointer to serial number
    \return NULL on failure

    \param x509 Certificate to get serial from

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_X509_load_certificate_file(file,
                                                              format);
    WOLFSSL_ASN1_INTEGER* serial = wolfSSL_X509_get_serialNumber(x509);
    if (serial != NULL) {
        long sn = wolfSSL_ASN1_INTEGER_get(serial);
        printf("Serial number: %ld\n", sn);
    }
    \endcode

    \sa wolfSSL_X509_set_serialNumber
*/
WOLFSSL_ASN1_INTEGER* wolfSSL_X509_get_serialNumber(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Frees ASN1_INTEGER.

    \return none

    \param in ASN1_INTEGER to free

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* num = wolfSSL_ASN1_INTEGER_new();
    wolfSSL_ASN1_INTEGER_free(num);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_new
*/
void wolfSSL_ASN1_INTEGER_free(WOLFSSL_ASN1_INTEGER* in);

/*!
    \ingroup CertsKeys

    \brief Creates new ASN1_INTEGER.

    \return WOLFSSL_ASN1_INTEGER* Pointer to new integer
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* num = wolfSSL_ASN1_INTEGER_new();
    if (num != NULL) {
        wolfSSL_ASN1_INTEGER_set(num, 12345);
        wolfSSL_ASN1_INTEGER_free(num);
    }
    \endcode

    \sa wolfSSL_ASN1_INTEGER_free
*/
WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_new(void);

/*!
    \ingroup CertsKeys

    \brief Duplicates ASN1_INTEGER.

    \return WOLFSSL_ASN1_INTEGER* Pointer to duplicated integer
    \return NULL on failure

    \param src ASN1_INTEGER to duplicate

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* orig = wolfSSL_ASN1_INTEGER_new();
    WOLFSSL_ASN1_INTEGER* dup = wolfSSL_ASN1_INTEGER_dup(orig);
    if (dup != NULL) {
        wolfSSL_ASN1_INTEGER_free(dup);
    }
    \endcode

    \sa wolfSSL_ASN1_INTEGER_new
*/
WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_dup(
    const WOLFSSL_ASN1_INTEGER* src);

/*!
    \ingroup CertsKeys

    \brief Sets value of ASN1_INTEGER.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param a ASN1_INTEGER to set
    \param v Value to set

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* num = wolfSSL_ASN1_INTEGER_new();
    int ret = wolfSSL_ASN1_INTEGER_set(num, 12345);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_get
*/
int wolfSSL_ASN1_INTEGER_set(WOLFSSL_ASN1_INTEGER* a, long v);

/*!
    \ingroup CertsKeys

    \brief Decodes ASN1_INTEGER from DER.

    \return WOLFSSL_ASN1_INTEGER* Pointer to decoded integer
    \return NULL on failure

    \param a Pointer to store result
    \param in Pointer to DER data
    \param inSz Length of DER data

    _Example_
    \code
    const unsigned char* der = buffer;
    WOLFSSL_ASN1_INTEGER* num = wolfSSL_d2i_ASN1_INTEGER(NULL, &der,
                                                           len);
    if (num != NULL) {
        long val = wolfSSL_ASN1_INTEGER_get(num);
        wolfSSL_ASN1_INTEGER_free(num);
    }
    \endcode

    \sa wolfSSL_i2d_ASN1_INTEGER
*/
WOLFSSL_ASN1_INTEGER* wolfSSL_d2i_ASN1_INTEGER(WOLFSSL_ASN1_INTEGER** a,
    const unsigned char** in, long inSz);

/*!
    \ingroup CertsKeys

    \brief Encodes ASN1_INTEGER to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param a ASN1_INTEGER to encode
    \param pp Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* num = wolfSSL_ASN1_INTEGER_new();
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_ASN1_INTEGER(num, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_ASN1_INTEGER
*/
int wolfSSL_i2d_ASN1_INTEGER(const WOLFSSL_ASN1_INTEGER* a,
                               unsigned char** pp);

/*!
    \ingroup CertsKeys

    \brief Prints ASN1_TIME to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param asnTime Time to print

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    WOLFSSL_ASN1_TIME* time = wolfSSL_X509_get_notAfter(x509);
    int ret = wolfSSL_ASN1_TIME_print(bio, time);
    \endcode

    \sa wolfSSL_ASN1_TIME_to_string
*/
int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO* bio,
                              const WOLFSSL_ASN1_TIME* asnTime);

/*!
    \ingroup CertsKeys

    \brief Converts ASN1_TIME to string.

    \return char* Pointer to string
    \return NULL on failure

    \param t Time to convert
    \param buf Buffer to store string
    \param len Length of buffer

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_X509_get_notAfter(x509);
    char buf[80];
    char* str = wolfSSL_ASN1_TIME_to_string(time, buf, sizeof(buf));
    if (str != NULL) {
        printf("Time: %s\n", str);
    }
    \endcode

    \sa wolfSSL_ASN1_TIME_print
*/
char* wolfSSL_ASN1_TIME_to_string(WOLFSSL_ASN1_TIME* t, char* buf,
                                    int len);

/*!
    \ingroup CertsKeys

    \brief Converts ASN1_TIME to tm structure.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param asnTime Time to convert
    \param tm Structure to store result

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_X509_get_notAfter(x509);
    struct tm tm;
    int ret = wolfSSL_ASN1_TIME_to_tm(time, &tm);
    if (ret == WOLFSSL_SUCCESS) {
        printf("Year: %d\n", tm.tm_year + 1900);
    }
    \endcode

    \sa wolfSSL_ASN1_TIME_to_string
*/
int wolfSSL_ASN1_TIME_to_tm(const WOLFSSL_ASN1_TIME* asnTime,
                              struct tm* tm);

/*!
    \ingroup CertsKeys

    \brief Compares two ASN1_INTEGERs.

    \return 0 if equal
    \return negative if a < b
    \return positive if a > b

    \param a First integer
    \param b Second integer

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* num1 = wolfSSL_ASN1_INTEGER_new();
    WOLFSSL_ASN1_INTEGER* num2 = wolfSSL_ASN1_INTEGER_new();
    int cmp = wolfSSL_ASN1_INTEGER_cmp(num1, num2);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_get
*/
int wolfSSL_ASN1_INTEGER_cmp(const WOLFSSL_ASN1_INTEGER* a,
                               const WOLFSSL_ASN1_INTEGER* b);

/*!
    \ingroup CertsKeys

    \brief Gets long value from ASN1_INTEGER.

    \return long Integer value

    \param a ASN1_INTEGER to get value from

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* num = wolfSSL_ASN1_INTEGER_new();
    wolfSSL_ASN1_INTEGER_set(num, 12345);
    long val = wolfSSL_ASN1_INTEGER_get(num);
    printf("Value: %ld\n", val);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_set
*/
long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER* a);

/*!
    \ingroup CertsKeys

    \brief Adjusts ASN1_TIME by offset.

    \return WOLFSSL_ASN1_TIME* Pointer to adjusted time
    \return NULL on failure

    \param s ASN1_TIME to adjust (NULL to allocate new)
    \param t Base time
    \param offset_day Day offset
    \param offset_sec Second offset

    _Example_
    \code
    time_t now = time(NULL);
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_adj(NULL, now, 30, 0);
    if (time != NULL) {
        printf("Time 30 days from now\n");
        wolfSSL_ASN1_TIME_free(time);
    }
    \endcode

    \sa wolfSSL_X509_gmtime_adj
*/
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_adj(WOLFSSL_ASN1_TIME* s, time_t t,
                                           int offset_day, long offset_sec);

/*!
    \ingroup CertsKeys

    \brief Creates new ASN1_TIME.

    \return WOLFSSL_ASN1_TIME* Pointer to new time
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    if (time != NULL) {
        wolfSSL_ASN1_TIME_free(time);
    }
    \endcode

    \sa wolfSSL_ASN1_TIME_free
*/
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_new(void);

/*!
    \ingroup CertsKeys

    \brief Frees ASN1_TIME.

    \return none

    \param t ASN1_TIME to free

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    wolfSSL_ASN1_TIME_free(time);
    \endcode

    \sa wolfSSL_ASN1_TIME_new
*/
void wolfSSL_ASN1_TIME_free(WOLFSSL_ASN1_TIME* t);

/*!
    \ingroup CertsKeys

    \brief Gets extra data from X509_STORE_CTX.

    \return void* Pointer to extra data
    \return NULL if not found

    \param ctx X509_STORE_CTX to get data from
    \param idx Index of extra data

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    void* data = wolfSSL_X509_STORE_CTX_get_ex_data(ctx, 0);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_set_ex_data
*/
void* wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX* ctx,
                                           int idx);

/*!
    \ingroup CertsKeys

    \brief Sets extra data in X509_STORE_CTX.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_STORE_CTX to set data in
    \param idx Index of extra data
    \param data Data to set

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    int ret = wolfSSL_X509_STORE_CTX_set_ex_data(ctx, 0, myData);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_ex_data
*/
int wolfSSL_X509_STORE_CTX_set_ex_data(WOLFSSL_X509_STORE_CTX* ctx,
                                         int idx, void* data);

/*!
    \ingroup CertsKeys

    \brief Sets extra data with cleanup in X509_STORE_CTX.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx X509_STORE_CTX to set data in
    \param idx Index of extra data
    \param data Data to set
    \param cleanup_routine Cleanup function

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    int ret = wolfSSL_X509_STORE_CTX_set_ex_data_with_cleanup(ctx, 0,
                                                                myData,
                                                                myCleanup);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_set_ex_data
*/
int wolfSSL_X509_STORE_CTX_set_ex_data_with_cleanup(
    WOLFSSL_X509_STORE_CTX* ctx, int idx, void* data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine);

/*!
    \ingroup CertsKeys

    \brief Gets extra data from X509_STORE.

    \return void* Pointer to extra data
    \return NULL if not found

    \param store X509_STORE to get data from
    \param idx Index of extra data

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    void* data = wolfSSL_X509_STORE_get_ex_data(store, 0);
    \endcode

    \sa wolfSSL_X509_STORE_set_ex_data
*/
void* wolfSSL_X509_STORE_get_ex_data(WOLFSSL_X509_STORE* store, int idx);

/*!
    \ingroup CertsKeys

    \brief Sets extra data in X509_STORE.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param store X509_STORE to set data in
    \param idx Index of extra data
    \param data Data to set

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    int ret = wolfSSL_X509_STORE_set_ex_data(store, 0, myData);
    \endcode

    \sa wolfSSL_X509_STORE_get_ex_data
*/
int wolfSSL_X509_STORE_set_ex_data(WOLFSSL_X509_STORE* store, int idx,
                                     void* data);

/*!
    \ingroup CertsKeys

    \brief Sets extra data with cleanup in X509_STORE.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param store X509_STORE to set data in
    \param idx Index of extra data
    \param data Data to set
    \param cleanup_routine Cleanup function

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_new();
    int ret = wolfSSL_X509_STORE_set_ex_data_with_cleanup(store, 0,
                                                            myData,
                                                            myCleanup);
    \endcode

    \sa wolfSSL_X509_STORE_set_ex_data
*/
int wolfSSL_X509_STORE_set_ex_data_with_cleanup(WOLFSSL_X509_STORE* store,
    int idx, void* data, wolfSSL_ex_data_cleanup_routine_t cleanup_routine);

/*!
    \ingroup CertsKeys

    \brief Sets verification depth in X509_STORE_CTX.

    \return none

    \param ctx X509_STORE_CTX to modify
    \param depth Maximum verification depth

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    wolfSSL_X509_STORE_CTX_set_depth(ctx, 5);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error_depth
*/
void wolfSSL_X509_STORE_CTX_set_depth(WOLFSSL_X509_STORE_CTX* ctx,
                                        int depth);

/*!
    \ingroup CertsKeys

    \brief Gets current issuer from X509_STORE_CTX.

    \return WOLFSSL_X509* Pointer to current issuer
    \return NULL if not found

    \param ctx X509_STORE_CTX to get issuer from

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_X509* issuer = wolfSSL_X509_STORE_CTX_get0_current_issuer(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get0_cert
*/
WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_current_issuer(
    WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets X509_STORE from X509_STORE_CTX.

    \return WOLFSSL_X509_STORE* Pointer to store
    \return NULL if not found

    \param ctx X509_STORE_CTX to get store from

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_X509_STORE* store = wolfSSL_X509_STORE_CTX_get0_store(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get0_cert
*/
WOLFSSL_X509_STORE* wolfSSL_X509_STORE_CTX_get0_store(
    WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets certificate from X509_STORE_CTX.

    \return WOLFSSL_X509* Pointer to certificate
    \return NULL if not found

    \param ctx X509_STORE_CTX to get certificate from

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    WOLFSSL_X509* cert = wolfSSL_X509_STORE_CTX_get0_cert(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get0_store
*/
WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_cert(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets ex_data index for X509_STORE_CTX.

    \return int Ex_data index

    _Example_
    \code
    int idx = wolfSSL_get_ex_data_X509_STORE_CTX_idx();
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_ex_data
*/
int wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);

/*!
    \ingroup CertsKeys

    \brief Sets error in X509_STORE_CTX.

    \return none

    \param ctx X509_STORE_CTX to set error in
    \param er Error code

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    wolfSSL_X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_HAS_EXPIRED);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error
*/
void wolfSSL_X509_STORE_CTX_set_error(WOLFSSL_X509_STORE_CTX* ctx, int er);

/*!
    \ingroup openSSL

    \brief Peeks at error without removing from queue.

    \return unsigned long Error code
    \return 0 if no error

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_peek_error();
    if (err != 0) {
        printf("Error: %lu\n", err);
    }
    \endcode

    \sa wolfSSL_ERR_get_error
*/
unsigned long wolfSSL_ERR_peek_error(void);

/*!
    \ingroup openSSL

    \brief Gets reason code from error.

    \return int Reason code

    \param err Error code

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    int reason = wolfSSL_GET_REASON(err);
    \endcode

    \sa wolfSSL_ERR_get_error
*/
int wolfSSL_GET_REASON(int err);

/*!
    \ingroup openSSL

    \brief Gets long alert type string.

    \return const char* Alert type string

    \param alertID Alert identifier

    _Example_
    \code
    const char* type = wolfSSL_alert_type_string_long(alertID);
    printf("Alert type: %s\n", type);
    \endcode

    \sa wolfSSL_alert_desc_string_long
*/
const char* wolfSSL_alert_type_string_long(int alertID);

/*!
    \ingroup openSSL

    \brief Gets long alert description string.

    \return const char* Alert description string

    \param alertID Alert identifier

    _Example_
    \code
    const char* desc = wolfSSL_alert_desc_string_long(alertID);
    printf("Alert: %s\n", desc);
    \endcode

    \sa wolfSSL_alert_type_string_long
*/
const char* wolfSSL_alert_desc_string_long(int alertID);

/*!
    \ingroup openSSL

    \brief Gets long state string.

    \return const char* State string

    \param ssl SSL object

    _Example_
    \code
    const char* state = wolfSSL_state_string_long(ssl);
    printf("State: %s\n", state);
    \endcode

    \sa wolfSSL_state_string
*/
const char* wolfSSL_state_string_long(const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Encodes RSA public key to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param r RSA key to encode
    \param pp Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_RSAPublicKey(rsa, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_i2d_RSAPrivateKey
*/
int wolfSSL_i2d_RSAPublicKey(WOLFSSL_RSA* r, unsigned char** pp);

/*!
    \ingroup openSSL

    \brief Encodes RSA private key to DER.

    \return int Length of DER encoding
    \return negative value on failure

    \param r RSA key to encode
    \param pp Pointer to store DER buffer

    _Example_
    \code
    WOLFSSL_RSA* rsa = wolfSSL_RSA_new();
    unsigned char* der = NULL;
    int derLen = wolfSSL_i2d_RSAPrivateKey(rsa, &der);
    if (derLen > 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_i2d_RSAPublicKey
*/
int wolfSSL_i2d_RSAPrivateKey(WOLFSSL_RSA* r, unsigned char** pp);

/*!
    \ingroup openSSL

    \brief Default PEM password callback.

    \return int Length of password

    \param name Buffer for password
    \param num Maximum password length
    \param w Read/write flag
    \param key User data

    _Example_
    \code
    char passwd[128];
    int len = wolfSSL_PEM_def_callback(passwd, sizeof(passwd), 0, NULL);
    \endcode

    \sa wolfSSL_CTX_set_default_passwd_cb
*/
int wolfSSL_PEM_def_callback(char* name, int num, int w, void* key);

/*!
    \ingroup openSSL

    \brief Gets session accept count.

    \return long Number of accepts

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long accepts = wolfSSL_CTX_sess_accept(ctx);
    printf("Accepts: %ld\n", accepts);
    \endcode

    \sa wolfSSL_CTX_sess_connect
*/
long wolfSSL_CTX_sess_accept(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets session connect count.

    \return long Number of connects

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long connects = wolfSSL_CTX_sess_connect(ctx);
    printf("Connects: %ld\n", connects);
    \endcode

    \sa wolfSSL_CTX_sess_accept
*/
long wolfSSL_CTX_sess_connect(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets successful accept count.

    \return long Number of successful accepts

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long good = wolfSSL_CTX_sess_accept_good(ctx);
    printf("Good accepts: %ld\n", good);
    \endcode

    \sa wolfSSL_CTX_sess_accept
*/
long wolfSSL_CTX_sess_accept_good(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets successful connect count.

    \return long Number of successful connects

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long good = wolfSSL_CTX_sess_connect_good(ctx);
    printf("Good connects: %ld\n", good);
    \endcode

    \sa wolfSSL_CTX_sess_connect
*/
long wolfSSL_CTX_sess_connect_good(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets accept renegotiation count.

    \return long Number of accept renegotiations

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long reneg = wolfSSL_CTX_sess_accept_renegotiate(ctx);
    printf("Accept renegotiations: %ld\n", reneg);
    \endcode

    \sa wolfSSL_CTX_sess_connect_renegotiate
*/
long wolfSSL_CTX_sess_accept_renegotiate(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets connect renegotiation count.

    \return long Number of connect renegotiations

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long reneg = wolfSSL_CTX_sess_connect_renegotiate(ctx);
    printf("Connect renegotiations: %ld\n", reneg);
    \endcode

    \sa wolfSSL_CTX_sess_accept_renegotiate
*/
long wolfSSL_CTX_sess_connect_renegotiate(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets session cache hit count.

    \return long Number of cache hits

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long hits = wolfSSL_CTX_sess_hits(ctx);
    printf("Cache hits: %ld\n", hits);
    \endcode

    \sa wolfSSL_CTX_sess_misses
*/
long wolfSSL_CTX_sess_hits(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets session callback hit count.

    \return long Number of callback hits

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long cb_hits = wolfSSL_CTX_sess_cb_hits(ctx);
    printf("Callback hits: %ld\n", cb_hits);
    \endcode

    \sa wolfSSL_CTX_sess_hits
*/
long wolfSSL_CTX_sess_cb_hits(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets session cache full count.

    \return long Number of times cache was full

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long full = wolfSSL_CTX_sess_cache_full(ctx);
    printf("Cache full: %ld\n", full);
    \endcode

    \sa wolfSSL_CTX_sess_hits
*/
long wolfSSL_CTX_sess_cache_full(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets session cache miss count.

    \return long Number of cache misses

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long misses = wolfSSL_CTX_sess_misses(ctx);
    printf("Cache misses: %ld\n", misses);
    \endcode

    \sa wolfSSL_CTX_sess_hits
*/
long wolfSSL_CTX_sess_misses(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets session timeout count.

    \return long Number of session timeouts

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long timeouts = wolfSSL_CTX_sess_timeouts(ctx);
    printf("Timeouts: %ld\n", timeouts);
    \endcode

    \sa wolfSSL_CTX_sess_hits
*/
long wolfSSL_CTX_sess_timeouts(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets number of sessions in cache.

    \return long Number of sessions

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long num = wolfSSL_CTX_sess_number(ctx);
    printf("Sessions: %ld\n", num);
    \endcode

    \sa wolfSSL_CTX_sess_hits
*/
long wolfSSL_CTX_sess_number(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Sets session cache size.

    \return long Previous cache size

    \param ctx SSL context
    \param sz New cache size

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long prev = wolfSSL_CTX_sess_set_cache_size(ctx, 1000);
    \endcode

    \sa wolfSSL_CTX_sess_get_cache_size
*/
long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX* ctx, long sz);

/*!
    \ingroup openSSL

    \brief Gets session cache size.

    \return long Cache size

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long size = wolfSSL_CTX_sess_get_cache_size(ctx);
    printf("Cache size: %ld\n", size);
    \endcode

    \sa wolfSSL_CTX_sess_set_cache_size
*/
long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets session cache mode.

    \return long Cache mode flags

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long mode = wolfSSL_CTX_get_session_cache_mode(ctx);
    \endcode

    \sa wolfSSL_CTX_set_session_cache_mode
*/
long wolfSSL_CTX_get_session_cache_mode(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets read-ahead mode.

    \return int Read-ahead setting

    \param ssl SSL object

    _Example_
    \code
    int ahead = wolfSSL_get_read_ahead(ssl);
    if (ahead) {
        printf("Read-ahead enabled\n");
    }
    \endcode

    \sa wolfSSL_set_read_ahead
*/
int wolfSSL_get_read_ahead(const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Sets read-ahead mode.

    \return int Previous read-ahead setting

    \param ssl SSL object
    \param v Read-ahead value

    _Example_
    \code
    int ret = wolfSSL_set_read_ahead(ssl, 1);
    \endcode

    \sa wolfSSL_get_read_ahead
*/
int wolfSSL_set_read_ahead(WOLFSSL* ssl, int v);

/*!
    \ingroup openSSL

    \brief Adds client CA to context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param x509 CA certificate

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL_X509* ca = wolfSSL_X509_load_certificate_file("ca.pem",
                                                            format);
    int ret = wolfSSL_CTX_add_client_CA(ctx, ca);
    \endcode

    \sa wolfSSL_add_client_CA
*/
int wolfSSL_CTX_add_client_CA(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup openSSL

    \brief Adds client CA to SSL object.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param x509 CA certificate

    _Example_
    \code
    WOLFSSL_X509* ca = wolfSSL_X509_load_certificate_file("ca.pem",
                                                            format);
    int ret = wolfSSL_add_client_CA(ssl, ca);
    \endcode

    \sa wolfSSL_CTX_add_client_CA
*/
int wolfSSL_add_client_CA(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup openSSL

    \brief Adds certificate to CA list in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param x509 Certificate to add

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL_X509* cert = wolfSSL_X509_load_certificate_file("cert.pem",
                                                              format);
    int ret = wolfSSL_CTX_add1_to_CA_list(ctx, cert);
    \endcode

    \sa wolfSSL_add1_to_CA_list
*/
int wolfSSL_CTX_add1_to_CA_list(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup openSSL

    \brief Adds certificate to CA list in SSL object.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param x509 Certificate to add

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_load_certificate_file("cert.pem",
                                                              format);
    int ret = wolfSSL_add1_to_CA_list(ssl, cert);
    \endcode

    \sa wolfSSL_CTX_add1_to_CA_list
*/
int wolfSSL_add1_to_CA_list(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup openSSL

    \brief Sets SRP password in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param password SRP password

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_set_srp_password(ctx, "mypassword");
    \endcode

    \sa wolfSSL_CTX_set_srp_username
*/
int wolfSSL_CTX_set_srp_password(WOLFSSL_CTX* ctx, char* password);

/*!
    \ingroup openSSL

    \brief Sets SRP username in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param username SRP username

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_set_srp_username(ctx, "myuser");
    \endcode

    \sa wolfSSL_CTX_set_srp_password
*/
int wolfSSL_CTX_set_srp_username(WOLFSSL_CTX* ctx, char* username);

/*!
    \ingroup openSSL

    \brief Sets SRP strength in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param strength SRP strength

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_set_srp_strength(ctx, 2048);
    \endcode

    \sa wolfSSL_CTX_set_srp_username
*/
int wolfSSL_CTX_set_srp_strength(WOLFSSL_CTX* ctx, int strength);

/*!
    \ingroup openSSL

    \brief Gets SRP username from SSL object.

    \return char* SRP username
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    char* user = wolfSSL_get_srp_username(ssl);
    if (user != NULL) {
        printf("SRP user: %s\n", user);
    }
    \endcode

    \sa wolfSSL_CTX_set_srp_username
*/
char* wolfSSL_get_srp_username(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Clears SSL options.

    \return long Updated options

    \param s SSL object
    \param op Options to clear

    _Example_
    \code
    long opts = wolfSSL_clear_options(ssl, SSL_OP_NO_TLSv1);
    \endcode

    \sa wolfSSL_set_options
*/
long wolfSSL_clear_options(WOLFSSL* s, long op);

/*!
    \ingroup openSSL

    \brief Sets temporary DH parameters.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s SSL object
    \param dh DH parameters

    _Example_
    \code
    WOLFSSL_DH* dh = wolfSSL_DH_new();
    long ret = wolfSSL_set_tmp_dh(ssl, dh);
    \endcode

    \sa wolfSSL_CTX_SetTmpDH
*/
long wolfSSL_set_tmp_dh(WOLFSSL* s, WOLFSSL_DH* dh);

/*!
    \ingroup openSSL

    \brief Gets TLS extension status type.

    \return long Status type

    \param s SSL object

    _Example_
    \code
    long type = wolfSSL_get_tlsext_status_type(ssl);
    \endcode

    \sa wolfSSL_set_tlsext_status_type
*/
long wolfSSL_get_tlsext_status_type(WOLFSSL* s);

/*!
    \ingroup openSSL

    \brief Sets TLS extension status extensions.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s SSL object
    \param arg Extension data

    _Example_
    \code
    long ret = wolfSSL_set_tlsext_status_exts(ssl, exts);
    \endcode

    \sa wolfSSL_get_tlsext_status_exts
*/
long wolfSSL_set_tlsext_status_exts(WOLFSSL* s, void* arg);

/*!
    \ingroup openSSL

    \brief Gets TLS extension status IDs.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s SSL object
    \param arg ID data

    _Example_
    \code
    long ret = wolfSSL_get_tlsext_status_ids(ssl, &ids);
    \endcode

    \sa wolfSSL_set_tlsext_status_ids
*/
long wolfSSL_get_tlsext_status_ids(WOLFSSL* s, void* arg);

/*!
    \ingroup openSSL

    \brief Sets TLS extension status IDs.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s SSL object
    \param arg ID data

    _Example_
    \code
    long ret = wolfSSL_set_tlsext_status_ids(ssl, ids);
    \endcode

    \sa wolfSSL_get_tlsext_status_ids
*/
long wolfSSL_set_tlsext_status_ids(WOLFSSL* s, void* arg);

/*!
    \ingroup openSSL

    \brief Sets maximum fragment length.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s SSL object
    \param mode Fragment length mode

    _Example_
    \code
    int ret = wolfSSL_set_tlsext_max_fragment_length(ssl,
                                                       TLSEXT_max_fragment_length_512);
    \endcode

    \sa wolfSSL_CTX_set_tlsext_max_fragment_length
*/
int wolfSSL_set_tlsext_max_fragment_length(WOLFSSL* s, unsigned char mode);

/*!
    \ingroup openSSL

    \brief Sets maximum fragment length in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param c SSL context
    \param mode Fragment length mode

    _Example_
    \code
    int ret = wolfSSL_CTX_set_tlsext_max_fragment_length(ctx,
                                                           TLSEXT_max_fragment_length_1024);
    \endcode

    \sa wolfSSL_set_tlsext_max_fragment_length
*/
int wolfSSL_CTX_set_tlsext_max_fragment_length(WOLFSSL_CTX* c,
                                                 unsigned char mode);

/*!
    \ingroup openSSL

    \brief Unloads configuration modules.

    \return none

    \param all Unload all flag

    _Example_
    \code
    wolfSSL_CONF_modules_unload(1);
    \endcode

    \sa wolfSSL_CONF_modules_load
*/
void wolfSSL_CONF_modules_unload(int all);

/*!
    \ingroup openSSL

    \brief Gets default config file path.

    \return char* Config file path
    \return NULL on failure

    _Example_
    \code
    char* path = wolfSSL_CONF_get1_default_config_file();
    if (path != NULL) {
        printf("Config: %s\n", path);
        XFREE(path, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_CONF_modules_load
*/
char* wolfSSL_CONF_get1_default_config_file(void);

/*!
    \ingroup openSSL

    \brief Gets TLS extension status extensions.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s SSL object
    \param arg Extension data

    _Example_
    \code
    long ret = wolfSSL_get_tlsext_status_exts(ssl, &exts);
    \endcode

    \sa wolfSSL_set_tlsext_status_exts
*/
long wolfSSL_get_tlsext_status_exts(WOLFSSL* s, void* arg);

/*!
    \ingroup openSSL

    \brief Gets application data from SSL object.

    \return void* Application data pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* data = wolfSSL_get_app_data(ssl);
    if (data != NULL) {
        MyAppData* appData = (MyAppData*)data;
    }
    \endcode

    \sa wolfSSL_set_app_data
*/
void* wolfSSL_get_app_data(const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Sets password callback user data.

    \return none

    \param ctx SSL context
    \param userdata User data pointer

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    wolfSSL_CTX_set_default_passwd_cb_userdata(ctx, myData);
    \endcode

    \sa wolfSSL_CTX_set_default_passwd_cb
*/
void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX* ctx,
                                                  void* userdata);

/*!
    \ingroup openSSL

    \brief Sets password callback function.

    \return none

    \param ctx SSL context
    \param cb Password callback function

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    wolfSSL_CTX_set_default_passwd_cb(ctx, myPasswordCallback);
    \endcode

    \sa wolfSSL_CTX_get_default_passwd_cb
*/
void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX* ctx,
                                         wc_pem_password_cb* cb);

/*!
    \ingroup openSSL

    \brief Gets password callback function.

    \return wc_pem_password_cb* Password callback
    \return NULL if not set

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    wc_pem_password_cb* cb = wolfSSL_CTX_get_default_passwd_cb(ctx);
    \endcode

    \sa wolfSSL_CTX_set_default_passwd_cb
*/
wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Checks if renegotiation is pending.

    \return 1 if pending
    \return 0 if not pending

    \param s SSL object

    _Example_
    \code
    int pending = wolfSSL_SSL_renegotiate_pending(ssl);
    if (pending) {
        printf("Renegotiation pending\n");
    }
    \endcode

    \sa wolfSSL_Rehandshake
*/
int wolfSSL_SSL_renegotiate_pending(WOLFSSL* s);

/*!
    \ingroup openSSL

    \brief Gets total renegotiation count.

    \return long Number of renegotiations

    \param s SSL object

    _Example_
    \code
    long total = wolfSSL_total_renegotiations(ssl);
    printf("Total renegotiations: %ld\n", total);
    \endcode

    \sa wolfSSL_num_renegotiations
*/
long wolfSSL_total_renegotiations(WOLFSSL* s);

/*!
    \ingroup openSSL

    \brief Gets current renegotiation count.

    \return long Number of renegotiations

    \param s SSL object

    _Example_
    \code
    long num = wolfSSL_num_renegotiations(ssl);
    printf("Renegotiations: %ld\n", num);
    \endcode

    \sa wolfSSL_total_renegotiations
*/
long wolfSSL_num_renegotiations(WOLFSSL* s);

/*!
    \ingroup openSSL

    \brief Clears renegotiation count.

    \return long Previous count

    \param s SSL object

    _Example_
    \code
    long prev = wolfSSL_clear_num_renegotiations(ssl);
    \endcode

    \sa wolfSSL_num_renegotiations
*/
long wolfSSL_clear_num_renegotiations(WOLFSSL* s);

/*!
    \ingroup openSSL

    \brief Sets read file descriptor.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param rfd Read file descriptor

    _Example_
    \code
    int ret = wolfSSL_set_rfd(ssl, sockfd);
    \endcode

    \sa wolfSSL_set_wfd
*/
int wolfSSL_set_rfd(WOLFSSL* ssl, int rfd);

/*!
    \ingroup openSSL

    \brief Sets write file descriptor.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param wfd Write file descriptor

    _Example_
    \code
    int ret = wolfSSL_set_wfd(ssl, sockfd);
    \endcode

    \sa wolfSSL_set_rfd
*/
int wolfSSL_set_wfd(WOLFSSL* ssl, int wfd);

/*!
    \ingroup openSSL

    \brief Sets shutdown mode.

    \return none

    \param ssl SSL object
    \param opt Shutdown options

    _Example_
    \code
    wolfSSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN);
    \endcode

    \sa wolfSSL_get_shutdown
*/
void wolfSSL_set_shutdown(WOLFSSL* ssl, int opt);

/*!
    \ingroup openSSL

    \brief Sets session ID context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param id Session ID context
    \param len Length of context

    _Example_
    \code
    unsigned char id[] = "myapp";
    int ret = wolfSSL_set_session_id_context(ssl, id, sizeof(id));
    \endcode

    \sa wolfSSL_CTX_set_session_id_context
*/
int wolfSSL_set_session_id_context(WOLFSSL* ssl, const unsigned char* id,
                                     unsigned int len);

/*!
    \ingroup openSSL

    \brief Sets SSL to connect state.

    \return none

    \param ssl SSL object

    _Example_
    \code
    wolfSSL_set_connect_state(ssl);
    int ret = wolfSSL_connect(ssl);
    \endcode

    \sa wolfSSL_set_accept_state
*/
void wolfSSL_set_connect_state(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Sets SSL to accept state.

    \return none

    \param ssl SSL object

    _Example_
    \code
    wolfSSL_set_accept_state(ssl);
    int ret = wolfSSL_accept(ssl);
    \endcode

    \sa wolfSSL_set_connect_state
*/
void wolfSSL_set_accept_state(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets maximum fragment length from session.

    \return unsigned char Fragment length

    \param session SSL session

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_get_session(ssl);
    unsigned char mfl = wolfSSL_SESSION_get_max_fragment_length(session);
    \endcode

    \sa wolfSSL_set_tlsext_max_fragment_length
*/
unsigned char wolfSSL_SESSION_get_max_fragment_length(
    WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Increments session reference count.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param session SSL session

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_get_session(ssl);
    int ret = wolfSSL_SESSION_up_ref(session);
    \endcode

    \sa wolfSSL_SESSION_free
*/
int wolfSSL_SESSION_up_ref(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Duplicates SSL session.

    \return WOLFSSL_SESSION* Duplicated session
    \return NULL on failure

    \param session SSL session to duplicate

    _Example_
    \code
    WOLFSSL_SESSION* orig = wolfSSL_get_session(ssl);
    WOLFSSL_SESSION* dup = wolfSSL_SESSION_dup(orig);
    if (dup != NULL) {
        wolfSSL_SESSION_free(dup);
    }
    \endcode

    \sa wolfSSL_SESSION_new
*/
WOLFSSL_SESSION* wolfSSL_SESSION_dup(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Creates new SSL session.

    \return WOLFSSL_SESSION* New session
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_SESSION_new();
    if (session != NULL) {
        wolfSSL_SESSION_free(session);
    }
    \endcode

    \sa wolfSSL_SESSION_free
*/
WOLFSSL_SESSION* wolfSSL_SESSION_new(void);

/*!
    \ingroup openSSL

    \brief Creates new SSL session with heap.

    \return WOLFSSL_SESSION* New session
    \return NULL on failure

    \param heap Heap hint

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_SESSION_new_ex(myHeap);
    if (session != NULL) {
        wolfSSL_SESSION_free(session);
    }
    \endcode

    \sa wolfSSL_SESSION_new
*/
WOLFSSL_SESSION* wolfSSL_SESSION_new_ex(void* heap);

/*!
    \ingroup openSSL

    \brief Frees SSL session.

    \return none

    \param session SSL session to free

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_SESSION_new();
    wolfSSL_SESSION_free(session);
    \endcode

    \sa wolfSSL_SESSION_new
*/
void wolfSSL_SESSION_free(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Adds session to context cache.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param session Session to add

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL_SESSION* session = wolfSSL_SESSION_new();
    int ret = wolfSSL_CTX_add_session(ctx, session);
    \endcode

    \sa wolfSSL_CTX_remove_session
*/
int wolfSSL_CTX_add_session(WOLFSSL_CTX* ctx, WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Sets cipher in session.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param session SSL session
    \param cipher Cipher to set

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_SESSION_new();
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    int ret = wolfSSL_SESSION_set_cipher(session, cipher);
    \endcode

    \sa wolfSSL_get_current_cipher
*/
int wolfSSL_SESSION_set_cipher(WOLFSSL_SESSION* session,
                                 const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets protocol version string.

    \return const char* Version string

    \param ssl SSL object

    _Example_
    \code
    const char* version = wolfSSL_get_version(ssl);
    printf("Version: %s\n", version);
    \endcode

    \sa wolfSSL_version
*/
const char* wolfSSL_get_version(const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets current cipher.

    \return WOLFSSL_CIPHER* Current cipher
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    if (cipher != NULL) {
        const char* name = wolfSSL_CIPHER_get_name(cipher);
        printf("Cipher: %s\n", name);
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
WOLFSSL_CIPHER* wolfSSL_get_current_cipher(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets cipher description.

    \return char* Description string
    \return NULL on failure

    \param cipher Cipher to describe
    \param in Buffer for description
    \param len Buffer length

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    char desc[256];
    char* ret = wolfSSL_CIPHER_description(cipher, desc, sizeof(desc));
    if (ret != NULL) {
        printf("Description: %s\n", desc);
    }
    \endcode

    \sa wolfSSL_get_current_cipher
*/
char* wolfSSL_CIPHER_description(const WOLFSSL_CIPHER* cipher, char* in,
                                   int len);

/*!
    \ingroup openSSL

    \brief Gets cipher name.

    \return const char* Cipher name

    \param cipher Cipher to get name from

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    const char* name = wolfSSL_CIPHER_get_name(cipher);
    printf("Cipher: %s\n", name);
    \endcode

    \sa wolfSSL_get_current_cipher
*/
const char* wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets cipher version.

    \return const char* Version string

    \param cipher Cipher to get version from

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    const char* version = wolfSSL_CIPHER_get_version(cipher);
    printf("Version: %s\n", version);
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
const char* wolfSSL_CIPHER_get_version(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets cipher ID.

    \return word32 Cipher ID

    \param cipher Cipher to get ID from

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    word32 id = wolfSSL_CIPHER_get_id(cipher);
    printf("Cipher ID: 0x%08X\n", id);
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
word32 wolfSSL_CIPHER_get_id(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets cipher authentication NID.

    \return int Authentication NID

    \param cipher Cipher to get auth NID from

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    int nid = wolfSSL_CIPHER_get_auth_nid(cipher);
    \endcode

    \sa wolfSSL_CIPHER_get_cipher_nid
*/
int wolfSSL_CIPHER_get_auth_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets cipher algorithm NID.

    \return int Cipher NID

    \param cipher Cipher to get NID from

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    int nid = wolfSSL_CIPHER_get_cipher_nid(cipher);
    \endcode

    \sa wolfSSL_CIPHER_get_auth_nid
*/
int wolfSSL_CIPHER_get_cipher_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets cipher digest NID.

    \return int Digest NID

    \param cipher Cipher to get digest NID from

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    int nid = wolfSSL_CIPHER_get_digest_nid(cipher);
    \endcode

    \sa wolfSSL_CIPHER_get_cipher_nid
*/
int wolfSSL_CIPHER_get_digest_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets cipher key exchange NID.

    \return int Key exchange NID

    \param cipher Cipher to get kx NID from

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    int nid = wolfSSL_CIPHER_get_kx_nid(cipher);
    \endcode

    \sa wolfSSL_CIPHER_get_cipher_nid
*/
int wolfSSL_CIPHER_get_kx_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Checks if cipher is AEAD.

    \return 1 if AEAD
    \return 0 if not AEAD

    \param cipher Cipher to check

    _Example_
    \code
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(ssl);
    int isAead = wolfSSL_CIPHER_is_aead(cipher);
    if (isAead) {
        printf("Cipher is AEAD\n");
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
int wolfSSL_CIPHER_is_aead(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL

    \brief Gets cipher by value.

    \return const WOLFSSL_CIPHER* Cipher object
    \return NULL if not found

    \param value Cipher suite value

    _Example_
    \code
    const WOLFSSL_CIPHER* cipher = wolfSSL_get_cipher_by_value(0x1301);
    if (cipher != NULL) {
        const char* name = wolfSSL_CIPHER_get_name(cipher);
        printf("Cipher: %s\n", name);
    }
    \endcode

    \sa wolfSSL_get_current_cipher
*/
const WOLFSSL_CIPHER* wolfSSL_get_cipher_by_value(word16 value);

/*!
    \ingroup openSSL

    \brief Gets cipher name from session.

    \return const char* Cipher name
    \return NULL if not set

    \param session SSL session

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_get_session(ssl);
    const char* name = wolfSSL_SESSION_CIPHER_get_name(session);
    if (name != NULL) {
        printf("Session cipher: %s\n", name);
    }
    \endcode

    \sa wolfSSL_get_cipher
*/
const char* wolfSSL_SESSION_CIPHER_get_name(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Gets cipher name string.

    \return const char* Cipher name

    \param ssl SSL object

    _Example_
    \code
    const char* cipher = wolfSSL_get_cipher(ssl);
    printf("Cipher: %s\n", cipher);
    \endcode

    \sa wolfSSL_get_current_cipher
*/
const char* wolfSSL_get_cipher(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets session with reference count increment.

    \return WOLFSSL_SESSION* Session object
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_get1_session(ssl);
    if (session != NULL) {
        wolfSSL_SESSION_free(session);
    }
    \endcode

    \sa wolfSSL_get_session
*/
WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Checks if session is setup.

    \return 1 if setup
    \return 0 if not setup

    \param session SSL session

    _Example_
    \code
    WOLFSSL_SESSION* session = wolfSSL_get_session(ssl);
    int setup = wolfSSL_SessionIsSetup(session);
    if (setup) {
        printf("Session is setup\n");
    }
    \endcode

    \sa wolfSSL_get_session
*/
int wolfSSL_SessionIsSetup(WOLFSSL_SESSION* session);

/*!
    \ingroup CertsKeys

    \brief Creates new X509_STORE_CTX.

    \return WOLFSSL_X509_STORE_CTX* New context
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    if (ctx != NULL) {
        wolfSSL_X509_STORE_CTX_free(ctx);
    }
    \endcode

    \sa wolfSSL_X509_STORE_CTX_free
*/
WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void);

/*!
    \ingroup CertsKeys

    \brief Creates new X509_STORE_CTX with heap.

    \return WOLFSSL_X509_STORE_CTX* New context
    \return NULL on failure

    \param heap Heap hint

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new_ex(myHeap);
    if (ctx != NULL) {
        wolfSSL_X509_STORE_CTX_free(ctx);
    }
    \endcode

    \sa wolfSSL_X509_STORE_CTX_new
*/
WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new_ex(void* heap);

/*!
    \ingroup CertsKeys

    \brief Frees X509_STORE_CTX.

    \return none

    \param ctx X509_STORE_CTX to free

    _Example_
    \code
    WOLFSSL_X509_STORE_CTX* ctx = wolfSSL_X509_STORE_CTX_new();
    wolfSSL_X509_STORE_CTX_free(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_new
*/
void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Converts X509_NAME to one-line string.

    \return char* Name string
    \return NULL on failure

    \param name X509_NAME to convert
    \param in Buffer for string
    \param sz Buffer size

    _Example_
    \code
    WOLFSSL_X509* x509 = wolfSSL_get_peer_certificate(ssl);
    WOLFSSL_X509_NAME* name = wolfSSL_X509_get_subject_name(x509);
    char buf[256];
    char* str = wolfSSL_X509_NAME_oneline(name, buf, sizeof(buf));
    if (str != NULL) {
        printf("Subject: %s\n", str);
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
*/
char* wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME* name, char* in, int sz);

/*!
    \ingroup openSSL

    \brief Dumps errors to file pointer.

    \return none

    \param fp File pointer

    _Example_
    \code
    wolfSSL_ERR_dump_errors_fp(stderr);
    \endcode

    \sa wolfSSL_ERR_print_errors_fp
*/
void wolfSSL_ERR_dump_errors_fp(XFILE fp);

/*!
    \ingroup openSSL

    \brief Sets PSK use session callback.

    \return none

    \param ssl SSL object
    \param cb Callback function

    _Example_
    \code
    wolfSSL_set_psk_use_session_callback(ssl, myPskUseSessionCallback);
    \endcode

    \sa wolfSSL_set_psk_client_callback
*/
void wolfSSL_set_psk_use_session_callback(WOLFSSL* ssl,
                                            wc_psk_use_session_cb_func cb);

/*!
    \ingroup openSSL

    \brief Sets PSK client cipher suite callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    wolfSSL_CTX_set_psk_client_cs_callback(ctx, myPskClientCsCallback);
    \endcode

    \sa wolfSSL_set_psk_client_cs_callback
*/
void wolfSSL_CTX_set_psk_client_cs_callback(WOLFSSL_CTX* ctx,
                                              wc_psk_client_cs_callback cb);

/*!
    \ingroup openSSL

    \brief Sets PSK client cipher suite callback.

    \return none

    \param ssl SSL object
    \param cb Callback function

    _Example_
    \code
    wolfSSL_set_psk_client_cs_callback(ssl, myPskClientCsCallback);
    \endcode

    \sa wolfSSL_CTX_set_psk_client_cs_callback
*/
void wolfSSL_set_psk_client_cs_callback(WOLFSSL* ssl,
                                          wc_psk_client_cs_callback cb);

/*!
    \ingroup openSSL

    \brief Gets PSK identity hint.

    \return const char* Identity hint
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    const char* hint = wolfSSL_get_psk_identity_hint(ssl);
    if (hint != NULL) {
        printf("PSK hint: %s\n", hint);
    }
    \endcode

    \sa wolfSSL_get_psk_identity
*/
const char* wolfSSL_get_psk_identity_hint(const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets PSK identity.

    \return const char* Identity
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    const char* identity = wolfSSL_get_psk_identity(ssl);
    if (identity != NULL) {
        printf("PSK identity: %s\n", identity);
    }
    \endcode

    \sa wolfSSL_get_psk_identity_hint
*/
const char* wolfSSL_get_psk_identity(const WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets PSK callback context.

    \return void* Callback context
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_get_psk_callback_ctx(ssl);
    \endcode

    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets PSK callback context from context.

    \return void* Callback context
    \return NULL if not set

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    void* cbCtx = wolfSSL_CTX_get_psk_callback_ctx(ctx);
    \endcode

    \sa wolfSSL_get_psk_callback_ctx
*/
void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Gets cipher name by hash.

    \return const char* Cipher name
    \return NULL if not found

    \param ssl SSL object
    \param hash Hash string

    _Example_
    \code
    const char* name = wolfSSL_get_cipher_name_by_hash(ssl, "SHA256");
    if (name != NULL) {
        printf("Cipher: %s\n", name);
    }
    \endcode

    \sa wolfSSL_get_cipher
*/
const char* wolfSSL_get_cipher_name_by_hash(WOLFSSL* ssl,
                                              const char* hash);

/*!
    \ingroup openSSL

    \brief Puts error on error queue.

    \return none

    \param lib Library code
    \param fun Function code
    \param err Error code
    \param file Source file
    \param line Line number

    _Example_
    \code
    wolfSSL_ERR_put_error(0, 0, -1, __FILE__, __LINE__);
    \endcode

    \sa wolfSSL_ERR_get_error
*/
void wolfSSL_ERR_put_error(int lib, int fun, int err, const char* file,
                             int line);

/*!
    \ingroup openSSL

    \brief Gets error with file and line.

    \return unsigned long Error code
    \return 0 if no error

    \param file Pointer to store file name
    \param line Pointer to store line number

    _Example_
    \code
    const char* file;
    int line;
    unsigned long err = wolfSSL_ERR_get_error_line(&file, &line);
    if (err != 0) {
        printf("Error at %s:%d\n", file, line);
    }
    \endcode

    \sa wolfSSL_ERR_get_error
*/
unsigned long wolfSSL_ERR_get_error_line(const char** file, int* line);

/*!
    \ingroup openSSL

    \brief Gets error with file, line, and data.

    \return unsigned long Error code
    \return 0 if no error

    \param file Pointer to store file name
    \param line Pointer to store line number
    \param data Pointer to store error data
    \param flags Pointer to store flags

    _Example_
    \code
    const char* file;
    const char* data;
    int line, flags;
    unsigned long err = wolfSSL_ERR_get_error_line_data(&file, &line,
                                                         &data, &flags);
    \endcode

    \sa wolfSSL_ERR_get_error_line
*/
unsigned long wolfSSL_ERR_get_error_line_data(const char** file, int* line,
                                                const char** data, int* flags);

/*!
    \ingroup openSSL

    \brief Gets error from queue.

    \return unsigned long Error code
    \return 0 if no error

    _Example_
    \code
    unsigned long err = wolfSSL_ERR_get_error();
    if (err != 0) {
        printf("Error: %lu\n", err);
    }
    \endcode

    \sa wolfSSL_ERR_peek_error
*/
unsigned long wolfSSL_ERR_get_error(void);

/*!
    \ingroup openSSL

    \brief Clears error queue.

    \return none

    _Example_
    \code
    wolfSSL_ERR_clear_error();
    \endcode

    \sa wolfSSL_ERR_get_error
*/
void wolfSSL_ERR_clear_error(void);

/*!
    \ingroup openSSL

    \brief Gets RAND status.

    \return 1 if RAND is seeded
    \return 0 if not seeded

    _Example_
    \code
    int status = wolfSSL_RAND_status();
    if (status) {
        printf("RAND is seeded\n");
    }
    \endcode

    \sa wolfSSL_RAND_bytes
*/
int wolfSSL_RAND_status(void);

/*!
    \ingroup openSSL

    \brief Generates pseudo-random bytes.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param buf Buffer for random bytes
    \param num Number of bytes to generate

    _Example_
    \code
    unsigned char buf[32];
    int ret = wolfSSL_RAND_pseudo_bytes(buf, sizeof(buf));
    \endcode

    \sa wolfSSL_RAND_bytes
*/
int wolfSSL_RAND_pseudo_bytes(unsigned char* buf, int num);

/*!
    \ingroup openSSL

    \brief Generates random bytes.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param buf Buffer for random bytes
    \param num Number of bytes to generate

    _Example_
    \code
    unsigned char buf[32];
    int ret = wolfSSL_RAND_bytes(buf, sizeof(buf));
    if (ret == WOLFSSL_SUCCESS) {
        printf("Generated %d random bytes\n", sizeof(buf));
    }
    \endcode

    \sa wolfSSL_RAND_pseudo_bytes
*/
int wolfSSL_RAND_bytes(unsigned char* buf, int num);

/*!
    \ingroup openSSL

    \brief Sets SSL context options.

    \return long Updated options

    \param ctx SSL context
    \param opt Options to set

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long opts = wolfSSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    \endcode

    \sa wolfSSL_CTX_get_options
*/
long wolfSSL_CTX_set_options(WOLFSSL_CTX* ctx, long opt);

/*!
    \ingroup openSSL

    \brief Gets SSL context options.

    \return long Current options

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long opts = wolfSSL_CTX_get_options(ctx);
    printf("Options: 0x%lx\n", opts);
    \endcode

    \sa wolfSSL_CTX_set_options
*/
long wolfSSL_CTX_get_options(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Checks if private key matches certificate.

    \return WOLFSSL_SUCCESS if match
    \return WOLFSSL_FAILURE if no match

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_check_private_key(ctx);
    if (ret == WOLFSSL_SUCCESS) {
        printf("Private key matches certificate\n");
    }
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_file
*/
int wolfSSL_CTX_check_private_key(const WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Frees error strings.

    \return none

    _Example_
    \code
    wolfSSL_ERR_free_strings();
    \endcode

    \sa wolfSSL_ERR_load_error_strings
*/
void wolfSSL_ERR_free_strings(void);

/*!
    \ingroup openSSL

    \brief Removes error state for thread.

    \return none

    \param id Thread ID

    _Example_
    \code
    wolfSSL_ERR_remove_state(0);
    \endcode

    \sa wolfSSL_ERR_clear_error
*/
void wolfSSL_ERR_remove_state(unsigned long id);

/*!
    \ingroup openSSL

    \brief Clears SSL object for reuse.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_clear(ssl);
    if (ret == WOLFSSL_SUCCESS) {
        printf("SSL cleared\n");
    }
    \endcode

    \sa wolfSSL_free
*/
int wolfSSL_clear(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Cleans up all ex_data.

    \return none

    _Example_
    \code
    wolfSSL_cleanup_all_ex_data();
    \endcode

    \sa wolfSSL_set_ex_data
*/
void wolfSSL_cleanup_all_ex_data(void);

/*!
    \ingroup openSSL

    \brief Sets SSL context mode.

    \return long Updated mode

    \param ctx SSL context
    \param mode Mode to set

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long mode = wolfSSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    \endcode

    \sa wolfSSL_CTX_get_mode
*/
long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode);

/*!
    \ingroup openSSL

    \brief Clears SSL context mode.

    \return long Updated mode

    \param ctx SSL context
    \param mode Mode to clear

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long mode = wolfSSL_CTX_clear_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    \endcode

    \sa wolfSSL_CTX_set_mode
*/
long wolfSSL_CTX_clear_mode(WOLFSSL_CTX* ctx, long mode);

/*!
    \ingroup openSSL

    \brief Gets SSL context mode.

    \return long Current mode

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    long mode = wolfSSL_CTX_get_mode(ctx);
    printf("Mode: 0x%lx\n", mode);
    \endcode

    \sa wolfSSL_CTX_set_mode
*/
long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Sets default read-ahead in context.

    \return none

    \param ctx SSL context
    \param m Read-ahead value

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    wolfSSL_CTX_set_default_read_ahead(ctx, 1);
    \endcode

    \sa wolfSSL_set_read_ahead
*/
void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m);

/*!
    \ingroup openSSL

    \brief Gets SSL mode.

    \return long Current mode

    \param ssl SSL object

    _Example_
    \code
    long mode = wolfSSL_SSL_get_mode(ssl);
    printf("Mode: 0x%lx\n", mode);
    \endcode

    \sa wolfSSL_CTX_get_mode
*/
long wolfSSL_SSL_get_mode(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Sets default verify paths.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    int ret = wolfSSL_CTX_set_default_verify_paths(ctx);
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
*/
int wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets default cert file environment variable.

    \return const char* Environment variable name

    _Example_
    \code
    const char* env = wolfSSL_X509_get_default_cert_file_env();
    printf("Cert file env: %s\n", env);
    \endcode

    \sa wolfSSL_X509_get_default_cert_file
*/
const char* wolfSSL_X509_get_default_cert_file_env(void);

/*!
    \ingroup CertsKeys

    \brief Gets default cert file path.

    \return const char* Default cert file path

    _Example_
    \code
    const char* path = wolfSSL_X509_get_default_cert_file();
    printf("Default cert file: %s\n", path);
    \endcode

    \sa wolfSSL_X509_get_default_cert_file_env
*/
const char* wolfSSL_X509_get_default_cert_file(void);

/*!
    \ingroup CertsKeys

    \brief Gets default cert dir environment variable.

    \return const char* Environment variable name

    _Example_
    \code
    const char* env = wolfSSL_X509_get_default_cert_dir_env();
    printf("Cert dir env: %s\n", env);
    \endcode

    \sa wolfSSL_X509_get_default_cert_dir
*/
const char* wolfSSL_X509_get_default_cert_dir_env(void);

/*!
    \ingroup CertsKeys

    \brief Gets default cert directory path.

    \return const char* Default cert directory path

    _Example_
    \code
    const char* path = wolfSSL_X509_get_default_cert_dir();
    printf("Default cert dir: %s\n", path);
    \endcode

    \sa wolfSSL_X509_get_default_cert_dir_env
*/
const char* wolfSSL_X509_get_default_cert_dir(void);

/*!
    \ingroup openSSL

    \brief Sets session ID context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param sid_ctx Session ID context
    \param sid_ctx_len Context length

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    unsigned char sid_ctx[] = "MyApp";
    int ret = wolfSSL_CTX_set_session_id_context(ctx, sid_ctx,
                                                   sizeof(sid_ctx));
    \endcode

    \sa wolfSSL_set_session_id_context
*/
int wolfSSL_CTX_set_session_id_context(WOLFSSL_CTX* ctx,
                                         const unsigned char* sid_ctx,
                                         unsigned int sid_ctx_len);

/*!
    \ingroup CertsKeys

    \brief Gets peer certificate.

    \return WOLFSSL_X509* Peer certificate
    \return NULL if no peer certificate

    \param ssl SSL object

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        wolfSSL_X509_free(cert);
    }
    \endcode

    \sa wolfSSL_X509_free
*/
WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets what SSL wants to do.

    \return SSL_NOTHING No operation pending
    \return SSL_WRITING Want to write
    \return SSL_READING Want to read
    \return SSL_X509_LOOKUP Want X509 lookup

    \param ssl SSL object

    _Example_
    \code
    int want = wolfSSL_want(ssl);
    if (want == SSL_READING) {
        printf("SSL wants to read\n");
    }
    \endcode

    \sa wolfSSL_want_read
*/
int wolfSSL_want(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Gets private key from context.

    \return WOLFSSL_EVP_PKEY* Private key
    \return NULL if not set

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_CTX_get0_privatekey(ctx);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_CTX_get0_privatekey(const WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief Prints formatted output to BIO with va_list.

    \return int Number of bytes written
    \return negative on error

    \param bio BIO to write to
    \param format Format string
    \param args Variable argument list

    _Example_
    \code
    va_list args;
    va_start(args, format);
    int ret = wolfSSL_BIO_vprintf(bio, format, args);
    va_end(args);
    \endcode

    \sa wolfSSL_BIO_printf
*/
int wolfSSL_BIO_vprintf(WOLFSSL_BIO* bio, const char* format, va_list args);

/*!
    \ingroup openSSL

    \brief Prints formatted output to BIO.

    \return int Number of bytes written
    \return negative on error

    \param bio BIO to write to
    \param format Format string
    \param ... Variable arguments

    _Example_
    \code
    int ret = wolfSSL_BIO_printf(bio, "Value: %d\n", 42);
    \endcode

    \sa wolfSSL_BIO_vprintf
*/
int wolfSSL_BIO_printf(WOLFSSL_BIO* bio, const char* format, ...);

/*!
    \ingroup openSSL

    \brief Dumps binary data to BIO.

    \return int Number of bytes written
    \return negative on error

    \param bio BIO to write to
    \param buf Buffer to dump
    \param length Buffer length

    _Example_
    \code
    unsigned char data[16];
    int ret = wolfSSL_BIO_dump(bio, (const char*)data, sizeof(data));
    \endcode

    \sa wolfSSL_BIO_printf
*/
int wolfSSL_BIO_dump(WOLFSSL_BIO *bio, const char* buf, int length);

/*!
    \ingroup ASN

    \brief Prints UTC time to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param a UTC time to print

    _Example_
    \code
    WOLFSSL_ASN1_UTCTIME* utc = wolfSSL_X509_get_notBefore(cert);
    int ret = wolfSSL_ASN1_UTCTIME_print(bio, utc);
    \endcode

    \sa wolfSSL_ASN1_GENERALIZEDTIME_print
*/
int wolfSSL_ASN1_UTCTIME_print(WOLFSSL_BIO* bio,
                                 const WOLFSSL_ASN1_UTCTIME* a);

/*!
    \ingroup ASN

    \brief Prints generalized time to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param asnTime Generalized time to print

    _Example_
    \code
    WOLFSSL_ASN1_GENERALIZEDTIME* gt = wolfSSL_X509_get_notAfter(cert);
    int ret = wolfSSL_ASN1_GENERALIZEDTIME_print(bio, gt);
    \endcode

    \sa wolfSSL_ASN1_UTCTIME_print
*/
int wolfSSL_ASN1_GENERALIZEDTIME_print(WOLFSSL_BIO* bio,
                                        const WOLFSSL_ASN1_GENERALIZEDTIME*
                                        asnTime);

/*!
    \ingroup ASN

    \brief Frees generalized time.

    \return none

    \param gt Generalized time to free

    _Example_
    \code
    WOLFSSL_ASN1_GENERALIZEDTIME* gt = wolfSSL_ASN1_GENERALIZEDTIME_new();
    wolfSSL_ASN1_GENERALIZEDTIME_free(gt);
    \endcode

    \sa wolfSSL_ASN1_GENERALIZEDTIME_new
*/
void wolfSSL_ASN1_GENERALIZEDTIME_free(WOLFSSL_ASN1_GENERALIZEDTIME* gt);

/*!
    \ingroup ASN

    \brief Checks if ASN1_TIME is valid.

    \return WOLFSSL_SUCCESS if valid
    \return WOLFSSL_FAILURE if invalid

    \param a Time to check

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_X509_get_notBefore(cert);
    int ret = wolfSSL_ASN1_TIME_check(time);
    \endcode

    \sa wolfSSL_ASN1_TIME_compare
*/
int wolfSSL_ASN1_TIME_check(const WOLFSSL_ASN1_TIME* a);

/*!
    \ingroup ASN

    \brief Calculates time difference.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param days Pointer to store days difference
    \param secs Pointer to store seconds difference
    \param from Start time
    \param to End time

    _Example_
    \code
    int days, secs;
    int ret = wolfSSL_ASN1_TIME_diff(&days, &secs, from, to);
    printf("Difference: %d days, %d seconds\n", days, secs);
    \endcode

    \sa wolfSSL_ASN1_TIME_compare
*/
int wolfSSL_ASN1_TIME_diff(int* days, int* secs,
                            const WOLFSSL_ASN1_TIME* from,
                            const WOLFSSL_ASN1_TIME* to);

/*!
    \ingroup ASN

    \brief Compares two ASN1_TIME values.

    \return negative if a < b
    \return 0 if a == b
    \return positive if a > b

    \param a First time
    \param b Second time

    _Example_
    \code
    int cmp = wolfSSL_ASN1_TIME_compare(time1, time2);
    if (cmp < 0) {
        printf("time1 is before time2\n");
    }
    \endcode

    \sa wolfSSL_ASN1_TIME_diff
*/
int wolfSSL_ASN1_TIME_compare(const WOLFSSL_ASN1_TIME *a,
                                const WOLFSSL_ASN1_TIME *b);

/*!
    \ingroup ASN

    \brief Sets ASN1_TIME from string.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param s Time object to set
    \param str Time string

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    int ret = wolfSSL_ASN1_TIME_set_string(time, "20231231120000Z");
    \endcode

    \sa wolfSSL_ASN1_TIME_set_string_X509
*/
int wolfSSL_ASN1_TIME_set_string(WOLFSSL_ASN1_TIME *s, const char *str);

/*!
    \ingroup ASN

    \brief Sets ASN1_TIME from X509 format string.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param t Time object to set
    \param str Time string in X509 format

    _Example_
    \code
    WOLFSSL_ASN1_TIME* time = wolfSSL_ASN1_TIME_new();
    int ret = wolfSSL_ASN1_TIME_set_string_X509(time, "231231120000Z");
    \endcode

    \sa wolfSSL_ASN1_TIME_set_string
*/
int wolfSSL_ASN1_TIME_set_string_X509(WOLFSSL_ASN1_TIME *t,
                                       const char *str);

/*!
    \ingroup openSSL

    \brief Encodes session to DER.

    \return int Number of bytes written
    \return negative on error

    \param sess Session to encode
    \param p Pointer to buffer pointer

    _Example_
    \code
    unsigned char* buf = NULL;
    int len = wolfSSL_i2d_SSL_SESSION(session, &buf);
    if (len > 0) {
        XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_SSL_SESSION
*/
int wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION* sess, unsigned char** p);

/*!
    \ingroup openSSL

    \brief Decodes session from DER.

    \return WOLFSSL_SESSION* Decoded session
    \return NULL on failure

    \param sess Pointer to session pointer
    \param p Pointer to DER buffer pointer
    \param i Buffer length

    _Example_
    \code
    const unsigned char* p = der_buf;
    WOLFSSL_SESSION* sess = wolfSSL_d2i_SSL_SESSION(NULL, &p, len);
    \endcode

    \sa wolfSSL_i2d_SSL_SESSION
*/
WOLFSSL_SESSION* wolfSSL_d2i_SSL_SESSION(WOLFSSL_SESSION** sess,
                                          const unsigned char** p, long i);

/*!
    \ingroup openSSL

    \brief Checks if session has ticket.

    \return 1 if has ticket
    \return 0 if no ticket

    \param session Session to check

    _Example_
    \code
    int has = wolfSSL_SESSION_has_ticket(session);
    if (has) {
        printf("Session has ticket\n");
    }
    \endcode

    \sa wolfSSL_SESSION_get_ticket_lifetime_hint
*/
int wolfSSL_SESSION_has_ticket(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Gets ticket lifetime hint.

    \return unsigned long Lifetime hint in seconds

    \param sess Session to query

    _Example_
    \code
    unsigned long hint = wolfSSL_SESSION_get_ticket_lifetime_hint(sess);
    printf("Ticket lifetime: %lu seconds\n", hint);
    \endcode

    \sa wolfSSL_SESSION_has_ticket
*/
unsigned long wolfSSL_SESSION_get_ticket_lifetime_hint(
                                                  const WOLFSSL_SESSION* sess);

/*!
    \ingroup openSSL

    \brief Gets session timeout.

    \return long Timeout in seconds

    \param session Session to query

    _Example_
    \code
    long timeout = wolfSSL_SESSION_get_timeout(session);
    printf("Session timeout: %ld seconds\n", timeout);
    \endcode

    \sa wolfSSL_SESSION_get_time
*/
long wolfSSL_SESSION_get_timeout(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Gets session creation time.

    \return long Creation time (Unix timestamp)

    \param session Session to query

    _Example_
    \code
    long time = wolfSSL_SESSION_get_time(session);
    printf("Session created at: %ld\n", time);
    \endcode

    \sa wolfSSL_SESSION_get_timeout
*/
long wolfSSL_SESSION_get_time(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Gets peer certificate chain from session.

    \return WOLFSSL_X509_CHAIN* Certificate chain
    \return NULL if not available

    \param session Session to query

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = wolfSSL_SESSION_get_peer_chain(session);
    \endcode

    \sa wolfSSL_SESSION_get0_peer
*/
WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Gets peer certificate from session.

    \return WOLFSSL_X509* Peer certificate
    \return NULL if not available

    \param session Session to query

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_SESSION_get0_peer(session);
    \endcode

    \sa wolfSSL_SESSION_get_peer_chain
*/
WOLFSSL_X509* wolfSSL_SESSION_get0_peer(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL

    \brief Enables crypto policy.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param policy Policy name to enable

    _Example_
    \code
    int ret = wolfSSL_crypto_policy_enable("FIPS");
    if (ret == WOLFSSL_SUCCESS) {
        printf("FIPS policy enabled\n");
    }
    \endcode

    \sa wolfSSL_CTX_new
*/
int wolfSSL_crypto_policy_enable(const char * policy);

/*!
    \ingroup openSSL

    \brief Enables crypto policy from buffer.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param buf Policy buffer to enable

    _Example_
    \code
    const char* policy = "level=2\nciphers=TLS13-AES128-GCM-SHA256";
    int ret = wolfSSL_crypto_policy_enable_buffer(policy);
    \endcode

    \sa wolfSSL_crypto_policy_enable
*/
int wolfSSL_crypto_policy_enable_buffer(const char * buf);

/*!
    \ingroup openSSL

    \brief Disables crypto policy.

    \return none

    _Example_
    \code
    wolfSSL_crypto_policy_disable();
    \endcode

    \sa wolfSSL_crypto_policy_enable
*/
void wolfSSL_crypto_policy_disable(void);

/*!
    \ingroup openSSL

    \brief Checks if crypto policy is enabled.

    \return 1 if enabled
    \return 0 if disabled

    _Example_
    \code
    int enabled = wolfSSL_crypto_policy_is_enabled();
    if (enabled) {
        printf("Crypto policy is enabled\n");
    }
    \endcode

    \sa wolfSSL_crypto_policy_enable
*/
int wolfSSL_crypto_policy_is_enabled(void);

/*!
    \ingroup openSSL

    \brief Gets allowed ciphers from policy.

    \return const char* Cipher list
    \return NULL if not set

    _Example_
    \code
    const char* ciphers = wolfSSL_crypto_policy_get_ciphers();
    if (ciphers != NULL) {
        printf("Allowed ciphers: %s\n", ciphers);
    }
    \endcode

    \sa wolfSSL_crypto_policy_get_level
*/
const char * wolfSSL_crypto_policy_get_ciphers(void);

/*!
    \ingroup openSSL

    \brief Gets crypto policy level.

    \return int Policy level

    _Example_
    \code
    int level = wolfSSL_crypto_policy_get_level();
    printf("Policy level: %d\n", level);
    \endcode

    \sa wolfSSL_crypto_policy_get_ciphers
*/
int wolfSSL_crypto_policy_get_level(void);

/*!
    \ingroup openSSL

    \brief Gets security level.

    \return int Security level

    \param ssl SSL object

    _Example_
    \code
    int level = wolfSSL_get_security_level(ssl);
    printf("Security level: %d\n", level);
    \endcode

    \sa wolfSSL_set_security_level
*/
int wolfSSL_get_security_level(const WOLFSSL * ssl);

/*!
    \ingroup openSSL

    \brief Sets security level.

    \return none

    \param ssl SSL object
    \param level Security level to set

    _Example_
    \code
    wolfSSL_set_security_level(ssl, 2);
    \endcode

    \sa wolfSSL_get_security_level
*/
void wolfSSL_set_security_level(WOLFSSL * ssl, int level);

/*!
    \ingroup openSSL

    \brief Gets library version string.

    \return const char* Version string

    _Example_
    \code
    const char* version = wolfSSL_lib_version();
    printf("wolfSSL version: %s\n", version);
    \endcode

    \sa wolfSSL_OpenSSL_version
*/
const char* wolfSSL_lib_version(void);

/*!
    \ingroup openSSL

    \brief Gets OpenSSL version string.

    \return const char* Version string

    \param a Version type

    _Example_
    \code
    const char* version = wolfSSL_OpenSSL_version(0);
    printf("OpenSSL version: %s\n", version);
    \endcode

    \sa wolfSSL_lib_version
*/
const char* wolfSSL_OpenSSL_version(int a);

/*!
    \ingroup CertsKeys

    \brief Gets peer certificate chain.

    \return WOLFSSL_X509_CHAIN* Certificate chain
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(ssl);
    \endcode

    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Checks if peer has alternate cert chain.

    \return 1 if has alternate chain
    \return 0 if no alternate chain

    \param ssl SSL object

    _Example_
    \code
    int has_alt = wolfSSL_is_peer_alt_cert_chain(ssl);
    if (has_alt) {
        printf("Peer has alternate cert chain\n");
    }
    \endcode

    \sa wolfSSL_get_peer_alt_chain
*/
int wolfSSL_is_peer_alt_cert_chain(const WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Gets peer alternate certificate chain.

    \return WOLFSSL_X509_CHAIN* Alternate certificate chain
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_alt_chain(ssl);
    \endcode

    \sa wolfSSL_is_peer_alt_cert_chain
*/
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_alt_chain(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Gets certificate from chain by index.

    \return unsigned char* Certificate buffer
    \return NULL if not found

    \param chain Certificate chain
    \param idx Certificate index

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(ssl);
    unsigned char* cert = wolfSSL_get_chain_cert(chain, 0);
    \endcode

    \sa wolfSSL_get_chain_X509
*/
unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup CertsKeys

    \brief Gets X509 certificate from chain by index.

    \return WOLFSSL_X509* Certificate
    \return NULL if not found

    \param chain Certificate chain
    \param idx Certificate index

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(ssl);
    WOLFSSL_X509* cert = wolfSSL_get_chain_X509(chain, 0);
    \endcode

    \sa wolfSSL_get_chain_cert
*/
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 certificate.

    \return WOLFSSL_X509* New certificate
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new();
    if (cert != NULL) {
        wolfSSL_X509_free(cert);
    }
    \endcode

    \sa wolfSSL_X509_free
*/
WOLFSSL_X509* wolfSSL_X509_new(void);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 certificate with heap.

    \return WOLFSSL_X509* New certificate
    \return NULL on failure

    \param heap Heap hint for allocation

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_new_ex(NULL);
    if (cert != NULL) {
        wolfSSL_X509_free(cert);
    }
    \endcode

    \sa wolfSSL_X509_new
*/
WOLFSSL_X509* wolfSSL_X509_new_ex(void* heap);

/*!
    \ingroup CertsKeys

    \brief Duplicates X509 certificate.

    \return WOLFSSL_X509* Duplicated certificate
    \return NULL on failure

    \param x Certificate to duplicate

    _Example_
    \code
    WOLFSSL_X509* dup = wolfSSL_X509_dup(cert);
    if (dup != NULL) {
        wolfSSL_X509_free(dup);
    }
    \endcode

    \sa wolfSSL_X509_new
*/
WOLFSSL_X509* wolfSSL_X509_dup(WOLFSSL_X509* x);

/*!
    \ingroup CertsKeys

    \brief Gets issuer name from certificate.

    \return WOLFSSL_X509_NAME* Issuer name
    \return NULL if not available

    \param cert Certificate to query

    _Example_
    \code
    WOLFSSL_X509_NAME* issuer = wolfSSL_X509_get_issuer_name(cert);
    \endcode

    \sa wolfSSL_X509_get_subject_name
*/
WOLFSSL_X509_NAME* wolfSSL_X509_get_issuer_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief Gets subject name from certificate.

    \return WOLFSSL_X509_NAME* Subject name
    \return NULL if not available

    \param cert Certificate to query

    _Example_
    \code
    WOLFSSL_X509_NAME* subject = wolfSSL_X509_get_subject_name(cert);
    \endcode

    \sa wolfSSL_X509_get_issuer_name
*/
WOLFSSL_X509_NAME* wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief Gets public key buffer from certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to query
    \param buf Buffer for public key
    \param bufSz Pointer to buffer size

    _Example_
    \code
    unsigned char buf[2048];
    int bufSz = sizeof(buf);
    int ret = wolfSSL_X509_get_pubkey_buffer(cert, buf, &bufSz);
    \endcode

    \sa wolfSSL_X509_get_pubkey_type
*/
int wolfSSL_X509_get_pubkey_buffer(WOLFSSL_X509* x509, unsigned char* buf,
                                     int* bufSz);

/*!
    \ingroup CertsKeys

    \brief Gets public key type from certificate.

    \return int Key type (RSA, ECC, etc.)
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to query

    _Example_
    \code
    int type = wolfSSL_X509_get_pubkey_type(cert);
    if (type == RSAk) {
        printf("RSA key\n");
    }
    \endcode

    \sa wolfSSL_X509_get_pubkey_buffer
*/
int wolfSSL_X509_get_pubkey_type(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Loads certificate from file.

    \return WOLFSSL_X509* Loaded certificate
    \return NULL on failure

    \param fname File name
    \param format File format (PEM or DER)

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_load_certificate_file("cert.pem",
                                                             SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_load_certificate_buffer
*/
WOLFSSL_X509* wolfSSL_X509_load_certificate_file(const char* fname,
                                                  int format);

/*!
    \ingroup CertsKeys

    \brief Loads certificate from buffer.

    \return WOLFSSL_X509* Loaded certificate
    \return NULL on failure

    \param buf Certificate buffer
    \param sz Buffer size
    \param format Buffer format (PEM or DER)

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_load_certificate_buffer(buf, sz,
                                                            SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_load_certificate_file
*/
WOLFSSL_X509* wolfSSL_X509_load_certificate_buffer(const unsigned char* buf,
                                                     int sz, int format);

/*!
    \ingroup CertsKeys

    \brief Loads certificate request from buffer.

    \return WOLFSSL_X509* Loaded certificate request
    \return NULL on failure

    \param buf Certificate request buffer
    \param sz Buffer size
    \param format Buffer format (PEM or DER)

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_X509_REQ_load_certificate_buffer(buf, sz,
                                                            SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_load_certificate_buffer
*/
WOLFSSL_X509* wolfSSL_X509_REQ_load_certificate_buffer(
                                                  const unsigned char* buf,
                                                  int sz, int format);

/*!
    \ingroup openSSL

    \brief Gets session ID.

    \return const unsigned char* Session ID
    \return NULL if not available

    \param s Session to query

    _Example_
    \code
    const unsigned char* id = wolfSSL_get_sessionID(session);
    \endcode

    \sa wolfSSL_SESSION_get_time
*/
const unsigned char* wolfSSL_get_sessionID(const WOLFSSL_SESSION* s);

/*!
    \ingroup CertsKeys

    \brief Gets subject common name from certificate.

    \return char* Subject common name
    \return NULL if not available

    \param x509 Certificate to query

    _Example_
    \code
    char* cn = wolfSSL_X509_get_subjectCN(cert);
    if (cn != NULL) {
        printf("Subject CN: %s\n", cn);
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
*/
char* wolfSSL_X509_get_subjectCN(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets DER encoding of certificate.

    \return const unsigned char* DER buffer
    \return NULL if not available

    \param x509 Certificate to query
    \param outSz Pointer to store size

    _Example_
    \code
    int sz;
    const unsigned char* der = wolfSSL_X509_get_der(cert, &sz);
    \endcode

    \sa wolfSSL_X509_get_tbs
*/
const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz);

/*!
    \ingroup CertsKeys

    \brief Gets TBS (To Be Signed) portion of certificate.

    \return const unsigned char* TBS buffer
    \return NULL if not available

    \param x509 Certificate to query
    \param outSz Pointer to store size

    _Example_
    \code
    int sz;
    const unsigned char* tbs = wolfSSL_X509_get_tbs(cert, &sz);
    \endcode

    \sa wolfSSL_X509_get_der
*/
const unsigned char* wolfSSL_X509_get_tbs(WOLFSSL_X509* x509, int* outSz);

/*!
    \ingroup CertsKeys

    \brief Gets notBefore date from certificate.

    \return const byte* notBefore date
    \return NULL if not available

    \param x509 Certificate to query

    _Example_
    \code
    const byte* notBefore = wolfSSL_X509_notBefore(cert);
    \endcode

    \sa wolfSSL_X509_notAfter
*/
const byte* wolfSSL_X509_notBefore(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets notAfter date from certificate.

    \return const byte* notAfter date
    \return NULL if not available

    \param x509 Certificate to query

    _Example_
    \code
    const byte* notAfter = wolfSSL_X509_notAfter(cert);
    \endcode

    \sa wolfSSL_X509_notBefore
*/
const byte* wolfSSL_X509_notAfter(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Compares peer certificate to file.

    \return WOLFSSL_SUCCESS if match
    \return WOLFSSL_FAILURE if no match

    \param ssl SSL object
    \param fname Certificate file name

    _Example_
    \code
    int ret = wolfSSL_cmp_peer_cert_to_file(ssl, "peer.pem");
    if (ret == WOLFSSL_SUCCESS) {
        printf("Peer certificate matches file\n");
    }
    \endcode

    \sa wolfSSL_get_peer_certificate
*/
int wolfSSL_cmp_peer_cert_to_file(WOLFSSL* ssl, const char* fname);

/*!
    \ingroup CertsKeys

    \brief Gets next alternate name from certificate.

    \return char* Alternate name
    \return NULL if no more names

    \param cert Certificate to query

    _Example_
    \code
    char* altname;
    while ((altname = wolfSSL_X509_get_next_altname(cert)) != NULL) {
        printf("Alt name: %s\n", altname);
    }
    \endcode

    \sa wolfSSL_X509_add_altname
*/
char* wolfSSL_X509_get_next_altname(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief Adds alternate name to certificate with size.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param name Alternate name
    \param nameSz Name size
    \param type Name type

    _Example_
    \code
    int ret = wolfSSL_X509_add_altname_ex(cert, "example.com", 11,
                                           ASN_DNS_TYPE);
    \endcode

    \sa wolfSSL_X509_add_altname
*/
int wolfSSL_X509_add_altname_ex(WOLFSSL_X509* x509, const char* name,
                                 word32 nameSz, int type);

/*!
    \ingroup CertsKeys

    \brief Adds alternate name to certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Certificate to modify
    \param name Alternate name
    \param type Name type

    _Example_
    \code
    int ret = wolfSSL_X509_add_altname(cert, "example.com", ASN_DNS_TYPE);
    \endcode

    \sa wolfSSL_X509_add_altname_ex
*/
int wolfSSL_X509_add_altname(WOLFSSL_X509* x509, const char* name, int type);

/*!
    \ingroup CertsKeys

    \brief Decodes X509 certificate from DER.

    \return WOLFSSL_X509* Decoded certificate
    \return NULL on failure

    \param x509 Pointer to certificate pointer
    \param in Pointer to DER buffer pointer
    \param len Buffer length

    _Example_
    \code
    const unsigned char* p = der_buf;
    WOLFSSL_X509* cert = wolfSSL_d2i_X509(NULL, &p, len);
    \endcode

    \sa wolfSSL_i2d_X509
*/
WOLFSSL_X509* wolfSSL_d2i_X509(WOLFSSL_X509** x509,
                                const unsigned char** in, int len);

/*!
    \ingroup CertsKeys

    \brief Decodes X509 certificate from DER buffer.

    \return WOLFSSL_X509* Decoded certificate
    \return NULL on failure

    \param x509 Pointer to certificate pointer
    \param in DER buffer
    \param len Buffer length

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_d2i(NULL, der_buf, len);
    \endcode

    \sa wolfSSL_d2i_X509
*/
WOLFSSL_X509* wolfSSL_X509_d2i(WOLFSSL_X509** x509,
                                const unsigned char* in, int len);

/*!
    \ingroup CertsKeys

    \brief Decodes X509 certificate from DER with heap.

    \return WOLFSSL_X509* Decoded certificate
    \return NULL on failure

    \param x509 Pointer to certificate pointer
    \param in DER buffer
    \param len Buffer length
    \param heap Heap hint

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_X509_d2i_ex(NULL, der_buf, len, NULL);
    \endcode

    \sa wolfSSL_X509_d2i
*/
WOLFSSL_X509* wolfSSL_X509_d2i_ex(WOLFSSL_X509** x509,
                                   const unsigned char* in, int len,
                                   void* heap);

/*!
    \ingroup CertsKeys

    \brief Decodes X509 certificate request from DER.

    \return WOLFSSL_X509* Decoded certificate request
    \return NULL on failure

    \param x509 Pointer to certificate pointer
    \param in DER buffer
    \param len Buffer length

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_X509_REQ_d2i(NULL, der_buf, len);
    \endcode

    \sa wolfSSL_X509_d2i
*/
WOLFSSL_X509* wolfSSL_X509_REQ_d2i(WOLFSSL_X509** x509,
                                    const unsigned char* in, int len);

/*!
    \ingroup CertsKeys

    \brief Decodes X509 request info from DER.

    \return WOLFSSL_X509* Decoded request info
    \return NULL on failure

    \param req Pointer to request pointer
    \param in Pointer to DER buffer pointer
    \param len Buffer length

    _Example_
    \code
    const unsigned char* p = der_buf;
    WOLFSSL_X509* req = wolfSSL_d2i_X509_REQ_INFO(NULL, &p, len);
    \endcode

    \sa wolfSSL_X509_REQ_d2i
*/
WOLFSSL_X509* wolfSSL_d2i_X509_REQ_INFO(WOLFSSL_X509** req,
                                         const unsigned char** in, int len);

/*!
    \ingroup CertsKeys

    \brief Encodes X509 certificate to DER.

    \return int Number of bytes written
    \return negative on error

    \param x509 Certificate to encode
    \param out Pointer to buffer pointer

    _Example_
    \code
    unsigned char* buf = NULL;
    int len = wolfSSL_i2d_X509(cert, &buf);
    if (len > 0) {
        XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    \endcode

    \sa wolfSSL_d2i_X509
*/
int wolfSSL_i2d_X509(WOLFSSL_X509* x509, unsigned char** out);

/*!
    \ingroup CertsKeys

    \brief Gets CRL version.

    \return int Version number
    \return negative on error

    \param crl CRL to query

    _Example_
    \code
    int version = wolfSSL_X509_CRL_version(crl);
    printf("CRL version: %d\n", version);
    \endcode

    \sa wolfSSL_X509_CRL_get_issuer_name
*/
int wolfSSL_X509_CRL_version(WOLFSSL_X509_CRL *crl);

/*!
    \ingroup CertsKeys

    \brief Gets CRL signature type.

    \return int Signature type
    \return negative on error

    \param crl CRL to query

    _Example_
    \code
    int type = wolfSSL_X509_CRL_get_signature_type(crl);
    \endcode

    \sa wolfSSL_X509_CRL_get_signature_nid
*/
int wolfSSL_X509_CRL_get_signature_type(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys

    \brief Gets CRL signature NID.

    \return int Signature NID
    \return negative on error

    \param crl CRL to query

    _Example_
    \code
    int nid = wolfSSL_X509_CRL_get_signature_nid(crl);
    \endcode

    \sa wolfSSL_X509_CRL_get_signature_type
*/
int wolfSSL_X509_CRL_get_signature_nid(const WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys

    \brief Gets CRL signature.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param crl CRL to query
    \param buf Buffer for signature
    \param bufSz Pointer to buffer size

    _Example_
    \code
    unsigned char buf[512];
    int bufSz = sizeof(buf);
    int ret = wolfSSL_X509_CRL_get_signature(crl, buf, &bufSz);
    \endcode

    \sa wolfSSL_X509_CRL_get_signature_nid
*/
int wolfSSL_X509_CRL_get_signature(WOLFSSL_X509_CRL* crl,
                                     unsigned char* buf, int* bufSz);

/*!
    \ingroup CertsKeys

    \brief Prints CRL to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param crl CRL to print

    _Example_
    \code
    int ret = wolfSSL_X509_CRL_print(bio, crl);
    \endcode

    \sa wolfSSL_X509_CRL_version
*/
int wolfSSL_X509_CRL_print(WOLFSSL_BIO* bio, WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys

    \brief Gets CRL issuer name.

    \return WOLFSSL_X509_NAME* Issuer name
    \return NULL if not available

    \param crl CRL to query

    _Example_
    \code
    WOLFSSL_X509_NAME* issuer = wolfSSL_X509_CRL_get_issuer_name(crl);
    \endcode

    \sa wolfSSL_X509_CRL_version
*/
WOLFSSL_X509_NAME* wolfSSL_X509_CRL_get_issuer_name(WOLFSSL_X509_CRL *crl);

/*!
    \ingroup CertsKeys

    \brief Gets serial number from revoked certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param rev Revoked certificate
    \param in Buffer for serial number
    \param inOutSz Pointer to buffer size

    _Example_
    \code
    byte buf[32];
    int sz = sizeof(buf);
    int ret = wolfSSL_X509_REVOKED_get_serial_number(rev, buf, &sz);
    \endcode

    \sa wolfSSL_X509_CRL_get_REVOKED
*/
int wolfSSL_X509_REVOKED_get_serial_number(RevokedCert* rev, byte* in,
                                             int* inOutSz);

/*!
    \ingroup CertsKeys

    \brief Duplicates CRL.

    \return WOLFSSL_X509_CRL* Duplicated CRL
    \return NULL on failure

    \param crl CRL to duplicate

    _Example_
    \code
    WOLFSSL_X509_CRL* dup = wolfSSL_X509_CRL_dup(crl);
    if (dup != NULL) {
        wolfSSL_X509_CRL_free(dup);
    }
    \endcode

    \sa wolfSSL_X509_CRL_free
*/
WOLFSSL_X509_CRL* wolfSSL_X509_CRL_dup(const WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys

    \brief Frees CRL.

    \return none

    \param crl CRL to free

    _Example_
    \code
    wolfSSL_X509_CRL_free(crl);
    \endcode

    \sa wolfSSL_X509_CRL_dup
*/
void wolfSSL_X509_CRL_free(WOLFSSL_X509_CRL *crl);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 attribute certificate with heap.

    \return WOLFSSL_X509_ACERT* New attribute certificate
    \return NULL on failure

    \param heap Heap hint for allocation

    _Example_
    \code
    WOLFSSL_X509_ACERT* acert = wolfSSL_X509_ACERT_new_ex(NULL);
    \endcode

    \sa wolfSSL_X509_new_ex
*/
WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_new_ex(void * heap);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 attribute certificate.

    \return WOLFSSL_X509_ACERT* New attribute certificate
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_ACERT* acert = wolfSSL_X509_ACERT_new();
    \endcode

    \sa wolfSSL_X509_ACERT_free
*/
WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_new(void);

/*!
    \ingroup CertsKeys

    \brief Initializes X509 attribute certificate.

    \return none

    \param x509 Attribute certificate to initialize
    \param dynamic Dynamic allocation flag
    \param heap Heap hint

    _Example_
    \code
    WOLFSSL_X509_ACERT acert;
    wolfSSL_X509_ACERT_init(&acert, 0, NULL);
    \endcode

    \sa wolfSSL_X509_ACERT_new
*/
void wolfSSL_X509_ACERT_init(WOLFSSL_X509_ACERT * x509, int dynamic,
                              void * heap);

/*!
    \ingroup CertsKeys

    \brief Frees X509 attribute certificate.

    \return none

    \param x509 Attribute certificate to free

    _Example_
    \code
    wolfSSL_X509_ACERT_free(acert);
    \endcode

    \sa wolfSSL_X509_ACERT_new
*/
void wolfSSL_X509_ACERT_free(WOLFSSL_X509_ACERT* x509);

/*!
    \ingroup CertsKeys

    \brief Signs X509 attribute certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Attribute certificate to sign
    \param pkey Private key
    \param md Message digest

    _Example_
    \code
    int ret = wolfSSL_X509_ACERT_sign(acert, pkey, md);
    \endcode

    \sa wolfSSL_X509_ACERT_verify
*/
int wolfSSL_X509_ACERT_sign(WOLFSSL_X509_ACERT * x509,
                             WOLFSSL_EVP_PKEY * pkey,
                             const WOLFSSL_EVP_MD * md);

/*!
    \ingroup CertsKeys

    \brief Verifies X509 attribute certificate signature.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Attribute certificate to verify
    \param pkey Public key

    _Example_
    \code
    int ret = wolfSSL_X509_ACERT_verify(acert, pkey);
    \endcode

    \sa wolfSSL_X509_ACERT_sign
*/
int wolfSSL_X509_ACERT_verify(WOLFSSL_X509_ACERT* x509,
                               WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief Gets signature NID from attribute certificate.

    \return int Signature NID
    \return negative on error

    \param x Attribute certificate

    _Example_
    \code
    int nid = wolfSSL_X509_ACERT_get_signature_nid(acert);
    \endcode

    \sa wolfSSL_X509_ACERT_get_signature
*/
int wolfSSL_X509_ACERT_get_signature_nid(const WOLFSSL_X509_ACERT* x);

/*!
    \ingroup CertsKeys

    \brief Prints attribute certificate to BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO to write to
    \param x509_acert Attribute certificate to print

    _Example_
    \code
    int ret = wolfSSL_X509_ACERT_print(bio, acert);
    \endcode

    \sa wolfSSL_X509_ACERT_get_version
*/
int wolfSSL_X509_ACERT_print(WOLFSSL_BIO* bio,
                              WOLFSSL_X509_ACERT* x509_acert);

/*!
    \ingroup CertsKeys

    \brief Reads attribute certificate from BIO.

    \return WOLFSSL_X509_ACERT* Attribute certificate
    \return NULL on failure

    \param bp BIO to read from
    \param x Pointer to attribute certificate pointer
    \param cb Password callback
    \param u User data

    _Example_
    \code
    WOLFSSL_X509_ACERT* acert = wolfSSL_PEM_read_bio_X509_ACERT(bio,
                                                                  NULL,
                                                                  NULL,
                                                                  NULL);
    \endcode

    \sa wolfSSL_X509_ACERT_print
*/
WOLFSSL_X509_ACERT * wolfSSL_PEM_read_bio_X509_ACERT(WOLFSSL_BIO *bp,
                                                      WOLFSSL_X509_ACERT **x,
                                                      wc_pem_password_cb *cb,
                                                      void *u);

/*!
    \ingroup CertsKeys

    \brief Gets version from attribute certificate.

    \return long Version number

    \param x Attribute certificate

    _Example_
    \code
    long version = wolfSSL_X509_ACERT_get_version(acert);
    \endcode

    \sa wolfSSL_X509_ACERT_version
*/
long wolfSSL_X509_ACERT_get_version(const WOLFSSL_X509_ACERT *x);

/*!
    \ingroup CertsKeys

    \brief Gets attribute buffer from attribute certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Attribute certificate
    \param rawAttr Pointer to store attribute buffer
    \param rawAttrLen Pointer to store attribute length

    _Example_
    \code
    const byte* attr;
    word32 attrLen;
    int ret = wolfSSL_X509_ACERT_get_attr_buf(acert, &attr, &attrLen);
    \endcode

    \sa wolfSSL_X509_ACERT_get_serial_number
*/
int wolfSSL_X509_ACERT_get_attr_buf(const WOLFSSL_X509_ACERT* x509,
                                     const byte ** rawAttr,
                                     word32 * rawAttrLen);

/*!
    \ingroup CertsKeys

    \brief Gets serial number from attribute certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Attribute certificate
    \param in Buffer for serial number
    \param inOutSz Pointer to buffer size

    _Example_
    \code
    unsigned char buf[32];
    int sz = sizeof(buf);
    int ret = wolfSSL_X509_ACERT_get_serial_number(acert, buf, &sz);
    \endcode

    \sa wolfSSL_X509_ACERT_version
*/
int wolfSSL_X509_ACERT_get_serial_number(WOLFSSL_X509_ACERT* x509,
                                          unsigned char* in, int * inOutSz);

/*!
    \ingroup CertsKeys

    \brief Gets version from attribute certificate.

    \return int Version number
    \return negative on error

    \param x509 Attribute certificate

    _Example_
    \code
    int version = wolfSSL_X509_ACERT_version(acert);
    \endcode

    \sa wolfSSL_X509_ACERT_get_version
*/
int wolfSSL_X509_ACERT_version(WOLFSSL_X509_ACERT* x509);

/*!
    \ingroup CertsKeys

    \brief Gets signature from attribute certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 Attribute certificate
    \param buf Buffer for signature
    \param bufSz Pointer to buffer size

    _Example_
    \code
    unsigned char buf[512];
    int bufSz = sizeof(buf);
    int ret = wolfSSL_X509_ACERT_get_signature(acert, buf, &bufSz);
    \endcode

    \sa wolfSSL_X509_ACERT_get_signature_nid
*/
int wolfSSL_X509_ACERT_get_signature(WOLFSSL_X509_ACERT* x509,
                                      unsigned char* buf, int* bufSz);

/*!
    \ingroup CertsKeys

    \brief Loads attribute certificate from buffer with heap.

    \return WOLFSSL_X509_ACERT* Loaded attribute certificate
    \return NULL on failure

    \param buf Certificate buffer
    \param sz Buffer size
    \param format Buffer format
    \param heap Heap hint

    _Example_
    \code
    WOLFSSL_X509_ACERT* acert =
        wolfSSL_X509_ACERT_load_certificate_buffer_ex(buf, sz,
                                                       SSL_FILETYPE_PEM,
                                                       NULL);
    \endcode

    \sa wolfSSL_X509_ACERT_load_certificate_buffer
*/
WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_load_certificate_buffer_ex(
                                                  const unsigned char* buf,
                                                  int sz, int format,
                                                  void * heap);

/*!
    \ingroup CertsKeys

    \brief Loads attribute certificate from buffer.

    \return WOLFSSL_X509_ACERT* Loaded attribute certificate
    \return NULL on failure

    \param buf Certificate buffer
    \param sz Buffer size
    \param format Buffer format

    _Example_
    \code
    WOLFSSL_X509_ACERT* acert =
        wolfSSL_X509_ACERT_load_certificate_buffer(buf, sz,
                                                    SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_X509_ACERT_load_certificate_buffer_ex
*/
WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_load_certificate_buffer(
                                                  const unsigned char* buf,
                                                  int sz, int format);

/*!
    \ingroup CertsKeys

    \brief Gets serial number from revoked certificate.

    \return const WOLFSSL_ASN1_INTEGER* Serial number
    \return NULL if not available

    \param rev Revoked certificate

    _Example_
    \code
    const WOLFSSL_ASN1_INTEGER* serial =
        wolfSSL_X509_REVOKED_get0_serial_number(rev);
    \endcode

    \sa wolfSSL_X509_REVOKED_get0_revocation_date
*/
const WOLFSSL_ASN1_INTEGER* wolfSSL_X509_REVOKED_get0_serial_number(
                                                const WOLFSSL_X509_REVOKED *rev);

/*!
    \ingroup CertsKeys

    \brief Gets revocation date from revoked certificate.

    \return const WOLFSSL_ASN1_TIME* Revocation date
    \return NULL if not available

    \param rev Revoked certificate

    _Example_
    \code
    const WOLFSSL_ASN1_TIME* date =
        wolfSSL_X509_REVOKED_get0_revocation_date(rev);
    \endcode

    \sa wolfSSL_X509_REVOKED_get0_serial_number
*/
const WOLFSSL_ASN1_TIME* wolfSSL_X509_REVOKED_get0_revocation_date(
                                                const WOLFSSL_X509_REVOKED *rev);

/*!
    \ingroup CertsKeys

    \brief Decodes X509 certificate from file.

    \return WOLFSSL_X509* Decoded certificate
    \return NULL on failure

    \param x509 Pointer to certificate pointer
    \param file File to read from

    _Example_
    \code
    XFILE fp = XFOPEN("cert.der", "rb");
    WOLFSSL_X509* cert = wolfSSL_X509_d2i_fp(NULL, fp);
    XFCLOSE(fp);
    \endcode

    \sa wolfSSL_X509_d2i
*/
WOLFSSL_X509* wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, XFILE file);

/*!
    \ingroup CertsKeys

    \brief Adds PKCS12 PBE algorithms.

    \return none

    _Example_
    \code
    wolfSSL_PKCS12_PBE_add();
    \endcode

    \sa wolfSSL_d2i_PKCS12_fp
*/
void wolfSSL_PKCS12_PBE_add(void);

/*!
    \ingroup CertsKeys

    \brief Decodes PKCS12 from file.

    \return WOLFSSL_X509_PKCS12* Decoded PKCS12
    \return NULL on failure

    \param fp File to read from
    \param pkcs12 Pointer to PKCS12 pointer

    _Example_
    \code
    XFILE fp = XFOPEN("cert.p12", "rb");
    WOLFSSL_X509_PKCS12* p12 = wolfSSL_d2i_PKCS12_fp(fp, NULL);
    XFCLOSE(fp);
    \endcode

    \sa wolfSSL_PKCS12_parse
*/
WOLFSSL_X509_PKCS12* wolfSSL_d2i_PKCS12_fp(XFILE fp,
                                            WOLFSSL_X509_PKCS12** pkcs12);

/*!
    \ingroup CertsKeys

    \brief Verifies PKCS12 MAC.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param pkcs12 PKCS12 structure
    \param psw Password
    \param pswLen Password length

    _Example_
    \code
    int ret = wolfSSL_PKCS12_verify_mac(p12, "password", 8);
    if (ret == WOLFSSL_SUCCESS) {
        printf("MAC verified\n");
    }
    \endcode

    \sa wolfSSL_PKCS12_parse
*/
int wolfSSL_PKCS12_verify_mac(WC_PKCS12 *pkcs12, const char *psw,
                               int pswLen);

/*!
    \ingroup Setup

    \brief Enables DH key test.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param enable Enable flag

    _Example_
    \code
    int ret = wolfSSL_SetEnableDhKeyTest(ssl, 1);
    \endcode

    \sa wolfSSL_SetTmpEC_DHE_Sz
*/
int wolfSSL_SetEnableDhKeyTest(WOLFSSL* ssl, int enable);

/*!
    \ingroup Setup

    \brief Sets temporary EC DHE size.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param sz Key size

    _Example_
    \code
    int ret = wolfSSL_SetTmpEC_DHE_Sz(ssl, 256);
    \endcode

    \sa wolfSSL_CTX_SetTmpEC_DHE_Sz
*/
int wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL* ssl, word16 sz);

/*!
    \ingroup Setup

    \brief Sets temporary EC DHE size in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param sz Key size

    _Example_
    \code
    int ret = wolfSSL_CTX_SetTmpEC_DHE_Sz(ctx, 256);
    \endcode

    \sa wolfSSL_SetTmpEC_DHE_Sz
*/
int wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX* ctx, word16 sz);

/*!
    \ingroup openSSL

    \brief Gets keyblock size.

    \return int Keyblock size
    \return negative on error

    \param ssl SSL object

    _Example_
    \code
    int size = wolfSSL_get_keyblock_size(ssl);
    printf("Keyblock size: %d\n", size);
    \endcode

    \sa wolfSSL_get_keys
*/
int wolfSSL_get_keyblock_size(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets session keys.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param ms Pointer to store master secret
    \param msLen Pointer to store master secret length
    \param sr Pointer to store server random
    \param srLen Pointer to store server random length
    \param cr Pointer to store client random
    \param crLen Pointer to store client random length

    _Example_
    \code
    unsigned char *ms, *sr, *cr;
    unsigned int msLen, srLen, crLen;
    int ret = wolfSSL_get_keys(ssl, &ms, &msLen, &sr, &srLen,
                                &cr, &crLen);
    \endcode

    \sa wolfSSL_get_keyblock_size
*/
int wolfSSL_get_keys(WOLFSSL* ssl, unsigned char** ms, unsigned int* msLen,
                      unsigned char** sr, unsigned int* srLen,
                      unsigned char** cr, unsigned int* crLen);

/*!
    \ingroup CertsKeys

    \brief Unloads trust peers.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_Unload_trust_peers(ssl);
    \endcode

    \sa wolfSSL_CTX_trust_peer_buffer
*/
int wolfSSL_Unload_trust_peers(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Uses private key by ID in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param id Key ID
    \param sz ID size
    \param devId Device ID
    \param keySz Key size

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_CTX_use_PrivateKey_id(ctx, id, sizeof(id), 0, 2048);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_Id
*/
int wolfSSL_CTX_use_PrivateKey_id(WOLFSSL_CTX* ctx,
                                   const unsigned char* id, long sz,
                                   int devId, long keySz);

/*!
    \ingroup CertsKeys

    \brief Uses private key by ID in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param id Key ID
    \param sz ID size
    \param devId Device ID

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_CTX_use_PrivateKey_Id(ctx, id, sizeof(id), 0);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_id
*/
int wolfSSL_CTX_use_PrivateKey_Id(WOLFSSL_CTX* ctx,
                                   const unsigned char* id, long sz,
                                   int devId);

/*!
    \ingroup CertsKeys

    \brief Uses private key by label in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param label Key label
    \param devId Device ID

    _Example_
    \code
    int ret = wolfSSL_CTX_use_PrivateKey_Label(ctx, "mykey", 0);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_Id
*/
int wolfSSL_CTX_use_PrivateKey_Label(WOLFSSL_CTX* ctx, const char* label,
                                      int devId);

/*!
    \ingroup CertsKeys

    \brief Uses certificate chain from buffer with format.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param in Certificate chain buffer
    \param sz Buffer size
    \param format Buffer format

    _Example_
    \code
    int ret = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz,
                                                            SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_CTX_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx,
                                                      const unsigned char* in,
                                                      long sz, int format);

/*!
    \ingroup CertsKeys

    \brief Uses certificate by label in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param label Certificate label
    \param devId Device ID

    _Example_
    \code
    int ret = wolfSSL_CTX_use_certificate_label(ctx, "mycert", 0);
    \endcode

    \sa wolfSSL_CTX_use_certificate_id
*/
int wolfSSL_CTX_use_certificate_label(WOLFSSL_CTX* ctx, const char *label,
                                       int devId);

/*!
    \ingroup CertsKeys

    \brief Uses certificate by ID in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param id Certificate ID
    \param idLen ID length
    \param devId Device ID

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_CTX_use_certificate_id(ctx, id, sizeof(id), 0);
    \endcode

    \sa wolfSSL_CTX_use_certificate_label
*/
int wolfSSL_CTX_use_certificate_id(WOLFSSL_CTX* ctx,
                                    const unsigned char *id, int idLen,
                                    int devId);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key from buffer in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param in Private key buffer
    \param sz Buffer size
    \param format Buffer format

    _Example_
    \code
    int ret = wolfSSL_CTX_use_AltPrivateKey_buffer(ctx, buf, sz,
                                                     SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_buffer
*/
int wolfSSL_CTX_use_AltPrivateKey_buffer(WOLFSSL_CTX* ctx,
                                          const unsigned char* in, long sz,
                                          int format);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key by ID in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param id Key ID
    \param sz ID size
    \param devId Device ID
    \param keySz Key size

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_CTX_use_AltPrivateKey_id(ctx, id, sizeof(id), 0, 2048);
    \endcode

    \sa wolfSSL_CTX_use_AltPrivateKey_Id
*/
int wolfSSL_CTX_use_AltPrivateKey_id(WOLFSSL_CTX* ctx,
                                      const unsigned char* id, long sz,
                                      int devId, long keySz);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key by ID in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param id Key ID
    \param sz ID size
    \param devId Device ID

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_CTX_use_AltPrivateKey_Id(ctx, id, sizeof(id), 0);
    \endcode

    \sa wolfSSL_CTX_use_AltPrivateKey_id
*/
int wolfSSL_CTX_use_AltPrivateKey_Id(WOLFSSL_CTX* ctx,
                                      const unsigned char* id, long sz,
                                      int devId);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key by label in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param label Key label
    \param devId Device ID

    _Example_
    \code
    int ret = wolfSSL_CTX_use_AltPrivateKey_Label(ctx, "myaltkey", 0);
    \endcode

    \sa wolfSSL_CTX_use_AltPrivateKey_Id
*/
int wolfSSL_CTX_use_AltPrivateKey_Label(WOLFSSL_CTX* ctx, const char* label,
                                         int devId);

/*!
    \ingroup CertsKeys

    \brief Uses private key by ID.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param id Key ID
    \param sz ID size
    \param devId Device ID
    \param keySz Key size

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_use_PrivateKey_id(ssl, id, sizeof(id), 0, 2048);
    \endcode

    \sa wolfSSL_use_PrivateKey_Id
*/
int wolfSSL_use_PrivateKey_id(WOLFSSL* ssl, const unsigned char* id, long sz,
                               int devId, long keySz);

/*!
    \ingroup CertsKeys

    \brief Uses private key by ID.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param id Key ID
    \param sz ID size
    \param devId Device ID

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_use_PrivateKey_Id(ssl, id, sizeof(id), 0);
    \endcode

    \sa wolfSSL_use_PrivateKey_id
*/
int wolfSSL_use_PrivateKey_Id(WOLFSSL* ssl, const unsigned char* id, long sz,
                               int devId);

/*!
    \ingroup CertsKeys

    \brief Uses private key by label.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param label Key label
    \param devId Device ID

    _Example_
    \code
    int ret = wolfSSL_use_PrivateKey_Label(ssl, "mykey", 0);
    \endcode

    \sa wolfSSL_use_PrivateKey_Id
*/
int wolfSSL_use_PrivateKey_Label(WOLFSSL* ssl, const char* label, int devId);

/*!
    \ingroup CertsKeys

    \brief Uses certificate chain from buffer with format.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param in Certificate chain buffer
    \param sz Buffer size
    \param format Buffer format

    _Example_
    \code
    int ret = wolfSSL_use_certificate_chain_buffer_format(ssl, buf, sz,
                                                           SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_certificate_chain_buffer_format(WOLFSSL* ssl,
                                                  const unsigned char* in,
                                                  long sz, int format);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key from buffer.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param in Private key buffer
    \param sz Buffer size
    \param format Buffer format

    _Example_
    \code
    int ret = wolfSSL_use_AltPrivateKey_buffer(ssl, buf, sz,
                                                SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_use_PrivateKey_buffer
*/
int wolfSSL_use_AltPrivateKey_buffer(WOLFSSL* ssl, const unsigned char* in,
                                      long sz, int format);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key by ID.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param id Key ID
    \param sz ID size
    \param devId Device ID
    \param keySz Key size

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_use_AltPrivateKey_id(ssl, id, sizeof(id), 0, 2048);
    \endcode

    \sa wolfSSL_use_AltPrivateKey_Id
*/
int wolfSSL_use_AltPrivateKey_id(WOLFSSL* ssl, const unsigned char* id,
                                  long sz, int devId, long keySz);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key by ID.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param id Key ID
    \param sz ID size
    \param devId Device ID

    _Example_
    \code
    unsigned char id[] = {0x01, 0x02, 0x03};
    int ret = wolfSSL_use_AltPrivateKey_Id(ssl, id, sizeof(id), 0);
    \endcode

    \sa wolfSSL_use_AltPrivateKey_id
*/
int wolfSSL_use_AltPrivateKey_Id(WOLFSSL* ssl, const unsigned char* id,
                                  long sz, int devId);

/*!
    \ingroup CertsKeys

    \brief Uses alternate private key by label.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param label Key label
    \param devId Device ID

    _Example_
    \code
    int ret = wolfSSL_use_AltPrivateKey_Label(ssl, "myaltkey", 0);
    \endcode

    \sa wolfSSL_use_AltPrivateKey_Id
*/
int wolfSSL_use_AltPrivateKey_Label(WOLFSSL* ssl, const char* label,
                                     int devId);

/*!
    \ingroup CertsKeys

    \brief Gets certificate from SSL object.

    \return WOLFSSL_X509* Certificate
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_get_certificate(ssl);
    if (cert != NULL) {
        printf("Certificate found\n");
    }
    \endcode

    \sa wolfSSL_CTX_get0_certificate
*/
WOLFSSL_X509* wolfSSL_get_certificate(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Gets certificate from context.

    \return WOLFSSL_X509* Certificate
    \return NULL if not available

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_CTX_get0_certificate(ctx);
    \endcode

    \sa wolfSSL_get_certificate
*/
WOLFSSL_X509* wolfSSL_CTX_get0_certificate(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Gets RNG from SSL object.

    \return WC_RNG* Random number generator
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    WC_RNG* rng = wolfSSL_GetRNG(ssl);
    \endcode

    \sa wolfSSL_CTX_new
*/
WC_RNG* wolfSSL_GetRNG(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Gets WOLFSSL object size.

    \return int Object size in bytes

    _Example_
    \code
    int size = wolfSSL_GetObjectSize();
    printf("WOLFSSL object size: %d bytes\n", size);
    \endcode

    \sa wolfSSL_CTX_GetObjectSize
*/
int wolfSSL_GetObjectSize(void);

/*!
    \ingroup Setup

    \brief Gets WOLFSSL_CTX object size.

    \return int Object size in bytes

    _Example_
    \code
    int size = wolfSSL_CTX_GetObjectSize();
    printf("WOLFSSL_CTX object size: %d bytes\n", size);
    \endcode

    \sa wolfSSL_GetObjectSize
*/
int wolfSSL_CTX_GetObjectSize(void);

/*!
    \ingroup Setup

    \brief Gets WOLFSSL_METHOD object size.

    \return int Object size in bytes

    _Example_
    \code
    int size = wolfSSL_METHOD_GetObjectSize();
    printf("WOLFSSL_METHOD object size: %d bytes\n", size);
    \endcode

    \sa wolfSSL_GetObjectSize
*/
int wolfSSL_METHOD_GetObjectSize(void);

/*!
    \ingroup Setup

    \brief Gets protocol version.

    \return int Protocol version constant

    \param ssl SSL object

    _Example_
    \code
    int version = wolfSSL_GetVersion(ssl);
    printf("Protocol version: %d\n", version);
    \endcode

    \sa wolfSSL_get_version
*/
int wolfSSL_GetVersion(const WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Gets MAC encrypt context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetMacEncryptCtx(ssl);
    \endcode

    \sa wolfSSL_SetEncryptMacCtx
*/
void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Gets decrypt verify context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetDecryptVerifyCtx(ssl);
    \endcode

    \sa wolfSSL_SetVerifyDecryptCtx
*/
void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets encrypt MAC callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEncryptMacCb(ctx, myEncryptMacCallback);
    \endcode

    \sa wolfSSL_SetEncryptMacCtx
*/
void wolfSSL_CTX_SetEncryptMacCb(WOLFSSL_CTX* ctx, CallbackEncryptMac cb);

/*!
    \ingroup Callbacks

    \brief Sets encrypt MAC context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEncryptMacCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEncryptMacCtx
*/
void wolfSSL_SetEncryptMacCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets encrypt MAC context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEncryptMacCtx(ssl);
    \endcode

    \sa wolfSSL_SetEncryptMacCtx
*/
void* wolfSSL_GetEncryptMacCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Checks if async encrypt is ready.

    \return 1 if ready
    \return 0 if not ready

    \param ssl SSL object
    \param idx Index

    _Example_
    \code
    if (wolfSSL_AsyncEncryptReady(ssl, 0)) {
        printf("Async encrypt ready\n");
    }
    \endcode

    \sa wolfSSL_AsyncEncrypt
*/
int wolfSSL_AsyncEncryptReady(WOLFSSL* ssl, int idx);

/*!
    \ingroup Callbacks

    \brief Stops async encrypt.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param idx Index

    _Example_
    \code
    int ret = wolfSSL_AsyncEncryptStop(ssl, 0);
    \endcode

    \sa wolfSSL_AsyncEncrypt
*/
int wolfSSL_AsyncEncryptStop(WOLFSSL* ssl, int idx);

/*!
    \ingroup Callbacks

    \brief Performs async encrypt.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param idx Index

    _Example_
    \code
    int ret = wolfSSL_AsyncEncrypt(ssl, 0);
    \endcode

    \sa wolfSSL_AsyncEncryptReady
*/
int wolfSSL_AsyncEncrypt(WOLFSSL* ssl, int idx);

/*!
    \ingroup Callbacks

    \brief Sets async encrypt signal.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param idx Index
    \param signal Thread signal
    \param ctx Context pointer

    _Example_
    \code
    int ret = wolfSSL_AsyncEncryptSetSignal(ssl, 0, signal, ctx);
    \endcode

    \sa wolfSSL_AsyncEncrypt
*/
int wolfSSL_AsyncEncryptSetSignal(WOLFSSL* ssl, int idx,
                                   WOLFSSL_THREAD_SIGNAL signal, void* ctx);

/*!
    \ingroup Callbacks

    \brief Sets verify decrypt callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetVerifyDecryptCb(ctx, myVerifyDecryptCallback);
    \endcode

    \sa wolfSSL_SetVerifyDecryptCtx
*/
void wolfSSL_CTX_SetVerifyDecryptCb(WOLFSSL_CTX* ctx,
                                     CallbackVerifyDecrypt cb);

/*!
    \ingroup Callbacks

    \brief Sets verify decrypt context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetVerifyDecryptCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetVerifyDecryptCtx
*/
void wolfSSL_SetVerifyDecryptCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets verify decrypt context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetVerifyDecryptCtx(ssl);
    \endcode

    \sa wolfSSL_SetVerifyDecryptCtx
*/
void* wolfSSL_GetVerifyDecryptCtx(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets MAC secret.

    \return const unsigned char* MAC secret
    \return NULL if not available

    \param ssl SSL object
    \param verify Verify flag

    _Example_
    \code
    const unsigned char* secret = wolfSSL_GetMacSecret(ssl, 0);
    \endcode

    \sa wolfSSL_GetDtlsMacSecret
*/
const unsigned char* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify);

/*!
    \ingroup openSSL

    \brief Gets DTLS MAC secret.

    \return const unsigned char* MAC secret
    \return NULL if not available

    \param ssl SSL object
    \param verify Verify flag
    \param epochOrder Epoch order

    _Example_
    \code
    const unsigned char* secret = wolfSSL_GetDtlsMacSecret(ssl, 0, 0);
    \endcode

    \sa wolfSSL_GetMacSecret
*/
const unsigned char* wolfSSL_GetDtlsMacSecret(WOLFSSL* ssl, int verify,
                                               int epochOrder);

/*!
    \ingroup openSSL

    \brief Gets client write key.

    \return const unsigned char* Client write key
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    const unsigned char* key = wolfSSL_GetClientWriteKey(ssl);
    \endcode

    \sa wolfSSL_GetServerWriteKey
*/
const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets client write IV.

    \return const unsigned char* Client write IV
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    const unsigned char* iv = wolfSSL_GetClientWriteIV(ssl);
    \endcode

    \sa wolfSSL_GetServerWriteIV
*/
const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets server write key.

    \return const unsigned char* Server write key
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    const unsigned char* key = wolfSSL_GetServerWriteKey(ssl);
    \endcode

    \sa wolfSSL_GetClientWriteKey
*/
const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets server write IV.

    \return const unsigned char* Server write IV
    \return NULL if not available

    \param ssl SSL object

    _Example_
    \code
    const unsigned char* iv = wolfSSL_GetServerWriteIV(ssl);
    \endcode

    \sa wolfSSL_GetClientWriteIV
*/
const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Gets peer sequence number.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param seq Pointer to store sequence number

    _Example_
    \code
    word64 seq;
    int ret = wolfSSL_GetPeerSequenceNumber(ssl, &seq);
    \endcode

    \sa wolfSSL_GetSequenceNumber
*/
int wolfSSL_GetPeerSequenceNumber(WOLFSSL* ssl, word64* seq);

/*!
    \ingroup openSSL

    \brief Gets sequence number.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param seq Pointer to store sequence number

    _Example_
    \code
    word64 seq;
    int ret = wolfSSL_GetSequenceNumber(ssl, &seq);
    \endcode

    \sa wolfSSL_GetPeerSequenceNumber
*/
int wolfSSL_GetSequenceNumber(WOLFSSL* ssl, word64* seq);

/*!
    \ingroup Callbacks

    \brief Sets ECC key generation callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEccKeyGenCb(ctx, myEccKeyGenCallback);
    \endcode

    \sa wolfSSL_SetEccKeyGenCtx
*/
void wolfSSL_CTX_SetEccKeyGenCb(WOLFSSL_CTX* ctx, CallbackEccKeyGen cb);

/*!
    \ingroup Callbacks

    \brief Sets ECC key generation context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEccKeyGenCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEccKeyGenCtx
*/
void wolfSSL_SetEccKeyGenCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets ECC key generation context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEccKeyGenCtx(ssl);
    \endcode

    \sa wolfSSL_SetEccKeyGenCtx
*/
void* wolfSSL_GetEccKeyGenCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Gets ECC sign context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEccSignCtx(ssl);
    \endcode

    \sa wolfSSL_CTX_GetEccSignCtx
*/
void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Gets ECC sign context from context.

    \return void* Context pointer
    \return NULL if not set

    \param ctx SSL context

    _Example_
    \code
    void* ctx = wolfSSL_CTX_GetEccSignCtx(ctx);
    \endcode

    \sa wolfSSL_GetEccSignCtx
*/
void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx);

/*!
    \ingroup Callbacks

    \brief Gets ECC verify context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEccVerifyCtx(ssl);
    \endcode

    \sa wolfSSL_GetEccSignCtx
*/
void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets ECC shared secret callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, myEccSharedSecretCallback);
    \endcode

    \sa wolfSSL_SetEccSharedSecretCtx
*/
void wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX* ctx,
                                       CallbackEccSharedSecret cb);

/*!
    \ingroup Callbacks

    \brief Sets ECC shared secret context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEccSharedSecretCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEccSharedSecretCtx
*/
void wolfSSL_SetEccSharedSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets ECC shared secret context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEccSharedSecretCtx(ssl);
    \endcode

    \sa wolfSSL_SetEccSharedSecretCtx
*/
void* wolfSSL_GetEccSharedSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets HKDF extract callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetHKDFExtractCb(ctx, myHKDFExtractCallback);
    \endcode

    \sa wolfSSL_SetHKDFExtractCtx
*/
void wolfSSL_CTX_SetHKDFExtractCb(WOLFSSL_CTX* ctx,
                                   CallbackHKDFExtract cb);

/*!
    \ingroup Callbacks

    \brief Gets HKDF extract context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetHKDFExtractCtx(ssl);
    \endcode

    \sa wolfSSL_SetHKDFExtractCtx
*/
void* wolfSSL_GetHKDFExtractCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets HKDF extract context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetHKDFExtractCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetHKDFExtractCtx
*/
void wolfSSL_SetHKDFExtractCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Sets DH generate key pair callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetDhGenerateKeyPair(ctx, myDhGenerateKeyPairCallback);
    \endcode

    \sa wolfSSL_CTX_SetDhAgreeCb
*/
void wolfSSL_CTX_SetDhGenerateKeyPair(WOLFSSL_CTX* ctx,
                                       CallbackDhGenerateKeyPair cb);

/*!
    \ingroup Callbacks

    \brief Sets DH agree callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetDhAgreeCb(ctx, myDhAgreeCallback);
    \endcode

    \sa wolfSSL_SetDhAgreeCtx
*/
void wolfSSL_CTX_SetDhAgreeCb(WOLFSSL_CTX* ctx, CallbackDhAgree cb);

/*!
    \ingroup Callbacks

    \brief Sets DH agree context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetDhAgreeCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetDhAgreeCtx
*/
void wolfSSL_SetDhAgreeCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets DH agree context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetDhAgreeCtx(ssl);
    \endcode

    \sa wolfSSL_SetDhAgreeCtx
*/
void* wolfSSL_GetDhAgreeCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets Ed25519 sign callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEd25519SignCb(ctx, myEd25519SignCallback);
    \endcode

    \sa wolfSSL_SetEd25519SignCtx
*/
void wolfSSL_CTX_SetEd25519SignCb(WOLFSSL_CTX* ctx,
                                   CallbackEd25519Sign cb);

/*!
    \ingroup Callbacks

    \brief Sets Ed25519 sign context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEd25519SignCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEd25519SignCtx
*/
void wolfSSL_SetEd25519SignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets Ed25519 sign context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEd25519SignCtx(ssl);
    \endcode

    \sa wolfSSL_SetEd25519SignCtx
*/
void* wolfSSL_GetEd25519SignCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets Ed25519 verify callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEd25519VerifyCb(ctx, myEd25519VerifyCallback);
    \endcode

    \sa wolfSSL_SetEd25519VerifyCtx
*/
void wolfSSL_CTX_SetEd25519VerifyCb(WOLFSSL_CTX* ctx,
                                     CallbackEd25519Verify cb);

/*!
    \ingroup Callbacks

    \brief Sets Ed25519 verify context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEd25519VerifyCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEd25519VerifyCtx
*/
void wolfSSL_SetEd25519VerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets Ed25519 verify context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEd25519VerifyCtx(ssl);
    \endcode

    \sa wolfSSL_SetEd25519VerifyCtx
*/
void* wolfSSL_GetEd25519VerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets X25519 key generation callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetX25519KeyGenCb(ctx, myX25519KeyGenCallback);
    \endcode

    \sa wolfSSL_SetX25519KeyGenCtx
*/
void wolfSSL_CTX_SetX25519KeyGenCb(WOLFSSL_CTX* ctx,
                                    CallbackX25519KeyGen cb);

/*!
    \ingroup Callbacks

    \brief Sets X25519 key generation context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetX25519KeyGenCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetX25519KeyGenCtx
*/
void wolfSSL_SetX25519KeyGenCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets X25519 key generation context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetX25519KeyGenCtx(ssl);
    \endcode

    \sa wolfSSL_SetX25519KeyGenCtx
*/
void* wolfSSL_GetX25519KeyGenCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets X25519 shared secret callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetX25519SharedSecretCb(ctx, myX25519SharedSecretCallback);
    \endcode

    \sa wolfSSL_SetX25519SharedSecretCtx
*/
void wolfSSL_CTX_SetX25519SharedSecretCb(WOLFSSL_CTX* ctx,
                                          CallbackX25519SharedSecret cb);

/*!
    \ingroup Callbacks

    \brief Sets X25519 shared secret context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetX25519SharedSecretCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetX25519SharedSecretCtx
*/
void wolfSSL_SetX25519SharedSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets X25519 shared secret context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetX25519SharedSecretCtx(ssl);
    \endcode

    \sa wolfSSL_SetX25519SharedSecretCtx
*/
void* wolfSSL_GetX25519SharedSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets Ed448 sign callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEd448SignCb(ctx, myEd448SignCallback);
    \endcode

    \sa wolfSSL_SetEd448SignCtx
*/
void wolfSSL_CTX_SetEd448SignCb(WOLFSSL_CTX* ctx, CallbackEd448Sign cb);

/*!
    \ingroup Callbacks

    \brief Sets Ed448 sign context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEd448SignCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEd448SignCtx
*/
void wolfSSL_SetEd448SignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets Ed448 sign context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEd448SignCtx(ssl);
    \endcode

    \sa wolfSSL_SetEd448SignCtx
*/
void* wolfSSL_GetEd448SignCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets Ed448 verify callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEd448VerifyCb(ctx, myEd448VerifyCallback);
    \endcode

    \sa wolfSSL_SetEd448VerifyCtx
*/
void wolfSSL_CTX_SetEd448VerifyCb(WOLFSSL_CTX* ctx, CallbackEd448Verify cb);

/*!
    \ingroup Callbacks

    \brief Sets Ed448 verify context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEd448VerifyCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEd448VerifyCtx
*/
void wolfSSL_SetEd448VerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets Ed448 verify context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEd448VerifyCtx(ssl);
    \endcode

    \sa wolfSSL_SetEd448VerifyCtx
*/
void* wolfSSL_GetEd448VerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets X448 key generation callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetX448KeyGenCb(ctx, myX448KeyGenCallback);
    \endcode

    \sa wolfSSL_SetX448KeyGenCtx
*/
void wolfSSL_CTX_SetX448KeyGenCb(WOLFSSL_CTX* ctx, CallbackX448KeyGen cb);

/*!
    \ingroup Callbacks

    \brief Sets X448 key generation context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetX448KeyGenCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetX448KeyGenCtx
*/
void wolfSSL_SetX448KeyGenCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets X448 key generation context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetX448KeyGenCtx(ssl);
    \endcode

    \sa wolfSSL_SetX448KeyGenCtx
*/
void* wolfSSL_GetX448KeyGenCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets X448 shared secret callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetX448SharedSecretCb(ctx, myX448SharedSecretCallback);
    \endcode

    \sa wolfSSL_SetX448SharedSecretCtx
*/
void wolfSSL_CTX_SetX448SharedSecretCb(WOLFSSL_CTX* ctx,
                                        CallbackX448SharedSecret cb);

/*!
    \ingroup Callbacks

    \brief Sets X448 shared secret context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetX448SharedSecretCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetX448SharedSecretCtx
*/
void wolfSSL_SetX448SharedSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets X448 shared secret context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetX448SharedSecretCtx(ssl);
    \endcode

    \sa wolfSSL_SetX448SharedSecretCtx
*/
void* wolfSSL_GetX448SharedSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Gets RSA sign context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetRsaSignCtx(ssl);
    \endcode

    \sa wolfSSL_GetRsaVerifyCtx
*/
void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets RSA sign check callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetRsaSignCheckCb(ctx, myRsaSignCheckCallback);
    \endcode

    \sa wolfSSL_GetRsaVerifyCtx
*/
void wolfSSL_CTX_SetRsaSignCheckCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);

/*!
    \ingroup Callbacks

    \brief Gets RSA verify context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetRsaVerifyCtx(ssl);
    \endcode

    \sa wolfSSL_GetRsaSignCtx
*/
void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets RSA-PSS sign callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetRsaPssSignCb(ctx, myRsaPssSignCallback);
    \endcode

    \sa wolfSSL_SetRsaPssSignCtx
*/
void wolfSSL_CTX_SetRsaPssSignCb(WOLFSSL_CTX* ctx, CallbackRsaPssSign cb);

/*!
    \ingroup Callbacks

    \brief Sets RSA-PSS sign context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetRsaPssSignCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetRsaPssSignCtx
*/
void wolfSSL_SetRsaPssSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets RSA-PSS sign context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetRsaPssSignCtx(ssl);
    \endcode

    \sa wolfSSL_SetRsaPssSignCtx
*/
void* wolfSSL_GetRsaPssSignCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets RSA-PSS verify callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetRsaPssVerifyCb(ctx, myRsaPssVerifyCallback);
    \endcode

    \sa wolfSSL_CTX_SetRsaPssSignCheckCb
*/
void wolfSSL_CTX_SetRsaPssVerifyCb(WOLFSSL_CTX* ctx,
                                    CallbackRsaPssVerify cb);

/*!
    \ingroup Callbacks

    \brief Sets RSA-PSS sign check callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetRsaPssSignCheckCb(ctx, myRsaPssSignCheckCallback);
    \endcode

    \sa wolfSSL_CTX_SetRsaPssVerifyCb
*/
void wolfSSL_CTX_SetRsaPssSignCheckCb(WOLFSSL_CTX* ctx,
                                       CallbackRsaPssVerify cb);

/*!
    \ingroup Callbacks

    \brief Sets RSA-PSS verify context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetRsaPssVerifyCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetRsaPssVerifyCtx
*/
void wolfSSL_SetRsaPssVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets RSA-PSS verify context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetRsaPssVerifyCtx(ssl);
    \endcode

    \sa wolfSSL_SetRsaPssVerifyCtx
*/
void* wolfSSL_GetRsaPssVerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Gets RSA encrypt context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetRsaEncCtx(ssl);
    \endcode

    \sa wolfSSL_GetRsaDecCtx
*/
void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Gets RSA decrypt context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetRsaDecCtx(ssl);
    \endcode

    \sa wolfSSL_GetRsaEncCtx
*/
void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets generate master secret callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetGenMasterSecretCb(ctx, myGenMasterSecretCallback);
    \endcode

    \sa wolfSSL_SetGenMasterSecretCtx
*/
void wolfSSL_CTX_SetGenMasterSecretCb(WOLFSSL_CTX* ctx,
                                       CallbackGenMasterSecret cb);

/*!
    \ingroup Callbacks

    \brief Sets generate master secret context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetGenMasterSecretCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetGenMasterSecretCtx
*/
void wolfSSL_SetGenMasterSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets generate master secret context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetGenMasterSecretCtx(ssl);
    \endcode

    \sa wolfSSL_SetGenMasterSecretCtx
*/
void* wolfSSL_GetGenMasterSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets generate extended master secret callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetGenExtMasterSecretCb(ctx, myGenExtMasterSecretCallback);
    \endcode

    \sa wolfSSL_SetGenExtMasterSecretCtx
*/
void wolfSSL_CTX_SetGenExtMasterSecretCb(WOLFSSL_CTX* ctx,
                                          CallbackGenExtMasterSecret cb);

/*!
    \ingroup Callbacks

    \brief Sets generate extended master secret context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetGenExtMasterSecretCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetGenExtMasterSecretCtx
*/
void wolfSSL_SetGenExtMasterSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets generate extended master secret context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetGenExtMasterSecretCtx(ssl);
    \endcode

    \sa wolfSSL_SetGenExtMasterSecretCtx
*/
void* wolfSSL_GetGenExtMasterSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets generate pre-master callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetGenPreMasterCb(ctx, myGenPreMasterCallback);
    \endcode

    \sa wolfSSL_SetGenPreMasterCtx
*/
void wolfSSL_CTX_SetGenPreMasterCb(WOLFSSL_CTX* ctx,
                                    CallbackGenPreMaster cb);

/*!
    \ingroup Callbacks

    \brief Sets generate pre-master context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetGenPreMasterCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetGenPreMasterCtx
*/
void wolfSSL_SetGenPreMasterCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets generate pre-master context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetGenPreMasterCtx(ssl);
    \endcode

    \sa wolfSSL_SetGenPreMasterCtx
*/
void* wolfSSL_GetGenPreMasterCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets generate session key callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetGenSessionKeyCb(ctx, myGenSessionKeyCallback);
    \endcode

    \sa wolfSSL_SetGenSessionKeyCtx
*/
void wolfSSL_CTX_SetGenSessionKeyCb(WOLFSSL_CTX* ctx,
                                     CallbackGenSessionKey cb);

/*!
    \ingroup Callbacks

    \brief Sets generate session key context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetGenSessionKeyCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetGenSessionKeyCtx
*/
void wolfSSL_SetGenSessionKeyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets generate session key context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetGenSessionKeyCtx(ssl);
    \endcode

    \sa wolfSSL_SetGenSessionKeyCtx
*/
void* wolfSSL_GetGenSessionKeyCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets encrypt keys callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetEncryptKeysCb(ctx, myEncryptKeysCallback);
    \endcode

    \sa wolfSSL_SetEncryptKeysCtx
*/
void wolfSSL_CTX_SetEncryptKeysCb(WOLFSSL_CTX* ctx,
                                   CallbackEncryptKeys cb);

/*!
    \ingroup Callbacks

    \brief Sets encrypt keys context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetEncryptKeysCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetEncryptKeysCtx
*/
void wolfSSL_SetEncryptKeysCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets encrypt keys context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetEncryptKeysCtx(ssl);
    \endcode

    \sa wolfSSL_SetEncryptKeysCtx
*/
void* wolfSSL_GetEncryptKeysCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets TLS finished callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetTlsFinishedCb(ctx, myTlsFinishedCallback);
    \endcode

    \sa wolfSSL_SetTlsFinishedCtx
*/
void wolfSSL_CTX_SetTlsFinishedCb(WOLFSSL_CTX* ctx,
                                   CallbackTlsFinished cb);

/*!
    \ingroup Callbacks

    \brief Sets TLS finished context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetTlsFinishedCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetTlsFinishedCtx
*/
void wolfSSL_SetTlsFinishedCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets TLS finished context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetTlsFinishedCtx(ssl);
    \endcode

    \sa wolfSSL_SetTlsFinishedCtx
*/
void* wolfSSL_GetTlsFinishedCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets verify MAC callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetVerifyMacCb(ctx, myVerifyMacCallback);
    \endcode

    \sa wolfSSL_SetVerifyMacCtx
*/
void wolfSSL_CTX_SetVerifyMacCb(WOLFSSL_CTX* ctx, CallbackVerifyMac cb);

/*!
    \ingroup Callbacks

    \brief Sets verify MAC context.

    \return none

    \param ssl SSL object
    \param ctx Context pointer

    _Example_
    \code
    wolfSSL_SetVerifyMacCtx(ssl, myContext);
    \endcode

    \sa wolfSSL_GetVerifyMacCtx
*/
void wolfSSL_SetVerifyMacCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup Callbacks

    \brief Gets verify MAC context.

    \return void* Context pointer
    \return NULL if not set

    \param ssl SSL object

    _Example_
    \code
    void* ctx = wolfSSL_GetVerifyMacCtx(ssl);
    \endcode

    \sa wolfSSL_SetVerifyMacCtx
*/
void* wolfSSL_GetVerifyMacCtx(WOLFSSL* ssl);

/*!
    \ingroup Callbacks

    \brief Sets HKDF expand label callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetHKDFExpandLabelCb(ctx, myHKDFExpandLabelCallback);
    \endcode

    \sa wolfSSL_CTX_SetHKDFExtractCb
*/
void wolfSSL_CTX_SetHKDFExpandLabelCb(WOLFSSL_CTX* ctx,
                                       CallbackHKDFExpandLabel cb);

/*!
    \ingroup Callbacks

    \brief Sets process server signature key exchange callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetProcessServerSigKexCb(ctx, myProcessServerSigKexCallback);
    \endcode

    \sa wolfSSL_CTX_SetPerformTlsRecordProcessingCb
*/
void wolfSSL_CTX_SetProcessServerSigKexCb(WOLFSSL_CTX* ctx,
                                           CallbackProcessServerSigKex cb);

/*!
    \ingroup Callbacks

    \brief Sets perform TLS record processing callback in context.

    \return none

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CTX_SetPerformTlsRecordProcessingCb(ctx, myCallback);
    \endcode

    \sa wolfSSL_CTX_SetProcessServerSigKexCb
*/
void wolfSSL_CTX_SetPerformTlsRecordProcessingCb(WOLFSSL_CTX* ctx,
                                        CallbackPerformTlsRecordProcessing cb);

/*!
    \ingroup CertsKeys

    \brief Gets certificate manager from context.

    \return WOLFSSL_CERT_MANAGER* Certificate manager
    \return NULL if not available

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CTX_GetCertManager(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Creates new certificate manager with heap.

    \return WOLFSSL_CERT_MANAGER* New certificate manager
    \return NULL on failure

    \param heap Heap hint

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew_ex(NULL);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);

/*!
    \ingroup CertsKeys

    \brief Creates new certificate manager.

    \return WOLFSSL_CERT_MANAGER* New certificate manager
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    \endcode

    \sa wolfSSL_CertManagerNew_ex
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);

/*!
    \ingroup CertsKeys

    \brief Increments certificate manager reference count.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager

    _Example_
    \code
    int ret = wolfSSL_CertManager_up_ref(cm);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
int wolfSSL_CertManager_up_ref(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertsKeys

    \brief Sets unknown extension callback.

    \return none

    \param cm Certificate manager
    \param cb Callback function

    _Example_
    \code
    wolfSSL_CertManagerSetUnknownExtCallback(cm, myUnknownExtCallback);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
void wolfSSL_CertManagerSetUnknownExtCallback(WOLFSSL_CERT_MANAGER* cm,
                                                wc_UnknownExtCallback cb);

/*!
    \ingroup CertsKeys

    \brief Loads CA buffer with type.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param buff Buffer containing CA
    \param sz Buffer size
    \param format Buffer format
    \param userChain User chain flag
    \param flags Load flags
    \param type Certificate type

    _Example_
    \code
    int ret = wolfSSL_CertManagerLoadCABufferType(cm, buf, sz,
                                        SSL_FILETYPE_PEM, 0, 0, 0);
    \endcode

    \sa wolfSSL_CertManagerLoadCABuffer
*/
int wolfSSL_CertManagerLoadCABufferType(WOLFSSL_CERT_MANAGER* cm,
                                         const unsigned char* buff, long sz,
                                         int format, int userChain,
                                         word32 flags, int type);

/*!
    \ingroup CertsKeys

    \brief Loads CA buffer with extended options.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param buff Buffer containing CA
    \param sz Buffer size
    \param format Buffer format
    \param userChain User chain flag
    \param flags Load flags

    _Example_
    \code
    int ret = wolfSSL_CertManagerLoadCABuffer_ex(cm, buf, sz,
                                        SSL_FILETYPE_PEM, 0, 0);
    \endcode

    \sa wolfSSL_CertManagerLoadCABuffer
*/
int wolfSSL_CertManagerLoadCABuffer_ex(WOLFSSL_CERT_MANAGER* cm,
                                        const unsigned char* buff, long sz,
                                        int format, int userChain,
                                        word32 flags);

/*!
    \ingroup CertsKeys

    \brief Unloads certificates of specific type.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param type Certificate type

    _Example_
    \code
    int ret = wolfSSL_CertManagerUnloadTypeCerts(cm, 0);
    \endcode

    \sa wolfSSL_CertManagerLoadCABuffer
*/
int wolfSSL_CertManagerUnloadTypeCerts(WOLFSSL_CERT_MANAGER* cm, byte type);

/*!
    \ingroup CertsKeys

    \brief Loads CRL from file.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param file CRL file path
    \param type CRL type

    _Example_
    \code
    int ret = wolfSSL_CertManagerLoadCRLFile(cm, "crl.pem",
                                              SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
*/
int wolfSSL_CertManagerLoadCRLFile(WOLFSSL_CERT_MANAGER* cm,
                                    const char* file, int type);

/*!
    \ingroup CertsKeys

    \brief Sets CRL error callback.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param cb Callback function
    \param ctx Context pointer

    _Example_
    \code
    int ret = wolfSSL_CertManagerSetCRL_ErrorCb(cm, myCrlErrorCb, ctx);
    \endcode

    \sa wolfSSL_CertManagerSetCRL_Cb
*/
int wolfSSL_CertManagerSetCRL_ErrorCb(WOLFSSL_CERT_MANAGER* cm,
                                       crlErrorCb cb, void* ctx);

/*!
    \ingroup CertsKeys

    \brief Sets CRL I/O callback.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param cb Callback function

    _Example_
    \code
    int ret = wolfSSL_CertManagerSetCRL_IOCb(cm, myCrlIOCb);
    \endcode

    \sa wolfSSL_CertManagerSetCRL_Cb
*/
int wolfSSL_CertManagerSetCRL_IOCb(WOLFSSL_CERT_MANAGER* cm, CbCrlIO cb);

/*!
    \ingroup CertsKeys

    \brief Gets CRL info from buffer.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param info CRL info structure
    \param buff CRL buffer
    \param sz Buffer size
    \param type CRL type

    _Example_
    \code
    CrlInfo info;
    int ret = wolfSSL_CertManagerGetCRLInfo(cm, &info, buf, sz,
                                             SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
*/
int wolfSSL_CertManagerGetCRLInfo(WOLFSSL_CERT_MANAGER* cm, CrlInfo* info,
                                   const byte* buff, long sz, int type);

/*!
    \ingroup CertsKeys

    \brief Checks OCSP response.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager
    \param response OCSP response
    \param responseSz Response size
    \param responseBuffer Response buffer info
    \param status Certificate status
    \param entry OCSP entry
    \param ocspRequest OCSP request

    _Example_
    \code
    int ret = wolfSSL_CertManagerCheckOCSPResponse(cm, resp, respSz,
                                                    &buf, &status,
                                                    &entry, &req);
    \endcode

    \sa wolfSSL_CertManagerCheckOCSP
*/
int wolfSSL_CertManagerCheckOCSPResponse(WOLFSSL_CERT_MANAGER* cm,
                                          unsigned char *response,
                                          int responseSz,
                                          WOLFSSL_BUFFER_INFO *responseBuffer,
                                          CertStatus *status,
                                          OcspEntry *entry,
                                          OcspRequest *ocspRequest);

/*!
    \ingroup CertsKeys

    \brief Disables OCSP stapling.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager

    _Example_
    \code
    int ret = wolfSSL_CertManagerDisableOCSPStapling(cm);
    \endcode

    \sa wolfSSL_CertManagerEnableOCSPStapling
*/
int wolfSSL_CertManagerDisableOCSPStapling(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertsKeys

    \brief Enables OCSP must staple.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager

    _Example_
    \code
    int ret = wolfSSL_CertManagerEnableOCSPMustStaple(cm);
    \endcode

    \sa wolfSSL_CertManagerDisableOCSPMustStaple
*/
int wolfSSL_CertManagerEnableOCSPMustStaple(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertsKeys

    \brief Disables OCSP must staple.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cm Certificate manager

    _Example_
    \code
    int ret = wolfSSL_CertManagerDisableOCSPMustStaple(cm);
    \endcode

    \sa wolfSSL_CertManagerEnableOCSPMustStaple
*/
int wolfSSL_CertManagerDisableOCSPMustStaple(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertsKeys

    \brief Gets certificates from certificate manager.

    \return WOLFSSL_STACK* Stack of certificates
    \return NULL on failure

    \param cm Certificate manager

    _Example_
    \code
    WOLFSSL_STACK* certs = wolfSSL_CertManagerGetCerts(cm);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
WOLFSSL_STACK* wolfSSL_CertManagerGetCerts(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertsKeys

    \brief Loads CRL from file.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param file CRL file path
    \param type CRL type

    _Example_
    \code
    int ret = wolfSSL_LoadCRLFile(ssl, "crl.pem", SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_LoadCRLBuffer
*/
int wolfSSL_LoadCRLFile(WOLFSSL* ssl, const char* file, int type);

/*!
    \ingroup CertsKeys

    \brief Loads CRL from buffer.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param buff CRL buffer
    \param sz Buffer size
    \param type CRL type

    _Example_
    \code
    int ret = wolfSSL_LoadCRLBuffer(ssl, buf, sz, SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_LoadCRLFile
*/
int wolfSSL_LoadCRLBuffer(WOLFSSL* ssl, const unsigned char* buff, long sz,
                           int type);

/*!
    \ingroup CertsKeys

    \brief Sets CRL error callback.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param cb Callback function
    \param ctx Context pointer

    _Example_
    \code
    int ret = wolfSSL_SetCRL_ErrorCb(ssl, myCrlErrorCb, ctx);
    \endcode

    \sa wolfSSL_SetCRL_IOCb
*/
int wolfSSL_SetCRL_ErrorCb(WOLFSSL* ssl, crlErrorCb cb, void* ctx);

/*!
    \ingroup CertsKeys

    \brief Sets CRL I/O callback.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param cb Callback function

    _Example_
    \code
    int ret = wolfSSL_SetCRL_IOCb(ssl, myCrlIOCb);
    \endcode

    \sa wolfSSL_SetCRL_ErrorCb
*/
int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb);

/*!
    \ingroup CertsKeys

    \brief Enables OCSP stapling.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_EnableOCSPStapling(ssl);
    \endcode

    \sa wolfSSL_UseOCSPStapling
*/
int wolfSSL_EnableOCSPStapling(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Disables OCSP stapling.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_DisableOCSPStapling(ssl);
    \endcode

    \sa wolfSSL_EnableOCSPStapling
*/
int wolfSSL_DisableOCSPStapling(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Loads CRL from file in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param path CRL file path
    \param type CRL type

    _Example_
    \code
    int ret = wolfSSL_CTX_LoadCRLFile(ctx, "crl.pem", SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_CTX_LoadCRLBuffer
*/
int wolfSSL_CTX_LoadCRLFile(WOLFSSL_CTX* ctx, const char* path, int type);

/*!
    \ingroup CertsKeys

    \brief Loads CRL from buffer in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param buff CRL buffer
    \param sz Buffer size
    \param type CRL type

    _Example_
    \code
    int ret = wolfSSL_CTX_LoadCRLBuffer(ctx, buf, sz, SSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_CTX_LoadCRLFile
*/
int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                               long sz, int type);

/*!
    \ingroup CertsKeys

    \brief Sets CRL error callback in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param cb Callback function
    \param cbCtx Context pointer

    _Example_
    \code
    int ret = wolfSSL_CTX_SetCRL_ErrorCb(ctx, myCrlErrorCb, ctx);
    \endcode

    \sa wolfSSL_CTX_SetCRL_IOCb
*/
int wolfSSL_CTX_SetCRL_ErrorCb(WOLFSSL_CTX* ctx, crlErrorCb cb, void* cbCtx);

/*!
    \ingroup CertsKeys

    \brief Sets CRL I/O callback in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param cb Callback function

    _Example_
    \code
    int ret = wolfSSL_CTX_SetCRL_IOCb(ctx, myCrlIOCb);
    \endcode

    \sa wolfSSL_CTX_SetCRL_ErrorCb
*/
int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX* ctx, CbCrlIO cb);

/*!
    \ingroup CertsKeys

    \brief Disables OCSP stapling in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_DisableOCSPStapling(ctx);
    \endcode

    \sa wolfSSL_CTX_UseOCSPStapling
*/
int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Enables OCSP must staple in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_EnableOCSPMustStaple(ctx);
    \endcode

    \sa wolfSSL_CTX_DisableOCSPMustStaple
*/
int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Disables OCSP must staple in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_DisableOCSPMustStaple(ctx);
    \endcode

    \sa wolfSSL_CTX_EnableOCSPMustStaple
*/
int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Creates new RNG in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_new_rng(ctx);
    \endcode

    \sa wolfSSL_CTX_new
*/
int wolfSSL_CTX_new_rng(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Keeps handshake resources after handshake.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_KeepHandshakeResources(ssl);
    \endcode

    \sa wolfSSL_FreeHandshakeResources
*/
int wolfSSL_KeepHandshakeResources(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Frees handshake resources.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_FreeHandshakeResources(ssl);
    \endcode

    \sa wolfSSL_KeepHandshakeResources
*/
int wolfSSL_FreeHandshakeResources(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Uses client cipher suites in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_UseClientSuites(ctx);
    \endcode

    \sa wolfSSL_UseClientSuites
*/
int wolfSSL_CTX_UseClientSuites(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Uses client cipher suites.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_UseClientSuites(ssl);
    \endcode

    \sa wolfSSL_CTX_UseClientSuites
*/
int wolfSSL_UseClientSuites(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Gets heap from context.

    \return void* Heap pointer
    \return NULL if not set

    \param ctx SSL context
    \param ssl SSL object

    _Example_
    \code
    void* heap = wolfSSL_CTX_GetHeap(ctx, ssl);
    \endcode

    \sa wolfSSL_CTX_new_ex
*/
void* wolfSSL_CTX_GetHeap(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Uses trusted CA extension.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param type CA type
    \param certId Certificate ID
    \param certIdSz Certificate ID size

    _Example_
    \code
    int ret = wolfSSL_UseTrustedCA(ssl, 0, id, idSz);
    \endcode

    \sa wolfSSL_CTX_UseTrustedCA
*/
int wolfSSL_UseTrustedCA(WOLFSSL* ssl, unsigned char type,
                          const unsigned char* certId, unsigned int certIdSz);

/*!
    \ingroup Setup

    \brief Frees peer protocol list.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param list Protocol list

    _Example_
    \code
    int ret = wolfSSL_ALPN_FreePeerProtocol(ssl, &list);
    \endcode

    \sa wolfSSL_ALPN_GetPeerProtocol
*/
int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char **list);

/*!
    \ingroup Setup

    \brief Uses cookie key share extension.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param sigSpec Signature specification
    \param sigSpecSz Specification size

    _Example_
    \code
    int ret = wolfSSL_UseCKS(ssl, spec, specSz);
    \endcode

    \sa wolfSSL_CTX_UseCKS
*/
int wolfSSL_UseCKS(WOLFSSL* ssl, byte *sigSpec, word16 sigSpecSz);

/*!
    \ingroup Setup

    \brief Uses cookie key share extension in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param sigSpec Signature specification
    \param sigSpecSz Specification size

    _Example_
    \code
    int ret = wolfSSL_CTX_UseCKS(ctx, spec, specSz);
    \endcode

    \sa wolfSSL_UseCKS
*/
int wolfSSL_CTX_UseCKS(WOLFSSL_CTX* ctx, byte *sigSpec, word16 sigSpecSz);

/*!
    \ingroup Setup

    \brief Uses secure renegotiation in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_UseSecureRenegotiation(ctx);
    \endcode

    \sa wolfSSL_SecureResume
*/
int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Securely resumes session.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_SecureResume(ssl);
    \endcode

    \sa wolfSSL_CTX_UseSecureRenegotiation
*/
int wolfSSL_SecureResume(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Gets secure renegotiation support.

    \return 1 if supported
    \return 0 if not supported

    \param ssl SSL object

    _Example_
    \code
    long ret = wolfSSL_SSL_get_secure_renegotiation_support(ssl);
    \endcode

    \sa wolfSSL_CTX_UseSecureRenegotiation
*/
long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Disables session tickets for TLS 1.2 in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_NoTicketTLSv12(ctx);
    \endcode

    \sa wolfSSL_NoTicketTLSv12
*/
int wolfSSL_CTX_NoTicketTLSv12(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Disables session tickets for TLS 1.2.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_NoTicketTLSv12(ssl);
    \endcode

    \sa wolfSSL_CTX_NoTicketTLSv12
*/
int wolfSSL_NoTicketTLSv12(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Gets ticket encryption context.

    \return void* Context pointer
    \return NULL if not set

    \param ctx SSL context

    _Example_
    \code
    void* ticketCtx = wolfSSL_CTX_get_TicketEncCtx(ctx);
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCb
*/
void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Gets number of tickets.

    \return size_t Number of tickets

    \param ctx SSL context

    _Example_
    \code
    size_t num = wolfSSL_CTX_get_num_tickets(ctx);
    \endcode

    \sa wolfSSL_CTX_set_num_tickets
*/
size_t wolfSSL_CTX_get_num_tickets(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Sets number of tickets.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param mxTickets Maximum tickets

    _Example_
    \code
    int ret = wolfSSL_CTX_set_num_tickets(ctx, 2);
    \endcode

    \sa wolfSSL_CTX_get_num_tickets
*/
int wolfSSL_CTX_set_num_tickets(WOLFSSL_CTX* ctx, size_t mxTickets);

/*!
    \ingroup Setup

    \brief Disables extended master secret.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object

    _Example_
    \code
    int ret = wolfSSL_DisableExtendedMasterSecret(ssl);
    \endcode

    \sa wolfSSL_CTX_DisableExtendedMasterSecret
*/
int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Disables extended master secret in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    int ret = wolfSSL_CTX_DisableExtendedMasterSecret(ctx);
    \endcode

    \sa wolfSSL_DisableExtendedMasterSecret
*/
int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Makes TLS extended master secret.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ms Master secret buffer
    \param msLen Master secret length
    \param pms Pre-master secret
    \param pmsLen Pre-master secret length
    \param sHash Session hash
    \param sHashLen Session hash length
    \param tls1_2 TLS 1.2 flag
    \param hash_type Hash type

    _Example_
    \code
    int ret = wolfSSL_MakeTlsExtendedMasterSecret(ms, msLen, pms, pmsLen,
                                                   sHash, sHashLen, 1, 0);
    \endcode

    \sa wolfSSL_MakeTlsMasterSecret
*/
int wolfSSL_MakeTlsExtendedMasterSecret(unsigned char* ms, word32 msLen,
                                         const unsigned char* pms,
                                         word32 pmsLen,
                                         const unsigned char* sHash,
                                         word32 sHashLen, int tls1_2,
                                         int hash_type);

/*!
    \ingroup Setup

    \brief Placeholder for wolfSCEP support.

    \return none

    _Example_
    \code
    wolfSSL_wolfSCEP();
    \endcode

    \sa wolfSSL_cert_service
*/
void wolfSSL_wolfSCEP(void);

/*!
    \ingroup Setup

    \brief Placeholder for certificate service support.

    \return none

    _Example_
    \code
    wolfSSL_cert_service();
    \endcode

    \sa wolfSSL_wolfSCEP
*/
void wolfSSL_cert_service(void);

/*!
    \ingroup openSSL

    \brief Gets index by object in X509 name.

    \return int Index
    \return -1 if not found

    \param name X509 name
    \param obj ASN1 object
    \param idx Starting index

    _Example_
    \code
    int idx = wolfSSL_X509_NAME_get_index_by_OBJ(name, obj, -1);
    \endcode

    \sa wolfSSL_X509_NAME_get_entry
*/
int wolfSSL_X509_NAME_get_index_by_OBJ(WOLFSSL_X509_NAME *name,
                                        const WOLFSSL_ASN1_OBJECT *obj,
                                        int idx);

/*!
    \ingroup openSSL

    \brief Converts NID to short name.

    \return const char* Short name
    \return NULL if not found

    \param n NID

    _Example_
    \code
    const char* sn = wolfSSL_OBJ_nid2sn(NID_commonName);
    \endcode

    \sa wolfSSL_OBJ_nid2ln
*/
const char* wolfSSL_OBJ_nid2sn(int n);

/*!
    \ingroup openSSL

    \brief Converts object to NID.

    \return int NID
    \return NID_undef if not found

    \param o ASN1 object

    _Example_
    \code
    int nid = wolfSSL_OBJ_obj2nid(obj);
    \endcode

    \sa wolfSSL_OBJ_nid2obj
*/
int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o);

/*!
    \ingroup openSSL

    \brief Gets object type.

    \return int Object type
    \return 0 if not found

    \param o ASN1 object

    _Example_
    \code
    int type = wolfSSL_OBJ_get_type(obj);
    \endcode

    \sa wolfSSL_OBJ_obj2nid
*/
int wolfSSL_OBJ_get_type(const WOLFSSL_ASN1_OBJECT *o);

/*!
    \ingroup openSSL

    \brief Converts short name to NID.

    \return int NID
    \return NID_undef if not found

    \param sn Short name

    _Example_
    \code
    int nid = wolfSSL_OBJ_sn2nid("CN");
    \endcode

    \sa wolfSSL_OBJ_nid2sn
*/
int wolfSSL_OBJ_sn2nid(const char *sn);

/*!
    \ingroup openSSL

    \brief Gets object length.

    \return size_t Object length

    \param o ASN1 object

    _Example_
    \code
    size_t len = wolfSSL_OBJ_length(obj);
    \endcode

    \sa wolfSSL_OBJ_get0_data
*/
size_t wolfSSL_OBJ_length(const WOLFSSL_ASN1_OBJECT* o);

/*!
    \ingroup openSSL

    \brief Gets object data.

    \return const unsigned char* Object data
    \return NULL if not available

    \param o ASN1 object

    _Example_
    \code
    const unsigned char* data = wolfSSL_OBJ_get0_data(obj);
    \endcode

    \sa wolfSSL_OBJ_length
*/
const unsigned char* wolfSSL_OBJ_get0_data(const WOLFSSL_ASN1_OBJECT* o);

/*!
    \ingroup openSSL

    \brief Converts NID to long name.

    \return const char* Long name
    \return NULL if not found

    \param n NID

    _Example_
    \code
    const char* ln = wolfSSL_OBJ_nid2ln(NID_commonName);
    \endcode

    \sa wolfSSL_OBJ_nid2sn
*/
const char* wolfSSL_OBJ_nid2ln(int n);

/*!
    \ingroup openSSL

    \brief Converts long name to NID.

    \return int NID
    \return NID_undef if not found

    \param ln Long name

    _Example_
    \code
    int nid = wolfSSL_OBJ_ln2nid("commonName");
    \endcode

    \sa wolfSSL_OBJ_nid2ln
*/
int wolfSSL_OBJ_ln2nid(const char *ln);

/*!
    \ingroup openSSL

    \brief Compares two objects.

    \return 0 if equal
    \return non-zero if different

    \param a First object
    \param b Second object

    _Example_
    \code
    int cmp = wolfSSL_OBJ_cmp(obj1, obj2);
    \endcode

    \sa wolfSSL_OBJ_obj2nid
*/
int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a,
                     const WOLFSSL_ASN1_OBJECT* b);

/*!
    \ingroup openSSL

    \brief Converts text to NID.

    \return int NID
    \return NID_undef if not found

    \param sn Text name

    _Example_
    \code
    int nid = wolfSSL_OBJ_txt2nid("CN");
    \endcode

    \sa wolfSSL_OBJ_txt2obj
*/
int wolfSSL_OBJ_txt2nid(const char *sn);

/*!
    \ingroup openSSL

    \brief Converts text to object.

    \return WOLFSSL_ASN1_OBJECT* Object
    \return NULL on failure

    \param s Text string
    \param no_name No name flag

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_OBJ_txt2obj("CN", 0);
    \endcode

    \sa wolfSSL_OBJ_txt2nid
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name);

/*!
    \ingroup openSSL

    \brief Converts NID to object.

    \return WOLFSSL_ASN1_OBJECT* Object
    \return NULL on failure

    \param n NID

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_OBJ_nid2obj(NID_commonName);
    \endcode

    \sa wolfSSL_OBJ_obj2nid
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj(int n);

/*!
    \ingroup openSSL

    \brief Converts object to text.

    \return int Length written
    \return -1 on failure

    \param buf Output buffer
    \param buf_len Buffer length
    \param a ASN1 object
    \param no_name No name flag

    _Example_
    \code
    char buf[256];
    int len = wolfSSL_OBJ_obj2txt(buf, sizeof(buf), obj, 0);
    \endcode

    \sa wolfSSL_OBJ_txt2obj
*/
int wolfSSL_OBJ_obj2txt(char *buf, int buf_len,
                         const WOLFSSL_ASN1_OBJECT *a, int no_name);

/*!
    \ingroup openSSL

    \brief Cleans up object table.

    \return none

    _Example_
    \code
    wolfSSL_OBJ_cleanup();
    \endcode

    \sa wolfSSL_OBJ_create
*/
void wolfSSL_OBJ_cleanup(void);

/*!
    \ingroup openSSL

    \brief Creates new object.

    \return int NID
    \return NID_undef on failure

    \param oid OID string
    \param sn Short name
    \param ln Long name

    _Example_
    \code
    int nid = wolfSSL_OBJ_create("1.2.3.4", "myObj", "My Object");
    \endcode

    \sa wolfSSL_OBJ_cleanup
*/
int wolfSSL_OBJ_create(const char *oid, const char *sn, const char *ln);

/*!
    \ingroup Debug

    \brief Peeks last error line.

    \return unsigned long Error code

    \param file File pointer
    \param line Line pointer

    _Example_
    \code
    const char* file;
    int line;
    unsigned long err = wolfSSL_ERR_peek_last_error_line(&file, &line);
    \endcode

    \sa wolfSSL_ERR_get_error
*/
unsigned long wolfSSL_ERR_peek_last_error_line(const char **file, int *line);

/*!
    \ingroup Setup

    \brief Controls context settings.

    \return long Result value

    \param ctx SSL context
    \param cmd Command
    \param opt Option
    \param pt Pointer

    _Example_
    \code
    long ret = wolfSSL_CTX_ctrl(ctx, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY,
                                 NULL);
    \endcode

    \sa wolfSSL_ctrl
*/
long wolfSSL_CTX_ctrl(WOLFSSL_CTX* ctx, int cmd, long opt, void* pt);

/*!
    \ingroup CertsKeys

    \brief Clears extra chain certificates.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context

    _Example_
    \code
    long ret = wolfSSL_CTX_clear_extra_chain_certs(ctx);
    \endcode

    \sa wolfSSL_CTX_add_extra_chain_cert
*/
long wolfSSL_CTX_clear_extra_chain_certs(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Clears certificates from SSL object.

    \return none

    \param ssl SSL object

    _Example_
    \code
    wolfSSL_certs_clear(ssl);
    \endcode

    \sa wolfSSL_CTX_clear_extra_chain_certs
*/
void wolfSSL_certs_clear(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Creates X509 name entry by NID.

    \return WOLFSSL_X509_NAME_ENTRY* Entry
    \return NULL on failure

    \param out Output entry pointer
    \param nid NID
    \param type Value type
    \param data Value data
    \param dataSz Data size

    _Example_
    \code
    WOLFSSL_X509_NAME_ENTRY* entry;
    entry = wolfSSL_X509_NAME_ENTRY_create_by_NID(&entry, NID_commonName,
                                                    MBSTRING_UTF8,
                                                    (unsigned char*)"Test",
                                                    4);
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_create_by_txt
*/
WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_ENTRY_create_by_NID(
                                        WOLFSSL_X509_NAME_ENTRY** out,
                                        int nid, int type,
                                        const unsigned char* data,
                                        int dataSz);

/*!
    \ingroup openSSL

    \brief Creates X509 name entry by text.

    \return WOLFSSL_X509_NAME_ENTRY* Entry
    \return NULL on failure

    \param neIn Input entry pointer
    \param txt Field name
    \param format Value format
    \param data Value data
    \param dataSz Data size

    _Example_
    \code
    WOLFSSL_X509_NAME_ENTRY* entry;
    entry = wolfSSL_X509_NAME_ENTRY_create_by_txt(&entry, "CN",
                                                    MBSTRING_UTF8,
                                                    (unsigned char*)"Test",
                                                    4);
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_create_by_NID
*/
WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_ENTRY_create_by_txt(
                                        WOLFSSL_X509_NAME_ENTRY **neIn,
                                        const char *txt, int format,
                                        const unsigned char *data,
                                        int dataSz);

/*!
    \ingroup openSSL

    \brief Adds entry to X509 name.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param name X509 name
    \param entry Name entry
    \param idx Index
    \param set Set

    _Example_
    \code
    int ret = wolfSSL_X509_NAME_add_entry(name, entry, -1, 0);
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_create_by_NID
*/
int wolfSSL_X509_NAME_add_entry(WOLFSSL_X509_NAME* name,
                                 WOLFSSL_X509_NAME_ENTRY* entry,
                                 int idx, int set);

/*!
    \ingroup openSSL

    \brief Adds entry to X509 name by text.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param name X509 name
    \param field Field name
    \param type Value type
    \param bytes Value bytes
    \param len Value length
    \param loc Location
    \param set Set

    _Example_
    \code
    int ret = wolfSSL_X509_NAME_add_entry_by_txt(name, "CN",
                                                   MBSTRING_UTF8,
                                                   (unsigned char*)"Test",
                                                   4, -1, 0);
    \endcode

    \sa wolfSSL_X509_NAME_add_entry
*/
int wolfSSL_X509_NAME_add_entry_by_txt(WOLFSSL_X509_NAME *name,
                                        const char *field, int type,
                                        const unsigned char *bytes,
                                        int len, int loc, int set);

/*!
    \ingroup openSSL

    \brief Adds entry to X509 name by NID.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param name X509 name
    \param nid NID
    \param type Value type
    \param bytes Value bytes
    \param len Value length
    \param loc Location
    \param set Set

    _Example_
    \code
    int ret = wolfSSL_X509_NAME_add_entry_by_NID(name, NID_commonName,
                                                   MBSTRING_UTF8,
                                                   (unsigned char*)"Test",
                                                   4, -1, 0);
    \endcode

    \sa wolfSSL_X509_NAME_add_entry_by_txt
*/
int wolfSSL_X509_NAME_add_entry_by_NID(WOLFSSL_X509_NAME *name, int nid,
                                        int type,
                                        const unsigned char *bytes,
                                        int len, int loc, int set);

/*!
    \ingroup openSSL

    \brief Compares two X509 names.

    \return 0 if equal
    \return non-zero if different

    \param x First name
    \param y Second name

    _Example_
    \code
    int cmp = wolfSSL_X509_NAME_cmp(name1, name2);
    \endcode

    \sa wolfSSL_X509_cmp
*/
int wolfSSL_X509_NAME_cmp(const WOLFSSL_X509_NAME* x,
                          const WOLFSSL_X509_NAME* y);

/*!
    \ingroup openSSL

    \brief Creates new X509 name.

    \return WOLFSSL_X509_NAME* Name
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_NAME_new();
    \endcode

    \sa wolfSSL_X509_NAME_new_ex
*/
WOLFSSL_X509_NAME* wolfSSL_X509_NAME_new(void);

/*!
    \ingroup openSSL

    \brief Creates new X509 name with heap.

    \return WOLFSSL_X509_NAME* Name
    \return NULL on failure

    \param heap Heap hint

    _Example_
    \code
    WOLFSSL_X509_NAME* name = wolfSSL_X509_NAME_new_ex(NULL);
    \endcode

    \sa wolfSSL_X509_NAME_new
*/
WOLFSSL_X509_NAME* wolfSSL_X509_NAME_new_ex(void *heap);

/*!
    \ingroup openSSL

    \brief Duplicates X509 name.

    \return WOLFSSL_X509_NAME* Duplicated name
    \return NULL on failure

    \param name Name to duplicate

    _Example_
    \code
    WOLFSSL_X509_NAME* dup = wolfSSL_X509_NAME_dup(name);
    \endcode

    \sa wolfSSL_X509_NAME_copy
*/
WOLFSSL_X509_NAME* wolfSSL_X509_NAME_dup(WOLFSSL_X509_NAME* name);

/*!
    \ingroup openSSL

    \brief Copies X509 name.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param from Source name
    \param to Destination name

    _Example_
    \code
    int ret = wolfSSL_X509_NAME_copy(from, to);
    \endcode

    \sa wolfSSL_X509_NAME_dup
*/
int wolfSSL_X509_NAME_copy(WOLFSSL_X509_NAME* from, WOLFSSL_X509_NAME* to);

/*!
    \ingroup Setup

    \brief Controls SSL settings.

    \return long Result value

    \param ssl SSL object
    \param cmd Command
    \param opt Option
    \param pt Pointer

    _Example_
    \code
    long ret = wolfSSL_ctrl(ssl, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, NULL);
    \endcode

    \sa wolfSSL_CTX_ctrl
*/
long wolfSSL_ctrl(WOLFSSL* ssl, int cmd, long opt, void* pt);

/*!
    \ingroup CertsKeys

    \brief Gets extension data by NID.

    \return void* Extension data
    \return NULL if not found

    \param x509 X509 certificate
    \param nid NID
    \param c Critical flag pointer
    \param idx Index pointer

    _Example_
    \code
    void* data = wolfSSL_X509_get_ext_d2i(x509, NID_subject_alt_name,
                                           NULL, NULL);
    \endcode

    \sa wolfSSL_X509_get_ext
*/
void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509, int nid,
                                int* c, int* idx);

/*!
    \ingroup CertsKeys

    \brief Gets extension flags.

    \return unsigned int Extension flags

    \param x509 X509 certificate

    _Example_
    \code
    unsigned int flags = wolfSSL_X509_get_extension_flags(x509);
    \endcode

    \sa wolfSSL_X509_get_key_usage
*/
unsigned int wolfSSL_X509_get_extension_flags(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets key usage.

    \return unsigned int Key usage flags

    \param x509 X509 certificate

    _Example_
    \code
    unsigned int usage = wolfSSL_X509_get_key_usage(x509);
    \endcode

    \sa wolfSSL_X509_get_extended_key_usage
*/
unsigned int wolfSSL_X509_get_key_usage(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets extended key usage.

    \return unsigned int Extended key usage flags

    \param x509 X509 certificate

    _Example_
    \code
    unsigned int usage = wolfSSL_X509_get_extended_key_usage(x509);
    \endcode

    \sa wolfSSL_X509_get_key_usage
*/
unsigned int wolfSSL_X509_get_extended_key_usage(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets extension count.

    \return int Extension count

    \param passedCert X509 certificate

    _Example_
    \code
    int count = wolfSSL_X509_get_ext_count(x509);
    \endcode

    \sa wolfSSL_X509_get_ext
*/
int wolfSSL_X509_get_ext_count(const WOLFSSL_X509* passedCert);

/*!
    \ingroup CertsKeys

    \brief Adds extension to X509.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x X509 certificate
    \param ex Extension
    \param loc Location

    _Example_
    \code
    int ret = wolfSSL_X509_add_ext(x509, ext, -1);
    \endcode

    \sa wolfSSL_X509_get_ext
*/
int wolfSSL_X509_add_ext(WOLFSSL_X509 *x, WOLFSSL_X509_EXTENSION *ex,
                         int loc);

/*!
    \ingroup CertsKeys

    \brief Sets X509V3 context.

    \return none

    \param ctx Context
    \param issuer Issuer certificate
    \param subject Subject certificate
    \param req Request
    \param crl CRL
    \param flag Flags

    _Example_
    \code
    wolfSSL_X509V3_set_ctx(&ctx, issuer, subject, NULL, NULL, 0);
    \endcode

    \sa wolfSSL_X509V3_set_ctx_nodb
*/
void wolfSSL_X509V3_set_ctx(WOLFSSL_X509V3_CTX* ctx,
                             WOLFSSL_X509* issuer, WOLFSSL_X509* subject,
                             WOLFSSL_X509* req, WOLFSSL_X509_CRL* crl,
                             int flag);

/*!
    \ingroup CertsKeys

    \brief Sets X509V3 context no database.

    \return none

    \param ctx Context

    _Example_
    \code
    wolfSSL_X509V3_set_ctx_nodb(&ctx);
    \endcode

    \sa wolfSSL_X509V3_set_ctx
*/
void wolfSSL_X509V3_set_ctx_nodb(WOLFSSL_X509V3_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Gets public key digest.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 X509 certificate
    \param digest Digest type
    \param buf Output buffer
    \param len Length pointer

    _Example_
    \code
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len;
    int ret = wolfSSL_X509_pubkey_digest(x509, wolfSSL_EVP_sha256(),
                                          buf, &len);
    \endcode

    \sa wolfSSL_X509_digest
*/
int wolfSSL_X509_pubkey_digest(const WOLFSSL_X509 *x509,
                                const WOLFSSL_EVP_MD *digest,
                                unsigned char* buf, unsigned int* len);

/*!
    \ingroup CertsKeys

    \brief Uses private key ASN1 in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param pri Key type
    \param ctx SSL context
    \param der DER buffer
    \param derSz DER size

    _Example_
    \code
    int ret = wolfSSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, der,
                                               derSz);
    \endcode

    \sa wolfSSL_use_PrivateKey_ASN1
*/
int wolfSSL_CTX_use_PrivateKey_ASN1(int pri, WOLFSSL_CTX* ctx,
                                     unsigned char* der, long derSz);

/*!
    \ingroup CertsKeys

    \brief Compares two X509 certificates.

    \return 0 if equal
    \return non-zero if different

    \param a First certificate
    \param b Second certificate

    _Example_
    \code
    int cmp = wolfSSL_X509_cmp(cert1, cert2);
    \endcode

    \sa wolfSSL_X509_NAME_cmp
*/
int wolfSSL_X509_cmp(const WOLFSSL_X509* a, const WOLFSSL_X509* b);

/*!
    \ingroup CertsKeys

    \brief Gets extension by location.

    \return WOLFSSL_X509_EXTENSION* Extension
    \return NULL if not found

    \param x X509 certificate
    \param loc Location

    _Example_
    \code
    WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_get_ext(x509, 0);
    \endcode

    \sa wolfSSL_X509_get_ext_count
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_get_ext(const WOLFSSL_X509* x,
                                              int loc);

/*!
    \ingroup CertsKeys

    \brief Gets extension by object.

    \return int Extension index
    \return -1 if not found

    \param x X509 certificate
    \param obj ASN1 object
    \param lastpos Last position

    _Example_
    \code
    int idx = wolfSSL_X509_get_ext_by_OBJ(x509, obj, -1);
    \endcode

    \sa wolfSSL_X509_get_ext
*/
int wolfSSL_X509_get_ext_by_OBJ(const WOLFSSL_X509 *x,
                                 const WOLFSSL_ASN1_OBJECT *obj,
                                 int lastpos);

/*!
    \ingroup CertsKeys

    \brief Sets X509 in object.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param a X509 object
    \param obj X509 certificate

    _Example_
    \code
    int ret = wolfSSL_X509_OBJECT_set1_X509(obj, x509);
    \endcode

    \sa wolfSSL_X509_OBJECT_set1_X509_CRL
*/
int wolfSSL_X509_OBJECT_set1_X509(WOLFSSL_X509_OBJECT *a,
                                   WOLFSSL_X509 *obj);

/*!
    \ingroup CertsKeys

    \brief Sets X509 CRL in object.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param a X509 object
    \param obj X509 CRL

    _Example_
    \code
    int ret = wolfSSL_X509_OBJECT_set1_X509_CRL(obj, crl);
    \endcode

    \sa wolfSSL_X509_OBJECT_set1_X509
*/
int wolfSSL_X509_OBJECT_set1_X509_CRL(WOLFSSL_X509_OBJECT *a,
                                       WOLFSSL_X509_CRL *obj);

/*!
    \ingroup CertsKeys

    \brief Sets extension in X509.

    \return WOLFSSL_X509_EXTENSION* Extension
    \return NULL on failure

    \param x X509 certificate
    \param loc Location

    _Example_
    \code
    WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_set_ext(x509, 0);
    \endcode

    \sa wolfSSL_X509_get_ext
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_set_ext(WOLFSSL_X509* x, int loc);

/*!
    \ingroup CertsKeys

    \brief Gets extension critical flag.

    \return 1 if critical
    \return 0 if not critical

    \param ex Extension

    _Example_
    \code
    int crit = wolfSSL_X509_EXTENSION_get_critical(ext);
    \endcode

    \sa wolfSSL_X509_EXTENSION_set_critical
*/
int wolfSSL_X509_EXTENSION_get_critical(const WOLFSSL_X509_EXTENSION* ex);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 extension.

    \return WOLFSSL_X509_EXTENSION* Extension
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_EXTENSION* ext = wolfSSL_X509_EXTENSION_new();
    \endcode

    \sa wolfSSL_X509_EXTENSION_free
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_new(void);

/*!
    \ingroup CertsKeys

    \brief Creates extension by object.

    \return WOLFSSL_X509_EXTENSION* Extension
    \return NULL on failure

    \param ex Extension pointer
    \param obj ASN1 object
    \param crit Critical flag
    \param data ASN1 string data

    _Example_
    \code
    WOLFSSL_X509_EXTENSION* ext;
    ext = wolfSSL_X509_EXTENSION_create_by_OBJ(NULL, obj, 0, data);
    \endcode

    \sa wolfSSL_X509_EXTENSION_new
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_create_by_OBJ(
                                        WOLFSSL_X509_EXTENSION* ex,
                                        WOLFSSL_ASN1_OBJECT *obj, int crit,
                                        WOLFSSL_ASN1_STRING *data);

/*!
    \ingroup CertsKeys

    \brief Duplicates X509 extension.

    \return WOLFSSL_X509_EXTENSION* Duplicated extension
    \return NULL on failure

    \param src Source extension

    _Example_
    \code
    WOLFSSL_X509_EXTENSION* dup = wolfSSL_X509_EXTENSION_dup(ext);
    \endcode

    \sa wolfSSL_X509_EXTENSION_new
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_dup(
                                        WOLFSSL_X509_EXTENSION* src);

/*!
    \ingroup CertsKeys

    \brief Pushes extension to stack.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param sk Stack
    \param ext Extension

    _Example_
    \code
    int ret = wolfSSL_sk_X509_EXTENSION_push(sk, ext);
    \endcode

    \sa wolfSSL_sk_new_x509_ext
*/
int wolfSSL_sk_X509_EXTENSION_push(WOLFSSL_STACK* sk,
                                    WOLFSSL_X509_EXTENSION* ext);

/*!
    \ingroup CertsKeys

    \brief Frees X509 extension.

    \return none

    \param ext_to_free Extension to free

    _Example_
    \code
    wolfSSL_X509_EXTENSION_free(ext);
    \endcode

    \sa wolfSSL_X509_EXTENSION_new
*/
void wolfSSL_X509_EXTENSION_free(WOLFSSL_X509_EXTENSION* ext_to_free);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 extension stack.

    \return WOLFSSL_STACK* Stack
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_STACK* sk = wolfSSL_sk_new_x509_ext();
    \endcode

    \sa wolfSSL_sk_X509_EXTENSION_push
*/
WOLFSSL_STACK* wolfSSL_sk_new_x509_ext(void);

/*!
    \ingroup CertsKeys

    \brief Gets extension object.

    \return WOLFSSL_ASN1_OBJECT* Object
    \return NULL on failure

    \param ext Extension

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_X509_EXTENSION_get_object(ext);
    \endcode

    \sa wolfSSL_X509_EXTENSION_set_object
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_X509_EXTENSION_get_object(
                                        WOLFSSL_X509_EXTENSION* ext);

/*!
    \ingroup CertsKeys

    \brief Sets extension object.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ext Extension
    \param obj ASN1 object

    _Example_
    \code
    int ret = wolfSSL_X509_EXTENSION_set_object(ext, obj);
    \endcode

    \sa wolfSSL_X509_EXTENSION_get_object
*/
int wolfSSL_X509_EXTENSION_set_object(WOLFSSL_X509_EXTENSION* ext,
                                       const WOLFSSL_ASN1_OBJECT* obj);

/*!
    \ingroup CertsKeys

    \brief Gets extension data.

    \return WOLFSSL_ASN1_STRING* Data
    \return NULL on failure

    \param ext Extension

    _Example_
    \code
    WOLFSSL_ASN1_STRING* data = wolfSSL_X509_EXTENSION_get_data(ext);
    \endcode

    \sa wolfSSL_X509_EXTENSION_set_data
*/
WOLFSSL_ASN1_STRING* wolfSSL_X509_EXTENSION_get_data(
                                        WOLFSSL_X509_EXTENSION* ext);

/*!
    \ingroup CertsKeys

    \brief Sets extension data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ext Extension
    \param data ASN1 string data

    _Example_
    \code
    int ret = wolfSSL_X509_EXTENSION_set_data(ext, data);
    \endcode

    \sa wolfSSL_X509_EXTENSION_get_data
*/
int wolfSSL_X509_EXTENSION_set_data(WOLFSSL_X509_EXTENSION* ext,
                                     WOLFSSL_ASN1_STRING* data);

/*!
    \ingroup CertsKeys

    \brief Writes X509 to BIO in DER format.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO object
    \param x509 X509 certificate

    _Example_
    \code
    int ret = wolfSSL_i2d_X509_bio(bio, x509);
    \endcode

    \sa wolfSSL_d2i_X509_bio
*/
int wolfSSL_i2d_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Writes X509 request to BIO in DER format.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bio BIO object
    \param x509 X509 request

    _Example_
    \code
    int ret = wolfSSL_i2d_X509_REQ_bio(bio, req);
    \endcode

    \sa wolfSSL_d2i_X509_REQ_bio
*/
int wolfSSL_i2d_X509_REQ_bio(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Reads X509 from file in DER format.

    \return WOLFSSL_X509* Certificate
    \return NULL on failure

    \param fp File pointer
    \param x509 X509 pointer

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_d2i_X509_fp(fp, NULL);
    \endcode

    \sa wolfSSL_d2i_X509_bio
*/
WOLFSSL_X509* wolfSSL_d2i_X509_fp(XFILE fp, WOLFSSL_X509** x509);

/*!
    \ingroup CertsKeys

    \brief Gets certificates from store context.

    \return WOLFSSL_STACK* Certificate stack
    \return NULL on failure

    \param s Store context

    _Example_
    \code
    WOLFSSL_STACK* certs = wolfSSL_X509_STORE_GetCerts(ctx);
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_chain
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_GetCerts(WOLFSSL_X509_STORE_CTX* s);

/*!
    \ingroup CertsKeys

    \brief Reads X509 from BIO in DER format.

    \return WOLFSSL_X509* Certificate
    \return NULL on failure

    \param bio BIO object
    \param x509 X509 pointer

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_d2i_X509_bio(bio, NULL);
    \endcode

    \sa wolfSSL_i2d_X509_bio
*/
WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509** x509);

/*!
    \ingroup CertsKeys

    \brief Reads X509 request from BIO in DER format.

    \return WOLFSSL_X509* Request
    \return NULL on failure

    \param bio BIO object
    \param x509 X509 pointer

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_d2i_X509_REQ_bio(bio, NULL);
    \endcode

    \sa wolfSSL_i2d_X509_REQ_bio
*/
WOLFSSL_X509* wolfSSL_d2i_X509_REQ_bio(WOLFSSL_BIO* bio,
                                        WOLFSSL_X509** x509);

/*!
    \ingroup CertsKeys

    \brief Reads X509 request from file in DER format.

    \return WOLFSSL_X509* Request
    \return NULL on failure

    \param fp File pointer
    \param req X509 pointer

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_d2i_X509_REQ_fp(fp, NULL);
    \endcode

    \sa wolfSSL_d2i_X509_fp
*/
WOLFSSL_X509* wolfSSL_d2i_X509_REQ_fp(XFILE fp, WOLFSSL_X509 **req);

/*!
    \ingroup CertsKeys

    \brief Sets verify certificate store in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param str X509 store

    _Example_
    \code
    int ret = wolfSSL_CTX_set1_verify_cert_store(ctx, store);
    \endcode

    \sa wolfSSL_set1_verify_cert_store
*/
int wolfSSL_CTX_set1_verify_cert_store(WOLFSSL_CTX* ctx,
                                        WOLFSSL_X509_STORE* str);

/*!
    \ingroup CertsKeys

    \brief Sets verify certificate store without incrementing reference.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param str X509 store

    _Example_
    \code
    int ret = wolfSSL_set0_verify_cert_store(ssl, store);
    \endcode

    \sa wolfSSL_set1_verify_cert_store
*/
int wolfSSL_set0_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str);

/*!
    \ingroup CertsKeys

    \brief Sets verify certificate store.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param str X509 store

    _Example_
    \code
    int ret = wolfSSL_set1_verify_cert_store(ssl, store);
    \endcode

    \sa wolfSSL_CTX_set1_verify_cert_store
*/
int wolfSSL_set1_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str);

/*!
    \ingroup CertsKeys

    \brief Gets certificate store from context.

    \return WOLFSSL_X509_STORE* Store
    \return NULL on failure

    \param ctx SSL context

    _Example_
    \code
    WOLFSSL_X509_STORE* store = wolfSSL_CTX_get_cert_store(ctx);
    \endcode

    \sa wolfSSL_CTX_set_cert_store
*/
WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(const WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief Gets write pending bytes in BIO.

    \return size_t Pending bytes

    \param bio BIO object

    _Example_
    \code
    size_t pending = wolfSSL_BIO_wpending(bio);
    \endcode

    \sa wolfSSL_BIO_pending
*/
size_t wolfSSL_BIO_wpending(const WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Checks if BIO supports pending.

    \return 1 if supported
    \return 0 if not supported

    \param bio BIO object

    _Example_
    \code
    int ret = wolfSSL_BIO_supports_pending(bio);
    \endcode

    \sa wolfSSL_BIO_pending
*/
int wolfSSL_BIO_supports_pending(const WOLFSSL_BIO *bio);

/*!
    \ingroup CertsKeys

    \brief Gets peer temporary key.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param pkey EVP_PKEY pointer

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey;
    int ret = wolfSSL_get_peer_tmp_key(ssl, &pkey);
    \endcode

    \sa wolfSSL_CTX_get_ephemeral_key
*/
int wolfSSL_get_peer_tmp_key(const WOLFSSL* ssl, WOLFSSL_EVP_PKEY** pkey);

/*!
    \ingroup Setup

    \brief Sets minimum protocol version in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param version Protocol version

    _Example_
    \code
    int ret = wolfSSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    \endcode

    \sa wolfSSL_CTX_set_max_proto_version
*/
int wolfSSL_CTX_set_min_proto_version(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup Setup

    \brief Sets maximum protocol version in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param version Protocol version

    _Example_
    \code
    int ret = wolfSSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    \endcode

    \sa wolfSSL_CTX_set_min_proto_version
*/
int wolfSSL_CTX_set_max_proto_version(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup Setup

    \brief Sets minimum protocol version.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param version Protocol version

    _Example_
    \code
    int ret = wolfSSL_set_min_proto_version(ssl, TLS1_2_VERSION);
    \endcode

    \sa wolfSSL_set_max_proto_version
*/
int wolfSSL_set_min_proto_version(WOLFSSL* ssl, int version);

/*!
    \ingroup Setup

    \brief Sets maximum protocol version.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param version Protocol version

    _Example_
    \code
    int ret = wolfSSL_set_max_proto_version(ssl, TLS1_3_VERSION);
    \endcode

    \sa wolfSSL_set_min_proto_version
*/
int wolfSSL_set_max_proto_version(WOLFSSL* ssl, int version);

/*!
    \ingroup Setup

    \brief Gets minimum protocol version from context.

    \return int Protocol version

    \param ctx SSL context

    _Example_
    \code
    int version = wolfSSL_CTX_get_min_proto_version(ctx);
    \endcode

    \sa wolfSSL_CTX_get_max_proto_version
*/
int wolfSSL_CTX_get_min_proto_version(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Gets maximum protocol version from context.

    \return int Protocol version

    \param ctx SSL context

    _Example_
    \code
    int version = wolfSSL_CTX_get_max_proto_version(ctx);
    \endcode

    \sa wolfSSL_CTX_get_min_proto_version
*/
int wolfSSL_CTX_get_max_proto_version(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Uses private key in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param pkey EVP_PKEY

    _Example_
    \code
    int ret = wolfSSL_CTX_use_PrivateKey(ctx, pkey);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_file
*/
int wolfSSL_CTX_use_PrivateKey(WOLFSSL_CTX *ctx, WOLFSSL_EVP_PKEY *pkey);

/*!
    \ingroup CertsKeys

    \brief Reads X509 request from PEM file.

    \return WOLFSSL_X509* Request
    \return NULL on failure

    \param fp File pointer
    \param x X509 pointer
    \param cb Password callback
    \param u User data

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_PEM_read_X509_REQ(fp, NULL, NULL, NULL);
    \endcode

    \sa wolfSSL_PEM_read_X509
*/
WOLFSSL_X509* wolfSSL_PEM_read_X509_REQ(XFILE fp, WOLFSSL_X509** x,
                                         wc_pem_password_cb* cb, void* u);

/*!
    \ingroup CertsKeys

    \brief Gets EVP cipher info from PEM header.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param header PEM header
    \param cipher Encrypted info

    _Example_
    \code
    EncryptedInfo cipher;
    int ret = wolfSSL_PEM_get_EVP_CIPHER_INFO(header, &cipher);
    \endcode

    \sa wolfSSL_PEM_do_header
*/
int wolfSSL_PEM_get_EVP_CIPHER_INFO(const char* header,
                                     EncryptedInfo* cipher);

/*!
    \ingroup CertsKeys

    \brief Processes PEM header.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param cipher Encrypted info
    \param data Data buffer
    \param len Length pointer
    \param callback Password callback
    \param ctx User context

    _Example_
    \code
    int ret = wolfSSL_PEM_do_header(&cipher, data, &len, NULL, NULL);
    \endcode

    \sa wolfSSL_PEM_get_EVP_CIPHER_INFO
*/
int wolfSSL_PEM_do_header(EncryptedInfo* cipher, unsigned char* data,
                          long* len, wc_pem_password_cb* callback,
                          void* ctx);

/*!
    \ingroup openSSL

    \brief Sets X509 name entry.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ne Name entry

    _Example_
    \code
    int ret = wolfSSL_X509_NAME_ENTRY_set(entry);
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_new
*/
int wolfSSL_X509_NAME_ENTRY_set(const WOLFSSL_X509_NAME_ENTRY *ne);

/*!
    \ingroup openSSL

    \brief Frees X509 name entry.

    \return none

    \param ne Name entry

    _Example_
    \code
    wolfSSL_X509_NAME_ENTRY_free(entry);
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_new
*/
void wolfSSL_X509_NAME_ENTRY_free(WOLFSSL_X509_NAME_ENTRY* ne);

/*!
    \ingroup openSSL

    \brief Creates new X509 name entry.

    \return WOLFSSL_X509_NAME_ENTRY* Entry
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_NAME_ENTRY* entry = wolfSSL_X509_NAME_ENTRY_new();
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_free
*/
WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_ENTRY_new(void);

/*!
    \ingroup openSSL

    \brief Frees X509 name.

    \return none

    \param name X509 name

    _Example_
    \code
    wolfSSL_X509_NAME_free(name);
    \endcode

    \sa wolfSSL_X509_NAME_new
*/
void wolfSSL_X509_NAME_free(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys

    \brief Uses certificate in context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param x X509 certificate

    _Example_
    \code
    int ret = wolfSSL_CTX_use_certificate(ctx, x509);
    \endcode

    \sa wolfSSL_CTX_use_certificate_file
*/
int wolfSSL_CTX_use_certificate(WOLFSSL_CTX* ctx, WOLFSSL_X509* x);

/*!
    \ingroup CertsKeys

    \brief Adds chain certificate without incrementing reference.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param x509 X509 certificate

    _Example_
    \code
    int ret = wolfSSL_CTX_add0_chain_cert(ctx, x509);
    \endcode

    \sa wolfSSL_CTX_add1_chain_cert
*/
int wolfSSL_CTX_add0_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Adds chain certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ctx SSL context
    \param x509 X509 certificate

    _Example_
    \code
    int ret = wolfSSL_CTX_add1_chain_cert(ctx, x509);
    \endcode

    \sa wolfSSL_CTX_add0_chain_cert
*/
int wolfSSL_CTX_add1_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Adds chain certificate without incrementing reference.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param x509 X509 certificate

    _Example_
    \code
    int ret = wolfSSL_add0_chain_cert(ssl, x509);
    \endcode

    \sa wolfSSL_add1_chain_cert
*/
int wolfSSL_add0_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Adds chain certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param x509 X509 certificate

    _Example_
    \code
    int ret = wolfSSL_add1_chain_cert(ssl, x509);
    \endcode

    \sa wolfSSL_add0_chain_cert
*/
int wolfSSL_add1_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup IO

    \brief Reads filename into BIO.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param b BIO object
    \param name Filename

    _Example_
    \code
    int ret = wolfSSL_BIO_read_filename(bio, "cert.pem");
    \endcode

    \sa wolfSSL_BIO_new_file
*/
int wolfSSL_BIO_read_filename(WOLFSSL_BIO *b, const char *name);

/*!
    \ingroup Setup

    \brief Sets verify depth.

    \return none

    \param ssl SSL object
    \param depth Depth

    _Example_
    \code
    wolfSSL_set_verify_depth(ssl, 5);
    \endcode

    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_set_verify_depth(WOLFSSL *ssl, int depth);

/*!
    \ingroup Setup

    \brief Sets application data.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param ssl SSL object
    \param arg Application data

    _Example_
    \code
    int ret = wolfSSL_set_app_data(ssl, myData);
    \endcode

    \sa wolfSSL_get_app_data
*/
int wolfSSL_set_app_data(WOLFSSL *ssl, void *arg);

/*!
    \ingroup openSSL

    \brief Gets object from name entry.

    \return WOLFSSL_ASN1_OBJECT* Object
    \return NULL on failure

    \param ne Name entry

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_X509_NAME_ENTRY_get_object(entry);
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_get_data
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_X509_NAME_ENTRY_get_object(
                                        WOLFSSL_X509_NAME_ENTRY *ne);

/*!
    \ingroup CertsKeys

    \brief Checks if private key matches certificate.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x509 X509 certificate
    \param pkey EVP_PKEY

    _Example_
    \code
    int ret = wolfSSL_X509_check_private_key(x509, pkey);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey
*/
int wolfSSL_X509_check_private_key(WOLFSSL_X509* x509,
                                    WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief Checks if certificate is CA.

    \return 1 if CA
    \return 0 if not CA

    \param x509 X509 certificate

    _Example_
    \code
    int ret = wolfSSL_X509_check_ca(x509);
    \endcode

    \sa wolfSSL_X509_check_private_key
*/
int wolfSSL_X509_check_ca(WOLFSSL_X509 *x509);

/*!
    \ingroup IO

    \brief Creates new BIO from file.

    \return WOLFSSL_BIO* BIO object
    \return NULL on failure

    \param filename Filename
    \param mode File mode

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_file("cert.pem", "r");
    \endcode

    \sa wolfSSL_BIO_new_fp
*/
WOLFSSL_BIO* wolfSSL_BIO_new_file(const char *filename, const char *mode);

/*!
    \ingroup IO

    \brief Creates new BIO from file pointer.

    \return WOLFSSL_BIO* BIO object
    \return NULL on failure

    \param fp File pointer
    \param c Close flag

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_fp(fp, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_new_file
*/
WOLFSSL_BIO* wolfSSL_BIO_new_fp(XFILE fp, int c);

/*!
    \ingroup CertsKeys

    \brief Writes X509 request to BIO in PEM format.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bp BIO object
    \param x X509 request

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_X509_REQ(bio, req);
    \endcode

    \sa wolfSSL_PEM_write_bio_X509
*/
int wolfSSL_PEM_write_bio_X509_REQ(WOLFSSL_BIO *bp, WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys

    \brief Writes X509 to BIO in PEM format with auxiliary.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bp BIO object
    \param x X509 certificate

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_X509_AUX(bio, x509);
    \endcode

    \sa wolfSSL_PEM_write_bio_X509
*/
int wolfSSL_PEM_write_bio_X509_AUX(WOLFSSL_BIO *bp, WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys

    \brief Writes X509 to BIO in PEM format.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param bp BIO object
    \param x X509 certificate

    _Example_
    \code
    int ret = wolfSSL_PEM_write_bio_X509(bio, x509);
    \endcode

    \sa wolfSSL_PEM_read_bio_X509
*/
int wolfSSL_PEM_write_bio_X509(WOLFSSL_BIO *bp, WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys

    \brief Converts X509 request to DER format.

    \return int Length written
    \return negative on failure

    \param req X509 request
    \param out Output buffer pointer

    _Example_
    \code
    unsigned char* out = NULL;
    int len = wolfSSL_i2d_X509_REQ(req, &out);
    \endcode

    \sa wolfSSL_d2i_X509_REQ
*/
int wolfSSL_i2d_X509_REQ(WOLFSSL_X509* req, unsigned char** out);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 request.

    \return WOLFSSL_X509* Request
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509* req = wolfSSL_X509_REQ_new();
    \endcode

    \sa wolfSSL_X509_REQ_free
*/
WOLFSSL_X509* wolfSSL_X509_REQ_new(void);

/*!
    \ingroup CertsKeys

    \brief Frees X509 request.

    \return none

    \param req X509 request

    _Example_
    \code
    wolfSSL_X509_REQ_free(req);
    \endcode

    \sa wolfSSL_X509_REQ_new
*/
void wolfSSL_X509_REQ_free(WOLFSSL_X509* req);

/*!
    \ingroup CertsKeys

    \brief Gets X509 request version.

    \return long Version number

    \param req X509 request

    _Example_
    \code
    long version = wolfSSL_X509_REQ_get_version(req);
    \endcode

    \sa wolfSSL_X509_REQ_set_version
*/
long wolfSSL_X509_REQ_get_version(const WOLFSSL_X509 *req);

/*!
    \ingroup CertsKeys

    \brief Sets X509 request version.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param x X509 request
    \param version Version number

    _Example_
    \code
    int ret = wolfSSL_X509_REQ_set_version(req, 0);
    \endcode

    \sa wolfSSL_X509_REQ_get_version
*/
int wolfSSL_X509_REQ_set_version(WOLFSSL_X509 *x, long version);

/*!
    \ingroup CertsKeys

    \brief Signs X509 request.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param req X509 request
    \param pkey EVP_PKEY
    \param md EVP_MD

    _Example_
    \code
    int ret = wolfSSL_X509_REQ_sign(req, pkey, wolfSSL_EVP_sha256());
    \endcode

    \sa wolfSSL_X509_REQ_sign_ctx
*/
int wolfSSL_X509_REQ_sign(WOLFSSL_X509 *req, WOLFSSL_EVP_PKEY *pkey,
                           const WOLFSSL_EVP_MD *md);

/*!
    \ingroup CertsKeys

    \brief Signs X509 request with context.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param req X509 request
    \param md_ctx EVP_MD_CTX

    _Example_
    \code
    int ret = wolfSSL_X509_REQ_sign_ctx(req, md_ctx);
    \endcode

    \sa wolfSSL_X509_REQ_sign
*/
int wolfSSL_X509_REQ_sign_ctx(WOLFSSL_X509 *req,
                               WOLFSSL_EVP_MD_CTX* md_ctx);

/*!
    \ingroup CertsKeys

    \brief Sets subject name in X509 request.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param req X509 request
    \param name X509 name

    _Example_
    \code
    int ret = wolfSSL_X509_REQ_set_subject_name(req, name);
    \endcode

    \sa wolfSSL_X509_REQ_get_subject_name
*/
int wolfSSL_X509_REQ_set_subject_name(WOLFSSL_X509 *req,
                                       WOLFSSL_X509_NAME *name);

/*!
    \ingroup CertsKeys

    \brief Sets public key in X509 request.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param req X509 request
    \param pkey EVP_PKEY

    _Example_
    \code
    int ret = wolfSSL_X509_REQ_set_pubkey(req, pkey);
    \endcode

    \sa wolfSSL_X509_REQ_get_pubkey
*/
int wolfSSL_X509_REQ_set_pubkey(WOLFSSL_X509 *req, WOLFSSL_EVP_PKEY *pkey);

/*!
    \ingroup CertsKeys

    \brief Adds attribute to X509 request by NID.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param req X509 request
    \param nid NID
    \param type Value type
    \param bytes Value bytes
    \param len Value length

    _Example_
    \code
    int ret = wolfSSL_X509_REQ_add1_attr_by_NID(req, NID_pkcs9_emailAddress,
                                                  MBSTRING_UTF8,
                                                  (unsigned char*)"test@test.com",
                                                  13);
    \endcode

    \sa wolfSSL_X509_REQ_add1_attr_by_txt
*/
int wolfSSL_X509_REQ_add1_attr_by_NID(WOLFSSL_X509 *req, int nid, int type,
                                       const unsigned char *bytes, int len);

/*!
    \ingroup CertsKeys

    \brief Adds attribute to X509 request by text.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param req X509 request
    \param attrname Attribute name
    \param type Value type
    \param bytes Value bytes
    \param len Value length

    _Example_
    \code
    int ret = wolfSSL_X509_REQ_add1_attr_by_txt(req, "emailAddress",
                                                  MBSTRING_UTF8,
                                                  (unsigned char*)"test@test.com",
                                                  13);
    \endcode

    \sa wolfSSL_X509_REQ_add1_attr_by_NID
*/
int wolfSSL_X509_REQ_add1_attr_by_txt(WOLFSSL_X509 *req,
                                       const char *attrname, int type,
                                       const unsigned char *bytes, int len);

/*!
    \ingroup CertsKeys

    \brief Gets attribute count from X509 request.

    \return int Attribute count

    \param req X509 request

    _Example_
    \code
    int count = wolfSSL_X509_REQ_get_attr_count(req);
    \endcode

    \sa wolfSSL_X509_REQ_get_attr_by_NID
*/
int wolfSSL_X509_REQ_get_attr_count(const WOLFSSL_X509 *req);

/*!
    \ingroup CertsKeys

    \brief Gets attribute by NID from X509 request.

    \return int Attribute index
    \return -1 if not found

    \param req X509 request
    \param nid NID
    \param lastpos Last position

    _Example_
    \code
    int idx = wolfSSL_X509_REQ_get_attr_by_NID(req, NID_pkcs9_emailAddress,
                                                 -1);
    \endcode

    \sa wolfSSL_X509_REQ_get_attr_count
*/
int wolfSSL_X509_REQ_get_attr_by_NID(const WOLFSSL_X509 *req, int nid,
                                      int lastpos);

/*!
    \ingroup CertsKeys

    \brief Creates new X509 attribute.

    \return WOLFSSL_X509_ATTRIBUTE* Attribute
    \return NULL on failure

    _Example_
    \code
    WOLFSSL_X509_ATTRIBUTE* attr = wolfSSL_X509_ATTRIBUTE_new();
    \endcode

    \sa wolfSSL_X509_ATTRIBUTE_free
*/
WOLFSSL_X509_ATTRIBUTE* wolfSSL_X509_ATTRIBUTE_new(void);

/*!
    \ingroup CertsKeys

    \brief Frees X509 attribute.

    \return none

    \param attr Attribute

    _Example_
    \code
    wolfSSL_X509_ATTRIBUTE_free(attr);
    \endcode

    \sa wolfSSL_X509_ATTRIBUTE_new
*/
void wolfSSL_X509_ATTRIBUTE_free(WOLFSSL_X509_ATTRIBUTE* attr);

/*!
    \ingroup Setup

    \brief Sets memory functions.

    \return WOLFSSL_SUCCESS on success
    \return WOLFSSL_FAILURE on failure

    \param m Malloc callback
    \param r Realloc callback
    \param f Free callback

    _Example_
    \code
    int ret = wolfSSL_CRYPTO_set_mem_functions(myMalloc, myRealloc, myFree);
    \endcode

    \sa wolfSSL_SetAllocators
*/
int wolfSSL_CRYPTO_set_mem_functions(wolfSSL_OSSL_Malloc_cb  m,
                                      wolfSSL_OSSL_Realloc_cb r,
                                      wolfSSL_OSSL_Free_cb    f);

/*!
    \ingroup Setup

    \brief Constant time memory comparison.

    \return 0 if equal
    \return non-zero if different

    \param a First buffer
    \param b Second buffer
    \param size Size

    _Example_
    \code
    int ret = wolfSSL_CRYPTO_memcmp(buf1, buf2, 32);
    \endcode

    \sa ConstantCompare
*/
int wolfSSL_CRYPTO_memcmp(const void *a, const void *b, size_t size);
