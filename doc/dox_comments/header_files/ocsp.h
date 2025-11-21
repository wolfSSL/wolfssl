/*!
    \ingroup OCSP

    \brief Allocates and initialises an OCSP context.

    This function allocates and initialises a WOLFSSL_OCSP structure for use
    with OCSP operations.

    \param cm   Pointer to the certificate manager.

    \return Pointer to allocated WOLFSSL_OCSP on success
    \return NULL on failure

    \sa wc_FreeOCSP
*/
WOLFSSL_OCSP* wc_NewOCSP(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup OCSP

    \brief Frees resources associated with an OCSP context.

    This function releases any resources associated with a WOLFSSL_OCSP structure.

    \param ocsp Pointer to the WOLFSSL_OCSP structure to free.

    \return void

    \sa wc_NewOCSP
*/
void wc_FreeOCSP(WOLFSSL_OCSP* ocsp);

/*!
    \ingroup OCSP

    \brief Checks the OCSP response for a given certificate.

    This function verifies an OCSP response for a specific certificate.

    \param ocsp       Pointer to the WOLFSSL_OCSP structure.
    \param cert       Pointer to the decoded certificate.
    \param response   Pointer to the OCSP response buffer.
    \param responseSz Size of the OCSP response buffer.
    \param heap       Optional heap pointer.

    \return 0 on success
    \return <0 on failure
*/
int wc_CheckCertOcspResponse(WOLFSSL_OCSP *ocsp, DecodedCert *cert, byte *response, int responseSz, void* heap);

/*!
    \ingroup OCSP
    \brief Finds OCSP status in basic response.

    \return 1 on success
    \return 0 or negative on error

    \param bs OCSP basic response
    \param id Certificate ID
    \param status Pointer to store status
    \param reason Pointer to store revocation reason
    \param revtime Pointer to store revocation time
    \param thisupd Pointer to store this update time
    \param nextupd Pointer to store next update time

    _Example_
    \code
    int status, reason;
    WOLFSSL_ASN1_TIME *revtime, *thisupd, *nextupd;
    int ret = wolfSSL_OCSP_resp_find_status(bs, id, &status, &reason,
                                            &revtime, &thisupd, &nextupd);
    \endcode

    \sa wolfSSL_OCSP_check_validity
*/
int wolfSSL_OCSP_resp_find_status(WOLFSSL_OCSP_BASICRESP *bs,
                                  WOLFSSL_OCSP_CERTID *id, int *status,
                                  int *reason, WOLFSSL_ASN1_TIME **revtime,
                                  WOLFSSL_ASN1_TIME **thisupd,
                                  WOLFSSL_ASN1_TIME **nextupd);

/*!
    \ingroup OCSP
    \brief Checks OCSP response validity period.

    \return 1 if valid
    \return 0 if invalid

    \param thisupd This update time
    \param nextupd Next update time
    \param sec Seconds tolerance
    \param maxsec Maximum age in seconds

    _Example_
    \code
    int ret = wolfSSL_OCSP_check_validity(thisupd, nextupd, 300, 86400);
    \endcode

    \sa wolfSSL_OCSP_resp_find_status
*/
int wolfSSL_OCSP_check_validity(WOLFSSL_ASN1_TIME* thisupd,
                                WOLFSSL_ASN1_TIME* nextupd, long sec,
                                long maxsec);

/*!
    \ingroup OCSP
    \brief Frees OCSP certificate ID.

    \return none No returns

    \param certId Certificate ID to free

    _Example_
    \code
    wolfSSL_OCSP_CERTID_free(certId);
    \endcode

    \sa wolfSSL_OCSP_cert_to_id
*/
void wolfSSL_OCSP_CERTID_free(WOLFSSL_OCSP_CERTID* certId);

/*!
    \ingroup OCSP
    \brief Creates OCSP certificate ID from certificates.

    \return Pointer to certificate ID on success
    \return NULL on error

    \param dgst Digest algorithm
    \param subject Subject certificate
    \param issuer Issuer certificate

    _Example_
    \code
    WOLFSSL_OCSP_CERTID* id = wolfSSL_OCSP_cert_to_id(EVP_sha1(), cert,
                                                      issuer);
    \endcode

    \sa wolfSSL_OCSP_CERTID_free
*/
WOLFSSL_OCSP_CERTID* wolfSSL_OCSP_cert_to_id(const WOLFSSL_EVP_MD *dgst,
                                             const WOLFSSL_X509 *subject,
                                             const WOLFSSL_X509 *issuer);

/*!
    \ingroup OCSP
    \brief Frees OCSP basic response.

    \return none No returns

    \param basicResponse Basic response to free

    _Example_
    \code
    wolfSSL_OCSP_BASICRESP_free(basicResponse);
    \endcode

    \sa wolfSSL_OCSP_response_get1_basic
*/
void wolfSSL_OCSP_BASICRESP_free(WOLFSSL_OCSP_BASICRESP* basicResponse);

/*!
    \ingroup OCSP
    \brief Frees OCSP response.

    \return none No returns

    \param response Response to free

    _Example_
    \code
    wolfSSL_OCSP_RESPONSE_free(response);
    \endcode

    \sa wolfSSL_d2i_OCSP_RESPONSE
*/
void wolfSSL_OCSP_RESPONSE_free(OcspResponse* response);

/*!
    \ingroup OCSP
    \brief Decodes OCSP response from BIO.

    \return Pointer to OCSP response on success
    \return NULL on error

    \param bio BIO to read from
    \param response Pointer to response pointer

    _Example_
    \code
    OcspResponse* resp = wolfSSL_d2i_OCSP_RESPONSE_bio(bio, NULL);
    \endcode

    \sa wolfSSL_OCSP_RESPONSE_free
*/
OcspResponse* wolfSSL_d2i_OCSP_RESPONSE_bio(WOLFSSL_BIO* bio,
                                            OcspResponse** response);

/*!
    \ingroup OCSP
    \brief Decodes OCSP response from DER.

    \return Pointer to OCSP response on success
    \return NULL on error

    \param response Pointer to response pointer
    \param data Pointer to DER data pointer
    \param len Length of DER data

    _Example_
    \code
    const unsigned char* der = ...; // DER data
    OcspResponse* resp = wolfSSL_d2i_OCSP_RESPONSE(NULL, &der, derLen);
    \endcode

    \sa wolfSSL_i2d_OCSP_RESPONSE
*/
OcspResponse* wolfSSL_d2i_OCSP_RESPONSE(OcspResponse** response,
                                        const unsigned char** data,
                                        int len);

/*!
    \ingroup OCSP
    \brief Encodes OCSP response to DER.

    \return Length on success
    \return negative on error

    \param response Response to encode
    \param data Pointer to output buffer pointer

    _Example_
    \code
    unsigned char* der = NULL;
    int len = wolfSSL_i2d_OCSP_RESPONSE(response, &der);
    \endcode

    \sa wolfSSL_d2i_OCSP_RESPONSE
*/
int wolfSSL_i2d_OCSP_RESPONSE(OcspResponse* response, unsigned char** data);

/*!
    \ingroup OCSP
    \brief Gets OCSP response status.

    \return Status value on success
    \return negative on error

    \param response OCSP response

    _Example_
    \code
    int status = wolfSSL_OCSP_response_status(response);
    \endcode

    \sa wolfSSL_OCSP_response_get1_basic
*/
int wolfSSL_OCSP_response_status(OcspResponse *response);

/*!
    \ingroup OCSP
    \brief Gets basic response from OCSP response.

    \return Pointer to basic response on success
    \return NULL on error

    \param response OCSP response

    _Example_
    \code
    WOLFSSL_OCSP_BASICRESP* bs = wolfSSL_OCSP_response_get1_basic(response);
    \endcode

    \sa wolfSSL_OCSP_BASICRESP_free
*/
WOLFSSL_OCSP_BASICRESP* wolfSSL_OCSP_response_get1_basic(OcspResponse* response);

/*!
    \ingroup OCSP
    \brief Creates new OCSP request.

    \return Pointer to OCSP request on success
    \return NULL on error

    \param none No parameters

    _Example_
    \code
    OcspRequest* req = wolfSSL_OCSP_REQUEST_new();
    \endcode

    \sa wolfSSL_OCSP_REQUEST_free
*/
OcspRequest* wolfSSL_OCSP_REQUEST_new(void);

/*!
    \ingroup OCSP
    \brief Frees OCSP request.

    \return none No returns

    \param request Request to free

    _Example_
    \code
    wolfSSL_OCSP_REQUEST_free(request);
    \endcode

    \sa wolfSSL_OCSP_REQUEST_new
*/
void wolfSSL_OCSP_REQUEST_free(OcspRequest* request);

/*!
    \ingroup OCSP
    \brief Encodes OCSP request to DER.

    \return Length on success
    \return negative on error

    \param request Request to encode
    \param data Pointer to output buffer pointer

    _Example_
    \code
    unsigned char* der = NULL;
    int len = wolfSSL_i2d_OCSP_REQUEST(request, &der);
    \endcode

    \sa wolfSSL_OCSP_REQUEST_new
*/
int wolfSSL_i2d_OCSP_REQUEST(OcspRequest* request, unsigned char** data);

/*!
    \ingroup OCSP
    \brief Adds certificate ID to OCSP request.

    \return Pointer to one request on success
    \return NULL on error

    \param req OCSP request
    \param cid Certificate ID

    _Example_
    \code
    WOLFSSL_OCSP_ONEREQ* one = wolfSSL_OCSP_request_add0_id(req, cid);
    \endcode

    \sa wolfSSL_OCSP_REQUEST_new
*/
WOLFSSL_OCSP_ONEREQ* wolfSSL_OCSP_request_add0_id(OcspRequest *req,
                                                  WOLFSSL_OCSP_CERTID *cid);

/*!
    \ingroup OCSP
    \brief Duplicates OCSP certificate ID.

    \return Pointer to duplicated certificate ID on success
    \return NULL on error

    \param id Certificate ID to duplicate

    _Example_
    \code
    WOLFSSL_OCSP_CERTID* dup = wolfSSL_OCSP_CERTID_dup(id);
    \endcode

    \sa wolfSSL_OCSP_CERTID_free
*/
WOLFSSL_OCSP_CERTID* wolfSSL_OCSP_CERTID_dup(WOLFSSL_OCSP_CERTID* id);

/*!
    \ingroup OCSP
    \brief Encodes OCSP request to BIO.

    \return Length on success
    \return negative on error

    \param out Output BIO
    \param req OCSP request

    _Example_
    \code
    int ret = wolfSSL_i2d_OCSP_REQUEST_bio(bio, req);
    \endcode

    \sa wolfSSL_i2d_OCSP_REQUEST
*/
int wolfSSL_i2d_OCSP_REQUEST_bio(WOLFSSL_BIO* out,
                                 WOLFSSL_OCSP_REQUEST *req);

/*!
    \ingroup OCSP
    \brief Encodes OCSP certificate ID to DER.

    \return Length on success
    \return negative on error

    \param id Certificate ID
    \param data Pointer to output buffer pointer

    _Example_
    \code
    unsigned char* der = NULL;
    int len = wolfSSL_i2d_OCSP_CERTID(id, &der);
    \endcode

    \sa wolfSSL_d2i_OCSP_CERTID
*/
int wolfSSL_i2d_OCSP_CERTID(WOLFSSL_OCSP_CERTID* id, unsigned char** data);

/*!
    \ingroup OCSP
    \brief Decodes OCSP certificate ID from DER.

    \return Pointer to certificate ID on success
    \return NULL on error

    \param cidOut Pointer to certificate ID pointer
    \param derIn Pointer to DER data pointer
    \param length Length of DER data

    _Example_
    \code
    const unsigned char* der = ...; // DER data
    WOLFSSL_OCSP_CERTID* id = wolfSSL_d2i_OCSP_CERTID(NULL, &der, derLen);
    \endcode

    \sa wolfSSL_i2d_OCSP_CERTID
*/
WOLFSSL_OCSP_CERTID* wolfSSL_d2i_OCSP_CERTID(WOLFSSL_OCSP_CERTID** cidOut,
                                             const unsigned char** derIn,
                                             int length);

/*!
    \ingroup OCSP
    \brief Gets certificate ID from single response.

    \return Pointer to certificate ID on success
    \return NULL on error

    \param single Single response

    _Example_
    \code
    const WOLFSSL_OCSP_CERTID* id = wolfSSL_OCSP_SINGLERESP_get0_id(single);
    \endcode

    \sa wolfSSL_OCSP_resp_get0
*/
const WOLFSSL_OCSP_CERTID* wolfSSL_OCSP_SINGLERESP_get0_id(const WOLFSSL_OCSP_SINGLERESP *single);

/*!
    \ingroup OCSP
    \brief Compares two OCSP certificate IDs.

    \return 0 if equal
    \return non-zero if different

    \param a First certificate ID
    \param b Second certificate ID

    _Example_
    \code
    int ret = wolfSSL_OCSP_id_cmp(id1, id2);
    if (ret == 0) {
        // IDs are equal
    }
    \endcode

    \sa wolfSSL_OCSP_CERTID_dup
*/
int wolfSSL_OCSP_id_cmp(WOLFSSL_OCSP_CERTID *a, WOLFSSL_OCSP_CERTID *b);

/*!
    \ingroup OCSP
    \brief Gets status from single response.

    \return Status value on success
    \return negative on error

    \param single Single response
    \param reason Pointer to store revocation reason
    \param revtime Pointer to store revocation time
    \param thisupd Pointer to store this update time
    \param nextupd Pointer to store next update time

    _Example_
    \code
    int reason;
    WOLFSSL_ASN1_TIME *revtime, *thisupd, *nextupd;
    int status = wolfSSL_OCSP_single_get0_status(single, &reason, &revtime,
                                                 &thisupd, &nextupd);
    \endcode

    \sa wolfSSL_OCSP_resp_get0
*/
int wolfSSL_OCSP_single_get0_status(WOLFSSL_OCSP_SINGLERESP *single,
                                    int *reason,
                                    WOLFSSL_ASN1_TIME **revtime,
                                    WOLFSSL_ASN1_TIME **thisupd,
                                    WOLFSSL_ASN1_TIME **nextupd);

/*!
    \ingroup OCSP
    \brief Gets count of responses in basic response.

    \return Count of responses

    \param bs Basic response

    _Example_
    \code
    int count = wolfSSL_OCSP_resp_count(bs);
    \endcode

    \sa wolfSSL_OCSP_resp_get0
*/
int wolfSSL_OCSP_resp_count(WOLFSSL_OCSP_BASICRESP *bs);

/*!
    \ingroup OCSP
    \brief Gets single response by index.

    \return Pointer to single response on success
    \return NULL on error

    \param bs Basic response
    \param idx Index of response

    _Example_
    \code
    WOLFSSL_OCSP_SINGLERESP* single = wolfSSL_OCSP_resp_get0(bs, 0);
    \endcode

    \sa wolfSSL_OCSP_resp_count
*/
WOLFSSL_OCSP_SINGLERESP* wolfSSL_OCSP_resp_get0(WOLFSSL_OCSP_BASICRESP *bs,
                                                int idx);

/*!
    \ingroup OCSP
    \brief Creates new OCSP request context.

    \return Pointer to request context on success
    \return NULL on error

    \param bio BIO for I/O
    \param maxline Maximum line length

    _Example_
    \code
    WOLFSSL_OCSP_REQ_CTX* ctx = wolfSSL_OCSP_REQ_CTX_new(bio, 4096);
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_free
*/
WOLFSSL_OCSP_REQ_CTX* wolfSSL_OCSP_REQ_CTX_new(WOLFSSL_BIO *bio,
                                               int maxline);

/*!
    \ingroup OCSP
    \brief Frees OCSP request context.

    \return none No returns

    \param ctx Request context to free

    _Example_
    \code
    wolfSSL_OCSP_REQ_CTX_free(ctx);
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_new
*/
void wolfSSL_OCSP_REQ_CTX_free(WOLFSSL_OCSP_REQ_CTX *ctx);

/*!
    \ingroup OCSP
    \brief Sets OCSP request in context.

    \return 1 on success
    \return 0 or negative on error

    \param ctx Request context
    \param req OCSP request

    _Example_
    \code
    int ret = wolfSSL_OCSP_REQ_CTX_set1_req(ctx, req);
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_new
*/
int wolfSSL_OCSP_REQ_CTX_set1_req(WOLFSSL_OCSP_REQ_CTX *ctx,
                                  OcspRequest *req);

/*!
    \ingroup OCSP
    \brief Adds HTTP header to OCSP request context.

    \return 1 on success
    \return 0 or negative on error

    \param ctx Request context
    \param name Header name
    \param value Header value

    _Example_
    \code
    int ret = wolfSSL_OCSP_REQ_CTX_add1_header(ctx, "Host",
                                               "ocsp.example.com");
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_http
*/
int wolfSSL_OCSP_REQ_CTX_add1_header(WOLFSSL_OCSP_REQ_CTX *ctx,
                                     const char *name, const char *value);

/*!
    \ingroup OCSP
    \brief Sets HTTP operation and path for OCSP request.

    \return 1 on success
    \return 0 or negative on error

    \param ctx Request context
    \param op HTTP operation (e.g., "POST")
    \param path URL path

    _Example_
    \code
    int ret = wolfSSL_OCSP_REQ_CTX_http(ctx, "POST", "/ocsp");
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_add1_header
*/
int wolfSSL_OCSP_REQ_CTX_http(WOLFSSL_OCSP_REQ_CTX *ctx, const char *op,
                              const char *path);

/*!
    \ingroup OCSP
    \brief Performs non-blocking I/O for OCSP request.

    \return 1 if complete
    \return 0 if incomplete
    \return negative on error

    \param ctx Request context

    _Example_
    \code
    int ret = wolfSSL_OCSP_REQ_CTX_nbio(ctx);
    \endcode

    \sa wolfSSL_OCSP_sendreq_nbio
*/
int wolfSSL_OCSP_REQ_CTX_nbio(WOLFSSL_OCSP_REQ_CTX *ctx);

/*!
    \ingroup OCSP
    \brief Sends OCSP request non-blocking.

    \return 1 if complete
    \return 0 if incomplete
    \return negative on error

    \param presp Pointer to response pointer
    \param rctx Request context

    _Example_
    \code
    OcspResponse* resp = NULL;
    int ret = wolfSSL_OCSP_sendreq_nbio(&resp, ctx);
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_nbio
*/
int wolfSSL_OCSP_sendreq_nbio(OcspResponse **presp,
                              WOLFSSL_OCSP_REQ_CTX *rctx);

/*!
    \ingroup OCSP
    \brief Adds extension to OCSP request.

    \return 1 on success
    \return 0 or negative on error

    \param req OCSP request
    \param ext Extension to add
    \param idx Index position

    _Example_
    \code
    int ret = wolfSSL_OCSP_REQUEST_add_ext(req, ext, -1);
    \endcode

    \sa wolfSSL_OCSP_REQUEST_new
*/
int wolfSSL_OCSP_REQUEST_add_ext(OcspRequest* req,
                                 WOLFSSL_X509_EXTENSION* ext, int idx);

/*!
    \ingroup OCSP
    \brief Creates OCSP response with status.

    \return Pointer to OCSP response on success
    \return NULL on error

    \param status Response status
    \param bs Basic response

    _Example_
    \code
    OcspResponse* resp = wolfSSL_OCSP_response_create(
                             OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);
    \endcode

    \sa wolfSSL_OCSP_RESPONSE_free
*/
OcspResponse* wolfSSL_OCSP_response_create(int status,
                                           WOLFSSL_OCSP_BASICRESP* bs);

/*!
    \ingroup OCSP
    \brief Gets CRL reason string.

    \return Pointer to reason string

    \param s Reason code

    _Example_
    \code
    const char* reason = wolfSSL_OCSP_crl_reason_str(1);
    \endcode

    \sa wolfSSL_OCSP_single_get0_status
*/
const char* wolfSSL_OCSP_crl_reason_str(long s);

/*!
    \ingroup OCSP
    \brief Gets information from OCSP certificate ID.

    \return 1 on success
    \return 0 or negative on error

    \param name Pointer to store name
    \param pmd Pointer to store algorithm
    \param keyHash Pointer to store key hash
    \param serial Pointer to store serial number
    \param cid Certificate ID

    _Example_
    \code
    WOLFSSL_ASN1_STRING *name, *keyHash;
    WOLFSSL_ASN1_OBJECT *pmd;
    WOLFSSL_ASN1_INTEGER *serial;
    int ret = wolfSSL_OCSP_id_get0_info(&name, &pmd, &keyHash, &serial,
                                        cid);
    \endcode

    \sa wolfSSL_OCSP_cert_to_id
*/
int wolfSSL_OCSP_id_get0_info(WOLFSSL_ASN1_STRING **name,
                              WOLFSSL_ASN1_OBJECT **pmd,
                              WOLFSSL_ASN1_STRING **keyHash,
                              WOLFSSL_ASN1_INTEGER **serial,
                              WOLFSSL_OCSP_CERTID *cid);

/*!
    \ingroup OCSP
    \brief Adds nonce to OCSP request.

    \return 1 on success
    \return 0 or negative on error

    \param req OCSP request
    \param val Nonce value (NULL for random)
    \param sz Nonce size

    _Example_
    \code
    int ret = wolfSSL_OCSP_request_add1_nonce(req, NULL, 16);
    \endcode

    \sa wolfSSL_OCSP_check_nonce
*/
int wolfSSL_OCSP_request_add1_nonce(OcspRequest* req, unsigned char* val,
                                    int sz);

/*!
    \ingroup OCSP
    \brief Checks nonce in OCSP response.

    \return 1 if nonce matches
    \return 0 if no nonce
    \return negative on error

    \param req OCSP request
    \param bs Basic response

    _Example_
    \code
    int ret = wolfSSL_OCSP_check_nonce(req, bs);
    \endcode

    \sa wolfSSL_OCSP_request_add1_nonce
*/
int wolfSSL_OCSP_check_nonce(OcspRequest* req, WOLFSSL_OCSP_BASICRESP* bs);
