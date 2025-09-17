/*!
    \ingroup OCSP

    \brief Initializes an OCSP context.

    This function initializes a WOLFSSL_OCSP structure for use with OCSP operations.

    \param ocsp Pointer to the WOLFSSL_OCSP structure to initialize.
    \param cm   Pointer to the certificate manager.

    \return 0 on success
    \return <0 on failure

    \sa wc_FreeOCSP
*/
int wc_InitOCSP(WOLFSSL_OCSP* ocsp, WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup OCSP

    \brief Frees resources associated with an OCSP context.

    This function releases any resources associated with a WOLFSSL_OCSP structure.

    \param ocsp Pointer to the WOLFSSL_OCSP structure to free.

    \return void

    \sa wc_InitOCSP
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
