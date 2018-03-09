/*!
    \ingroup ASN
    
    \brief This function converts a pem certificate to a der certificate, 
    and places the resulting certificate in the derBuf buffer provided.
    
    \return Success On success returns the size of the derBuf generated
    \return BUFFER_E Returned if the size of derBuf is too small to hold 
    the certificate generated
    \return MEMORY_E Returned if the call to XMALLOC fails
    
    \param fileName path to the file containing a pem certificate to 
    convert to a der certificate
    \param derBuf pointer to a char buffer in which to store the 
    converted certificate
    \param derSz size of the char buffer in which to store the 
    converted certificate
    
    _Example_
    \code
    char * file = “./certs/client-cert.pem”;
    int derSz;
    byte * der = (byte*)XMALLOC(EIGHTK_BUF, NULL, DYNAMIC_TYPE_CERT);

    derSz = wolfsSSL_PemCertToDer(file, der, EIGHTK_BUF);
    if(derSz <= 0) {
    	//PemCertToDer error
    }
    \endcode
    
    \sa none
*/
WOLFSSL_API
int wolfSSL_PemCertToDer(const char* fileName,unsigned char* derBuf,int derSz);
