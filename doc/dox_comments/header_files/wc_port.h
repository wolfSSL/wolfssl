/*!
    \ingroup wolfCrypt
    
    \brief Used to clean up resources used by wolfCrypt.
    
    \return 0 upon success.
    \return <0 upon failure of cleaning up resources.
    
    \param none No parameters.
    
    _Example_
    \code
    ...
    if (wolfCrypt_Cleanup() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Cleanup call");
    }
    \endcode
    
    \sa wolfCrypt_Init
*/
WOLFSSL_API int wolfCrypt_Cleanup(void);
