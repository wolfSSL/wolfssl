/*!
    \ingroup Logging
    
    \brief This function registers a logging callback that will be used to 
    handle the wolfSSL log message. By default, if the system supports it 
    fprintf() to stderr is used but by using this function anything 
    can be done by the user.
    
    \return Success If successful this function will return 0.
    \return BAD_FUNC_ARG is the error that will be returned if a function 
    pointer is not provided.
    
    \param log_function function to register as a logging callback. 
    Function signature must follow the above prototype.
    
    _Example_
    \code
    int ret = 0;
    // Logging callback prototype
    void MyLoggingCallback(const int logLevel, const char* const logMessage);
    // Register the custom logging callback with wolfSSL
    ret = wolfSSL_SetLoggingCb(MyLoggingCallback);
    if (ret != 0) {
	    // failed to set logging callback
    }
    void MyLoggingCallback(const int logLevel, const char* const logMessage)
    {
	// custom logging function
    }
    \endcode
    
    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_Debugging_OFF
*/
WOLFSSL_API int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);
