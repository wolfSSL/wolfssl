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
int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);

/*!
    \ingroup Debug

    \brief If logging has been enabled at build time this function turns on
    logging at runtime.  To enable logging at build time use --enable-debug
    or define DEBUG_WOLFSSL.

    \return 0 upon success.
    \return NOT_COMPILED_IN is the error that will be returned if logging
    isn’t enabled for this build.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_Debugging_ON();
    \endcode

    \sa wolfSSL_Debugging_OFF
    \sa wolfSSL_SetLoggingCb
*/
int  wolfSSL_Debugging_ON(void);

/*!
    \ingroup Debug

    \brief This function turns off runtime logging messages.  If they’re
    already off, no action is taken.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_Debugging_OFF();
    \endcode

    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_SetLoggingCb
*/
void wolfSSL_Debugging_OFF(void);

/*!
    \ingroup Logging
    \brief Gets the currently registered logging callback.

    \return Pointer to logging callback function
    \return NULL if no callback is registered

    _Example_
    \code
    wolfSSL_Logging_cb cb = wolfSSL_GetLoggingCb();
    if (cb != NULL) {
        // callback is registered
    }
    \endcode

    \sa wolfSSL_SetLoggingCb
*/
wolfSSL_Logging_cb wolfSSL_GetLoggingCb(void);

/*!
    \ingroup Debug
    \brief Enables certificate debugging messages.

    \return 0 on success
    \return NOT_COMPILED_IN if not enabled at build time

    _Example_
    \code
    int ret = wolfSSL_CertDebugging_ON();
    \endcode

    \sa wolfSSL_CertDebugging_OFF
*/
int wolfSSL_CertDebugging_ON(void);

/*!
    \ingroup Debug
    \brief Disables certificate debugging messages.

    \return 0 on success

    _Example_
    \code
    int ret = wolfSSL_CertDebugging_OFF();
    \endcode

    \sa wolfSSL_CertDebugging_ON
*/
int wolfSSL_CertDebugging_OFF(void);

/*!
    \ingroup Logging
    \brief Sets a prefix string for all log messages.

    \param prefix Prefix string to prepend to log messages

    _Example_
    \code
    wolfSSL_SetLoggingPrefix("[MyApp] ");
    \endcode

    \sa wolfSSL_SetLoggingCb
*/
void wolfSSL_SetLoggingPrefix(const char* prefix);

/*!
    \ingroup Logging
    \brief Sets heap hint for logging allocations.

    \return 0 on success
    \return BAD_FUNC_ARG if h is invalid

    \param h Heap hint pointer

    _Example_
    \code
    void* heap = NULL;
    int ret = wc_SetLoggingHeap(heap);
    \endcode

    \sa wolfSSL_SetLoggingCb
*/
int wc_SetLoggingHeap(void* h);

/*!
    \ingroup Logging
    \brief Removes error state for OpenSSL compatibility.

    \return 0 on success

    _Example_
    \code
    int ret = wc_ERR_remove_state();
    \endcode

    \sa wc_ERR_print_errors_fp
*/
int wc_ERR_remove_state(void);

/*!
    \ingroup Logging
    \brief Prints errors to file pointer for OpenSSL compatibility.

    \param fp File pointer to write errors

    _Example_
    \code
    wc_ERR_print_errors_fp(stderr);
    \endcode

    \sa wc_ERR_remove_state
*/
void wc_ERR_print_errors_fp(XFILE fp);

/*!
    \ingroup Debug
    \brief Marks start of function for profiling.

    \param funcNum Function number identifier

    _Example_
    \code
    WOLFSSL_START(1);
    // function code
    WOLFSSL_END(1);
    \endcode

    \sa WOLFSSL_END
*/
void WOLFSSL_START(int funcNum);

/*!
    \ingroup Debug
    \brief Marks end of function for profiling.

    \param funcNum Function number identifier

    _Example_
    \code
    WOLFSSL_START(1);
    // function code
    WOLFSSL_END(1);
    \endcode

    \sa WOLFSSL_START
*/
void WOLFSSL_END(int funcNum);

/*!
    \ingroup Debug
    \brief Records timing information for profiling.

    \param count Count value for timing

    _Example_
    \code
    WOLFSSL_TIME(iterations);
    \endcode

    \sa WOLFSSL_START
*/
void WOLFSSL_TIME(int count);

/*!
    \ingroup Debug
    \brief Logs certificate-related message.

    \return 0 on success

    \param msg Message to log

    _Example_
    \code
    WOLFSSL_MSG_CERT("Processing certificate");
    \endcode

    \sa WOLFSSL_MSG_CERT_EX
*/
int WOLFSSL_MSG_CERT(const char* msg);

/*!
    \ingroup Debug
    \brief Logs formatted certificate message.

    \return 0 on success

    \param fmt Format string
    \param ... Variable arguments

    _Example_
    \code
    WOLFSSL_MSG_CERT_EX("Cert size: %d", certSize);
    \endcode

    \sa WOLFSSL_MSG_CERT
*/
int WOLFSSL_MSG_CERT_EX(const char* fmt, ...);

/*!
    \ingroup Debug
    \brief Logs function entry.

    \param msg Function name

    _Example_
    \code
    WOLFSSL_ENTER("MyFunction");
    \endcode

    \sa WOLFSSL_LEAVE
*/
void WOLFSSL_ENTER(const char* msg);

/*!
    \ingroup Debug
    \brief Logs function exit with return value.

    \param msg Function name
    \param ret Return value

    _Example_
    \code
    WOLFSSL_LEAVE("MyFunction", ret);
    \endcode

    \sa WOLFSSL_ENTER
*/
void WOLFSSL_LEAVE(const char* msg, int ret);

/*!
    \ingroup Debug
    \brief Checks if debug logging is enabled.

    \return 1 if debug is on
    \return 0 if debug is off

    _Example_
    \code
    if (WOLFSSL_IS_DEBUG_ON()) {
        // debug-only code
    }
    \endcode

    \sa wolfSSL_Debugging_ON
*/
int WOLFSSL_IS_DEBUG_ON(void);

/*!
    \ingroup Debug
    \brief Logs formatted debug message.

    \param fmt Format string
    \param ... Variable arguments

    _Example_
    \code
    WOLFSSL_MSG_EX("Value: %d", value);
    \endcode

    \sa WOLFSSL_MSG
*/
void WOLFSSL_MSG_EX(const char* fmt, ...);

/*!
    \ingroup Debug
    \brief Logs debug message.

    \param msg Message to log

    _Example_
    \code
    WOLFSSL_MSG("Processing data");
    \endcode

    \sa WOLFSSL_MSG_EX
*/
void WOLFSSL_MSG(const char* msg);

/*!
    \ingroup Debug
    \brief Logs message with file and line info.

    \param file Source file name
    \param line Line number
    \param msg Message to log

    _Example_
    \code
    WOLFSSL_MSG2(__FILE__, __LINE__, "Debug info");
    \endcode

    \sa WOLFSSL_MSG
*/
void WOLFSSL_MSG2(const char *file, int line, const char* msg);

/*!
    \ingroup Debug
    \brief Logs function entry with file and line.

    \param file Source file name
    \param line Line number
    \param msg Function name

    _Example_
    \code
    WOLFSSL_ENTER2(__FILE__, __LINE__, "MyFunction");
    \endcode

    \sa WOLFSSL_ENTER
*/
void WOLFSSL_ENTER2(const char *file, int line, const char* msg);

/*!
    \ingroup Debug
    \brief Logs function exit with file, line, and return value.

    \param file Source file name
    \param line Line number
    \param msg Function name
    \param ret Return value

    _Example_
    \code
    WOLFSSL_LEAVE2(__FILE__, __LINE__, "MyFunction", ret);
    \endcode

    \sa WOLFSSL_LEAVE
*/
void WOLFSSL_LEAVE2(const char *file, int line, const char* msg,
                   int ret);

/*!
    \ingroup Debug
    \brief Logs formatted message with file and line.

    \param file Source file name
    \param line Line number
    \param fmt Format string
    \param ... Variable arguments

    _Example_
    \code
    WOLFSSL_MSG_EX2(__FILE__, __LINE__, "Value: %d", val);
    \endcode

    \sa WOLFSSL_MSG_EX
*/
void WOLFSSL_MSG_EX2(const char *file, int line, const char* fmt,
                    ...);

/*!
    \ingroup Debug
    \brief Logs buffer contents in hex format.

    \param buffer Buffer to log
    \param length Buffer length

    _Example_
    \code
    byte data[16];
    WOLFSSL_BUFFER(data, sizeof(data));
    \endcode

    \sa WOLFSSL_MSG
*/
void WOLFSSL_BUFFER(const byte* buffer, word32 length);

/*!
    \ingroup Debug
    \brief Logs error with file and line information.

    \param err Error code
    \param func Function name
    \param line Line number
    \param file Source file name
    \param ctx Context pointer

    _Example_
    \code
    WOLFSSL_ERROR_LINE(err, __func__, __LINE__, __FILE__, NULL);
    \endcode

    \sa WOLFSSL_ERROR
*/
void WOLFSSL_ERROR_LINE(int err, const char* func, unsigned int line,
                       const char* file, void* ctx);

/*!
    \ingroup Debug
    \brief Logs error code.

    \param err Error code

    _Example_
    \code
    WOLFSSL_ERROR(BAD_FUNC_ARG);
    \endcode

    \sa WOLFSSL_ERROR_LINE
*/
void WOLFSSL_ERROR(int err);

/*!
    \ingroup Debug
    \brief Logs error message.

    \param msg Error message

    _Example_
    \code
    WOLFSSL_ERROR_MSG("Invalid parameter");
    \endcode

    \sa WOLFSSL_ERROR
*/
void WOLFSSL_ERROR_MSG(const char* msg);

/*!
    \ingroup Debug
    \brief Arduino-specific serial print function.

    \return Number of characters printed
    \return Negative on error

    \param s String to print

    _Example_
    \code
    wolfSSL_Arduino_Serial_Print("Debug message\n");
    \endcode

    \sa WOLFSSL_MSG
*/
extern int wolfSSL_Arduino_Serial_Print(const char* const s);
