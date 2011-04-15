#ifndef CYASSL_LOGGING_H
#define CYASSL_LOGGING_H


#ifdef __cplusplus
    extern "C" {
#endif


enum  CYA_Log_Levels {
    ERROR_LOG = 0,
    INFO_LOG,
	ENTER_LOG,
	LEAVE_LOG,
	OTHER_LOG
};

typedef void (*CyaSSL_Logging_cb)(const int logLevel,
                                  const char *const logMessage);

int CyaSSL_SetLoggingCb(CyaSSL_Logging_cb log_function);


#ifdef DEBUG_CYASSL

    void CYASSL_ENTER(const char* msg);
    void CYASSL_LEAVE(const char* msg, int ret);

    void CYASSL_ERROR(int);
    void CYASSL_MSG(const char* msg);

#else /* DEBUG_CYASSL   */

    #define CYASSL_ENTER(m)
    #define CYASSL_LEAVE(m, r)

    #define CYASSL_ERROR(e) 
    #define CYASSL_MSG(m)

#endif /* DEBUG_CYASSL  */

#ifdef __cplusplus
}
#endif

#endif /* CYASSL_MEMORY_H */
