/* logging.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
    \file wolfssl/wolfcrypt/logging.h
*/


/* submitted by eof */

/*
 * Enable wolfSSL debugging with DEBUG_WOLFSSL
 *
 * Certificate debugging is a subset of DEBUG_WOLFSSL but can be enabled
 * exclusively with WOLFSSL_DEBUG_CERTS.
 *
 * When DEBUG_WOLFSSL is enabled, but the subset of certificate debugging
 * is not desired, it can disabled with NO_WOLFSSL_DEBUG_CERTS
 *
 * ****************************************************************************
 * Message / printf debugging
 * ****************************************************************************
 *
 * WOLFSSL_DEBUG_PRINTF()
 *   Utility macro: A buffer-less, non-truncating debug message renderer.  On
 *   supported targets, it is always functional, i.e. it is not affected by
 *   DEBUG_WOLFSSL or wolfSSL_Debugging_{ON,OFF}().  Test for support using
 *   defined(WOLFSSL_DEBUG_PRINTF) -- if it is unsupported it is not defined.
 *
 * WOLFSSL_DEBUG_PRINTF_FN
 *   Used to supply an override definition of the target platform's printf-like
 *   function.  By default, it is defined to fprintf.  If defined, this is used
 *   as the underlying function for all logging by the library.
 *
 * WOLFSSL_DEBUG_PRINTF_FIRST_ARGS
 *   Used to supply an override definition of the initial args to the target
 *   platform's printf-like function, with a trailing comma.  This can be
 *   defined to nothing if there are no initial args to supply.  By default, it
 *   is defined to stderr plus a trailing comma.  If defined, the args are
 *   passed to WOLFSSL_DEBUG_PRINTF_FN wherever it is called.
 *
 * WOLFSSL_MSG_EX_BUF_SZ
 *   Re-definable macro: maximum length of WOLFSSL_MSG_EX debugging messages.
 *
 * WOLFSSL_MSG
 *   Single message parameter. Works everywhere.
 *
 * WOLFSSL_MSG_EX
 *   Variable number of parameters. Should be supported nearly everywhere.
 *
 * WOLFSSL_MSG_EX2
 *   Variable number of parameters. Should be supported nearly everywhere.
 *   Special case where first two parameters are const char *file, int line
 *
 * ****************************************************************************
 * Certificate Debugging: a subset of DEBUG_WOLFSSL
 * or can be used alone WOLFSSL_DEBUG_CERTS without all the debugging noise
 * ****************************************************************************
 *
 * WOLFSSL_MSG_CERT_BUF_SZ
 *   Used by WOLFSSL_MSG_CERT and WOLFSSL_MSG_CERT_EX
 *   Re-definable macro: maximum length of debugging messages.
 *
 * WOLFSSL_MSG_CERT
 *   Single message parameter. Works everywhere.
 *   Print only during WOLFSSL_DEBUG_CERTS
 *
 * WOLFSSL_MSG_CERT_LOG
 *   Single message parameter. Works everywhere.
 *   Print during either DEBUG_WOLFSSL or WOLFSSL_DEBUG_CERTS
 *
 * WOLFSSL_MSG_CERT_EX
 *   Variable number of parameters. Should be supported nearly everywhere.
 *
 * WOLFSSL_MSG_CERT_LOG_EX
 *   Variable number of parameters. Should be supported nearly everywhere.
 *   Print during either DEBUG_WOLFSSL or WOLFSSL_DEBUG_CERTS
 *
 * When any of the above are disabled:
 *   With WOLF_NO_VARIADIC_MACROS a do nothing placeholder function is used.
 *   Otherwise, a do-nothing macro. See WC_DO_NOTHING
 *
 * Optional user callbacks:
 *   wolfSSL_SetLoggingCb(my_log_cb);
 *
 * To disable certificate debugging:
 *   Do not define WOLFSSL_DEBUG_CERTS when used without DEBUG_WOLFSSL
 *      or
 *   Define NO_WOLFSSL_DEBUG_CERTS when DEBUG_WOLFSSL is enabled
 *
 *  If NO_WOLFSSL_DEBUG_CERTS is detected in settings.h, the respective
 *  WOLFSSL_DEBUG_CERTS will be undefined. The explicit NO_WOLFSSL_DEBUG_CERTS
 *  checks are still performed in logging source for code clarity only.
 *
 * ****************************************************************************
 * At runtime with debugging enabled:
 * ****************************************************************************
 *
 * Display debug messages:
 *  int  wolfSSL_Debugging_ON(void)
 *  int  wolfSSL_CertDebugging_ON(void)
 *
 * Disable debug messages until re-enabled at runtime:
 *  void wolfSSL_Debugging_OFF(void);
 *  int  wolfSSL_CertDebugging_OFF(void)
 *
 * See also:
 *  int WOLFSSL_IS_DEBUG_ON(void)
 *
 *  Note: does not affect WOLFSSL_DEBUG_PRINTF(), which renders unconditionally.
 *
 */

#ifndef WOLFSSL_LOGGING_H
#define WOLFSSL_LOGGING_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef __cplusplus
    extern "C" {
#endif


enum wc_LogLevels {
    ERROR_LOG = 0,
    INFO_LOG,
    ENTER_LOG,
    LEAVE_LOG,
    CERT_LOG,
    OTHER_LOG
};

#ifdef WOLFSSL_FUNC_TIME
/* WARNING: This code is only to be used for debugging performance.
 *          The code is not thread-safe.
 *          Do not use WOLFSSL_FUNC_TIME in production code.
 */
enum wc_FuncNum {
    WC_FUNC_HELLO_REQUEST_SEND = 0,
    WC_FUNC_HELLO_REQUEST_DO,
    WC_FUNC_CLIENT_HELLO_SEND,
    WC_FUNC_CLIENT_HELLO_DO,
    WC_FUNC_SERVER_HELLO_SEND,
    WC_FUNC_SERVER_HELLO_DO,
    WC_FUNC_ENCRYPTED_EXTENSIONS_SEND,
    WC_FUNC_ENCRYPTED_EXTENSIONS_DO,
    WC_FUNC_CERTIFICATE_REQUEST_SEND,
    WC_FUNC_CERTIFICATE_REQUEST_DO,
    WC_FUNC_CERTIFICATE_SEND,
    WC_FUNC_CERTIFICATE_DO,
    WC_FUNC_CERTIFICATE_VERIFY_SEND,
    WC_FUNC_CERTIFICATE_VERIFY_DO,
    WC_FUNC_FINISHED_SEND,
    WC_FUNC_FINISHED_DO,
    WC_FUNC_KEY_UPDATE_SEND,
    WC_FUNC_KEY_UPDATE_DO,
    WC_FUNC_EARLY_DATA_SEND,
    WC_FUNC_EARLY_DATA_DO,
    WC_FUNC_NEW_SESSION_TICKET_SEND,
    WC_FUNC_NEW_SESSION_TICKET_DO,
    WC_FUNC_SERVER_HELLO_DONE_SEND,
    WC_FUNC_SERVER_HELLO_DONE_DO,
    WC_FUNC_TICKET_SEND,
    WC_FUNC_TICKET_DO,
    WC_FUNC_CLIENT_KEY_EXCHANGE_SEND,
    WC_FUNC_CLIENT_KEY_EXCHANGE_DO,
    WC_FUNC_CERTIFICATE_STATUS_SEND,
    WC_FUNC_CERTIFICATE_STATUS_DO,
    WC_FUNC_SERVER_KEY_EXCHANGE_SEND,
    WC_FUNC_SERVER_KEY_EXCHANGE_DO,
    WC_FUNC_END_OF_EARLY_DATA_SEND,
    WC_FUNC_END_OF_EARLY_DATA_DO,
    WC_FUNC_COUNT
};
#endif

typedef void (*wolfSSL_Logging_cb)(const int logLevel,
                                   const char *const logMessage);

WOLFSSL_API int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);
WOLFSSL_API wolfSSL_Logging_cb wolfSSL_GetLoggingCb(void);

/* turn logging on, only if compiled in */
WOLFSSL_API int  wolfSSL_Debugging_ON(void);
/* turn logging off */
WOLFSSL_API void wolfSSL_Debugging_OFF(void);
/* turn cert debugging on, only if compiled in */
WOLFSSL_API int  wolfSSL_CertDebugging_ON(void);
/* turn cert debugging off */
WOLFSSL_API int  wolfSSL_CertDebugging_OFF(void);


WOLFSSL_API void wolfSSL_SetLoggingPrefix(const char* prefix);

#ifdef HAVE_WC_INTROSPECTION
    WOLFSSL_API const char *wolfSSL_configure_args(void);
    WOLFSSL_API const char *wolfSSL_global_cflags(void);
#endif


#if (defined(OPENSSL_EXTRA) && !defined(_WIN32) && \
        !defined(NO_ERROR_QUEUE)) || defined(DEBUG_WOLFSSL_VERBOSE) \
        || defined(HAVE_MEMCACHED)
#define WOLFSSL_HAVE_ERROR_QUEUE
#endif

#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE) || defined(HAVE_MEMCACHED)
    WOLFSSL_LOCAL int wc_LoggingInit(void);
    WOLFSSL_LOCAL int wc_LoggingCleanup(void);
    WOLFSSL_LOCAL int wc_AddErrorNode(int error, int line, char* buf,
            char* file);
    WOLFSSL_LOCAL int wc_PeekErrorNode(int idx, const char **file,
            const char **reason, int *line);
    WOLFSSL_LOCAL void wc_RemoveErrorNode(int idx);
    WOLFSSL_LOCAL void wc_ClearErrorNodes(void);
    WOLFSSL_LOCAL int wc_PullErrorNode(const char **file, const char **reason,
                            int *line);
    WOLFSSL_API   int wc_SetLoggingHeap(void* h);
    WOLFSSL_API   int wc_ERR_remove_state(void);
    WOLFSSL_LOCAL unsigned long wc_PeekErrorNodeLineData(
            const char **file, int *line, const char **data, int *flags,
            int (*ignore_err)(int err));
    WOLFSSL_LOCAL int wc_GetErrorNodeErr(void);
    #if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
        WOLFSSL_API void wc_ERR_print_errors_fp(XFILE fp);
        WOLFSSL_API void wc_ERR_print_errors_cb(int (*cb)(const char *str,
                                                size_t len, void *u), void *u);
    #endif
#endif /* OPENSSL_EXTRA || DEBUG_WOLFSSL_VERBOSE || HAVE_MEMCACHED */

#ifdef WOLFSSL_FUNC_TIME
    /* WARNING: This code is only to be used for debugging performance.
     *          The code is not thread-safe.
     *          Do not use WOLFSSL_FUNC_TIME in production code.
     */
    WOLFSSL_API void WOLFSSL_START(int funcNum);
    WOLFSSL_API void WOLFSSL_END(int funcNum);
    WOLFSSL_API void WOLFSSL_TIME(int count);
#else
    #define WOLFSSL_START(n) WC_DO_NOTHING
    #define WOLFSSL_END(n)   WC_DO_NOTHING
    #define WOLFSSL_TIME(n)  WC_DO_NOTHING
#endif

/* Certificate Debugging: WOLFSSL_MSG_CERT */
#if defined(XVSNPRINTF) && !defined(NO_WOLFSSL_DEBUG_CERTS) && \
   (defined(DEBUG_WOLFSSL) || defined(WOLFSSL_DEBUG_CERTS))
    #define HAVE_WOLFSSL_DEBUG_CERTS
    #ifndef WOLFSSL_MSG_CERT_INDENT
        #define WOLFSSL_MSG_CERT_INDENT "\t-  "
    #endif

    WOLFSSL_API int WOLFSSL_MSG_CERT(const char* msg);
    WOLFSSL_API int WOLFSSL_MSG_CERT_EX(const char* fmt, ...);
#else
    /* No Certificate Debugging */
    #undef WOLFSSL_DEBUG_CERTS

    #ifndef WOLFSSL_MSG_CERT_INDENT
        #define WOLFSSL_MSG_CERT_INDENT ""
    #endif
    #ifdef WOLF_NO_VARIADIC_MACROS
        /* The issue is variadic macros, not function parameters. e.g Watcom
         * Additionally, Watcom needs the empty declaration here: */
        #ifdef __WATCOMC__
            /* don't use WOLFSSL_API nor inline for Watcom stubs */
            static int WOLFSSL_MSG_CERT(const char* msg)
            {
                (void)msg;
                return NOT_COMPILED_IN;
            }

            static int WOLFSSL_MSG_CERT_EX(const char* fmt, ...)
            {
                (void)fmt;
                return NOT_COMPILED_IN;
            }
        #else
            WOLFSSL_API int WOLFSSL_MSG_CERT(const char* msg);
            WOLFSSL_API int WOLFSSL_MSG_CERT_EX(const char* fmt, ...);
        #endif
    #else
        /* Nearly all compilers will support variadic macros */
        #define WOLFSSL_MSG_CERT(m)      WC_DO_NOTHING
        #define WOLFSSL_MSG_CERT_EX(...) WC_DO_NOTHING
    #endif
#endif /* Certificate Debugging: WOLFSSL_MSG_CERT */

#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_DEBUG_ERRORS_ONLY)
    #if defined(_WIN32) && !defined(__WATCOMC__)
        #if defined(INTIME_RTOS)
            #define __func__ NULL
        #else
            #define __func__ __FUNCTION__
        #endif
    #endif

    /* a is prepended to m and b is appended, creating a log msg a + m + b */
    #define WOLFSSL_LOG_CAT(a, m, b) #a " " m " "  #b

    WOLFSSL_API void WOLFSSL_ENTER(const char* msg);
    WOLFSSL_API void WOLFSSL_LEAVE(const char* msg, int ret);
    #define WOLFSSL_STUB(m) \
        WOLFSSL_MSG(WOLFSSL_LOG_CAT(wolfSSL Stub, m, not implemented))
    WOLFSSL_API int WOLFSSL_IS_DEBUG_ON(void);

    /* WOLFSSL_MSG_EX may not be available. Check with HAVE_WOLFSSL_MSG_EX */
#if defined(XVSNPRINTF) && !defined(NO_WOLFSSL_MSG_EX)
    WOLFSSL_API void WOLFSSL_MSG_EX(const char* fmt, ...);
    #define HAVE_WOLFSSL_MSG_EX
#else
    #ifdef WOLF_NO_VARIADIC_MACROS
        /* We need a do-nothing function with a variable number of parameters */
        /* see logging.c
         *   static inline void WOLFSSL_MSG_EX(const char* fmt, ...); */
    #else
        #define WOLFSSL_MSG_EX(...)   WC_DO_NOTHING
    #endif
#endif
    WOLFSSL_API void WOLFSSL_MSG(const char* msg);
#ifdef WOLFSSL_DEBUG_CODEPOINTS
    WOLFSSL_API void WOLFSSL_MSG2(
        const char *file, int line, const char* msg);
    WOLFSSL_API void WOLFSSL_ENTER2(
        const char *file, int line, const char* msg);
    WOLFSSL_API void WOLFSSL_LEAVE2(
        const char *file, int line, const char* msg, int ret);
    #define WOLFSSL_MSG(msg) WOLFSSL_MSG2(__FILE__, __LINE__, msg)
    #define WOLFSSL_ENTER(msg) WOLFSSL_ENTER2(__FILE__, __LINE__, msg)
    #define WOLFSSL_LEAVE(msg, ret) WOLFSSL_LEAVE2(__FILE__, __LINE__, msg, ret)
    #ifdef XVSNPRINTF
        WOLFSSL_API void WOLFSSL_MSG_EX2(
            const char *file, int line, const char* fmt, ...);
        #define WOLFSSL_MSG_EX(fmt, args...) \
                WOLFSSL_MSG_EX2(__FILE__, __LINE__, fmt, ## args)
    #else
        #ifdef WOLF_NO_VARIADIC_MACROS
            #define WOLFSSL_MSG_EX2() WC_DO_NOTHING
        #else
            #define WOLFSSL_MSG_EX2(...) WC_DO_NOTHING
        #endif
    #endif
#endif
    WOLFSSL_API void WOLFSSL_BUFFER(const byte* buffer, word32 length);

#else
    /* ! (defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_DEBUG_ERRORS_ONLY)) */
    #define WOLFSSL_ENTER(m)          WC_DO_NOTHING
    #define WOLFSSL_LEAVE(m, r)       WC_DO_NOTHING
    #define WOLFSSL_STUB(m)           WC_DO_NOTHING
    #define WOLFSSL_IS_DEBUG_ON() 0

    #ifdef WOLF_NO_VARIADIC_MACROS
        /* note, modern preprocessors will generate errors with this definition.
         * "error: macro "WOLFSSL_MSG_EX" passed 2 arguments, but takes just 0"
         *
         *  #define WOLFSSL_MSG_EX(a, b)  WC_DO_NOTHING
         *
         * We need a do-nothing function with a variable number of parameters: */
        #ifdef __WATCOMC__
            /* don't use WOLFSSL_API nor inline for Watcom stubs */
            static void WOLFSSL_MSG_EX(const char* fmt, ...)
            {
                (void)fmt;
            }
        #else
            WOLFSSL_API void WOLFSSL_MSG_EX(const char* fmt, ...);
        #endif
    #else
        #define WOLFSSL_MSG_EX(...)   WC_DO_NOTHING
    #endif

    #define WOLFSSL_MSG(m)            WC_DO_NOTHING
    #define WOLFSSL_BUFFER(b, l)      WC_DO_NOTHING
#endif /* DEBUG_WOLFSSL && !WOLFSSL_DEBUG_ERRORS_ONLY */

/* A special case of certificate-related debug AND regular debug.
 * WOLFSSL_MSG_CERT_LOG will always print during DEBUG_WOLFSSL
 * even if cert debugging disabled with NO_WOLFSSL_DEBUG_CERTS.
 *
 * WOLFSSL_MSG_CERT_LOG will also print during WOLFSSL_DEBUG_CERTS
 * even if standard DEBUG_WOLFSSL is not enabled. */
#if defined(WOLFSSL_DEBUG_CERTS)
    #define WOLFSSL_MSG_CERT_LOG(msg) WOLFSSL_MSG_CERT(msg)
    #define WOLFSSL_MSG_CERT_LOG_EX WOLFSSL_MSG_CERT_EX
#elif defined(DEBUG_WOLFSSL)
    #define WOLFSSL_MSG_CERT_LOG(msg) WOLFSSL_MSG(msg)
    #define WOLFSSL_MSG_CERT_LOG_EX WOLFSSL_MSG_EX
#else
    #define WOLFSSL_MSG_CERT_LOG(msg) WC_DO_NOTHING
    #define WOLFSSL_MSG_CERT_LOG_EX WOLFSSL_MSG_EX
#endif

/* WOLFSSL_ERROR and WOLFSSL_HAVE_ERROR_QUEUE */
#if defined(DEBUG_WOLFSSL) || defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) ||\
    defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA)

    #ifdef WOLFSSL_HAVE_ERROR_QUEUE
        WOLFSSL_API void WOLFSSL_ERROR_LINE(int err, const char* func, unsigned int line,
            const char* file, void* ctx);
        #ifdef WOLF_C89
            #define WOLFSSL_ERROR(x) \
                WOLFSSL_ERROR_LINE((x), __FILE__, __LINE__, __FILE__, NULL)
        #else
            #define WOLFSSL_ERROR(x) \
                WOLFSSL_ERROR_LINE((x), __func__, __LINE__, __FILE__, NULL)
        #endif
    #else
        WOLFSSL_API void WOLFSSL_ERROR(int err);
    #endif /* WOLFSSL_HAVE_ERROR_QUEUE */

    WOLFSSL_API void WOLFSSL_ERROR_MSG(const char* msg);
#else
    #define WOLFSSL_ERROR(e) (void)(e)
    #define WOLFSSL_ERROR_MSG(m) (void)(m)
#endif /* DEBUG_WOLFSSL | OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
          OPENSSL_EXTRA */

#ifdef WOLFSSL_VERBOSE_ERRORS
#define WOLFSSL_ERROR_VERBOSE(e) WOLFSSL_ERROR(e)
#else
#define WOLFSSL_ERROR_VERBOSE(e) (void)(e)
#endif /* WOLFSSL_VERBOSE_ERRORS */

#ifdef HAVE_STACK_SIZE_VERBOSE
    extern WOLFSSL_API THREAD_LS_T unsigned char *StackSizeCheck_myStack;
    extern WOLFSSL_API THREAD_LS_T size_t StackSizeCheck_stackSize;
    extern WOLFSSL_API THREAD_LS_T size_t StackSizeCheck_stackSizeHWM;
    extern WOLFSSL_API THREAD_LS_T size_t *StackSizeCheck_stackSizeHWM_ptr;
    extern WOLFSSL_API THREAD_LS_T void *StackSizeCheck_stackOffsetPointer;
#endif

/* Port-specific includes and printf methods: */

#if defined(ARDUINO)
    /* implemented in Arduino wolfssl.h */
    extern WOLFSSL_API int wolfSSL_Arduino_Serial_Print(const char* const s);
#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    /* see wc_port.h for fio.h and nio.h includes */
#elif defined(WOLFSSL_SGX)
    /* Declare sprintf for ocall */
    int sprintf(char* buf, const char *fmt, ...);
#elif defined(WOLFSSL_DEOS)
#elif defined(MICRIUM)
    #if (BSP_SER_COMM_EN  == DEF_ENABLED)
        #include <bsp_ser.h>
    #endif
#elif defined(WOLFSSL_USER_LOG)
    /* user includes their own headers */
#elif defined(WOLFSSL_ESPIDF)
    #include "esp_types.h"
    #include "esp_log.h"
#elif defined(WOLFSSL_TELIT_M2MB)
    #include <stdio.h>
    #include "m2m_log.h"
#elif defined(WOLFSSL_ANDROID_DEBUG)
    #include <android/log.h>
#elif defined(WOLFSSL_XILINX)
    #include "xil_printf.h"
#elif defined(WOLFSSL_LINUXKM)
    /* the requisite linux/kernel.h is included in linuxkm_wc_port.h, with
     * incompatible warnings masked out.
     */
#elif defined(WOLFSSL_BSDKM)
    /* see bsdkm/bsdkm_wc_port.h for includes and defines. */
#elif defined(FUSION_RTOS)
    #include <fclstdio.h>
    #define fprintf FCL_FPRINTF
#else
    #include <stdio.h>  /* for default printf stuff */
#endif

#if defined(THREADX) && !defined(THREADX_NO_DC_PRINTF)
    int dc_log_printf(char*, ...);
#endif

/* WOLFSSL_DEBUG_PRINTF_FN is intended to be used only in wolfssl_log(),
 * but is exposed in header as a customer cross-platform debugging capability.
 *
 * All general wolfSSL debugging should use:
 *   WOLFSSL_MSG and WOLFSSL_MSG_EX
 *
 * All wolfSSL certificate-related debugging should use:
 *   WOLFSSL_MSG_CERT and WOLFSSL_MSG_CERT_EX
 *
 * For custom debugging output, define your own WOLFSSL_DEBUG_PRINTF_FN
 */
#ifdef WOLFSSL_DEBUG_PRINTF_FN
    /* user-supplied definition */
#elif defined(ARDUINO)
    /* ARDUINO only has print and sprintf, no printf. */
#elif defined(__WATCOMC__)
    #if defined(DEBUG_WOLFSSL) || defined(WOLFSSL_DEBUG_CERTS)
        #include <stdio.h>
        #define WOLFSSL_DEBUG_PRINTF_FN printf
    #else
        /* Watcom does not support variadic macros; we need a no-op function */
        static int WOLFSSL_DEBUG_PRINTF(const char* fmt, ...)
        {
            (void)fmt;
            return NOT_COMPILED_IN;
        }
    #endif /* __WATCOMC__ */
#elif defined(WOLFSSL_LOG_PRINTF) || defined(WOLFSSL_DEOS)
    #define WOLFSSL_DEBUG_PRINTF_FN printf
#elif defined(THREADX) && !defined(THREADX_NO_DC_PRINTF)
    #define WOLFSSL_DEBUG_PRINTF_FN dc_log_printf
#elif defined(MICRIUM)
    #define WOLFSSL_DEBUG_PRINTF_FN BSP_Ser_Printf
#elif defined(WOLFSSL_MDK_ARM)
    #define WOLFSSL_DEBUG_PRINTF_FN printf
#elif defined(WOLFSSL_UTASKER)
    /* WOLFSSL_UTASKER only has fnDebugMsg and related primitives, no printf. */
#elif defined(MQX_USE_IO_OLD)
    #define WOLFSSL_DEBUG_PRINTF_FN fprintf
    #define WOLFSSL_DEBUG_PRINTF_FIRST_ARGS _mqxio_stderr,
#elif defined(WOLFSSL_APACHE_MYNEWT)
    #define WOLFSSL_DEBUG_PRINTF_FN LOG_DEBUG
    #define WOLFSSL_DEBUG_PRINTF_FIRST_ARGS &mynewt_log, LOG_MODULE_DEFAULT,
#elif defined(WOLFSSL_ESPIDF)
    #define WOLFSSL_DEBUG_PRINTF_FN ESP_LOGI
    #define WOLFSSL_DEBUG_PRINTF_FIRST_ARGS "wolfssl",
#elif defined(WOLFSSL_ZEPHYR)
    #define WOLFSSL_DEBUG_PRINTF_FN printk
#elif defined(WOLFSSL_TELIT_M2MB)
    #define WOLFSSL_DEBUG_PRINTF_FN M2M_LOG_INFO
#elif defined(WOLFSSL_ANDROID_DEBUG)
    #define WOLFSSL_DEBUG_PRINTF_FN __android_log_print
    #define WOLFSSL_DEBUG_PRINTF_FIRST_ARGS ANDROID_LOG_VERBOSE, "[wolfSSL]",
#elif defined(WOLFSSL_XILINX)
    #define WOLFSSL_DEBUG_PRINTF_FN xil_printf
#elif defined(WOLFSSL_LINUXKM)
    #define WOLFSSL_DEBUG_PRINTF_FN printk
#elif defined(WOLFSSL_RENESAS_RA6M4)
    #define WOLFSSL_DEBUG_PRINTF_FN myprintf
#elif defined(NO_STDIO_FILESYSTEM)
    #define WOLFSSL_DEBUG_PRINTF_FN printf
#else
    #define WOLFSSL_DEBUG_PRINTF_FN fprintf
    #define WOLFSSL_DEBUG_PRINTF_FIRST_ARGS stderr,
#endif

#ifndef WOLFSSL_DEBUG_PRINTF_FIRST_ARGS
    #define WOLFSSL_DEBUG_PRINTF_FIRST_ARGS
#endif

#if defined(WOLFSSL_DEBUG_PRINTF_FN) && !defined(WOLFSSL_DEBUG_PRINTF)
    #if defined(WOLF_NO_VARIADIC_MACROS)
        #define WOLFSSL_DEBUG_PRINTF(a) \
            WOLFSSL_DEBUG_PRINTF_FN(WOLFSSL_DEBUG_PRINTF_FIRST_ARGS a)
    #else
        #define WOLFSSL_DEBUG_PRINTF(...) \
            WOLFSSL_DEBUG_PRINTF_FN(WOLFSSL_DEBUG_PRINTF_FIRST_ARGS __VA_ARGS__)
    #endif
#endif

/* Sanity Checks */
#if defined(WOLFSSL_DEBUG_ERRORS_ONLY) && defined(DEBUG_WOLFSSL)
    #error "Failed: WOLFSSL_DEBUG_ERRORS_ONLY and DEBUG_WOLFSSL pick one"
#endif
#if defined(WOLFSSL_DEBUG_ERRORS_ONLY) && defined(WOLFSSL_DEBUG_CERTS)
    #error "Failed: Cannot WOLFSSL_DEBUG_CERTS with WOLFSSL_DEBUG_ERRORS_ONLY"
#endif

#ifdef __cplusplus
}
#endif
#endif /* WOLFSSL_LOGGING_H */

