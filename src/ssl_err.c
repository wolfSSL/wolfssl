/* ssl_err.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_SSL_ERR_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_err.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY

/* Get the string describing an error value.
 *
 * When data is NULL, a static buffer is used and the string is overwritten by
 * the next call that passes NULL.
 *
 * @param [in]      errNumber  Error value.
 * @param [in, out] data       Buffer to hold string. Must be at least
 *                             WOLFSSL_MAX_ERROR_SZ bytes. May be NULL.
 * @return  Buffer holding string.
 */
char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data)
{
    WOLFSSL_ENTER("wolfSSL_ERR_error_string");
    if (data) {
        SetErrorString((int)errNumber, data);
        return data;
    }
    else {
        static char tmp[WOLFSSL_MAX_ERROR_SZ] = {0};
        SetErrorString((int)errNumber, tmp);
        return tmp;
    }
}

/* Get the string describing an error value into a buffer of limited size.
 *
 * String is truncated to fit, including the NUL terminator.
 *
 * @param [in]      e    Error value.
 * @param [in, out] buf  Buffer to hold string.
 * @param [in]      len  Length of buffer in bytes.
 */
void wolfSSL_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
    WOLFSSL_ENTER("wolfSSL_ERR_error_string_n");
    if (len >= WOLFSSL_MAX_ERROR_SZ)
        wolfSSL_ERR_error_string(e, buf);
    else {
        WOLFSSL_MSG("Error buffer too short, truncating");
        if (len) {
            char tmp[WOLFSSL_MAX_ERROR_SZ];
            wolfSSL_ERR_error_string(e, tmp);
            XMEMCPY(buf, tmp, len-1);
            buf[len-1] = '\0';
        }
    }
}

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) \
    && defined(XFPRINTF)
/* Print the string describing an error value to a file.
 *
 * @param [in] fp   File to print to.
 * @param [in] err  Error value.
 */
void wolfSSL_ERR_print_errors_fp(XFILE fp, int err)
{
    char data[WOLFSSL_MAX_ERROR_SZ + 1];

    WOLFSSL_ENTER("wolfSSL_ERR_print_errors_fp");
    SetErrorString(err, data);
    if (XFPRINTF(fp, "%s", data) < 0)
        WOLFSSL_MSG("fprintf failed in wolfSSL_ERR_print_errors_fp");
}

#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
/* Print the entries of the error queue to a file.
 *
 * @param [in] fp  File to print to.
 */
void wolfSSL_ERR_dump_errors_fp(XFILE fp)
{
    wc_ERR_print_errors_fp(fp);
}

/* Pass the entries of the error queue to a callback.
 *
 * @param [in] cb  Callback to pass each error string to.
 * @param [in] u   Context to pass to the callback.
 */
void wolfSSL_ERR_print_errors_cb (int (*cb)(const char *str, size_t len,
                                            void *u), void *u)
{
    wc_ERR_print_errors_cb(cb, u);
}
#endif
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED)
    /* Get the last error value from the error queue and remove it.
     *
     * @return  Error value on success.
     * @return  0 when there is no error queue.
     */
    unsigned long wolfSSL_ERR_get_error(void)
    {
        WOLFSSL_ENTER("wolfSSL_ERR_get_error");
#ifdef WOLFSSL_HAVE_ERROR_QUEUE
        return (unsigned long)wc_GetErrorNodeErr();
#else
        return 0;
#endif
    }
#endif

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
#ifdef WOLFSSL_HAVE_ERROR_QUEUE
#ifndef NO_BIO
    /* Print the entries of the error queue to a BIO.
     *
     * Entries are removed from the queue as they are printed.
     *
     * @param [in, out] bio  BIO to print to.
     */
    void wolfSSL_ERR_print_errors(WOLFSSL_BIO* bio)
    {
        const char* file = NULL;
        const char* reason = NULL;
        int ret;
        int line = 0;
        char buf[WOLFSSL_MAX_ERROR_SZ * 2];

        WOLFSSL_ENTER("wolfSSL_ERR_print_errors");

        if (bio == NULL) {
            WOLFSSL_MSG("BIO passed in was null");
            return;
        }

        do {
        ret = wc_PeekErrorNode(0, &file, &reason, &line);
        if (ret >= 0) {
            const char* r = wolfSSL_ERR_reason_error_string(
                (unsigned long)(0 - ret));
            if (XSNPRINTF(buf, sizeof(buf),
                          "error:%d:wolfSSL library:%s:%s:%d\n",
                          ret, r, file, line)
                >= (int)sizeof(buf))
            {
                WOLFSSL_MSG("Buffer overrun formatting error message");
            }
            wolfSSL_BIO_write(bio, buf, (int)XSTRLEN(buf));
            wc_RemoveErrorNode(0);
        }
        } while (ret >= 0);
        if (wolfSSL_BIO_write(bio, "", 1) != 1) {
            WOLFSSL_MSG("Issue writing final string terminator");
        }
    }
#endif
#endif
#endif

#ifdef OPENSSL_EXTRA
    /* Free the error strings.
     *
     * Error strings are handled internally. For OpenSSL compatibility only.
     */
    void wolfSSL_ERR_free_strings(void)
    {
        /* handled internally */
    }
#endif

#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE) || \
    defined(HAVE_CURL)
    /* Remove all entries from the error queue.
     */
    void wolfSSL_ERR_clear_error(void)
    {
        WOLFSSL_ENTER("wolfSSL_ERR_clear_error");
    #if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
        wc_ClearErrorNodes();
    #endif
    }
#endif

#ifdef OPENSSL_EXTRA
    /* Get the last error value from the error queue with its file and line.
     *
     * Entry is removed from the queue.
     *
     * @param [out] file  Name of file error occurred in.
     * @param [out] line  Line number error occurred on.
     * @return  Error value on success.
     * @return  0 when there are no entries in the queue or there is no error
     *          queue.
     */
    unsigned long wolfSSL_ERR_get_error_line(const char** file, int* line)
    {
    #ifdef WOLFSSL_HAVE_ERROR_QUEUE
        int ret = wc_PullErrorNode(file, NULL, line);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(BAD_STATE_E))
                return 0; /* no errors in queue */
            WOLFSSL_MSG("Issue getting error node");
            WOLFSSL_LEAVE("wolfSSL_ERR_get_error_line", ret);
            ret = 0 - ret; /* return absolute value of error */

            /* panic and try to clear out nodes */
            wc_ClearErrorNodes();
        }
        return (unsigned long)ret;
    #else
        (void)file;
        (void)line;

        return 0;
    #endif
    }

#if (defined(DEBUG_WOLFSSL) || defined(OPENSSL_EXTRA)) && \
    (!defined(_WIN32) && !defined(NO_ERROR_QUEUE))
    static const char WOLFSSL_SYS_ACCEPT_T[]  = "accept";
    static const char WOLFSSL_SYS_BIND_T[]    = "bind";
    static const char WOLFSSL_SYS_CONNECT_T[] = "connect";
    static const char WOLFSSL_SYS_FOPEN_T[]   = "fopen";
    static const char WOLFSSL_SYS_FREAD_T[]   = "fread";
    static const char WOLFSSL_SYS_GETADDRINFO_T[] = "getaddrinfo";
    static const char WOLFSSL_SYS_GETSOCKOPT_T[]  = "getsockopt";
    static const char WOLFSSL_SYS_GETSOCKNAME_T[] = "getsockname";
    static const char WOLFSSL_SYS_GETHOSTBYNAME_T[] = "gethostbyname";
    static const char WOLFSSL_SYS_GETNAMEINFO_T[]   = "getnameinfo";
    static const char WOLFSSL_SYS_GETSERVBYNAME_T[] = "getservbyname";
    static const char WOLFSSL_SYS_IOCTLSOCKET_T[]   = "ioctlsocket";
    static const char WOLFSSL_SYS_LISTEN_T[]        = "listen";
    static const char WOLFSSL_SYS_OPENDIR_T[]       = "opendir";
    static const char WOLFSSL_SYS_SETSOCKOPT_T[]    = "setsockopt";
    static const char WOLFSSL_SYS_SOCKET_T[]        = "socket";

    /* Get the name of a system function.
     *
     * Maps the int identifier to a function name for compatibility.
     *
     * @param [in] fun  System function identifier. WOLFSSL_SYS_*.
     * @return  Name of function on success.
     * @return  "NULL" when the identifier is not known.
     */
    static const char* wolfSSL_ERR_sys_func(int fun)
    {
        switch (fun) {
            case WOLFSSL_SYS_ACCEPT:      return WOLFSSL_SYS_ACCEPT_T;
            case WOLFSSL_SYS_BIND:        return WOLFSSL_SYS_BIND_T;
            case WOLFSSL_SYS_CONNECT:     return WOLFSSL_SYS_CONNECT_T;
            case WOLFSSL_SYS_FOPEN:       return WOLFSSL_SYS_FOPEN_T;
            case WOLFSSL_SYS_FREAD:       return WOLFSSL_SYS_FREAD_T;
            case WOLFSSL_SYS_GETADDRINFO: return WOLFSSL_SYS_GETADDRINFO_T;
            case WOLFSSL_SYS_GETSOCKOPT:  return WOLFSSL_SYS_GETSOCKOPT_T;
            case WOLFSSL_SYS_GETSOCKNAME: return WOLFSSL_SYS_GETSOCKNAME_T;
            case WOLFSSL_SYS_GETHOSTBYNAME: return WOLFSSL_SYS_GETHOSTBYNAME_T;
            case WOLFSSL_SYS_GETNAMEINFO: return WOLFSSL_SYS_GETNAMEINFO_T;
            case WOLFSSL_SYS_GETSERVBYNAME: return WOLFSSL_SYS_GETSERVBYNAME_T;
            case WOLFSSL_SYS_IOCTLSOCKET: return WOLFSSL_SYS_IOCTLSOCKET_T;
            case WOLFSSL_SYS_LISTEN:      return WOLFSSL_SYS_LISTEN_T;
            case WOLFSSL_SYS_OPENDIR:     return WOLFSSL_SYS_OPENDIR_T;
            case WOLFSSL_SYS_SETSOCKOPT:  return WOLFSSL_SYS_SETSOCKOPT_T;
            case WOLFSSL_SYS_SOCKET:      return WOLFSSL_SYS_SOCKET_T;
            default:
                return "NULL";
        }
    }
#endif

    /* Add an error to the error queue.
     *
     * @param [in] lib   Library the error occurred in. Not used.
     * @param [in] fun   System function the error occurred in. WOLFSSL_SYS_*.
     * @param [in] err   Error value.
     * @param [in] file  Name of file the error occurred in.
     * @param [in] line  Line number the error occurred on.
     */
    void wolfSSL_ERR_put_error(int lib, int fun, int err, const char* file,
            int line)
    {
        WOLFSSL_ENTER("wolfSSL_ERR_put_error");

        #if !defined(DEBUG_WOLFSSL) && !defined(OPENSSL_EXTRA)
        (void)fun;
        (void)err;
        (void)file;
        (void)line;
        WOLFSSL_MSG("Not compiled in debug mode");
        #elif defined(OPENSSL_EXTRA) && \
                (defined(_WIN32) || defined(NO_ERROR_QUEUE))
        (void)fun;
        (void)file;
        (void)line;
        WOLFSSL_ERROR(err);
        #else
        WOLFSSL_ERROR_LINE(err, wolfSSL_ERR_sys_func(fun), (unsigned int)line,
            file, NULL);
        #endif
        (void)lib;
    }

    /* Get the last error value from the error queue with its data.
     *
     * Entry is removed from the queue. Similar to
     * wolfSSL_ERR_get_error_line() but takes a flags argument for more
     * flexibility.
     *
     * @param [out] file   Name of file error occurred in.
     * @param [out] line   Line number error occurred on.
     * @param [out] data   Error data. A string when the WOLFSSL_ERR_TXT_STRING
     *                     flag is returned.
     * @param [out] flags  Format of data. WOLFSSL_ERR_TXT_STRING.
     * @return  Error value on success.
     * @return  0 when there are no entries in the queue or there is no error
     *          queue.
     */
    unsigned long wolfSSL_ERR_get_error_line_data(const char** file, int* line,
                                                  const char** data, int *flags)
    {
#ifdef WOLFSSL_HAVE_ERROR_QUEUE
        int ret;

        WOLFSSL_ENTER("wolfSSL_ERR_get_error_line_data");

        if (flags != NULL)
            *flags = WOLFSSL_ERR_TXT_STRING; /* Clear the flags */

        ret = wc_PullErrorNode(file, data, line);
        if (ret < 0) {
            if (ret == WC_NO_ERR_TRACE(BAD_STATE_E))
                return 0; /* no errors in queue */
            WOLFSSL_MSG("Error with pulling error node!");
            WOLFSSL_LEAVE("wolfSSL_ERR_get_error_line_data", ret);
            ret = 0 - ret; /* return absolute value of error */

            /* panic and try to clear out nodes */
            wc_ClearErrorNodes();
        }

        return (unsigned long)ret;
#else
        WOLFSSL_ENTER("wolfSSL_ERR_get_error_line_data");
        WOLFSSL_MSG("Error queue turned off, can not get error line");
        (void)file;
        (void)line;
        (void)data;
        (void)flags;
        return 0;
#endif
    }

/* Get the last error value from the error queue without removing it.
 *
 * @return  Error value on success.
 * @return  0 when there are no entries in the queue.
 */
unsigned long wolfSSL_ERR_peek_error(void)
{
    WOLFSSL_ENTER("wolfSSL_ERR_peek_error");

    return wolfSSL_ERR_peek_error_line_data(NULL, NULL, NULL, NULL);
}

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES_H
#include <wolfssl/debug-untrace-error-codes.h>
#endif

/* Get the library that an error value belongs to.
 *
 * @param [in] err  Error value.
 * @return  WOLFSSL_ERR_LIB_* value on success.
 * @return  WOLFSSL_ERR_LIB_SSL when the library is not identifiable.
 */
int wolfSSL_ERR_GET_LIB(unsigned long err)
{
    unsigned long value;

    value = (err & 0xFFFFFFL);
    switch (value) {
    case -PARSE_ERROR:
        return WOLFSSL_ERR_LIB_SSL;
    case -ASN_NO_PEM_HEADER:
    case -WOLFSSL_PEM_R_NO_START_LINE_E:
    case -WOLFSSL_PEM_R_PROBLEMS_GETTING_PASSWORD_E:
    case -WOLFSSL_PEM_R_BAD_PASSWORD_READ_E:
    case -WOLFSSL_PEM_R_BAD_DECRYPT_E:
        return WOLFSSL_ERR_LIB_PEM;
    case -WOLFSSL_EVP_R_BAD_DECRYPT_E:
    case -WOLFSSL_EVP_R_BN_DECODE_ERROR:
    case -WOLFSSL_EVP_R_DECODE_ERROR:
    case -WOLFSSL_EVP_R_PRIVATE_KEY_DECODE_ERROR:
        return WOLFSSL_ERR_LIB_EVP;
    case -WOLFSSL_ASN1_R_HEADER_TOO_LONG_E:
        return WOLFSSL_ERR_LIB_ASN1;
    default:
        return 0;
    }
}

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES
#include <wolfssl/debug-trace-error-codes.h>
#endif

/* This function is to find global error values that are the same through out
 * all library version. With wolfSSL having only one set of error codes the
 * return value is pretty straight forward. The only thing needed is all wolfSSL
 * error values are typically negative.
 *
 * Returns the error reason
 */
int wolfSSL_ERR_GET_REASON(unsigned long err)
{
    int ret = (int)err;

    WOLFSSL_ENTER("wolfSSL_ERR_GET_REASON");

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
    /* Nginx looks for this error to know to stop parsing certificates.
     * Same for HAProxy. */
    if ((err == (unsigned long)((ERR_LIB_PEM << 24) | PEM_R_NO_START_LINE)) ||
        ((err & 0xFFFFFFL) ==
            (unsigned long)(-WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER))) ||
        ((err & 0xFFFL) == (unsigned long)PEM_R_NO_START_LINE))
        return PEM_R_NO_START_LINE;
    if (err == (unsigned long)((ERR_LIB_SSL << 24) | -SSL_R_HTTP_REQUEST))
        return SSL_R_HTTP_REQUEST;
#endif
#if defined(OPENSSL_ALL) && defined(WOLFSSL_PYTHON)
    if (err == (unsigned long)((ERR_LIB_ASN1 << 24) | ASN1_R_HEADER_TOO_LONG))
        return ASN1_R_HEADER_TOO_LONG;
#endif

    /* check if error value is in range of wolfCrypt or wolfSSL errors */
    ret = 0 - ret; /* setting as negative value */

    if ((ret <= WC_SPAN1_FIRST_E && ret >= WC_SPAN1_LAST_E) ||
        (ret <= WC_SPAN2_FIRST_E && ret >= WC_SPAN2_LAST_E) ||
        (ret <= WOLFSSL_FIRST_E && ret >= WOLFSSL_LAST_E))
    {
        return ret;
    }
    else {
        WOLFSSL_MSG("Not in range of typical error values");
        ret = (int)err;
    }

    return ret;
}

#if !defined(NETOS)
/* Load the SSL error strings.
 *
 * Error strings are handled internally. For OpenSSL compatibility only.
 */
void wolfSSL_ERR_load_SSL_strings(void)
{

}
#endif

/* Get the last error value from the error queue with its file and line
 * without removing it.
 *
 * @param [out] file  Name of file error occurred in.
 * @param [out] line  Line number error occurred on.
 * @return  Error value on success.
 * @return  0 when there are no entries in the queue.
 * @return  0 when there is no error queue.
 */
unsigned long wolfSSL_ERR_peek_last_error_line(const char **file, int *line)
{
    WOLFSSL_ENTER("wolfSSL_ERR_peek_last_error");

    (void)line;
    (void)file;
#ifdef WOLFSSL_HAVE_ERROR_QUEUE
    {
        int ret;

        if ((ret = wc_PeekErrorNode(-1, file, NULL, line)) < 0) {
            WOLFSSL_MSG("Issue peeking at error node in queue");
            return 0;
        }
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) \
        || defined(WOLFSSL_HAPROXY)
        if (ret == -WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER))
            return (ERR_LIB_PEM << 24) | PEM_R_NO_START_LINE;
    #endif
    #if defined(OPENSSL_ALL) && defined(WOLFSSL_PYTHON)
        if (ret == ASN1_R_HEADER_TOO_LONG) {
            return (ERR_LIB_ASN1 << 24) | ASN1_R_HEADER_TOO_LONG;
        }
    #endif
        return (unsigned long)ret;
    }
#else
    return 0;
#endif
}
#endif

#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
     defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
     defined(WOLFSSL_OPENSSH)))
/* Remove the error queue entries of a thread.
 *
 * Not implemented. For OpenSSL compatibility only.
 *
 * @param [in] pid  Thread identifier. Not used.
 */
void wolfSSL_ERR_remove_thread_state(void* pid)
{
    (void) pid;
    return;
}
#endif

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
/* Load the ERR error strings.
 *
 * Error strings are handled internally. For OpenSSL compatibility only.
 *
 * @return  WOLFSSL_SUCCESS always.
 */
int wolfSSL_ERR_load_ERR_strings(void)
{
    return WOLFSSL_SUCCESS;
}

/* Load the crypto error strings.
 *
 * Error strings are handled internally. For OpenSSL compatibility only.
 */
void wolfSSL_ERR_load_crypto_strings(void)
{
    WOLFSSL_ENTER("wolfSSL_ERR_load_crypto_strings");
    /* Do nothing */
    return;
}

#ifndef NO_BIO
/* Load the BIO error strings.
 *
 * Error strings are handled internally. For OpenSSL compatibility only.
 */
void wolfSSL_ERR_load_BIO_strings(void) {
    WOLFSSL_ENTER("wolfSSL_ERR_load_BIO_strings");
    /* do nothing */
}
#endif
#endif

#if defined(OPENSSL_EXTRA)
/* Get the last error value from the error queue without removing it.
 *
 * Some error values are mapped to the OpenSSL equivalent.
 *
 * @return  Error value on success.
 * @return  0 when there are no entries in the queue.
 * @return  0 when there is no error queue.
 */
unsigned long wolfSSL_ERR_peek_last_error(void)
{
    WOLFSSL_ENTER("wolfSSL_ERR_peek_last_error");

#ifdef WOLFSSL_HAVE_ERROR_QUEUE
    {
        int ret;

        if ((ret = wc_PeekErrorNode(-1, NULL, NULL, NULL)) < 0) {
            WOLFSSL_MSG("Issue peeking at error node in queue");
            return 0;
        }
        if (ret == -WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER))
            return (WOLFSSL_ERR_LIB_PEM << 24) |
                -WC_NO_ERR_TRACE(WOLFSSL_PEM_R_NO_START_LINE_E);
    #if defined(WOLFSSL_PYTHON)
        if (ret == ASN1_R_HEADER_TOO_LONG)
            return (WOLFSSL_ERR_LIB_ASN1 << 24) |
                -WC_NO_ERR_TRACE(WOLFSSL_ASN1_R_HEADER_TOO_LONG_E);
    #endif
        return (unsigned long)ret;
    }
#else
    return 0;
#endif
}

/* Determine whether an error value is to be ignored when peeking.
 *
 * @param [in] err  Error value.
 * @return  1 when the error is to be ignored.
 * @return  0 otherwise.
 */
static int peek_ignore_err(int err)
{
  switch(err) {
    case -WC_NO_ERR_TRACE(WANT_READ):
    case -WC_NO_ERR_TRACE(WANT_WRITE):
    case -WC_NO_ERR_TRACE(ZERO_RETURN):
    case -WOLFSSL_ERROR_ZERO_RETURN:
    case -WC_NO_ERR_TRACE(SOCKET_PEER_CLOSED_E):
    case -WC_NO_ERR_TRACE(SOCKET_ERROR_E):
      return 1;
    default:
      return 0;
  }
}

/* Get the last error value from the error queue with its data without
 * removing it.
 *
 * Errors that are not real errors, such as WANT_READ, are skipped.
 *
 * @param [out] file   Name of file error occurred in.
 * @param [out] line   Line number error occurred on.
 * @param [out] data   Error data. Always set to "" when not NULL.
 * @param [out] flags  Format of data. Always set to WOLFSSL_ERR_TXT_STRING
 *                     when not NULL.
 * @return  Error value on success.
 * @return  0 when there are no entries in the queue.
 */
unsigned long wolfSSL_ERR_peek_error_line_data(const char **file, int *line,
                                               const char **data, int *flags)
{
  unsigned long err;

    WOLFSSL_ENTER("wolfSSL_ERR_peek_error_line_data");
    err = wc_PeekErrorNodeLineData(file, line, data, flags, peek_ignore_err);

    if (err == -WC_NO_ERR_TRACE(ASN_NO_PEM_HEADER))
        return (WOLFSSL_ERR_LIB_PEM << 24) |
            -WC_NO_ERR_TRACE(WOLFSSL_PEM_R_NO_START_LINE_E);
#ifdef OPENSSL_ALL
    /* PARSE_ERROR is returned if an HTTP request is detected. */
    else if (err == -WC_NO_ERR_TRACE(PARSE_ERROR))
        /* SSL_R_HTTP_REQUEST */
        return (WOLFSSL_ERR_LIB_SSL << 24) | -WC_NO_ERR_TRACE(PARSE_ERROR);
#endif
#if defined(OPENSSL_ALL) && defined(WOLFSSL_PYTHON)
    else if (err == ASN1_R_HEADER_TOO_LONG)
        return (WOLFSSL_ERR_LIB_ASN1 << 24) |
            -WC_NO_ERR_TRACE(WOLFSSL_ASN1_R_HEADER_TOO_LONG_E);
#endif
  return err;
}

/* Remove the error queue entries of a thread.
 *
 * All entries of the current thread's queue are removed, not just those of the
 * given thread.
 *
 * @param [in] id  Thread identifier. Not used.
 */
void wolfSSL_ERR_remove_state(unsigned long id)
{
    WOLFSSL_ENTER("wolfSSL_ERR_remove_state");
    (void)id;
    if (wc_ERR_remove_state() != 0) {
        WOLFSSL_MSG("Error with removing the state");
    }
}
#endif

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_SSL_ERR_INCLUDED */
