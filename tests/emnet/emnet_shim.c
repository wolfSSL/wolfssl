/* emnet_shim.c -- POSIX-backed shim for the emNET (embOS/IP) socket ABI
 * used by wolfSSL when WOLFSSL_EMNET is defined.
 *
 * Provides the canonical error lookup path wolfSSL's wolfSSL_LastError
 * relies on: IP_SOCK_getsockopt(SO_ERROR) returns the pending IP_ERR_*
 * for a socket, as required by UM07001's emNET API contract. On top of
 * Linux BSD sockets this is emulated by consulting POSIX SO_ERROR plus
 * the thread-local errno (because Linux does not store transient
 * would-block conditions in SO_ERROR).
 */

#include "IP/IP.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

/* Translate a POSIX errno value into the emNET IP_ERR_* space. */
static int emnet_errno_to_ip_err(int err)
{
    /* Linux, where this shim runs in CI, defines EWOULDBLOCK == EAGAIN,
     * so EAGAIN covers both. */
    switch (err) {
        case EAGAIN:
            return IP_ERR_WOULD_BLOCK;
        case ECONNRESET:
            return IP_ERR_CONN_RESET;
        case ECONNREFUSED:
            return IP_ERR_CONN_REFUSED;
        case ECONNABORTED:
            return IP_ERR_CONN_ABORTED;
        case EPIPE:
            return IP_ERR_PIPE;
        default:
            return IP_ERR_FAULT;
    }
}

/* IP_SOCK_getsockopt: emulates the emNET ABI on top of POSIX. This is
 * the canonical error source for WOLFSSL_EMNET code paths - wolfSSL
 * calls it after a negative recv/send return to retrieve the real
 * IP_ERR_* value.
 *
 * For SO_ERROR we deliberately diverge from a pure POSIX pass-through:
 * Linux stores sticky socket errors (ECONNRESET etc.) in SO_ERROR but
 * does NOT store transient would-block conditions (EAGAIN/EWOULDBLOCK)
 * there - those live only in thread-local errno after the failing
 * syscall. Real emNET's SO_ERROR does carry would-block. To reproduce
 * that contract here, read POSIX SO_ERROR first, fall back to errno
 * when SO_ERROR is empty, then translate into the IP_ERR_* space. */
int IP_SOCK_getsockopt(int hSock, int Level, int Name,
                       void *pVal, int ValLen)
{
    if (pVal == NULL || ValLen <= 0) {
        errno = EINVAL;
        return -1;
    }

    if (Level == SOL_SOCKET && Name == SO_ERROR
            && ValLen >= (int)sizeof(int)) {
        int       saved_errno = errno;
        int       so_err      = 0;
        socklen_t posix_len   = (socklen_t)sizeof(so_err);
        int       ip_err;

        (void)getsockopt(hSock, SOL_SOCKET, SO_ERROR, &so_err, &posix_len);
        if (so_err == 0)
            so_err = saved_errno;

        ip_err = emnet_errno_to_ip_err(so_err);
        memcpy(pVal, &ip_err, sizeof(ip_err));
        return 0;
    }

    /* Pass-through for other options. */
    {
        socklen_t posix_len = (socklen_t)ValLen;
        return getsockopt(hSock, Level, Name, pVal, &posix_len);
    }
}
