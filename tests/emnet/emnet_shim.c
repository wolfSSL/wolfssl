/* emnet_shim.c -- POSIX-backed shim for the emNET (embOS/IP) socket ABI
 * used by wolfSSL when WOLFSSL_EMNET is defined.
 *
 * The goal is to reproduce the error-reporting contract of emNET on top
 * of stock Linux BSD sockets: when the underlying socket signals
 * would-block, connection reset, etc., the shim surfaces the
 * corresponding IP_ERR_* negative constant (emNET convention) instead
 * of -1/errno (POSIX convention). This is exactly what wolfSSL's
 * WOLFSSL_EMNET branch in wolfio.h/wolfio.c was written to consume, so
 * CI can drive the non-blocking handshake paths without the real
 * SEGGER stack.
 *
 * Linker wrapping:
 *   -Wl,--wrap=recv,--wrap=send
 * hooks wolfSSL's RECV_FUNCTION/SEND_FUNCTION (which are the
 * unqualified POSIX send/recv on the WOLFSSL_EMNET build) without
 * patching any wolfSSL source.
 */

#include "IP/IP.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

/* Forward declarations for the linker's --wrap mechanism. */
ssize_t __real_recv(int sd, void *buf, size_t len, int flags);
ssize_t __real_send(int sd, const void *buf, size_t len, int flags);

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

/* recv wrapper: preserve success/close semantics; on error return the
 * emNET-style negative error code in place of -1/errno. wolfSSL's
 * TranslateIoReturnCode uses err < 0 to branch into error handling and
 * then compares against SOCKET_EWOULDBLOCK == IP_ERR_WOULD_BLOCK. */
ssize_t __wrap_recv(int sd, void *buf, size_t len, int flags)
{
    ssize_t ret = __real_recv(sd, buf, len, flags);
    if (ret < 0) {
        return (ssize_t)emnet_errno_to_ip_err(errno);
    }
    return ret;
}

ssize_t __wrap_send(int sd, const void *buf, size_t len, int flags)
{
    ssize_t ret = __real_send(sd, buf, len, flags);
    if (ret < 0) {
        return (ssize_t)emnet_errno_to_ip_err(errno);
    }
    return ret;
}

/* IP_SOCK_getsockopt: kept to satisfy the emNET ABI surface expected
 * by WOLFSSL_EMNET-linked code. Delegates to POSIX getsockopt and, for
 * SO_ERROR, maps the returned POSIX errno value into emNET's IP_ERR_*
 * space so callers see emNET-style error reporting. */
int IP_SOCK_getsockopt(int sd, int level, int optname,
                       void *optval, int *optlen)
{
    socklen_t posix_len;
    int rc;

    if (optlen == NULL) {
        errno = EINVAL;
        return -1;
    }
    posix_len = (socklen_t)*optlen;
    rc = getsockopt(sd, level, optname, optval, &posix_len);
    *optlen = (int)posix_len;

    if (rc == 0 && level == SOL_SOCKET && optname == SO_ERROR
            && optval != NULL && posix_len >= (socklen_t)sizeof(int)) {
        int so_err;
        memcpy(&so_err, optval, sizeof(so_err));
        if (so_err != 0) {
            so_err = emnet_errno_to_ip_err(so_err);
            memcpy(optval, &so_err, sizeof(so_err));
        }
    }
    return rc;
}
