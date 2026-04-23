/* IP.h -- clean-room shim for the subset of SEGGER emNET (embOS/IP) API
 * that wolfSSL's WOLFSSL_EMNET port compiles against. Written from the
 * public API surface documented in SEGGER UM07001; contains no SEGGER
 * source.
 *
 * Scope: enough to build wolfSSL with -DWOLFSSL_EMNET on a POSIX host
 * for CI test purposes. Only error constants and IP_SOCK_getsockopt are
 * provided here; the runtime behaviour of send/recv under emNET is
 * emulated by emnet_shim.c via linker --wrap.
 */

#ifndef WOLFSSL_EMNET_SHIM_IP_H
#define WOLFSSL_EMNET_SHIM_IP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* emNET error codes (UM07001). Values match the public ABI. */
#define IP_ERR_CONN_ABORTED   (-5)
#define IP_ERR_WOULD_BLOCK    (-6)
#define IP_ERR_CONN_REFUSED   (-7)
#define IP_ERR_CONN_RESET     (-8)
#define IP_ERR_PIPE          (-13)
#define IP_ERR_FAULT         (-25)

/* BSD-style socket option retrieval. Signature matches the SEGGER API:
 * length is passed by pointer of type int*, unlike POSIX socklen_t*. */
int IP_SOCK_getsockopt(int sd, int level, int optname,
                       void *optval, int *optlen);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_EMNET_SHIM_IP_H */
