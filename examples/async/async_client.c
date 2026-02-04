/* async_client.c
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

/* TLS client demonstrating asynchronous cryptography features and non-blocking
 * operation using WOLFSSL_USER_IO callbacks. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* std */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* socket */
#ifndef NET_USER_HEADER
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#endif

/* wolfSSL */
#ifdef WOLFSSL_USER_SETTINGS
    #include "user_settings.h"
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/certs_test.h>
#include "examples/async/async_tls.h"

/* ------------------------------------------------------------------ */
/* POSIX transport helpers (replace with your BSP/port layer).         */
/* ------------------------------------------------------------------ */
#ifndef NET_USER_HEADER
static int posix_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int posix_connect_nonblock(int fd, const struct sockaddr* sa,
                                  socklen_t sa_len, int timeout_ms)
{
    int ret = connect(fd, sa, sa_len);
    if (ret == 0) {
        return 0;
    }
    if (ret < 0 && errno != EINPROGRESS) {
        return -1;
    }

    /* Wait for connect to finish. */
    fd_set wfds;
    struct timeval tv;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    ret = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
        return -1;
    }
    if (FD_ISSET(fd, &wfds)) {
        int so_err = 0;
        socklen_t len = sizeof(so_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0) {
            return -1;
        }
        if (so_err != 0) {
            errno = so_err;
            return -1;
        }
        return 0;
    }
    return -1;
}

static int posix_net_connect(const char* host, int port)
{
    char port_str[8];
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* it = NULL;
    int fd = -1;
    int ret;

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (posix_set_nonblocking(fd) != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        ret = posix_connect_nonblock(fd, it->ai_addr,
                                     (socklen_t)it->ai_addrlen, 5000);
        if (ret == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    if (res != NULL) {
        freeaddrinfo(res);
    }
    return fd;
}
#endif

/* ------------------------------------------------------------------ */
/* WOLFSSL_USER_IO callbacks.                                          */
/* ------------------------------------------------------------------ */
static void usage(const char* prog)
{
    printf("usage: %s [--ecc|--x25519] [--mutual] [--tls12] [host] [port]\n",
        prog);
}

static const char* group_name(word16 group)
{
    switch (group) {
        case WOLFSSL_ECC_SECP256R1:
            return "secp256r1";
        case WOLFSSL_ECC_X25519:
            return "x25519";
        default:
            return "unknown";
    }
}

static int parse_client_args(int argc, char** argv,
    const char** host, int* port, word16* group, int* mutual, int* tls12)
{
    int i;
    int host_set = 0;
    int port_set = 0;

    *host = DEFAULT_TLS_HOST;
    *port = DEFAULT_TLS_PORT;
    *group = WOLFSSL_ECC_SECP256R1;
    *mutual = 0;
    *tls12 = 0;

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "--ecc") == 0) {
            *group = WOLFSSL_ECC_SECP256R1;
        }
        else if (XSTRCMP(argv[i], "--x25519") == 0) {
            *group = WOLFSSL_ECC_X25519;
        }
        else if (XSTRCMP(argv[i], "--mutual") == 0) {
            *mutual = 1;
        }
        else if (XSTRCMP(argv[i], "--tls12") == 0) {
            *tls12 = 1;
        }
        else if (XSTRCMP(argv[i], "--help") == 0) {
            return -1;
        }
        else if (!host_set) {
            *host = argv[i];
            host_set = 1;
        }
        else if (!port_set) {
            *port = atoi(argv[i]);
            port_set = 1;
        }
        else {
            return -1;
        }
    }

    return 0;
}

int client_async_test(int argc, char** argv)
{
    int ret = -1;
    int net = -1;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char rx[128];
    char tx[256];
    int tx_len = 0;
    int err = 0;
#ifdef WOLFSSL_ASYNC_CRYPT
    int devId = INVALID_DEVID;
#endif
#ifdef WOLFSSL_DEBUG_NONBLOCK
    int wouldblock_count = 0;
    int pending_count = 0;
#endif
    const char* host = NULL;
    int port = 0;
    word16 group = WOLFSSL_ECC_SECP256R1;
    const char* mode = NULL;
    int mutual = 0;
    int tls12 = 0;

    if (parse_client_args(argc, argv, &host, &port, &group, &mutual,
            &tls12) != 0) {
        usage(argv[0]);
        return 0;
    }
    mode = group_name(group);
    printf("Async client mode: %s, TLS %s%s\n", mode,
        tls12 ? "1.2" : "1.3", mutual ? ", mutual auth" : "");

    {
        const char* ready = getenv(WOLFSSL_ASYNC_READYFILE_ENV);
        if (ready != NULL) {
            (void)async_readyfile_wait(ready,
                WOLFSSL_ASYNC_READYFILE_TIMEOUT_MS);
        }
    }
    net = NET_CONNECT(host, port);
    if (net < 0) {
        return -1;
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return -1;
    }
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    if (wolfAsync_DevOpenThread(&devId, NULL) != 0) {
        goto out;
    }
#endif

#ifndef WOLFSSL_NO_TLS12
    if (tls12)
        ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    else
#endif
        ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        goto out;
    }
#ifdef WOLFSSL_ASYNC_CRYPT
    wolfSSL_CTX_SetDevId(ctx, devId);
#endif

    if (mutual) {
        if (group == WOLFSSL_ECC_X25519) {
        #ifdef HAVE_ED25519
            ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_ed25519_cert,
                sizeof_ca_ed25519_cert, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: failed to load ED25519 CA cert.\n");
                goto out;
            }
            ret = wolfSSL_CTX_use_certificate_buffer(ctx, client_ed25519_cert,
                sizeof_client_ed25519_cert, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: failed to load ED25519 client cert.\n");
                goto out;
            }
            ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, client_ed25519_key,
                sizeof_client_ed25519_key, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: failed to load ED25519 client key.\n");
                goto out;
            }
        #else
            fprintf(stderr,
                "ERROR: --x25519 --mutual requires HAVE_ED25519\n");
            goto out;
        #endif
        }
        else {
            ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_ecc_cert_der_256,
                sizeof_ca_ecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: failed to load ECC CA cert.\n");
                goto out;
            }
            ret = wolfSSL_CTX_use_certificate_buffer(ctx, cliecc_cert_der_256,
                sizeof_cliecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: failed to load ECC client cert.\n");
                goto out;
            }
            ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, ecc_clikey_der_256,
                sizeof_ecc_clikey_der_256, WOLFSSL_FILETYPE_ASN1);
            if (ret != WOLFSSL_SUCCESS) {
                fprintf(stderr, "ERROR: failed to load ECC client key.\n");
                goto out;
            }
        }
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    }
    else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    }

    wolfSSL_SetIORecv(ctx, NET_IO_RECV_CB);
    wolfSSL_SetIOSend(ctx, NET_IO_SEND_CB);

    wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, host,
        (word16)XSTRLEN(host));

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        goto out;
    }

    wolfSSL_SetIOReadCtx(ssl, (void*)(intptr_t)net);
    wolfSSL_SetIOWriteCtx(ssl, (void*)(intptr_t)net);
    (void)wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host,
        (word16)XSTRLEN(host));

    /* UseKeyShare is TLS 1.3 only */
    if (!tls12) {
        for (;;) {
            ret = wolfSSL_UseKeyShare(ssl, group);
            if (ret == WOLFSSL_SUCCESS) {
                break;
            }
            if (ret == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                    goto out;
                }
#endif
                continue;
            }
            goto out;
        }
    }

    /* Non-blocking style loop. */
    for (;;) {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS) {
            break;
        }
        err = wolfSSL_get_error(ssl, 0);
        if (err == WC_NO_ERR_TRACE(WC_PENDING_E) ||
            err == WOLFSSL_ERROR_WANT_READ ||
            err == WOLFSSL_ERROR_WANT_WRITE) {
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                    goto out;
                }
#endif
            }
            else {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                wouldblock_count++;
#endif
            }
            continue;
        }
        fprintf(stderr, "ERROR: wolfSSL_connect failed: %d (%s)\n",
            err, wolfSSL_ERR_reason_error_string(err));
        goto out;
    }

    {
        const char* cipher = wolfSSL_get_cipher_name(ssl);
        const char* curve = wolfSSL_get_curve_name(ssl);
        printf("Negotiated cipher: %s\n", cipher != NULL ? cipher : "unknown");
        printf("Negotiated group: %s\n", curve != NULL ? curve : "unknown");
    }

    tx_len = XSNPRINTF(tx, sizeof(tx),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: wolfSSL-async\r\n"
        "Connection: close\r\n"
        "\r\n",
        host);
    if (tx_len <= 0 || tx_len >= (int)sizeof(tx)) {
        goto out;
    }

    for (;;) {
        ret = wolfSSL_write(ssl, tx, tx_len);
        if (ret > 0) {
            break;
        }
        err = wolfSSL_get_error(ssl, 0);
        if (err == WC_NO_ERR_TRACE(WC_PENDING_E) ||
            err == WOLFSSL_ERROR_WANT_READ ||
            err == WOLFSSL_ERROR_WANT_WRITE) {
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                    goto out;
                }
#endif
            }
            else {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                wouldblock_count++;
#endif
            }
            continue;
        }
        goto out;
    }

    XMEMSET(rx, 0, sizeof(rx));
    for (;;) {
        ret = wolfSSL_read(ssl, rx, (int)sizeof(rx) - 1);
        if (ret > 0) {
            rx[ret] = '\0';
            printf("RX: %s\n", rx);
            break;
        }
        err = wolfSSL_get_error(ssl, 0);
        if (err == WC_NO_ERR_TRACE(WC_PENDING_E) ||
            err == WOLFSSL_ERROR_WANT_READ ||
            err == WOLFSSL_ERROR_WANT_WRITE) {
            if (err == WC_NO_ERR_TRACE(WC_PENDING_E)) {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                pending_count++;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                if (wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW) < 0) {
                    goto out;
                }
#endif
            }
            else {
#ifdef WOLFSSL_DEBUG_NONBLOCK
                wouldblock_count++;
#endif
            }
            continue;
        }
        goto out;
    }

#ifdef WOLFSSL_DEBUG_NONBLOCK
    printf("WANT_READ/WRITE count: %d\n", wouldblock_count);
    printf("WC_PENDING_E count: %d\n", pending_count);
#endif
    ret = 0;

out:
    if (ssl != NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
    }
#ifdef WOLFSSL_ASYNC_CRYPT
    if (devId != INVALID_DEVID) {
        wolfAsync_DevClose(&devId);
    }
#endif
    wolfSSL_Cleanup();
    if (net >= 0) {
        NET_CLOSE(net);
    }

    return ret;
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    return client_async_test(argc, argv);
}
#endif /* !NO_MAIN_DRIVER */
