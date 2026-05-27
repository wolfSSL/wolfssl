/* dtls_bench.c
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

/*
 * Single-binary DTLS throughput benchmark over real UDP loopback (or any
 * picked interface).
 *
 *   Server:  ./dtls_bench -s
 *   Client:  ./dtls_bench
 *
 * Defaults are tuned so the client's crypto path is the only bottleneck:
 *   - regular Ethernet MTU (1400 B, matching wolfSSL's WOLFSSL_MAX_MTU)
 *   - record write of 1300 B per wolfSSL_write (one app write = one record
 *     = one UDP datagram)
 *   - 8 MiB SO_SNDBUF/SO_RCVBUF
 *   - pre-filled buffer; no allocation/RNG/logging in the timed loop
 *   - server completes the DTLS handshake, then bypasses wolfSSL and just
 *     recv()s the UDP socket and drops the bytes. This keeps the receiver
 *     arbitrarily faster than the sender so we can never saturate kernel
 *     buffers, and the reported client throughput is the true ceiling
 *     of wolfSSL's encrypt-and-send path on this CPU.
 *
 * Use -n for a plain-UDP baseline (no DTLS) at the same record size to see
 * the pure transport ceiling. Compare different ciphers with -c to confirm
 * crypto is on the critical path.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#define USE_CERT_BUFFERS_2048
#include <wolfssl/certs_test.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/time.h>      /* struct timeval (SO_RCVTIMEO) */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

#define DEFAULT_HOST       "127.0.0.1"
#define DEFAULT_PORT       11111
#define DEFAULT_DURATION   10
#define DEFAULT_MTU        1400
#define DEFAULT_RECORD     1300
#define DEFAULT_VERSION    13
#define DEFAULT_SOCKBUF    (8 * 1024 * 1024)

/* Upper bound on per-record overhead the user must leave under MTU.
 * DTLS 1.2 worst case: 13 (hdr) + 8 (explicit nonce) + 16 (AEAD tag) = 37.
 * DTLS 1.3 typical:    ~7 (hdr) + 16 (AEAD tag) = 23. Round up to 40. */
#define DTLS_OVERHEAD      40

typedef struct cfg {
    int   isServer;
    int   plainUdp;
    const char* host;
    int   port;
    const char* iface;
    int   duration;
    int   recordSz;
    int   mtu;
    int   version;
    const char* cipherList;
    int   sockBuf;
    int   listCipher;
    int   sinkSend;
} cfg_t;

static double now_sec(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Post-handshake send sink. Pretends every byte was transmitted but does
 * nothing; the kernel's UDP/IP path never runs. Used via -z to measure the
 * pure wolfSSL encrypt-and-frame ceiling, free of any I/O cost. */
static int dtls_bench_sink_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl; (void)buf; (void)ctx;
    return sz;
}

static void print_stats(const char* dir, long long bytes, double sec)
{
    double mib  = (double)bytes / (1024.0 * 1024.0);
    double mbps = sec > 0 ? mib / sec : 0;
    double gbps = sec > 0 ? ((double)bytes * 8.0) / sec / 1e9 : 0;
    printf("  %s bytes : %lld\n", dir, bytes);
    printf("  duration  : %.3f s\n", sec);
    printf("  throughput: %.1f MiB/s   (%.3f Gbps)\n", mbps, gbps);
}

static void usage(const char* prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -s              run as DTLS server (default: client)\n"
        "  -h <host>       server address (client only, default %s)\n"
        "  -p <port>       UDP port (default %d)\n"
        "  -i <ifname>     bind to network interface (Linux SO_BINDTODEVICE)\n"
        "  -d <seconds>    test duration (client only, default %d)\n"
        "  -r <bytes>      bytes per wolfSSL_write/send (default %d)\n"
        "  -m <mtu>        DTLS MTU (default %d)\n"
        "  -v <12|13>      DTLS version (default %d)\n"
        "  -c <list|help>  cipher list, or 'help' to print compiled ciphers\n"
        "  -b <bytes>      SO_SNDBUF/SO_RCVBUF (default %d)\n"
        "  -n              plain UDP baseline (no DTLS)\n"
        "  -z              client-only: install a no-op IOSend after the\n"
        "                  handshake (measure pure wolfSSL encrypt path,\n"
        "                  no kernel send).\n"
        "  -?              show this help\n",
        prog, DEFAULT_HOST, DEFAULT_PORT,
        DEFAULT_DURATION, DEFAULT_RECORD, DEFAULT_MTU,
        DEFAULT_VERSION, DEFAULT_SOCKBUF);
}

static void list_ciphers(void)
{
    char  buf[8192];
    char* save = NULL;
    char* tok;
    if (wolfSSL_get_ciphers(buf, (int)sizeof(buf)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_get_ciphers failed\n");
        return;
    }
    printf("Compiled-in ciphers:\n");
    tok = strtok_r(buf, ":", &save);
    while (tok) {
        printf("  %s\n", tok);
        tok = strtok_r(NULL, ":", &save);
    }
}

static int parse_args(int argc, char** argv, cfg_t* c)
{
    int opt;

    c->isServer    = 0;
    c->plainUdp    = 0;
    c->host        = DEFAULT_HOST;
    c->port        = DEFAULT_PORT;
    c->iface       = NULL;
    c->duration    = DEFAULT_DURATION;
    c->recordSz    = DEFAULT_RECORD;
    c->mtu         = DEFAULT_MTU;
    c->version     = DEFAULT_VERSION;
    c->cipherList  = NULL;
    c->sockBuf     = DEFAULT_SOCKBUF;
    c->listCipher  = 0;
    c->sinkSend    = 0;

    while ((opt = getopt(argc, argv, "sh:p:i:d:r:m:v:c:b:nz?")) != -1) {
        switch (opt) {
            case 's': c->isServer    = 1; break;
            case 'h': c->host        = optarg; break;
            case 'p': c->port        = atoi(optarg); break;
            case 'i': c->iface       = optarg; break;
            case 'd': c->duration    = atoi(optarg); break;
            case 'r': c->recordSz    = atoi(optarg); break;
            case 'm': c->mtu         = atoi(optarg); break;
            case 'v': c->version     = atoi(optarg); break;
            case 'c':
                if (strcmp(optarg, "help") == 0 ||
                    strcmp(optarg, "list") == 0) {
                    c->listCipher = 1;
                }
                else {
                    c->cipherList = optarg;
                }
                break;
            case 'b': c->sockBuf     = atoi(optarg); break;
            case 'n': c->plainUdp    = 1; break;
            case 'z': c->sinkSend    = 1; break;
            case '?':
            default:  usage(argv[0]); return -1;
        }
    }

    if (c->listCipher) {
        wolfSSL_Init();
        list_ciphers();
        wolfSSL_Cleanup();
        return -2;
    }

    if (c->version != 12 && c->version != 13) {
        fprintf(stderr, "DTLS version must be 12 or 13\n");
        return -1;
    }
    if (c->mtu < 64 || c->mtu > 16384) {
        fprintf(stderr, "MTU must be between 64 and 16384\n");
        return -1;
    }
    if (c->recordSz < 1) {
        fprintf(stderr, "record size must be > 0\n");
        return -1;
    }
    if (!c->plainUdp && c->recordSz > c->mtu - DTLS_OVERHEAD) {
        fprintf(stderr,
            "record size (%d) exceeds MTU (%d) - %d B DTLS overhead.\n"
            "Pick -r <= %d, or raise -m.\n",
            c->recordSz, c->mtu, DTLS_OVERHEAD, c->mtu - DTLS_OVERHEAD);
        return -1;
    }
    if (c->plainUdp && c->recordSz > c->mtu) {
        fprintf(stderr, "plain-UDP record size (%d) > mtu (%d)\n",
                c->recordSz, c->mtu);
        return -1;
    }
    if (c->duration < 1) {
        fprintf(stderr, "duration must be >= 1 second\n");
        return -1;
    }
    return 0;
}

static int set_sockbuf(int fd, int which, int requested, const char* label)
{
    int got = 0;
    socklen_t glen = sizeof(got);
    if (setsockopt(fd, SOL_SOCKET, which,
                   &requested, sizeof(requested)) < 0) {
        perror(label);
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, which, &got, &glen) == 0) {
        /* Linux returns 2x what was set, on success.
         * If half the reported value is below what we asked, kernel clamped. */
        if (got < 2 * requested) {
            fprintf(stderr,
                "warning: %s clamped to %d (asked %d). "
                "Try: sudo sysctl -w net.core.%cmem_max=%d\n",
                label, got / 2, requested,
                which == SO_SNDBUF ? 'w' : 'r', requested);
        }
    }
    return 0;
}

static int bind_to_iface(int fd, const char* ifname)
{
#ifdef SO_BINDTODEVICE
    /* Linux SO_BINDTODEVICE expects the NUL-terminated ifname; pass strlen+1
     * so the kernel sees the terminator. Passing strlen() alone yields
     * EINVAL on some kernels. */
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   ifname, (socklen_t)(strlen(ifname) + 1)) < 0) {
        if (errno == EPERM) {
            fprintf(stderr,
                "SO_BINDTODEVICE requires CAP_NET_RAW.\n"
                "Run with sudo, or:\n"
                "  sudo setcap cap_net_raw+ep ./dtls_bench\n");
        }
        else {
            perror("SO_BINDTODEVICE");
        }
        return -1;
    }
    return 0;
#else
    (void)fd; (void)ifname;
    fprintf(stderr, "SO_BINDTODEVICE not available on this platform\n");
    return -1;
#endif
}

static WOLFSSL_METHOD* pick_method(int version, int isServer)
{
    if (version == 13) {
#ifdef WOLFSSL_DTLS13
        if (isServer) {
    #ifndef NO_WOLFSSL_SERVER
            return wolfDTLSv1_3_server_method();
    #endif
        }
        else {
    #ifndef NO_WOLFSSL_CLIENT
            return wolfDTLSv1_3_client_method();
    #endif
        }
#if defined(NO_WOLFSSL_SERVER) || defined(NO_WOLFSSL_CLIENT)
        fprintf(stderr, "DTLS 1.3 %s side not compiled in\n",
                isServer ? "server" : "client");
        return NULL;
#endif
#else
        fprintf(stderr,
            "DTLS 1.3 not compiled in (rebuild with --enable-dtls13)\n");
        return NULL;
#endif
    }
#ifndef WOLFSSL_NO_TLS12
    if (isServer) {
    #ifndef NO_WOLFSSL_SERVER
        return wolfDTLSv1_2_server_method();
    #endif
    }
    else {
    #ifndef NO_WOLFSSL_CLIENT
        return wolfDTLSv1_2_client_method();
    #endif
    }
#if defined(NO_WOLFSSL_SERVER) || defined(NO_WOLFSSL_CLIENT)
    fprintf(stderr, "DTLS 1.2 %s side not compiled in\n",
            isServer ? "server" : "client");
    return NULL;
#endif
#else
    fprintf(stderr, "DTLS 1.2 not compiled in\n");
    return NULL;
#endif
}

static int set_mtu(WOLFSSL* ssl, int mtu)
{
#ifdef WOLFSSL_DTLS_MTU
    if (wolfSSL_dtls_set_mtu(ssl, (unsigned short)mtu) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_dtls_set_mtu failed\n");
        return -1;
    }
    return 0;
#else
    (void)ssl;
    if (mtu != DEFAULT_MTU) {
        fprintf(stderr,
            "warning: -m %d ignored (built without --enable-dtls-mtu)\n",
            mtu);
    }
    return 0;
#endif
}

/* ----- Plain-UDP baseline (-n) ----- */

static int udp_server(const cfg_t* c)
{
    int                fd     = -1;
    unsigned char*     buf    = NULL;
    int                ret    = 1;
    int                one    = 1;
    int                recvSz;
    long long          total  = 0;
    double             start  = 0;
    double             last   = 0;
    struct sockaddr_in addr;
    struct timeval     tv     = { .tv_sec = 2, .tv_usec = 0 };

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); goto out; }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    set_sockbuf(fd, SO_RCVBUF, c->sockBuf, "SO_RCVBUF");
    if (c->iface && bind_to_iface(fd, c->iface) != 0) goto out;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)c->port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); goto out;
    }
    printf("dtls_bench server: plain UDP on port %d\n", c->port);

    /* Exit after 2s of silence following first packet. */
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    recvSz = c->mtu > 65507 ? 65507 : c->mtu;
    buf = (unsigned char*)XMALLOC((size_t)recvSz, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (!buf) goto out;

    for (;;) {
        ssize_t n = recvfrom(fd, buf, (size_t)recvSz, 0, NULL, NULL);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0) perror("recvfrom");
            break;
        }
        if (total == 0) start = now_sec();
        total += n;
        last = now_sec();
    }
    printf("dtls_bench server: plain UDP results\n");
    print_stats("recv", total, last - start);
    ret = 0;
out:
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (fd >= 0) close(fd);
    return ret;
}

static int udp_client(const cfg_t* c)
{
    int                fd      = -1;
    unsigned char*     buf     = NULL;
    int                ret     = 1;
    long long          total   = 0;
    double             start;
    double             end;
    double             elapsed;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); goto out; }
    set_sockbuf(fd, SO_SNDBUF, c->sockBuf, "SO_SNDBUF");
    if (c->iface && bind_to_iface(fd, c->iface) != 0) goto out;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)c->port);
    if (inet_pton(AF_INET, c->host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid host %s\n", c->host); goto out;
    }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); goto out;
    }

    buf = (unsigned char*)XMALLOC((size_t)c->recordSz, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (!buf) goto out;
    memset(buf, 0xA5, (size_t)c->recordSz);

    start = now_sec();
    end   = start + (double)c->duration;
    while (now_sec() < end) {
        ssize_t n = send(fd, buf, (size_t)c->recordSz, 0);
        if (n != c->recordSz) {
            if (n < 0 && (errno == ENOBUFS || errno == EAGAIN
                          || errno == EWOULDBLOCK)) {
                continue; /* tx queue full, retry */
            }
            if (n < 0) perror("send");
            break;
        }
        total += n;
    }
    elapsed = now_sec() - start;
    printf("dtls_bench client: plain UDP results (peer %s:%d)\n",
           c->host, c->port);
    printf("  iface     : %s\n", c->iface ? c->iface : "(kernel default)");
    printf("  mtu       : %d\n", c->mtu);
    printf("  record    : %d B per send\n", c->recordSz);
    print_stats("sent", total, elapsed);
    ret = 0;
out:
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (fd >= 0) close(fd);
    return ret;
}

/* ----- DTLS server ----- */

static int dtls_server(const cfg_t* c)
{
    int                ret      = 1;
    int                listenFd = -1;
    WOLFSSL_CTX*       ctx      = NULL;
    WOLFSSL*           ssl      = NULL;
    unsigned char*     buf      = NULL;
    WOLFSSL_METHOD*    method;
    int                one      = 1;
    int                rbufSz   = 16384;
    long long          total    = 0;
    double             start    = 0;
    double             last     = 0;
    ssize_t            pn;
    socklen_t          plen;
    unsigned char      peekbuf[256];
    struct sockaddr_in servAddr;
    struct sockaddr_in peer;
    struct timeval     tv       = { .tv_sec = 2, .tv_usec = 0 };

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n"); return 1;
    }

    method = pick_method(c->version, 1);
    if (!method) goto cleanup;
    ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n"); goto cleanup;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,
            server_key_der_2048, sizeof_server_key_der_2048,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "use_PrivateKey_buffer failed\n"); goto cleanup;
    }
    if (wolfSSL_CTX_use_certificate_buffer(ctx,
            server_cert_der_2048, sizeof_server_cert_der_2048,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "use_certificate_buffer failed\n"); goto cleanup;
    }
    if (c->cipherList && wolfSSL_CTX_set_cipher_list(ctx, c->cipherList)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list failed for '%s'\n",
                c->cipherList);
        goto cleanup;
    }

    listenFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenFd < 0) { perror("socket"); goto cleanup; }
    (void)setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    set_sockbuf(listenFd, SO_RCVBUF, c->sockBuf, "SO_RCVBUF");
    if (c->iface && bind_to_iface(listenFd, c->iface) != 0) goto cleanup;

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons((uint16_t)c->port);
    if (bind(listenFd, (struct sockaddr*)&servAddr,
             sizeof(servAddr)) < 0) {
        perror("bind"); goto cleanup;
    }
    printf("dtls_bench server: DTLS %s on UDP/%d\n",
           c->version == 13 ? "1.3" : "1.2", c->port);

    /* Peek at first datagram to learn peer, then connect to pin. */
    plen = sizeof(peer);
    pn = recvfrom(listenFd, peekbuf, sizeof(peekbuf), MSG_PEEK,
                  (struct sockaddr*)&peer, &plen);
    if (pn < 0) { perror("recvfrom"); goto cleanup; }
    if (connect(listenFd, (struct sockaddr*)&peer, plen) < 0) {
        perror("connect"); goto cleanup;
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) { fprintf(stderr, "wolfSSL_new failed\n"); goto cleanup; }
    if (wolfSSL_dtls_set_peer(ssl, &peer, plen) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "dtls_set_peer failed\n"); goto cleanup;
    }
    /* listenFd was connect()-ed to the peer above; mark it as such so
     * EmbedSendTo skips its per-send SO_TYPE probe. */
    if (wolfSSL_set_dtls_fd_connected(ssl, listenFd) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_dtls_fd_connected failed\n"); goto cleanup;
    }
    if (set_mtu(ssl, c->mtu) != 0) goto cleanup;

    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, 0);
        fprintf(stderr, "wolfSSL_accept err=%d %s\n",
                err, wolfSSL_ERR_reason_error_string(err));
        goto cleanup;
    }
    printf("dtls_bench server: handshake OK (cipher=%s)\n",
           wolfSSL_get_cipher(ssl));

    /* Once the handshake is up, stop using wolfSSL on this side and just
     * drain the UDP socket as fast as the kernel will deliver datagrams.
     * The server then runs arbitrarily faster than the client, so the
     * client's crypto path is the only thing under measurement and there
     * is no way for the receiver to backpressure or drop. */
    buf = (unsigned char*)XMALLOC((size_t)rbufSz, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (!buf) goto cleanup;

    /* Exit after 2s of idle following the last datagram. */
    (void)setsockopt(listenFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        ssize_t n = recv(listenFd, buf, (size_t)rbufSz, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0) perror("recv");
            break;
        }
        if (total == 0) start = now_sec();
        total += n;
        last = now_sec();
    }

    printf("dtls_bench server: results (raw recv-and-drop after handshake)\n");
    printf("  cipher    : %s\n", wolfSSL_get_cipher(ssl));
    printf("  mtu       : %d\n", c->mtu);
    print_stats("wire recv", total, last - start);

    ret = 0;

cleanup:
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    if (listenFd >= 0) close(listenFd);
    wolfSSL_Cleanup();
    return ret;
}

/* ----- DTLS client ----- */

static int dtls_client(const cfg_t* c)
{
    int                ret      = 1;
    int                fd       = -1;
    WOLFSSL_CTX*       ctx      = NULL;
    WOLFSSL*           ssl      = NULL;
    unsigned char*     buf      = NULL;
    WOLFSSL_METHOD*    method;
    long long          total    = 0;
    double             start;
    double             end;
    double             elapsed;
    struct sockaddr_in addr;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init failed\n"); return 1;
    }

    method = pick_method(c->version, 0);
    if (!method) goto cleanup;
    ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n"); goto cleanup;
    }

    if (wolfSSL_CTX_load_verify_buffer(ctx,
            ca_cert_der_2048, sizeof_ca_cert_der_2048,
            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "load_verify_buffer failed\n"); goto cleanup;
    }
    if (c->cipherList && wolfSSL_CTX_set_cipher_list(ctx, c->cipherList)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_cipher_list failed for '%s'\n",
                c->cipherList);
        goto cleanup;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); goto cleanup; }
    set_sockbuf(fd, SO_SNDBUF, c->sockBuf, "SO_SNDBUF");
    set_sockbuf(fd, SO_RCVBUF, c->sockBuf, "SO_RCVBUF");
    if (c->iface && bind_to_iface(fd, c->iface) != 0) goto cleanup;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)c->port);
    if (inet_pton(AF_INET, c->host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid host %s\n", c->host); goto cleanup;
    }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); goto cleanup;
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) { fprintf(stderr, "wolfSSL_new failed\n"); goto cleanup; }
    if (wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "dtls_set_peer failed\n"); goto cleanup;
    }
    /* Socket was connect()-ed above; tell wolfSSL so EmbedSendTo can skip
     * its per-send getsockopt(SO_TYPE) probe. */
    if (wolfSSL_set_dtls_fd_connected(ssl, fd) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "set_dtls_fd_connected failed\n"); goto cleanup;
    }
    if (set_mtu(ssl, c->mtu) != 0) goto cleanup;

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, 0);
        fprintf(stderr, "wolfSSL_connect err=%d %s\n",
                err, wolfSSL_ERR_reason_error_string(err));
        goto cleanup;
    }

    /* Handshake bytes had to go on the wire so the server could complete
     * its half. From this point on, swap in a no-op IOSend so wolfSSL_write
     * encrypts and frames as usual but never enters the kernel -- the
     * resulting throughput is the pure wolfSSL encrypt-and-frame ceiling
     * on this CPU. */
    if (c->sinkSend) {
        wolfSSL_SSLSetIOSend(ssl, dtls_bench_sink_send);
    }

    printf("dtls_bench client: handshake OK to %s:%d\n", c->host, c->port);
    printf("  version   : %s\n", wolfSSL_get_version(ssl));
    printf("  cipher    : %s\n", wolfSSL_get_cipher(ssl));
    printf("  iface     : %s\n", c->iface ? c->iface : "(kernel default)");
    printf("  mtu       : %d\n", c->mtu);
    printf("  record    : %d B per write\n", c->recordSz);
    if (c->sinkSend) {
        printf("  send mode : sink (no-op IOSend, kernel never sees data)\n");
    }

    buf = (unsigned char*)XMALLOC((size_t)c->recordSz, NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (!buf) goto cleanup;
    memset(buf, 0xA5, (size_t)c->recordSz);

    start = now_sec();
    end   = start + (double)c->duration;
    while (now_sec() < end) {
        int n = wolfSSL_write(ssl, buf, c->recordSz);
        if (n != c->recordSz) {
            int err = wolfSSL_get_error(ssl, n);
            fprintf(stderr, "wolfSSL_write n=%d err=%d %s\n",
                    n, err, wolfSSL_ERR_reason_error_string(err));
            goto cleanup;
        }
        total += n;
    }
    elapsed = now_sec() - start;

    print_stats("sent", total, elapsed);

    /* Send a one-way close_notify and exit. Don't loop on
     * WOLFSSL_SHUTDOWN_NOT_DONE: the server dropped its SSL state right
     * after the handshake and will never send back a close_notify, so a
     * bidirectional shutdown would block forever. */
    wolfSSL_shutdown(ssl);
    ret = 0;

cleanup:
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ssl) wolfSSL_free(ssl);
    if (ctx) wolfSSL_CTX_free(ctx);
    if (fd >= 0) close(fd);
    wolfSSL_Cleanup();
    return ret;
}

int main(int argc, char** argv)
{
    cfg_t c;
    int rc = parse_args(argc, argv, &c);
    if (rc == -2) return 0;   /* -c help handled */
    if (rc < 0)   return 1;

    if (c.plainUdp) {
        return c.isServer ? udp_server(&c) : udp_client(&c);
    }
    return c.isServer ? dtls_server(&c) : dtls_client(&c);
}
