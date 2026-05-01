/* emnet_nonblock_test.c -- non-blocking TLS 1.3 handshake over a
 * socketpair, with wolfSSL built for WOLFSSL_EMNET and the canonical
 * IP_ERR_* lookup provided by IP_SOCK_getsockopt in emnet_shim.c.
 *
 * recv/send fall through to glibc's POSIX implementation, returning
 * -1 with errno set on would-block. This reproduces the integrator
 * convention in ticket #21673, where wolfSSL_LastError must consult
 * IP_SOCK_getsockopt(SO_ERROR) rather than trusting the raw recv/send
 * return value.
 *
 * Asserts the steady-state contract of wolfSSL's WOLFSSL_EMNET path:
 * when the underlying socket would block, wolfSSL_get_error returns
 * WOLFSSL_ERROR_WANT_READ / WOLFSSL_ERROR_WANT_WRITE and the handshake
 * completes without spurious fatal errors.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define MAX_ITERS   200   /* handshake loop safety cap */
#define POLL_MS     500

#define CERT_PATH    "certs/server-ecc.pem"
#define KEY_PATH     "certs/ecc-key.pem"
#define CA_PATH      "certs/ca-ecc-cert.pem"

struct side {
    int fd;
    const char *name;
    WOLFSSL *ssl;
    int (*fn)(WOLFSSL *);
    int saw_would_block;
    int completed;
    int failed;
    int last_err;
};

static void set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl F_GETFL");
        exit(2);
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl F_SETFL O_NONBLOCK");
        exit(2);
    }
}

/* Wait for the socket to become readable or writable. Returns 0 on
 * success (ready or timeout, caller retries), -1 on hard failure. */
static int wait_io(struct side *s, short events, int iter)
{
    struct pollfd pfd;
    int r;

    pfd.fd = s->fd;
    pfd.events = events;
    pfd.revents = 0;
    r = poll(&pfd, 1, POLL_MS);
    if (r >= 0)
        return 0;
    if (errno == EINTR)
        return 0;
    fprintf(stderr, "FAIL: %s: poll failed at iter=%d: %s\n",
            s->name, iter, strerror(errno));
    return -1;
}

static void *run_side(void *arg)
{
    struct side *s = (struct side *)arg;
    int iter;
    int ret;
    int err;

    for (iter = 0; iter < MAX_ITERS; iter++) {
        ret = s->fn(s->ssl);
        if (ret == WOLFSSL_SUCCESS) {
            s->completed = 1;
            return NULL;
        }

        err = wolfSSL_get_error(s->ssl, ret);
        s->last_err = err;

        if (err == WOLFSSL_ERROR_WANT_READ) {
            s->saw_would_block = 1;
            if (wait_io(s, POLLIN, iter) < 0) {
                s->failed = 1;
                return NULL;
            }
            continue;
        }
        if (err == WOLFSSL_ERROR_WANT_WRITE) {
            s->saw_would_block = 1;
            if (wait_io(s, POLLOUT, iter) < 0) {
                s->failed = 1;
                return NULL;
            }
            continue;
        }

        /* Anything else on a non-blocking handshake is a failure. */
        fprintf(stderr,
            "FAIL: %s: wolfSSL_get_error=%d after iter=%d. "
            "Expected WANT_READ/WANT_WRITE on a non-blocking socketpair. "
            "Indicates a regression in the WOLFSSL_EMNET error-translation "
            "path in src/wolfio.c:wolfSSL_LastError.\n",
            s->name, err, iter);
        s->failed = 1;
        return NULL;
    }

    fprintf(stderr, "FAIL: %s: handshake did not complete within %d "
            "iterations (last err=%d)\n",
            s->name, MAX_ITERS, s->last_err);
    s->failed = 1;
    return NULL;
}

int main(void)
{
    int sv[2];
    WOLFSSL_CTX *sctx;
    WOLFSSL_CTX *cctx;
    WOLFSSL *server_ssl;
    WOLFSSL *client_ssl;
    struct side server;
    struct side client;
    pthread_t st, ct;
    int prc;
    int rc;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair");
        return 2;
    }
    set_nonblock(sv[0]);
    set_nonblock(sv[1]);

    wolfSSL_Init();

    sctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    cctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!sctx || !cctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        return 2;
    }

    if (wolfSSL_CTX_use_certificate_file(sctx, CERT_PATH,
                                         WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to load server cert %s\n", CERT_PATH);
        return 2;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(sctx, KEY_PATH,
                                        WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to load server key %s\n", KEY_PATH);
        return 2;
    }
    if (wolfSSL_CTX_load_verify_locations(cctx, CA_PATH, NULL)
            != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to load CA %s\n", CA_PATH);
        return 2;
    }

    server_ssl = wolfSSL_new(sctx);
    client_ssl = wolfSSL_new(cctx);
    if (!server_ssl || !client_ssl) {
        fprintf(stderr, "wolfSSL_new failed\n");
        return 2;
    }

    wolfSSL_set_fd(server_ssl, sv[0]);
    wolfSSL_set_fd(client_ssl, sv[1]);

    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));
    server.fd = sv[0];
    server.name = "server";
    server.ssl = server_ssl;
    server.fn = wolfSSL_accept;
    client.fd = sv[1];
    client.name = "client";
    client.ssl = client_ssl;
    client.fn = wolfSSL_connect;

    prc = pthread_create(&st, NULL, run_side, &server);
    if (prc != 0) {
        fprintf(stderr, "FAIL: pthread_create(server): %s\n", strerror(prc));
        return 2;
    }
    prc = pthread_create(&ct, NULL, run_side, &client);
    if (prc != 0) {
        fprintf(stderr, "FAIL: pthread_create(client): %s\n", strerror(prc));
        pthread_join(st, NULL);
        return 2;
    }
    prc = pthread_join(st, NULL);
    if (prc != 0) {
        fprintf(stderr, "FAIL: pthread_join(server): %s\n", strerror(prc));
        return 2;
    }
    prc = pthread_join(ct, NULL);
    if (prc != 0) {
        fprintf(stderr, "FAIL: pthread_join(client): %s\n", strerror(prc));
        return 2;
    }

    rc = 0;
    if (server.failed || client.failed) {
        rc = 1;
    } else if (!server.completed || !client.completed) {
        fprintf(stderr, "FAIL: handshake incomplete (server=%d client=%d)\n",
                server.completed, client.completed);
        rc = 1;
    } else if (!server.saw_would_block && !client.saw_would_block) {
        fprintf(stderr, "FAIL: handshake completed but never hit a "
                "non-blocking path. Test scaffolding not exercising "
                "the WOLFSSL_EMNET error-translation code.\n");
        rc = 1;
    } else {
        printf("OK: handshake completed, would-block paths exercised\n");
    }

    wolfSSL_free(server_ssl);
    wolfSSL_free(client_ssl);
    wolfSSL_CTX_free(sctx);
    wolfSSL_CTX_free(cctx);
    wolfSSL_Cleanup();
    close(sv[0]);
    close(sv[1]);
    return rc;
}
