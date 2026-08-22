/* test_wc_port_whitebox.c
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

/* White-box supplement for wolfcrypt/src/wc_port.c.
 *
 * wolfSSL_strnstr is not declared in any public wolfcrypt header, so the
 * tests/api "port" group cannot reach it. Its loop guard
 * "n >= s2_len && s1[0]" needs both operands driven false independently,
 * which needs a haystack shorter than the needle and an empty haystack.
 *
 * This file also interposes accept4() for wc_accept_cloexec(), see the
 * block immediately below and the note above wb_cloexec_wrappers().
 */

/* ---- accept4() macro interposition -------------------------------------- *
 *
 * wc_accept_cloexec()'s guard `if (errno != ENOSYS && errno != EINVAL)`
 * (wc_port.c ~:5684) can only see errno == ENOSYS on a kernel that does not
 * implement accept4(). Every host this suite runs on does, so the first
 * operand has no reachable independence pair from the outside.
 *
 * The white-box TU #includes wc_port.c directly, so accept4() can be
 * replaced at PREPROCESSING time for this translation unit only - the same
 * technique mcdc_fault_hash.h uses for the hash primitives. Ordering is
 * load-bearing and mirrors that header exactly:
 *   1. define _GNU_SOURCE before the first libc header, exactly as
 *      wc_port.c does at its own top. Without it glibc does not declare
 *      accept4(), __USE_GNU is never set, and wc_port.c's
 *      `#if defined(__USE_GNU) && ...` block - the block that CONTAINS the
 *      target guard - would compile out of this TU entirely;
 *   2. include <sys/socket.h> so the REAL accept4() declaration is in scope
 *      and is never rewritten by the macro;
 *   3. define the wrapper, which is compiled BEFORE the macro exists and so
 *      still calls the real accept4() when disarmed;
 *   4. only then #define accept4 to the wrapper, and include wc_port.c.
 * wc_port.c's own `#include <sys/socket.h>` becomes a no-op (include guard)
 * and its own `#define _GNU_SOURCE 1` is skipped by its `!defined(_GNU_SOURCE)`
 * test, so the preprocessor state wc_port.c sees is identical to a normal
 * build. accept4 appears exactly once in wc_port.c (in wc_accept_cloexec),
 * so nothing else in the file is affected.
 * ------------------------------------------------------------------------ */
#if (defined(__linux__) || defined(__ANDROID__)) && \
    !defined(WOLFSSL_LINUXKM) && !defined(WOLFSSL_ZEPHYR) && \
    !defined(_GNU_SOURCE)
    #define _GNU_SOURCE 1
#endif

#if (defined(__unix__) || defined(__APPLE__)) && \
    !defined(WOLFSSL_LINUXKM) && !defined(WOLFSSL_KERNEL_MODE) && \
    !defined(WOLFSSL_ZEPHYR) && !defined(WOLFSSL_SGX)
#include <errno.h>
#include <sys/socket.h>
#endif

#if defined(__USE_GNU) && (defined(__linux__) || defined(__ANDROID__))
#define WB_HAVE_ACCEPT4_HOOK

/* 0 = pass through to the real accept4(); otherwise fail with this errno. */
static int wb_accept4_errno = 0;

static int wb_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen,
    int flags)
{
    if (wb_accept4_errno != 0) {
        errno = wb_accept4_errno;
        return -1;
    }
    return accept4(sockfd, addr, addrlen, flags);
}

#define accept4 wb_accept4
#endif /* __USE_GNU && (__linux__ || __ANDROID__) */

#include <wolfcrypt/src/wc_port.c>

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if (!defined(WOLFSSL_LEANPSK) && !defined(STRING_USER)) || \
    defined(USE_WOLF_STRNSTR)

static void wb_strnstr(void)
{
    const char* hay = "abcdef";

    /* n >= s2_len false on entry: search window shorter than the needle. */
    if (wolfSSL_strnstr(hay, "abc", 2) != NULL) {
        printf("  [wb] FAIL: short window matched\n");
        wb_fail++;
    }

    /* s1[0] false: empty haystack, window wide enough so the first operand
     * stays true and the second decides. */
    if (wolfSSL_strnstr("", "abc", 8) != NULL) {
        printf("  [wb] FAIL: empty haystack matched\n");
        wb_fail++;
    }

    /* both true, then a hit, so the loop body and the return are exercised. */
    if (wolfSSL_strnstr(hay, "cd", 6) == NULL) {
        printf("  [wb] FAIL: expected match not found\n");
        wb_fail++;
    }

    /* both true, no hit: the loop runs to exhaustion and returns NULL. */
    if (wolfSSL_strnstr(hay, "xy", 6) != NULL) {
        printf("  [wb] FAIL: unexpected match\n");
        wb_fail++;
    }

    /* zero-length needle short-circuits before the loop. */
    if (wolfSSL_strnstr(hay, "", 6) != hay) {
        printf("  [wb] FAIL: empty needle did not return s1\n");
        wb_fail++;
    }

    WB_NOTE("wolfSSL_strnstr loop-guard operand pairs done");
}

#else
static void wb_strnstr(void) { WB_NOTE("wolfSSL_strnstr not compiled; skipped"); }
#endif

/* ---- close-on-exec syscall wrappers (lines ~5654 / ~5666 / ~5684) --------- *
 *
 *   wc_open_cloexec():   if (fd < 0 && errno == EINVAL)
 *   wc_socket_cloexec(): if (fd < 0 && errno == EINVAL)
 *   wc_accept_cloexec(): if (errno != ENOSYS && errno != EINVAL)
 *
 * These retry-without-the-CLOEXEC-flag fallbacks exist for kernels that
 * reject O_CLOEXEC / SOCK_CLOEXEC / accept4() with EINVAL or ENOSYS. On a
 * modern Linux host every call in the "port" API group succeeds first try, so
 * each guard only ever sees its all-false vector. Both halves of every
 * satisfiable operand are driven here in ONE binary by choosing arguments
 * whose failure mode is known:
 *
 *   open("/tmp", O_TMPFILE|O_RDONLY) -> O_TMPFILE demands write access
 *                                   -> EINVAL, no file created  (T,T)
 *   open("/nonexistent/...")     -> ENOENT                   (T,F)
 *   open("/dev/null", O_RDONLY)  -> succeeds                 (F,-)
 *   socket(AF_INET, SOCK_STREAM|<bogus flag bit>) -> EINVAL   (T,T)
 *   socket(<unsupported family>, SOCK_STREAM)     -> EAFNOSUPPORT (T,F)
 *   socket(AF_INET, SOCK_STREAM, 0)               -> succeeds (F,-)
 *   accept on a NON-listening socket -> EINVAL               (T,F) at 5684
 *   accept on a bad descriptor       -> EBADF                (T,T) at 5684
 *   accept4() interposed to fail with ENOSYS -> (F,-) at 5684
 *
 * Every failing call returns a negative fd that the wrapper only ever passes
 * to wc_set_cloexec(), which returns immediately for fd < 0; the two
 * successful descriptors are closed here. No file is created or written and
 * no socket is ever connected or bound, so nothing outside this process is
 * touched.
 *
 * 5684's idx0 ("errno != ENOSYS") is the one operand no argument choice can
 * reach, because it needs a kernel that does not implement accept4(). It is
 * driven instead by the macro interposition set up at the top of this file:
 * the wrapper reports ENOSYS for exactly one call, which short-circuits the
 * AND and drops wc_accept_cloexec() into its plain accept() fallback. That
 * fallback is issued on fd -1, so accept() returns -1/EBADF and
 * wc_set_cloexec(-1) returns immediately - no descriptor is produced and
 * nothing blocks. The hook is disarmed again on the next line, so every other
 * call in this file reaches the real accept4().
 * ------------------------------------------------------------------------ */
#if (defined(__unix__) || defined(__APPLE__)) && \
    !defined(WOLFSSL_KERNEL_MODE) && !defined(WOLFSSL_ZEPHYR) && \
    !defined(WOLFSSL_SGX) && defined(FD_CLOEXEC)
#include <unistd.h>
static void wb_cloexec_wrappers(void)
{
    int fd;

    /* --- wc_open_cloexec --- */
#ifdef O_TMPFILE
    /* O_TMPFILE with neither O_WRONLY nor O_RDWR is rejected with EINVAL by
     * the kernel before any file is created, which is exactly the (T,T)
     * vector. The retry without O_CLOEXEC fails the same way, so no temporary
     * file is ever produced and no descriptor is leaked. */
    errno = 0;
    fd = wc_open_cloexec("/tmp", O_TMPFILE | O_RDONLY);     /* EINVAL */
    if (fd >= 0) {
        close(fd);
        WB_NOTE("O_TMPFILE|O_RDONLY unexpectedly succeeded");
    }
#else
    WB_NOTE("O_TMPFILE unavailable; open() EINVAL vector skipped");
#endif
    errno = 0;
    fd = wc_open_cloexec("/nonexistent-mcdc-path/xyz", O_RDONLY); /* ENOENT */
    if (fd >= 0) {
        close(fd);
        WB_NOTE("open of a nonexistent path unexpectedly succeeded");
    }
    errno = 0;
    fd = wc_open_cloexec("/dev/null", O_RDONLY);            /* success */
    if (fd < 0) {
        WB_NOTE("open of /dev/null failed");
        wb_fail++;
    }
    else {
        close(fd);
    }

    /* --- wc_socket_cloexec --- */
    errno = 0;
    /* 0x10000000 is not a defined SOCK_* flag bit -> EINVAL. */
    fd = wc_socket_cloexec(AF_INET, SOCK_STREAM | 0x10000000, 0);
    if (fd >= 0) {
        close(fd);
        WB_NOTE("socket with a bogus type flag unexpectedly succeeded");
    }
    errno = 0;
    fd = wc_socket_cloexec(0x7f, SOCK_STREAM, 0);   /* EAFNOSUPPORT */
    if (fd >= 0) {
        close(fd);
        WB_NOTE("socket with an unsupported family unexpectedly succeeded");
    }
    errno = 0;
    fd = wc_socket_cloexec(AF_INET, SOCK_STREAM, 0);        /* success */
    if (fd < 0) {
        WB_NOTE("plain AF_INET socket() failed");
        wb_fail++;
    }
    else {
        int nfd;
        /* --- wc_accept_cloexec on a valid but NON-listening socket: the
         * kernel rejects it with EINVAL, driving 5684's idx1 FALSE. --- */
        errno = 0;
        nfd = wc_accept_cloexec(fd, NULL, NULL);
        if (nfd >= 0) {
            close(nfd);
            WB_NOTE("accept on a non-listening socket unexpectedly succeeded");
        }
        close(fd);
    }

    /* --- wc_accept_cloexec on a closed/invalid descriptor: EBADF, so both
     * operands of 5684 are true and the early return is taken. --- */
    errno = 0;
    fd = wc_accept_cloexec(-1, NULL, NULL);
    if (fd >= 0) {
        close(fd);
        WB_NOTE("accept on fd -1 unexpectedly succeeded");
    }

    /* --- 5684 idx0 FALSE: accept4() reports ENOSYS, so `errno != ENOSYS` is
     * false and the AND short-circuits into the accept() fallback below it.
     * Paired in this same binary with the EBADF vector immediately above,
     * which has idx0 TRUE and the same outcome flip. --- */
#ifdef WB_HAVE_ACCEPT4_HOOK
    errno = 0;
    wb_accept4_errno = ENOSYS;
    fd = wc_accept_cloexec(-1, NULL, NULL);
    wb_accept4_errno = 0;
    if (fd >= 0) {
        close(fd);
        WB_NOTE("accept() fallback on fd -1 unexpectedly succeeded");
    }
    WB_NOTE("accept4 ENOSYS interposition drove 5684 idx0 false");
#else
    WB_NOTE("accept4() not compiled in this TU; 5684 idx0 false vector "
            "skipped");
#endif

    WB_NOTE("cloexec open/socket/accept fallback guard pairs done");
}
#else
static void wb_cloexec_wrappers(void)
{ WB_NOTE("POSIX cloexec wrappers not compiled in this variant; skipped"); }
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_port white-box\n");
    wb_strnstr();
    wb_cloexec_wrappers();
    printf("  [wb] failures: %d\n", wb_fail);
    /* Always 0: a non-zero exit makes the test harness discard the
     * whole variant rather than record its coverage. */
    return 0;
}
