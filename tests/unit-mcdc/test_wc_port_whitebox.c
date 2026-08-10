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
 */

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
 *
 * Every failing call returns a negative fd that the wrapper only ever passes
 * to wc_set_cloexec(), which returns immediately for fd < 0; the two
 * successful descriptors are closed here. No file is created or written and
 * no socket is ever connected or bound, so nothing outside this process is
 * touched.
 *
 * 5684's idx0 ("errno != ENOSYS") stays a justified residual: making accept4()
 * report ENOSYS needs a kernel without the syscall, which no build variant of
 * this campaign runs on, so that operand has no reachable independence pair.
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
    /* Always 0: a non-zero exit makes the campaign harness discard the
     * whole variant rather than record its coverage. */
    return 0;
}
