/* test_port.c
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

#include <tests/unit.h>

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <tests/api/api.h>
#include <tests/api/test_port.h>

/*
 * MC/DC decision coverage for the portability layer (wolfcrypt/src/wc_port.c):
 * the file/directory helpers and the wolfCrypt string helpers, whose argument
 * guards are multi-operand ORs that no other module's tests reach.
 *
 * Residuals left uncovered on purpose: wc_open_cloexec / wc_accept_cloexec's
 * "fd < 0 && errno == EINVAL" and "errno != ENOSYS && errno != EINVAL" arms are
 * the fallback for kernels without O_CLOEXEC / SOCK_CLOEXEC, unreachable on any
 * host the harness runs on.
 */

#ifndef SINGLE_THREADED
static THREAD_RETURN WOLFSSL_THREAD test_port_thread_cb(void* arg)
{
    (void)arg;
    WOLFSSL_RETURN_FROM_THREAD(0);
}
#endif

int test_wc_PortDecisionCoverage(void)
{
    EXPECT_DECLS;

#ifndef NO_FILESYSTEM
    {
        unsigned char* fbuf = NULL;
        size_t fbufLen = 0;

        /* wc_FileLoad: "fname == NULL || buf == NULL || bufLen == NULL",
         * one operand true per call so each independence pair is shown. */
        ExpectIntEQ(wc_FileLoad(NULL, &fbuf, &fbufLen, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_FileLoad("./certs/server-cert.pem", NULL, &fbufLen, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_FileLoad("./certs/server-cert.pem", &fbuf, NULL, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* all three operands false: the guard is passed and the call is
         * decided by the filesystem, not by the argument check. */
        ExpectIntNE(wc_FileLoad("./certs/no-such-file.der", &fbuf, &fbufLen,
            NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        if (fbuf != NULL) {
            XFREE(fbuf, NULL, DYNAMIC_TYPE_FILE);
            fbuf = NULL;
        }
    }
#endif /* !NO_FILESYSTEM */

#if !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
    {
        ReadDirCtx dirCtx;
        char* dirName = NULL;

        XMEMSET(&dirCtx, 0, sizeof(dirCtx));

        /* wc_ReadDirFirst / wc_ReadDirNext: "ctx == NULL || path == NULL",
         * each operand flipped independently. */
        ExpectIntEQ(wc_ReadDirFirst(NULL, "./certs", &dirName),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ReadDirFirst(&dirCtx, NULL, &dirName),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ReadDirNext(NULL, "./certs", &dirName),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ReadDirNext(&dirCtx, NULL, &dirName),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* both operands false on a directory that always exists in-tree. */
        if (wc_ReadDirFirst(&dirCtx, "./certs", &dirName) == 0) {
            (void)wc_ReadDirNext(&dirCtx, "./certs", &dirName);
            wc_ReadDirClose(&dirCtx);
        }
    }
#endif /* !NO_FILESYSTEM && !NO_WOLFSSL_DIR */

#ifdef USE_WOLF_STRTOK
    {
        char tokBuf[] = "a,b";
        char* tokNext = NULL;

        /* "str == NULL && nextp": nextp NULL is the operand's false half, and
         * the same call then takes "str == NULL || *str == '\0'" true on its
         * first operand. */
        ExpectNull(wc_strtok(NULL, ",", NULL));

        /* str non-NULL: first operand false, and the second guard decided by
         * *str instead. */
        ExpectNotNull(wc_strtok(tokBuf, ",", &tokNext));
    }
#endif /* USE_WOLF_STRTOK */

#ifdef USE_WOLF_STRSEP
    {
        char sepBuf[] = "a,b";
        char* sepp = sepBuf;
        char* sepNull = NULL;

        /* "stringp == NULL || *stringp == NULL", one operand true per call. */
        ExpectNull(wc_strsep(NULL, ","));
        ExpectNull(wc_strsep(&sepNull, ","));
        /* both false */
        ExpectNotNull(wc_strsep(&sepp, ","));
    }
#endif /* USE_WOLF_STRSEP */

#ifndef SINGLE_THREADED
    {
        THREAD_TYPE portThread;

        XMEMSET(&portThread, 0, sizeof(portThread));

        /* wolfSSL_NewThread: "thread == NULL || cb == NULL", each operand
         * flipped independently, then both false on a thread that is created
         * and joined. */
        ExpectIntEQ(wolfSSL_NewThread(NULL, test_port_thread_cb, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wolfSSL_NewThread(&portThread, NULL, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        if (EXPECT_SUCCESS()) {
            int thrRet = wolfSSL_NewThread(&portThread, test_port_thread_cb,
                NULL);
            ExpectIntEQ(thrRet, 0);
            if (thrRet == 0) {
                ExpectIntEQ(wolfSSL_JoinThread(portThread), 0);
            }
        }
    }
#endif /* !SINGLE_THREADED */

#ifdef USE_WOLF_STRLCPY
    {
        char lcpyDst[4];

        /* strlcpy(3) returns the length of src -- the length the copy would
         * have needed -- not the number of bytes it managed to copy. That is
         * what makes the documented truncation check (ret >= dstSize) work,
         * and it is what the doxygen comment for wc_strlcpy already specifies
         * ("Length of source string").
         *
         * The copy loop "i < (dstSize - 1) && *src != '\0'" is also the MC/DC
         * target here: a source longer than the destination ends it on the
         * size operand, a shorter one on the terminator. */
        XMEMSET(lcpyDst, 0, sizeof(lcpyDst));
        ExpectIntEQ((int)wc_strlcpy(lcpyDst, "abcdef", 3), 6);
        ExpectIntEQ(XSTRNCMP(lcpyDst, "ab", 3), 0);
        /* truncation is detectable from the return value alone */
        ExpectIntGE((int)wc_strlcpy(lcpyDst, "abcdef", 3), 3);

        /* short source: the loop ends on the terminator, no truncation. */
        XMEMSET(lcpyDst, 0, sizeof(lcpyDst));
        ExpectIntEQ((int)wc_strlcpy(lcpyDst, "a", sizeof(lcpyDst)), 1);
        ExpectIntEQ(XSTRNCMP(lcpyDst, "a", 2), 0);

        /* exact fit: src length equals dstSize - 1, still no truncation. */
        XMEMSET(lcpyDst, 0, sizeof(lcpyDst));
        ExpectIntEQ((int)wc_strlcpy(lcpyDst, "abc", sizeof(lcpyDst)), 3);
        ExpectIntEQ(XSTRNCMP(lcpyDst, "abc", 4), 0);

        /* dstSize 0: nothing may be written, but the length src would have
         * needed is still reported. */
        XMEMSET(lcpyDst, 'Z', sizeof(lcpyDst));
        ExpectIntEQ((int)wc_strlcpy(lcpyDst, "abcdef", 0), 6);
        ExpectIntEQ(lcpyDst[0], 'Z');
    }
#endif /* USE_WOLF_STRLCPY */

#ifdef USE_WOLF_STRLCAT
    {
        char lcatDst[8];

        /* strlcat(3) returns the total length it tried to create: the initial
         * length of dst plus the length of src. */
        XMEMSET(lcatDst, 0, sizeof(lcatDst));
        XMEMCPY(lcatDst, "ab", 3);
        ExpectIntEQ((int)wc_strlcat(lcatDst, "cdefghi", sizeof(lcatDst)), 9);
        ExpectIntEQ(XSTRNCMP(lcatDst, "abcdefg", 8), 0);

        /* fits: no truncation, and the result is the concatenation. */
        XMEMSET(lcatDst, 0, sizeof(lcatDst));
        XMEMCPY(lcatDst, "ab", 3);
        ExpectIntEQ((int)wc_strlcat(lcatDst, "cd", sizeof(lcatDst)), 4);
        ExpectIntEQ(XSTRNCMP(lcatDst, "abcd", 5), 0);

        /* dst with no NUL inside dstSize: per strlcat(3) the length of dst is
         * taken to be dstSize, nothing is appended and dst is left
         * un-terminated. Measuring dst must stop at dstSize, since an
         * unbounded scan of a dst that is not a C string is exactly the
         * out-of-bounds read the standard bounds this at to prevent.
         *
         * The NUL sits at the end of the array rather than nowhere at all, so
         * that an unbounded implementation reads a wrong length (and fails
         * this assertion) instead of running off the buffer and taking the
         * whole suite down under a sanitizer. */
        XMEMSET(lcatDst, 'A', sizeof(lcatDst) - 1);
        lcatDst[sizeof(lcatDst) - 1] = '\0';
        ExpectIntEQ((int)wc_strlcat(lcatDst, "xy", 4), 6);
        /* untouched: no append, no terminator written inside dstSize */
        ExpectIntEQ(lcatDst[0], 'A');
        ExpectIntEQ(lcatDst[4], 'A');

        /* dstSize 0: nothing can be appended, but the attempted length is
         * still the length of src. */
        XMEMSET(lcatDst, 'B', sizeof(lcatDst));
        ExpectIntEQ((int)wc_strlcat(lcatDst, "xyz", 0), 3);
        ExpectIntEQ(lcatDst[0], 'B');
    }
#endif /* USE_WOLF_STRLCAT */

    return EXPECT_RESULT();
}
