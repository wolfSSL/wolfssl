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
 * host the campaign runs on.
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

        /* "i < (dstSize - 1) && *src != '\0'": a source longer than the
         * destination ends the loop on the size operand rather than on the
         * terminator, which is that operand's uncovered half.
         *
         * Note wc_strlcpy returns the number of bytes copied, not
         * XSTRLEN(src) as BSD strlcpy does, so a truncating call reports the
         * truncated length (2 here, not 6). */
        XMEMSET(lcpyDst, 0, sizeof(lcpyDst));
        ExpectIntEQ((int)wc_strlcpy(lcpyDst, "abcdef", 3), 2);
        ExpectIntEQ(XSTRNCMP(lcpyDst, "ab", 3), 0);

        /* short source: the loop ends on the terminator instead. */
        XMEMSET(lcpyDst, 0, sizeof(lcpyDst));
        ExpectIntEQ((int)wc_strlcpy(lcpyDst, "a", sizeof(lcpyDst)), 1);
    }
#endif /* USE_WOLF_STRLCPY */

    return EXPECT_RESULT();
}
