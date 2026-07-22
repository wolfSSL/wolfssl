/* test_logging_whitebox.c
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
 * White-box MC/DC supplement for wolfcrypt/src/logging.c -- CORE (non
 * OpenSSL-compat) decisions only.
 *
 * The campaign's default build for this module measures 0 MC/DC on
 * logging.c's core decisions because every one of them lives behind a
 * debug/error-queue macro that the default variant does not enable
 * (DEBUG_WOLFSSL / WOLFSSL_DEBUG_CERTS for certificate logging,
 * WOLFSSL_HAVE_ERROR_QUEUE for the error queue). This translation unit
 * defines the minimal set of macros needed to compile those decisions in,
 * then #includes logging.c directly and drives both halves of every
 * targeted independence pair from this single binary (per
 * tests/unit-mcdc/README.md's per-binary MC/DC contract).
 *
 * IMPORTANT SCOPE: OPENSSL_EXTRA is deliberately NEVER defined here. The
 * per-module campaign excludes logging.c's OPENSSL_EXTRA-guarded (OpenSSL
 * compatibility) decisions from its MC/DC boundary; this file only targets
 * the CORE decisions. Where a core decision needs the same top-level guard
 * that also (independently) admits OPENSSL_EXTRA builds (e.g. the error
 * queue's "#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE) ||
 * defined(HAVE_MEMCACHED)"), DEBUG_WOLFSSL_VERBOSE is used instead of
 * OPENSSL_EXTRA to admit the block without touching the excluded surface.
 *
 * Enabling macros defined below (guarded so a build that already sets any
 * of these via its own user_settings.h/CFLAGS is not broken by
 * redefinition):
 *   DEBUG_WOLFSSL          - core debug logging + certificate logging.
 *   WOLFSSL_DEBUG_CERTS    - belt-and-suspenders alternate gate for cert
 *                            logging (redundant with DEBUG_WOLFSSL here,
 *                            included per spec).
 *   DEBUG_WOLFSSL_VERBOSE  - non-OPENSSL_EXTRA gate that admits the error
 *                            queue implementation block.
 *   WOLFSSL_HAVE_ERROR_QUEUE - selects the real (non-stub) error queue.
 *   ERROR_QUEUE_PER_THREAD  - selects the thread-local-storage error queue
 *                            implementation (get_abs_idx() / struct array,
 *                            no heap allocation, no mutex needed), which is
 *                            the simpler of logging.c's two error-queue
 *                            implementations to drive crash-safely here.
 *
 * Targeted core decisions, by logging.c line (as reviewed during authoring;
 * line numbers may drift slightly with unrelated edits):
 *
 *   :372 WOLFSSL_MSG_CERT(): "(msg != NULL) && (loggingCertEnabled != 0)"
 *   :402 WOLFSSL_MSG_CERT_EX(): "(written > 0) && (loggingCertEnabled != 0)"
 *   :753 get_abs_idx() [ERROR_QUEUE_PER_THREAD variant]:
 *        "(wc_errors.count == 0) || (relative_idx >= (int)wc_errors.count)"
 *   :997 wc_PeekErrorNodeLineData() [ERROR_QUEUE_PER_THREAD variant]:
 *        "ignore_err && ignore_err(ret)"
 *   :559 WOLFSSL_BUFFER(): "31 < buffer[i] && buffer[i] < 127" (the
 *        printable-character ternary in the hex-dump helper). Not in the
 *        original target list, but DEBUG_WOLFSSL (needed for the decisions
 *        above) compiles this decision in too, and it is trivial to drive
 *        through the public API, so it is covered here as well rather than
 *        left as an avoidable residual.
 *
 * Each is driven through the public API (WOLFSSL_MSG_CERT[_EX],
 * wolfSSL_CertDebugging_ON/OFF, wc_AddErrorNode, wc_PeekErrorNode,
 * wc_PeekErrorNodeLineData, wc_ClearErrorNodes) rather than by poking the
 * file-static state directly, so the calls also exercise real behaviour
 * (verified via an installed wolfSSL_SetLoggingCb() counter for the cert
 * logging pair).
 *
 * Residual -- NOT covered by this file (documented, not silently dropped):
 *   :1504 / :1516 in the OTHER ("global mutex + linked list", i.e.
 *   ERROR_QUEUE_PER_THREAD *undefined*) error-queue implementation's
 *   wc_PeekErrorNodeLineData() -- "ret == WC_NO_ERR_TRACE(BAD_MUTEX_E) ||
 *   ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG) || ret == WC_NO_ERR_TRACE(BAD_STATE_E)"
 *   and "ignore_err && ignore_err(ret)". logging.c's two error-queue
 *   implementations are mutually exclusive at the preprocessor level
 *   (#ifdef ERROR_QUEUE_PER_THREAD / #else); a single translation unit can
 *   only compile in one. This file selects ERROR_QUEUE_PER_THREAD because
 *   it is heap/mutex-free and therefore simpler to drive crash-safely.
 *   Reaching the :1504/:1516 pair would require a second white-box binary
 *   built with ERROR_QUEUE_PER_THREAD left undefined -- out of scope for
 *   this single-file task; left as a follow-up variant.
 *
 * Build: intended to be compiled the same way as the other white-box files
 * in this directory (same MC/DC CFLAGS, -DHAVE_CONFIG_H and -I<workspace>
 * as the instrumented library), then linked against that
 * variant's libwolfssl.a with its logging.o removed (this TU supplies the
 * instrumented logging.c, compiled here with the macros above regardless of
 * what the rest of the library was built with). NOT part of the wolfSSL
 * build; not registered in tests/api. See tests/unit-mcdc/README.md.
 */

#ifndef DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL
#endif
#ifndef WOLFSSL_DEBUG_CERTS
    #define WOLFSSL_DEBUG_CERTS
#endif
#ifndef DEBUG_WOLFSSL_VERBOSE
    #define DEBUG_WOLFSSL_VERBOSE
#endif
#ifndef WOLFSSL_HAVE_ERROR_QUEUE
    #define WOLFSSL_HAVE_ERROR_QUEUE
#endif
#ifndef ERROR_QUEUE_PER_THREAD
    #define ERROR_QUEUE_PER_THREAD
#endif

/* Pull logging.c in verbatim so its file-static state (loggingCertEnabled,
 * wc_errors, get_abs_idx(), ...) is in scope and instrumented in THIS
 * binary. logging.c includes settings.h (which picks up user_settings.h via
 * -DWOLFSSL_USER_SETTINGS) via libwolfssl_sources.h. */
#include <wolfcrypt/src/logging.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* ------------------------------------------------------------------------- *
 * Logging callback used to verify (not just execute) the cert-logging
 * decisions: it counts how many times a message actually reached
 * wolfssl_log(), which only happens on the "true" side of each AND.
 * ------------------------------------------------------------------------- */
static int wb_log_count = 0;
static void wb_log_cb(const int logLevel, const char* const logMessage)
{
    (void)logLevel;
    (void)logMessage;
    wb_log_count++;
}

/* ignore_err predicates for wc_PeekErrorNodeLineData()'s
 * "ignore_err && ignore_err(ret)" pair. */
static int wb_ignore_all(int err)  { (void)err; return 1; }
static int wb_ignore_none(int err) { (void)err; return 0; }

/* ------------------------------------------------------------------------- *
 * :372 / :402 -- WOLFSSL_MSG_CERT() / WOLFSSL_MSG_CERT_EX()
 * "(msg != NULL / written > 0) && (loggingCertEnabled != 0)"
 * ------------------------------------------------------------------------- */
static void wb_cert_logging(void)
{
#if defined(HAVE_WOLFSSL_DEBUG_CERTS) || \
    ((defined(WOLFSSL_DEBUG_CERTS) || defined(DEBUG_WOLFSSL)) && \
     !defined(NO_WOLFSSL_DEBUG_CERTS) && !defined(WOLFSSL_DEBUG_ERRORS_ONLY))
    (void)wolfSSL_SetLoggingCb(wb_log_cb);

    /* WOLFSSL_MSG_CERT(): msg != NULL, loggingCertEnabled != 0 */

    /* (msg!=NULL)=T, (loggingCertEnabled!=0)=T -> decision TRUE, logs once */
    wolfSSL_CertDebugging_ON();
    wb_log_count = 0;
    (void)WOLFSSL_MSG_CERT("cert debug message");
    if (wb_log_count != 1) wb_fail = 1;

    /* (msg!=NULL)=T, (loggingCertEnabled!=0)=F -> decision FALSE, no log */
    wolfSSL_CertDebugging_OFF();
    wb_log_count = 0;
    (void)WOLFSSL_MSG_CERT("cert debug message");
    if (wb_log_count != 0) wb_fail = 1;

    /* (msg!=NULL)=F, (loggingCertEnabled!=0)=T -> decision FALSE, no log */
    wolfSSL_CertDebugging_ON();
    wb_log_count = 0;
    (void)WOLFSSL_MSG_CERT(NULL);
    if (wb_log_count != 0) wb_fail = 1;

    WB_NOTE("WOLFSSL_MSG_CERT (:372) msg/loggingCertEnabled pair covered");

#ifdef XVSNPRINTF
    /* WOLFSSL_MSG_CERT_EX(): written > 0, loggingCertEnabled != 0 */

    /* (written>0)=T, (loggingCertEnabled!=0)=T -> decision TRUE, logs once */
    wolfSSL_CertDebugging_ON();
    wb_log_count = 0;
    (void)WOLFSSL_MSG_CERT_EX("cert %s", "debug");
    if (wb_log_count != 1) wb_fail = 1;

    /* (written>0)=T, (loggingCertEnabled!=0)=F -> decision FALSE, no log */
    wolfSSL_CertDebugging_OFF();
    wb_log_count = 0;
    (void)WOLFSSL_MSG_CERT_EX("cert %s", "debug");
    if (wb_log_count != 0) wb_fail = 1;

    /* (written>0)=F (empty formatted string), (loggingCertEnabled!=0)=T
     * -> decision FALSE, no log */
    wolfSSL_CertDebugging_ON();
    wb_log_count = 0;
    (void)WOLFSSL_MSG_CERT_EX("%s", "");
    if (wb_log_count != 0) wb_fail = 1;

    WB_NOTE("WOLFSSL_MSG_CERT_EX (:402) written/loggingCertEnabled pair "
            "covered");
#else
    WB_NOTE("XVSNPRINTF not defined; WOLFSSL_MSG_CERT_EX (:402) skipped");
#endif /* XVSNPRINTF */

    wolfSSL_CertDebugging_OFF();
    (void)wolfSSL_SetLoggingCb(NULL);
#else
    WB_NOTE("certificate logging not compiled in this variant; :372/:402 "
            "skipped");
#endif
}

/* ------------------------------------------------------------------------- *
 * :753 / :997 -- error queue (ERROR_QUEUE_PER_THREAD variant)
 *   get_abs_idx(): "(wc_errors.count == 0) || (relative_idx >= (int)count)"
 *   wc_PeekErrorNodeLineData(): "ignore_err && ignore_err(ret)"
 * ------------------------------------------------------------------------- */
static void wb_error_queue(void)
{
#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && defined(ERROR_QUEUE_PER_THREAD)
    const char *file = NULL;
    const char *reason = NULL;
    int line = 0;
    int ret;

    wc_ClearErrorNodes();

    /* get_abs_idx() via wc_PeekErrorNode(): (count==0)=T -> short circuit,
     * decision TRUE regardless of relative_idx. */
    ret = wc_PeekErrorNode(0, &file, &reason, &line);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) wb_fail = 1;

    if (wc_AddErrorNode(BAD_FUNC_ARG, 111, (char*)"synthetic reason",
            (char*)"synthetic.c") != 0)
        wb_fail = 1;

    /* (count==0)=F, (relative_idx >= count)=T -> decision TRUE via 2nd
     * operand. */
    ret = wc_PeekErrorNode(5, &file, &reason, &line);
    if (ret != WC_NO_ERR_TRACE(BAD_STATE_E)) wb_fail = 1;

    /* (count==0)=F, (relative_idx >= count)=F -> decision FALSE (both
     * operands false, in-range index). */
    ret = wc_PeekErrorNode(0, &file, &reason, &line);
    if (ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG)) wb_fail = 1;

    WB_NOTE("get_abs_idx() (:753) count==0/relative_idx>=count pair "
            "covered");

    /* wc_PeekErrorNodeLineData(): "ignore_err && ignore_err(ret)" */
    wc_ClearErrorNodes();
    if (wc_AddErrorNode(BAD_FUNC_ARG, 111, (char*)"r1", (char*)"f1") != 0)
        wb_fail = 1;

    /* ignore_err==NULL -> 1st operand FALSE, short circuit, node kept. */
    (void)wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, NULL);

    /* ignore_err set but returns 0 -> 1st TRUE, 2nd FALSE, node kept. */
    (void)wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, wb_ignore_none);

    /* ignore_err set and returns 1 -> 1st TRUE, 2nd TRUE, node removed
     * and the loop continues (queue becomes empty -> returns 0). */
    (void)wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, wb_ignore_all);

    WB_NOTE("wc_PeekErrorNodeLineData ignore_err (:997) pair covered");

    wc_ClearErrorNodes();
#else
    WB_NOTE("error queue (WOLFSSL_HAVE_ERROR_QUEUE && "
            "ERROR_QUEUE_PER_THREAD) not compiled in this variant; "
            ":753/:997 skipped");
#endif
    WB_NOTE(":1504/:1516 (the OTHER, non-ERROR_QUEUE_PER_THREAD error-queue "
            "implementation's ignore_err/BAD_MUTEX_E checks) are "
            "structurally excluded from this binary -- see file header "
            "residual note; would need a second white-box variant built "
            "with ERROR_QUEUE_PER_THREAD left undefined.");
}

/* ------------------------------------------------------------------------- *
 * :559 -- WOLFSSL_BUFFER(): "31 < buffer[i] && buffer[i] < 127"
 * Incidentally compiled in by DEBUG_WOLFSSL; covered for completeness.
 * ------------------------------------------------------------------------- */
static void wb_buffer_dump(void)
{
#ifndef WOLFSSL_BUFFER
    /* single call drives all three MC/DC combinations for the ternary's
     * "31 < buffer[i] && buffer[i] < 127" condition, one byte value each:
     *   buffer[0]=65  (31<65)=T,  (65<127)=T  -> printable  ('A')
     *   buffer[1]=0   (31<0)=F   -> short circuit           ('.')
     *   buffer[2]=200 (31<200)=T, (200<127)=F -> not printable ('.') */
    byte buf[3];

    buf[0] = 65;
    buf[1] = 0;
    buf[2] = 200;

    (void)wolfSSL_Debugging_ON();
    WOLFSSL_BUFFER(buf, (word32)sizeof(buf));
    (void)wolfSSL_Debugging_OFF();

    WB_NOTE("WOLFSSL_BUFFER (:559) printable-char ternary pair covered");
#else
    WB_NOTE("WOLFSSL_BUFFER is a macro override in this variant; :559 "
            "skipped");
#endif
}

int main(void)
{
    printf("logging.c core white-box supplement\n");

    wb_cert_logging();
    wb_error_queue();
    wb_buffer_dump();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    return wb_fail ? 1 : 0;
}
