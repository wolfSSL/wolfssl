/* test_logging_globalq_whitebox.c
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
 * White-box MC/DC supplement for wolfcrypt/src/logging.c -- the GLOBAL
 * (mutex + linked-list) error-queue implementation, i.e. the
 * "#else" / ERROR_QUEUE_PER_THREAD *undefined* half of the
 * "#ifdef ERROR_QUEUE_PER_THREAD" split.
 *
 * Sibling tests/unit-mcdc/test_logging_whitebox.c compiles logging.c with
 * ERROR_QUEUE_PER_THREAD defined and therefore can only reach the
 * thread-local-storage error-queue implementation's decisions. Its file
 * header documents (and this file closes) the residual it explicitly left
 * behind: the *other*, mutually exclusive error-queue implementation's
 * wc_PeekErrorNodeLineData() decisions at logging.c:1504 and :1516,
 * plus the multi-condition loop guards in getErrorNodeCurrentIdx() (:1340)
 * and removeErrorNode() (:1361) that only exist in this global-queue half.
 * A single translation unit can only compile in one of the two
 * implementations (they are #ifdef/#else exclusive), hence this second,
 * otherwise-identical white-box binary.
 *
 * Targeted decisions, by logging.c line (as reviewed during authoring; line
 * numbers may drift slightly with unrelated edits):
 *
 *   :1340 getErrorNodeCurrentIdx():
 *         "current != wc_current_node && current != NULL"
 *   :1361 removeErrorNode():
 *         "current != NULL && idx > 0"
 *   :1504 wc_PeekErrorNodeLineData():
 *         "ret == WC_NO_ERR_TRACE(BAD_MUTEX_E) ||
 *          ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG) ||
 *          ret == WC_NO_ERR_TRACE(BAD_STATE_E)"
 *   :1516 wc_PeekErrorNodeLineData(): "ignore_err && ignore_err(ret)"
 *
 * Enabling macros defined below (guarded so a build that already sets any
 * of these via its own user_settings.h/CFLAGS is not broken by
 * redefinition):
 *   DEBUG_WOLFSSL            - core debug logging (also needed to compile
 *                              WOLFSSL_MSG()/WOLFSSL_ENTER() used inside the
 *                              error-queue functions).
 *   WOLFSSL_HAVE_ERROR_QUEUE - selects the real (non-stub) error queue.
 *   DEBUG_WOLFSSL_VERBOSE    - non-OPENSSL_EXTRA gate that admits the error
 *                              queue implementation block
 *                              ("#if defined(OPENSSL_EXTRA) ||
 *                              defined(DEBUG_WOLFSSL_VERBOSE) ||
 *                              defined(HAVE_MEMCACHED)").
 *
 * IMPORTANT: ERROR_QUEUE_PER_THREAD is deliberately left UNDEFINED here --
 * that is precisely what selects logging.c's "#else" global-queue
 * implementation this file targets. OPENSSL_EXTRA is also deliberately
 * never defined (out of scope, same rationale as the sibling file).
 *
 * Each targeted decision is driven mostly through the public error-queue
 * API (wc_LoggingInit, wc_AddErrorNode, wc_PullErrorNode, wc_RemoveErrorNode,
 * wc_PeekErrorNodeLineData, wc_ClearErrorNodes, wc_LoggingCleanup). Since
 * this file #includes logging.c directly, its file-static helpers
 * (getErrorNodeCurrentIdx(), removeErrorNode(), peekErrorNode()) and file
 * globals (wc_errors, wc_current_node, wc_last_node, wc_errors_count) are
 * also in scope in this translation unit and are read (never written
 * directly) to confirm queue shape between calls.
 *
 * Build: intended to be compiled the same way as the other white-box files
 * in this directory (same MC/DC CFLAGS, -DHAVE_CONFIG_H and -I<workspace>
 * as the instrumented library), then linked against that variant's
 * libwolfssl.a with its logging.o removed (this TU supplies the
 * instrumented logging.c, compiled here with the macros above regardless of
 * what the rest of the library was built with). NOT part of the wolfSSL
 * build; not registered in tests/api. See tests/unit-mcdc/README.md.
 */

#ifndef DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL
#endif
#ifndef DEBUG_WOLFSSL_VERBOSE
    #define DEBUG_WOLFSSL_VERBOSE
#endif
#ifndef WOLFSSL_HAVE_ERROR_QUEUE
    #define WOLFSSL_HAVE_ERROR_QUEUE
#endif

/* Pull logging.c in verbatim so its file-static state (wc_errors,
 * wc_current_node, wc_last_node, getErrorNodeCurrentIdx(),
 * removeErrorNode(), peekErrorNode(), ...) is in scope and instrumented in
 * THIS binary. logging.c includes settings.h (which picks up
 * user_settings.h via -DWOLFSSL_USER_SETTINGS) via libwolfssl_sources.h. */
#include <wolfcrypt/src/logging.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && !defined(ERROR_QUEUE_PER_THREAD)

/* ignore_err predicates for wc_PeekErrorNodeLineData()'s
 * "ignore_err && ignore_err(ret)" pair (:1516). */
static int wb_ignore_all(int err)  { (void)err; return 1; }
static int wb_ignore_none(int err) { (void)err; return 0; }

/* Small helper so failures point at a specific check without aborting the
 * whole run (crash-safety: never dereference on a failed expectation). */
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

#endif /* WOLFSSL_HAVE_ERROR_QUEUE && !ERROR_QUEUE_PER_THREAD */

/* ------------------------------------------------------------------------- *
 * :1504 -- wc_PeekErrorNodeLineData(): the peekErrorNode() return-value OR,
 *   "ret == WC_NO_ERR_TRACE(BAD_MUTEX_E) ||
 *    ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG) ||
 *    ret == WC_NO_ERR_TRACE(BAD_STATE_E)"
 *
 * peekErrorNode() itself only ever *returns* BAD_FUNC_ARG (mid-list index
 * search runs off the end) or BAD_STATE_E (queue empty / index not found at
 * all) as its own error signal; it never manufactures BAD_MUTEX_E. To
 * exercise the first OR operand (and to isolate each operand from the
 * others per node-value equality, independent of *how* the code path is
 * reached) this drives the comparison via the stored node *value*: a node
 * is added whose application-supplied error code numerically equals one of
 * the three sentinel codes, then peeked back out, which is exactly the
 * (pre-existing, not-our-bug-to-fix) code-reuse hazard that makes this
 * decision reachable with all three operands independently true.
 * ------------------------------------------------------------------------- */
static void wb_peek_line_data_ret_or(void)
{
#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && !defined(ERROR_QUEUE_PER_THREAD)
    unsigned long uret;

    /* (1) ret == BAD_MUTEX_E -> 1st operand TRUE, decision TRUE, function
     * returns 0 without ever reaching the ignore_err check. */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(BAD_MUTEX_E, 10, (char*)"bad mutex node",
            (char*)"synthetic.c") == 0, "AddErrorNode(BAD_MUTEX_E)");
    uret = wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, NULL);
    WB_CHECK(uret == 0, ":1504 ret==BAD_MUTEX_E short-circuits to 0");

    /* (2) ret == BAD_FUNC_ARG -> 1st operand FALSE, 2nd operand TRUE,
     * decision TRUE via the 2nd operand. */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(BAD_FUNC_ARG, 20, (char*)"bad func arg node",
            (char*)"synthetic.c") == 0, "AddErrorNode(BAD_FUNC_ARG)");
    uret = wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, NULL);
    WB_CHECK(uret == 0, ":1504 ret==BAD_FUNC_ARG short-circuits to 0");

    /* (3) ret == BAD_STATE_E via the *natural* empty-queue path (1st and
     * 2nd operands FALSE, 3rd operand TRUE): peekErrorNode() returns
     * BAD_STATE_E itself when the queue has no nodes at all. */
    wc_ClearErrorNodes();
    uret = wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, NULL);
    WB_CHECK(uret == 0, ":1504 empty queue -> ret==BAD_STATE_E -> 0");

    /* (4) all three operands FALSE: a node whose stored value is a normal,
     * non-sentinel error code. Decision FALSE, execution falls through to
     * the "ret < 0" normalization and the :1516 ignore_err check. */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(WC_KEY_SIZE_E, 30, (char*)"ordinary node",
            (char*)"synthetic.c") == 0, "AddErrorNode(WC_KEY_SIZE_E)");
    uret = wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, NULL);
    WB_CHECK(uret == (unsigned long)(0 - WC_KEY_SIZE_E),
            ":1504 ordinary code falls through, :1516 short-circuits false, "
            "value normalized and returned");

    wc_ClearErrorNodes();

    WB_NOTE("wc_PeekErrorNodeLineData ret==BAD_MUTEX_E/BAD_FUNC_ARG/"
            "BAD_STATE_E OR (:1504) covered -- all 3 operands independently "
            "true, plus all-false");
#else
    WB_NOTE("global error queue (WOLFSSL_HAVE_ERROR_QUEUE && "
            "!ERROR_QUEUE_PER_THREAD) not compiled in this variant; :1504 "
            "skipped");
#endif
}

/* ------------------------------------------------------------------------- *
 * :1516 -- wc_PeekErrorNodeLineData(): "ignore_err && ignore_err(ret)"
 * ------------------------------------------------------------------------- */
static void wb_peek_line_data_ignore_err(void)
{
#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && !defined(ERROR_QUEUE_PER_THREAD)
    unsigned long uret;

    /* ignore_err == NULL -> 1st operand FALSE, short circuit: node kept,
     * its (normalized, positive) value returned. */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(WC_KEY_SIZE_E, 40, (char*)"r1", (char*)"f1")
            == 0, "AddErrorNode #1");
    uret = wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, NULL);
    WB_CHECK(uret == (unsigned long)(0 - WC_KEY_SIZE_E),
            ":1516 ignore_err==NULL -> node kept, value returned");
    WB_CHECK(wc_errors_count == 1, ":1516 node NOT removed (ignore_err NULL)");

    /* ignore_err set but returns 0 -> 1st operand TRUE, 2nd operand FALSE:
     * node kept, its value returned. */
    uret = wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, wb_ignore_none);
    WB_CHECK(uret == (unsigned long)(0 - WC_KEY_SIZE_E),
            ":1516 ignore_err(ret)==0 -> node kept, value returned");
    WB_CHECK(wc_errors_count == 1,
            ":1516 node NOT removed (ignore_err returns 0)");

    /* ignore_err set and returns 1 -> both operands TRUE: node removed and
     * the loop continues; queue becomes empty so the *next* iteration hits
     * the :1504 BAD_STATE_E natural-empty-queue path and returns 0 (this
     * also confirms the loop's "continue" edge terminates rather than
     * spinning). */
    uret = wc_PeekErrorNodeLineData(NULL, NULL, NULL, NULL, wb_ignore_all);
    WB_CHECK(uret == 0,
            ":1516 ignore_err(ret)==1 -> node removed, loop drains to 0");
    WB_CHECK(wc_errors_count == 0, ":1516 node WAS removed (ignore_err(ret))");

    wc_ClearErrorNodes();

    WB_NOTE("wc_PeekErrorNodeLineData ignore_err (:1516) pair covered");
#else
    WB_NOTE("global error queue (WOLFSSL_HAVE_ERROR_QUEUE && "
            "!ERROR_QUEUE_PER_THREAD) not compiled in this variant; :1516 "
            "skipped");
#endif
}

/* ------------------------------------------------------------------------- *
 * :1340 -- getErrorNodeCurrentIdx():
 *   "current != wc_current_node && current != NULL"
 *
 * getErrorNodeCurrentIdx() is a file-static helper, in scope in this TU
 * (see file header), so it is called directly rather than through
 * wc_GetErrorNodeErr(): that public wrapper only reaches it when
 * pullErrorNode() returns a non-negative value, which never happens for
 * wolfSSL's own (negative) error codes and would otherwise force awkward
 * positive placeholder "error" values just to route around it.
 *
 *   - op1 FALSE immediately (0 iterations): wc_current_node == wc_errors
 *     (the head) -- the default state right after wc_AddErrorNode(), before
 *     anything pulls the cursor forward.
 *   - op1 TRUE, op2 TRUE for one iteration, then op1 FALSE (found): two
 *     nodes queued, wc_PullErrorNode() advances the cursor to the 2nd node
 *     while wc_errors (the list head pointer) still points at the 1st, so
 *     the search walks exactly one non-matching, non-NULL node.
 *   - op1 TRUE, op2 FALSE (list exhausted without finding the cursor): this
 *     defensive "cursor not found" case never occurs through the public API
 *     (pullErrorNode()/removeErrorNode() always keep wc_current_node
 *     consistent with the list). It is driven here by temporarily pointing
 *     the file-static wc_current_node at a value that is provably not a
 *     member of the (real, valid) wc_errors list. This is safe: the
 *     function only ever *compares* wc_current_node as a pointer value; it
 *     never dereferences it, so no invalid memory is read. wc_current_node
 *     is restored (via wc_ClearErrorNodes(), which unconditionally resets
 *     it to NULL) immediately afterward.
 * ------------------------------------------------------------------------- */
static void wb_get_error_node_current_idx(void)
{
#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && !defined(ERROR_QUEUE_PER_THREAD)
    int idx;
    int not_in_list; /* address used only for pointer comparison, never
                       * dereferenced as a struct wc_error_queue* */

    /* op1 FALSE immediately: wc_current_node == wc_errors (head). */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(WC_KEY_SIZE_E, 50, (char*)"n1", (char*)"f1")
            == 0, "AddErrorNode #1");
    idx = getErrorNodeCurrentIdx();
    WB_CHECK(idx == 0, ":1340 op1 false at head (cursor==wc_errors)");

    /* op1 TRUE, op2 TRUE for one iteration, then op1 FALSE (found): two
     * nodes queued, pull the first so the cursor advances to the 2nd node
     * while wc_errors still points at the (still-linked) 1st node. */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(WC_KEY_SIZE_E, 60, (char*)"n1", (char*)"f1")
            == 0, "AddErrorNode #1");
    WB_CHECK(wc_AddErrorNode(BUFFER_E, 61, (char*)"n2", (char*)"f2")
            == 0, "AddErrorNode #2");
    WB_CHECK(wc_PullErrorNode(NULL, NULL, NULL) == WC_KEY_SIZE_E,
            ":1340 setup pull #1");
    idx = getErrorNodeCurrentIdx();
    WB_CHECK(idx == 1,
            ":1340 op1/op2 true for one iteration (cursor advanced past "
            "head)");

    /* op1 TRUE, op2 FALSE: point the cursor at a bogus, not-in-list value
     * so the search walks every real node (op1 true each time, since the
     * bogus cursor never matches) and only stops when it runs off the end
     * (op2 false). getErrorNodeCurrentIdx() resets idx to 0 whenever it
     * exits with current==NULL, whether "found" (cursor was NULL, matched)
     * or "not found" (ran off the list) -- so idx==0 here is the same
     * defensive-recovery result the real code falls back to. */
    wc_current_node = (struct wc_error_queue*)&not_in_list;
    idx = getErrorNodeCurrentIdx();
    WB_CHECK(idx == 0,
            ":1340 op1 true/op2 false -- cursor not found, list exhausted");

    wc_ClearErrorNodes(); /* also restores wc_current_node to NULL */

    WB_NOTE("getErrorNodeCurrentIdx (:1340) current!=wc_current_node/"
            "current!=NULL pair covered -- all 3 reachable operand "
            "combinations (op1 false / op1+op2 true / op1 true+op2 false)");
#else
    WB_NOTE("global error queue not compiled in this variant; :1340 "
            "skipped");
#endif
}

/* ------------------------------------------------------------------------- *
 * :1361 -- removeErrorNode(): "current != NULL && idx > 0"
 *
 * Driven via wc_RemoveErrorNode(idx), the public wrapper.
 * ------------------------------------------------------------------------- */
static void wb_remove_error_node(void)
{
#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && !defined(ERROR_QUEUE_PER_THREAD)
    /* op1 TRUE, op2 FALSE (idx==0): zero loop iterations, the common case
     * of removing the head. */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(WC_KEY_SIZE_E, 70, (char*)"n1", (char*)"f1")
            == 0, "AddErrorNode #1");
    wc_RemoveErrorNode(0);
    WB_CHECK(wc_errors_count == 0, ":1361 op2 false (idx==0) removes head");

    /* op1 TRUE, op2 TRUE for one iteration, then op1 FALSE (found before
     * running off the list): 3 nodes, remove idx==1 (the middle one). */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(WC_KEY_SIZE_E, 80, (char*)"n1", (char*)"f1")
            == 0, "AddErrorNode #1");
    WB_CHECK(wc_AddErrorNode(BUFFER_E, 81, (char*)"n2", (char*)"f2")
            == 0, "AddErrorNode #2");
    WB_CHECK(wc_AddErrorNode(MEMORY_E, 82, (char*)"n3", (char*)"f3")
            == 0, "AddErrorNode #3");
    wc_RemoveErrorNode(1);
    WB_CHECK(wc_errors_count == 2,
            ":1361 op1/op2 true then op1 false (middle node found)");

    /* op1 FALSE via running off the end (idx beyond the queue length):
     * single node, idx far larger than count -- loop decrements idx while
     * walking next pointers until current becomes NULL. */
    wc_ClearErrorNodes();
    WB_CHECK(wc_AddErrorNode(WC_KEY_SIZE_E, 90, (char*)"n1", (char*)"f1")
            == 0, "AddErrorNode #1");
    wc_RemoveErrorNode(99);
    WB_CHECK(wc_errors_count == 1,
            ":1361 op1 false via list exhaustion (out-of-range idx) -- no "
            "node removed");

    wc_ClearErrorNodes();

    WB_NOTE("removeErrorNode (:1361) current!=NULL/idx>0 pair covered");
#else
    WB_NOTE("global error queue not compiled in this variant; :1361 "
            "skipped");
#endif
}

int main(void)
{
    printf("logging.c global error-queue white-box supplement\n");

#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && !defined(ERROR_QUEUE_PER_THREAD)
    if (wc_LoggingInit() != 0) {
        printf("  [wb][FAIL] wc_LoggingInit failed\n");
        return 1;
    }
#endif

    wb_peek_line_data_ret_or();
    wb_peek_line_data_ignore_err();
    wb_get_error_node_current_idx();
    wb_remove_error_node();

#if defined(WOLFSSL_HAVE_ERROR_QUEUE) && !defined(ERROR_QUEUE_PER_THREAD)
    (void)wc_LoggingCleanup();
#endif

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    return wb_fail ? 1 : 0;
}
