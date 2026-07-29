/* test_wolfevent.c
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

#include <wolfssl/wolfcrypt/wolfevent.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <tests/api/api.h>
#include <tests/api/test_wolfevent.h>

/*
 * MC/DC decision coverage for the wolfEvent / wolfEventQueue_* queue core
 * (wolfcrypt/src/wolfevent.c). The event queue is a generic doubly-linked FIFO
 * whose logic is async-independent, so this drives every reachable decision
 * from the public API in a non-async (HAVE_WOLF_EVENT without
 * WOLFSSL_ASYNC_CRYPT) build:
 *   - the NULL-argument guards (queue==NULL || event==NULL) in
 *     Push/Pop/Add/Remove, each operand flipped independently;
 *   - the Add first-element branch (queue->tail == NULL);
 *   - the Remove head/tail/middle cascade, incl. the
 *     (event==head && event==tail) sole-element AND and the defensive
 *     (next==NULL || prev==NULL) corruption guard;
 *   - the Poll queue==NULL guard and the (context_filter==NULL ||
 *     event->context==context_filter) match, each operand flipped.
 *
 * Documented residuals (async-coupled, out of the MC/DC boundary like async.c):
 * the single async decision in wolfEvent_Poll (type-range check, compiled only
 * under WOLFSSL_ASYNC_CRYPT), and the Poll event-processing tail
 * (state==DONE / events / count>=maxEvents), unreachable once the non-async
 * wolfEvent_Poll returns BAD_COND_E (<0) and breaks the iteration loop.
 */
int test_wc_WolfEventDecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_WOLF_EVENT
    WOLF_EVENT_QUEUE q;
    WOLF_EVENT e1, e2, e3;
    WOLF_EVENT* popped = NULL;
    WOLF_EVENT* polled[4];
    int qInit = 0;
    int cnt = 0;

    /* ---- wolfEvent_Init: event==NULL, then state==PENDING ---- */
    ExpectIntEQ(wolfEvent_Init(NULL, WOLF_EVENT_TYPE_NONE, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                 /* event==NULL true */
    XMEMSET(&e1, 0, sizeof(e1));
    ExpectIntEQ(wolfEvent_Init(&e1, WOLF_EVENT_TYPE_NONE, NULL), 0); /* both false */
    e1.state = WOLF_EVENT_STATE_PENDING;
    ExpectIntEQ(wolfEvent_Init(&e1, WOLF_EVENT_TYPE_NONE, NULL),
        WC_NO_ERR_TRACE(BAD_COND_E));                   /* state==PENDING true */

    /* ---- wolfEventQueue_Init: queue==NULL ---- */
    ExpectIntEQ(wolfEventQueue_Init(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfEventQueue_Init(&q), 0);
    qInit = 1;

    /* Fresh events with distinct, non-NULL contexts for the Poll filter. */
    XMEMSET(&e1, 0, sizeof(e1));
    XMEMSET(&e2, 0, sizeof(e2));
    XMEMSET(&e3, 0, sizeof(e3));
    ExpectIntEQ(wolfEvent_Init(&e1, WOLF_EVENT_TYPE_NONE, (void*)0x1), 0);
    ExpectIntEQ(wolfEvent_Init(&e2, WOLF_EVENT_TYPE_NONE, (void*)0x2), 0);
    ExpectIntEQ(wolfEvent_Init(&e3, WOLF_EVENT_TYPE_NONE, (void*)0x3), 0);

    /* ---- wolfEventQueue_Push: queue==NULL || event==NULL ---- */
    ExpectIntEQ(wolfEventQueue_Push(NULL, &e1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                 /* queue==NULL true */
    ExpectIntEQ(wolfEventQueue_Push(&q, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                 /* event==NULL true */
    /* both false: real pushes. The first Add hits queue->tail==NULL (true),
     * the rest hit the false (append) arm. */
    ExpectIntEQ(wolfEventQueue_Push(&q, &e1), 0);       /* Add: tail==NULL true */
    ExpectIntEQ(wolfEventQueue_Push(&q, &e2), 0);       /* Add: tail==NULL false */
    ExpectIntEQ(wolfEventQueue_Push(&q, &e3), 0);
    ExpectIntEQ(wolfEventQueue_Count(&q), 3);

    /* ---- wolfEventQueue_Add direct: queue==NULL || event==NULL ---- */
    ExpectIntEQ(wolfEventQueue_Add(NULL, &e1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfEventQueue_Add(&q, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ---- wolfEventQueue_Count: queue==NULL ---- */
    ExpectIntEQ(wolfEventQueue_Count(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ---- wolfEventQueue_Poll: queue==NULL, then the context filter ----
     * The non-async wolfEvent_Poll returns BAD_COND_E, so each Poll that enters
     * an event breaks after the first match (ret<0); no events are removed, so
     * the queue is intact for the Remove tests below. */
    ExpectIntEQ(wolfEventQueue_Poll(NULL, NULL, NULL, 0, 0, &cnt),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                 /* queue==NULL true */
    cnt = 0;
    (void)wolfEventQueue_Poll(&q, NULL, polled, 4, 0, &cnt);      /* filter==NULL true */
    cnt = 0;
    (void)wolfEventQueue_Poll(&q, (void*)0x1, polled, 4, 0, &cnt);/* filter!=NULL, head matches */
    cnt = 0;
    /* filter == tail context: head/middle don't match (both operands false),
     * tail matches (second operand true). */
    (void)wolfEventQueue_Poll(&q, (void*)0x3, polled, 4, 0, &cnt);

    /* ---- wolfEventQueue_Pop / Remove NULL guards ---- */
    ExpectIntEQ(wolfEventQueue_Pop(NULL, &popped), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfEventQueue_Pop(&q, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfEventQueue_Remove(NULL, &e1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfEventQueue_Remove(&q, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* ---- Remove head/tail/sole cascade (queue is [e1,e2,e3]) ----
     *   remove e1: event==head (true) && event==tail (false) -> head arm
     *   remove e3: not head (AND false via op0) -> tail arm (event==tail true)
     *   remove e2: event==head && event==tail both true -> sole arm */
    ExpectIntEQ(wolfEventQueue_Remove(&q, &e1), 0);     /* head of >1 */
    ExpectIntEQ(wolfEventQueue_Remove(&q, &e3), 0);     /* tail of >1 */
    ExpectIntEQ(wolfEventQueue_Remove(&q, &e2), 0);     /* sole element */
    ExpectIntEQ(wolfEventQueue_Count(&q), 0);

    /* ---- Remove middle: the else (not head, not tail) arm, with a
     * well-formed queue so (next==NULL || prev==NULL) is false both ways. */
    ExpectIntEQ(wolfEventQueue_Add(&q, &e1), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e2), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e3), 0);
    ExpectIntEQ(wolfEventQueue_Remove(&q, &e2), 0);     /* middle: next,prev both set */

    /* ---- (next==NULL || prev==NULL) TRUE halves: a deliberately corrupted
     * middle node exercises the defensive BAD_STATE_E guard that a well-formed
     * queue can never reach. */
    if (qInit) {
        wolfEventQueue_Free(&q);
    }
    ExpectIntEQ(wolfEventQueue_Init(&q), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e1), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e2), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e3), 0);
    e2.next = NULL;                                     /* corrupt: middle w/ NULL next */
    ExpectIntEQ(wolfEventQueue_Remove(&q, &e2),
        WC_NO_ERR_TRACE(BAD_STATE_E));                  /* next==NULL true */

    wolfEventQueue_Free(&q);
    ExpectIntEQ(wolfEventQueue_Init(&q), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e1), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e2), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e3), 0);
    e2.prev = NULL;                                     /* corrupt: next set, prev NULL */
    ExpectIntEQ(wolfEventQueue_Remove(&q, &e2),
        WC_NO_ERR_TRACE(BAD_STATE_E));                  /* next!=NULL, prev==NULL true */

    wolfEventQueue_Free(&q);

    /* ---- successful Pop: the (queue==NULL || event==NULL) all-false half.
     * Pop hands back the head node via *event and returns 0. */
    ExpectIntEQ(wolfEventQueue_Init(&q), 0);
    ExpectIntEQ(wolfEventQueue_Add(&q, &e1), 0);
    popped = NULL;
    ExpectIntEQ(wolfEventQueue_Pop(&q, &popped), 0);   /* both operands false */
    ExpectNotNull(popped);
    ExpectIntEQ(wolfEventQueue_Count(&q), 0);
    wolfEventQueue_Free(&q);
#endif /* HAVE_WOLF_EVENT */
    return EXPECT_RESULT();
}
