/* wolfevent.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifndef _WOLF_EVENT_H_
#define _WOLF_EVENT_H_

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef SINGLE_THREADED
    #include <wolfssl/wolfcrypt/wc_port.h>
#endif

typedef struct WOLFSSL WOLFSSL;
typedef struct WOLF_EVENT WOLF_EVENT;
typedef struct WOLFSSL_CTX WOLFSSL_CTX;

typedef unsigned short WOLF_EVENT_FLAG;

typedef enum WOLF_EVENT_TYPE {
    WOLF_EVENT_TYPE_NONE,
    #ifdef WOLFSSL_ASYNC_CRYPT
        WOLF_EVENT_TYPE_ASYNC_ANY,
        WOLF_EVENT_TYPE_ASYNC_WOLFSSL,
        WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT,
        WOLF_EVENT_TYPE_ASYNC_FIRST = WOLF_EVENT_TYPE_ASYNC_WOLFSSL,
        WOLF_EVENT_TYPE_ASYNC_LAST = WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT,
    #endif
} WOLF_EVENT_TYPE;

struct WOLF_EVENT {
    /* double linked list */
    WOLF_EVENT*         next;
    WOLF_EVENT*         prev;

    void*               context;
#ifdef HAVE_CAVIUM
    word64              reqId;
#endif
    int                 ret;    /* Async return code */
    WOLF_EVENT_TYPE     type;
    WOLF_EVENT_FLAG     pending:1;
    WOLF_EVENT_FLAG     done:1;
    /* Future event flags can go here */
};

enum WOLF_POLL_FLAGS {
    WOLF_POLL_FLAG_CHECK_HW = 0x01,
};

typedef struct {
    WOLF_EVENT*         head;     /* head of queue */
    WOLF_EVENT*         tail;     /* tail of queue */
#ifndef SINGLE_THREADED
    wolfSSL_Mutex       lock;     /* queue lock */
#endif
    int                 count;
} WOLF_EVENT_QUEUE;


#ifdef HAVE_WOLF_EVENT

/* Event */
WOLFSSL_API int wolfEvent_Init(WOLF_EVENT* event, WOLF_EVENT_TYPE type, void* context);
WOLFSSL_API int wolfEvent_Poll(WOLF_EVENT* event, WOLF_EVENT_FLAG flags);

/* Event Queue */
WOLFSSL_API int wolfEventQueue_Init(WOLF_EVENT_QUEUE* queue);
WOLFSSL_API int wolfEventQueue_Push(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);
WOLFSSL_API int wolfEventQueue_Pop(WOLF_EVENT_QUEUE* queue, WOLF_EVENT** event);
WOLFSSL_API int wolfEventQueue_Remove(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);
WOLFSSL_API int wolfEventQueue_Poll(WOLF_EVENT_QUEUE* queue, void* context_filter,
    WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount);
WOLFSSL_API int wolfEventQueue_Count(WOLF_EVENT_QUEUE* queue);
WOLFSSL_API void wolfEventQueue_Free(WOLF_EVENT_QUEUE* queue);

#endif /* HAVE_WOLF_EVENT */


#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif /* _WOLF_EVENT_H_ */
