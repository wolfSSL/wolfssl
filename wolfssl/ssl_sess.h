/* ssl_sess.h
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

#ifndef WOLFSSL_SSL_SESS_H
#define WOLFSSL_SSL_SESS_H

#ifndef NO_SESSION_CACHE

#ifdef __cplusplus
    extern "C" {
#endif /* __cplusplus */

    /* basic config gives a cache with 33 sessions, adequate for clients and
       embedded servers

       TITAN_SESSION_CACHE allows just over 2 million sessions, for servers
       with titanic amounts of memory with long session ID timeouts and high
       levels of traffic.

       ENABLE_SESSION_CACHE_ROW_LOCK: Allows row level locking for increased
       performance with large session caches

       HUGE_SESSION_CACHE yields 65,791 sessions, for servers under heavy load,
       allows over 13,000 new sessions per minute or over 200 new sessions per
       second

       BIG_SESSION_CACHE yields 20,027 sessions

       MEDIUM_SESSION_CACHE allows 1055 sessions, adequate for servers that
       aren't under heavy load, basically allows 200 new sessions per minute

       SMALL_SESSION_CACHE only stores 6 sessions, good for embedded clients
       or systems where the default of is too much RAM.
       SessionCache takes about 2K, ClientCache takes about 3Kbytes

       MICRO_SESSION_CACHE only stores 1 session, good for embedded clients
       or systems where memory is at a premium.
       SessionCache takes about 400 bytes, ClientCache takes 576 bytes

       default SESSION_CACHE stores 33 sessions (no XXX_SESSION_CACHE defined)
       SessionCache takes about 13K bytes, ClientCache takes 17K bytes
    */
    #if defined(TITAN_SESSION_CACHE)
        #define SESSIONS_PER_ROW 31
        #define SESSION_ROWS 64937
        #ifndef ENABLE_SESSION_CACHE_ROW_LOCK
            #define ENABLE_SESSION_CACHE_ROW_LOCK
        #endif
    #elif defined(HUGE_SESSION_CACHE)
        #define SESSIONS_PER_ROW 11
        #define SESSION_ROWS 5981
    #elif defined(BIG_SESSION_CACHE)
        #define SESSIONS_PER_ROW 7
        #define SESSION_ROWS 2861
    #elif defined(MEDIUM_SESSION_CACHE)
        #define SESSIONS_PER_ROW 5
        #define SESSION_ROWS 211
    #elif defined(SMALL_SESSION_CACHE)
        #define SESSIONS_PER_ROW 2
        #define SESSION_ROWS 3
    #elif defined(MICRO_SESSION_CACHE)
        #define SESSIONS_PER_ROW 1
        #define SESSION_ROWS 1
    #else
        #define SESSIONS_PER_ROW 3
        #define SESSION_ROWS 11
    #endif

    #define INVALID_SESSION_ROW (-1)

    #ifdef NO_SESSION_CACHE_ROW_LOCK
        #undef ENABLE_SESSION_CACHE_ROW_LOCK
    #endif

    typedef struct SessionRow {
        int nextIdx;                           /* where to place next one   */
        int totalCount;                        /* sessions ever on this row */
    #ifdef SESSION_CACHE_DYNAMIC_MEM
        WOLFSSL_SESSION* Sessions[SESSIONS_PER_ROW];
        void* heap;
    #else
        WOLFSSL_SESSION Sessions[SESSIONS_PER_ROW];
    #endif

    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        /* not included in import/export */
        wolfSSL_RwLock row_lock;
        int lock_valid;
    #endif
    } SessionRow;

    #if defined(PERSIST_SESSION_CACHE) && !defined(SESSION_CACHE_DYNAMIC_MEM)
        /* when writing / restoring from storage, do not read the full struct,
         * as this would clobber active row locks. */
        #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
            #define SIZEOF_SESSION_ROW WC_OFFSETOF(SessionRow, row_lock)
        #else
            #define SIZEOF_SESSION_ROW (sizeof(SessionRow))
        #endif /* ENABLE_SESSION_CACHE_ROW_LOCK */
    #endif /* PERSIST_SESSION_CACHE && !SESSION_CACHE_DYNAMIC_MEM */

    #ifndef NO_CLIENT_CACHE
        #ifndef CLIENT_SESSIONS_MULTIPLIER
            #ifdef NO_SESSION_CACHE_REF
                #define CLIENT_SESSIONS_MULTIPLIER 1
            #else
                /* ClientSession objects are lightweight (compared to
                 * WOLFSSL_SESSION) so to decrease chance that user will reuse
                 * the wrong session, increase the ClientCache size. This will
                 * make the entire ClientCache about the size of one
                 * WOLFSSL_SESSION object. */
                #define CLIENT_SESSIONS_MULTIPLIER 8
            #endif
        #endif
        #define CLIENT_SESSIONS_PER_ROW \
                                (SESSIONS_PER_ROW * CLIENT_SESSIONS_MULTIPLIER)
        #define CLIENT_SESSION_ROWS (SESSION_ROWS * CLIENT_SESSIONS_MULTIPLIER)

        #if CLIENT_SESSIONS_PER_ROW > 65535
            #error CLIENT_SESSIONS_PER_ROW too big
        #endif
        #if CLIENT_SESSION_ROWS > 65535
            #error CLIENT_SESSION_ROWS too big
        #endif

        struct ClientSession {
            word16 serverRow;            /* SessionCache Row id */
            word16 serverIdx;            /* SessionCache Idx (column) */
            word32 sessionIDHash;
        };
    #ifndef WOLFSSL_CLIENT_SESSION_DEFINED
        typedef struct ClientSession ClientSession;
        #define WOLFSSL_CLIENT_SESSION_DEFINED
    #endif

        typedef struct ClientRow {
            int nextIdx;                /* where to place next one   */
            int totalCount;             /* sessions ever on this row */
            ClientSession Clients[CLIENT_SESSIONS_PER_ROW];
        } ClientRow;
    #endif /* !NO_CLIENT_CACHE */

    #if defined(PERSIST_SESSION_CACHE) && !defined(SESSION_CACHE_DYNAMIC_MEM)
    /* for persistence, if changes to layout need to increment and modify
       save_session_cache() and restore_session_cache and memory versions too */
    #define WOLFSSL_CACHE_VERSION 3

    /* Session Cache Header information */
    typedef struct {
        int version;     /* cache layout version id */
        int rows;        /* session rows */
        int columns;     /* session columns */
        int sessionSz;   /* sizeof WOLFSSL_SESSION */
    } cache_header_t;

    /* current persistence layout is:

       1) cache_header_t
       2) SessionCache
       3) ClientCache

       update WOLFSSL_CACHE_VERSION if change layout for the following
       PERSISTENT_SESSION_CACHE functions
    */
    #endif /* PERSIST_SESSION_CACHE && !SESSION_CACHE_DYNAMIC_MEM */

#ifdef __cplusplus
    }  /* extern "C" */
#endif /* __cplusplus */

#endif /* !NO_SESSION_CACHE */

#endif /* WOLFSSL_SSL_SESS_H */
