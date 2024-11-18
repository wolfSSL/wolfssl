/* ssl_sess.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_SSL_SESS_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_sess.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef NO_SESSION_CACHE

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
    #define SIZEOF_SESSION_ROW (sizeof(WOLFSSL_SESSION) + (sizeof(int) * 2))

    static WOLFSSL_GLOBAL SessionRow SessionCache[SESSION_ROWS];

    #if defined(WOLFSSL_SESSION_STATS) && defined(WOLFSSL_PEAK_SESSIONS)
        static WOLFSSL_GLOBAL word32 PeakSessions;
    #endif

    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
    #define SESSION_ROW_RD_LOCK(row)   wc_LockRwLock_Rd(&(row)->row_lock)
    #define SESSION_ROW_WR_LOCK(row)   wc_LockRwLock_Wr(&(row)->row_lock)
    #define SESSION_ROW_UNLOCK(row)    wc_UnLockRwLock(&(row)->row_lock);
    #else
    static WOLFSSL_GLOBAL wolfSSL_RwLock session_lock; /* SessionCache lock */
    static WOLFSSL_GLOBAL int session_lock_valid = 0;
    #define SESSION_ROW_RD_LOCK(row)   wc_LockRwLock_Rd(&session_lock)
    #define SESSION_ROW_WR_LOCK(row)   wc_LockRwLock_Wr(&session_lock)
    #define SESSION_ROW_UNLOCK(row)    wc_UnLockRwLock(&session_lock);
    #endif

    #if !defined(NO_SESSION_CACHE_REF) && defined(NO_CLIENT_CACHE)
    #error ClientCache is required when not using NO_SESSION_CACHE_REF
    #endif

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

        static WOLFSSL_GLOBAL ClientRow ClientCache[CLIENT_SESSION_ROWS];
                                                     /* Client Cache */
                                                     /* uses session mutex */

        /* ClientCache mutex */
        static WOLFSSL_GLOBAL wolfSSL_Mutex clisession_mutex
            WOLFSSL_MUTEX_INITIALIZER_CLAUSE(clisession_mutex);
        #ifndef WOLFSSL_MUTEX_INITIALIZER
        static WOLFSSL_GLOBAL int clisession_mutex_valid = 0;
        #endif
    #endif /* !NO_CLIENT_CACHE */

    void EvictSessionFromCache(WOLFSSL_SESSION* session)
    {
#ifdef HAVE_EX_DATA
        int save_ownExData = session->ownExData;
        session->ownExData = 1; /* Make sure ex_data access doesn't lead back
                                 * into the cache. */
#endif
#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
        if (session->rem_sess_cb != NULL) {
            session->rem_sess_cb(NULL, session);
            session->rem_sess_cb = NULL;
        }
#endif
        ForceZero(session->masterSecret, SECRET_LEN);
        XMEMSET(session->sessionID, 0, ID_LEN);
        session->sessionIDSz = 0;
#ifdef HAVE_SESSION_TICKET
        if (session->ticketLenAlloc > 0) {
            XFREE(session->ticket, NULL, DYNAMIC_TYPE_SESSION_TICK);
            session->ticket = session->staticTicket;
            session->ticketLen = 0;
            session->ticketLenAlloc = 0;
        }
#endif
#ifdef HAVE_EX_DATA
        session->ownExData = save_ownExData;
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) &&                  \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                                    \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        if ((session->ticketNonce.data != NULL) &&
            (session->ticketNonce.data != session->ticketNonce.dataStatic))
        {
            XFREE(session->ticketNonce.data, NULL, DYNAMIC_TYPE_SESSION_TICK);
            session->ticketNonce.data = NULL;
        }
#endif
    }

WOLFSSL_ABI
WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_session");
    if (ssl) {
#ifdef NO_SESSION_CACHE_REF
        return ssl->session;
#else
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            /* On the client side we want to return a persistent reference for
             * backwards compatibility. */
#ifndef NO_CLIENT_CACHE
            if (ssl->clientSession) {
                return (WOLFSSL_SESSION*)ssl->clientSession;
            }
            else {
                /* Try to add a ClientCache entry to associate with the current
                 * session. Ignore any session cache options. */
                int err;
                const byte* id = ssl->session->sessionID;
                byte idSz = ssl->session->sessionIDSz;
                if (ssl->session->haveAltSessionID) {
                    id = ssl->session->altSessionID;
                    idSz = ID_LEN;
                }
                err = AddSessionToCache(ssl->ctx, ssl->session, id, idSz,
                        NULL, ssl->session->side,
                #ifdef HAVE_SESSION_TICKET
                        ssl->session->ticketLen > 0,
                #else
                        0,
                #endif
                        &ssl->clientSession);
                if (err == 0) {
                    return (WOLFSSL_SESSION*)ssl->clientSession;
                }
            }
#endif
        }
        else {
            return ssl->session;
        }
#endif
    }

    return NULL;
}

/* The get1 version requires caller to call SSL_SESSION_free */
WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl)
{
    WOLFSSL_SESSION* sess = NULL;
    WOLFSSL_ENTER("wolfSSL_get1_session");
    if (ssl != NULL) {
        sess = ssl->session;
        if (sess != NULL) {
            /* increase reference count if allocated session */
            if (sess->type == WOLFSSL_SESSION_TYPE_HEAP) {
                if (wolfSSL_SESSION_up_ref(sess) != WOLFSSL_SUCCESS)
                    sess = NULL;
            }
        }
    }
    return sess;
}

/* session is a private struct, return if it is setup or not */
WOLFSSL_API int wolfSSL_SessionIsSetup(WOLFSSL_SESSION* session)
{
    if (session != NULL)
        return session->isSetup;
    return 0;
}

/*
 * Sets the session object to use when establishing a TLS/SSL session using
 * the ssl object. Therefore, this function must be called before
 * wolfSSL_connect. The session object to use can be obtained in a previous
 * TLS/SSL connection using wolfSSL_get_session.
 *
 * This function rejects the session if it has been expired when this function
 * is called. Note that this expiration check is wolfSSL specific and differs
 * from OpenSSL return code behavior.
 *
 * By default, wolfSSL_set_session returns WOLFSSL_SUCCESS on successfully
 * setting the session, WOLFSSL_FAILURE on failure due to the session cache
 * being disabled, or the session has expired.
 *
 * To match OpenSSL return code behavior when session is expired, define
 * OPENSSL_EXTRA and WOLFSSL_ERROR_CODE_OPENSSL. This behavior will return
 * WOLFSSL_SUCCESS even when the session is expired and rejected.
 */
WOLFSSL_ABI
int wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session)
{
    WOLFSSL_ENTER("wolfSSL_set_session");
    if (session)
        return wolfSSL_SetSession(ssl, session);

    return WOLFSSL_FAILURE;
}


#ifndef NO_CLIENT_CACHE

/* Associate client session with serverID, find existing or store for saving
   if newSession flag on, don't reuse existing session
   WOLFSSL_SUCCESS on ok */
int wolfSSL_SetServerID(WOLFSSL* ssl, const byte* id, int len, int newSession)
{
    WOLFSSL_SESSION* session = NULL;
    byte idHash[SERVER_ID_LEN];

    WOLFSSL_ENTER("wolfSSL_SetServerID");

    if (ssl == NULL || id == NULL || len <= 0)
        return BAD_FUNC_ARG;

    if (len > SERVER_ID_LEN) {
#if defined(NO_SHA) && !defined(NO_SHA256)
        if (wc_Sha256Hash(id, len, idHash) != 0)
            return WOLFSSL_FAILURE;
#else
        if (wc_ShaHash(id, (word32)len, idHash) != 0)
            return WOLFSSL_FAILURE;
#endif
        id = idHash;
        len = SERVER_ID_LEN;
    }

    if (newSession == 0) {
        session = wolfSSL_GetSessionClient(ssl, id, len);
        if (session) {
            if (wolfSSL_SetSession(ssl, session) != WOLFSSL_SUCCESS) {
            #ifdef HAVE_EXT_CACHE
                wolfSSL_FreeSession(ssl->ctx, session);
            #endif
                WOLFSSL_MSG("wolfSSL_SetSession failed");
                session = NULL;
            }
        }
    }

    if (session == NULL) {
        WOLFSSL_MSG("Valid ServerID not cached already");

        ssl->session->idLen = (word16)len;
        XMEMCPY(ssl->session->serverID, id, len);
    }
#ifdef HAVE_EXT_CACHE
    else {
        wolfSSL_FreeSession(ssl->ctx, session);
    }
#endif

    return WOLFSSL_SUCCESS;
}

#endif /* !NO_CLIENT_CACHE */

/* TODO: Add SESSION_CACHE_DYNAMIC_MEM support for PERSIST_SESSION_CACHE.
 * Need a count of current sessions to get an accurate memsize (totalCount is
 * not decremented when sessions are removed).
 * Need to determine ideal layout for mem/filesave.
 * Also need mem/filesave checking to ensure not restoring non DYNAMIC_MEM
 * cache.
 */
#if defined(PERSIST_SESSION_CACHE) && !defined(SESSION_CACHE_DYNAMIC_MEM)

/* for persistence, if changes to layout need to increment and modify
   save_session_cache() and restore_session_cache and memory versions too */
#define WOLFSSL_CACHE_VERSION 2

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

/* get how big the the session cache save buffer needs to be */
int wolfSSL_get_session_cache_memsize(void)
{
    int sz  = (int)(sizeof(SessionCache) + sizeof(cache_header_t));
#ifndef NO_CLIENT_CACHE
    sz += (int)(sizeof(ClientCache));
#endif
    return sz;
}


/* Persist session cache to memory */
int wolfSSL_memsave_session_cache(void* mem, int sz)
{
    int i;
    cache_header_t cache_header;
    SessionRow*    row  = (SessionRow*)((byte*)mem + sizeof(cache_header));

    WOLFSSL_ENTER("wolfSSL_memsave_session_cache");

    if (sz < wolfSSL_get_session_cache_memsize()) {
        WOLFSSL_MSG("Memory buffer too small");
        return BUFFER_E;
    }

    cache_header.version   = WOLFSSL_CACHE_VERSION;
    cache_header.rows      = SESSION_ROWS;
    cache_header.columns   = SESSIONS_PER_ROW;
    cache_header.sessionSz = (int)sizeof(WOLFSSL_SESSION);
    XMEMCPY(mem, &cache_header, sizeof(cache_header));

#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    if (SESSION_ROW_RD_LOCK(row) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        return BAD_MUTEX_E;
    }
#endif
    for (i = 0; i < cache_header.rows; ++i) {
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        if (SESSION_ROW_RD_LOCK(&SessionCache[i]) != 0) {
            WOLFSSL_MSG("Session row cache mutex lock failed");
            return BAD_MUTEX_E;
        }
    #endif

        XMEMCPY(row++, &SessionCache[i], SIZEOF_SESSION_ROW);
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        SESSION_ROW_UNLOCK(&SessionCache[i]);
    #endif
    }
#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    SESSION_ROW_UNLOCK(row);
#endif

#ifndef NO_CLIENT_CACHE
    if (wc_LockMutex(&clisession_mutex) != 0) {
        WOLFSSL_MSG("Client cache mutex lock failed");
        return BAD_MUTEX_E;
    }
    XMEMCPY(row, ClientCache, sizeof(ClientCache));
    wc_UnLockMutex(&clisession_mutex);
#endif

    WOLFSSL_LEAVE("wolfSSL_memsave_session_cache", WOLFSSL_SUCCESS);

    return WOLFSSL_SUCCESS;
}


/* Restore the persistent session cache from memory */
int wolfSSL_memrestore_session_cache(const void* mem, int sz)
{
    int    i;
    cache_header_t cache_header;
    SessionRow*    row  = (SessionRow*)((byte*)mem + sizeof(cache_header));

    WOLFSSL_ENTER("wolfSSL_memrestore_session_cache");

    if (sz < wolfSSL_get_session_cache_memsize()) {
        WOLFSSL_MSG("Memory buffer too small");
        return BUFFER_E;
    }

    XMEMCPY(&cache_header, mem, sizeof(cache_header));
    if (cache_header.version   != WOLFSSL_CACHE_VERSION ||
        cache_header.rows      != SESSION_ROWS ||
        cache_header.columns   != SESSIONS_PER_ROW ||
        cache_header.sessionSz != (int)sizeof(WOLFSSL_SESSION)) {

        WOLFSSL_MSG("Session cache header match failed");
        return CACHE_MATCH_ERROR;
    }

#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    if (SESSION_ROW_WR_LOCK(&SessionCache[0]) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        return BAD_MUTEX_E;
    }
#endif
    for (i = 0; i < cache_header.rows; ++i) {
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        if (SESSION_ROW_WR_LOCK(&SessionCache[i]) != 0) {
            WOLFSSL_MSG("Session row cache mutex lock failed");
            return BAD_MUTEX_E;
        }
    #endif

        XMEMCPY(&SessionCache[i], row++, SIZEOF_SESSION_ROW);
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        SESSION_ROW_UNLOCK(&SessionCache[i]);
    #endif
    }
#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    SESSION_ROW_UNLOCK(&SessionCache[0]);
#endif

#ifndef NO_CLIENT_CACHE
    if (wc_LockMutex(&clisession_mutex) != 0) {
        WOLFSSL_MSG("Client cache mutex lock failed");
        return BAD_MUTEX_E;
    }
    XMEMCPY(ClientCache, row, sizeof(ClientCache));
    wc_UnLockMutex(&clisession_mutex);
#endif

    WOLFSSL_LEAVE("wolfSSL_memrestore_session_cache", WOLFSSL_SUCCESS);

    return WOLFSSL_SUCCESS;
}

#if !defined(NO_FILESYSTEM)

/* Persist session cache to file */
/* doesn't use memsave because of additional memory use */
int wolfSSL_save_session_cache(const char *fname)
{
    XFILE  file;
    int    ret;
    int    rc = WOLFSSL_SUCCESS;
    int    i;
    cache_header_t cache_header;

    WOLFSSL_ENTER("wolfSSL_save_session_cache");

    file = XFOPEN(fname, "w+b");
    if (file == XBADFILE) {
        WOLFSSL_MSG("Couldn't open session cache save file");
        return WOLFSSL_BAD_FILE;
    }
    cache_header.version   = WOLFSSL_CACHE_VERSION;
    cache_header.rows      = SESSION_ROWS;
    cache_header.columns   = SESSIONS_PER_ROW;
    cache_header.sessionSz = (int)sizeof(WOLFSSL_SESSION);

    /* cache header */
    ret = (int)XFWRITE(&cache_header, sizeof cache_header, 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Session cache header file write failed");
        XFCLOSE(file);
        return FWRITE_ERROR;
    }

#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    if (SESSION_ROW_RD_LOCK(&SessionCache[0]) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }
#endif
    /* session cache */
    for (i = 0; i < cache_header.rows; ++i) {
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        if (SESSION_ROW_RD_LOCK(&SessionCache[i]) != 0) {
            WOLFSSL_MSG("Session row cache mutex lock failed");
            XFCLOSE(file);
            return BAD_MUTEX_E;
        }
    #endif

        ret = (int)XFWRITE(&SessionCache[i], SIZEOF_SESSION_ROW, 1, file);
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        SESSION_ROW_UNLOCK(&SessionCache[i]);
    #endif
        if (ret != 1) {
            WOLFSSL_MSG("Session cache member file write failed");
            rc = FWRITE_ERROR;
            break;
        }
    }
#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    SESSION_ROW_UNLOCK(&SessionCache[0]);
#endif

#ifndef NO_CLIENT_CACHE
    /* client cache */
    if (wc_LockMutex(&clisession_mutex) != 0) {
        WOLFSSL_MSG("Client cache mutex lock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }
    ret = (int)XFWRITE(ClientCache, sizeof(ClientCache), 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Client cache member file write failed");
        rc = FWRITE_ERROR;
    }
    wc_UnLockMutex(&clisession_mutex);
#endif /* !NO_CLIENT_CACHE */

    XFCLOSE(file);
    WOLFSSL_LEAVE("wolfSSL_save_session_cache", rc);

    return rc;
}


/* Restore the persistent session cache from file */
/* doesn't use memstore because of additional memory use */
int wolfSSL_restore_session_cache(const char *fname)
{
    XFILE  file;
    int    rc = WOLFSSL_SUCCESS;
    int    ret;
    int    i;
    cache_header_t cache_header;

    WOLFSSL_ENTER("wolfSSL_restore_session_cache");

    file = XFOPEN(fname, "rb");
    if (file == XBADFILE) {
        WOLFSSL_MSG("Couldn't open session cache save file");
        return WOLFSSL_BAD_FILE;
    }
    /* cache header */
    ret = (int)XFREAD(&cache_header, sizeof(cache_header), 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Session cache header file read failed");
        XFCLOSE(file);
        return FREAD_ERROR;
    }
    if (cache_header.version   != WOLFSSL_CACHE_VERSION ||
        cache_header.rows      != SESSION_ROWS ||
        cache_header.columns   != SESSIONS_PER_ROW ||
        cache_header.sessionSz != (int)sizeof(WOLFSSL_SESSION)) {

        WOLFSSL_MSG("Session cache header match failed");
        XFCLOSE(file);
        return CACHE_MATCH_ERROR;
    }

#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    if (SESSION_ROW_WR_LOCK(&SessionCache[0]) != 0) {
        WOLFSSL_MSG("Session cache mutex lock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }
#endif
    /* session cache */
    for (i = 0; i < cache_header.rows; ++i) {
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        if (SESSION_ROW_WR_LOCK(&SessionCache[i]) != 0) {
            WOLFSSL_MSG("Session row cache mutex lock failed");
            XFCLOSE(file);
            return BAD_MUTEX_E;
        }
    #endif

        ret = (int)XFREAD(&SessionCache[i], SIZEOF_SESSION_ROW, 1, file);
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        SESSION_ROW_UNLOCK(&SessionCache[i]);
    #endif
        if (ret != 1) {
            WOLFSSL_MSG("Session cache member file read failed");
            XMEMSET(SessionCache, 0, sizeof SessionCache);
            rc = FREAD_ERROR;
            break;
        }
    }
#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    SESSION_ROW_UNLOCK(&SessionCache[0]);
#endif

#ifndef NO_CLIENT_CACHE
    /* client cache */
    if (wc_LockMutex(&clisession_mutex) != 0) {
        WOLFSSL_MSG("Client cache mutex lock failed");
        XFCLOSE(file);
        return BAD_MUTEX_E;
    }
    ret = (int)XFREAD(ClientCache, sizeof(ClientCache), 1, file);
    if (ret != 1) {
        WOLFSSL_MSG("Client cache member file read failed");
        XMEMSET(ClientCache, 0, sizeof ClientCache);
        rc = FREAD_ERROR;
    }
    wc_UnLockMutex(&clisession_mutex);
#endif /* !NO_CLIENT_CACHE */

    XFCLOSE(file);
    WOLFSSL_LEAVE("wolfSSL_restore_session_cache", rc);

    return rc;
}

#endif /* !NO_FILESYSTEM */
#endif /* PERSIST_SESSION_CACHE && !SESSION_CACHE_DYNAMIC_MEM */


/* on by default if built in but allow user to turn off */
WOLFSSL_ABI
long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX* ctx, long mode)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_session_cache_mode");

    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    if (mode == WOLFSSL_SESS_CACHE_OFF) {
        ctx->sessionCacheOff = 1;
#ifdef HAVE_EXT_CACHE
        ctx->internalCacheOff = 1;
        ctx->internalCacheLookupOff = 1;
#endif
    }

    if ((mode & WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR) != 0)
        ctx->sessionCacheFlushOff = 1;

#ifdef HAVE_EXT_CACHE
    /* WOLFSSL_SESS_CACHE_NO_INTERNAL activates both if's */
    if ((mode & WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE) != 0)
        ctx->internalCacheOff = 1;
    if ((mode & WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP) != 0)
        ctx->internalCacheLookupOff = 1;
#endif

    return WOLFSSL_SUCCESS;
}

#ifdef OPENSSL_EXTRA
#ifdef HAVE_MAX_FRAGMENT
/* return the max fragment size set when handshake was negotiated */
unsigned char wolfSSL_SESSION_get_max_fragment_length(WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);
    if (session == NULL) {
        return 0;
    }

    return session->mfl;
}
#endif


/* Get the session cache mode for CTX
 *
 * ctx  WOLFSSL_CTX struct to get cache mode from
 *
 * Returns a bit mask that has the session cache mode */
long wolfSSL_CTX_get_session_cache_mode(WOLFSSL_CTX* ctx)
{
    long m = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_get_session_cache_mode");

    if (ctx == NULL) {
        return m;
    }

    if (ctx->sessionCacheOff != 1) {
        m |= WOLFSSL_SESS_CACHE_SERVER;
    }

    if (ctx->sessionCacheFlushOff == 1) {
        m |= WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR;
    }

#ifdef HAVE_EXT_CACHE
    if (ctx->internalCacheOff == 1) {
        m |= WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE;
    }
    if (ctx->internalCacheLookupOff == 1) {
        m |= WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
    }
#endif

    return m;
}
#endif /* OPENSSL_EXTRA */

#endif /* !NO_SESSION_CACHE */

#ifndef NO_SESSION_CACHE

WOLFSSL_ABI
void wolfSSL_flush_sessions(WOLFSSL_CTX* ctx, long tm)
{
    /* static table now, no flushing needed */
    (void)ctx;
    (void)tm;
}

void wolfSSL_CTX_flush_sessions(WOLFSSL_CTX* ctx, long tm)
{
    int i, j;
    byte id[ID_LEN];

    (void)ctx;
    XMEMSET(id, 0, ID_LEN);
    WOLFSSL_ENTER("wolfSSL_flush_sessions");
    for (i = 0; i < SESSION_ROWS; ++i) {
        if (SESSION_ROW_WR_LOCK(&SessionCache[i]) != 0) {
            WOLFSSL_MSG("Session cache mutex lock failed");
            return;
        }
        for (j = 0; j < SESSIONS_PER_ROW; j++) {
#ifdef SESSION_CACHE_DYNAMIC_MEM
            WOLFSSL_SESSION* s = SessionCache[i].Sessions[j];
#else
            WOLFSSL_SESSION* s = &SessionCache[i].Sessions[j];
#endif
            if (
#ifdef SESSION_CACHE_DYNAMIC_MEM
                s != NULL &&
#endif
                XMEMCMP(s->sessionID, id, ID_LEN) != 0 &&
                s->bornOn + s->timeout < (word32)tm
                )
            {
                EvictSessionFromCache(s);
#ifdef SESSION_CACHE_DYNAMIC_MEM
                XFREE(s, s->heap, DYNAMIC_TYPE_SESSION);
                SessionCache[i].Sessions[j] = NULL;
#endif
            }
        }
        SESSION_ROW_UNLOCK(&SessionCache[i]);
    }
}


/* set ssl session timeout in seconds */
WOLFSSL_ABI
int wolfSSL_set_timeout(WOLFSSL* ssl, unsigned int to)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (to == 0)
        to = WOLFSSL_SESSION_TIMEOUT;
    ssl->timeout = to;

    return WOLFSSL_SUCCESS;
}


/**
 * Sets ctx session timeout in seconds.
 * The timeout value set here should be reflected in the
 * "session ticket lifetime hint" if this API works in the openssl compat-layer.
 * Therefore wolfSSL_CTX_set_TicketHint is called internally.
 * Arguments:
 *  - ctx  WOLFSSL_CTX object which the timeout is set to
 *  - to   timeout value in second
 * Returns:
 *  WOLFSSL_SUCCESS on success, BAD_FUNC_ARG on failure.
 *  When WOLFSSL_ERROR_CODE_OPENSSL is defined, returns previous timeout value
 *  on success, BAD_FUNC_ARG on failure.
 */
WOLFSSL_ABI
int wolfSSL_CTX_set_timeout(WOLFSSL_CTX* ctx, unsigned int to)
{
    #if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    word32 prev_timeout = 0;
    #endif

    int ret = WOLFSSL_SUCCESS;
    (void)ret;

    if (ctx == NULL)
        ret = BAD_FUNC_ARG;

    if (ret == WOLFSSL_SUCCESS) {
    #if defined(WOLFSSL_ERROR_CODE_OPENSSL)
        prev_timeout = ctx->timeout;
    #endif
        if (to == 0) {
            ctx->timeout = WOLFSSL_SESSION_TIMEOUT;
        }
        else {
            ctx->timeout = to;
        }
    }
#if defined(OPENSSL_EXTRA) && defined(HAVE_SESSION_TICKET) && \
   !defined(NO_WOLFSSL_SERVER)
    if (ret == WOLFSSL_SUCCESS) {
        if (to == 0) {
            ret = wolfSSL_CTX_set_TicketHint(ctx, SESSION_TICKET_HINT_DEFAULT);
        }
        else {
            ret = wolfSSL_CTX_set_TicketHint(ctx, (int)to);
        }
    }
#endif /* OPENSSL_EXTRA && HAVE_SESSION_TICKET && !NO_WOLFSSL_SERVER */

#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    if (ret == WOLFSSL_SUCCESS) {
        return (int)prev_timeout;
    }
    else {
        return ret;
    }
#else
    return ret;
#endif /* WOLFSSL_ERROR_CODE_OPENSSL */
}


#ifndef NO_CLIENT_CACHE

/* Get Session from Client cache based on id/len, return NULL on failure */
WOLFSSL_SESSION* wolfSSL_GetSessionClient(WOLFSSL* ssl, const byte* id, int len)
{
    WOLFSSL_SESSION* ret = NULL;
    word32          row;
    int             idx;
    int             count;
    int             error = 0;
    ClientSession*  clSess;

    WOLFSSL_ENTER("wolfSSL_GetSessionClient");

    if (ssl->ctx->sessionCacheOff) {
        WOLFSSL_MSG("Session Cache off");
        return NULL;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END)
        return NULL;

    len = (int)min(SERVER_ID_LEN, (word32)len);

    /* Do not access ssl->ctx->get_sess_cb from here. It is using a different
     * set of ID's */

    row = HashObject(id, (word32)len, &error) % CLIENT_SESSION_ROWS;
    if (error != 0) {
        WOLFSSL_MSG("Hash session failed");
        return NULL;
    }

    if (wc_LockMutex(&clisession_mutex) != 0) {
        WOLFSSL_MSG("Client cache mutex lock failed");
        return NULL;
    }

    /* start from most recently used */
    count = (int)min((word32)ClientCache[row].totalCount, CLIENT_SESSIONS_PER_ROW);
    idx = ClientCache[row].nextIdx - 1;
    if (idx < 0 || idx >= CLIENT_SESSIONS_PER_ROW) {
        /* if back to front, the previous was end */
        idx = CLIENT_SESSIONS_PER_ROW - 1;
    }
    clSess = ClientCache[row].Clients;

    for (; count > 0; --count) {
        WOLFSSL_SESSION* current;
        SessionRow* sessRow;

        if (clSess[idx].serverRow >= SESSION_ROWS) {
            WOLFSSL_MSG("Client cache serverRow invalid");
            break;
        }

        /* lock row */
        sessRow = &SessionCache[clSess[idx].serverRow];
        if (SESSION_ROW_RD_LOCK(sessRow) != 0) {
            WOLFSSL_MSG("Session cache row lock failure");
            break;
        }

#ifdef SESSION_CACHE_DYNAMIC_MEM
        current = sessRow->Sessions[clSess[idx].serverIdx];
#else
        current = &sessRow->Sessions[clSess[idx].serverIdx];
#endif
        if (current && XMEMCMP(current->serverID, id, (unsigned long)len) == 0) {
            WOLFSSL_MSG("Found a serverid match for client");
            if (LowResTimer() < (current->bornOn + current->timeout)) {
                WOLFSSL_MSG("Session valid");
                ret = current;
                SESSION_ROW_UNLOCK(sessRow);
                break;
            } else {
                WOLFSSL_MSG("Session timed out");  /* could have more for id */
            }
        } else {
            WOLFSSL_MSG("ServerID not a match from client table");
        }
        SESSION_ROW_UNLOCK(sessRow);

        idx = idx > 0 ? idx - 1 : CLIENT_SESSIONS_PER_ROW - 1;
    }

    wc_UnLockMutex(&clisession_mutex);

    return ret;
}

#endif /* !NO_CLIENT_CACHE */

static int SslSessionCacheOff(const WOLFSSL* ssl,
    const WOLFSSL_SESSION* session)
{
    (void)session;
    return ssl->options.sessionCacheOff
    #if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_FORCE_CACHE_ON_TICKET)
                && session->ticketLen == 0
    #endif
                ;
}

#if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TLS13) &&                  \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) && \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
/**
 * SessionTicketNoncePrealloc() - prealloc a buffer for ticket nonces
 * @output: [in] pointer to WOLFSSL_SESSION object that will soon be a
 * destination of a session duplication
 * @buf: [out] address of the preallocated buf
 * @len: [out] len of the preallocated buf
 *
 * prealloc a buffer that will likely suffice to contain a ticket nonce. It's
 * used when copying session under lock, when syscalls need to be avoided. If
 * output already has a dynamic buffer, it's reused.
 */
static int SessionTicketNoncePrealloc(byte** buf, byte* len, void *heap)
{
    (void)heap;

    *buf = (byte*)XMALLOC(PREALLOC_SESSION_TICKET_NONCE_LEN, heap,
        DYNAMIC_TYPE_SESSION_TICK);
    if (*buf == NULL) {
        WOLFSSL_MSG("Failed to preallocate ticket nonce buffer");
        *len = 0;
        return 1;
    }

    *len = PREALLOC_SESSION_TICKET_NONCE_LEN;
    return 0;
}
#endif /* HAVE_SESSION_TICKET && WOLFSSL_TLS13 */

static int wolfSSL_DupSessionEx(const WOLFSSL_SESSION* input,
    WOLFSSL_SESSION* output, int avoidSysCalls, byte* ticketNonceBuf,
    byte* ticketNonceLen, byte* preallocUsed);

void TlsSessionCacheUnlockRow(word32 row)
{
    SessionRow* sessRow;

    sessRow = &SessionCache[row];
    (void)sessRow;
    SESSION_ROW_UNLOCK(sessRow);
}

/* Don't use this function directly. Use TlsSessionCacheGetAndRdLock and
 * TlsSessionCacheGetAndWrLock to fully utilize compiler const support. */
static int TlsSessionCacheGetAndLock(const byte *id,
    const WOLFSSL_SESSION **sess, word32 *lockedRow, byte readOnly, byte side)
{
    SessionRow *sessRow;
    const WOLFSSL_SESSION *s;
    word32 row;
    int count;
    int error;
    int idx;

    *sess = NULL;
    row = HashObject(id, ID_LEN, &error) % SESSION_ROWS;
    if (error != 0)
        return error;
    sessRow = &SessionCache[row];
    if (readOnly)
        error = SESSION_ROW_RD_LOCK(sessRow);
    else
        error = SESSION_ROW_WR_LOCK(sessRow);
    if (error != 0)
        return FATAL_ERROR;

    /* start from most recently used */
    count = (int)min((word32)sessRow->totalCount, SESSIONS_PER_ROW);
    idx = sessRow->nextIdx - 1;
    if (idx < 0 || idx >= SESSIONS_PER_ROW) {
        idx = SESSIONS_PER_ROW - 1; /* if back to front, the previous was end */
    }
    for (; count > 0; --count) {
#ifdef SESSION_CACHE_DYNAMIC_MEM
        s = sessRow->Sessions[idx];
#else
        s = &sessRow->Sessions[idx];
#endif
        if (s && XMEMCMP(s->sessionID, id, ID_LEN) == 0 && s->side == side) {
            *sess = s;
            break;
        }
        idx = idx > 0 ? idx - 1 : SESSIONS_PER_ROW - 1;
    }
    if (*sess == NULL) {
        SESSION_ROW_UNLOCK(sessRow);
    }
    else {
        *lockedRow = row;
    }

    return 0;
}

static int CheckSessionMatch(const WOLFSSL* ssl, const WOLFSSL_SESSION* sess)
{
    if (ssl == NULL || sess == NULL)
        return 0;
#ifdef OPENSSL_EXTRA
    if (ssl->sessionCtxSz > 0 && (ssl->sessionCtxSz != sess->sessionCtxSz ||
           XMEMCMP(ssl->sessionCtx, sess->sessionCtx, sess->sessionCtxSz) != 0))
        return 0;
#endif
#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)
    if (IsAtLeastTLSv1_3(ssl->version) != IsAtLeastTLSv1_3(sess->version))
        return 0;
#endif
    return 1;
}

int TlsSessionCacheGetAndRdLock(const byte *id, const WOLFSSL_SESSION **sess,
        word32 *lockedRow, byte side)
{
    return TlsSessionCacheGetAndLock(id, sess, lockedRow, 1, side);
}

int TlsSessionCacheGetAndWrLock(const byte *id, WOLFSSL_SESSION **sess,
        word32 *lockedRow, byte side)
{
    return TlsSessionCacheGetAndLock(id, (const WOLFSSL_SESSION**)sess,
            lockedRow, 0, side);
}

int wolfSSL_GetSessionFromCache(WOLFSSL* ssl, WOLFSSL_SESSION* output)
{
    const WOLFSSL_SESSION* sess = NULL;
    const byte*  id = NULL;
    word32       row;
    int          error = 0;
#ifdef HAVE_SESSION_TICKET
#ifndef WOLFSSL_SMALL_STACK
    byte         tmpTicket[PREALLOC_SESSION_TICKET_LEN];
#else
    byte*        tmpTicket = NULL;
#endif
#ifdef WOLFSSL_TLS13
    byte *preallocNonce = NULL;
    byte preallocNonceLen = 0;
    byte preallocNonceUsed = 0;
#endif /* WOLFSSL_TLS13 */
    byte         tmpBufSet = 0;
#endif
#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* peer = NULL;
#endif
    byte         bogusID[ID_LEN];
    byte         bogusIDSz = 0;

    WOLFSSL_ENTER("wolfSSL_GetSessionFromCache");

    if (output == NULL) {
        WOLFSSL_MSG("NULL output");
        return WOLFSSL_FAILURE;
    }

    if (SslSessionCacheOff(ssl, ssl->session))
        return WOLFSSL_FAILURE;

    if (ssl->options.haveSessionId == 0 && !ssl->session->haveAltSessionID)
        return WOLFSSL_FAILURE;

#ifdef HAVE_SESSION_TICKET
    if (ssl->options.side == WOLFSSL_SERVER_END && ssl->options.useTicket == 1)
        return WOLFSSL_FAILURE;
#endif

    XMEMSET(bogusID, 0, sizeof(bogusID));
    if (!IsAtLeastTLSv1_3(ssl->version) && ssl->arrays != NULL
            && !ssl->session->haveAltSessionID)
        id = ssl->arrays->sessionID;
    else if (ssl->session->haveAltSessionID) {
        id = ssl->session->altSessionID;
        /* We want to restore the bogus ID for TLS compatibility */
        if (output == ssl->session) {
            XMEMCPY(bogusID, ssl->session->sessionID, ID_LEN);
            bogusIDSz = ssl->session->sessionIDSz;
        }
    }
    else
        id = ssl->session->sessionID;


#ifdef HAVE_EXT_CACHE
    if (ssl->ctx->get_sess_cb != NULL) {
        int copy = 0;
        int found = 0;
        WOLFSSL_SESSION* extSess;
        /* Attempt to retrieve the session from the external cache. */
        WOLFSSL_MSG("Calling external session cache");
        extSess = ssl->ctx->get_sess_cb(ssl, (byte*)id, ID_LEN, &copy);
        if ((extSess != NULL)
                && CheckSessionMatch(ssl, extSess)
            ) {
            WOLFSSL_MSG("Session found in external cache");
            found = 1;

            error = wolfSSL_DupSession(extSess, output, 0);
#ifdef HAVE_EX_DATA
            extSess->ownExData = 1;
            output->ownExData = 0;
#endif
            /* We want to restore the bogus ID for TLS compatibility */
            if (ssl->session->haveAltSessionID &&
                    output == ssl->session) {
                XMEMCPY(ssl->session->sessionID, bogusID, ID_LEN);
                ssl->session->sessionIDSz = bogusIDSz;
            }
        }
        /* If copy not set then free immediately */
        if (extSess != NULL && !copy)
            wolfSSL_FreeSession(ssl->ctx, extSess);
        if (found)
            return error;
        WOLFSSL_MSG("Session not found in external cache");
    }

    if (ssl->options.internalCacheLookupOff) {
        WOLFSSL_MSG("Internal cache lookup turned off");
        return WOLFSSL_FAILURE;
    }
#endif

#ifdef HAVE_SESSION_TICKET
    if (output->ticket == NULL ||
            output->ticketLenAlloc < PREALLOC_SESSION_TICKET_LEN) {
#ifdef WOLFSSL_SMALL_STACK
        tmpTicket = (byte*)XMALLOC(PREALLOC_SESSION_TICKET_LEN, output->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (tmpTicket == NULL) {
            WOLFSSL_MSG("tmpTicket malloc failed");
            return WOLFSSL_FAILURE;
        }
#endif
        if (output->ticketLenAlloc)
            XFREE(output->ticket, output->heap, DYNAMIC_TYPE_SESSION_TICK);
        output->ticket = tmpTicket; /* cppcheck-suppress autoVariables
                                     */
        output->ticketLenAlloc = PREALLOC_SESSION_TICKET_LEN;
        output->ticketLen = 0;
        tmpBufSet = 1;
    }
#endif

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    if (output->peer != NULL) {
        wolfSSL_X509_free(output->peer);
        output->peer = NULL;
    }
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) &&                  \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                                    \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    if (output->ticketNonce.data != output->ticketNonce.dataStatic) {
        XFREE(output->ticketNonce.data, output->heap,
            DYNAMIC_TYPE_SESSION_TICK);
        output->ticketNonce.data = output->ticketNonce.dataStatic;
        output->ticketNonce.len = 0;
    }
    error = SessionTicketNoncePrealloc(&preallocNonce, &preallocNonceLen,
        output->heap);
    if (error != 0) {
        if (tmpBufSet) {
            output->ticket = output->staticTicket;
            output->ticketLenAlloc = 0;
        }
#ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpTicket, output->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return WOLFSSL_FAILURE;
    }
#endif /* WOLFSSL_TLS13 && HAVE_SESSION_TICKET*/

    /* init to avoid clang static analyzer false positive */
    row = 0;
    error = TlsSessionCacheGetAndRdLock(id, &sess, &row,
        (byte)ssl->options.side);
    error = (error == 0) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
    if (error != WOLFSSL_SUCCESS || sess == NULL) {
        WOLFSSL_MSG("Get Session from cache failed");
        error = WOLFSSL_FAILURE;
#ifdef HAVE_SESSION_TICKET
        if (tmpBufSet) {
            output->ticket = output->staticTicket;
            output->ticketLenAlloc = 0;
        }
#ifdef WOLFSSL_TLS13
        XFREE(preallocNonce, output->heap, DYNAMIC_TYPE_SESSION_TICK);
        preallocNonce = NULL;
#endif /* WOLFSSL_TLS13 */
#ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpTicket, output->heap, DYNAMIC_TYPE_TMP_BUFFER);
        tmpTicket = NULL;
#endif
#endif
    }
    else {
        if (!CheckSessionMatch(ssl, sess)) {
            WOLFSSL_MSG("Invalid session: can't be used in this context");
            TlsSessionCacheUnlockRow(row);
            error = WOLFSSL_FAILURE;
        }
        else if (LowResTimer() >= (sess->bornOn + sess->timeout)) {
            WOLFSSL_SESSION* wrSess = NULL;
            WOLFSSL_MSG("Invalid session: timed out");
            sess = NULL;
            TlsSessionCacheUnlockRow(row);
            /* Attempt to get a write lock */
            error = TlsSessionCacheGetAndWrLock(id, &wrSess, &row,
                    (byte)ssl->options.side);
            if (error == 0 && wrSess != NULL) {
                EvictSessionFromCache(wrSess);
                TlsSessionCacheUnlockRow(row);
            }
            error = WOLFSSL_FAILURE;
        }
    }

    /* mollify confused cppcheck nullPointer warning. */
    if (sess == NULL)
        error = WOLFSSL_FAILURE;

    if (error == WOLFSSL_SUCCESS) {
#if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TLS13)
        error = wolfSSL_DupSessionEx(sess, output, 1,
            preallocNonce, &preallocNonceLen, &preallocNonceUsed);
#else
        error = wolfSSL_DupSession(sess, output, 1);
#endif /* HAVE_SESSION_TICKET && WOLFSSL_TLS13 */
#ifdef HAVE_EX_DATA
        output->ownExData = !sess->ownExData; /* Session may own ex_data */
#endif
        TlsSessionCacheUnlockRow(row);
    }

    /* We want to restore the bogus ID for TLS compatibility */
    if (ssl->session->haveAltSessionID &&
            output == ssl->session) {
        XMEMCPY(ssl->session->sessionID, bogusID, ID_LEN);
        ssl->session->sessionIDSz = bogusIDSz;
    }

#ifdef HAVE_SESSION_TICKET
    if (tmpBufSet) {
        if (error == WOLFSSL_SUCCESS) {
            if (output->ticketLen > SESSION_TICKET_LEN) {
                output->ticket = (byte*)XMALLOC(output->ticketLen, output->heap,
                        DYNAMIC_TYPE_SESSION_TICK);
                if (output->ticket == NULL) {
                    error = WOLFSSL_FAILURE;
                    output->ticket = output->staticTicket;
                    output->ticketLenAlloc = 0;
                    output->ticketLen = 0;
                }
            }
            else {
                output->ticket = output->staticTicket;
                output->ticketLenAlloc = 0;
            }
        }
        else {
            output->ticket = output->staticTicket;
            output->ticketLenAlloc = 0;
            output->ticketLen = 0;
        }
        if (error == WOLFSSL_SUCCESS) {
            XMEMCPY(output->ticket, tmpTicket, output->ticketLen); /* cppcheck-suppress uninitvar */
        }
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpTicket, output->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    if (error == WOLFSSL_SUCCESS && preallocNonceUsed) {
        if (preallocNonceLen < PREALLOC_SESSION_TICKET_NONCE_LEN) {
            /* buffer bigger than needed */
#ifndef XREALLOC
            output->ticketNonce.data = (byte*)XMALLOC(preallocNonceLen,
                output->heap, DYNAMIC_TYPE_SESSION_TICK);
            if (output->ticketNonce.data != NULL)
                XMEMCPY(output->ticketNonce.data, preallocNonce,
                    preallocNonceLen);
            XFREE(preallocNonce, output->heap, DYNAMIC_TYPE_SESSION_TICK);
            preallocNonce = NULL;
#else
            output->ticketNonce.data = (byte*)XREALLOC(preallocNonce,
                preallocNonceLen, output->heap, DYNAMIC_TYPE_SESSION_TICK);
            if (output->ticketNonce.data != NULL) {
                /* don't free the reallocated pointer */
                preallocNonce = NULL;
            }
#endif /* !XREALLOC */
            if (output->ticketNonce.data == NULL) {
                output->ticketNonce.data = output->ticketNonce.dataStatic;
                output->ticketNonce.len = 0;
                error = WOLFSSL_FAILURE;
                /* preallocNonce will be free'd after the if */
            }
        }
        else {
            output->ticketNonce.data = preallocNonce;
            output->ticketNonce.len = preallocNonceLen;
            preallocNonce = NULL;
        }
    }
    XFREE(preallocNonce, output->heap, DYNAMIC_TYPE_SESSION_TICK);
#endif /* WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC && FIPS_VERSION_GE(5,3)*/

#endif

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    if (peer != NULL) {
        wolfSSL_X509_free(peer);
    }
#endif

    return error;
}

WOLFSSL_SESSION* wolfSSL_GetSession(WOLFSSL* ssl, byte* masterSecret,
        byte restoreSessionCerts)
{
    WOLFSSL_SESSION* ret = NULL;

    (void)restoreSessionCerts; /* Kept for compatibility */

    if (wolfSSL_GetSessionFromCache(ssl, ssl->session) == WOLFSSL_SUCCESS) {
        ret = ssl->session;
    }
    else {
        WOLFSSL_MSG("wolfSSL_GetSessionFromCache did not return a session");
    }

    if (ret != NULL && masterSecret != NULL)
        XMEMCPY(masterSecret, ret->masterSecret, SECRET_LEN);

    return ret;
}

int wolfSSL_SetSession(WOLFSSL* ssl, WOLFSSL_SESSION* session)
{
    SessionRow* sessRow = NULL;
    int ret = WOLFSSL_SUCCESS;

    session = ClientSessionToSession(session);

    if (ssl == NULL || session == NULL || !session->isSetup) {
        WOLFSSL_MSG("ssl or session NULL or not set up");
        return WOLFSSL_FAILURE;
    }

    /* We need to lock the session as the first step if its in the cache */
    if (session->type == WOLFSSL_SESSION_TYPE_CACHE) {
        if (session->cacheRow < SESSION_ROWS) {
            sessRow = &SessionCache[session->cacheRow];
            if (SESSION_ROW_RD_LOCK(sessRow) != 0) {
                WOLFSSL_MSG("Session row lock failed");
                return WOLFSSL_FAILURE;
            }
        }
    }

    if (ret == WOLFSSL_SUCCESS && ssl->options.side != WOLFSSL_NEITHER_END &&
            (byte)ssl->options.side != session->side) {
        WOLFSSL_MSG("Setting session for wrong role");
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (ssl->session == session) {
            WOLFSSL_MSG("ssl->session and session same");
        }
        else if (session->type != WOLFSSL_SESSION_TYPE_CACHE) {
            if (wolfSSL_SESSION_up_ref(session) == WOLFSSL_SUCCESS) {
                wolfSSL_FreeSession(ssl->ctx, ssl->session);
                ssl->session = session;
            }
            else
                ret = WOLFSSL_FAILURE;
        }
        else {
            ret = wolfSSL_DupSession(session, ssl->session, 0);
            if (ret != WOLFSSL_SUCCESS)
                WOLFSSL_MSG("Session duplicate failed");
        }
    }

    /* Let's copy over the altSessionID for local cache purposes */
    if (ret == WOLFSSL_SUCCESS && session->haveAltSessionID &&
            ssl->session != session) {
        ssl->session->haveAltSessionID = 1;
        XMEMCPY(ssl->session->altSessionID, session->altSessionID, ID_LEN);
    }

    if (sessRow != NULL) {
        SESSION_ROW_UNLOCK(sessRow);
        sessRow = NULL;
    }

    /* Note: the `session` variable cannot be used below, since the row is
     * un-locked */

    if (ret != WOLFSSL_SUCCESS)
        return ret;

#ifdef WOLFSSL_SESSION_ID_CTX
    /* check for application context id */
    if (ssl->sessionCtxSz > 0) {
        if (XMEMCMP(ssl->sessionCtx, ssl->session->sessionCtx,
                ssl->sessionCtxSz)) {
            /* context id did not match! */
            WOLFSSL_MSG("Session context did not match");
            return WOLFSSL_FAILURE;
        }
    }
#endif /* WOLFSSL_SESSION_ID_CTX */

    if (LowResTimer() >= (ssl->session->bornOn + ssl->session->timeout)) {
#if !defined(OPENSSL_EXTRA) || !defined(WOLFSSL_ERROR_CODE_OPENSSL)
        return WOLFSSL_FAILURE;  /* session timed out */
#else /* defined(OPENSSL_EXTRA) && defined(WOLFSSL_ERROR_CODE_OPENSSL) */
        WOLFSSL_MSG("Session is expired but return success for "
                    "OpenSSL compatibility");
#endif
    }
    ssl->options.resuming = 1;
    ssl->options.haveEMS = ssl->session->haveEMS;

#if defined(SESSION_CERTS) || (defined(WOLFSSL_TLS13) && \
                           defined(HAVE_SESSION_TICKET))
    ssl->version              = ssl->session->version;
    if (IsAtLeastTLSv1_3(ssl->version))
        ssl->options.tls1_3 = 1;
#endif
#if defined(SESSION_CERTS) || !defined(NO_RESUME_SUITE_CHECK) || \
                    (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET))
    ssl->options.cipherSuite0 = ssl->session->cipherSuite0;
    ssl->options.cipherSuite  = ssl->session->cipherSuite;
#endif
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    ssl->peerVerifyRet = (unsigned long)ssl->session->peerVerifyRet;
#endif

    return WOLFSSL_SUCCESS;
}


#ifdef WOLFSSL_SESSION_STATS
static int get_locked_session_stats(word32* active, word32* total,
                                    word32* peak);
#endif

#ifndef NO_CLIENT_CACHE
ClientSession* AddSessionToClientCache(int side, int row, int idx,
    byte* serverID, word16 idLen, const byte* sessionID, word16 useTicket)
{
    int error = -1;
    word32 clientRow = 0, clientIdx = 0;
    ClientSession* ret = NULL;

    (void)useTicket;
    if (side == WOLFSSL_CLIENT_END
            && row != INVALID_SESSION_ROW
            && (idLen
#ifdef HAVE_SESSION_TICKET
                || useTicket == 1
#endif
                || serverID != NULL
                )) {

        WOLFSSL_MSG("Trying to add client cache entry");

        if (idLen) {
            clientRow = HashObject(serverID,
                    idLen, &error) % CLIENT_SESSION_ROWS;
        }
        else if (serverID != NULL) {
            clientRow = HashObject(sessionID,
                    ID_LEN, &error) % CLIENT_SESSION_ROWS;
        }
        else {
            error = WOLFSSL_FATAL_ERROR;
        }
        if (error == 0 && wc_LockMutex(&clisession_mutex) == 0) {
            clientIdx = (word32)ClientCache[clientRow].nextIdx;
            if (clientIdx < CLIENT_SESSIONS_PER_ROW) {
                ClientCache[clientRow].Clients[clientIdx].serverRow =
                                                                (word16)row;
                ClientCache[clientRow].Clients[clientIdx].serverIdx =
                                                                (word16)idx;
                if (sessionID != NULL) {
                    word32 sessionIDHash = HashObject(sessionID, ID_LEN,
                                                      &error);
                    if (error == 0) {
                        ClientCache[clientRow].Clients[clientIdx].sessionIDHash
                            = sessionIDHash;
                    }
                }
            }
            else {
                error = WOLFSSL_FATAL_ERROR;
                ClientCache[clientRow].nextIdx = 0; /* reset index as safety */
                WOLFSSL_MSG("Invalid client cache index! "
                            "Possible corrupted memory");
            }
            if (error == 0) {
                WOLFSSL_MSG("Adding client cache entry");

                ret = &ClientCache[clientRow].Clients[clientIdx];

                if (ClientCache[clientRow].totalCount < CLIENT_SESSIONS_PER_ROW)
                    ClientCache[clientRow].totalCount++;
                ClientCache[clientRow].nextIdx++;
                ClientCache[clientRow].nextIdx %= CLIENT_SESSIONS_PER_ROW;
            }

            wc_UnLockMutex(&clisession_mutex);
        }
        else {
            WOLFSSL_MSG("Hash session or lock failed");
        }
    }
    else {
        WOLFSSL_MSG("Skipping client cache");
    }

    return ret;
}
#endif /* !NO_CLIENT_CACHE */

/**
 * For backwards compatibility, this API needs to be used in *ALL* functions
 * that access the WOLFSSL_SESSION members directly.
 *
 * This API checks if the passed in session is actually a ClientSession object
 * and returns the matching session cache object. Otherwise just return the
 * input. ClientSession objects only occur in the ClientCache. They are not
 * allocated anywhere else.
 */
WOLFSSL_SESSION* ClientSessionToSession(const WOLFSSL_SESSION* session)
{
    WOLFSSL_ENTER("ClientSessionToSession");
#ifdef NO_SESSION_CACHE_REF
    return (WOLFSSL_SESSION*)session;
#else
#ifndef NO_CLIENT_CACHE
    if (session == NULL)
        return NULL;
    /* Check if session points into ClientCache */
    if ((byte*)session >= (byte*)ClientCache &&
            /* Cast to byte* to make pointer arithmetic work per byte */
            (byte*)session < ((byte*)ClientCache) + sizeof(ClientCache)) {
        ClientSession* clientSession = (ClientSession*)session;
        SessionRow* sessRow = NULL;
        WOLFSSL_SESSION* cacheSession = NULL;
        word32 sessionIDHash = 0;
        int error = 0;
        session = NULL; /* Default to NULL for failure case */
        if (wc_LockMutex(&clisession_mutex) != 0) {
            WOLFSSL_MSG("Client cache mutex lock failed");
            return NULL;
        }
        if (clientSession->serverRow >= SESSION_ROWS ||
                clientSession->serverIdx >= SESSIONS_PER_ROW) {
            WOLFSSL_MSG("Client cache serverRow or serverIdx invalid");
            error = WOLFSSL_FATAL_ERROR;
        }
        if (error == 0) {
            /* Lock row */
            sessRow = &SessionCache[clientSession->serverRow];
            /* Prevent memory access before clientSession->serverRow and
             * clientSession->serverIdx are sanitized. */
            XFENCE();
            error = SESSION_ROW_RD_LOCK(sessRow);
            if (error != 0) {
                WOLFSSL_MSG("Session cache row lock failure");
                sessRow = NULL;
            }
        }
        if (error == 0) {
#ifdef SESSION_CACHE_DYNAMIC_MEM
            cacheSession = sessRow->Sessions[clientSession->serverIdx];
#else
            cacheSession = &sessRow->Sessions[clientSession->serverIdx];
#endif
            /* Prevent memory access */
            XFENCE();
            if (cacheSession && cacheSession->sessionIDSz == 0) {
                cacheSession = NULL;
                WOLFSSL_MSG("Session cache entry not set");
                error = WOLFSSL_FATAL_ERROR;
            }
        }
        if (error == 0) {
            /* Calculate the hash of the session ID */
            sessionIDHash = HashObject(cacheSession->sessionID, ID_LEN,
                    &error);
        }
        if (error == 0) {
            /* Check the session ID hash matches */
            error = clientSession->sessionIDHash != sessionIDHash;
            if (error != 0)
                WOLFSSL_MSG("session ID hashes don't match");
        }
        if (error == 0) {
            /* Hashes match */
            session = cacheSession;
            WOLFSSL_MSG("Found session cache matching client session object");
        }
        if (sessRow != NULL) {
            SESSION_ROW_UNLOCK(sessRow);
        }
        wc_UnLockMutex(&clisession_mutex);
        return (WOLFSSL_SESSION*)session;
    }
    else {
        /* Plain WOLFSSL_SESSION object */
        return (WOLFSSL_SESSION*)session;
    }
#else
    return (WOLFSSL_SESSION*)session;
#endif
#endif
}

int AddSessionToCache(WOLFSSL_CTX* ctx, WOLFSSL_SESSION* addSession,
        const byte* id, byte idSz, int* sessionIndex, int side,
        word16 useTicket, ClientSession** clientCacheEntry)
{
    WOLFSSL_SESSION* cacheSession = NULL;
    SessionRow* sessRow = NULL;
    word32 idx = 0;
#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* cachePeer = NULL;
    WOLFSSL_X509* addPeer = NULL;
#endif
#ifdef HAVE_SESSION_TICKET
    byte*  cacheTicBuff = NULL;
    byte   ticBuffUsed = 0;
    byte*  ticBuff = NULL;
    int    ticLen  = 0;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    byte *preallocNonce = NULL;
    byte preallocNonceLen = 0;
    byte preallocNonceUsed = 0;
    byte *toFree = NULL;
#endif /* WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC */
#endif /* HAVE_SESSION_TICKET */
    int ret = 0;
    int row;
    int i;
    int overwrite = 0;
    (void)ctx;
    (void)sessionIndex;
    (void)useTicket;
    (void)clientCacheEntry;

    WOLFSSL_ENTER("AddSessionToCache");

    if (idSz == 0) {
        WOLFSSL_MSG("AddSessionToCache idSz == 0");
        return BAD_FUNC_ARG;
    }

    addSession = ClientSessionToSession(addSession);
    if (addSession == NULL) {
        WOLFSSL_MSG("AddSessionToCache is NULL");
        return MEMORY_E;
    }

#ifdef HAVE_SESSION_TICKET
    ticLen = addSession->ticketLen;
    /* Alloc Memory here to avoid syscalls during lock */
    if (ticLen > SESSION_TICKET_LEN) {
        ticBuff = (byte*)XMALLOC(ticLen, NULL,
                DYNAMIC_TYPE_SESSION_TICK);
        if (ticBuff == NULL) {
            return MEMORY_E;
        }
    }
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    if (addSession->ticketNonce.data != addSession->ticketNonce.dataStatic) {
        /* use the AddSession->heap even if the buffer maybe saved in
         * CachedSession objects. CachedSession heap and AddSession heap should
         * be the same */
        preallocNonce = (byte*)XMALLOC(addSession->ticketNonce.len,
            addSession->heap, DYNAMIC_TYPE_SESSION_TICK);
        if (preallocNonce == NULL) {
            XFREE(ticBuff, addSession->heap, DYNAMIC_TYPE_SESSION_TICK);
            return MEMORY_E;
        }
        preallocNonceLen = addSession->ticketNonce.len;
    }
#endif /* WOLFSSL_TLS13 && WOLFSL_TICKET_NONCE_MALLOC && FIPS_VERSION_GE(5,3) */
#endif /* HAVE_SESSION_TICKET */

    /* Find a position for the new session in cache and use that */
    /* Use the session object in the cache for external cache if required */
    row = (int)(HashObject(id, ID_LEN, &ret) % SESSION_ROWS);
    if (ret != 0) {
        WOLFSSL_MSG("Hash session failed");
    #ifdef HAVE_SESSION_TICKET
        XFREE(ticBuff, NULL, DYNAMIC_TYPE_SESSION_TICK);
    #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&      \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        XFREE(preallocNonce, addSession->heap, DYNAMIC_TYPE_SESSION_TICK);
    #endif
    #endif
        return ret;
    }

    sessRow = &SessionCache[row];
    if (SESSION_ROW_WR_LOCK(sessRow) != 0) {
    #ifdef HAVE_SESSION_TICKET
        XFREE(ticBuff, NULL, DYNAMIC_TYPE_SESSION_TICK);
    #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        XFREE(preallocNonce, addSession->heap, DYNAMIC_TYPE_SESSION_TICK);
    #endif
    #endif
        WOLFSSL_MSG("Session row lock failed");
        return BAD_MUTEX_E;
    }

    for (i = 0; i < SESSIONS_PER_ROW && i < sessRow->totalCount; i++) {
#ifdef SESSION_CACHE_DYNAMIC_MEM
        cacheSession = sessRow->Sessions[i];
#else
        cacheSession = &sessRow->Sessions[i];
#endif
        if (cacheSession && XMEMCMP(id,
                cacheSession->sessionID, ID_LEN) == 0 &&
                cacheSession->side == side) {
            WOLFSSL_MSG("Session already exists. Overwriting.");
            overwrite = 1;
            idx = (word32)i;
            break;
        }
    }

    if (!overwrite)
        idx = (word32)sessRow->nextIdx;
#ifdef SESSION_INDEX
    if (sessionIndex != NULL)
        *sessionIndex = (row << SESSIDX_ROW_SHIFT) | idx;
#endif

#ifdef SESSION_CACHE_DYNAMIC_MEM
    cacheSession = sessRow->Sessions[idx];
    if (cacheSession == NULL) {
        cacheSession = (WOLFSSL_SESSION*) XMALLOC(sizeof(WOLFSSL_SESSION),
                                         sessRow->heap, DYNAMIC_TYPE_SESSION);
        if (cacheSession == NULL) {
        #ifdef HAVE_SESSION_TICKET
            XFREE(ticBuff, NULL, DYNAMIC_TYPE_SESSION_TICK);
        #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
        (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
            XFREE(preallocNonce, addSession->heap, DYNAMIC_TYPE_SESSION_TICK);
        #endif
        #endif
            SESSION_ROW_UNLOCK(sessRow);
            return MEMORY_E;
        }
        XMEMSET(cacheSession, 0, sizeof(WOLFSSL_SESSION));
        sessRow->Sessions[idx] = cacheSession;
    }
#else
    cacheSession = &sessRow->Sessions[idx];
#endif

#ifdef HAVE_EX_DATA
    if (overwrite) {
        /* Figure out who owns the ex_data */
        if (cacheSession->ownExData) {
            /* Prioritize cacheSession copy */
            XMEMCPY(&addSession->ex_data, &cacheSession->ex_data,
                    sizeof(WOLFSSL_CRYPTO_EX_DATA));
        }
        /* else will be copied in wolfSSL_DupSession call */
    }
    else if (cacheSession->ownExData) {
        crypto_ex_cb_free_data(cacheSession, crypto_ex_cb_ctx_session,
                               &cacheSession->ex_data);
        cacheSession->ownExData = 0;
    }
#endif

    if (!overwrite)
        EvictSessionFromCache(cacheSession);

    cacheSession->type = WOLFSSL_SESSION_TYPE_CACHE;
    cacheSession->cacheRow = row;

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    /* Save the peer field to free after unlocking the row */
    if (cacheSession->peer != NULL)
        cachePeer = cacheSession->peer;
    cacheSession->peer = NULL;
#endif
#ifdef HAVE_SESSION_TICKET
    /* If we can reuse the existing buffer in cacheSession then we won't touch
     * ticBuff at all making it a very cheap malloc/free. The page on a modern
     * OS will most likely not even be allocated to the process. */
    if (ticBuff != NULL && cacheSession->ticketLenAlloc < ticLen) {
        /* Save pointer only if separately allocated */
        if (cacheSession->ticket != cacheSession->staticTicket)
            cacheTicBuff = cacheSession->ticket;
        ticBuffUsed = 1;
        cacheSession->ticket = ticBuff;
        cacheSession->ticketLenAlloc = (word16) ticLen;
    }
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    /* cache entry never used */
    if (cacheSession->ticketNonce.data == NULL)
        cacheSession->ticketNonce.data = cacheSession->ticketNonce.dataStatic;

    if (cacheSession->ticketNonce.data !=
            cacheSession->ticketNonce.dataStatic) {
        toFree = cacheSession->ticketNonce.data;
        cacheSession->ticketNonce.data = cacheSession->ticketNonce.dataStatic;
        cacheSession->ticketNonce.len = 0;
    }
#endif /* WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC && FIPS_VERSION_GE(5,3)*/
#endif
#ifdef SESSION_CERTS
    if (overwrite &&
            addSession->chain.count == 0 &&
            cacheSession->chain.count > 0) {
        /* Copy in the certs from the session */
        addSession->chain.count = cacheSession->chain.count;
        XMEMCPY(addSession->chain.certs, cacheSession->chain.certs,
                sizeof(x509_buffer) * cacheSession->chain.count);
    }
#endif /* SESSION_CERTS */
#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    /* Don't copy the peer cert into cache */
    addPeer = addSession->peer;
    addSession->peer = NULL;
#endif
    cacheSession->heap = NULL;
    /* Copy data into the cache object */
#if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TLS13) &&                  \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                                   \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    ret = (wolfSSL_DupSessionEx(addSession, cacheSession, 1, preallocNonce,
                                &preallocNonceLen, &preallocNonceUsed)
           == WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#else
    ret = (wolfSSL_DupSession(addSession, cacheSession, 1)
           == WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif /* HAVE_SESSION_TICKET && WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC
          && FIPS_VERSION_GE(5,3)*/
#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    addSession->peer = addPeer;
#endif

    if (ret == 0) {
        if (!overwrite) {
            /* Increment the totalCount and the nextIdx */
            if (sessRow->totalCount < SESSIONS_PER_ROW)
                sessRow->totalCount++;
            sessRow->nextIdx = (sessRow->nextIdx + 1) % SESSIONS_PER_ROW;
        }
        if (id != addSession->sessionID) {
            /* ssl->session->sessionID may contain the bogus ID or we want the
             * ID from the arrays object */
            XMEMCPY(cacheSession->sessionID, id, ID_LEN);
            cacheSession->sessionIDSz = ID_LEN;
        }
#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
        if (ctx->rem_sess_cb != NULL)
            cacheSession->rem_sess_cb = ctx->rem_sess_cb;
#endif
#ifdef HAVE_EX_DATA
        /* The session in cache now owns the ex_data */
        addSession->ownExData = 0;
        cacheSession->ownExData = 1;
#endif
#if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TLS13) &&                  \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                                    \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        if (preallocNonce != NULL && preallocNonceUsed) {
            cacheSession->ticketNonce.data = preallocNonce;
            cacheSession->ticketNonce.len = preallocNonceLen;
            preallocNonce = NULL;
            preallocNonceLen = 0;
        }
#endif /* HAVE_SESSION_TICKET && WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC
        * && FIPS_VERSION_GE(5,3)*/
    }
#ifdef HAVE_SESSION_TICKET
    else if (ticBuffUsed) {
        /* Error occurred. Need to clean up the ticket buffer. */
        cacheSession->ticket = cacheSession->staticTicket;
        cacheSession->ticketLenAlloc = 0;
        cacheSession->ticketLen = 0;
    }
#endif
    SESSION_ROW_UNLOCK(sessRow);
    cacheSession = NULL; /* Can't access after unlocked */

#ifndef NO_CLIENT_CACHE
    if (ret == 0 && clientCacheEntry != NULL) {
        ClientSession* clientCache = AddSessionToClientCache(side, row, (int)idx,
                addSession->serverID, addSession->idLen, id, useTicket);
        if (clientCache != NULL)
            *clientCacheEntry = clientCache;
    }
#endif

#ifdef HAVE_SESSION_TICKET
    if (ticBuff != NULL && !ticBuffUsed)
        XFREE(ticBuff, NULL, DYNAMIC_TYPE_SESSION_TICK);
    XFREE(cacheTicBuff, NULL, DYNAMIC_TYPE_SESSION_TICK);
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&         \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    XFREE(preallocNonce, addSession->heap, DYNAMIC_TYPE_SESSION_TICK);
    XFREE(toFree, addSession->heap, DYNAMIC_TYPE_SESSION_TICK);
#endif /* WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC && FIPS_VERSION_GE(5,3)*/
#endif

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    if (cachePeer != NULL) {
        wolfSSL_X509_free(cachePeer);
        cachePeer = NULL; /* Make sure not use after this point */
    }
#endif

    return ret;
}

void AddSession(WOLFSSL* ssl)
{
    int    error = 0;
    const byte* id = NULL;
    byte idSz = 0;
    WOLFSSL_SESSION* session = ssl->session;

    (void)error;

    WOLFSSL_ENTER("AddSession");

    if (SslSessionCacheOff(ssl, session)) {
        WOLFSSL_MSG("Cache off");
        return;
    }

    if (session->haveAltSessionID) {
        id = session->altSessionID;
        idSz = ID_LEN;
    }
    else {
        id = session->sessionID;
        idSz = session->sessionIDSz;
    }

    /* Do this only for the client because if the server doesn't have an ID at
     * this point, it won't on resumption. */
    if (idSz == 0 && ssl->options.side == WOLFSSL_CLIENT_END) {
        WC_RNG* rng = NULL;
        if (ssl->rng != NULL)
            rng = ssl->rng;
#if defined(HAVE_GLOBAL_RNG) && defined(OPENSSL_EXTRA)
        else if (initGlobalRNG == 1 || wolfSSL_RAND_Init() == WOLFSSL_SUCCESS) {
            rng = &globalRNG;
        }
#endif
        if (wc_RNG_GenerateBlock(rng, ssl->session->altSessionID,
                ID_LEN) != 0)
            return;
        ssl->session->haveAltSessionID = 1;
        id = ssl->session->altSessionID;
        idSz = ID_LEN;
    }

#ifdef HAVE_EXT_CACHE
    if (!ssl->options.internalCacheOff)
#endif
    {
        /* Try to add the session to internal cache or external cache
        if a new_sess_cb is set. Its ok if we don't succeed. */
        (void)AddSessionToCache(ssl->ctx, session, id, idSz,
#ifdef SESSION_INDEX
                &ssl->sessionIndex,
#else
                NULL,
#endif
                ssl->options.side,
#ifdef HAVE_SESSION_TICKET
                ssl->options.useTicket,
#else
                0,
#endif
#ifdef NO_SESSION_CACHE_REF
                NULL
#else
                (ssl->options.side == WOLFSSL_CLIENT_END) ?
                        &ssl->clientSession : NULL
#endif
                        );
    }

#ifdef HAVE_EXT_CACHE
    if (error == 0 && ssl->ctx->new_sess_cb != NULL) {
        int cbRet = 0;
        wolfSSL_SESSION_up_ref(session);
        cbRet = ssl->ctx->new_sess_cb(ssl, session);
        if (cbRet == 0)
            wolfSSL_FreeSession(ssl->ctx, session);
    }
#endif

#if defined(WOLFSSL_SESSION_STATS) && defined(WOLFSSL_PEAK_SESSIONS)
    if (error == 0) {
        word32 active = 0;

        error = get_locked_session_stats(&active, NULL, NULL);
        if (error == WOLFSSL_SUCCESS) {
            error = 0;  /* back to this function ok */

            if (PeakSessions < active) {
                PeakSessions = active;
            }
        }
    }
#endif /* WOLFSSL_SESSION_STATS && WOLFSSL_PEAK_SESSIONS */
    (void)error;
}


#ifdef SESSION_INDEX

int wolfSSL_GetSessionIndex(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_GetSessionIndex");
    WOLFSSL_LEAVE("wolfSSL_GetSessionIndex", ssl->sessionIndex);
    return ssl->sessionIndex;
}


int wolfSSL_GetSessionAtIndex(int idx, WOLFSSL_SESSION* session)
{
    int row, col, result = WOLFSSL_FAILURE;
    SessionRow* sessRow;
    WOLFSSL_SESSION* cacheSession;

    WOLFSSL_ENTER("wolfSSL_GetSessionAtIndex");

    session = ClientSessionToSession(session);

    row = idx >> SESSIDX_ROW_SHIFT;
    col = idx & SESSIDX_IDX_MASK;

    if (session == NULL ||
            row < 0 || row >= SESSION_ROWS || col >= SESSIONS_PER_ROW) {
        return WOLFSSL_FAILURE;
    }

    sessRow = &SessionCache[row];
    if (SESSION_ROW_RD_LOCK(sessRow) != 0) {
        return BAD_MUTEX_E;
    }

#ifdef SESSION_CACHE_DYNAMIC_MEM
    cacheSession = sessRow->Sessions[col];
#else
    cacheSession = &sessRow->Sessions[col];
#endif
    if (cacheSession) {
        XMEMCPY(session, cacheSession, sizeof(WOLFSSL_SESSION));
        result = WOLFSSL_SUCCESS;
    }
    else {
        result = WOLFSSL_FAILURE;
    }

    SESSION_ROW_UNLOCK(sessRow);

    WOLFSSL_LEAVE("wolfSSL_GetSessionAtIndex", result);
    return result;
}

#endif /* SESSION_INDEX */

#if defined(SESSION_CERTS)

WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session)
{
    WOLFSSL_X509_CHAIN* chain = NULL;

    WOLFSSL_ENTER("wolfSSL_SESSION_get_peer_chain");

    session = ClientSessionToSession(session);

    if (session)
        chain = &session->chain;

    WOLFSSL_LEAVE("wolfSSL_SESSION_get_peer_chain", chain ? 1 : 0);
    return chain;
}


#ifdef OPENSSL_EXTRA
/* gets the peer certificate associated with the session passed in
 * returns null on failure, the caller should not free the returned pointer */
WOLFSSL_X509* wolfSSL_SESSION_get0_peer(WOLFSSL_SESSION* session)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_get_peer_chain");

    session = ClientSessionToSession(session);
    if (session) {
        int count;

        count = wolfSSL_get_chain_count(&session->chain);
        if (count < 1 || count >= MAX_CHAIN_DEPTH) {
            WOLFSSL_MSG("bad count found");
            return NULL;
        }

        if (session->peer == NULL) {
            session->peer = wolfSSL_get_chain_X509(&session->chain, 0);
        }
        return session->peer;
    }
    WOLFSSL_MSG("No session passed in");

    return NULL;
}
#endif /* OPENSSL_EXTRA */
#endif /* SESSION_INDEX && SESSION_CERTS */


#ifdef WOLFSSL_SESSION_STATS

static int get_locked_session_stats(word32* active, word32* total, word32* peak)
{
    int result = WOLFSSL_SUCCESS;
    int i;
    int count;
    int idx;
    word32 now   = 0;
    word32 seen  = 0;
    word32 ticks = LowResTimer();

    WOLFSSL_ENTER("get_locked_session_stats");

#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    SESSION_ROW_RD_LOCK(&SessionCache[0]);
#endif
    for (i = 0; i < SESSION_ROWS; i++) {
        SessionRow* row = &SessionCache[i];
    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        if (SESSION_ROW_RD_LOCK(row) != 0) {
            WOLFSSL_MSG("Session row cache mutex lock failed");
            return BAD_MUTEX_E;
        }
    #endif

        seen += row->totalCount;

        if (active == NULL) {
            SESSION_ROW_UNLOCK(row);
            continue;
        }

        count = min((word32)row->totalCount, SESSIONS_PER_ROW);
        idx   = row->nextIdx - 1;
        if (idx < 0 || idx >= SESSIONS_PER_ROW) {
            idx = SESSIONS_PER_ROW - 1; /* if back to front previous was end */
        }

        for (; count > 0; --count) {
            /* if not expired then good */
#ifdef SESSION_CACHE_DYNAMIC_MEM
            if (row->Sessions[idx] &&
                ticks < (row->Sessions[idx]->bornOn +
                            row->Sessions[idx]->timeout) )
#else
            if (ticks < (row->Sessions[idx].bornOn +
                            row->Sessions[idx].timeout) )
#endif
            {
                now++;
            }

            idx = idx > 0 ? idx - 1 : SESSIONS_PER_ROW - 1;
        }

    #ifdef ENABLE_SESSION_CACHE_ROW_LOCK
        SESSION_ROW_UNLOCK(row);
    #endif
    }
#ifndef ENABLE_SESSION_CACHE_ROW_LOCK
    SESSION_ROW_UNLOCK(&SessionCache[0]);
#endif

    if (active) {
        *active = now;
    }
    if (total) {
        *total = seen;
    }

#ifdef WOLFSSL_PEAK_SESSIONS
    if (peak) {
        *peak = PeakSessions;
    }
#else
    (void)peak;
#endif

    WOLFSSL_LEAVE("get_locked_session_stats", result);

    return result;
}


/* return WOLFSSL_SUCCESS on ok */
int wolfSSL_get_session_stats(word32* active, word32* total, word32* peak,
                              word32* maxSessions)
{
    int result = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_get_session_stats");

    if (maxSessions) {
        *maxSessions = SESSIONS_PER_ROW * SESSION_ROWS;

        if (active == NULL && total == NULL && peak == NULL)
            return result;  /* we're done */
    }

    /* user must provide at least one query value */
    if (active == NULL && total == NULL && peak == NULL) {
        return BAD_FUNC_ARG;
    }

    result = get_locked_session_stats(active, total, peak);

    WOLFSSL_LEAVE("wolfSSL_get_session_stats", result);

    return result;
}

#endif /* WOLFSSL_SESSION_STATS */


    #ifdef PRINT_SESSION_STATS

    /* WOLFSSL_SUCCESS on ok */
    int wolfSSL_PrintSessionStats(void)
    {
        word32 totalSessionsSeen = 0;
        word32 totalSessionsNow = 0;
        word32 peak = 0;
        word32 maxSessions = 0;
        int    i;
        int    ret;
        double E;               /* expected freq */
        double chiSquare = 0;

        ret = wolfSSL_get_session_stats(&totalSessionsNow, &totalSessionsSeen,
                                        &peak, &maxSessions);
        if (ret != WOLFSSL_SUCCESS)
            return ret;
        printf("Total Sessions Seen = %u\n", totalSessionsSeen);
        printf("Total Sessions Now  = %u\n", totalSessionsNow);
#ifdef WOLFSSL_PEAK_SESSIONS
        printf("Peak  Sessions      = %u\n", peak);
#endif
        printf("Max   Sessions      = %u\n", maxSessions);

        E = (double)totalSessionsSeen / SESSION_ROWS;

        for (i = 0; i < SESSION_ROWS; i++) {
            double diff = SessionCache[i].totalCount - E;
            diff *= diff;                /* square    */
            diff /= E;                   /* normalize */

            chiSquare += diff;
        }
        printf("  chi-square = %5.1f, d.f. = %d\n", chiSquare,
                                                     SESSION_ROWS - 1);
        #if (SESSION_ROWS == 11)
            printf(" .05 p value =  18.3, chi-square should be less\n");
        #elif (SESSION_ROWS == 211)
            printf(".05 p value  = 244.8, chi-square should be less\n");
        #elif (SESSION_ROWS == 5981)
            printf(".05 p value  = 6161.0, chi-square should be less\n");
        #elif (SESSION_ROWS == 3)
            printf(".05 p value  =   6.0, chi-square should be less\n");
        #elif (SESSION_ROWS == 2861)
            printf(".05 p value  = 2985.5, chi-square should be less\n");
        #endif
        printf("\n");

        return ret;
    }

    #endif /* SESSION_STATS */

#else  /* NO_SESSION_CACHE */

WOLFSSL_SESSION* ClientSessionToSession(const WOLFSSL_SESSION* session)
{
    return (WOLFSSL_SESSION*)session;
}

/* No session cache version */
WOLFSSL_SESSION* wolfSSL_GetSession(WOLFSSL* ssl, byte* masterSecret,
        byte restoreSessionCerts)
{
    (void)ssl;
    (void)masterSecret;
    (void)restoreSessionCerts;

    return NULL;
}

#endif /* NO_SESSION_CACHE */

#ifdef OPENSSL_EXTRA

   /* returns previous set cache size which stays constant */
    long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX* ctx, long sz)
    {
        /* cache size fixed at compile time in wolfSSL */
        (void)ctx;
        (void)sz;
        WOLFSSL_MSG("session cache is set at compile time");
        #ifndef NO_SESSION_CACHE
            return (long)(SESSIONS_PER_ROW * SESSION_ROWS);
        #else
            return 0;
        #endif
    }


    long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX* ctx)
    {
        (void)ctx;
        #ifndef NO_SESSION_CACHE
            return (long)(SESSIONS_PER_ROW * SESSION_ROWS);
        #else
            return 0;
        #endif
    }

#endif

#ifndef NO_SESSION_CACHE
int wolfSSL_CTX_add_session(WOLFSSL_CTX* ctx, WOLFSSL_SESSION* session)
{
    int    error = 0;
    const byte* id = NULL;
    byte idSz = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_add_session");

    session = ClientSessionToSession(session);
    if (session == NULL)
        return WOLFSSL_FAILURE;

    /* Session cache is global */
    (void)ctx;

    if (session->haveAltSessionID) {
        id = session->altSessionID;
        idSz = ID_LEN;
    }
    else {
        id = session->sessionID;
        idSz = session->sessionIDSz;
    }

    error = AddSessionToCache(ctx, session, id, idSz,
            NULL, session->side,
#ifdef HAVE_SESSION_TICKET
            session->ticketLen > 0,
#else
            0,
#endif
            NULL);

    return error == 0 ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
#endif

#if !defined(NO_SESSION_CACHE) && (defined(OPENSSL_EXTRA) || \
        defined(HAVE_EXT_CACHE))
/* stunnel 4.28 needs
 *
 * Callback that is called if a session tries to resume but could not find
 * the session to resume it.
 */
void wolfSSL_CTX_sess_set_get_cb(WOLFSSL_CTX* ctx,
    WOLFSSL_SESSION*(*f)(WOLFSSL*, const unsigned char*, int, int*))
{
    if (ctx == NULL)
        return;

#ifdef HAVE_EXT_CACHE
    ctx->get_sess_cb = f;
#else
    (void)f;
#endif
}

void wolfSSL_CTX_sess_set_new_cb(WOLFSSL_CTX* ctx,
                             int (*f)(WOLFSSL*, WOLFSSL_SESSION*))
{
    if (ctx == NULL)
        return;

#ifdef HAVE_EXT_CACHE
    ctx->new_sess_cb = f;
#else
    (void)f;
#endif
}

void wolfSSL_CTX_sess_set_remove_cb(WOLFSSL_CTX* ctx, void (*f)(WOLFSSL_CTX*,
                                                        WOLFSSL_SESSION*))
{
    if (ctx == NULL)
        return;

#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
    ctx->rem_sess_cb = f;
#else
    (void)f;
#endif
}


/*
 *
 * Note: It is expected that the importing and exporting function have been
 *       built with the same settings. For example if session tickets was
 *       enabled with the wolfSSL library exporting a session then it is
 *       expected to be turned on with the wolfSSL library importing the
 *       session.
 */
int wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION* sess, unsigned char** p)
{
    int size = 0;
#ifdef HAVE_EXT_CACHE
    int idx = 0;
#ifdef SESSION_CERTS
    int i;
#endif

    WOLFSSL_ENTER("wolfSSL_i2d_SSL_SESSION");

    sess = ClientSessionToSession(sess);
    if (sess == NULL) {
        return BAD_FUNC_ARG;
    }

    /* side | bornOn | timeout | sessionID len | sessionID | masterSecret |
     * haveEMS  */
    size += OPAQUE8_LEN + OPAQUE32_LEN + OPAQUE32_LEN + OPAQUE8_LEN +
            sess->sessionIDSz + SECRET_LEN + OPAQUE8_LEN;
    /* altSessionID */
    size += OPAQUE8_LEN + (sess->haveAltSessionID ? ID_LEN : 0);
#ifdef SESSION_CERTS
    /* Peer chain */
    size += OPAQUE8_LEN;
    for (i = 0; i < sess->chain.count; i++)
        size += OPAQUE16_LEN + sess->chain.certs[i].length;
#endif
#if defined(SESSION_CERTS) || (defined(WOLFSSL_TLS13) && \
                               defined(HAVE_SESSION_TICKET))
    /* Protocol version */
    size += OPAQUE16_LEN;
#endif
#if defined(SESSION_CERTS) || !defined(NO_RESUME_SUITE_CHECK) || \
                        (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET))
    /* cipher suite */
    size += OPAQUE16_LEN;
#endif
#ifndef NO_CLIENT_CACHE
    /* ServerID len | ServerID */
    size += OPAQUE16_LEN + sess->idLen;
#endif
#ifdef WOLFSSL_SESSION_ID_CTX
    /* session context ID len | session context ID */
    size += OPAQUE8_LEN + sess->sessionCtxSz;
#endif
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    /* peerVerifyRet */
    size += OPAQUE8_LEN;
#endif
#ifdef WOLFSSL_TLS13
    /* namedGroup */
    size += OPAQUE16_LEN;
#endif
#if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
#ifdef WOLFSSL_TLS13
#ifdef WOLFSSL_32BIT_MILLI_TIME
    /* ticketSeen | ticketAdd */
    size += OPAQUE32_LEN + OPAQUE32_LEN;
#else
    /* ticketSeen Hi 32 bits | ticketSeen Lo 32 bits | ticketAdd */
    size += OPAQUE32_LEN + OPAQUE32_LEN + OPAQUE32_LEN;
#endif
    /* ticketNonce */
    size += OPAQUE8_LEN + sess->ticketNonce.len;
#endif
#ifdef WOLFSSL_EARLY_DATA
    size += OPAQUE32_LEN;
#endif
#endif
#ifdef HAVE_SESSION_TICKET
    /* ticket len | ticket */
    size += OPAQUE16_LEN + sess->ticketLen;
#endif

    if (p != NULL) {
        unsigned char *data;

        if (*p == NULL)
            *p = (unsigned char*)XMALLOC(size, NULL, DYNAMIC_TYPE_OPENSSL);
        if (*p == NULL)
            return 0;
        data = *p;

        data[idx++] = sess->side;
        c32toa(sess->bornOn, data + idx); idx += OPAQUE32_LEN;
        c32toa(sess->timeout, data + idx); idx += OPAQUE32_LEN;
        data[idx++] = sess->sessionIDSz;
        XMEMCPY(data + idx, sess->sessionID, sess->sessionIDSz);
        idx += sess->sessionIDSz;
        XMEMCPY(data + idx, sess->masterSecret, SECRET_LEN); idx += SECRET_LEN;
        data[idx++] = (byte)sess->haveEMS;
        data[idx++] = sess->haveAltSessionID ? ID_LEN : 0;
        if (sess->haveAltSessionID) {
            XMEMCPY(data + idx, sess->altSessionID, ID_LEN);
            idx += ID_LEN;
        }
#ifdef SESSION_CERTS
        data[idx++] = (byte)sess->chain.count;
        for (i = 0; i < sess->chain.count; i++) {
            c16toa((word16)sess->chain.certs[i].length, data + idx);
            idx += OPAQUE16_LEN;
            XMEMCPY(data + idx, sess->chain.certs[i].buffer,
                    sess->chain.certs[i].length);
            idx += sess->chain.certs[i].length;
        }
#endif
#if defined(SESSION_CERTS) || (defined(WOLFSSL_TLS13) && \
                               defined(HAVE_SESSION_TICKET))
        data[idx++] = sess->version.major;
        data[idx++] = sess->version.minor;
#endif
#if defined(SESSION_CERTS) || !defined(NO_RESUME_SUITE_CHECK) || \
                        (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET))
        data[idx++] = sess->cipherSuite0;
        data[idx++] = sess->cipherSuite;
#endif
#ifndef NO_CLIENT_CACHE
        c16toa(sess->idLen, data + idx); idx += OPAQUE16_LEN;
        XMEMCPY(data + idx, sess->serverID, sess->idLen);
        idx += sess->idLen;
#endif
#ifdef WOLFSSL_SESSION_ID_CTX
        data[idx++] = sess->sessionCtxSz;
        XMEMCPY(data + idx, sess->sessionCtx, sess->sessionCtxSz);
        idx += sess->sessionCtxSz;
#endif
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        data[idx++] = sess->peerVerifyRet;
#endif
#ifdef WOLFSSL_TLS13
        c16toa(sess->namedGroup, data + idx);
        idx += OPAQUE16_LEN;
#endif
#if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
#ifdef WOLFSSL_TLS13
#ifdef WOLFSSL_32BIT_MILLI_TIME
        c32toa(sess->ticketSeen, data + idx);
        idx += OPAQUE32_LEN;
#else
        c32toa((word32)(sess->ticketSeen >> 32), data + idx);
        idx += OPAQUE32_LEN;
        c32toa((word32)sess->ticketSeen, data + idx);
        idx += OPAQUE32_LEN;
#endif
        c32toa(sess->ticketAdd, data + idx);
        idx += OPAQUE32_LEN;
        data[idx++] = sess->ticketNonce.len;
        XMEMCPY(data + idx, sess->ticketNonce.data, sess->ticketNonce.len);
        idx += sess->ticketNonce.len;
#endif
#ifdef WOLFSSL_EARLY_DATA
        c32toa(sess->maxEarlyDataSz, data + idx);
        idx += OPAQUE32_LEN;
#endif
#endif
#ifdef HAVE_SESSION_TICKET
        c16toa(sess->ticketLen, data + idx); idx += OPAQUE16_LEN;
        XMEMCPY(data + idx, sess->ticket, sess->ticketLen);
        idx += sess->ticketLen;
#endif
    }
#endif

    (void)sess;
    (void)p;
#ifdef HAVE_EXT_CACHE
    (void)idx;
#endif

    return size;
}


/* TODO: no function to free new session.
 *
 * Note: It is expected that the importing and exporting function have been
 *       built with the same settings. For example if session tickets was
 *       enabled with the wolfSSL library exporting a session then it is
 *       expected to be turned on with the wolfSSL library importing the
 *       session.
 */
WOLFSSL_SESSION* wolfSSL_d2i_SSL_SESSION(WOLFSSL_SESSION** sess,
                                const unsigned char** p, long i)
{
    WOLFSSL_SESSION* s = NULL;
    int ret = 0;
#if defined(HAVE_EXT_CACHE)
    int idx = 0;
    byte* data;
#ifdef SESSION_CERTS
    int j;
    word16 length;
#endif
#endif /* HAVE_EXT_CACHE */

    (void)p;
    (void)i;
    (void)ret;
    (void)sess;

#ifdef HAVE_EXT_CACHE
    if (p == NULL || *p == NULL)
        return NULL;

    s = wolfSSL_SESSION_new();
    if (s == NULL)
        return NULL;

    idx = 0;
    data = (byte*)*p;

    /* side | bornOn | timeout | sessionID len */
    if (i < OPAQUE8_LEN + OPAQUE32_LEN + OPAQUE32_LEN + OPAQUE8_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->side = data[idx++];
    ato32(data + idx, &s->bornOn); idx += OPAQUE32_LEN;
    ato32(data + idx, &s->timeout); idx += OPAQUE32_LEN;
    s->sessionIDSz = data[idx++];

    /* sessionID | secret | haveEMS | haveAltSessionID */
    if (i - idx < s->sessionIDSz + SECRET_LEN + OPAQUE8_LEN + OPAQUE8_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    XMEMCPY(s->sessionID, data + idx, s->sessionIDSz);
    idx  += s->sessionIDSz;
    XMEMCPY(s->masterSecret, data + idx, SECRET_LEN); idx += SECRET_LEN;
    s->haveEMS = data[idx++];
    if (data[idx] != ID_LEN && data[idx] != 0) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->haveAltSessionID = data[idx++] == ID_LEN;

    /* altSessionID */
    if (s->haveAltSessionID) {
        if (i - idx < ID_LEN) {
            ret = BUFFER_ERROR;
            goto end;
        }
        XMEMCPY(s->altSessionID, data + idx, ID_LEN); idx += ID_LEN;
    }

#ifdef SESSION_CERTS
    /* Certificate chain */
    if (i - idx == 0) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->chain.count = data[idx++];
    for (j = 0; j < s->chain.count; j++) {
        if (i - idx < OPAQUE16_LEN) {
            ret = BUFFER_ERROR;
            goto end;
        }
        ato16(data + idx, &length); idx += OPAQUE16_LEN;
        s->chain.certs[j].length = length;
        if (i - idx < length) {
            ret = BUFFER_ERROR;
            goto end;
        }
        XMEMCPY(s->chain.certs[j].buffer, data + idx, length);
        idx += length;
    }
#endif
#if defined(SESSION_CERTS) || (defined(WOLFSSL_TLS13) && \
                               defined(HAVE_SESSION_TICKET))
    /* Protocol Version */
    if (i - idx < OPAQUE16_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->version.major = data[idx++];
    s->version.minor = data[idx++];
#endif
#if defined(SESSION_CERTS) || !defined(NO_RESUME_SUITE_CHECK) || \
                        (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET))
    /* Cipher suite */
    if (i - idx < OPAQUE16_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->cipherSuite0 = data[idx++];
    s->cipherSuite = data[idx++];
#endif
#ifndef NO_CLIENT_CACHE
    /* ServerID len */
    if (i - idx < OPAQUE16_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    ato16(data + idx, &s->idLen); idx += OPAQUE16_LEN;

    /* ServerID */
    if (i - idx < s->idLen) {
        ret = BUFFER_ERROR;
        goto end;
    }
    XMEMCPY(s->serverID, data + idx, s->idLen); idx += s->idLen;
#endif
#ifdef WOLFSSL_SESSION_ID_CTX
    /* byte for length of session context ID */
    if (i - idx < OPAQUE8_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->sessionCtxSz = data[idx++];

    /* app session context ID */
    if (i - idx < s->sessionCtxSz) {
        ret = BUFFER_ERROR;
        goto end;
    }
    XMEMCPY(s->sessionCtx, data + idx, s->sessionCtxSz); idx += s->sessionCtxSz;
#endif
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    /* byte for peerVerifyRet */
    if (i - idx < OPAQUE8_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->peerVerifyRet = data[idx++];
#endif
#ifdef WOLFSSL_TLS13
    if (i - idx < OPAQUE16_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    ato16(data + idx, &s->namedGroup);
    idx += OPAQUE16_LEN;
#endif
#if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
#ifdef WOLFSSL_TLS13
    if (i - idx < (OPAQUE32_LEN * 2)) {
        ret = BUFFER_ERROR;
        goto end;
    }
#ifdef WOLFSSL_32BIT_MILLI_TIME
    ato32(data + idx, &s->ticketSeen);
    idx += OPAQUE32_LEN;
#else
    {
        word32 seenHi, seenLo;

        ato32(data + idx, &seenHi);
        idx += OPAQUE32_LEN;
        ato32(data + idx, &seenLo);
        idx += OPAQUE32_LEN;
        s->ticketSeen = ((sword64)seenHi << 32) + seenLo;
    }
#endif
    ato32(data + idx, &s->ticketAdd);
    idx += OPAQUE32_LEN;
    if (i - idx < OPAQUE8_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    s->ticketNonce.len = data[idx++];

    if (i - idx < s->ticketNonce.len) {
        ret = BUFFER_ERROR;
        goto end;
    }
#if defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                     \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    ret = SessionTicketNoncePopulate(s, data + idx, s->ticketNonce.len);
    if (ret != 0)
        goto end;
#else
    if (s->ticketNonce.len > MAX_TICKET_NONCE_STATIC_SZ) {
        ret = BUFFER_ERROR;
        goto end;
    }
    XMEMCPY(s->ticketNonce.data, data + idx, s->ticketNonce.len);
#endif /* defined(WOLFSSL_TICKET_NONCE_MALLOC) && FIPS_VERSION_GE(5,3) */

    idx += s->ticketNonce.len;
#endif
#ifdef WOLFSSL_EARLY_DATA
    if (i - idx < OPAQUE32_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    ato32(data + idx, &s->maxEarlyDataSz);
    idx += OPAQUE32_LEN;
#endif
#endif
#ifdef HAVE_SESSION_TICKET
    /* ticket len */
    if (i - idx < OPAQUE16_LEN) {
        ret = BUFFER_ERROR;
        goto end;
    }
    ato16(data + idx, &s->ticketLen); idx += OPAQUE16_LEN;

    /* Dispose of ol dynamic ticket and ensure space for new ticket. */
    if (s->ticketLenAlloc > 0) {
        XFREE(s->ticket, NULL, DYNAMIC_TYPE_SESSION_TICK);
    }
    if (s->ticketLen <= SESSION_TICKET_LEN)
        s->ticket = s->staticTicket;
    else {
        s->ticket = (byte*)XMALLOC(s->ticketLen, NULL,
                                   DYNAMIC_TYPE_SESSION_TICK);
        if (s->ticket == NULL) {
            ret = MEMORY_ERROR;
            goto end;
        }
        s->ticketLenAlloc = (word16)s->ticketLen;
    }

    /* ticket */
    if (i - idx < s->ticketLen) {
        ret = BUFFER_ERROR;
        goto end;
    }
    XMEMCPY(s->ticket, data + idx, s->ticketLen); idx += s->ticketLen;
#endif
    (void)idx;

    if (sess != NULL) {
        *sess = s;
    }

    s->isSetup = 1;

    *p += idx;

end:
    if (ret != 0 && (sess == NULL || *sess != s)) {
        wolfSSL_FreeSession(NULL, s);
        s = NULL;
    }
#endif /* HAVE_EXT_CACHE */
    return s;
}

/* Check if there is a session ticket associated with this WOLFSSL_SESSION.
 *
 * sess - pointer to WOLFSSL_SESSION struct
 *
 * Returns 1 if has session ticket, otherwise 0 */
int wolfSSL_SESSION_has_ticket(const WOLFSSL_SESSION* sess)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_has_ticket");
#ifdef HAVE_SESSION_TICKET
    sess = ClientSessionToSession(sess);
    if (sess) {
        if ((sess->ticketLen > 0) && (sess->ticket != NULL)) {
            return WOLFSSL_SUCCESS;
        }
    }
#else
    (void)sess;
#endif
    return WOLFSSL_FAILURE;
}

unsigned long wolfSSL_SESSION_get_ticket_lifetime_hint(
                  const WOLFSSL_SESSION* sess)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_get_ticket_lifetime_hint");
    sess = ClientSessionToSession(sess);
    if (sess) {
        return sess->timeout;
    }
    return 0;
}

long wolfSSL_SESSION_get_timeout(const WOLFSSL_SESSION* sess)
{
    long timeout = 0;
    WOLFSSL_ENTER("wolfSSL_SESSION_get_timeout");
    sess = ClientSessionToSession(sess);
    if (sess)
        timeout = sess->timeout;
    return timeout;
}

long wolfSSL_SSL_SESSION_set_timeout(WOLFSSL_SESSION* ses, long t)
{
    word32 tmptime;

    ses = ClientSessionToSession(ses);
    if (ses == NULL || t < 0) {
        return BAD_FUNC_ARG;
    }

    tmptime = t & 0xFFFFFFFF;
    ses->timeout = tmptime;

    return WOLFSSL_SUCCESS;
}

long wolfSSL_SESSION_get_time(const WOLFSSL_SESSION* sess)
{
    long bornOn = 0;
    WOLFSSL_ENTER("wolfSSL_SESSION_get_time");
    sess = ClientSessionToSession(sess);
    if (sess)
        bornOn = sess->bornOn;
    return bornOn;
}

long wolfSSL_SESSION_set_time(WOLFSSL_SESSION *ses, long t)
{

    ses = ClientSessionToSession(ses);
    if (ses == NULL || t < 0) {
        return 0;
    }
    ses->bornOn = (word32)t;
    return t;
}

#endif /* !NO_SESSION_CACHE && OPENSSL_EXTRA || HAVE_EXT_CACHE */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(HAVE_EX_DATA)

#if defined(HAVE_EX_DATA) && !defined(NO_SESSION_CACHE)
static void SESSION_ex_data_cache_update(WOLFSSL_SESSION* session, int idx,
        void* data, byte get, void** getRet, int* setRet)
{
    int row;
    int i;
    int error = 0;
    SessionRow* sessRow = NULL;
    const byte* id;
    byte foundCache = 0;

    if (getRet != NULL)
        *getRet = NULL;
    if (setRet != NULL)
        *setRet = WOLFSSL_FAILURE;

    id = session->sessionID;
    if (session->haveAltSessionID)
        id = session->altSessionID;

    row = (int)(HashObject(id, ID_LEN, &error) % SESSION_ROWS);
    if (error != 0) {
        WOLFSSL_MSG("Hash session failed");
        return;
    }

    sessRow = &SessionCache[row];
    if (get)
        error = SESSION_ROW_RD_LOCK(sessRow);
    else
        error = SESSION_ROW_WR_LOCK(sessRow);
    if (error != 0) {
        WOLFSSL_MSG("Session row lock failed");
        return;
    }

    for (i = 0; i < SESSIONS_PER_ROW && i < sessRow->totalCount; i++) {
        WOLFSSL_SESSION* cacheSession;
#ifdef SESSION_CACHE_DYNAMIC_MEM
        cacheSession = sessRow->Sessions[i];
#else
        cacheSession = &sessRow->Sessions[i];
#endif
        if (cacheSession &&
                XMEMCMP(id, cacheSession->sessionID, ID_LEN) == 0
                && session->side == cacheSession->side
        #if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET)
                && (IsAtLeastTLSv1_3(session->version) ==
                    IsAtLeastTLSv1_3(cacheSession->version))
        #endif
            ) {
            if (get) {
                if (getRet) {
                    *getRet = wolfSSL_CRYPTO_get_ex_data(
                        &cacheSession->ex_data, idx);
                }
            }
            else {
                if (setRet) {
                    *setRet = wolfSSL_CRYPTO_set_ex_data(
                        &cacheSession->ex_data, idx, data);
                }
            }
            foundCache = 1;
            break;
        }
    }
    SESSION_ROW_UNLOCK(sessRow);
    /* If we don't have a session in cache then clear the ex_data and
     * own it */
    if (!foundCache) {
        XMEMSET(&session->ex_data, 0, sizeof(WOLFSSL_CRYPTO_EX_DATA));
        session->ownExData = 1;
        if (!get) {
            *setRet = wolfSSL_CRYPTO_set_ex_data(&session->ex_data, idx,
                    data);
        }
    }

}
#endif

#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

#ifndef NO_SESSION_CACHE
int wolfSSL_SSL_CTX_remove_session(WOLFSSL_CTX *ctx, WOLFSSL_SESSION *s)
{
#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
    int rem_called = FALSE;
#endif

    WOLFSSL_ENTER("wolfSSL_SSL_CTX_remove_session");

    s = ClientSessionToSession(s);
    if (ctx == NULL || s == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_EXT_CACHE
    if (!ctx->internalCacheOff)
#endif
    {
        const byte* id;
        WOLFSSL_SESSION *sess = NULL;
        word32 row = 0;
        int ret;

        id = s->sessionID;
        if (s->haveAltSessionID)
            id = s->altSessionID;

        ret = TlsSessionCacheGetAndWrLock(id, &sess, &row, ctx->method->side);
        if (ret == 0 && sess != NULL) {
#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
            if (sess->rem_sess_cb != NULL) {
                rem_called = TRUE;
            }
#endif
            /* Call this before changing ownExData so that calls to ex_data
             * don't try to access the SessionCache again. */
            EvictSessionFromCache(sess);
#ifdef HAVE_EX_DATA
            if (sess->ownExData) {
                /* Most recent version of ex data is in cache. Copy it
                 * over so the user can free it. */
                XMEMCPY(&s->ex_data, &sess->ex_data,
                        sizeof(WOLFSSL_CRYPTO_EX_DATA));
                s->ownExData = 1;
                sess->ownExData = 0;
            }
#endif
#ifdef SESSION_CACHE_DYNAMIC_MEM
            {
                /* Find and clear entry. Row is locked so we are good to go. */
                int idx;
                for (idx = 0; idx < SESSIONS_PER_ROW; idx++) {
                    if (sess == SessionCache[row].Sessions[idx]) {
                        XFREE(sess, sess->heap, DYNAMIC_TYPE_SESSION);
                        SessionCache[row].Sessions[idx] = NULL;
                        break;
                    }
                }
            }
#endif
            TlsSessionCacheUnlockRow(row);
        }
    }

#if defined(HAVE_EXT_CACHE) || defined(HAVE_EX_DATA)
    if (ctx->rem_sess_cb != NULL && !rem_called) {
        ctx->rem_sess_cb(ctx, s);
    }
#endif

    /* s cannot be resumed at this point */
    s->timeout = 0;

    return 0;
}

WOLFSSL_SESSION *wolfSSL_SSL_get0_session(const WOLFSSL *ssl)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get0_session");

    return ssl->session;
}

#endif /* NO_SESSION_CACHE */

#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */

#ifdef WOLFSSL_SESSION_EXPORT
/* Used to import a serialized TLS session.
 * WARNING: buf contains sensitive information about the state and is best to be
 *          encrypted before storing if stored.
 *
 * @param ssl WOLFSSL structure to import the session into
 * @param buf serialized session
 * @param sz  size of buffer 'buf'
 * @return the number of bytes read from buffer 'buf'
 */
int wolfSSL_tls_import(WOLFSSL* ssl, const unsigned char* buf, unsigned int sz)
{
    if (ssl == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSSL_session_import_internal(ssl, buf, sz, WOLFSSL_EXPORT_TLS);
}


/* Used to export a serialized TLS session.
 * WARNING: buf contains sensitive information about the state and is best to be
 *          encrypted before storing if stored.
 *
 * @param ssl WOLFSSL structure to export the session from
 * @param buf output of serialized session
 * @param sz  size in bytes set in 'buf'
 * @return the number of bytes written into buffer 'buf'
 */
int wolfSSL_tls_export(WOLFSSL* ssl, unsigned char* buf, unsigned int* sz)
{
    if (ssl == NULL || sz == NULL) {
        return BAD_FUNC_ARG;
    }
    return wolfSSL_session_export_internal(ssl, buf, sz, WOLFSSL_EXPORT_TLS);
}

#ifdef WOLFSSL_DTLS
int wolfSSL_dtls_import(WOLFSSL* ssl, const unsigned char* buf, unsigned int sz)
{
    WOLFSSL_ENTER("wolfSSL_session_import");

    if (ssl == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }

    /* sanity checks on buffer and protocol are done in internal function */
    return wolfSSL_session_import_internal(ssl, buf, sz, WOLFSSL_EXPORT_DTLS);
}


/* Sets the function to call for serializing the session. This function is
 * called right after the handshake is completed. */
int wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx, wc_dtls_export func)
{

    WOLFSSL_ENTER("wolfSSL_CTX_dtls_set_export");

    /* purposefully allow func to be NULL */
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    ctx->dtls_export = func;

    return WOLFSSL_SUCCESS;
}

/* Sets the function in WOLFSSL struct to call for serializing the session. This
 * function is called right after the handshake is completed. */
int wolfSSL_dtls_set_export(WOLFSSL* ssl, wc_dtls_export func)
{

    WOLFSSL_ENTER("wolfSSL_dtls_set_export");

    /* purposefully allow func to be NULL */
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ssl->dtls_export = func;

    return WOLFSSL_SUCCESS;
}


/* This function allows for directly serializing a session rather than using
 * callbacks. It has less overhead by removing a temporary buffer and gives
 * control over when the session gets serialized. When using callbacks the
 * session is always serialized immediately after the handshake is finished.
 *
 * buf is the argument to contain the serialized session
 * sz  is the size of the buffer passed in
 * ssl is the WOLFSSL struct to serialize
 * returns the size of serialized session on success, 0 on no action, and
 *         negative value on error */
int wolfSSL_dtls_export(WOLFSSL* ssl, unsigned char* buf, unsigned int* sz)
{
    WOLFSSL_ENTER("wolfSSL_dtls_export");

    if (ssl == NULL || sz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (buf == NULL) {
        *sz = MAX_EXPORT_BUFFER;
        return 0;
    }

    /* if not DTLS do nothing */
    if (!ssl->options.dtls) {
        WOLFSSL_MSG("Currently only DTLS export is supported");
        return 0;
    }

    /* copy over keys, options, and dtls state struct */
    return wolfSSL_session_export_internal(ssl, buf, sz, WOLFSSL_EXPORT_DTLS);
}


/* This function is similar to wolfSSL_dtls_export but only exports the portion
 * of the WOLFSSL structure related to the state of the connection, i.e. peer
 * sequence number, epoch, AEAD state etc.
 *
 * buf is the argument to contain the serialized state, if null then set "sz" to
 *     buffer size required
 * sz  is the size of the buffer passed in
 * ssl is the WOLFSSL struct to serialize
 * returns the size of serialized session on success, 0 on no action, and
 *         negative value on error */
int wolfSSL_dtls_export_state_only(WOLFSSL* ssl, unsigned char* buf,
        unsigned int* sz)
{
    WOLFSSL_ENTER("wolfSSL_dtls_export_state_only");

    if (ssl == NULL || sz == NULL) {
        return BAD_FUNC_ARG;
    }

    if (buf == NULL) {
        *sz = MAX_EXPORT_STATE_BUFFER;
        return 0;
    }

    /* if not DTLS do nothing */
    if (!ssl->options.dtls) {
        WOLFSSL_MSG("Currently only DTLS export state is supported");
        return 0;
    }

    /* copy over keys, options, and dtls state struct */
    return wolfSSL_dtls_export_state_internal(ssl, buf, *sz);
}


/* returns 0 on success */
int wolfSSL_send_session(WOLFSSL* ssl)
{
    int ret;
    byte* buf;
    word32 bufSz = MAX_EXPORT_BUFFER;

    WOLFSSL_ENTER("wolfSSL_send_session");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    buf = (byte*)XMALLOC(bufSz, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return MEMORY_E;
    }

    /* if not DTLS do nothing */
    if (!ssl->options.dtls) {
        XFREE(buf, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WOLFSSL_MSG("Currently only DTLS export is supported");
        return 0;
    }

    /* copy over keys, options, and dtls state struct */
    ret = wolfSSL_session_export_internal(ssl, buf, &bufSz,
        WOLFSSL_EXPORT_DTLS);
    if (ret < 0) {
        XFREE(buf, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /* if no error ret has size of buffer */
    ret = ssl->dtls_export(ssl, buf, ret, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        XFREE(buf, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    XFREE(buf, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}
#endif /* WOLFSSL_DTLS */
#endif /* WOLFSSL_SESSION_EXPORT */

#ifdef OPENSSL_EXTRA

/* Copies the master secret over to out buffer. If outSz is 0 returns the size
 * of master secret.
 *
 * ses : a session from completed TLS/SSL handshake
 * out : buffer to hold copy of master secret
 * outSz : size of out buffer
 * returns : number of bytes copied into out buffer on success
 *           less then or equal to 0 is considered a failure case
 */
int wolfSSL_SESSION_get_master_key(const WOLFSSL_SESSION* ses,
        unsigned char* out, int outSz)
{
    int size;

    ses = ClientSessionToSession(ses);

    if (outSz == 0) {
        return SECRET_LEN;
    }

    if (ses == NULL || out == NULL || outSz < 0) {
        return 0;
    }

    if (outSz > SECRET_LEN) {
        size = SECRET_LEN;
    }
    else {
        size = outSz;
    }

    XMEMCPY(out, ses->masterSecret, size);
    return size;
}


int wolfSSL_SESSION_get_master_key_length(const WOLFSSL_SESSION* ses)
{
    (void)ses;
    return SECRET_LEN;
}

#ifdef WOLFSSL_EARLY_DATA
unsigned int wolfSSL_SESSION_get_max_early_data(const WOLFSSL_SESSION *session)
{
    return session->maxEarlyDataSz;
}
#endif /* WOLFSSL_EARLY_DATA */

#endif /* OPENSSL_EXTRA */

void SetupSession(WOLFSSL* ssl)
{
    WOLFSSL_SESSION* session = ssl->session;

    WOLFSSL_ENTER("SetupSession");

    if (!IsAtLeastTLSv1_3(ssl->version) && ssl->arrays != NULL) {
        /* Make sure the session ID is available when the user calls any
         * get_session API */
        if (!session->haveAltSessionID) {
            XMEMCPY(session->sessionID, ssl->arrays->sessionID, ID_LEN);
            session->sessionIDSz = ssl->arrays->sessionIDSz;
        }
        else {
            XMEMCPY(session->sessionID, session->altSessionID, ID_LEN);
            session->sessionIDSz = ID_LEN;
        }
    }
    session->side = (byte)ssl->options.side;
    if (!IsAtLeastTLSv1_3(ssl->version) && ssl->arrays != NULL)
        XMEMCPY(session->masterSecret, ssl->arrays->masterSecret, SECRET_LEN);
    session->haveEMS = ssl->options.haveEMS;
#ifdef WOLFSSL_SESSION_ID_CTX
    /* If using compatibility layer then check for and copy over session context
     * id. */
    if (ssl->sessionCtxSz > 0 && ssl->sessionCtxSz < ID_LEN) {
        XMEMCPY(ssl->session->sessionCtx, ssl->sessionCtx, ssl->sessionCtxSz);
        session->sessionCtxSz = ssl->sessionCtxSz;
    }
#endif
    session->timeout = ssl->timeout;
#ifndef NO_ASN_TIME
    session->bornOn  = LowResTimer();
#endif
#if defined(SESSION_CERTS) || (defined(WOLFSSL_TLS13) && \
                               defined(HAVE_SESSION_TICKET))
    session->version = ssl->version;
#endif
#if defined(SESSION_CERTS) || !defined(NO_RESUME_SUITE_CHECK) || \
                        (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET))
    session->cipherSuite0 = ssl->options.cipherSuite0;
    session->cipherSuite = ssl->options.cipherSuite;
#endif
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    session->peerVerifyRet = (byte)ssl->peerVerifyRet;
#endif
    session->isSetup = 1;
}

#ifdef WOLFSSL_SESSION_ID_CTX
    /* Storing app session context id, this value is inherited by WOLFSSL
     * objects created from WOLFSSL_CTX. Any session that is imported with a
     * different session context id will be rejected.
     *
     * ctx         structure to set context in
     * sid_ctx     value of context to set
     * sid_ctx_len length of sid_ctx buffer
     *
     * Returns WOLFSSL_SUCCESS in success case and WOLFSSL_FAILURE when failing
     */
    int wolfSSL_CTX_set_session_id_context(WOLFSSL_CTX* ctx,
                                           const unsigned char* sid_ctx,
                                           unsigned int sid_ctx_len)
    {
        WOLFSSL_ENTER("wolfSSL_CTX_set_session_id_context");

        /* No application specific context needed for wolfSSL */
        if (sid_ctx_len > ID_LEN || ctx == NULL || sid_ctx == NULL) {
            return WOLFSSL_FAILURE;
        }
        XMEMCPY(ctx->sessionCtx, sid_ctx, sid_ctx_len);
        ctx->sessionCtxSz = (byte)sid_ctx_len;

        return WOLFSSL_SUCCESS;
    }



    /* Storing app session context id. Any session that is imported with a
     * different session context id will be rejected.
     *
     * ssl  structure to set context in
     * id   value of context to set
     * len  length of sid_ctx buffer
     *
     * Returns WOLFSSL_SUCCESS in success case and WOLFSSL_FAILURE when failing
     */
    int wolfSSL_set_session_id_context(WOLFSSL* ssl, const unsigned char* id,
                                   unsigned int len)
    {
        WOLFSSL_ENTER("wolfSSL_set_session_id_context");

        if (len > ID_LEN || ssl == NULL || id == NULL) {
            return WOLFSSL_FAILURE;
        }
        XMEMCPY(ssl->sessionCtx, id, len);
        ssl->sessionCtxSz = (byte)len;

        return WOLFSSL_SUCCESS;
    }
#endif

/* return a new malloc'd session with default settings on success */
WOLFSSL_SESSION* wolfSSL_NewSession(void* heap)
{
    WOLFSSL_SESSION* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_NewSession");

    ret = (WOLFSSL_SESSION*)XMALLOC(sizeof(WOLFSSL_SESSION), heap,
            DYNAMIC_TYPE_SESSION);
    if (ret != NULL) {
        int err;
        XMEMSET(ret, 0, sizeof(WOLFSSL_SESSION));
        wolfSSL_RefInit(&ret->ref, &err);
    #ifdef WOLFSSL_REFCNT_ERROR_RETURN
        if (err != 0) {
            WOLFSSL_MSG("Error setting up session reference mutex");
            XFREE(ret, ret->heap, DYNAMIC_TYPE_SESSION);
            return NULL;
        }
    #else
        (void)err;
    #endif
#ifndef NO_SESSION_CACHE
        ret->cacheRow = INVALID_SESSION_ROW; /* not in cache */
#endif
        ret->type = WOLFSSL_SESSION_TYPE_HEAP;
        ret->heap = heap;
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SESSION master secret", ret->masterSecret, SECRET_LEN);
        wc_MemZero_Add("SESSION id", ret->sessionID, ID_LEN);
#endif
    #ifdef HAVE_SESSION_TICKET
        ret->ticket = ret->staticTicket;
        #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&  \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        ret->ticketNonce.data = ret->ticketNonce.dataStatic;
        #endif
    #endif
#ifdef HAVE_EX_DATA
        ret->ownExData = 1;
        if (crypto_ex_cb_ctx_session != NULL) {
            crypto_ex_cb_setup_new_data(ret, crypto_ex_cb_ctx_session,
                    &ret->ex_data);
        }
#endif
    }
    return ret;
}


WOLFSSL_SESSION* wolfSSL_SESSION_new_ex(void* heap)
{
    return wolfSSL_NewSession(heap);
}

WOLFSSL_SESSION* wolfSSL_SESSION_new(void)
{
    return wolfSSL_SESSION_new_ex(NULL);
}

/* add one to session reference count
 * return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on error */
int wolfSSL_SESSION_up_ref(WOLFSSL_SESSION* session)
{
    int ret;

    session = ClientSessionToSession(session);

    if (session == NULL || session->type != WOLFSSL_SESSION_TYPE_HEAP)
        return WOLFSSL_FAILURE;

    wolfSSL_RefInc(&session->ref, &ret);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    if (ret != 0) {
        WOLFSSL_MSG("Failed to lock session mutex");
        return WOLFSSL_FAILURE;
    }
#else
    (void)ret;
#endif

    return WOLFSSL_SUCCESS;
}

/**
 * Deep copy the contents from input to output.
 * @param input         The source of the copy.
 * @param output        The destination of the copy.
 * @param avoidSysCalls If true, then system calls will be avoided or an error
 *                      will be returned if it is not possible to proceed
 *                      without a system call. This is useful for fetching
 *                      sessions from cache. When a cache row is locked, we
 *                      don't want to block other threads with long running
 *                      system calls.
 * @param ticketNonceBuf If not null and @avoidSysCalls is true, the copy of the
 *                      ticketNonce will happen in this pre allocated buffer
 * @param ticketNonceLen @ticketNonceBuf len as input, used length on output
 * @param ticketNonceUsed if @ticketNonceBuf was used to copy the ticket noncet
 * @return              WOLFSSL_SUCCESS on success
 *                      WOLFSSL_FAILURE on failure
 */
static int wolfSSL_DupSessionEx(const WOLFSSL_SESSION* input,
    WOLFSSL_SESSION* output, int avoidSysCalls, byte* ticketNonceBuf,
    byte* ticketNonceLen, byte* preallocUsed)
{
#ifdef HAVE_SESSION_TICKET
    int   ticLenAlloc = 0;
    byte *ticBuff = NULL;
#endif
    const size_t copyOffset = OFFSETOF(WOLFSSL_SESSION, heap) +
        sizeof(input->heap);
    int ret = WOLFSSL_SUCCESS;

    (void)avoidSysCalls;
    (void)ticketNonceBuf;
    (void)ticketNonceLen;
    (void)preallocUsed;

    input = ClientSessionToSession(input);
    output = ClientSessionToSession(output);

    if (input == NULL || output == NULL || input == output) {
        WOLFSSL_MSG("input or output are null or same");
        return WOLFSSL_FAILURE;
    }

#ifdef HAVE_SESSION_TICKET
    if (output->ticket != output->staticTicket) {
        ticBuff = output->ticket;
        ticLenAlloc = output->ticketLenAlloc;
    }
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
        /* free the data, it would be better to reuse the buffer but this
         * maintain the code simpler. A smart allocator should reuse the free'd
         * buffer in the next malloc without much performance penalties. */
    if (output->ticketNonce.data != output->ticketNonce.dataStatic) {

        /*  Callers that avoid syscall should never calls this with
         * output->tickeNonce.data being a dynamic buffer.*/
        if (avoidSysCalls) {
            WOLFSSL_MSG("can't avoid syscalls with dynamic TicketNonce buffer");
            return WOLFSSL_FAILURE;
        }

        XFREE(output->ticketNonce.data,
            output->heap, DYNAMIC_TYPE_SESSION_TICK);
        output->ticketNonce.data = output->ticketNonce.dataStatic;
        output->ticketNonce.len = 0;
    }
#endif /* WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC && FIPS_VERSION_GE(5,3)*/
#endif /* HAVE_SESSION_TICKET */

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    if (output->peer != NULL) {
        if (avoidSysCalls) {
            WOLFSSL_MSG("Can't free cert when avoiding syscalls");
            return WOLFSSL_FAILURE;
        }
        wolfSSL_X509_free(output->peer);
        output->peer = NULL;
    }
#endif

    XMEMCPY((byte*)output + copyOffset, (byte*)input + copyOffset,
            sizeof(WOLFSSL_SESSION) - copyOffset);

#if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TLS13) &&                  \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                                    \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    /* fix pointer to static after the copy  */
    output->ticketNonce.data = output->ticketNonce.dataStatic;
#endif
    /* Set sane values for copy */
#ifndef NO_SESSION_CACHE
    if (output->type != WOLFSSL_SESSION_TYPE_CACHE)
        output->cacheRow = INVALID_SESSION_ROW;
#endif
#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    if (input->peer != NULL && input->peer->dynamicMemory) {
        if (wolfSSL_X509_up_ref(input->peer) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Can't increase peer cert ref count");
            output->peer = NULL;
        }
    }
    else if (!avoidSysCalls)
        output->peer = wolfSSL_X509_dup(input->peer);
    else
        /* output->peer is not that important to copy */
        output->peer = NULL;
#endif
#ifdef HAVE_SESSION_TICKET
    if (input->ticketLen > SESSION_TICKET_LEN) {
        /* Need dynamic buffer */
        if (ticBuff == NULL || ticLenAlloc < input->ticketLen) {
            /* allocate new one */
            byte* tmp;
            if (avoidSysCalls) {
                WOLFSSL_MSG("Failed to allocate memory for ticket when avoiding"
                        " syscalls");
                output->ticket = ticBuff;
                output->ticketLenAlloc = (word16) ticLenAlloc;
                output->ticketLen = 0;
                ret = WOLFSSL_FAILURE;
            }
            else {
#ifdef WOLFSSL_NO_REALLOC
                tmp = (byte*)XMALLOC(input->ticketLen,
                        output->heap, DYNAMIC_TYPE_SESSION_TICK);
                XFREE(ticBuff, output->heap, DYNAMIC_TYPE_SESSION_TICK);
                ticBuff = NULL;
#else
                tmp = (byte*)XREALLOC(ticBuff, input->ticketLen,
                        output->heap, DYNAMIC_TYPE_SESSION_TICK);
#endif /* WOLFSSL_NO_REALLOC */
                if (tmp == NULL) {
                    WOLFSSL_MSG("Failed to allocate memory for ticket");
#ifndef WOLFSSL_NO_REALLOC
                    XFREE(ticBuff, output->heap, DYNAMIC_TYPE_SESSION_TICK);
                    ticBuff = NULL;
#endif /* WOLFSSL_NO_REALLOC */
                    output->ticket = NULL;
                    output->ticketLen = 0;
                    output->ticketLenAlloc = 0;
                    ret = WOLFSSL_FAILURE;
                }
                else {
                    ticBuff = tmp;
                    ticLenAlloc = input->ticketLen;
                }
            }
        }
        if (ticBuff != NULL && ret == WOLFSSL_SUCCESS) {
            XMEMCPY(ticBuff, input->ticket, input->ticketLen);
            output->ticket = ticBuff;
            output->ticketLenAlloc = (word16) ticLenAlloc;
        }
    }
    else {
        /* Default ticket to non dynamic */
        if (avoidSysCalls) {
            /* Try to use ticBuf if available. Caller can later move it to
             * the static buffer. */
            if (ticBuff != NULL) {
                if (ticLenAlloc >= input->ticketLen) {
                    output->ticket = ticBuff;
                    output->ticketLenAlloc = ticLenAlloc;
                }
                else {
                    WOLFSSL_MSG("ticket dynamic buffer too small but we are "
                                "avoiding system calls");
                    ret = WOLFSSL_FAILURE;
                    output->ticket = ticBuff;
                    output->ticketLenAlloc = (word16) ticLenAlloc;
                    output->ticketLen = 0;
                }
            }
            else {
                output->ticket = output->staticTicket;
                output->ticketLenAlloc = 0;
            }
        }
        else {
            XFREE(ticBuff, output->heap, DYNAMIC_TYPE_SESSION_TICK);
            output->ticket = output->staticTicket;
            output->ticketLenAlloc = 0;
        }
        if (input->ticketLenAlloc > 0 && ret == WOLFSSL_SUCCESS) {
            /* Shouldn't happen as session should have placed this in
             * the static buffer */
            XMEMCPY(output->ticket, input->ticket,
                    input->ticketLen);
        }
    }
    ticBuff = NULL;

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    if (preallocUsed != NULL)
        *preallocUsed = 0;

    if (input->ticketNonce.len > MAX_TICKET_NONCE_STATIC_SZ &&
        ret == WOLFSSL_SUCCESS) {
        /* TicketNonce does not fit in the static buffer */
        if (!avoidSysCalls) {
            output->ticketNonce.data = (byte*)XMALLOC(input->ticketNonce.len,
                output->heap, DYNAMIC_TYPE_SESSION_TICK);

            if (output->ticketNonce.data == NULL) {
                WOLFSSL_MSG("Failed to allocate space for ticket nonce");
                output->ticketNonce.data = output->ticketNonce.dataStatic;
                output->ticketNonce.len = 0;
                ret = WOLFSSL_FAILURE;
            }
            else {
                output->ticketNonce.len = input->ticketNonce.len;
                XMEMCPY(output->ticketNonce.data, input->ticketNonce.data,
                    input->ticketNonce.len);
                ret = WOLFSSL_SUCCESS;
            }
        }
        /* we can't do syscalls. Use prealloc buffers if provided from the
         * caller. */
        else if (ticketNonceBuf != NULL &&
                 *ticketNonceLen >= input->ticketNonce.len) {
            XMEMCPY(ticketNonceBuf, input->ticketNonce.data,
                input->ticketNonce.len);
            *ticketNonceLen = input->ticketNonce.len;
            if (preallocUsed != NULL)
                *preallocUsed = 1;
            ret = WOLFSSL_SUCCESS;
        }
        else {
            WOLFSSL_MSG("TicketNonce bigger than static buffer, and we can't "
                        "do syscalls");
            ret = WOLFSSL_FAILURE;
        }
    }
#endif /* WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC && FIPS_VERSION_GE(5,3)*/

#endif /* HAVE_SESSION_TICKET */

#ifdef HAVE_EX_DATA
    if (input->type != WOLFSSL_SESSION_TYPE_CACHE &&
            output->type != WOLFSSL_SESSION_TYPE_CACHE) {
        /* Not called with cache as that passes ownership of ex_data */
        ret = crypto_ex_cb_dup_data(&input->ex_data, &output->ex_data,
                                    crypto_ex_cb_ctx_session);
    }
#endif

    return ret;
}

/**
 * Deep copy the contents from input to output.
 * @param input         The source of the copy.
 * @param output        The destination of the copy.
 * @param avoidSysCalls If true, then system calls will be avoided or an error
 *                      will be returned if it is not possible to proceed
 *                      without a system call. This is useful for fetching
 *                      sessions from cache. When a cache row is locked, we
 *                      don't want to block other threads with long running
 *                      system calls.
 * @return              WOLFSSL_SUCCESS on success
 *                      WOLFSSL_FAILURE on failure
 */
int wolfSSL_DupSession(const WOLFSSL_SESSION* input, WOLFSSL_SESSION* output,
        int avoidSysCalls)
{
    return wolfSSL_DupSessionEx(input, output, avoidSysCalls, NULL, NULL, NULL);
}

WOLFSSL_SESSION* wolfSSL_SESSION_dup(WOLFSSL_SESSION* session)
{
    WOLFSSL_SESSION* copy;

    WOLFSSL_ENTER("wolfSSL_SESSION_dup");

    session = ClientSessionToSession(session);
    if (session == NULL)
        return NULL;

#ifdef HAVE_SESSION_TICKET
    if (session->ticketLenAlloc > 0 && !session->ticket) {
        WOLFSSL_MSG("Session dynamic flag is set but ticket pointer is null");
        return NULL;
    }
#endif

    copy = wolfSSL_NewSession(session->heap);
    if (copy != NULL &&
            wolfSSL_DupSession(session, copy, 0) != WOLFSSL_SUCCESS) {
        wolfSSL_FreeSession(NULL, copy);
        copy = NULL;
    }
    return copy;
}

void wolfSSL_FreeSession(WOLFSSL_CTX* ctx, WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);
    if (session == NULL)
        return;

    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_FreeSession");

    if (session->ref.count > 0) {
        int ret;
        int isZero;
        wolfSSL_RefDec(&session->ref, &isZero, &ret);
        (void)ret;
        if (!isZero) {
            return;
        }
        wolfSSL_RefFree(&session->ref);
    }

    WOLFSSL_MSG("wolfSSL_FreeSession full free");

#ifdef HAVE_EX_DATA
    if (session->ownExData) {
        crypto_ex_cb_free_data(session, crypto_ex_cb_ctx_session,
                &session->ex_data);
    }
#endif

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
    wolfSSL_CRYPTO_cleanup_ex_data(&session->ex_data);
#endif

#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
    if (session->peer) {
        wolfSSL_X509_free(session->peer);
        session->peer = NULL;
    }
#endif

#ifdef HAVE_SESSION_TICKET
    if (session->ticketLenAlloc > 0) {
        XFREE(session->ticket, session->heap, DYNAMIC_TYPE_SESSION_TICK);
        session->ticket = session->staticTicket;
        session->ticketLen = 0;
        session->ticketLenAlloc = 0;
    }
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_TICKET_NONCE_MALLOC) &&          \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
    if (session->ticketNonce.data != session->ticketNonce.dataStatic) {
        XFREE(session->ticketNonce.data, session->heap,
            DYNAMIC_TYPE_SESSION_TICK);
        session->ticketNonce.data = session->ticketNonce.dataStatic;
        session->ticketNonce.len = 0;
    }
#endif /* WOLFSSL_TLS13 && WOLFSSL_TICKET_NONCE_MALLOC && FIPS_VERSION_GE(5,3)*/
#endif

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
    wolfSSL_CRYPTO_cleanup_ex_data(&session->ex_data);
#endif

    /* Make sure masterSecret is zeroed. */
    ForceZero(session->masterSecret, SECRET_LEN);
    /* Session ID is sensitive information too. */
    ForceZero(session->sessionID, ID_LEN);

    if (session->type == WOLFSSL_SESSION_TYPE_HEAP) {
        XFREE(session, session->heap, DYNAMIC_TYPE_SESSION);
    }
}

/* DO NOT use this API internally. Use wolfSSL_FreeSession directly instead
 * and pass in the ctx parameter if possible (like from ssl->ctx). */
void wolfSSL_SESSION_free(WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);
    wolfSSL_FreeSession(NULL, session);
}

#if defined(OPENSSL_EXTRA) || defined(HAVE_EXT_CACHE)

/**
* set cipher to WOLFSSL_SESSION from WOLFSSL_CIPHER
* @param session  a pointer to WOLFSSL_SESSION structure
* @param cipher   a function pointer to WOLFSSL_CIPHER
* @return WOLFSSL_SUCCESS on success, otherwise WOLFSSL_FAILURE
*/
int wolfSSL_SESSION_set_cipher(WOLFSSL_SESSION* session,
                                            const WOLFSSL_CIPHER* cipher)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_set_cipher");

    session = ClientSessionToSession(session);
    /* sanity check */
    if (session == NULL || cipher == NULL) {
        WOLFSSL_MSG("bad argument");
        return WOLFSSL_FAILURE;
    }
    session->cipherSuite0 = cipher->cipherSuite0;
    session->cipherSuite  = cipher->cipherSuite;

    WOLFSSL_LEAVE("wolfSSL_SESSION_set_cipher", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_EXTRA || HAVE_EXT_CACHE */

const char* wolfSSL_SESSION_CIPHER_get_name(const WOLFSSL_SESSION* session)
{
    session = ClientSessionToSession(session);
    if (session == NULL) {
        return NULL;
    }

#if defined(SESSION_CERTS) || !defined(NO_RESUME_SUITE_CHECK) || \
                        (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET))
    #if !defined(WOLFSSL_CIPHER_INTERNALNAME) && !defined(NO_ERROR_STRINGS)
        return GetCipherNameIana(session->cipherSuite0, session->cipherSuite);
    #else
        return GetCipherNameInternal(session->cipherSuite0,
            session->cipherSuite);
    #endif
#else
    return NULL;
#endif
}

#if defined(OPENSSL_ALL) || defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX)
const unsigned char *wolfSSL_SESSION_get0_id_context(
                      const WOLFSSL_SESSION *sess, unsigned int *sid_ctx_length)
{
    return wolfSSL_SESSION_get_id((WOLFSSL_SESSION *)sess, sid_ctx_length);
}
int wolfSSL_SESSION_set1_id(WOLFSSL_SESSION *s,
                                 const unsigned char *sid, unsigned int sid_len)
{
    if (s == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (sid_len > ID_LEN) {
        return WOLFSSL_FAILURE;
    }
    s->sessionIDSz = sid_len;
    if (sid != s->sessionID) {
        XMEMCPY(s->sessionID, sid, sid_len);
    }
    return WOLFSSL_SUCCESS;
}

int wolfSSL_SESSION_set1_id_context(WOLFSSL_SESSION *s,
                         const unsigned char *sid_ctx, unsigned int sid_ctx_len)
{
    if (s == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (sid_ctx_len > ID_LEN) {
        return WOLFSSL_FAILURE;
    }
    s->sessionCtxSz = sid_ctx_len;
    if (sid_ctx != s->sessionCtx) {
        XMEMCPY(s->sessionCtx, sid_ctx, sid_ctx_len);
    }

    return WOLFSSL_SUCCESS;
}

#endif

#ifdef OPENSSL_EXTRA

/* Return the total number of sessions */
long wolfSSL_CTX_sess_number(WOLFSSL_CTX* ctx)
{
    word32 total = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_sess_number");
    (void)ctx;

#if defined(WOLFSSL_SESSION_STATS) && !defined(NO_SESSION_CACHE)
    if (wolfSSL_get_session_stats(NULL, &total, NULL, NULL) !=
            WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error getting session stats");
    }
#else
    WOLFSSL_MSG("Please use macro WOLFSSL_SESSION_STATS for session stats");
#endif

    return (long)total;
}

#endif

#ifdef SESSION_CERTS

/* get session ID */
WOLFSSL_ABI
const byte* wolfSSL_get_sessionID(const WOLFSSL_SESSION* session)
{
    WOLFSSL_ENTER("wolfSSL_get_sessionID");
    session = ClientSessionToSession(session);
    if (session)
        return session->sessionID;

    return NULL;
}

#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL) || \
    defined(HAVE_EX_DATA)

int wolfSSL_SESSION_set_ex_data(WOLFSSL_SESSION* session, int idx, void* data)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("wolfSSL_SESSION_set_ex_data");
#ifdef HAVE_EX_DATA
    session = ClientSessionToSession(session);
    if (session != NULL) {
#ifndef NO_SESSION_CACHE
        if (!session->ownExData) {
            /* Need to update in cache */
            SESSION_ex_data_cache_update(session, idx, data, 0, NULL, &ret);
        }
        else
#endif
        {
            ret = wolfSSL_CRYPTO_set_ex_data(&session->ex_data, idx, data);
        }
    }
#else
    (void)session;
    (void)idx;
    (void)data;
#endif
    return ret;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
int wolfSSL_SESSION_set_ex_data_with_cleanup(
    WOLFSSL_SESSION* session,
    int idx,
    void* data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_set_ex_data_with_cleanup");
    session = ClientSessionToSession(session);
    if(session != NULL) {
        return wolfSSL_CRYPTO_set_ex_data_with_cleanup(&session->ex_data, idx,
                                                       data, cleanup_routine);
    }
    return WOLFSSL_FAILURE;
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

void* wolfSSL_SESSION_get_ex_data(const WOLFSSL_SESSION* session, int idx)
{
    void* ret = NULL;
    WOLFSSL_ENTER("wolfSSL_SESSION_get_ex_data");
#ifdef HAVE_EX_DATA
    session = ClientSessionToSession(session);
    if (session != NULL) {
#ifndef NO_SESSION_CACHE
        if (!session->ownExData) {
            /* Need to retrieve the data from the session cache */
            SESSION_ex_data_cache_update((WOLFSSL_SESSION*)session, idx, NULL,
                                         1, &ret, NULL);
        }
        else
#endif
        {
            ret = wolfSSL_CRYPTO_get_ex_data(&session->ex_data, idx);
        }
    }
#else
    (void)session;
    (void)idx;
#endif
    return ret;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL || HAVE_EX_DATA */

#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)))
#ifdef HAVE_EX_DATA
int wolfSSL_SESSION_get_ex_new_index(long ctx_l,void* ctx_ptr,
        WOLFSSL_CRYPTO_EX_new* new_func, WOLFSSL_CRYPTO_EX_dup* dup_func,
        WOLFSSL_CRYPTO_EX_free* free_func)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_get_ex_new_index");
    return wolfssl_get_ex_new_index(WOLF_CRYPTO_EX_INDEX_SSL_SESSION, ctx_l,
            ctx_ptr, new_func, dup_func, free_func);
}
#endif
#endif


#if defined(OPENSSL_ALL) || \
    defined(OPENSSL_EXTRA) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)

const byte* wolfSSL_SESSION_get_id(const WOLFSSL_SESSION* sess,
        unsigned int* idLen)
{
    WOLFSSL_ENTER("wolfSSL_SESSION_get_id");
    sess = ClientSessionToSession(sess);
    if (sess == NULL || idLen == NULL) {
        WOLFSSL_MSG("Bad func args. Please provide idLen");
        return NULL;
    }
#ifdef HAVE_SESSION_TICKET
    if (sess->haveAltSessionID) {
        *idLen = ID_LEN;
        return sess->altSessionID;
    }
#endif
    *idLen = sess->sessionIDSz;
    return sess->sessionID;
}

#if (defined(HAVE_SESSION_TICKET) || defined(SESSION_CERTS)) && \
    !defined(NO_FILESYSTEM)

#ifndef NO_BIO

#if defined(SESSION_CERTS) || \
   (defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET))
static const char* wolfSSL_internal_get_version(const ProtocolVersion* version);

/* returns a pointer to the protocol used by the session */
static const char* wolfSSL_SESSION_get_protocol(const WOLFSSL_SESSION* in)
{
    in = ClientSessionToSession(in);
    return wolfSSL_internal_get_version((ProtocolVersion*)&in->version);
}
#endif

/* returns true (non 0) if the session has EMS (extended master secret) */
static int wolfSSL_SESSION_haveEMS(const WOLFSSL_SESSION* in)
{
    in = ClientSessionToSession(in);
    if (in == NULL)
        return 0;
    return in->haveEMS;
}

#if defined(HAVE_SESSION_TICKET)
/* prints out the ticket to bio passed in
 * return WOLFSSL_SUCCESS on success
 */
static int wolfSSL_SESSION_print_ticket(WOLFSSL_BIO* bio,
        const WOLFSSL_SESSION* in, const char* tab)
{
    unsigned short i, j, z, sz;
    short tag = 0;
    byte* pt;


    in = ClientSessionToSession(in);
    if (in == NULL || bio == NULL) {
        return BAD_FUNC_ARG;
    }

    sz = in->ticketLen;
    pt = in->ticket;

    if (wolfSSL_BIO_printf(bio, "%s\n", (sz == 0)? " NONE": "") <= 0)
        return WOLFSSL_FAILURE;

    for (i = 0; i < sz;) {
        char asc[16];
        XMEMSET(asc, 0, sizeof(asc));

        if (sz - i < 16) {
            if (wolfSSL_BIO_printf(bio, "%s%04X -", tab, tag + (sz - i)) <= 0)
                return WOLFSSL_FAILURE;
        }
        else {
            if (wolfSSL_BIO_printf(bio, "%s%04X -", tab, tag) <= 0)
                return WOLFSSL_FAILURE;
        }
        for (j = 0; i < sz && j < 8; j++,i++) {
            asc[j] =  ((pt[i])&0x6f)>='A'?((pt[i])&0x6f):'.';
            if (wolfSSL_BIO_printf(bio, " %02X", pt[i]) <= 0)
                return WOLFSSL_FAILURE;
        }

        if (i < sz) {
            asc[j] =  ((pt[i])&0x6f)>='A'?((pt[i])&0x6f):'.';
            if (wolfSSL_BIO_printf(bio, "-%02X", pt[i]) <= 0)
                return WOLFSSL_FAILURE;
            j++;
            i++;
        }

        for (; i < sz && j < 16; j++,i++) {
            asc[j] =  ((pt[i])&0x6f)>='A'?((pt[i])&0x6f):'.';
            if (wolfSSL_BIO_printf(bio, " %02X", pt[i]) <= 0)
                return WOLFSSL_FAILURE;
        }

        /* pad out spacing */
        for (z = j; z < 17; z++) {
            if (wolfSSL_BIO_printf(bio, "   ") <= 0)
                return WOLFSSL_FAILURE;
        }

        for (z = 0; z < j; z++) {
            if (wolfSSL_BIO_printf(bio, "%c", asc[z]) <= 0)
                return WOLFSSL_FAILURE;
        }
        if (wolfSSL_BIO_printf(bio, "\n") <= 0)
            return WOLFSSL_FAILURE;

        tag += 16;
    }
    return WOLFSSL_SUCCESS;
}
#endif /* HAVE_SESSION_TICKET */


/* prints out the session information in human readable form
 * return WOLFSSL_SUCCESS on success
 */
int wolfSSL_SESSION_print(WOLFSSL_BIO *bp, const WOLFSSL_SESSION *session)
{
    const unsigned char* pt;
    unsigned char buf[SECRET_LEN];
    unsigned int sz = 0, i;
    int ret;

    session = ClientSessionToSession(session);
    if (session == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (wolfSSL_BIO_printf(bp, "%s\n", "SSL-Session:") <= 0)
        return WOLFSSL_FAILURE;

#if defined(SESSION_CERTS) || (defined(WOLFSSL_TLS13) && \
                               defined(HAVE_SESSION_TICKET))
    if (wolfSSL_BIO_printf(bp, "    Protocol  : %s\n",
            wolfSSL_SESSION_get_protocol(session)) <= 0)
        return WOLFSSL_FAILURE;
#endif

    if (wolfSSL_BIO_printf(bp, "    Cipher    : %s\n",
            wolfSSL_SESSION_CIPHER_get_name(session)) <= 0)
        return WOLFSSL_FAILURE;

    pt = wolfSSL_SESSION_get_id(session, &sz);
    if (wolfSSL_BIO_printf(bp, "    Session-ID: ") <= 0)
        return WOLFSSL_FAILURE;

    for (i = 0; i < sz; i++) {
        if (wolfSSL_BIO_printf(bp, "%02X", pt[i]) <= 0)
            return WOLFSSL_FAILURE;
    }
    if (wolfSSL_BIO_printf(bp, "\n") <= 0)
        return WOLFSSL_FAILURE;

    if (wolfSSL_BIO_printf(bp, "    Session-ID-ctx: \n") <= 0)
        return WOLFSSL_FAILURE;

    ret = wolfSSL_SESSION_get_master_key(session, buf, sizeof(buf));
    if (wolfSSL_BIO_printf(bp, "    Master-Key: ") <= 0)
        return WOLFSSL_FAILURE;

    if (ret > 0) {
        sz = (unsigned int)ret;
        for (i = 0; i < sz; i++) {
            if (wolfSSL_BIO_printf(bp, "%02X", buf[i]) <= 0)
                return WOLFSSL_FAILURE;
        }
    }
    if (wolfSSL_BIO_printf(bp, "\n") <= 0)
        return WOLFSSL_FAILURE;

    /* @TODO PSK identity hint and SRP */

    if (wolfSSL_BIO_printf(bp, "    TLS session ticket:") <= 0)
        return WOLFSSL_FAILURE;

#ifdef HAVE_SESSION_TICKET
    if (wolfSSL_SESSION_print_ticket(bp, session, "    ") != WOLFSSL_SUCCESS)
        return WOLFSSL_FAILURE;
#endif

#if !defined(NO_SESSION_CACHE) && (defined(OPENSSL_EXTRA) || \
        defined(HAVE_EXT_CACHE))
    if (wolfSSL_BIO_printf(bp, "    Start Time: %ld\n",
                wolfSSL_SESSION_get_time(session)) <= 0)
        return WOLFSSL_FAILURE;

    if (wolfSSL_BIO_printf(bp, "    Timeout   : %ld (sec)\n",
            wolfSSL_SESSION_get_timeout(session)) <= 0)
        return WOLFSSL_FAILURE;
#endif /* !NO_SESSION_CACHE && OPENSSL_EXTRA || HAVE_EXT_CACHE */

    /* @TODO verify return code print */

    if (wolfSSL_BIO_printf(bp, "    Extended master secret: %s\n",
            (wolfSSL_SESSION_haveEMS(session) == 0)? "no" : "yes") <= 0)
        return WOLFSSL_FAILURE;

    return WOLFSSL_SUCCESS;
}

#endif /* !NO_BIO */
#endif /* (HAVE_SESSION_TICKET || SESSION_CERTS) && !NO_FILESYSTEM */

#endif /* OPENSSL_ALL || OPENSSL_EXTRA || HAVE_STUNNEL || WOLFSSL_NGINX ||
        * WOLFSSL_HAPROXY */

#ifdef OPENSSL_EXTRA
/**
 * Determine whether a WOLFSSL_SESSION object can be used for resumption
 * @param s  a pointer to WOLFSSL_SESSION structure
 * @return return 1 if session is resumable, otherwise 0.
 */
int wolfSSL_SESSION_is_resumable(const WOLFSSL_SESSION *s)
{
    s = ClientSessionToSession(s);
    if (s == NULL)
        return 0;

#ifdef HAVE_SESSION_TICKET
    if (s->ticketLen > 0)
        return 1;
#endif

    if (s->sessionIDSz > 0)
        return 1;

    return 0;
}
#endif /* OPENSSL_EXTRA */

#endif /* !WOLFSSL_SSL_SESS_INCLUDED */

