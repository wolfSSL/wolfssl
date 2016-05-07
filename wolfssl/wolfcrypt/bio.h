#ifndef WOLF_CRYPT_BIO_H
#define WOLF_CRYPT_BIO_H

#include <stdio.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/compat-wolfssl.h>

#ifdef OPENSSL_EXTRA

#ifdef __cplusplus
extern "C" {
#endif

/* BIO types */
enum WS_BIO_TYPE {
    BIO_TYPE_NONE =         0,

    BIO_TYPE_SSL =          1,
    BIO_TYPE_MD =           2, /* passive */
    BIO_TYPE_BUFFER =       3,
    BIO_TYPE_CIPHER =       4,
    BIO_TYPE_BASE64 =       5,
    BIO_TYPE_LINEBUFFER =   6,
    BIO_TYPE_ASN1 =         7,
    BIO_TYPE_COMP =         8,
    BIO_TYPE_PROXY_CLIENT = 9,  /* client proxy BIO */
    BIO_TYPE_PROXY_SERVER = 10, /* server proxy BIO */
    BIO_TYPE_NULL_FILTER =  11,
    BIO_TYPE_BER =          12, /* BER -> bin filter */

    BIO_TYPE_MEM =          13,
    BIO_TYPE_FILE =         14,
    BIO_TYPE_NULL =         15,
    BIO_TYPE_BIO =          16, /* (half a) BIO pair */

    /* socket, fd, connect or accept */
    BIO_TYPE_DESCRIPTOR =   0x100,

    BIO_TYPE_FD =           17|BIO_TYPE_DESCRIPTOR,
    BIO_TYPE_SOCKET =       18|BIO_TYPE_DESCRIPTOR,
    /* socket - connect */
    BIO_TYPE_CONNECT =      19|BIO_TYPE_DESCRIPTOR,
    /* socket for accept */
    BIO_TYPE_ACCEPT =       20|BIO_TYPE_DESCRIPTOR,
    BIO_TYPE_DGRAM  =       21|BIO_TYPE_DESCRIPTOR,
};

/*
 * BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
 * BIO_set_fp(in,stdin,BIO_NOCLOSE);
 */
#define BIO_CLOSE 1
#define BIO_NOCLOSE 0

/*
 * These are used in the following macros and are passed to BIO_ctrl()
 */
enum WS_BIO_CTRL {
    BIO_CTRL_RESET =         1, /* opt - rewind/zero etc */
    BIO_CTRL_EOF =           2, /* opt - are we at the eof */
    BIO_CTRL_INFO =          3, /* opt - extra tit-bits */
    BIO_CTRL_SET =           4, /* man - set the 'IO' type */
    BIO_CTRL_GET =           5, /* man - get the 'IO' type */
    BIO_CTRL_PUSH =          6, /* opt - internal, used to signify change */
    BIO_CTRL_POP =           7, /* opt - internal, used to signify change */
    BIO_CTRL_GET_CLOSE =     8, /* man - set the 'close' on free */
    BIO_CTRL_SET_CLOSE =     9, /* man - set the 'close' on free */
    BIO_CTRL_PENDING =       10, /* opt - is their more data buffered */
    BIO_CTRL_FLUSH =         11, /* opt - 'flush' buffered output */
    BIO_CTRL_DUP =           12, /* man - extra stuff for 'duped' BIO */
    BIO_CTRL_WPENDING =      13, /* opt - number of bytes still to write */

    /* callback is int cb(BIO *bio,state,ret); */
    BIO_CTRL_SET_CALLBACK =  14, /* opt - set callback function */
    BIO_CTRL_GET_CALLBACK =  15, /* opt - set callback function */

    BIO_CTRL_SET_FILENAME =  30, /* BIO_s_file special */

    /* dgram BIO stuff */
    BIO_CTRL_DGRAM_CONNECT =      31, /* BIO dgram special */
    BIO_CTRL_DGRAM_SET_CONNECTED = 32, /* allow for an externally connected
                                        * socket to be passed in */
    BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33, /* setsockopt, essentially */
    BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34, /* getsockopt, essentially */
    BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35, /* setsockopt, essentially */
    BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36, /* getsockopt, essentially */

    BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37, /* flag whether the last */
    BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38, /* I/O operation tiemd out */

    /* #ifdef IP_MTU_DISCOVER */
    BIO_CTRL_DGRAM_MTU_DISCOVER =      39, /* set DF bit on egress packets */
    /* #endif */

    BIO_CTRL_DGRAM_QUERY_MTU =         40, /* as kernel for current MTU */
    BIO_CTRL_DGRAM_GET_FALLBACK_MTU =  47,
    BIO_CTRL_DGRAM_GET_MTU =           41, /* get cached value for MTU */
    BIO_CTRL_DGRAM_SET_MTU =           42, /* set cached value for MTU.
                                            * want to use this if asking
                                            * the kernel fails */
    BIO_CTRL_DGRAM_MTU_EXCEEDED =      43, /* check whether the MTU was
                                            * exceed in the previous write
                                            * operation */
    BIO_CTRL_DGRAM_GET_PEER =          46,
    BIO_CTRL_DGRAM_SET_PEER =          44, /* Destination for the data */

    BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT =  45, /* Next DTLS handshake timeout
                                            * to adjust socket timeouts */
    BIO_CTRL_DGRAM_SET_DONT_FRAG =     48,
    BIO_CTRL_DGRAM_GET_MTU_OVERHEAD =  49,
};

/* modifiers */
enum WS_BIO_MOD {
    BIO_FP_READ =            0x02,
    BIO_FP_WRITE =           0x04,
    BIO_FP_APPEND =          0x08,
    BIO_FP_TEXT =            0x10,
};


/* flags */
enum WS_BIO_FLAGS {
    BIO_FLAGS_READ =         0x01,
    BIO_FLAGS_WRITE =        0x02,
    BIO_FLAGS_IO_SPECIAL =   0x04,
    BIO_FLAGS_RWS =          BIO_FLAGS_READ|
    BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL,
    BIO_FLAGS_SHOULD_RETRY = 0x08,
    BIO_FLAGS_BASE64_NO_NL = 0x100,
    /* Used with memory BIOs: shouldn't free up or change the data in any way.
     */
    BIO_FLAGS_MEM_RDONLY =   0x200,
};

enum WS_BIO_RR {
/* Returned from the SSL bio when the certificate retrieval code had an error */
    BIO_RR_SSL_X509_LOOKUP =    0x01,
/* Returned from the connect BIO when a connect would have blocked */
    BIO_RR_CONNECT =            0x02,
/* Returned from the accept BIO when an accept would have blocked */
    BIO_RR_ACCEPT =             0x03,
};

/* These are passed by the BIO callback */
enum WS_BIO_CB_FLAGS {
    BIO_CB_FREE =    0x01,
    BIO_CB_READ =    0x02,
    BIO_CB_WRITE =   0x03,
    BIO_CB_PUTS =    0x04,
    BIO_CB_GETS =    0x05,
    BIO_CB_CTRL =    0x06,
    BIO_CB_RETURN =  0x80,
};

#define BIO_CB_return(a) ((a) | BIO_CB_RETURN)
#define BIO_cb_post(a)   ((a) & BIO_CB_RETURN)
#define BIO_cb_pre(a)    (!BIO_cb_post((a)))


typedef struct WOLFCRYPT_BIO         WOLFCRYPT_BIO;
typedef struct WOLFCRYPT_BIO_METHOD  WOLFCRYPT_BIO_METHOD;

typedef void WOLFCRYPT_BIO_info_cb (WOLFCRYPT_BIO *, int, const char *,
                                  int, long, long);

/* wolfSSL BIO_METHOD type */
struct WOLFCRYPT_BIO_METHOD {
    int type;               /* method type */
    const char *name;
    int (*bwrite) (WOLFCRYPT_BIO *, const char *, int);
    int (*bread)  (WOLFCRYPT_BIO *, char *, int);
    int (*bputs)  (WOLFCRYPT_BIO *, const char *);
    int (*bgets)  (WOLFCRYPT_BIO *, char *, int);
    long (*ctrl)  (WOLFCRYPT_BIO *, int, long, void *);
    int (*create) (WOLFCRYPT_BIO *);
    int (*destroy) (WOLFCRYPT_BIO *);
    long (*callback_ctrl) (WOLFCRYPT_BIO *, int, WOLFCRYPT_BIO_info_cb *);
};

struct WOLFCRYPT_BIO {
    WOLFCRYPT_BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    long (*callback) (WOLFCRYPT_BIO *, int, const char *, int, long, long);
    char *cb_arg;               /* first argument for the callback */
    int init;
    int shutdown;
    int flags;                  /* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    WOLFCRYPT_BIO *next_bio;    /* used by filter BIOs */
    WOLFCRYPT_BIO *prev_bio;    /* used by filter BIOs */
    int references;
    wolfSSL_Mutex refMutex; /* to lock r/w on references */
    unsigned long num_read;
    unsigned long num_write;
};

enum WS_BIO_C_FLAGS {
    BIO_C_SET_CONNECT =                  100,
    BIO_C_DO_STATE_MACHINE =             101,
    BIO_C_SET_NBIO =                     102,
    BIO_C_SET_PROXY_PARAM =              103,
    BIO_C_SET_FD =                       104,
    BIO_C_GET_FD =                       105,
    BIO_C_SET_FILE_PTR =                 106,
    BIO_C_GET_FILE_PTR =                 107,
    BIO_C_SET_FILENAME =                 108,
    BIO_C_SET_SSL =                      109,
    BIO_C_GET_SSL =                      110,
    BIO_C_SET_MD =                       111,
    BIO_C_GET_MD =                       112,
    BIO_C_GET_CIPHER_STATUS =            113,
    BIO_C_SET_BUF_MEM =                  114,
    BIO_C_GET_BUF_MEM_PTR =              115,
    BIO_C_GET_BUFF_NUM_LINES =           116,
    BIO_C_SET_BUFF_SIZE =                117,
    BIO_C_SET_ACCEPT =                   118,
    BIO_C_SSL_MODE =                     119,
    BIO_C_GET_MD_CTX =                   120,
    BIO_C_GET_PROXY_PARAM =              121,
    BIO_C_SET_BUFF_READ_DATA =           122, /* data to read first */
    BIO_C_GET_CONNECT =                  123,
    BIO_C_GET_ACCEPT =                   124,
    BIO_C_SET_SSL_RENEGOTIATE_BYTES =    125,
    BIO_C_GET_SSL_NUM_RENEGOTIATES =     126,
    BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT =  127,
    BIO_C_FILE_SEEK =                    128,
    BIO_C_GET_CIPHER_CTX =               129,
    BIO_C_SET_BUF_MEM_EOF_RETURN =       130, /* return end of input
                                               * value */
    BIO_C_SET_BIND_MODE =                131,
    BIO_C_GET_BIND_MODE =                132,
    BIO_C_FILE_TELL =                    133,
    BIO_C_GET_SOCKS =                    134,
    BIO_C_SET_SOCKS =                    135,

    BIO_C_SET_WRITE_BUF_SIZE =           136, /* for BIO_s_bio */
    BIO_C_GET_WRITE_BUF_SIZE =           137,
    BIO_C_MAKE_BIO_PAIR =                138,
    BIO_C_DESTROY_BIO_PAIR =             139,
    BIO_C_GET_WRITE_GUARANTEE =          140,
    BIO_C_GET_READ_REQUEST =             141,
    BIO_C_SHUTDOWN_WR =                  142,
    BIO_C_NREAD0 =                       143,
    BIO_C_NREAD =                        144,
    BIO_C_NWRITE0 =                      145,
    BIO_C_NWRITE =                       146,
    BIO_C_RESET_READ_REQUEST =           147,
    BIO_C_SET_MD_CTX =                   148,

    BIO_C_SET_PREFIX =                   149,
    BIO_C_GET_PREFIX =                   150,
    BIO_C_SET_SUFFIX =                   151,
    BIO_C_GET_SUFFIX =                   152,

    BIO_C_SET_EX_ARG =                   153,
    BIO_C_GET_EX_ARG =                   154,
};

/* connect BIO */
enum WS_BIO_CONN {
    BIO_CONN_S_BEFORE =             1,
    BIO_CONN_S_GET_IP =             2,
    BIO_CONN_S_GET_PORT =           3,
    BIO_CONN_S_CREATE_SOCKET =      4,
    BIO_CONN_S_CONNECT =            5,
    BIO_CONN_S_OK =                 6,
    BIO_CONN_S_BLOCKED_CONNECT =    7,
    BIO_CONN_S_NBIO =               8,
};

enum WS_BIO_BIND {
    BIO_BIND_NORMAL =               0,
    BIO_BIND_REUSEADDR_IF_UNUSED =  1,
    BIO_BIND_REUSEADDR =            2,
};

WOLFSSL_API WOLFCRYPT_BIO *wc_BioNew(WOLFCRYPT_BIO_METHOD *method);
WOLFSSL_API int wc_BioFree(WOLFCRYPT_BIO *bio);
WOLFSSL_API void wc_BioFreeAll(WOLFCRYPT_BIO *bio);

WOLFSSL_API const char *wc_BioMethodName(const WOLFCRYPT_BIO *bio);
WOLFSSL_API int wc_BioMethodType(const WOLFCRYPT_BIO *bio);

WOLFSSL_API int wc_BioSet(WOLFCRYPT_BIO *bio,
                                 WOLFCRYPT_BIO_METHOD *method);
WOLFSSL_API void wc_BioClearFlags(WOLFCRYPT_BIO *bio, int flags);
WOLFSSL_API void wc_BioSetFlags(WOLFCRYPT_BIO *bio, int flags);
WOLFSSL_API int wc_BioTestFlags(const WOLFCRYPT_BIO *bio, int flags);

#define wc_BioGetFlags(bio) wc_BioTestFlags(bio, ~(0x0))
#define wc_BioSetRetrySpecial(bio) \
    wc_BioSetFlags(bio, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
#define wc_BioSetRetryRead(bio) \
    wc_BioSetFlags(bio, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
#define wc_BioSetRetryWrite(bio) \
    wc_BioSetFlags(bio, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))


#define wc_BioClearRetryFlags(bio) \
    wc_BioClearFlags(bio, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
#define wc_BioGetRetryFlags(bio) \
    wc_BioTestFlags(bio, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))

/* These should be used by the application to tell why we should retry */
#define wc_BioShouldRead(bio)      wc_BioTestFlags(bio, BIO_FLAGS_READ)
#define wc_BioShouldWrite(bio)     wc_BioTestFlags(bio, BIO_FLAGS_WRITE)
#define wc_BioShouldIoSpecial(bio) wc_BioTestFlags(bio, BIO_FLAGS_IO_SPECIAL)
#define wc_BioRetryType(bio)       wc_BioTestFlags(bio, BIO_FLAGS_RWS)
#define wc_BioShouldRetry(bio)     wc_BioTestFlags(bio, BIO_FLAGS_SHOULD_RETRY)

WOLFSSL_API long (*wc_BioGetCallback(const WOLFCRYPT_BIO *bio))
                    (WOLFCRYPT_BIO *, int, const char *, int, long, long);

WOLFSSL_API void wc_BioSetCallback(WOLFCRYPT_BIO *bio,
                                          long (*cb) (WOLFCRYPT_BIO *, int,
                                          const char *, int, long, long));
WOLFSSL_API void wc_BioSetCallbackArg(WOLFCRYPT_BIO *bio, char *arg);
WOLFSSL_API char *wc_BioGetCallbackArg(const WOLFCRYPT_BIO *bio);

WOLFSSL_API int wc_BioRead(WOLFCRYPT_BIO *bio, void *out, int outl);
WOLFSSL_API int wc_BioWrite(WOLFCRYPT_BIO *bio, const void *in, int inl);
WOLFSSL_API int wc_BioPuts(WOLFCRYPT_BIO *bio, const char *in);
WOLFSSL_API int wc_BioGets(WOLFCRYPT_BIO *bio, char *in, int inl);

WOLFSSL_API WOLFCRYPT_BIO *wc_BioPush(WOLFCRYPT_BIO *top,
                                             WOLFCRYPT_BIO *next);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioPop(WOLFCRYPT_BIO *bio);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNext(WOLFCRYPT_BIO *bio);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioGetRetryBio(WOLFCRYPT_BIO *bio,
                                                   int *reason);
WOLFSSL_API int wc_BioGetRetryReason(WOLFCRYPT_BIO *bio);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioFindType(WOLFCRYPT_BIO *bio, int type);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioDupChain(WOLFCRYPT_BIO *bio);
#define wc_BioDupState(bio, ret) \
    wc_BioCtrl(bio, BIO_CTRL_DUP, 0, ret)

WOLFSSL_API long wc_BioCtrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long larg, void *parg);
WOLFSSL_API long wc_BioCallbackCtrl(WOLFCRYPT_BIO *bio, int cmd,
                                           void (*fp) (WOLFCRYPT_BIO *, int,
                                           const char *, int, long, long));
WOLFSSL_API long wc_BioIntCtrl(WOLFCRYPT_BIO *bio, int cmd,
                                      long larg, int iarg);
WOLFSSL_API char *wc_BioPtrCtrl(WOLFCRYPT_BIO *bio, int cmd, long larg);
WOLFSSL_API size_t wc_BioCtrlPending(WOLFCRYPT_BIO *bio);
WOLFSSL_API size_t wc_BioCtrlWpending(WOLFCRYPT_BIO *bio);

WOLFSSL_API int wc_BioIndent(WOLFCRYPT_BIO *bio, int indent, int max);

WOLFSSL_API unsigned long wc_BioNumberRead(WOLFCRYPT_BIO *bio);
WOLFSSL_API unsigned long wc_BioNumberWritten(WOLFCRYPT_BIO *bio);

#define wc_BioReset(bio) \
    (int)wc_BioCtrl(bio, BIO_CTRL_RESET, 0, NULL)
#define wc_BioEof(bio) \
    (int)wc_BioCtrl(bio, BIO_CTRL_EOF, 0, NULL)
#define wc_BioSetClose(bio,c) \
    (int)wc_BioCtrl(bio, BIO_CTRL_SET_CLOSE, (c), NULL)
#define wc_BioGetClose(bio) \
    (int)wc_BioCtrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL)
#define wc_BioPending(bio) \
    (int)wc_BioCtrl(bio, BIO_CTRL_PENDING, 0, NULL)
#define wc_BioWpending(bio) \
    (int)wc_BioCtrl(bio, BIO_CTRL_WPENDING, 0, NULL)
#define wc_BioFlush(bio) \
    (int)wc_BioCtrl(bio, BIO_CTRL_FLUSH, 0, NULL)
#define wc_BioSetInfoCallback(bio, cb) \
    (int)wc_BioCallbackCtrl(bio, BIO_CTRL_SET_CALLBACK, cb)
#define wc_BioGetInfoCallback(bio, cb) \
    (int)wc_BioCallbackCtrl(bio, BIO_CTRL_GET_CALLBACK, 0, cb)

WOLFSSL_API void wc_BioCopyNextRetry(WOLFCRYPT_BIO *b);

WOLFSSL_API int wc_BioPrintf(WOLFCRYPT_BIO *bio, const char *format, ...);

/* BIO file */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_file(void);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewFp(XFILE f, int close_flag);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewFile(const char *name,
                                                const char *mode);
#define wc_BioSetFp(bio, f, c) \
    wc_BioCtrl(bio, BIO_C_SET_FILE_PTR, c, (char *)f)
#define wc_BioGetFp(bio, f) \
    wc_BioCtrl(bio, BIO_C_GET_FILE_PTR, 0, (char *)f)
#define wc_BioSeek(bio, ofs) \
    (int)wc_BioCtrl(bio, BIO_C_FILE_SEEK, ofs, NULL)
#define wc_BioTell(bio) \
    (int)wc_BioCtrl(bio, BIO_C_FILE_TELL, 0, NULL)
#define wc_BioReadFilename(bio, name) \
    wc_BioCtrl(bio, BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_READ, name)
#define wc_BioWriteFilename(bio, name) \
    wc_BioCtrl(bio,BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_WRITE, name)
#define wc_BioAppendFilename(bio, name) \
    wc_BioCtrl(bio, BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_APPEND, name)
#define wc_BioRwFilename(bio, name) \
    wc_BioCtrl(bio, BIO_C_SET_FILENAME, \
                      BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name)

/* BIO memory */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_mem(void);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewMemBuf(void *data, int len);

/* BIO fd */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_fd(void);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewFd(int fd, int close_flag);

/* BIO null */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_null(void);

/* BIO socket */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_socket(void);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewSocket(int fd, int close_flag);
WOLFSSL_API int wc_BioSockShouldRetry(int i);
WOLFSSL_API int wc_BioSockNonFatalError(int err);

#define wc_BioSetFd(bio, fd, c) \
    wc_BioIntCtrl(bio, BIO_C_SET_FD, c, fd)
#define wc_BioGetFd(bio, c) \
    wc_BioCtrl(bio, BIO_C_GET_FD, 0, (char *)c)

/* BIO connect */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_connect(void);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewConnect(const char *host_port);
#define wc_BioSetConnHostname(bio, hname) \
    wc_BioCtrl(bio, BIO_C_SET_CONNECT, 0, (char *)hname)
#define wc_BioSetConnPort(bio, port) \
    wc_BioCtrl(bio, BIO_C_SET_CONNECT, 1, (char *)port)
#define wc_BioSetConnIp(bio, ip) \
    wc_BioCtrl(bio, BIO_C_SET_CONNECT, 2, (char *)ip)
#define wc_BioSetConnIntPort(bio, port) \
    wc_BioCtrl(bio, BIO_C_SET_CONNECT, 3, (int *)port)
#define wc_BioGetConnHostname(bio) \
    wc_BioPtrCtrl(bio, BIO_C_GET_CONNECT, 0)
#define wc_BioGetConnPort(bio) \
    wc_BioPtrCtrl(bio, BIO_C_GET_CONNECT, 1)
#define wc_BioGetConnIp(bio) \
    wc_BioPtrCtrl(bio, BIO_C_GET_CONNECT, 2)
#define wc_BioGetConnIntPort(bio) \
    wc_BioIntCtrl(bio, BIO_C_GET_CONNECT, 3, 0)

#define wc_BioSetNbio(bio, n) \
    wc_BioCtrl(bio, BIO_C_SET_NBIO, n, NULL)

#define wc_BioDoHandshake(bio) \
    wc_BioCtrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL)
#define wc_BioDoConnect(bio) wc_BioDoHandshake(bio)
#define wc_BioDoAccept(bio) wc_BioDoHandshake(bio)

/* BIO accept */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_accept(void);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewAccept(const char *str);
#define wc_BioSetAcceptPort(bio, name) \
    wc_BioCtrl(bio, BIO_C_SET_ACCEPT, 0, (char *)name)
#define wc_BioGetAcceptPort(bio) \
    wc_BioPtrCtrl(bio, BIO_C_GET_ACCEPT, 0)
#define wc_BioSetNbioAccept(bio, name) \
    wc_BioCtrl(bio, BIO_C_SET_ACCEPT, 1, name ? (void *)"a" : NULL)
#define wc_BioSetAcceptBios(bio, nbio) \
    wc_BioCtrl(bio, BIO_C_SET_ACCEPT, 2, nbio)
#define wc_BioSetBindMode(bio, mode) \
    wc_BioCtrl(bio, BIO_C_SET_BIND_MODE, mode, NULL)
#define wc_BioGetBindMode(bio, mode) \
    wc_BioCtrl(bio, BIO_C_GET_BIND_MODE, 0, NULL)
#define wc_BioSetSocketOptions(bio, opt) \
    wc_BioCtrl(bio, BIO_C_SET_EX_ARG, opt, NULL)


/* BIO datagram */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_s_datagram(void);
WOLFSSL_API WOLFCRYPT_BIO *wc_BioNewDgram(int fd, int close_flag);

/* BIO filter buffer */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_f_buffer(void);

#define wc_BioGetMemData(bio, data) \
    wc_BioCtrl(bio, BIO_CTRL_INFO, 0, data)
#define wc_BioSetMemBuf(bio, data, c) \
    wc_BioCtrl(bio, BIO_C_SET_BUF_MEM, c, data)
#define wc_BioGetMemPtr(b, ptr) \
    wc_BioCtrl(bio, BIO_C_GET_BUF_MEM_PTR,0, (char *)ptr)
#define wc_BioSetMemEofReturn(bio, v) \
    wc_BioCtrl(bio, BIO_C_SET_BUF_MEM_EOF_RETURN, v, NULL)

#define wc_BioGetBufferNumLines(bio) \
    wc_BioCtrl(bio, BIO_C_GET_BUFF_NUM_LINES, 0, NULL)
#define wc_BioSetBufferSize(bio, size) \
    wc_BioCtrl(bio, BIO_C_SET_BUFF_SIZE, size, NULL)
#define wc_BioSetReadBufferSize(bio, size) \
    wc_BioIntCtrl(bio, BIO_C_SET_BUFF_SIZE, size, 0)
#define wc_BioSetWriteBufferSize(bio, size) \
    wc_BioIntCtrl(bio, BIO_C_SET_BUFF_SIZE, size, 1)
#define wc_BioSetBufferReadData(bio, buf, num) \
    wc_BioCtrl(bio, BIO_C_SET_BUFF_READ_DATA, num, buf)

/* BIO filter cipher */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_f_cipher(void);
WOLFSSL_API void wc_BioSetCipher(WOLFCRYPT_BIO *bio,
                                        const WOLFCRYPT_EVP_CIPHER *cipher,
                                        const unsigned char *key,
                                        const unsigned char *iv, int enc);

#define wc_BioGetCipherStatus(bio) \
    wc_BioCtrl(bio, BIO_C_GET_CIPHER_STATUS, 0, NULL)
#define wc_BioGetCipherCtx(bio, ctx) \
    wc_BioCtrl(bio, BIO_C_GET_CIPHER_CTX, 0, ctx)

/* BIO filter base64 */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_f_base64(void);

/* BIO filter digest */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_f_md(void);

#define wc_BioSetMd(bio, md) \
    wc_BioCtrl(bio, BIO_C_SET_MD, 0, (WOLFCRYPT_EVP_MD *)md)
#define wc_BioGetMd(bio,md) \
    wc_BioCtrl(bio, BIO_C_GET_MD, 0, (WOLFCRYPT_EVP_MD *)md)
#define wc_BioGetmdCtx(bio,ctx) \
    wc_BioCtrl(bio, BIO_C_GET_MD_CTX, 0, (WOLFCRYPT_EVP_MD_CTX *)ctx)
#define wc_BioSetMdCtx(bio, ctx) \
    wc_BioCtrl(bio, BIO_C_SET_MD_CTX, 0, (WOLFCRYPT_EVP_MD_CTX *)ctx)

/* BIO filter SSL */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *wc_Bio_f_ssl(void);
WOLFSSL_API void wc_BioSSLShutdown(WOLFCRYPT_BIO *bio);

#define wc_BioSetSSL(bio, ssl, mode) \
    wc_BioCtrl(bio, BIO_C_SET_SSL, mode, ssl)
#define wc_BioGetSSL(bio, ssl) \
    wc_BioCtrl(bio, BIO_C_GET_SSL, 0, ssl)
#define wc_BIOSetSSLMode(bio, client) \
    wc_BioCtrl(bio, BIO_C_SSL_MODE, client, NULL)
#define wc_BIOSetSSLRenegotiateBytes(bio, num) \
    wc_BIOCtrl(bio, BIO_C_SET_SSL_RENEGOTIATE_BYTES, num, NULL);
#define wc_BIOGetNumRenegotiates(bio) \
    wc_BIOCtrl(bio, BIO_C_GET_SSL_NUM_RENEGOTIATES, 0, NULL);
#define wc_BIOSetSSLRenegotiateTimeout(bio, seconds) \
    wc_BIOCtrl(bio, BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT, seconds, NULL);


/* BIO socket internal functions */
int wc_BioGetHostIp(const char *str, unsigned char *ip);
int wc_BioGetPort(const char *str, unsigned short *port_ptr);
int wc_BioSockError(int sock);
int wc_BioSockInit(void);
void wc_BioSockCleanup(void);
int wc_BioGetAcceptSocket(char *host, int bind_mode);
int wc_BioAccept(int sock, char **addr);
int wc_BioSetTcpNdelay(int s, int on);
int wc_BioSetTcpNsigpipe(int s, int on);
int wc_BioSocketNbio(int s, int mode);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OPENSSL_EXTRA */
#endif /* WOLF_CRYPT_BIO_H */
