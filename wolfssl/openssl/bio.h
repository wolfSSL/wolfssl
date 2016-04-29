#ifndef WOLFCRYPT_BIO_H_
#define WOLFCRYPT_BIO_H_

#include <stdio.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/openssl/evp.h>

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
#if !defined(BIO_CLOSE) || !defined(BIO_NOCLOSE)
#define BIO_CLOSE 1
#define BIO_NOCLOSE 0
#endif

/*enum WS_BIO_FILE {
    BIO_NOCLOSE = 0,
    BIO_CLOSE   = 1,
};*/

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

WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_METHOD *method);
WOLFSSL_API int WOLFCRYPT_BIO_free(WOLFCRYPT_BIO *bio);
WOLFSSL_API void WOLFCRYPT_BIO_free_all(WOLFCRYPT_BIO *bio);

WOLFSSL_API const char *WOLFCRYPT_BIO_method_name(const WOLFCRYPT_BIO *bio);
WOLFSSL_API int WOLFCRYPT_BIO_method_type(const WOLFCRYPT_BIO *bio);

WOLFSSL_API int WOLFCRYPT_BIO_set(WOLFCRYPT_BIO *bio,
                                  WOLFCRYPT_BIO_METHOD *method);
WOLFSSL_API void WOLFCRYPT_BIO_clear_flags(WOLFCRYPT_BIO *bio, int flags);
WOLFSSL_API void WOLFCRYPT_BIO_set_flags(WOLFCRYPT_BIO *bio, int flags);
WOLFSSL_API int WOLFCRYPT_BIO_test_flags(const WOLFCRYPT_BIO *bio, int flags);

#define WOLFCRYPT_BIO_get_flags(b) WOLFCRYPT_BIO_test_flags(b, ~(0x0))
#define WOLFCRYPT_BIO_set_retry_special(b) \
    WOLFCRYPT_BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
#define WOLFCRYPT_BIO_set_retry_read(b) \
    WOLFCRYPT_BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
#define WOLFCRYPT_BIO_set_retry_write(b) \
    WOLFCRYPT_BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))


#define WOLFCRYPT_BIO_clear_retry_flags(b) \
    WOLFCRYPT_BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
#define WOLFCRYPT_BIO_get_retry_flags(b) \
    WOLFCRYPT_BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))

    /* These should be used by the application to tell why we should retry */
#define WOLFCRYPT_BIO_should_read(f) \
    WOLFCRYPT_BIO_test_flags(f, BIO_FLAGS_READ)
#define WOLFCRYPT_BIO_should_write(f) \
    WOLFCRYPT_BIO_test_flags(f, BIO_FLAGS_WRITE)
#define WOLFCRYPT_BIO_should_io_special(f) \
    WOLFCRYPT_BIO_test_flags(f, BIO_FLAGS_IO_SPECIAL)
#define WOLFCRYPT_BIO_retry_type(f) \
    WOLFCRYPT_BIO_test_flags(f, BIO_FLAGS_RWS)
#define WOLFCRYPT_BIO_should_retry(f) \
    WOLFCRYPT_BIO_test_flags(f, BIO_FLAGS_SHOULD_RETRY)

WOLFSSL_API long (*WOLFCRYPT_BIO_get_callback(const WOLFCRYPT_BIO *bio))
(WOLFCRYPT_BIO *, int, const char *, int, long, long);

WOLFSSL_API void WOLFCRYPT_BIO_set_callback(WOLFCRYPT_BIO *bio,
                                          long (*cb) (WOLFCRYPT_BIO *, int,
                                          const char *, int, long, long));
WOLFSSL_API void WOLFCRYPT_BIO_set_callback_arg(WOLFCRYPT_BIO *bio, char *arg);
WOLFSSL_API char *WOLFCRYPT_BIO_get_callback_arg(const WOLFCRYPT_BIO *bio);

WOLFSSL_API int WOLFCRYPT_BIO_read(WOLFCRYPT_BIO *bio, void *out, int outl);
WOLFSSL_API int WOLFCRYPT_BIO_write(WOLFCRYPT_BIO *bio, const void *in, int inl);
WOLFSSL_API int WOLFCRYPT_BIO_puts(WOLFCRYPT_BIO *bio, const char *in);
WOLFSSL_API int WOLFCRYPT_BIO_gets(WOLFCRYPT_BIO *bio, char *in, int inl);

WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_push(WOLFCRYPT_BIO *top,
                                              WOLFCRYPT_BIO *next);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_pop(WOLFCRYPT_BIO *bio);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_next(WOLFCRYPT_BIO *bio);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_get_retry_BIO(WOLFCRYPT_BIO *bio,
                                                   int *reason);
WOLFSSL_API int WOLFCRYPT_BIO_get_retry_reason(WOLFCRYPT_BIO *bio);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_find_type(WOLFCRYPT_BIO *bio, int type);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_dup_chain(WOLFCRYPT_BIO *bio);
#define WOLFCRYPT_BIO_dup_state(bio, ret) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_DUP, 0, ret)

WOLFSSL_API long WOLFCRYPT_BIO_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long larg, void *parg);
WOLFSSL_API long WOLFCRYPT_BIO_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                           void (*fp) (WOLFCRYPT_BIO *, int,
                                           const char *, int, long, long));
WOLFSSL_API long WOLFCRYPT_BIO_int_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                      long larg, int iarg);
WOLFSSL_API char *WOLFCRYPT_BIO_ptr_ctrl(WOLFCRYPT_BIO *bio, int cmd, long larg);
WOLFSSL_API size_t WOLFCRYPT_BIO_ctrl_pending(WOLFCRYPT_BIO *bio);
WOLFSSL_API size_t WOLFCRYPT_BIO_ctrl_wpending(WOLFCRYPT_BIO *bio);

WOLFSSL_API int WOLFCRYPT_BIO_indent(WOLFCRYPT_BIO *bio, int indent, int max);

WOLFSSL_API unsigned long WOLFCRYPT_BIO_number_read(WOLFCRYPT_BIO *bio);
WOLFSSL_API unsigned long WOLFCRYPT_BIO_number_written(WOLFCRYPT_BIO *bio);

#define WOLFCRYPT_BIO_reset(bio) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL)
#define WOLFCRYPT_BIO_eof(bio) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL)
#define WOLFCRYPT_BIO_set_close(bio,c) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_SET_CLOSE, (c), NULL)
#define WOLFCRYPT_BIO_get_close(bio) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_GET_CLOSE, 0, NULL)
#define WOLFCRYPT_BIO_pending(bio) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL)
#define WOLFCRYPT_BIO_wpending(bio) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL)
#define WOLFCRYPT_BIO_flush(bio) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL)
#define WOLFCRYPT_BIO_set_info_callback(bio, cb) \
    (int)WOLFCRYPT_BIO_callback_ctrl(bio, BIO_CTRL_SET_CALLBACK, cb)
#define WOLFCRYPT_BIO_get_info_callback(bio, cb) \
    (int)WOLFCRYPT_BIO_callback_ctrl(bio, BIO_CTRL_GET_CALLBACK, 0, cb)

WOLFSSL_API void WOLFCRYPT_BIO_copy_next_retry(WOLFCRYPT_BIO *b);

WOLFSSL_API int WOLFCRYPT_BIO_printf(WOLFCRYPT_BIO *bio,
                                     const char *format, ...);

/* BIO file */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_file(void);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_fp(XFILE f, int close_flag);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_file(const char *name,
                                              const char *mode);
#define WOLFCRYPT_BIO_set_fp(bio, f, c) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_FILE_PTR, c, (char *)f)
#define WOLFCRYPT_BIO_get_fp(bio, f) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_FILE_PTR, 0, (char *)f)
#define WOLFCRYPT_BIO_seek(bio, ofs) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_C_FILE_SEEK, ofs, NULL)
#define WOLFCRYPT_BIO_tell(bio) \
    (int)WOLFCRYPT_BIO_ctrl(bio, BIO_C_FILE_TELL, 0, NULL)
#define WOLFCRYPT_BIO_read_filename(bio, name) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_READ, name)
#define WOLFCRYPT_BIO_write_filename(bio, name) \
    WOLFCRYPT_BIO_ctrl(bio,BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_WRITE, name)
#define WOLFCRYPT_BIO_append_filename(bio, name) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_APPEND, name)
#define WOLFCRYPT_BIO_rw_filename(bio, name) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_FILENAME, \
                       BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name)

/* BIO memory */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_mem(void);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_mem_buf(void *data, int len);

/* BIO fd */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_fd(void);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_fd(int fd, int close_flag);

/* BIO null */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_null(void);

/* BIO socket */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_socket(void);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_socket(int fd, int close_flag);
WOLFSSL_API int WOLFCRYPT_BIO_sock_should_retry(int i);
WOLFSSL_API int WOLCRYPT_BIO_sock_non_fatal_error(int err);

#define WOLFCRYPT_BIO_set_fd(bio, fd, c) \
    WOLFCRYPT_BIO_int_ctrl(bio, BIO_C_SET_FD, c, fd)
#define WOLFCRYPT_BIO_get_fd(bio, c) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_FD, 0, (char *)c)

/* BIO connect */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_connect(void);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_connect(const char *host_port);
#define WOLFCRYPT_BIO_set_conn_hostname(bio, hname) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_CONNECT, 0, (char *)hname)
#define WOLFCRYPT_BIO_set_conn_port(bio, port) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_CONNECT, 1, (char *)port)
#define WOLFCRYPT_BIO_set_conn_ip(bio, ip) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_CONNECT, 2, (char *)ip)
#define WOLFCRYPT_BIO_set_conn_int_port(bio, port) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_CONNECT, 3, (char *)port)

#define WOLFCRYPT_BIO_get_conn_hostname(bio) \
    WOLFCRYPT_BIO_ptr_ctrl(bio, BIO_C_GET_CONNECT, 0)
#define WOLFCRYPT_BIO_get_conn_port(bio) \
    WOLFCRYPT_BIO_ptr_ctrl(bio, BIO_C_GET_CONNECT, 1)
#define WOLFCRYPT_BIO_get_conn_ip(bio) \
    WOLFCRYPT_BIO_ptr_ctrl(bio, BIO_C_GET_CONNECT, 2)
#define WOLFCRYPT_BIO_get_conn_int_port(bio) \
    WOLFCRYPT_BIO_int_ctrl(bio, BIO_C_GET_CONNECT, 3, 0)

#define WOLFCRYPT_BIO_set_nbio(bio, n) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_NBIO, n, NULL)

#define WOLFCRYPT_BIO_do_handshake(bio) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL)
#define WOLFCRYPT_BIO_do_connect(bio) WOLFCRYPT_BIO_do_handshake(bio)
#define WOLFCRYPT_BIO_do_accept(bio) WOLFCRYPT_BIO_do_handshake(bio)

/* BIO accept */
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_accept(const char *str);
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_accept(void);
#define WOLFCRYPT_BIO_set_accept_port(bio, name) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_ACCEPT, 0, (char *)name)
#define WOLFCRYPT_BIO_set_accept_bios(bio, nbio) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_ACCEPT, 2, nbio)
#define WOLFCRYPT_BIO_set_bind_mode(bio, mode) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_BIND_MODE, mode, NULL)
#define WOLFCRYPT_BIO_set_socket_options(bio, opt) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_EX_ARG, opt, NULL)


/* BIO datagram */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_datagram(void);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_dgram(int fd, int close_flag);

/* BIO filter buffer */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_buffer(void);

#define WOLFCRYPT_BIO_get_mem_data(bio, data) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_INFO, 0, data)
#define WOLFCRYPT_BIO_set_mem_buf(bio, data, c) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_BUF_MEM, c, data)
#define WOLFCRYPT_BIO_get_mem_ptr(b, ptr) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_BUF_MEM_PTR,0, (char *)ptr)
#define WOLFCRYPT_BIO_set_mem_eof_return(bio, v) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_BUF_MEM_EOF_RETURN, v, NULL)

#define WOLFCRYPT_BIO_get_buffer_num_lines(bio) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_BUFF_NUM_LINES, 0, NULL)
#define WOLFCRYPT_BIO_set_buffer_size(bio, size) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_BUFF_SIZE, size, NULL)
#define WOLFCRYPT_BIO_set_read_buffer_size(bio, size) \
    WOLFCRYPT_BIO_int_ctrl(bio, BIO_C_SET_BUFF_SIZE, size, 0)
#define WOLFCRYPT_BIO_set_write_buffer_size(bio, size) \
    WOLFCRYPT_BIO_int_ctrl(bio, BIO_C_SET_BUFF_SIZE, size, 1)
#define WOLFCRYPT_BIO_set_buffer_read_data(bio, buf, num) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_BUFF_READ_DATA, num, buf)

/* BIO filter cipher */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_cipher(void);
WOLFSSL_API void WOLFCRYPT_BIO_set_cipher(WOLFCRYPT_BIO *bio,
                                          const WOLFSSL_EVP_CIPHER *cipher,
                                          const unsigned char *key,
                                          const unsigned char *iv, int enc);

#define WOLFCRYPT_BIO_get_cipher_status(bio) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_CIPHER_STATUS, 0, NULL)
#define WOLFCRYPT_BIO_get_cipher_ctx(bio, ctx) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_CIPHER_CTX, 0, ctx)

/* BIO filter base64 */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_base64(void);

/* BIO filter digest */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_md(void);

#define WOLFCRYPT_BIO_set_md(bio, md) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_MD, 0, (WOLFSSL_EVP_MD *)md)
#define WOLFCRYPT_BIO_get_md(bio,md) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_MD, 0, (WOLFSSL_EVP_MD *)md)
#define WOLFCRYPT_BIO_get_md_ctx(bio,ctx) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_MD_CTX, 0, (WOLFSSL_EVP_MD_CTX *)ctx)
#define WOLFCRYPT_BIO_set_md_ctx(bio, ctx) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_MD_CTX, 0, (WOLFSSL_EVP_MD_CTX *)ctx)

/* BIO filter SSL */
WOLFSSL_API WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_f_ssl(void);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_buffer_ssl_connect(WOLFSSL_CTX *ctx);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_ssl_connect(WOLFSSL_CTX *ctx);
WOLFSSL_API WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_ssl(WOLFSSL_CTX *ctx, int client);
WOLFSSL_API void WOLFCRYPT_BIO_ssl_shutdown(WOLFCRYPT_BIO *bio);

#define WOLFCRYPT_BIO_set_ssl(bio, ssl, mode) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_SET_SSL, mode, ssl)
#define WOLFCRYPT_BIO_get_ssl(bio, ssl) \
    WOLFCRYPT_BIO_ctrl(bio, BIO_C_GET_SSL, 0, ssl)

/* BIO socket internal functions */
int WOLFCRYPT_BIO_get_host_ip(const char *str, unsigned char *ip);
int WOLFCRYPT_BIO_get_port(const char *str, unsigned short *port_ptr);
int WOLFCRYPT_BIO_sock_error(int sock);
int WOLFCRYPT_BIO_sock_init(void);
void WOLFCRYPT_BIO_sock_cleanup(void);
int WOLFCRYPT_BIO_get_accept_socket(char *host, int bind_mode);
int WOLFCRYPT_BIO_accept(int sock, char **addr);
int WOLFCRYPT_BIO_set_tcp_ndelay(int s, int on);
int WOLFCRYPT_BIO_set_tcp_nsigpipe(int s, int on);
int WOLFCRYPT_BIO_socket_nbio(int s, int mode);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OPENSSL_EXTRA */
#endif /* WOLFCRYPT_BIO_H_ */
