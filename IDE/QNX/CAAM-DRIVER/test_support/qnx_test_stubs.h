/* qnx_test_stubs.h
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

#ifndef CAAM_QNX_TEST_STUBS_H
#define CAAM_QNX_TEST_STUBS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#ifndef EOK
    #define EOK 0
#endif

#ifndef min
    #define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef NOFD
    #define NOFD (-1)
#endif

#ifndef PROT_NOCACHE
    #define PROT_NOCACHE 0
#endif

#ifndef MAP_PHYS
    #define MAP_PHYS 0
#endif

#ifndef MAP_ANON
    #define MAP_ANON 0
#endif

typedef int64_t off64_t;

typedef struct iov {
    void*  iov_base;
    size_t iov_len;
} iov_t;

#define SETIOV(iov, base, len) do { \
    (iov)->iov_base = (void*)(base); \
    (iov)->iov_len = (size_t)(len); \
} while (0)

typedef struct {
    int size;
    int rcvid;
} resmgr_context_t;

typedef struct {
    struct {
        unsigned int dcmd;
    } i;
    struct {
        unsigned int nbytes;
    } o;
} io_devctl_t;

typedef struct {
    struct {
        unsigned int xtype;
        unsigned int nbytes;
    } i;
} io_read_t;

typedef struct {
    int unused;
} io_write_t;

typedef struct {
    int unused;
} io_open_t;

typedef struct {
    int offset;
} iofunc_ocb_t;

typedef iofunc_ocb_t RESMGR_OCB_T;
typedef int RESMGR_HANDLE_T;

typedef struct {
    int unused;
} iofunc_attr_t;

typedef struct {
    int (*open)(resmgr_context_t*, io_open_t*, RESMGR_HANDLE_T*, void*);
} resmgr_connect_funcs_t;

typedef struct {
    int (*close_ocb)(resmgr_context_t*, void*, RESMGR_OCB_T*);
    int (*read)(resmgr_context_t*, io_read_t*, RESMGR_OCB_T*);
    int (*write)(resmgr_context_t*, io_write_t*, RESMGR_OCB_T*);
    int (*devctl)(resmgr_context_t*, io_devctl_t*, iofunc_ocb_t*);
} resmgr_io_funcs_t;

typedef struct {
    int unused;
} resmgr_attr_t;

typedef struct {
    int unused;
} dispatch_t;

typedef resmgr_context_t dispatch_context_t;

#define _RESMGR_DEFAULT 1
#define _RESMGR_NOREPLY 2
#define _RESMGR_CONNECT_NFUNCS 1
#define _RESMGR_IO_NFUNCS 1
#define _FTYPE_ANY 0
#define _IO_XTYPE_MASK 0
#define _IO_XTYPE_NONE 0
#define _IO_DEVCTL_VERIFY_OCB_READ 0
#define _IO_DEVCTL_VERIFY_OCB_WRITE 0

#define _DCMD_ALL 0
#define __DIOTF(group, cmd, type) (cmd)
#define __DIOT(group, cmd, type) (cmd)

static inline int iofunc_devctl_default(resmgr_context_t* ctp,
        io_devctl_t* msg, iofunc_ocb_t* ocb)
{
    (void)ctp;
    (void)msg;
    (void)ocb;
    return _RESMGR_DEFAULT;
}

static inline int iofunc_devctl_verify(resmgr_context_t* ctp,
        io_devctl_t* msg, iofunc_ocb_t* ocb, int flags)
{
    (void)ctp;
    (void)msg;
    (void)ocb;
    (void)flags;
    return EOK;
}

static inline int iofunc_open_default(resmgr_context_t* ctp, io_open_t* msg,
        RESMGR_HANDLE_T* handle, void* extra)
{
    (void)ctp;
    (void)msg;
    (void)handle;
    (void)extra;
    return EOK;
}

static inline int iofunc_close_ocb_default(resmgr_context_t* ctp,
        void* reserved, RESMGR_OCB_T* ocb)
{
    (void)ctp;
    (void)reserved;
    (void)ocb;
    return EOK;
}

static inline int iofunc_read_verify(resmgr_context_t* ctp, io_read_t* msg,
        RESMGR_OCB_T* ocb, void* extra)
{
    (void)ctp;
    (void)msg;
    (void)ocb;
    (void)extra;
    return EOK;
}

static inline void iofunc_attr_init(iofunc_attr_t* attr, int mode,
        void* a, void* b)
{
    (void)attr;
    (void)mode;
    (void)a;
    (void)b;
}

static inline void iofunc_func_init(int a, resmgr_connect_funcs_t* b,
        int c, resmgr_io_funcs_t* d)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
}

static inline dispatch_t* dispatch_create(void)
{
    return (dispatch_t*)1;
}

static inline int resmgr_attach(dispatch_t* dpp, resmgr_attr_t* attr,
        const char* path, int ftype, int flags, resmgr_connect_funcs_t* cf,
        resmgr_io_funcs_t* io, iofunc_attr_t* attr2)
{
    (void)dpp;
    (void)attr;
    (void)path;
    (void)ftype;
    (void)flags;
    (void)cf;
    (void)io;
    (void)attr2;
    return 0;
}

static inline dispatch_context_t* dispatch_context_alloc(dispatch_t* dpp)
{
    (void)dpp;
    return NULL;
}

static inline dispatch_context_t* dispatch_block(dispatch_context_t* ctp)
{
    (void)ctp;
    return NULL;
}

static inline int dispatch_handler(dispatch_context_t* ctp)
{
    (void)ctp;
    return 0;
}

static inline int MsgReply(int rcvid, int status, const void* msg, int size)
{
    (void)rcvid;
    (void)status;
    (void)msg;
    (void)size;
    return 0;
}

static inline uintptr_t mmap_device_io(size_t len, uintptr_t addr)
{
    (void)len;
    return addr;
}

static inline int munmap_device_io(uintptr_t addr, size_t len)
{
    (void)addr;
    (void)len;
    return 0;
}

static inline void* mmap_device_memory(void* addr, size_t len, int prot,
        int flags, uintptr_t offset)
{
    (void)addr;
    (void)len;
    (void)prot;
    (void)flags;
    (void)offset;
    return NULL;
}

static inline int mem_offset64(void* addr, int fd, int len, off64_t* offset,
        void* contig_len)
{
    (void)addr;
    (void)fd;
    (void)len;
    (void)offset;
    (void)contig_len;
    return -1;
}

static inline unsigned int in32(uintptr_t addr)
{
    (void)addr;
    return 0;
}

static inline void out32(uintptr_t addr, unsigned int val)
{
    (void)addr;
    (void)val;
}

#endif /* CAAM_QNX_TEST_STUBS_H */
