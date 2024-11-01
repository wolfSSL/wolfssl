/* bio.h
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

/* bio.h for openssl */


#ifndef WOLFSSL_BIO_H_
#define WOLFSSL_BIO_H_

#include <wolfssl/openssl/ssl.h>

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)

/* helper to set specific retry/read flags */
#define wolfSSL_BIO_set_retry_read(bio)\
    wolfSSL_BIO_set_flags((bio), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_READ)
#define wolfSSL_BIO_set_retry_write(bio)\
    wolfSSL_BIO_set_flags((bio), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_WRITE)

/* BIO CTRL */
#define WOLFSSL_BIO_CTRL_RESET             1
#define WOLFSSL_BIO_CTRL_EOF               2
#define WOLFSSL_BIO_CTRL_INFO              3
#define WOLFSSL_BIO_CTRL_SET               4
#define WOLFSSL_BIO_CTRL_GET               5
#define WOLFSSL_BIO_CTRL_PUSH              6
#define WOLFSSL_BIO_CTRL_POP               7
#define WOLFSSL_BIO_CTRL_GET_CLOSE         8
#define WOLFSSL_BIO_CTRL_SET_CLOSE         9
#define WOLFSSL_BIO_CTRL_PENDING           10
#define WOLFSSL_BIO_CTRL_FLUSH             11
#define WOLFSSL_BIO_CTRL_DUP               12
#define WOLFSSL_BIO_CTRL_WPENDING          13

#define WOLFSSL_BIO_C_SET_FILE_PTR              106
#define WOLFSSL_BIO_C_GET_FILE_PTR              107
#define WOLFSSL_BIO_C_SET_FILENAME              108
#define WOLFSSL_BIO_C_SET_BUF_MEM               114
#define WOLFSSL_BIO_C_GET_BUF_MEM_PTR           115
#define WOLFSSL_BIO_C_FILE_SEEK                 128
#define WOLFSSL_BIO_C_SET_BUF_MEM_EOF_RETURN    130
#define WOLFSSL_BIO_C_SET_WRITE_BUF_SIZE        136
#define WOLFSSL_BIO_C_MAKE_WOLFSSL_BIO_PAIR             138

#define WOLFSSL_BIO_CTRL_DGRAM_CONNECT       31
#define WOLFSSL_BIO_CTRL_DGRAM_SET_CONNECTED 32
#define WOLFSSL_BIO_CTRL_DGRAM_QUERY_MTU     40
#define WOLFSSL_BIO_CTRL_DGRAM_SET_PEER      44

#define WOLFSSL_BIO_FP_TEXT                0x00
#define WOLFSSL_BIO_NOCLOSE                0x00
#define WOLFSSL_BIO_CLOSE                  0x01

#define WOLFSSL_BIO_FP_WRITE               0x04

#ifndef OPENSSL_COEXIST

#define BIO_FLAGS_BASE64_NO_NL WOLFSSL_BIO_FLAG_BASE64_NO_NL
#define BIO_FLAGS_READ         WOLFSSL_BIO_FLAG_READ
#define BIO_FLAGS_WRITE        WOLFSSL_BIO_FLAG_WRITE
#define BIO_FLAGS_IO_SPECIAL   WOLFSSL_BIO_FLAG_IO_SPECIAL
#define BIO_FLAGS_SHOULD_RETRY WOLFSSL_BIO_FLAG_RETRY
/* You shouldn't free up or change the data if BIO_FLAGS_MEM_RDONLY is set */
#define BIO_FLAGS_MEM_RDONLY   WOLFSSL_BIO_FLAG_MEM_RDONLY

#define BIO_new_fp                      wolfSSL_BIO_new_fp
#if defined(OPENSSL_ALL) \
    || defined(HAVE_STUNNEL) \
    || defined(HAVE_LIGHTY) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) \
    || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA)
#define BIO_new_file                    wolfSSL_BIO_new_file
#endif
#define BIO_new_fp                      wolfSSL_BIO_new_fp
#define BIO_ctrl                        wolfSSL_BIO_ctrl
#define BIO_ctrl_pending                wolfSSL_BIO_ctrl_pending
#define BIO_wpending                    wolfSSL_BIO_wpending
#define BIO_get_mem_ptr                 wolfSSL_BIO_get_mem_ptr
#ifdef OPENSSL_ALL
#define BIO_set_mem_buf                 wolfSSL_BIO_set_mem_buf
#endif
#define BIO_int_ctrl                    wolfSSL_BIO_int_ctrl
#define BIO_reset                       wolfSSL_BIO_reset
#define BIO_s_file                      wolfSSL_BIO_s_file
#define BIO_s_bio                       wolfSSL_BIO_s_bio
#define BIO_s_socket                    wolfSSL_BIO_s_socket
#define BIO_s_datagram                  wolfSSL_BIO_s_datagram
#define BIO_s_accept                    wolfSSL_BIO_s_socket
#define BIO_set_fd                      wolfSSL_BIO_set_fd
#define BIO_set_close                   wolfSSL_BIO_set_close
#define BIO_ctrl_reset_read_request     wolfSSL_BIO_ctrl_reset_read_request
#define BIO_set_write_buf_size          wolfSSL_BIO_set_write_buf_size
#define BIO_make_bio_pair               wolfSSL_BIO_make_bio_pair
#define BIO_up_ref                      wolfSSL_BIO_up_ref

#define BIO_new_fd                      wolfSSL_BIO_new_fd
#define BIO_set_fp                      wolfSSL_BIO_set_fp
#define BIO_get_fp                      wolfSSL_BIO_get_fp
#define BIO_seek                        wolfSSL_BIO_seek
#define BIO_tell                        wolfSSL_BIO_tell
#define BIO_write_filename              wolfSSL_BIO_write_filename
#define BIO_set_mem_eof_return          wolfSSL_BIO_set_mem_eof_return

#define BIO_find_type wolfSSL_BIO_find_type
#define BIO_next      wolfSSL_BIO_next
#define BIO_gets      wolfSSL_BIO_gets
#define BIO_puts      wolfSSL_BIO_puts

#define BIO_should_retry                wolfSSL_BIO_should_retry
#define BIO_should_read                 wolfSSL_BIO_should_read
#define BIO_should_write                wolfSSL_BIO_should_write

#define BIO_TYPE_FILE WOLFSSL_BIO_FILE
#define BIO_TYPE_BIO  WOLFSSL_BIO_BIO
#define BIO_TYPE_MEM  WOLFSSL_BIO_MEMORY
#define BIO_TYPE_BASE64 WOLFSSL_BIO_BASE64

#define BIO_vprintf wolfSSL_BIO_vprintf
#define BIO_printf  wolfSSL_BIO_printf
#define BIO_dump    wolfSSL_BIO_dump

/* BIO info callback */
#define BIO_CB_FREE   WOLFSSL_BIO_CB_FREE
#define BIO_CB_READ   WOLFSSL_BIO_CB_READ
#define BIO_CB_WRITE  WOLFSSL_BIO_CB_WRITE
#define BIO_CB_PUTS   WOLFSSL_BIO_CB_PUTS
#define BIO_CB_GETS   WOLFSSL_BIO_CB_GETS
#define BIO_CB_CTRL   WOLFSSL_BIO_CB_CTRL
#define BIO_CB_RETURN WOLFSSL_BIO_CB_RETURN

#define BIO_set_callback         wolfSSL_BIO_set_callback
#define BIO_get_callback         wolfSSL_BIO_get_callback
#define BIO_set_callback_arg     wolfSSL_BIO_set_callback_arg
#define BIO_get_callback_arg     wolfSSL_BIO_get_callback_arg

/* BIO for 1.1.0 or later */
#define BIO_set_init               wolfSSL_BIO_set_init
#define BIO_get_data               wolfSSL_BIO_get_data
#define BIO_set_data               wolfSSL_BIO_set_data
#define BIO_get_shutdown           wolfSSL_BIO_get_shutdown
#define BIO_set_shutdown           wolfSSL_BIO_set_shutdown

#define BIO_get_fd                 wolfSSL_BIO_get_fd

#define BIO_clear_flags            wolfSSL_BIO_clear_flags
#define BIO_set_ex_data            wolfSSL_BIO_set_ex_data
#define BIO_get_ex_data            wolfSSL_BIO_get_ex_data

/* helper to set specific retry/read flags */
#define BIO_set_retry_read(bio) wolfSSL_BIO_set_retry_read(bio)
#define BIO_set_retry_write(bio) wolfSSL_BIO_set_retry_write(bio)

#define BIO_clear_retry_flags      wolfSSL_BIO_clear_retry_flags

#define BIO_meth_new               wolfSSL_BIO_meth_new
#define BIO_meth_set_write         wolfSSL_BIO_meth_set_write
#define BIO_meth_free              wolfSSL_BIO_meth_free
#define BIO_meth_set_write         wolfSSL_BIO_meth_set_write
#define BIO_meth_set_read          wolfSSL_BIO_meth_set_read
#define BIO_meth_set_puts          wolfSSL_BIO_meth_set_puts
#define BIO_meth_set_gets          wolfSSL_BIO_meth_set_gets
#define BIO_meth_set_ctrl          wolfSSL_BIO_meth_set_ctrl
#define BIO_meth_set_create        wolfSSL_BIO_meth_set_create
#define BIO_meth_set_destroy       wolfSSL_BIO_meth_set_destroy

#define BIO_snprintf               XSNPRINTF

/* BIO CTRL */
#define BIO_CTRL_RESET              WOLFSSL_BIO_CTRL_RESET
#define BIO_CTRL_EOF                WOLFSSL_BIO_CTRL_EOF
#define BIO_CTRL_INFO               WOLFSSL_BIO_CTRL_INFO
#define BIO_CTRL_SET                WOLFSSL_BIO_CTRL_SET
#define BIO_CTRL_GET                WOLFSSL_BIO_CTRL_GET
#define BIO_CTRL_PUSH               WOLFSSL_BIO_CTRL_PUSH
#define BIO_CTRL_POP                WOLFSSL_BIO_CTRL_POP
#define BIO_CTRL_GET_CLOSE          WOLFSSL_BIO_CTRL_GET_CLOSE
#define BIO_CTRL_SET_CLOSE          WOLFSSL_BIO_CTRL_SET_CLOSE
#define BIO_CTRL_PENDING            WOLFSSL_BIO_CTRL_PENDING
#define BIO_CTRL_FLUSH              WOLFSSL_BIO_CTRL_FLUSH
#define BIO_CTRL_DUP                WOLFSSL_BIO_CTRL_DUP
#define BIO_CTRL_WPENDING           WOLFSSL_BIO_CTRL_WPENDING

#define BIO_C_SET_FILE_PTR               WOLFSSL_BIO_C_SET_FILE_PTR
#define BIO_C_GET_FILE_PTR               WOLFSSL_BIO_C_GET_FILE_PTR
#define BIO_C_SET_FILENAME               WOLFSSL_BIO_C_SET_FILENAME
#define BIO_C_SET_BUF_MEM                WOLFSSL_BIO_C_SET_BUF_MEM
#define BIO_C_GET_BUF_MEM_PTR            WOLFSSL_BIO_C_GET_BUF_MEM_PTR
#define BIO_C_FILE_SEEK                  WOLFSSL_BIO_C_FILE_SEEK
#define BIO_C_SET_BUF_MEM_EOF_RETURN     WOLFSSL_BIO_C_SET_BUF_MEM_EOF_RETURN
#define BIO_C_SET_WRITE_BUF_SIZE         WOLFSSL_BIO_C_SET_WRITE_BUF_SIZE
#define BIO_C_MAKE_BIO_PAIR              WOLFSSL_BIO_C_MAKE_BIO_PAIR

#define BIO_CTRL_DGRAM_CONNECT        WOLFSSL_BIO_CTRL_DGRAM_CONNECT
#define BIO_CTRL_DGRAM_SET_CONNECTED  WOLFSSL_BIO_CTRL_DGRAM_SET_CONNECTED
#define BIO_CTRL_DGRAM_QUERY_MTU      WOLFSSL_BIO_CTRL_DGRAM_QUERY_MTU
#define BIO_CTRL_DGRAM_SET_PEER       WOLFSSL_BIO_CTRL_DGRAM_SET_PEER

#define BIO_FP_TEXT                 WOLFSSL_BIO_FP_TEXT
#define BIO_NOCLOSE                 WOLFSSL_BIO_NOCLOSE
#define BIO_CLOSE                   WOLFSSL_BIO_CLOSE

#define BIO_FP_WRITE                WOLFSSL_BIO_FP_WRITE

#endif /* !OPENSSL_COEXIST */

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_BIO_H_ */
