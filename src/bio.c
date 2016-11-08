/* bio.c
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

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_ctrl(WOLFSSL_BIO *bio, int cmd, long larg, void *parg)
{
    (void)bio;
    (void)cmd;
    (void)larg;
    (void)parg;

    WOLFSSL_ENTER("BIO_ctrl");
    return 1;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *b)
{
   (void) b;
    WOLFSSL_ENTER("BIO_ctrl_pending");
   return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *b, void *m)
{
   (void) b;
   (void) m;
    WOLFSSL_ENTER("BIO_get_mem_ptr");
   return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_int_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, int iarg)
{
    (void) bp;
    (void) cmd;
    (void) larg;
    (void) iarg;
    WOLFSSL_ENTER("BIO_int_ctrl");
    return 0;
}

/*** TBD ***/
WOLFSSL_API const WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void)
{
    WOLFSSL_ENTER("BIO_s_socket");
    return (void *)0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size)
{
    (void) b;
    (void) size;
    WOLFSSL_ENTER("BIO_set_write_buf_size");
    return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2)
{
      (void) b1;
      (void) b2;
      WOLFSSL_ENTER("BIO_make_bio_pair");
      return 0;
}

/*** TBD ***/
WOLFSSL_API int wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *b)
{
      (void) b;
      WOLFSSL_ENTER("BIO_ctrl_reset_read_request");
      return 0;
}

/*** TBD ***/
WOLFSSL_API int wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf)
{
      (void) bio;
      (void) buf;
      WOLFSSL_ENTER("BIO_nread0");
      return 0;
}

/*** TBD ***/
WOLFSSL_API int wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num)
{
      (void) bio;
      (void) buf;
      (void) num;
      WOLFSSL_ENTER("BIO_nread");
      return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num)
{
      (void) bio;
      (void) buf;
      (void) num;
      WOLFSSL_ENTER("BIO_nwrite");
      return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_reset(WOLFSSL_BIO *bio)
{
      (void) bio;
      WOLFSSL_ENTER("BIO_reset");
      return 0;
}

#if 0
#ifndef NO_FILESYSTEM
/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c)
{
      (void) bio;
      (void) fp;
      (void) c;
      WOLFSSL_ENTER("BIO_set_fp");
      return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE fp)
{
      (void) bio;
      (void) fp;
      WOLFSSL_ENTER("BIO_get_fp");
      return 0;
}
#endif
#endif

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs)
{
      (void) bio;
      (void) ofs;
      WOLFSSL_ENTER("BIO_seek");
      return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name)
{
      (void) bio;
      (void) name;
      WOLFSSL_ENTER("BIO_write_filename");
      return 0;
}

/*** TBD ***/
WOLFSSL_API long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v)
{
      (void) bio;
      (void) v;
      WOLFSSL_ENTER("BIO_set_mem_eof_return");
      return 0;
}
