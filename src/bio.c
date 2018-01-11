/* bio.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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

#if !defined(WOLFSSL_BIO_INCLUDED)
    #warning bio.c does not need to be compiled seperatly from ssl.c
#else

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


/* helper function for wolfSSL_BIO_gets
 * size till a newline is hit
 * returns the number of bytes including the new line character
 */
static int wolfSSL_getLineLength(char* in, int inSz)
{
    int i;

    for (i = 0; i < inSz; i++) {
        if (in[i] == '\n') {
            return i + 1; /* includes new line character */
        }
    }

    return inSz; /* rest of buffer is all one line */
}


/* Gets the next line from bio. Goes until a new line character or end of
 * buffer is reached.
 *
 * bio  the structure to read a new line from
 * buf  buffer to hold the result
 * sz   the size of "buf" buffer
 *
 * returns the size of the result placed in buf on success and a 0 or negative
 *         value in an error case.
 */
int wolfSSL_BIO_gets(WOLFSSL_BIO* bio, char* buf, int sz)
{
    int ret = WOLFSSL_BIO_UNSET;

    WOLFSSL_ENTER("wolfSSL_BIO_gets");

    if (bio == NULL || buf == NULL) {
        return SSL_FAILURE;
    }

    /* not enough space for character plus terminator */
    if (sz <= 1) {
        return 0;
    }

    switch (bio->type) {
#ifndef NO_FILESYSTEM
        case WOLFSSL_BIO_FILE:
            if (bio->file == NULL) {
                return WOLFSSL_BIO_ERROR;
            }

            #if defined(MICRIUM) || defined(LSR_FS) || defined(EBSNET)
            WOLFSSL_MSG("XFGETS not ported for this system yet");
            ret = XFGETS(buf, sz, bio->file);
            #else
            if (XFGETS(buf, sz, bio->file) != NULL) {
                ret = (int)XSTRLEN(buf);
            }
            else {
                ret = WOLFSSL_BIO_ERROR;
            }
            #endif
            break;
#endif /* NO_FILESYSTEM */
        case WOLFSSL_BIO_MEMORY:
            {
                const byte* c;
                int   cSz;
                cSz = wolfSSL_BIO_pending(bio);
                if (cSz < 0) {
                    ret = cSz;
                    break;
                }

                if (wolfSSL_BIO_get_mem_data(bio, (void*)&c) <= 0) {
                    ret = WOLFSSL_BIO_ERROR;
                    break;
                }

                cSz = wolfSSL_getLineLength((char*)c, cSz);
                /* check case where line was bigger then buffer and buffer
                 * needs end terminator */
                if (cSz >= sz) {
                    cSz = sz - 1;
                    buf[cSz] = '\0';
                }
                else {
                    /* not minus 1 here because placing terminator after
                       msg and have checked that sz is large enough */
                    buf[cSz] = '\0';
                }

                ret = wolfSSL_BIO_read(bio, (void*)buf, cSz);
                /* ret is read after the switch statment */
                break;
            }
        case WOLFSSL_BIO_BIO:
            {
                char* c;
                int   cSz;
                cSz = wolfSSL_BIO_nread0(bio, &c);
                if (cSz < 0) {
                    ret = cSz;
                    break;
                }

                cSz = wolfSSL_getLineLength(c, cSz);
                /* check case where line was bigger then buffer and buffer
                 * needs end terminator */
                if (cSz >= sz) {
                    cSz = sz - 1;
                    buf[cSz] = '\0';
                }
                else {
                    /* not minus 1 here because placing terminator after
                       msg and have checked that sz is large enough */
                    buf[cSz] = '\0';
                }

                ret = wolfSSL_BIO_nread(bio, &c, cSz);
                if (ret > 0 && ret < sz) {
                    XMEMCPY(buf, c, ret);
                }
                break;
            }

        default:
            WOLFSSL_MSG("BIO type not supported yet with wolfSSL_BIO_gets");
    }

    return ret;
}


/* searches through bio list for a BIO of type "type"
 * returns NULL on failure to find a given type */
WOLFSSL_BIO* wolfSSL_BIO_find_type(WOLFSSL_BIO* bio, int type)
{
    WOLFSSL_BIO* local = NULL;
    WOLFSSL_BIO* current;

    WOLFSSL_ENTER("wolfSSL_BIO_find_type");

    if (bio == NULL) {
        return local;
    }

    current = bio;
    while (current != NULL) {
        if (current->type == type) {
            WOLFSSL_MSG("Found matching WOLFSSL_BIO type");
            local = current;
            break;
        }
        current = current->next;
    }

    return local;
}


/* returns a pointer to the next WOLFSSL_BIO in the chain on success.
 * If a failure case then NULL is returned */
WOLFSSL_BIO* wolfSSL_BIO_next(WOLFSSL_BIO* bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_next");

    if (bio == NULL) {
        WOLFSSL_MSG("Bad argument passed in");
        return NULL;
    }

    return bio->next;
}


/* Return the number of pending bytes in read and write buffers */
size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *bio)
{
    WOLFSSL_ENTER("BIO_ctrl_pending");
    if (bio == NULL) {
        return 0;
    }

    if (bio->ssl != NULL) {
        return (long)wolfSSL_pending(bio->ssl);
    }

    if (bio->type == WOLFSSL_BIO_MEMORY) {
        return bio->wrSz;
    }

    /* type BIO_BIO then check paired buffer */
    if (bio->type == WOLFSSL_BIO_BIO && bio->pair != NULL) {
        WOLFSSL_BIO* pair = bio->pair;
        if (pair->wrIdx > 0 && pair->wrIdx <= pair->rdIdx) {
            /* in wrap around state where begining of buffer is being
             * overwritten */
            return pair->wrSz - pair->rdIdx + pair->wrIdx;
        }
        else {
            /* simple case where has not wrapped around */
            return pair->wrIdx - pair->rdIdx;
        }
    }

    return 0;
}


long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **ptr)
{
    WOLFSSL_ENTER("BIO_get_mem_ptr");

    if (bio == NULL || ptr == NULL) {
        return WOLFSSL_FAILURE;
    }

    *ptr = (WOLFSSL_BUF_MEM*)(bio->mem);
    return WOLFSSL_SUCCESS;
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


int wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *bio, long size)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_write_buf_size");

    if (bio == NULL || bio->type != WOLFSSL_BIO_BIO || size < 0) {
        return WOLFSSL_FAILURE;
    }

    /* if already in pair then do not change size */
    if (bio->pair != NULL) {
        WOLFSSL_MSG("WOLFSSL_BIO is paired, free from pair before changing");
        return WOLFSSL_FAILURE;
    }

    bio->wrSz  = (int)size;
    if (bio->wrSz < 0) {
        WOLFSSL_MSG("Unexpected negative size value");
        return WOLFSSL_FAILURE;
    }

    if (bio->mem != NULL) {
        XFREE(bio->mem, bio->heap, DYNAMIC_TYPE_OPENSSL);
    }

    bio->mem = (byte*)XMALLOC(bio->wrSz, bio->heap, DYNAMIC_TYPE_OPENSSL);
    if (bio->mem == NULL) {
        WOLFSSL_MSG("Memory allocation error");
        return WOLFSSL_FAILURE;
    }
    bio->memLen = bio->wrSz;
    bio->wrIdx = 0;
    bio->rdIdx = 0;

    return WOLFSSL_SUCCESS;
}


/* Joins two BIO_BIO types. The write of b1 goes to the read of b2 and vise
 * versa. Creating something similar to a two way pipe.
 * Reading and writing between the two BIOs is not thread safe, they are
 * expected to be used by the same thread. */
int wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2)
{
    WOLFSSL_ENTER("wolfSSL_BIO_make_bio_pair");

    if (b1 == NULL || b2 == NULL) {
        WOLFSSL_LEAVE("wolfSSL_BIO_make_bio_pair", BAD_FUNC_ARG);
        return WOLFSSL_FAILURE;
    }

    /* both are expected to be of type BIO and not already paired */
    if (b1->type != WOLFSSL_BIO_BIO || b2->type != WOLFSSL_BIO_BIO ||
        b1->pair != NULL || b2->pair != NULL) {
        WOLFSSL_MSG("Expected type BIO and not already paired");
        return WOLFSSL_FAILURE;
    }

    /* set default write size if not already set */
    if (b1->mem == NULL && wolfSSL_BIO_set_write_buf_size(b1,
                            WOLFSSL_BIO_SIZE) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (b2->mem == NULL && wolfSSL_BIO_set_write_buf_size(b2,
                            WOLFSSL_BIO_SIZE) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    b1->pair = b2;
    b2->pair = b1;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *b)
{
    WOLFSSL_ENTER("wolfSSL_BIO_ctrl_reset_read_request");

    if (b == NULL || b->type == WOLFSSL_BIO_MEMORY) {
        return SSL_FAILURE;
    }

    b->readRq = 0;

    return WOLFSSL_SUCCESS;
}


/* Does not advance read index pointer */
int wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf)
{
    WOLFSSL_ENTER("wolfSSL_BIO_nread0");

    if (bio == NULL || buf == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return 0;
    }

    /* if paired read from pair */
    if (bio->pair != NULL) {
        WOLFSSL_BIO* pair = bio->pair;

        /* case where have wrapped around write buffer */
        *buf = (char*)pair->mem + pair->rdIdx;
        if (pair->wrIdx > 0 && pair->rdIdx >= pair->wrIdx) {
            return pair->wrSz - pair->rdIdx;
        }
        else {
            return pair->wrIdx - pair->rdIdx;
        }
    }

    return 0;
}


/* similar to wolfSSL_BIO_nread0 but advances the read index */
int wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num)
{
    int sz = WOLFSSL_BIO_UNSET;

    WOLFSSL_ENTER("wolfSSL_BIO_nread");

    if (bio == NULL || buf == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return WOLFSSL_FAILURE;
    }

    if (bio->type == WOLFSSL_BIO_MEMORY) {
        return SSL_FAILURE;
    }

    if (bio->pair != NULL) {
        /* special case if asking to read 0 bytes */
        if (num == 0) {
            *buf = (char*)bio->pair->mem + bio->pair->rdIdx;
            return 0;
        }

        /* get amount able to read and set buffer pointer */
        sz = wolfSSL_BIO_nread0(bio, buf);
        if (sz == 0) {
            return WOLFSSL_BIO_ERROR;
        }

        if (num < sz) {
            sz = num;
        }
        bio->pair->rdIdx += sz;

        /* check if have read to the end of the buffer and need to reset */
        if (bio->pair->rdIdx == bio->pair->wrSz) {
            bio->pair->rdIdx = 0;
            if (bio->pair->wrIdx == bio->pair->wrSz) {
                bio->pair->wrIdx = 0;
            }
        }

        /* check if read up to write index, if so then reset indexs */
        if (bio->pair->rdIdx == bio->pair->wrIdx) {
            bio->pair->rdIdx = 0;
            bio->pair->wrIdx = 0;
        }
    }

    return sz;
}


int wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num)
{
    int sz = WOLFSSL_BIO_UNSET;

    WOLFSSL_ENTER("wolfSSL_BIO_nwrite");

    if (bio == NULL || buf == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return 0;
    }

    if (bio->type != WOLFSSL_BIO_BIO) {
        return SSL_FAILURE;
    }

    if (bio->pair != NULL) {
        if (num == 0) {
            *buf = (char*)bio->mem + bio->wrIdx;
            return 0;
        }

        if (bio->wrIdx < bio->rdIdx) {
            /* if wrapped around only write up to read index. In this case
             * rdIdx is always greater then wrIdx so sz will not be negative. */
            sz = bio->rdIdx - bio->wrIdx;
        }
        else if (bio->rdIdx > 0 && bio->wrIdx == bio->rdIdx) {
            return WOLFSSL_BIO_ERROR; /* no more room to write */
        }
        else {
            /* write index is past read index so write to end of buffer */
            sz = bio->wrSz - bio->wrIdx;

            if (sz <= 0) {
                /* either an error has occured with write index or it is at the
                 * end of the write buffer. */
                if (bio->rdIdx == 0) {
                    /* no more room, nothing has been read */
                    return WOLFSSL_BIO_ERROR;
                }

                bio->wrIdx = 0;

                /* check case where read index is not at 0 */
                if (bio->rdIdx > 0) {
                    sz = bio->rdIdx; /* can write up to the read index */
                }
                else {
                    sz = bio->wrSz; /* no restriction other then buffer size */
                }
            }
        }

        if (num < sz) {
            sz = num;
        }
        *buf = (char*)bio->mem + bio->wrIdx;
        bio->wrIdx += sz;

        /* if at the end of the buffer and space for wrap around then set
         * write index back to 0 */
        if (bio->wrIdx == bio->wrSz && bio->rdIdx > 0) {
            bio->wrIdx = 0;
        }
    }

    return sz;
}


/* Reset BIO to initial state */
int wolfSSL_BIO_reset(WOLFSSL_BIO *bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_reset");

    if (bio == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        /* -1 is consistent failure even for FILE type */
        return WOLFSSL_BIO_ERROR;
    }

    switch (bio->type) {
        #ifndef NO_FILESYSTEM
        case WOLFSSL_BIO_FILE:
            XREWIND(bio->file);
            return 0;
        #endif

        case WOLFSSL_BIO_BIO:
            bio->rdIdx = 0;
            bio->wrIdx = 0;
            return 0;

        default:
            WOLFSSL_MSG("Unknown BIO type needs added to reset function");
    }

    return WOLFSSL_BIO_ERROR;
}

#ifndef NO_FILESYSTEM
long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_fp");

    if (bio == NULL || fp == NULL) {
        WOLFSSL_LEAVE("wolfSSL_BIO_set_fp", BAD_FUNC_ARG);
        return WOLFSSL_FAILURE;
    }

    if (bio->type != WOLFSSL_BIO_FILE) {
        return WOLFSSL_FAILURE;
    }

    bio->close = (byte)c;
    bio->file  = fp;

    return WOLFSSL_SUCCESS;
}


long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_fp");

    if (bio == NULL || fp == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (bio->type != WOLFSSL_BIO_FILE) {
        return SSL_FAILURE;
    }

    *fp = bio->file;

    return WOLFSSL_SUCCESS;
}

/* overwrites file */
int wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name)
{
    WOLFSSL_ENTER("wolfSSL_BIO_write_filename");

    if (bio == NULL || name == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (bio->type == WOLFSSL_BIO_FILE) {
        if (bio->file != NULL && bio->close == BIO_CLOSE) {
            XFCLOSE(bio->file);
        }

        bio->file = XFOPEN(name, "w");
        if (bio->file == NULL) {
            return WOLFSSL_FAILURE;
        }
        bio->close = BIO_CLOSE;

        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs)
{
      WOLFSSL_ENTER("wolfSSL_BIO_seek");

      if (bio == NULL) {
          return -1;
      }

      /* offset ofs from begining of file */
      if (bio->type == WOLFSSL_BIO_FILE &&
              XFSEEK(bio->file, ofs, SEEK_SET) < 0) {
          return -1;
      }

      return 0;
}
#endif /* NO_FILESYSTEM */


long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v)
{
      WOLFSSL_ENTER("wolfSSL_BIO_set_mem_eof_return");

      if (bio != NULL) {
        bio->eof = v;
      }

      return 0;
}
#endif /* WOLFSSL_BIO_INCLUDED */

