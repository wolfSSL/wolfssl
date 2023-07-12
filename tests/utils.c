/* utils.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
#include <tests/unit.h>

#if !defined(WOLFSSL_TEST_UTILS_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning utils.c does not need to be compiled separately
    #endif
#else

#ifndef NO_FILESYSTEM

#ifdef _MSC_VER
#include <direct.h>
#endif

#define TMP_DIR_PREFIX "tmpDir-"
/* len is length of tmpDir name, assuming
 * len does not include null terminating character */
char* create_tmp_dir(char *tmpDir, int len)
{
    if (len < (int)XSTR_SIZEOF(TMP_DIR_PREFIX))
        return NULL;

    XMEMCPY(tmpDir, TMP_DIR_PREFIX, XSTR_SIZEOF(TMP_DIR_PREFIX));

    if (mymktemp(tmpDir, len, len - XSTR_SIZEOF(TMP_DIR_PREFIX)) == NULL)
        return NULL;

#ifdef _MSC_VER
    if (_mkdir(tmpDir) != 0)
        return NULL;
#elif defined(__CYGWIN__) || defined(__MINGW32__)
    if (mkdir(tmpDir) != 0)
        return NULL;
#else
    if (mkdir(tmpDir, 0700) != 0)
        return NULL;
#endif

    return tmpDir;
}

int rem_dir(const char* dirName)
{
#ifdef _MSC_VER
    if (_rmdir(dirName) != 0)
        return -1;
#else
    if (rmdir(dirName) != 0)
        return -1;
#endif
    return 0;
}

int rem_file(const char* fileName)
{
#ifdef _MSC_VER
    if (_unlink(fileName) != 0)
        return -1;
#else
    if (unlink(fileName) != 0)
        return -1;
#endif
    return 0;
}

int copy_file(const char* in, const char* out)
{
    byte buf[100];
    XFILE inFile = XBADFILE;
    XFILE outFile = XBADFILE;
    size_t sz;
    int ret = -1;

    inFile = XFOPEN(in, "rb");
    if (inFile == XBADFILE)
        goto cleanup;

    outFile = XFOPEN(out, "wb");
    if (outFile == XBADFILE)
        goto cleanup;

    while ((sz = XFREAD(buf, 1, sizeof(buf), inFile)) != 0) {
        if (XFWRITE(buf, 1, sz, outFile) != sz)
            goto cleanup;
    }

    ret = 0;
cleanup:
    if (inFile != XBADFILE)
        XFCLOSE(inFile);
    if (outFile != XBADFILE)
        XFCLOSE(outFile);
    return ret;
}
#endif /* !NO_FILESYSTEM */

#endif /* WOLFSSL_TEST_UTILS_INCLUDED */
