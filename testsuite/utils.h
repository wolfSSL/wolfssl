/* utils.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* This is a set of utility functions that are used by testsuite.c. They are
 * also used in api.c but we want to keep the utils for testsuite.c as small
 * as possible. */

#ifndef TESTSUITE_UTILS_H
#define TESTSUITE_UTILS_H

/* Return
 *   tmpDir on success
 *   NULL on failure */
char* create_tmp_dir(char* tmpDir, int len);
/* Remaining functions return
 * 0 on success
 * -1 on failure */
int rem_dir(const char* dirName);
int rem_file(const char* fileName);
int copy_file(const char* in, const char* out);

#endif /* TESTSUITE_UTILS_H */
