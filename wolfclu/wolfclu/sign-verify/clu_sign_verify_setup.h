/* clu_sign_verify_setup.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#ifndef WOLFCLU_SIGN_VERIFY_H
#define WOLFCLU_SIGN_VERIFY_H

int wolfCLU_sign_verify_setup(int, char**);

/**
 * @brief Handles dgst mode
 *
 * @param argc number of arguments
 * @param argv array of string args
 *
 * @return WOLFCLU_SUCCESS on success
 */
int wolfCLU_dgst_setup(int argc, char** argv);

#endif /* WOLFCLU_SIGN_VERIFY_H */

