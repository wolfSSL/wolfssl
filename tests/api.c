/* api.c API unit tests
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "../cyassl/ssl.h"
#include "unit.h"

static int test_CyaSSL_Init(void);
static int test_CyaSSL_Cleanup(void);

int ApiTest(void)
{
    if (test_CyaSSL_Init()) return 1;
    if (test_CyaSSL_Cleanup()) return 1;

    return 0;
}

int test_CyaSSL_Init(void)
{
    int result = CyaSSL_Init();
    
    if (result) printf("test_CyaSSL_Init(): failed\n");

    return result;
}

int test_CyaSSL_Cleanup(void)
{
    int result = CyaSSL_Cleanup();

    if (result) printf("test_CyaSSL_Cleanup(): failed\n");

    return result;
}

