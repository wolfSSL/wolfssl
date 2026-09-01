/* test_partition_bounds.c
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

#include <wolfssl/wolfcrypt/port/caam/caam_driver.h>

/* Array bounds provide compile-time validation of partition limits. */
typedef char QnxCaamFirstPartitionIsValid[
    CAAM_QNX_PARTITION_IS_VALID(0U) ? 1 : -1];

typedef char QnxCaamLastPartitionIsValid[
    CAAM_QNX_PARTITION_IS_VALID(CAAM_QNX_MAX_PARTITIONS - 1U) ? 1 : -1];

typedef char QnxCaamLimitIsInvalid[
    !CAAM_QNX_PARTITION_IS_VALID(CAAM_QNX_MAX_PARTITIONS) ? 1 : -1];

typedef char QnxCaamWrappedPartitionIsInvalid[
    !CAAM_QNX_PARTITION_IS_VALID(~0U) ? 1 : -1];
