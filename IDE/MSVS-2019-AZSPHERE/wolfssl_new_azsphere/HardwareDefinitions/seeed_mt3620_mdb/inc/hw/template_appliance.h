/* template_appliance.h
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

/* This file maps the Seeed MT3620 Mini Development Board (MDB)
 * to the 'template appliance' abstraction used by the templates.
 * Some peripherals are on-board, while other peripherals must be
 * attached externally (conditionally).
 * See https://aka.ms/AzureSphereHardwareDefinitions for more
 * information on how to use hardware abstractions .
 */

#pragma once
#include "seeed_mt3620_mdb.h"

/* MT3620 SK: wolfssl azsphere CI app */
#define WOLF_AZSPHERE SEEED_MT3620_MDB_USER_LED

