/* template_appliance.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* This file maps the Avnet MT3620 Starter Kit (SK)
 * to the 'template appliance' abstraction used by the templates.
 * Some peripherals are on-board, while other peripherals must be
 * attached externally (conditionally).
 * See https://aka.ms/AzureSphereHardwareDefinitions for more
 * information on how to use hardware abstractions .
 */


#pragma once
#include "avnet_mt3620_sk.h"

/* MT3620 SK: wolfssl azsphere CI app */
#define WOLF_AZSPHERE AVNET_MT3620_SK_USER_LED_RED

