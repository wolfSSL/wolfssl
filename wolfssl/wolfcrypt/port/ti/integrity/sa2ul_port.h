/* sa2ul_port.h
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

#ifndef SA2UL_PORT_H
#define SA2UL_PORT_H

#if defined(WOLFSSL_TI_AM64X_A53_INTEGRITY)

#define WOLFSSL_TI_SA2UL_DEVID 8888
#define WC_USE_DEVID WOLFSSL_TI_SA2UL_DEVID

int ti_sa2ul_port_init(void);

#endif /* WOLFSSL_TI_AM64X_A53_INTEGRITY */

#endif /* SA2UL_PORT_H */
