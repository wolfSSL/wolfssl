/*kernel.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

#ifndef KERNEL_H
#define KERNEL_H
#include "r_t4_itcpip.h"

extern ER		get_tid(ID *p_tskid);
extern ER		slp_tsk(void) ;
extern bool		sns_ctx(void);
extern ER		iwup_tsk(ID tskid);
extern ER		wup_tsk(ID tskid) ;
extern ER		iwup_tsk(ID tskid) ;
extern ER		rot_rdq(PRI tskpri);
#define TPRI_SELF		0
#define _RI_CLOCK_TIMER (0)
#define TRUE	true
#endif //KERNEL_H
