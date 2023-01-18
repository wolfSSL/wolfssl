/*target_edmac.c
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


#include "kernel_impl.h"
#include <sil.h>
#include "target_edmac.h"
#include "kernel.h"

 STK_T *const	istack;

extern void ether_int_Wrapper();
/*
 *	Target system dependent module (EDMAC Wrapper for RX72N)
 */

void
rx72n_edmac_interrput_wrapper(void){
	i_begin_int(INTNO_EDMAC_0);

	ether_int_Wrapper();

	i_end_int(INTNO_EDMAC_0);

}
void
rx72n_edmac_interrput_wrapper_term(void){

}
