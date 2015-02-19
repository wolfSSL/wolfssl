/* ecc25519_montgomery.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * From Daniel J Bernstein's curve25519 ref10 work.
 */

fe_sub(tmp0,x3,z3);
fe_sub(tmp1,x2,z2);
fe_add(x2,x2,z2);
fe_add(z2,x3,z3);
fe_mul(z3,tmp0,x2);
fe_mul(z2,z2,tmp1);
fe_sq(tmp0,tmp1);
fe_sq(tmp1,x2);
fe_add(x3,z3,z2);
fe_sub(z2,z3,z2);
fe_mul(x2,tmp1,tmp0);
fe_sub(tmp1,tmp1,tmp0);
fe_sq(z2,z2);
fe_mul121666(z3,tmp1);
fe_sq(x3,x3);
fe_add(tmp0,tmp0,z3);
fe_mul(z3,x1,z2);
fe_mul(z2,tmp1,tmp0);

