/* ecc25519_pow225521.h
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
 */

 /* Based On Daniel J Bernstein's curve25519 Public Domain ref10 work. */

fe_sq(t0,z); for (i = 1;i < 1;++i) fe_sq(t0,t0);
fe_sq(t1,t0); for (i = 1;i < 2;++i) fe_sq(t1,t1);
fe_mul(t1,z,t1);
fe_mul(t0,t0,t1);
fe_sq(t2,t0); for (i = 1;i < 1;++i) fe_sq(t2,t2);
fe_mul(t1,t1,t2);
fe_sq(t2,t1); for (i = 1;i < 5;++i) fe_sq(t2,t2);
fe_mul(t1,t2,t1);
fe_sq(t2,t1); for (i = 1;i < 10;++i) fe_sq(t2,t2);
fe_mul(t2,t2,t1);
fe_sq(t3,t2); for (i = 1;i < 20;++i) fe_sq(t3,t3);
fe_mul(t2,t3,t2);
fe_sq(t2,t2); for (i = 1;i < 10;++i) fe_sq(t2,t2);
fe_mul(t1,t2,t1);
fe_sq(t2,t1); for (i = 1;i < 50;++i) fe_sq(t2,t2);
fe_mul(t2,t2,t1);
fe_sq(t3,t2); for (i = 1;i < 100;++i) fe_sq(t3,t3);
fe_mul(t2,t3,t2);
fe_sq(t2,t2); for (i = 1;i < 50;++i) fe_sq(t2,t2);
fe_mul(t1,t2,t1);
fe_sq(t1,t1); for (i = 1;i < 5;++i) fe_sq(t1,t1);
fe_mul(out,t1,t0);

