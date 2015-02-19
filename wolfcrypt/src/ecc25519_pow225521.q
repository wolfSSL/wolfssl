#/* ecc25519_pow225521.q
# *
# * Copyright (C) 2006-2015 wolfSSL Inc.
# *
# * This file is part of wolfSSL. (formerly known as CyaSSL)
# *
# * wolfSSL is free software; you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation; either version 2 of the License, or
# * (at your option) any later version.
# *
# * wolfSSL is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
# *
# * From Daniel J Bernstein's curve25519 ref10 work.
# */

:name:fe:t0:t1:t2:t3:t4:t5:t6:t7:t8:t9:z:out:
fe r:var/r=fe:

enter f:enter/f:>z1=fe#11:
return:nofallthrough:<z_255_21=fe#12:leave:

h=f*g:<f=fe:<g=fe:>h=fe:asm/fe_mul(>h,<f,<g);:
h=f^2^k:<f=fe:>h=fe:#k:asm/fe_sq(>h,<f); for (i = 1;i !lt; #k;++i) fe_sq(>h,>h);:

:

fe z1
fe z2
fe z8
fe z9
fe z11
fe z22
fe z_5_0
fe z_10_5
fe z_10_0
fe z_20_10
fe z_20_0
fe z_40_20
fe z_40_0
fe z_50_10
fe z_50_0
fe z_100_50
fe z_100_0
fe z_200_100
fe z_200_0
fe z_250_50
fe z_250_0
fe z_255_5
fe z_255_21

enter pow225521

z2 = z1^2^1
z8 = z2^2^2
z9 = z1*z8
z11 = z2*z9
z22 = z11^2^1
z_5_0 = z9*z22
z_10_5 = z_5_0^2^5
z_10_0 = z_10_5*z_5_0
z_20_10 = z_10_0^2^10
z_20_0 = z_20_10*z_10_0
z_40_20 = z_20_0^2^20
z_40_0 = z_40_20*z_20_0
z_50_10 = z_40_0^2^10
z_50_0 = z_50_10*z_10_0
z_100_50 = z_50_0^2^50
z_100_0 = z_100_50*z_50_0
z_200_100 = z_100_0^2^100
z_200_0 = z_200_100*z_100_0
z_250_50 = z_200_0^2^50
z_250_0 = z_250_50*z_50_0
z_255_5 = z_250_0^2^5
z_255_21 = z_255_5*z11

return
