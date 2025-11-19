# ax_bsdkm.m4 -- macros for getting attributes of default configured kernel
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

AC_DEFUN([AC_PATH_DEFAULT_BSDKM_SOURCE],
[
AC_MSG_CHECKING([for default kernel FreeBSD build root])
if test -d /usr/src/sys/; then
  DEFAULT_BSDKM_ROOT=/usr/src/sys/
  AC_MSG_RESULT([$DEFAULT_BSDKM_ROOT])
else
  AC_MSG_RESULT([no default configured kernel found])
fi
])

