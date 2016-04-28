# random.py
#
# Copyright (C) 2006-2016 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
from wolfcrypt._ffi import ffi as _ffi
from wolfcrypt._ffi import lib as _lib


class Random(object):
    def __init__(self):
        self.native_object = _ffi.new("WC_RNG *")
        if _lib.wc_InitRng(self.native_object) != 0:
            self.native_object = None


    def __del__(self):
        if self.native_object:
            _lib.wc_FreeRng(self.native_object)


    def byte(self):
        ret = "\0"

        _lib.wc_RNG_GenerateByte(self.native_object, ret)

        return ret


    def bytes(self, length):
        ret = "\0" * length

        _lib.wc_RNG_GenerateBlock(self.native_object, ret, length)

        return ret
