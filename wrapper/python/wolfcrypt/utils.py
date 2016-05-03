# utils.py
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
import sys
from binascii import hexlify as b2h, unhexlify as h2b


if sys.version_info[0] == 3:
    _text_type = str
    _binary_type = bytes
else:
    _text_type = unicode
    _binary_type = str


def t2b(s):
    """
    Converts text to bynary.
    """
    if isinstance(s, _binary_type):
        return s
    return _text_type(s).encode("utf-8")
