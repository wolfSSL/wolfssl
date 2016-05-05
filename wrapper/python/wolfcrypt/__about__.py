# __about__.py
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

metadata = dict(
  __name__     = "wolfcrypt",
  __version__  = "0.1.5",
  __license__  = """GPLv2 or Commercial License""",
  __author__   = "wolfSSL Inc. <info@wolfssl.com>",
  __url__      = "https://wolfssl.github.io/wolfcrypt-py",
  __summary__  = "A Python library that encapsulates wolfSSL's wolfCrypt API.",
  __keywords__ = """
        OS independent, Python / 2.7, Python / 3.5, software development,
        security, cryptography, Proprietary, GPLv2
  """,
)

globals().update(metadata)

__all__ = list(metadata.keys())
