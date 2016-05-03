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
    __version__  = "0.1.0",
    __author__   = "wolfSSL Inc.",
    __email__    = "info@wolfssl.com",
    __url__      = "https://wolfssl.github.io/wolfcrypt-py",
    __summary__  = "A Python library that encapsulates wolfSSL's wolfCrypt API",
    __keywords__ = """
        cryptography, aes, des3, rsa, sha, sha256, sha384, sha512, hmac, random
    """,
    __license__  = """
        wolfSSL’s software is available under two distinct licensing models:
        open source and standard commercial licensing. Please see the relevant
        section below for information on each type of license.

        Open Source

        wolfSSL (formerly CyaSSL), yaSSL, wolfCrypt, yaSSH and TaoCrypt software
        are free software downloads and may be modified to the needs of the user
        as long as the user adheres to version two of the GPL License. The GPLv2
        license can be found on the gnu.org website:
            http://www.gnu.org/licenses/old-licenses/gpl-2.0.html

        Commercial Licensing

        Businesses and enterprises who wish to incorporate wolfSSL products into
        proprietary appliances or other commercial software products for
        re-distribution must license commercial versions. Commercial licenses for
        wolfSSL, yaSSL, and wolfCrypt are available for $5,000 USD per end product
        or SKU. Licenses are generally issued for one product and include unlimited
        royalty-free distribution. Custom licensing terms are also available.
    """,
    __copyright__ = "Copyright 2016 wolfSSL Inc.  All rights reserved"
)

globals().update(metadata)

__all__ = metadata.keys()
