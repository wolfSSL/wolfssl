# test_context.py
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
import unittest
import wolfssl
import ssl


class TestSSLContext(unittest.TestCase):
    provider = ssl

    def setUp(self):
        self.ctx = self.provider.SSLContext(self.provider.PROTOCOL_SSLv23)

    def test_context_creation(self):
        self.assertIsNotNone(self.ctx)

    def test_load_cert_chain(self):
        self.assertRaises(TypeError, self.ctx.load_cert_chain, None)

    def test_load_verify_locations(self):
        self.assertRaises(TypeError, self.ctx.load_verify_locations, None)

class TestWolfSSLContext(TestSSLContext):
    provider = wolfssl