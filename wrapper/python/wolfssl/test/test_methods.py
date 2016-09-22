# test_methods.py
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
from wolfssl._methods import *
from wolfssl._ffi import ffi as _ffi


class TestMethods(unittest.TestCase):
    def test_SSLv3_raises(self):
        self.assertRaises(ValueError, WolfSSLMethod, PROTOCOL_SSLv3, False)
        self.assertRaises(ValueError, WolfSSLMethod, PROTOCOL_SSLv3, True)


    def test_TLSv1_raises(self):
        self.assertRaises(ValueError, WolfSSLMethod, PROTOCOL_TLSv1, False)
        self.assertRaises(ValueError, WolfSSLMethod, PROTOCOL_TLSv1, True)


    def test_TLSv1_1_raises(self):
        self.assertRaises(ValueError, WolfSSLMethod, PROTOCOL_TLSv1_1, False)
        self.assertRaises(ValueError, WolfSSLMethod, PROTOCOL_TLSv1_1, True)


    def test_SSLv23_doesnt_raises(self):
        client = WolfSSLMethod(PROTOCOL_SSLv23, False)
        server = WolfSSLMethod(PROTOCOL_SSLv23, True)
        
        self.assertIsInstance(client, WolfSSLMethod)
        self.assertIsInstance(server, WolfSSLMethod)

        self.assertNotEquals(client.native_object, _ffi.NULL)
        self.assertNotEquals(server.native_object, _ffi.NULL)


    def test_TLS_doesnt_raises(self):
        client = WolfSSLMethod(PROTOCOL_TLS, False)
        server = WolfSSLMethod(PROTOCOL_TLS, True)
        
        self.assertIsInstance(client, WolfSSLMethod)
        self.assertIsInstance(server, WolfSSLMethod)

        self.assertNotEquals(client.native_object, _ffi.NULL)
        self.assertNotEquals(server.native_object, _ffi.NULL)


    def test_TLSv1_2_doesnt_raises(self):
        client = WolfSSLMethod(PROTOCOL_TLSv1_2, False)
        server = WolfSSLMethod(PROTOCOL_TLSv1_2, True)
        
        self.assertIsInstance(client, WolfSSLMethod)
        self.assertIsInstance(server, WolfSSLMethod)

        self.assertNotEquals(client.native_object, _ffi.NULL)
        self.assertNotEquals(server.native_object, _ffi.NULL)
