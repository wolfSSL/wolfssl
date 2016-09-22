# test_client.py
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
import socket
import wolfssl
import ssl

class SSLClientTest(unittest.TestCase):
    ssl_provider = ssl
    host = "www.google.com"
    port = 443
    
    def setUp(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def test_wrap_socket(self):
        self.secure_sock = self.ssl_provider.wrap_socket(
                                    self.sock, ssl_version=ssl.PROTOCOL_TLSv1_2)
        self.secure_sock.connect((self.host, self.port))

        self.secure_sock.send(b"GET / HTTP/1.1\n\n")
        self.assertEquals(b"HTTP", self.secure_sock.recv(4))

        self.secure_sock.close()


#class TestWolfSSL(SSLClientTest):
#    ssl_provider = wolfssl
