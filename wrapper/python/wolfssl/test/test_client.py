# -*- coding: utf-8 -*-
#
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

# pylint: disable=missing-docstring, invalid-name, import-error

import unittest
import socket
import ssl
import wolfssl

class SSLClientTest(unittest.TestCase):
    provider = ssl
    host = "www.globalsign.com"
    port = 443

    def setUp(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def test_wrap_socket(self):
        secure_sock = self.provider.wrap_socket(self.sock)
        secure_sock.connect((self.host, self.port))

        secure_sock.write(b"GET / HTTP/1.1\n\n")
        self.assertEqual(b"HTTP", secure_sock.read(4))

        secure_sock.close()

    def test_wrap_socket_with_ca(self):
        secure_sock = self.provider.wrap_socket(
            self.sock, cert_reqs=self.provider.CERT_REQUIRED,
            ca_certs="../../../certs/external/ca-globalsign-root-r2.pem")
        secure_sock.connect((self.host, self.port))

        secure_sock.write(b"GET / HTTP/1.1\n\n")
        self.assertEqual(b"HTTP", secure_sock.read(4))

        secure_sock.close()

    def test_wrap_socket_from_context(self):
        ctx = self.provider.SSLContext(self.provider.PROTOCOL_TLSv1_2)

        ctx.verify_mode = self.provider.CERT_REQUIRED
        ctx.load_verify_locations(
            "../../../certs/external/ca-globalsign-root-r2.pem")

        secure_sock = ctx.wrap_socket(self.sock)
        secure_sock.connect((self.host, self.port))

        secure_sock.write(b"GET / HTTP/1.1\n\n")
        self.assertEqual(b"HTTP", secure_sock.read(4))

        secure_sock.close()

    def test_ssl_socket(self):
        secure_sock = self.provider.SSLSocket(
            self.sock,
            cert_reqs=self.provider.CERT_REQUIRED,
            ca_certs="../../../certs/external/ca-globalsign-root-r2.pem")

        secure_sock.connect((self.host, self.port))

        secure_sock.write(b"GET / HTTP/1.1\n\n")
        self.assertEqual(b"HTTP", secure_sock.read(4))

        secure_sock.close()

class TestWolfSSL(SSLClientTest):
    provider = wolfssl
