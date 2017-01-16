# -*- coding: utf-8 -*-
#
# test_server.py
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

HOST = 'localhost'

class SSLTest(unittest.TestCase):
    provider = ssl

    def setUp(self):
        # server setup
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((HOST, 0))
        self.port = self.server.getsockname()[1]
        self.server.listen(1)

        # client setup
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def tearDown(self):
        self.server.close()
        self.server = None

        self.client.close()
        self.client = None

    def cleartext(self):
        conn = self.server.accept()[0]
        secure_server = self.provider.wrap_socket(
            conn, server_side=True,
            certfile="certs/server_cert.pem",
            keyfile="certs/server_key.pem")

        self.client.send(b"server, can you hear me?")
        self.assertEqual(b"server, can you hear me?",
                         secure_server.read(256))

        conn.send(b"I hear you loud and clear, client.")
        self.assertEqual(b"I hear you loud and clear, client.",
                         self.client.recv(256))
