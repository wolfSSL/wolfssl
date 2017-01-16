#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
# server.py
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

import sys
import socket

try:
    import wolfssl
except ImportError:
    print("You must run 'python setup.py install' to use the examples")
    sys.exit()

bind_socket = socket.socket()
bind_socket.bind(('', 0))
bind_socket.listen(5)

print("Server listening on port", bind_socket.getsockname()[1])

while True:
    try:
        secure_socket = None

        new_socket, from_addr = bind_socket.accept()

        secure_socket = wolfssl.wrap_socket(
            new_socket,
            server_side=True,
            certfile="certs/server-cert.pem",
            keyfile="certs/server-key.pem")

        print(secure_socket.read())
        secure_socket.write(b"I hear you fa shizzle!")

    except KeyboardInterrupt:
        print()
        break

    finally:
        if secure_socket:
            secure_socket.shutdown(socket.SHUT_RDWR)
            secure_socket.close()
